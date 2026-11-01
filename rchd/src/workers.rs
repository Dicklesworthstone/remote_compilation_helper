//! Worker pool management.

#![allow(dead_code)] // Scaffold code - methods will be used in future beads

use crate::DaemonContext;
use crate::disk_pressure::{
    DiskCapacityObservation, DiskPressurePolicyConfig, DiskSlotPolicy, PressureAssessment,
    evaluate_pressure_policy,
};
use crate::health::probe_worker_capabilities;
use rch_common::bypass_record::AdminDisableStore;
use rch_common::{
    CircuitBreakerConfig, CircuitState, CircuitStats, WorkerCapabilities, WorkerConfig, WorkerId,
    WorkerStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock, RwLockReadGuard, watch};
use tracing::debug;

// Sized for a *loaded* worker, not an idle one.
//
// `rch-wkr capabilities` shells out to rustc/node/npm/go/zig/cargo-zigbuild and
// stats the disk, behind a fresh SSH handshake. On an idle box that is ~1s; on a
// busy build host it is far more. Measured across the fleet with builds running
// (10-core workers at load 45-60): 2.9s, 6.3s, 7.2s, 8.6s, **15.8s**. Against the
// former 4s/8s pair every one of those hosts failed its probe.
//
// That failure is self-defeating: a probe that only fails under load means
// `disk_free_gb` goes stale exactly on the workers that are actively filling
// their disks, and `is_low_disk()` returns `None` for missing data — so the
// low-disk admission gate FAILS OPEN and the dispatcher keeps feeding a worker
// that is about to hit ENOSPC.
//
// This is a low-frequency operator query (`rch workers capabilities --refresh`),
// not one of the ~30s poll loops, and refreshes run concurrently across workers,
// so a generous ceiling costs nothing in the common case and only ever shortens
// the tail.
const CAPABILITIES_REFRESH_PROBE_TIMEOUT: Duration = Duration::from_secs(25);
const CAPABILITIES_REFRESH_WORKER_BUDGET: Duration = Duration::from_secs(35);

fn duration_millis_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn duration_secs_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

// =============================================================================
// Worker lifecycle type model (bd-session-history-remediation-ocv9i.1.1)
// =============================================================================
//
// A worker's lifecycle is modelled as **two independent axes** so that
// permanent operator intent can never be confused with transient scheduler
// eligibility:
//
//   1. [`AdminIntent`]  — the *desired inventory* axis. Changes ONLY through
//      explicit operator actions (`rch workers disable/enable/drain`). This is
//      what `workers.toml` encodes; it is the source of truth for what the
//      operator wants in the fleet.
//   2. [`EligibilityState`] — the *live scheduler eligibility* axis. Advances
//      automatically from health probes and concrete failure classes. It NEVER
//      writes back to `AdminIntent` / `workers.toml`.
//
// The cardinal safety invariant (session-history remediation): a transient
// failure quarantines a worker on the eligibility axis (`TemporaryBypass`) but
// must never mutate desired inventory, and a recovering worker must never
// auto-rejoin if the operator has disabled it. Keeping the two axes as distinct
// types makes "auto-rejoin an operator-disabled worker" unrepresentable rather
// than merely discouraged.
//
// ## Serialization compatibility policy
//
// These types derive `serde` with `snake_case` so they are stable across the
// daemon/status JSON boundary. They are *additive*: the legacy single-axis
// [`WorkerStatus`] enum is untouched, and [`WorkerLifecycle::legacy_status`]
// collapses the two axes back to a `WorkerStatus` for older status consumers
// (both quarantine states — `TemporaryBypass` and `RecoveredPendingCanary` —
// collapse to `Unreachable` so they stay out of legacy scheduling).
// New variants must be appended, never reordered or renamed, so historical
// JSONL replays continue to deserialize.

/// Operator-controlled *desired* lifecycle intent for a worker.
///
/// This is the desired-inventory axis. It changes only through explicit
/// operator actions and is never advanced by health probes or transient
/// failures. A worker is only ever schedulable when its intent is
/// [`AdminIntent::Active`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminIntent {
    /// Operator wants this worker in service (default).
    #[default]
    Active,
    /// Operator asked the worker to stop taking *new* jobs but finish current
    /// ones (`rch workers drain`).
    Draining,
    /// Drain has completed (no active jobs); the operator's intent is still
    /// "out of service" until they re-enable.
    Drained,
    /// Operator explicitly disabled the worker. Never eligible — and never
    /// auto-rejoined by the recovery path — until re-enabled.
    Disabled,
}

/// Transient *scheduler eligibility* derived from health probes and failure
/// classes.
///
/// This is the live axis. It advances automatically and never writes back to
/// [`AdminIntent`]. The quarantine lifecycle is:
///
/// ```text
/// Healthy/Degraded/Unreachable --enter_bypass(class)--> TemporaryBypass
/// TemporaryBypass              --recover_to_canary----> RecoveredPendingCanary
/// RecoveredPendingCanary       --promote_from_canary--> Healthy
/// RecoveredPendingCanary       --enter_bypass(class)--> TemporaryBypass   (relapse)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityState {
    /// Healthy and accepting work.
    #[default]
    Healthy,
    /// Responding but slow/partially degraded — still eligible for work.
    Degraded,
    /// Failed to respond to heartbeat — temporarily ineligible, but not yet
    /// quarantined into a failure-class bypass.
    Unreachable,
    /// Quarantined out of scheduling because a probe hit a concrete failure
    /// class. Distinct from [`AdminIntent::Disabled`]: this is transient and
    /// recovers automatically via probe + canary.
    TemporaryBypass,
    /// A previously bypassed worker passed its recovery probe and is awaiting a
    /// single canary build before full rejoin.
    RecoveredPendingCanary,
}

/// Concrete failure class that quarantined a worker into
/// [`EligibilityState::TemporaryBypass`]. Defined in `rch_common` so the shared
/// bypass-record schema, incident ledger, and status surfaces speak one
/// vocabulary; re-exported here as it is part of the worker lifecycle model.
pub use rch_common::BypassFailureClass;

/// An attempted lifecycle transition that the state machine rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalLifecycleTransition {
    /// Eligibility state the worker was in.
    pub from: EligibilityState,
    /// Eligibility state that was requested.
    pub to: EligibilityState,
    /// Why the transition is not permitted.
    pub reason: &'static str,
}

impl std::fmt::Display for IllegalLifecycleTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "illegal worker lifecycle transition {:?} -> {:?}: {}",
            self.from, self.to, self.reason
        )
    }
}

impl std::error::Error for IllegalLifecycleTransition {}

/// The full lifecycle state of a worker: the two independent axes plus the
/// failure class that explains a current bypass (if any).
///
/// Scheduling decisions combine both axes via [`WorkerLifecycle::is_schedulable`]
/// — admin intent dominates, but neither axis ever overwrites the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WorkerLifecycle {
    /// Operator-controlled desired intent.
    pub admin: AdminIntent,
    /// Health-/probe-driven live eligibility.
    pub eligibility: EligibilityState,
    /// Set iff `eligibility == TemporaryBypass`; explains the quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass_cause: Option<BypassFailureClass>,
}

impl WorkerLifecycle {
    /// A fresh, fully in-service worker: `Active` + `Healthy`.
    pub fn new() -> Self {
        Self {
            admin: AdminIntent::Active,
            eligibility: EligibilityState::Healthy,
            bypass_cause: None,
        }
    }

    /// Bridge from the legacy single-axis [`WorkerStatus`] so existing call
    /// sites can be migrated incrementally. Admin-intent statuses populate the
    /// admin axis with a `Healthy` eligibility; health statuses populate the
    /// eligibility axis with an `Active` intent.
    pub fn from_worker_status(status: WorkerStatus) -> Self {
        match status {
            WorkerStatus::Healthy => Self::new(),
            WorkerStatus::Degraded => Self {
                admin: AdminIntent::Active,
                eligibility: EligibilityState::Degraded,
                bypass_cause: None,
            },
            WorkerStatus::Unreachable => Self {
                admin: AdminIntent::Active,
                eligibility: EligibilityState::Unreachable,
                bypass_cause: None,
            },
            WorkerStatus::Draining => Self {
                admin: AdminIntent::Draining,
                eligibility: EligibilityState::Healthy,
                bypass_cause: None,
            },
            WorkerStatus::Drained => Self {
                admin: AdminIntent::Drained,
                eligibility: EligibilityState::Healthy,
                bypass_cause: None,
            },
            WorkerStatus::Disabled => Self {
                admin: AdminIntent::Disabled,
                eligibility: EligibilityState::Healthy,
                bypass_cause: None,
            },
        }
    }

    /// Collapse the two axes back to a legacy [`WorkerStatus`] for older
    /// status/JSON consumers. Admin intent takes precedence.
    ///
    /// Both transient quarantine states collapse to `Unreachable` so they stay
    /// EXCLUDED from the legacy scheduler (which treats `Degraded` as
    /// schedulable). In particular `RecoveredPendingCanary` must NOT become
    /// `Degraded`: the legacy scheduler would then route a normal build to a
    /// worker that is only cleared for a single canary build, violating the
    /// one-canary-first invariant that [`Self::is_schedulable`] enforces
    /// (bd-review-canary-legacy-status).
    pub fn legacy_status(&self) -> WorkerStatus {
        match self.admin {
            AdminIntent::Disabled => WorkerStatus::Disabled,
            AdminIntent::Draining => WorkerStatus::Draining,
            AdminIntent::Drained => WorkerStatus::Drained,
            AdminIntent::Active => match self.eligibility {
                EligibilityState::Healthy => WorkerStatus::Healthy,
                EligibilityState::Degraded => WorkerStatus::Degraded,
                // Unreachable, failure-class bypass, and canary-pending all stay
                // out of normal scheduling.
                EligibilityState::Unreachable
                | EligibilityState::TemporaryBypass
                | EligibilityState::RecoveredPendingCanary => WorkerStatus::Unreachable,
            },
        }
    }

    /// Whether the scheduler may route a *normal* build to this worker.
    ///
    /// True only when the operator intends it to be in service (`Active`) and
    /// its live eligibility is `Healthy` or `Degraded`. Unreachable, bypassed,
    /// and canary-pending workers are excluded from normal scheduling.
    pub fn is_schedulable(&self) -> bool {
        self.admin == AdminIntent::Active
            && matches!(
                self.eligibility,
                EligibilityState::Healthy | EligibilityState::Degraded
            )
    }

    /// Whether this worker may receive exactly one canary build (it recovered
    /// from a bypass and the operator still wants it in service). The canary
    /// build itself is driven by a later bead; this predicate gates it.
    pub fn is_canary_pending(&self) -> bool {
        self.admin == AdminIntent::Active
            && self.eligibility == EligibilityState::RecoveredPendingCanary
    }

    /// Apply an operator intent change. This is the *only* way the desired
    /// inventory axis moves; it never touches the eligibility axis.
    pub fn set_admin(&mut self, intent: AdminIntent) {
        self.admin = intent;
    }

    /// Record a plain health observation (`Healthy`/`Degraded`/`Unreachable`).
    ///
    /// Health observations move freely among the three plain health states but
    /// must NOT silently clear a quarantine: if the worker is currently
    /// `TemporaryBypass` or `RecoveredPendingCanary`, the observation is
    /// ignored and `false` is returned. Recovery happens only through the
    /// explicit probe/canary transitions.
    ///
    /// Returns `true` when the observation was applied. Passing a non-health
    /// state (`TemporaryBypass` / `RecoveredPendingCanary`) returns `false`
    /// without mutating; use [`Self::enter_bypass`] / [`Self::recover_to_canary`]
    /// for those.
    pub fn observe_health(&mut self, health: EligibilityState) -> bool {
        let is_plain_health = matches!(
            health,
            EligibilityState::Healthy | EligibilityState::Degraded | EligibilityState::Unreachable
        );
        let currently_quarantined = matches!(
            self.eligibility,
            EligibilityState::TemporaryBypass | EligibilityState::RecoveredPendingCanary
        );
        if !is_plain_health || currently_quarantined {
            return false;
        }
        self.eligibility = health;
        true
    }

    /// Quarantine the worker on the eligibility axis because a probe hit a
    /// concrete failure class. Legal from *any* eligibility state — a failure
    /// is a fact, including a failed canary (`RecoveredPendingCanary` relapses
    /// here) or an already-bypassed worker whose cause is being updated. Never
    /// mutates the admin axis — this is the core "transient failure ≠ desired
    /// inventory" invariant.
    pub fn enter_bypass(&mut self, cause: BypassFailureClass) {
        self.eligibility = EligibilityState::TemporaryBypass;
        self.bypass_cause = Some(cause);
    }

    /// Advance a bypassed worker to `RecoveredPendingCanary` after a successful
    /// recovery probe. Legal only from `TemporaryBypass`.
    pub fn recover_to_canary(&mut self) -> Result<(), IllegalLifecycleTransition> {
        if self.eligibility != EligibilityState::TemporaryBypass {
            return Err(IllegalLifecycleTransition {
                from: self.eligibility,
                to: EligibilityState::RecoveredPendingCanary,
                reason: "recovery to canary is only legal from temporary_bypass",
            });
        }
        self.eligibility = EligibilityState::RecoveredPendingCanary;
        self.bypass_cause = None;
        Ok(())
    }

    /// Fully rejoin a worker after a successful canary build. Legal only from
    /// `RecoveredPendingCanary`. Does not, and must not, change admin intent —
    /// an operator-disabled worker stays disabled even after a clean canary.
    pub fn promote_from_canary(&mut self) -> Result<(), IllegalLifecycleTransition> {
        if self.eligibility != EligibilityState::RecoveredPendingCanary {
            return Err(IllegalLifecycleTransition {
                from: self.eligibility,
                to: EligibilityState::Healthy,
                reason: "promotion is only legal from recovered_pending_canary",
            });
        }
        self.eligibility = EligibilityState::Healthy;
        self.bypass_cause = None;
        Ok(())
    }
}

/// Map a legacy health [`WorkerStatus`] to the eligibility axis for
/// [`WorkerLifecycle::observe_health`]. Administrative statuses
/// (`Draining`/`Drained`/`Disabled`) are not health observations and return
/// `None`, so the caller leaves the lifecycle untouched.
fn health_status_to_eligibility(status: WorkerStatus) -> Option<EligibilityState> {
    match status {
        WorkerStatus::Healthy => Some(EligibilityState::Healthy),
        WorkerStatus::Degraded => Some(EligibilityState::Degraded),
        WorkerStatus::Unreachable => Some(EligibilityState::Unreachable),
        WorkerStatus::Draining | WorkerStatus::Drained | WorkerStatus::Disabled => None,
    }
}

/// Whether a worker may accept a *new* slot reservation given its lifecycle.
///
/// Mirrors the pre-lifecycle `reserve_slots` admin guard (refuse
/// `Draining`/`Drained`/`Disabled`) and additionally refuses the transient
/// quarantine states so a bypassed or canary-pending worker can never have a
/// normal build land on it between selection and reservation. An `Unreachable`
/// but `Active` worker is intentionally still allowed here (unchanged from the
/// legacy guard); the selector already filters it out up front.
fn lifecycle_accepts_new_builds(lifecycle: WorkerLifecycle) -> bool {
    !matches!(
        lifecycle.admin,
        AdminIntent::Draining | AdminIntent::Drained | AdminIntent::Disabled
    ) && !matches!(
        lifecycle.eligibility,
        EligibilityState::TemporaryBypass | EligibilityState::RecoveredPendingCanary
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum DrainCompletionAction {
    #[default]
    StayDrained,
    /// The inventory removal itself requested this drain. Reintroducing the
    /// config may resume it only while no later operator action supersedes it.
    ResumeOnConfigReturn,
    Disable {
        reason: Option<String>,
    },
}

/// Transport recovery is independent of both operator intent and capability
/// quarantine. Current health checks and historical ownership recovery share
/// this state even after an endpoint leaves the configured inventory.
#[derive(Debug, Default)]
struct WorkerTransportState {
    failures: u32,
    down: bool,
    connected: bool,
    positive_evidence: Option<TransportProbeDeadline>,
    next_probe: Option<TransportProbeDeadline>,
}

#[derive(Debug, Clone)]
struct RecoveryTransportPolicy {
    circuit: CircuitBreakerConfig,
    normal_interval: Duration,
    probe_timeout: Duration,
}

impl Default for RecoveryTransportPolicy {
    fn default() -> Self {
        let health = crate::health::HealthConfig::default();
        Self {
            circuit: health.circuit,
            normal_interval: health.check_interval,
            probe_timeout: health.check_timeout,
        }
    }
}

/// A transport belongs to immutable connection coordinates, not a mutable
/// worker ID. Retargeting A -> B -> A must not reset A's outage clock or allow
/// cancellation and lease recovery to become independent outage probes.
#[derive(Debug)]
struct EndpointTransport {
    state: Mutex<WorkerTransportState>,
    probe: Arc<Mutex<()>>,
    recovery: Arc<Mutex<()>>,
    changes: watch::Sender<u64>,
}

impl EndpointTransport {
    fn new() -> Self {
        Self {
            state: Mutex::new(WorkerTransportState::default()),
            probe: Arc::new(Mutex::new(())),
            recovery: Arc::new(Mutex::new(())),
            changes: watch::channel(0).0,
        }
    }

    fn revision(&self) -> u64 {
        *self.changes.borrow()
    }

    fn revision_guard(&self) -> BackgroundProbe {
        let changes = self.changes.subscribe();
        let revision = *changes.borrow();
        BackgroundProbe {
            changes,
            revision,
            transport: None,
        }
    }

    fn revoke(&self) {
        self.changes
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }

    async fn reset(&self) {
        let mut state = self.state.lock().await;
        *state = WorkerTransportState::default();
        self.revoke();
    }

    async fn record_result(
        &self,
        connected: bool,
        normal_interval: Duration,
        circuit: &CircuitBreakerConfig,
    ) -> (bool, bool) {
        let mut state = self.state.lock().await;
        self.record_result_locked(&mut state, connected, normal_interval, circuit)
    }

    async fn record_probe_result(
        &self,
        network: &BackgroundProbe,
        connected: bool,
        normal_interval: Duration,
        circuit: &CircuitBreakerConfig,
    ) -> Option<(bool, bool)> {
        let mut state = self.state.lock().await;
        network
            .is_current()
            .then(|| self.record_result_locked(&mut state, connected, normal_interval, circuit))
    }

    fn record_result_locked(
        &self,
        state: &mut WorkerTransportState,
        connected: bool,
        normal_interval: Duration,
        circuit: &CircuitBreakerConfig,
    ) -> (bool, bool) {
        let was_down = state.down;
        state.connected = connected;
        state.positive_evidence = connected.then(|| TransportProbeDeadline::new(normal_interval));
        if connected {
            state.failures = 0;
            state.down = false;
        } else {
            state.failures = state.failures.saturating_add(1);
            state.down |= state.failures >= circuit.failure_threshold.max(1);
        }
        let down = state.down;
        if down || was_down {
            state.next_probe = Some(TransportProbeDeadline::new(if down {
                circuit.recovery_probe_interval()
            } else {
                normal_interval
            }));
        }
        if !connected {
            // All producers, including a current worker reintroduced during a
            // historical probe, lose their old network permission together.
            self.revoke();
        }
        (was_down, down)
    }

    async fn historical_recovery_eligible(&self) -> bool {
        if self.recovery.try_lock().is_err() {
            return false;
        }
        let state = self.state.lock().await;
        let due = state
            .next_probe
            .is_none_or(|deadline| deadline.remaining().is_zero());
        (state.connected
            && !state.down
            && state
                .positive_evidence
                .is_some_and(|evidence| !evidence.remaining().is_zero()))
            || (due && self.probe.try_lock().is_ok())
    }
}

#[derive(Debug, Default)]
struct EndpointTransports {
    endpoints: std::sync::Mutex<HashMap<WorkerEndpointIdentity, Arc<EndpointTransport>>>,
}

impl EndpointTransports {
    fn get(&self, config: &WorkerConfig) -> Arc<EndpointTransport> {
        let identity = WorkerEndpointIdentity::from_config(config);
        let mut endpoints = self
            .endpoints
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(transport) = endpoints.get(&identity) {
            return transport.clone();
        }
        // A failed or unproven endpoint must retain its threshold and slow
        // cadence even once the next probe becomes due. Only expired positive
        // evidence with no worker/operation owner is safe to forget.
        endpoints.retain(|_, transport| {
            if Arc::strong_count(transport) != 1 {
                return true;
            }
            let Ok(state) = transport.state.try_lock() else {
                return true;
            };
            !(state.connected
                && !state.down
                && state.failures == 0
                && state
                    .positive_evidence
                    .is_some_and(|evidence| evidence.remaining().is_zero()))
        });
        endpoints
            .entry(identity)
            .or_insert_with(|| Arc::new(EndpointTransport::new()))
            .clone()
    }
}

/// Store elapsed-time arithmetic instead of adding an operator-supplied u64
/// duration to Instant. Overflow must never turn a long interval into a probe
/// that appears immediately due.
#[derive(Debug, Clone, Copy)]
struct TransportProbeDeadline {
    started_at: tokio::time::Instant,
    interval: Duration,
}

impl TransportProbeDeadline {
    fn new(interval: Duration) -> Self {
        Self {
            started_at: tokio::time::Instant::now(),
            interval,
        }
    }

    fn remaining(self) -> Duration {
        self.interval.saturating_sub(self.started_at.elapsed())
    }
}

/// Revocable permission for background network I/O. A disable, outage or
/// endpoint replacement cancels the future (and its owned SSH child) rather
/// than letting a queued operation dial after the operator's acknowledgement.
#[derive(Debug, Clone)]
pub(crate) struct BackgroundProbe {
    changes: watch::Receiver<u64>,
    revision: u64,
    transport: Option<(watch::Receiver<u64>, u64)>,
}

impl BackgroundProbe {
    pub(crate) fn is_current(&self) -> bool {
        *self.changes.borrow() == self.revision
            && self
                .transport
                .as_ref()
                .is_none_or(|(changes, revision)| *changes.borrow() == *revision)
    }

    pub(crate) async fn run<F: std::future::Future>(&mut self, operation: F) -> Option<F::Output> {
        if !self.is_current() {
            return None;
        }
        let result = tokio::select! {
            biased;
            _ = self.changes.changed() => None,
            () = async {
                match &mut self.transport {
                    Some((changes, _)) => { let _ = changes.changed().await; }
                    None => std::future::pending().await,
                }
            } => None,
            result = operation => Some(result),
        };
        self.is_current().then_some(result).flatten()
    }
}

pub(crate) struct HealthProbePermit {
    pub(crate) network: BackgroundProbe,
    pub(crate) endpoint: WorkerEndpointSnapshot,
    /// Recovery uses a fresh, bounded connection rather than reviving either
    /// warm pool before the worker has proved it can run a command.
    pub(crate) isolated: bool,
    transport: Arc<EndpointTransport>,
    _singleflight: OwnedMutexGuard<()>,
}

/// Speculative admission is side-effect free. The operation lane and any due
/// historical probe are claimed only when `run` is polled under the caller's
/// stable worker-ID administrative permit.
pub(crate) struct OwnedRecoveryPermit {
    endpoint: WorkerConfig,
    transport: Arc<EndpointTransport>,
    policy: RecoveryTransportPolicy,
    current: Option<BackgroundProbe>,
    health_changes: watch::Sender<u64>,
}

/// The health monitor may have skipped a reintroduced endpoint while its
/// historical probe held this lane. Wake it after releasing the mutex even
/// when the probe future is cancelled, without resetting the shared deadline.
struct HistoricalProbeFlight {
    singleflight: Option<OwnedMutexGuard<()>>,
    health_changes: watch::Sender<u64>,
}

impl Drop for HistoricalProbeFlight {
    fn drop(&mut self) {
        // Notify only once the monitor can acquire the lane; notifying first
        // could make it observe a busy lane and sleep through the next probe.
        drop(self.singleflight.take());
        self.health_changes
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }
}

impl OwnedRecoveryPermit {
    pub(crate) async fn run<F: std::future::Future>(&mut self, operation: F) -> Option<F::Output> {
        let endpoint = self.endpoint.clone();
        let timeout = self.policy.probe_timeout;
        self.run_with_probe(
            operation,
            crate::health::probe_owned_recovery_transport(&endpoint, timeout),
        )
        .await
    }

    async fn run_with_probe<F: std::future::Future, P: std::future::Future<Output = bool>>(
        &mut self,
        operation: F,
        probe: P,
    ) -> Option<F::Output> {
        let _operation = self.transport.recovery.clone().try_lock_owned().ok()?;
        if let Some(current) = &mut self.current {
            if !current.is_current() || self.transport.state.lock().await.down {
                return None;
            }
            return current.run(operation).await;
        }

        let mut network = self.transport.revision_guard();
        let needs_probe = {
            let state = self.transport.state.lock().await;
            !(state.connected
                && !state.down
                && state
                    .positive_evidence
                    .is_some_and(|evidence| !evidence.remaining().is_zero()))
        };
        if needs_probe {
            let flight = HistoricalProbeFlight {
                singleflight: Some(self.transport.probe.clone().try_lock_owned().ok()?),
                health_changes: self.health_changes.clone(),
            };
            {
                let mut state = self.transport.state.lock().await;
                if state
                    .next_probe
                    .is_some_and(|deadline| !deadline.remaining().is_zero())
                {
                    return None;
                }
                // Reserve the next probe before any SSH work, including the
                // local capability check. Aborting this future cannot grant
                // unchecked recovery or move the next attempt earlier.
                state.connected = false;
                state.positive_evidence = None;
                state.next_probe = Some(TransportProbeDeadline::new(if state.down {
                    self.policy.circuit.recovery_probe_interval()
                } else {
                    self.policy.normal_interval
                }));
            }
            let connected = network.run(probe).await?;
            self.transport
                .record_probe_result(
                    &network,
                    connected,
                    self.policy.normal_interval,
                    &self.policy.circuit,
                )
                .await?;
            if !connected {
                return None;
            }
            drop(flight);
        }
        network.run(operation).await
    }
}

/// State of a single worker.
#[derive(Debug)]
pub struct WorkerState {
    id: WorkerId,
    /// Worker configuration.
    pub config: RwLock<WorkerConfig>,
    /// Runtime-only identity: restored ownership must not reuse a generation
    /// from another daemon lifetime or a removed and reintroduced worker.
    endpoint_incarnation: Arc<WorkerEndpointIncarnation>,
    /// Authoritative worker lifecycle — the two-axis (admin intent + live
    /// eligibility) model from [`WorkerLifecycle`].
    ///
    /// **Single source of truth.** The legacy single-axis [`WorkerStatus`] is
    /// *derived* from this via [`WorkerLifecycle::legacy_status`] (see
    /// [`Self::status`]); there is no separate status field that could disagree.
    /// Both transient quarantine states (`TemporaryBypass` /
    /// `RecoveredPendingCanary`) collapse to `Unreachable` for every legacy
    /// consumer, so a bypassed or canary-pending worker stays out of the
    /// scheduler automatically with no extra bookkeeping.
    lifecycle: RwLock<WorkerLifecycle>,
    transport: std::sync::RwLock<Arc<EndpointTransport>>,
    endpoint_transports: Arc<EndpointTransports>,
    connection_ready: AtomicBool,
    ready_transport_revision: AtomicU64,
    network_changes: watch::Sender<u64>,
    network_transition: Mutex<()>,
    /// Both daemon SSH pools obey the same worker lifecycle. Keeping their
    /// registrations on the worker also covers disables outside the HTTP API.
    ssh_pools: RwLock<Vec<Arc<rch_common::SshPool>>>,
    /// Number of slots currently in use.
    used_slots: Arc<AtomicU32>,
    /// Speed score from benchmarking (0-100).
    ///
    /// **Why atomic:** Read on every worker selection decision (hot path). RwLock's
    /// ~25ns overhead per acquire multiplied by N workers is measurable; AtomicU64
    /// load compiles to a single MOV instruction (~1ns).
    ///
    /// **Bit-casting:** `f64` is stored as `u64` via `f64::to_bits`/`f64::from_bits`.
    /// This is a zero-cost transmute that preserves all IEEE 754 values including
    /// NaN, infinity, and negative zero.
    ///
    /// **Ordering:** `Relaxed` — speed_score is a statistical performance hint, not
    /// a correctness-critical flag. Stale reads produce slightly suboptimal worker
    /// selection, never incorrect behavior. No happens-before dependency with other
    /// fields (status transitions use RwLock which provides its own ordering).
    pub speed_score: AtomicU64,
    /// Last observed worker latency in milliseconds (from health checks).
    ///
    /// **Why atomic:** Same hot-path rationale as `speed_score`.
    ///
    /// **Sentinel:** `0` encodes `None` (latency of exactly 0ms is not meaningful
    /// in practice). Use `last_latency_ms()` accessor which returns `Option<u64>`.
    ///
    /// **Ordering:** `Relaxed` — advisory diagnostic value with no ordering
    /// dependency. See `speed_score` rationale.
    last_latency_ms: AtomicU64,
    /// Projects cached on this worker.
    pub cached_projects: RwLock<Vec<String>>,
    /// Circuit breaker statistics.
    circuit: RwLock<CircuitStats>,
    /// Last error message.
    last_error_msg: RwLock<Option<String>>,
    /// Runtime capabilities (Bun, Node, Rust versions).
    capabilities: RwLock<WorkerCapabilities>,
    disk_capacity_generation: Arc<AtomicU64>,
    disk_capacity_observation: RwLock<Option<DiskCapacityObservation>>,
    /// Serialize daemon-side capability requests from health, operators and selection.
    capability_probe: tokio::sync::Mutex<()>,
    /// Cached per-toolchain preflight verdicts.
    toolchain_preflight: RwLock<HashMap<String, ToolchainPreflightStatus>>,
    /// Latest daemon-side pressure policy assessment for this worker.
    pressure_assessment: RwLock<PressureAssessment>,
    /// Disk budget shared by all workers created by the same daemon pool.
    disk_slot_policy: DiskSlotPolicy,
    /// Until this instant, a worker with no disk capacity sample gets no
    /// slots. `None` (tests, embedded pools) keeps the configured ceiling.
    unmeasured_capacity_hold_until: std::sync::Mutex<Option<std::time::Instant>>,
    /// Reason for disabling this worker (if disabled).
    disabled_reason: RwLock<Option<String>>,
    /// Administrative intent to apply when a draining worker reaches zero slots.
    drain_completion: RwLock<DrainCompletionAction>,
    /// Inventory removal is independent of operator intent. A disabled worker
    /// must remain dormant while its owned slots drain, yet still be removable
    /// once they are released. Mutations serialize under `network_transition`.
    removal_pending: AtomicBool,
    /// Unix timestamp (seconds since epoch) when worker was disabled.
    ///
    /// **Why atomic:** Queried during worker selection to skip disabled workers.
    ///
    /// **Sentinel:** `0` encodes `None` (no disable event). Use `disabled_at()`
    /// accessor which returns `Option<i64>`.
    ///
    /// **Ordering:** `Relaxed` — diagnostic timestamp set alongside `status`
    /// (RwLock) and `disabled_reason` (RwLock). The RwLock transitions provide
    /// happens-before ordering for the authoritative disabled state; this timestamp
    /// is supplementary. Briefly stale reads are acceptable for display purposes.
    disabled_at: AtomicI64,
}

pub(crate) struct CapabilityProbeContext {
    pub config: WorkerConfig,
    started_at: Instant,
    generation: u64,
    network_revision: u64,
}

/// Configuration and identity of the endpoint a network operation actually used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WorkerEndpointSnapshot {
    pub config: WorkerConfig,
    #[serde(skip)]
    pub generation: u64,
    #[serde(skip)]
    incarnation: Option<Arc<WorkerEndpointIncarnation>>,
}

#[derive(Debug)]
struct WorkerEndpointIncarnation {
    generation: AtomicU64,
    retired: AtomicBool,
}

/// Stable coordinates used by durable filesystem obligations. CPU capacity
/// and descriptive tags do not change the filesystem that failed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkerEndpointIdentity {
    pub id: WorkerId,
    pub host: String,
    pub user: String,
    pub identity_file: String,
    pub declared_os: Option<String>,
}

impl WorkerEndpointIdentity {
    pub(crate) fn from_config(config: &WorkerConfig) -> Self {
        Self {
            id: config.id.clone(),
            host: config.host.clone(),
            user: config.user.clone(),
            identity_file: config.identity_file.clone(),
            declared_os: rch_common::declared_os(&config.tags),
        }
    }

    pub(crate) fn matches_config(&self, config: &WorkerConfig) -> bool {
        self.id == config.id
            && self.host == config.host
            && self.user == config.user
            && self.identity_file == config.identity_file
            && self.declared_os == rch_common::declared_os(&config.tags)
    }
}

impl WorkerEndpointSnapshot {
    pub(crate) fn has_runtime_identity(&self) -> bool {
        self.incarnation.is_some()
    }

    /// Retain a known retarget in durable decisions before process-local
    /// generation evidence is lost on restart. Retirement alone is not a
    /// retarget: the same filesystem may return after inventory removal.
    pub(crate) fn source_was_retargeted(&self) -> bool {
        self.incarnation.as_ref().is_some_and(|incarnation| {
            self.generation != incarnation.generation.load(Ordering::Acquire)
        })
    }
}

fn same_endpoint(left: &WorkerConfig, right: &WorkerConfig) -> bool {
    left.id == right.id
        && left.host == right.host
        && left.user == right.user
        && left.identity_file == right.identity_file
        && rch_common::declared_os(&left.tags) == rch_common::declared_os(&right.tags)
}

impl WorkerState {
    /// Create a new worker state from configuration.
    pub fn new(config: WorkerConfig) -> Self {
        Self::with_disk_slot_policy(
            config,
            DiskSlotPolicy::from(&rch_common::SelectionConfig::default()),
        )
    }

    fn with_disk_slot_policy(config: WorkerConfig, disk_slot_policy: DiskSlotPolicy) -> Self {
        Self::with_endpoint_transports(
            config,
            disk_slot_policy,
            Arc::new(EndpointTransports::default()),
        )
    }

    fn with_endpoint_transports(
        config: WorkerConfig,
        disk_slot_policy: DiskSlotPolicy,
        endpoint_transports: Arc<EndpointTransports>,
    ) -> Self {
        let transport = endpoint_transports.get(&config);
        Self {
            id: config.id.clone(),
            config: RwLock::new(config),
            endpoint_incarnation: Arc::new(WorkerEndpointIncarnation {
                generation: AtomicU64::new(0),
                retired: AtomicBool::new(false),
            }),
            lifecycle: RwLock::new(WorkerLifecycle::new()),
            transport: std::sync::RwLock::new(transport),
            endpoint_transports,
            connection_ready: AtomicBool::new(true),
            ready_transport_revision: AtomicU64::new(0),
            network_changes: watch::channel(0).0,
            network_transition: Mutex::new(()),
            ssh_pools: RwLock::new(Vec::new()),
            used_slots: Arc::new(AtomicU32::new(0)),
            speed_score: AtomicU64::new(50.0_f64.to_bits()), // Default mid-range score
            last_latency_ms: AtomicU64::new(0),
            cached_projects: RwLock::new(Vec::new()),
            circuit: RwLock::new(CircuitStats::new()),
            last_error_msg: RwLock::new(None),
            capabilities: RwLock::new(WorkerCapabilities::new()),
            disk_capacity_generation: Arc::new(AtomicU64::new(0)),
            disk_capacity_observation: RwLock::new(None),
            capability_probe: tokio::sync::Mutex::new(()),
            toolchain_preflight: RwLock::new(HashMap::new()),
            pressure_assessment: RwLock::new(PressureAssessment::default()),
            disk_slot_policy,
            unmeasured_capacity_hold_until: std::sync::Mutex::new(None),
            disabled_reason: RwLock::new(None),
            drain_completion: RwLock::new(DrainCompletionAction::default()),
            removal_pending: AtomicBool::new(false),
            disabled_at: AtomicI64::new(0),
        }
    }

    fn revoke_background_network(&self) {
        self.network_changes
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }

    fn transport(&self) -> Arc<EndpointTransport> {
        self.transport
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn connection_is_ready(&self) -> bool {
        self.connection_ready.load(Ordering::Acquire)
            && self.ready_transport_revision.load(Ordering::Acquire) == self.transport().revision()
    }

    pub(crate) fn require_connection_probe(&self) {
        self.connection_ready.store(false, Ordering::Release);
        self.revoke_background_network();
    }

    async fn admin_allows_network(&self) -> bool {
        let admin = self.lifecycle.read().await.admin;
        !matches!(admin, AdminIntent::Disabled | AdminIntent::Drained)
            && !matches!(
                *self.drain_completion.read().await,
                DrainCompletionAction::Disable { .. }
            )
            && !self.is_endpoint_retired()
    }

    pub(crate) async fn background_network_allowed(&self) -> bool {
        self.connection_is_ready() && self.admin_allows_network().await
    }

    pub(crate) async fn background_probe(&self) -> Option<BackgroundProbe> {
        let permit = self.network_revision_guard();
        (self.background_network_allowed().await && permit.is_current()).then_some(permit)
    }

    /// Capture cancellation only. Recovery of a recorded orphan may use this
    /// after independently validating its durable evidence; it does not grant
    /// permission to probe an administratively disabled worker.
    pub(crate) fn network_revision_guard(&self) -> BackgroundProbe {
        let changes = self.network_changes.subscribe();
        let revision = *changes.borrow();
        let transport_changes = self.transport().changes.subscribe();
        let transport_revision = *transport_changes.borrow();
        BackgroundProbe {
            changes,
            revision,
            transport: Some((transport_changes, transport_revision)),
        }
    }

    /// Fence publication against disable/enable ABA. Endpoint guards protect
    /// retargeting; this short-lived lock protects the administrative epoch.
    /// Lock order: endpoint/config, then network publication; never hold it
    /// during network I/O.
    pub(crate) async fn lock_network_publication(
        &self,
        permit: &BackgroundProbe,
    ) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        let guard = self.network_transition.lock().await;
        permit.is_current().then_some(guard)
    }

    pub(crate) async fn transport_is_down(&self) -> bool {
        self.transport().state.lock().await.down
    }

    pub(crate) async fn next_health_probe_in(&self) -> Option<Duration> {
        let transport = self.transport();
        if !self.admin_allows_network().await || transport.probe.try_lock().is_err() {
            return None;
        }
        Some(
            transport
                .state
                .lock()
                .await
                .next_probe
                .map_or(Duration::ZERO, TransportProbeDeadline::remaining),
        )
    }

    pub(crate) async fn attach_ssh_pool(&self, pool: Arc<rch_common::SshPool>) {
        let _transition = self.network_transition.lock().await;
        let enabled = self.background_network_allowed().await;
        pool.set_worker_enabled(&self.id, enabled).await;
        self.ssh_pools.write().await.push(pool);
    }

    async fn set_pooled_connections_enabled(&self, enabled: bool) {
        let pools = self.ssh_pools.read().await.clone();
        for pool in pools {
            pool.set_worker_enabled(&self.id, enabled).await;
        }
    }

    /// Claim one due health check. The deadline is set on admission as well as
    /// completion so cancellation cannot turn a slow recovery cadence into a
    /// retry storm. Different workers never wait for this worker's lock.
    pub(crate) async fn health_probe_permit(
        &self,
        normal_interval: Duration,
        circuit: &CircuitBreakerConfig,
    ) -> Option<HealthProbePermit> {
        let config = self.config.read().await;
        let transport = self.transport();
        let singleflight = transport.probe.clone().try_lock_owned().ok()?;
        let network = self.network_revision_guard();
        if !self.admin_allows_network().await || !network.is_current() {
            return None;
        }
        let mut state = transport.state.lock().await;
        if state
            .next_probe
            .is_some_and(|deadline| !deadline.remaining().is_zero())
        {
            return None;
        }
        let delay = if state.down {
            circuit.recovery_probe_interval()
        } else {
            normal_interval
        };
        state.next_probe = Some(TransportProbeDeadline::new(delay));
        drop(state);
        Some(HealthProbePermit {
            network,
            endpoint: WorkerEndpointSnapshot {
                config: config.clone(),
                generation: self.endpoint_incarnation.generation.load(Ordering::Acquire),
                incarnation: Some(self.endpoint_incarnation.clone()),
            },
            isolated: !self.connection_is_ready(),
            transport,
            _singleflight: singleflight,
        })
    }

    /// Apply connection-stage evidence only. Command/storage failures remain
    /// governed by the existing circuit and bypass policy. A successful full
    /// health command restores transport service on its first recovery probe.
    pub(crate) async fn record_transport_result(
        &self,
        connected: bool,
        normal_interval: Duration,
        circuit: &CircuitBreakerConfig,
    ) -> (bool, bool) {
        self.record_transport_result_for(&self.transport(), connected, normal_interval, circuit)
            .await
    }

    /// The health task owns the governor it actually probed. Its publication
    /// must never follow a mutable worker ID to a replacement endpoint.
    pub(crate) async fn record_health_transport_result(
        &self,
        permit: &HealthProbePermit,
        connected: bool,
        normal_interval: Duration,
        circuit: &CircuitBreakerConfig,
    ) -> Option<(bool, bool)> {
        if !permit.network.is_current() || !Arc::ptr_eq(&self.transport(), &permit.transport) {
            return None;
        }
        Some(
            self.record_transport_result_for(
                &permit.transport,
                connected,
                normal_interval,
                circuit,
            )
            .await,
        )
    }

    async fn record_transport_result_for(
        &self,
        transport: &EndpointTransport,
        connected: bool,
        normal_interval: Duration,
        circuit: &CircuitBreakerConfig,
    ) -> (bool, bool) {
        let (was_down, down) = transport
            .record_result(connected, normal_interval, circuit)
            .await;
        if connected {
            // Do not reopen pools after a disable that raced the completed
            // probe. The health publisher also fences its network generation.
            let lifecycle = self.lifecycle.read().await;
            if !matches!(
                lifecycle.admin,
                AdminIntent::Disabled | AdminIntent::Drained
            ) && !matches!(
                *self.drain_completion.read().await,
                DrainCompletionAction::Disable { .. }
            ) && !self.is_endpoint_retired()
            {
                self.ready_transport_revision
                    .store(transport.revision(), Ordering::Release);
                self.connection_ready.store(true, Ordering::Release);
                self.set_pooled_connections_enabled(true).await;
            }
        } else {
            self.connection_ready.store(false, Ordering::Release);
            self.revoke_background_network();
            self.set_pooled_connections_enabled(false).await;
        }
        (was_down, down)
    }

    /// Snapshot the endpoint without retaining a configuration lock during I/O.
    pub(crate) async fn endpoint_snapshot(&self) -> WorkerEndpointSnapshot {
        let config = self.config.read().await;
        WorkerEndpointSnapshot {
            config: config.clone(),
            generation: self.endpoint_incarnation.generation.load(Ordering::Acquire),
            incarnation: Some(Arc::clone(&self.endpoint_incarnation)),
        }
    }

    /// Fence publication against retargeting, including an A -> B -> A change.
    /// Hold the returned guard only for local state updates, never network I/O
    /// or a method that reacquires `config`.
    pub(crate) async fn lock_current_endpoint(
        &self,
        snapshot: &WorkerEndpointSnapshot,
    ) -> Option<RwLockReadGuard<'_, WorkerConfig>> {
        let config = self.config.read().await;
        (!self.endpoint_incarnation.retired.load(Ordering::Acquire)
            && snapshot
                .incarnation
                .as_ref()
                .is_some_and(|incarnation| Arc::ptr_eq(incarnation, &self.endpoint_incarnation))
            && snapshot.generation == self.endpoint_incarnation.generation.load(Ordering::Acquire)
            && same_endpoint(&config, &snapshot.config))
        .then_some(config)
    }

    /// Durable filesystem failures survive daemon restart and inventory
    /// removal. A live retarget invalidates their publication, including ABA.
    /// A retired incarnation that never retargeted may resume its deferred
    /// obligation on matching coordinates; this does not authorize health or
    /// cache feedback from the old build.
    pub(crate) async fn lock_disk_fault_endpoint(
        &self,
        identity: &WorkerEndpointIdentity,
        runtime: Option<&WorkerEndpointSnapshot>,
    ) -> Option<RwLockReadGuard<'_, WorkerConfig>> {
        let config = self.config.read().await;
        let runtime_matches = runtime.is_none_or(|snapshot| {
            snapshot.incarnation.as_ref().is_some_and(|incarnation| {
                snapshot.generation == incarnation.generation.load(Ordering::Acquire)
                    && (Arc::ptr_eq(incarnation, &self.endpoint_incarnation)
                        || incarnation.retired.load(Ordering::Acquire))
            })
        });
        (!self.endpoint_incarnation.retired.load(Ordering::Acquire)
            && identity.matches_config(&config)
            && runtime_matches)
            .then_some(config)
    }

    pub(crate) fn is_endpoint_retired(&self) -> bool {
        self.endpoint_incarnation.retired.load(Ordering::Acquire)
    }

    /// Pool removal uses workers -> config order. A publication that already
    /// holds this config lock finishes before removal; one waiting elsewhere
    /// can never credit the ID after a replacement is installed.
    async fn retire_endpoint(&self) {
        let _config = self.config.write().await;
        let _transition = self.network_transition.lock().await;
        self.endpoint_incarnation
            .retired
            .store(true, Ordering::Release);
        self.require_connection_probe();
        self.set_pooled_connections_enabled(false).await;
    }

    /// Update configuration, returning whether health/recovery monitors need
    /// to wake for a new endpoint or a resumed inventory drain. Resuming the
    /// same endpoint preserves its existing transport recovery deadline.
    pub async fn update_config(&self, new_config: WorkerConfig) -> bool {
        let mut config = self.config.write().await;
        let _transition = self.network_transition.lock().await;
        let endpoint_changed = !same_endpoint(&config, &new_config);
        self.disk_capacity_generation.fetch_add(1, Ordering::AcqRel);
        if endpoint_changed {
            self.require_connection_probe();
            *self
                .transport
                .write()
                .unwrap_or_else(|error| error.into_inner()) =
                self.endpoint_transports.get(&new_config);
            self.set_pooled_connections_enabled(false).await;
            self.endpoint_incarnation
                .generation
                .fetch_add(1, Ordering::AcqRel);
            // Observations of the previous host/key/OS cannot condemn (or
            // qualify) its replacement. Preserve build ownership and the
            // operator's administrative intent, including an active bypass.
            *self.circuit.write().await = CircuitStats::new();
            *self.last_error_msg.write().await = None;
            self.last_latency_ms.store(0, Ordering::Relaxed);
            self.cached_projects.write().await.clear();
            self.toolchain_preflight.write().await.clear();
            *self.capabilities.write().await = WorkerCapabilities::new();
            *self.disk_capacity_observation.write().await = None;
            *self.pressure_assessment.write().await = PressureAssessment::default();
            self.lifecycle
                .write()
                .await
                .observe_health(EligibilityState::Unreachable);
        }
        *config = new_config;

        let resume_inventory_drain = {
            let removed = self.removal_pending.swap(false, Ordering::AcqRel);
            let mut completion = self.drain_completion.write().await;
            let resume = removed && *completion == DrainCompletionAction::ResumeOnConfigReturn;
            if resume {
                *completion = DrainCompletionAction::StayDrained;
            }
            resume
        };

        if resume_inventory_drain {
            {
                let mut lifecycle = self.lifecycle.write().await;
                if matches!(
                    lifecycle.admin,
                    AdminIntent::Draining | AdminIntent::Drained
                ) {
                    lifecycle.set_admin(AdminIntent::Active);
                }
            }
            self.set_pooled_connections_enabled(self.background_network_allowed().await)
                .await;
        }
        endpoint_changed || resume_inventory_drain
    }

    /// Get the current worker status as the legacy single-axis [`WorkerStatus`].
    ///
    /// This is a *derived* view of the authoritative [`WorkerLifecycle`]: both
    /// quarantine states (`TemporaryBypass` / `RecoveredPendingCanary`) collapse
    /// to [`WorkerStatus::Unreachable`], so a bypassed worker is excluded from
    /// the legacy scheduler with no separate bookkeeping.
    pub async fn status(&self) -> WorkerStatus {
        self.lifecycle.read().await.legacy_status()
    }

    /// Get a copy of the authoritative two-axis [`WorkerLifecycle`].
    pub async fn lifecycle(&self) -> WorkerLifecycle {
        *self.lifecycle.read().await
    }

    /// Get the live scheduler-eligibility axis.
    pub async fn eligibility(&self) -> EligibilityState {
        self.lifecycle.read().await.eligibility
    }

    /// Set worker status from the legacy single-axis [`WorkerStatus`].
    ///
    /// Bridges through [`WorkerLifecycle::from_worker_status`]. This is a legacy
    /// setter for status-API and test call sites; the lifecycle-aware paths
    /// ([`Self::enter_bypass`], [`Self::recover_to_canary`],
    /// [`Self::promote_from_canary`], [`Self::apply_health_status`]) move the
    /// two axes independently and must be used for quarantine/recovery.
    pub async fn set_status(&self, status: WorkerStatus) {
        if status == WorkerStatus::Disabled {
            self.disable(None).await;
            return;
        }
        *self.lifecycle.write().await = WorkerLifecycle::from_worker_status(status);
    }

    /// Apply a health-derived status without overriding administrative lifecycle
    /// states *or* an active quarantine.
    ///
    /// Health probes may mark a worker healthy/degraded/unreachable, but they
    /// must not revive workers that are intentionally `Draining`, `Drained`, or
    /// `Disabled` (admin axis), and — critically for auto-rejoin safety — they
    /// must NOT clear a `TemporaryBypass` / `RecoveredPendingCanary` quarantine.
    /// Only the recovery probe/canary loop may do that. The observation routes
    /// through [`WorkerLifecycle::observe_health`], which refuses to overwrite a
    /// quarantine, so a single lucky health check can never auto-rejoin a
    /// bypassed worker. Returns the resulting legacy [`WorkerStatus`].
    pub async fn apply_health_status(&self, health_status: WorkerStatus) -> WorkerStatus {
        let mut lifecycle = self.lifecycle.write().await;
        if let Some(eligibility) = health_status_to_eligibility(health_status) {
            lifecycle.observe_health(eligibility);
        }
        lifecycle.legacy_status()
    }

    /// Quarantine this worker into [`EligibilityState::TemporaryBypass`] because
    /// a probe hit a concrete failure `class`. Never touches the admin axis
    /// (transient failure ≠ desired inventory). The worker immediately drops out
    /// of scheduling — its [`Self::status`] reads `Unreachable` — and stays out
    /// until the recovery probe/canary loop clears it.
    pub async fn enter_bypass(&self, class: BypassFailureClass) {
        self.lifecycle.write().await.enter_bypass(class);
    }

    /// Advance a bypassed worker to [`EligibilityState::RecoveredPendingCanary`]
    /// after a fully-healthy recovery-probe streak. Legal only from
    /// `TemporaryBypass`.
    pub async fn recover_to_canary(&self) -> Result<(), IllegalLifecycleTransition> {
        self.lifecycle.write().await.recover_to_canary()
    }

    /// Fully rejoin a worker after a passing canary build. Legal only from
    /// `RecoveredPendingCanary`; never changes admin intent (an
    /// operator-disabled worker stays disabled even after a clean canary).
    pub async fn promote_from_canary(&self) -> Result<(), IllegalLifecycleTransition> {
        self.lifecycle.write().await.promote_from_canary()
    }

    /// Whether this worker is cleared for exactly one canary build.
    pub async fn is_canary_pending(&self) -> bool {
        self.lifecycle.read().await.is_canary_pending()
    }

    /// Configured ceiling reduced by current disk headroom.
    pub async fn effective_total_slots(&self) -> u32 {
        let config = self.config.read().await;
        let pressure = self.pressure_assessment.read().await;
        self.slots_for(config.total_slots, &pressure)
    }

    /// Hold this worker at zero slots until its first disk capacity sample,
    /// or until `hold` elapses, whichever comes first.
    pub(crate) fn hold_until_capacity_measured(&self, hold: std::time::Duration) {
        *self
            .unmeasured_capacity_hold_until
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = std::time::Instant::now().checked_add(hold);
    }

    /// Disk-derated slots. A restarted daemon knows no worker's disk until the
    /// first capability probe lands, and `effective_slots` then grants the full
    /// configured ceiling. On 2026-10-16 a drain-restart of every dispatcher
    /// re-added a 193 GB worker with 12 GB free at its full 3 slots; one mtdt
    /// source sync was admitted and filled the disk to 0. While the hold is
    /// active, an unmeasured worker gets no slots. A worker whose telemetry
    /// never arrives keeps the previous fail-open ceiling after the hold.
    fn slots_for(&self, configured: u32, pressure: &PressureAssessment) -> u32 {
        let measured = pressure
            .capacity_free_gb()
            .is_some_and(|free| free.is_finite());
        let held = !measured
            && self
                .unmeasured_capacity_hold_until
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some_and(|until| std::time::Instant::now() < until);
        if held {
            return 0;
        }
        self.disk_slot_policy.effective_slots(configured, pressure)
    }

    /// Available slots after disk derating and existing reservations.
    pub async fn available_slots(&self) -> u32 {
        let total = self.effective_total_slots().await;
        let used = self.used_slots.load(Ordering::Relaxed);
        total.saturating_sub(used)
    }

    /// Continuous disk-headroom credit using the same floor as slot admission.
    pub async fn disk_headroom(&self) -> f64 {
        let assessment = self.pressure_assessment.read().await;
        self.disk_slot_policy.headroom(&assessment)
    }

    /// Reserve slots for a job. Returns true if successful.
    ///
    /// Re-reads disk capacity on each CAS iteration and keeps the config and
    /// pressure snapshot locked through the reservation to avoid overallocation.
    ///
    /// Also re-checks status on each iteration and refuses reservations on
    /// workers that are `Draining`, `Drained`, or `Disabled`. The selector
    /// filters by `healthy_workers()` up-front, but between that filter and
    /// this CAS an operator may run `rch workers drain`, which would
    /// otherwise let a new build land on a worker that was just asked to
    /// stop accepting work — defeating the entire drain contract.
    pub async fn reserve_slots(&self, count: u32) -> bool {
        if count == 0 {
            return false;
        }

        let mut current = self.used_slots.load(Ordering::Relaxed);
        loop {
            // Re-read the lifecycle on each iteration so a concurrent `drain()`
            // / `disable()` (admin axis) or a freshly-entered `TemporaryBypass`
            // / `RecoveredPendingCanary` quarantine (eligibility axis) becomes
            // authoritative as soon as it's written, not only on the next
            // selection round.
            if !self.connection_is_ready()
                || !lifecycle_accepts_new_builds(*self.lifecycle.read().await)
            {
                return false;
            }
            let config = self.config.read().await;
            let pressure = self.pressure_assessment.read().await;
            let total_slots = self.slots_for(config.total_slots, &pressure);
            let Some(next) = current.checked_add(count) else {
                return false;
            };
            if next > total_slots {
                return false;
            }
            let reserved = self.used_slots.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
            drop(pressure);
            drop(config);
            match reserved {
                Ok(_) => {
                    // TOCTOU defense: re-check the lifecycle after a successful
                    // slot reservation. If a concurrent drain()/disable() or a
                    // bypass quarantine landed between our initial read and the
                    // CAS, roll the reservation back.
                    if lifecycle_accepts_new_builds(*self.lifecycle.read().await)
                        && self.connection_is_ready()
                        && self.used_slots() <= self.effective_total_slots().await
                    {
                        return true;
                    }
                    // Roll back the reservation; release_slots also handles
                    // transitioning Draining -> Drained if this was the last slot.
                    self.release_slots(count).await;
                    return false;
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Release slots after a job completes.
    ///
    /// If the worker is in `Draining` state and all slots are now free,
    /// automatically transitions to `Drained` state.
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

        // Check if draining worker should transition to drained
        self.check_drain_complete().await;
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
            // Limit cache size to prevent unbounded growth
            if cache.len() >= 100 {
                cache.remove(0);
            }
            cache.push(project);
        }
    }

    /// Update the speed score.
    pub fn set_speed_score(&self, score: f64) {
        self.speed_score.store(score.to_bits(), Ordering::Relaxed);
    }

    /// Get the current speed score.
    pub fn get_speed_score(&self) -> f64 {
        f64::from_bits(self.speed_score.load(Ordering::Relaxed))
    }

    /// Update the last observed worker latency (ms).
    pub fn set_last_latency_ms(&self, latency_ms: Option<u64>) {
        self.last_latency_ms
            .store(latency_ms.unwrap_or(0), Ordering::Relaxed);
    }

    /// Get the last observed worker latency (ms).
    pub fn last_latency_ms(&self) -> Option<u64> {
        let v = self.last_latency_ms.load(Ordering::Relaxed);
        if v == 0 { None } else { Some(v) }
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

    /// Drive the authoritative circuit through a single health-check outcome.
    ///
    /// This is the ONE write path the health monitor uses to move
    /// `WorkerState.circuit` — the circuit the scheduler actually reads — so a
    /// worker that fails a probe short-circuits out of selection and a recovered
    /// worker rejoins, all through the shared
    /// [`CircuitStats::apply_health_outcome`] engine. Returns
    /// `(previous_state, new_state)` so the caller can detect transitions for
    /// alerting/metrics without a second lock.
    ///
    /// `transient` flags a retryable transport blip that survived the in-check
    /// retries; a transient half-open failure will not reopen the circuit.
    pub async fn record_health_check(
        &self,
        healthy: bool,
        transient: bool,
        config: &CircuitBreakerConfig,
    ) -> (CircuitState, CircuitState) {
        let mut circuit = self.circuit.write().await;
        let previous = circuit.state();
        let new = circuit.apply_health_outcome(healthy, transient, config);
        (previous, new)
    }

    /// Drive the authoritative circuit through a single *command-class*
    /// outcome (see [`CircuitStats::apply_command_outcome`]): an operation of
    /// the same shape as dispatched work — the telemetry poll, or a health
    /// probe whose session connected but whose command never completed.
    /// Returns `(previous_state, new_state)` like [`Self::record_health_check`].
    pub async fn record_command_outcome(
        &self,
        success: bool,
        config: &CircuitBreakerConfig,
    ) -> (CircuitState, CircuitState) {
        let mut circuit = self.circuit.write().await;
        let previous = circuit.state();
        let new = circuit.apply_command_outcome(success, config);
        (previous, new)
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

    /// Skip overlapping probes instead of queuing more remote inventory scans.
    /// The guard releases on normal completion, error, panic or cancellation.
    pub fn try_capability_probe(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        self.capability_probe.try_lock().ok()
    }

    /// Test fixtures publish through the same generation-checked boundary.
    #[cfg(test)]
    pub async fn set_capabilities(&self, capabilities: WorkerCapabilities) {
        let context = self.capability_probe_context().await;
        assert!(self.publish_capabilities(context, capabilities).await);
    }

    pub(crate) async fn capability_probe_context(&self) -> CapabilityProbeContext {
        let config = self.config.read().await;
        CapabilityProbeContext {
            config: config.clone(),
            started_at: Instant::now(),
            generation: self.disk_capacity_generation.load(Ordering::Acquire),
            network_revision: *self.network_changes.borrow(),
        }
    }

    /// Publish a probe only for the endpoint/generation that launched it. No
    /// config lock is held over SSH; this short read lock fences local publish
    /// against retargeting while the three in-memory snapshots are updated.
    pub(crate) async fn publish_capabilities(
        &self,
        context: CapabilityProbeContext,
        capabilities: WorkerCapabilities,
    ) -> bool {
        let config = self.config.read().await;
        let _publication = self.network_transition.lock().await;
        if *self.network_changes.borrow() != context.network_revision {
            return false;
        }
        if config.id != context.config.id
            || config.host != context.config.host
            || config.user != context.config.user
            || config.identity_file != context.config.identity_file
        {
            return false;
        }
        let generation = context.generation.wrapping_add(1);
        if self
            .disk_capacity_generation
            .compare_exchange(
                context.generation,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let observation = DiskCapacityObservation::from_capabilities(
            config.id.to_string(),
            &capabilities,
            generation,
            Arc::clone(&self.disk_capacity_generation),
            context.started_at,
        );
        *self.disk_capacity_observation.write().await = observation;
        let pressure_config = DiskPressurePolicyConfig::configured();
        let pressure = evaluate_pressure_policy(&capabilities, None, &pressure_config);
        *self.capabilities.write().await = capabilities;

        let now_ms = current_unix_ms();
        let mut current = self.pressure_assessment.write().await;
        if pressure.state != crate::disk_pressure::PressureState::Critical
            && refresh_preserved_pressure_age(&mut current, &pressure_config, now_ms)
        {
            current.disk_free_gb = pressure.disk_free_gb;
            current.disk_total_gb = pressure.disk_total_gb;
            current.disk_free_ratio = pressure.disk_free_ratio;
            current.build_disk_free_gb = pressure.build_disk_free_gb;
            current.build_disk_total_gb = pressure.build_disk_total_gb;
            current.evaluated_at_unix_ms = now_ms;
            return true;
        }

        *current = pressure;
        true
    }

    /// Get worker capabilities.
    pub async fn capabilities(&self) -> WorkerCapabilities {
        self.capabilities.read().await.clone()
    }

    pub(crate) async fn disk_capacity_observation(&self) -> Option<DiskCapacityObservation> {
        self.disk_capacity_observation.read().await.clone()
    }

    /// Cache a toolchain preflight verdict for selection-time routing.
    pub async fn record_toolchain_preflight(
        &self,
        toolchain: String,
        usable: bool,
        reason: Option<String>,
    ) {
        self.toolchain_preflight.write().await.insert(
            toolchain,
            ToolchainPreflightStatus {
                usable,
                reason,
                checked_at_unix_ms: current_unix_ms(),
            },
        );
    }

    /// Retrieve a cached toolchain preflight verdict.
    pub async fn toolchain_preflight_status(
        &self,
        toolchain: &str,
    ) -> Option<ToolchainPreflightStatus> {
        self.toolchain_preflight
            .read()
            .await
            .get(toolchain)
            .cloned()
    }

    /// Update the latest disk-pressure policy assessment.
    pub async fn set_pressure_assessment(&self, assessment: PressureAssessment) {
        *self.pressure_assessment.write().await = assessment;
    }

    /// Get the latest disk-pressure policy assessment.
    pub async fn pressure_assessment(&self) -> PressureAssessment {
        self.pressure_assessment.read().await.clone()
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

    /// Check if this worker has Nix installed (nix binary + `/nix/store`).
    pub async fn has_nix(&self) -> bool {
        self.capabilities.read().await.has_nix()
    }

    /// Whether this worker has the Go toolchain installed.
    pub async fn has_go(&self) -> bool {
        self.capabilities.read().await.has_go()
    }

    /// Whether this worker can run `cargo zigbuild` (cargo-zigbuild + zig).
    pub async fn has_zig(&self) -> bool {
        self.capabilities.read().await.has_zig()
    }

    /// Disable the worker with an optional reason.
    /// Sets status to Disabled and records the timestamp and reason.
    pub async fn disable(&self, reason: Option<String>) {
        let _transition = self.network_transition.lock().await;
        self.disable_locked(reason).await;
    }

    /// Apply a completed probe's disable policy only to the worker and
    /// administrative decision that admitted it. Retain both guards through
    /// the transition so retarget, removal, and a later enable cannot race the
    /// comparison. Existing build reservations remain owned by this state.
    pub(crate) async fn disable_from_probe(
        &self,
        endpoint: &WorkerEndpointSnapshot,
        admission: &BackgroundProbe,
        admitted_admin: AdminIntent,
        reason: Option<String>,
    ) -> bool {
        let Some(_endpoint) = self.lock_current_endpoint(endpoint).await else {
            return false;
        };
        let Some(_transition) = self.lock_network_publication(admission).await else {
            return false;
        };
        if self.lifecycle.read().await.admin != admitted_admin
            || !self.background_network_allowed().await
        {
            return false;
        }
        self.disable_locked(reason).await;
        true
    }

    /// Caller owns network_transition; conditional publishers also retain the
    /// endpoint guard. Do not reacquire either lock while applying the change.
    async fn disable_locked(&self, reason: Option<String>) {
        *self.drain_completion.write().await = DrainCompletionAction::StayDrained;
        self.lifecycle
            .write()
            .await
            .set_admin(AdminIntent::Disabled);
        self.require_connection_probe();
        self.set_pooled_connections_enabled(false).await;
        *self.disabled_reason.write().await = reason;
        self.disabled_at
            .store(current_unix_secs_for_disabled_at(), Ordering::Relaxed);
    }

    /// Start draining the worker (no new jobs, but finish existing).
    pub async fn drain(&self) {
        let transition = self.network_transition.lock().await;
        let admin = self.lifecycle.read().await.admin;
        let disabled = admin == AdminIntent::Disabled
            || matches!(
                *self.drain_completion.read().await,
                DrainCompletionAction::Disable { .. }
            );
        if !disabled {
            *self.drain_completion.write().await = DrainCompletionAction::StayDrained;
            if admin == AdminIntent::Active {
                self.lifecycle
                    .write()
                    .await
                    .set_admin(AdminIntent::Draining);
            }
        }
        drop(transition);
        self.check_drain_complete().await;
    }

    /// Start draining a worker that should be removed once active jobs finish.
    pub async fn drain_for_removal(&self) {
        let transition = self.network_transition.lock().await;
        self.removal_pending.store(true, Ordering::Release);
        let admin = self.lifecycle.read().await.admin;
        if admin == AdminIntent::Active {
            *self.drain_completion.write().await = DrainCompletionAction::ResumeOnConfigReturn;
            self.lifecycle
                .write()
                .await
                .set_admin(AdminIntent::Draining);
        }
        drop(transition);
        self.check_drain_complete().await;
    }

    /// Start draining a worker that should become disabled once active jobs finish.
    pub async fn drain_then_disable(&self, reason: Option<String>) {
        let transition = self.network_transition.lock().await;
        let disabled = self.lifecycle.read().await.admin == AdminIntent::Disabled;
        if disabled {
            // A repeated disable with drain requested must not relax an
            // already effective disable while its existing builds finish.
            *self.disabled_reason.write().await = reason;
            self.disabled_at
                .store(current_unix_secs_for_disabled_at(), Ordering::Relaxed);
        } else {
            *self.drain_completion.write().await = DrainCompletionAction::Disable { reason };
            self.lifecycle
                .write()
                .await
                .set_admin(AdminIntent::Draining);
        }
        self.require_connection_probe();
        self.set_pooled_connections_enabled(false).await;
        drop(transition);
        self.check_drain_complete().await;
    }

    /// Enable a previously disabled/draining worker.
    /// Clears disabled reason and timestamp, sets status to Healthy.
    pub async fn enable(&self) {
        let _transition = self.network_transition.lock().await;
        let removed = self.removal_pending.load(Ordering::Acquire);
        *self.drain_completion.write().await = if removed {
            DrainCompletionAction::ResumeOnConfigReturn
        } else {
            DrainCompletionAction::StayDrained
        };
        // Operator re-enable clears administrative disable and quarantine. It
        // does not reintroduce missing inventory: those owners remain draining
        // until their builds finish or configuration explicitly restores them.
        let mut lifecycle = WorkerLifecycle::new();
        if removed {
            lifecycle.set_admin(if self.used_slots() == 0 {
                AdminIntent::Drained
            } else {
                AdminIntent::Draining
            });
        }
        *self.lifecycle.write().await = lifecycle;
        self.revoke_background_network();
        let ready = self.connection_is_ready();
        let transport = self.transport();
        transport.reset().await;
        self.connection_ready.store(ready, Ordering::Release);
        self.ready_transport_revision
            .store(transport.revision(), Ordering::Release);
        // Admission still requires the next health probe for monitored daemon
        // workers. An explicit enable does not prove the SSH endpoint is up.
        self.set_pooled_connections_enabled(self.background_network_allowed().await)
            .await;
        *self.disabled_reason.write().await = None;
        self.disabled_at.store(0, Ordering::Relaxed);
        // Also reset the circuit breaker — `WorkerState.circuit` is the single
        // source of truth the scheduler reads, and re-enabling a worker whose
        // circuit is still Open/HalfOpen would leave it short-circuited out of
        // selection despite the operator explicitly bringing it back. This is a
        // REAL reset (clears failure/success counters and error history), not a
        // status flip. (Also clears last_error_msg, matching close_circuit.)
        self.circuit.write().await.close();
        *self.last_error_msg.write().await = None;
    }

    /// Check if worker is disabled (operator admin intent).
    pub async fn is_disabled(&self) -> bool {
        self.lifecycle.read().await.admin == AdminIntent::Disabled
    }

    /// Check if worker is draining (operator admin intent).
    pub async fn is_draining(&self) -> bool {
        self.lifecycle.read().await.admin == AdminIntent::Draining
    }

    /// Check if worker is drained (drain complete, no active jobs).
    pub async fn is_drained(&self) -> bool {
        self.lifecycle.read().await.admin == AdminIntent::Drained
    }

    /// Check if draining worker has completed all jobs and apply the recorded completion action.
    ///
    /// Plain drains transition to `Drained`, config-removal drains become pruneable, and
    /// drain-before-disable transitions to `Disabled` while preserving the disable reason.
    pub async fn check_drain_complete(&self) {
        let _transition = self.network_transition.lock().await;
        let used = self.used_slots.load(Ordering::Acquire);
        if used != 0 || self.lifecycle.read().await.admin != AdminIntent::Draining {
            return;
        }

        let completion = self.drain_completion.read().await.clone();
        let mut lifecycle = self.lifecycle.write().await;
        if lifecycle.admin != AdminIntent::Draining || self.used_slots.load(Ordering::Acquire) != 0
        {
            return;
        }

        let disable_reason = match completion {
            DrainCompletionAction::StayDrained | DrainCompletionAction::ResumeOnConfigReturn => {
                lifecycle.set_admin(AdminIntent::Drained);
                None
            }
            DrainCompletionAction::Disable { reason } => {
                lifecycle.set_admin(AdminIntent::Disabled);
                Some(reason)
            }
        };
        drop(lifecycle);

        self.revoke_background_network();
        self.set_pooled_connections_enabled(false).await;

        if let Some(reason) = disable_reason {
            *self.disabled_reason.write().await = reason;
            self.disabled_at
                .store(current_unix_secs_for_disabled_at(), Ordering::Relaxed);
            *self.drain_completion.write().await = DrainCompletionAction::StayDrained;
        }
    }

    pub(crate) async fn remove_after_drain_pending(&self) -> bool {
        self.removal_pending.load(Ordering::Acquire)
    }

    /// Get the reason this worker was disabled (if any).
    pub async fn disabled_reason(&self) -> Option<String> {
        self.disabled_reason.read().await.clone()
    }

    /// Get the timestamp when this worker was disabled (Unix seconds).
    pub fn disabled_at(&self) -> Option<i64> {
        let v = self.disabled_at.load(Ordering::Relaxed);
        if v == 0 { None } else { Some(v) }
    }

    /// Get the number of slots currently in use.
    pub fn used_slots(&self) -> u32 {
        self.used_slots.load(Ordering::Relaxed)
    }

    /// Startup-only reconstruction, independent of present admission limits.
    pub fn restore_slots(&self, count: u32) -> std::io::Result<()> {
        self.used_slots
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(count)
            })
            .map(|_| ())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "durable reservation overflow",
                )
            })
    }
}

/// Cached result of checking a concrete Rust toolchain on a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainPreflightStatus {
    /// Whether both `rustc` and `cargo` work through `rustup run <toolchain>`.
    pub usable: bool,
    /// Stable diagnostic reason when unusable.
    pub reason: Option<String>,
    /// Epoch milliseconds when the verdict was recorded.
    pub checked_at_unix_ms: i64,
}

impl ToolchainPreflightStatus {
    /// Whether this verdict is fresh enough to reuse for dispatch decisions.
    pub fn is_fresh(&self, ttl: Duration) -> bool {
        let age_ms = current_unix_ms().saturating_sub(self.checked_at_unix_ms);
        age_ms <= duration_millis_i64(ttl)
    }

    /// Whether this verdict says anything about the toolchain itself.
    ///
    /// Only `toolchain_preflight_command_failed` means the probe ran and the
    /// toolchain is missing or broken. A connect failure or timeout (the probe
    /// runs over SSH against possibly loaded workers) says nothing about the
    /// toolchain, and caching it as "unusable" for the full TTL excluded a
    /// healthy worker from every build for that toolchain for 10 minutes.
    pub fn is_definitive(&self) -> bool {
        self.usable
            || self
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("toolchain_preflight_command_failed"))
    }

    /// How long to reuse this verdict: `definitive_ttl` for a real answer,
    /// `transient_ttl` for a probe that never reached a conclusion.
    pub fn is_reusable(&self, definitive_ttl: Duration, transient_ttl: Duration) -> bool {
        self.is_fresh(if self.is_definitive() {
            definitive_ttl
        } else {
            transient_ttl
        })
    }
}

/// Upper bound on per-worker project lanes: each lane is a full extra mirror.
pub const MAX_PROJECT_LANES: u32 = 8;

/// Pool of all workers.
#[derive(Clone)]
pub struct WorkerPool {
    workers: Arc<RwLock<HashMap<WorkerId, Arc<WorkerState>>>>,
    /// Startup ownership for workers absent from the current configuration.
    /// These are reservations, not schedulable workers. The durable build
    /// history remains their source of truth across process restarts.
    /// Lock order is always `workers` before `recovered_absent_slots`.
    recovered_absent_slots: Arc<RwLock<HashMap<WorkerId, u32>>>,
    /// Track worker count atomically for sync access.
    worker_count: Arc<AtomicUsize>,
    disk_slot_policy: DiskSlotPolicy,
    /// Zero-slot hold for each newly added worker until its first disk sample.
    unmeasured_capacity_hold: Option<std::time::Duration>,
    /// Per-worker project lanes from daemon.toml `[project_lanes]` (bd-sgvod).
    project_lanes: Arc<std::sync::RwLock<HashMap<String, u32>>>,
    /// Broadcast retargets to health and bypass recovery even while they probe.
    endpoint_changes: watch::Sender<u64>,
    monitor_connections: bool,
    ssh_pools: Arc<RwLock<Vec<Arc<rch_common::SshPool>>>>,
    admin_disable_store: Option<Arc<Mutex<AdminDisableStore>>>,
    endpoint_transports: Arc<EndpointTransports>,
    recovery_transport_policy: RecoveryTransportPolicy,
}

impl WorkerPool {
    /// Create a new empty worker pool.
    pub fn new() -> Self {
        Self::with_selection_config(&rch_common::SelectionConfig::default())
    }

    /// Create a pool whose current and subsequently reloaded workers share a disk budget.
    pub fn with_selection_config(config: &rch_common::SelectionConfig) -> Self {
        Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
            recovered_absent_slots: Arc::new(RwLock::new(HashMap::new())),
            worker_count: Arc::new(AtomicUsize::new(0)),
            disk_slot_policy: DiskSlotPolicy::from(config),
            unmeasured_capacity_hold: None,
            project_lanes: Arc::new(std::sync::RwLock::new(HashMap::new())),
            endpoint_changes: watch::channel(0).0,
            monitor_connections: false,
            ssh_pools: Arc::new(RwLock::new(Vec::new())),
            admin_disable_store: None,
            endpoint_transports: Arc::new(EndpointTransports::default()),
            recovery_transport_policy: RecoveryTransportPolicy::default(),
        }
    }

    /// Production pools verify a new/reloaded endpoint before any service can
    /// dial it or dispatch a build. This also makes restart ordering explicit.
    pub fn with_connection_monitoring(mut self) -> Self {
        self.monitor_connections = true;
        self
    }

    /// Historical endpoints obey the same failure threshold, normal cadence,
    /// recovery cadence and total probe budget as current health checks.
    pub fn with_recovery_transport_policy(
        mut self,
        circuit: CircuitBreakerConfig,
        normal_interval: Duration,
        probe_timeout: Duration,
    ) -> Self {
        self.recovery_transport_policy = RecoveryTransportPolicy {
            circuit,
            normal_interval: normal_interval.max(Duration::from_millis(1)),
            probe_timeout: probe_timeout.max(Duration::from_millis(1)),
        };
        self
    }

    /// Inspect eligibility without taking a lane, consuming a due probe, or
    /// performing I/O. Lease-directory scans may freely discard this permit;
    /// `run` rechecks and claims admission under the caller's admin guard.
    pub(crate) async fn owned_recovery_admission(
        &self,
        endpoint: &WorkerConfig,
    ) -> Option<OwnedRecoveryPermit> {
        {
            let workers = self.workers.read().await;
            if let Some(worker) = workers.get(&endpoint.id) {
                let config = worker.config.read().await;
                if same_endpoint(&config, endpoint) && !worker.is_endpoint_retired() {
                    let transport = worker.transport();
                    let network = worker.network_revision_guard();
                    let state = transport.state.lock().await;
                    if state.down
                        || (!state.connected && !worker.connection_is_ready())
                        || !network.is_current()
                        || transport.recovery.try_lock().is_err()
                    {
                        return None;
                    }
                    drop(state);
                    return Some(OwnedRecoveryPermit {
                        endpoint: endpoint.clone(),
                        transport,
                        policy: self.recovery_transport_policy.clone(),
                        current: Some(network),
                        health_changes: self.endpoint_changes.clone(),
                    });
                }
            }
        }
        let transport = self.endpoint_transports.get(endpoint);
        if !transport.historical_recovery_eligible().await {
            return None;
        }
        Some(OwnedRecoveryPermit {
            endpoint: endpoint.clone(),
            transport,
            policy: self.recovery_transport_policy.clone(),
            current: None,
            health_changes: self.endpoint_changes.clone(),
        })
    }

    /// Supply explicit transport evidence in tests that exercise admission
    /// around a local future rather than spawning an actual SSH subprocess.
    #[cfg(test)]
    pub(crate) async fn record_owned_recovery_transport_result(
        &self,
        endpoint: &WorkerConfig,
        connected: bool,
    ) {
        self.endpoint_transports
            .get(endpoint)
            .record_result(
                connected,
                self.recovery_transport_policy.normal_interval,
                &self.recovery_transport_policy.circuit,
            )
            .await;
    }

    pub fn with_admin_disable_store(mut self, store: Arc<Mutex<AdminDisableStore>>) -> Self {
        self.admin_disable_store = Some(store);
        self
    }

    pub async fn attach_ssh_pool(&self, pool: Arc<rch_common::SshPool>) {
        let mut pools = self.ssh_pools.write().await;
        for worker in self.all_workers().await {
            worker.attach_ssh_pool(pool.clone()).await;
        }
        pools.push(pool);
    }

    /// Replace the per-worker project lane counts (`[project_lanes]` in
    /// daemon.toml, bd-sgvod). Unlisted workers keep one lane.
    pub fn set_project_lanes(&self, lanes: HashMap<String, u32>) {
        *self
            .project_lanes
            .write()
            .unwrap_or_else(|e| e.into_inner()) = lanes;
    }

    /// How many builds of one project this worker may run at once, each in its
    /// own mirror (`<root>.rch-lane-<k>`). At least 1, at most
    /// [`MAX_PROJECT_LANES`].
    pub fn project_lanes(&self, worker_id: &str) -> u32 {
        self.project_lanes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(worker_id)
            .copied()
            .unwrap_or(1)
            .clamp(1, MAX_PROJECT_LANES)
    }

    /// Give every worker this pool adds a zero-slot hold until its first disk
    /// capacity sample, bounded by `hold` (see [`WorkerState::slots_for`]).
    pub fn with_unmeasured_capacity_hold(mut self, hold: std::time::Duration) -> Self {
        self.unmeasured_capacity_hold = Some(hold);
        self
    }

    pub(crate) fn subscribe_endpoint_changes(&self) -> watch::Receiver<u64> {
        self.endpoint_changes.subscribe()
    }

    pub(crate) fn notify_endpoint_change(&self) {
        self.endpoint_changes
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Add a worker to the pool.
    pub async fn add_worker(&self, config: WorkerConfig) {
        let id = config.id.clone();

        {
            let workers = self.workers.read().await;
            if let Some(existing) = workers.get(&id) {
                debug!("Updating existing worker: {}", id);
                if existing.update_config(config).await {
                    self.notify_endpoint_change();
                }
                return;
            }
        }

        let state = Arc::new(WorkerState::with_endpoint_transports(
            config,
            self.disk_slot_policy,
            self.endpoint_transports.clone(),
        ));
        // Keep the durable intent lock through registry publication. Otherwise
        // an enable racing a remove/re-add could publish a stale disable (or
        // admit a previously disabled ID before its record is applied).
        let durable = match &self.admin_disable_store {
            Some(store) => Some(store.lock().await),
            None => None,
        };
        if let Some(record) = durable
            .as_ref()
            .and_then(|store| store.effective_disable(id.as_str()))
        {
            state.disable(record.reason).await;
        }
        if self.monitor_connections {
            state.require_connection_probe();
        }
        if let Some(hold) = self.unmeasured_capacity_hold {
            state.hold_until_capacity_measured(hold);
        }
        // Match attach_ssh_pool's pools -> workers order. Only the state that
        // wins registry insertion may change admission for this worker ID;
        // a discarded candidate must not revoke the winner's healthy pools.
        let pools = self.ssh_pools.read().await;
        let mut workers = self.workers.write().await;
        // Check again under write lock
        if let Some(existing) = workers.get(&id) {
            // Race condition: added between read and write lock
            // Just update config on the existing one, drop the new state
            let config = state.config.read().await.clone();
            if existing.update_config(config).await {
                self.notify_endpoint_change();
            }
        } else {
            for pool in pools.iter() {
                state.attach_ssh_pool(pool.clone()).await;
            }
            // Publish a reintroduced worker only after restoring its surviving
            // builds. Holding the registry's write lock makes this transfer
            // atomic with release_slots, including a completion that arrived
            // while the worker was absent. There is no await after removing
            // the pending count and before inserting the initialized state.
            let restored = self
                .recovered_absent_slots
                .write()
                .await
                .remove(&id)
                .unwrap_or(0);
            // `state` is freshly constructed and has never been published.
            // Restore ownership even when it exceeds the new capacity; free
            // slots saturate at zero until the existing builds finish.
            state.used_slots.store(restored, Ordering::SeqCst);
            workers.insert(id.clone(), state);
            self.worker_count.fetch_add(1, Ordering::SeqCst);
            debug!("Added worker: {}", id);
            self.notify_endpoint_change();
        }
    }

    /// Add a worker with a pre-configured state (for testing).
    #[cfg(test)]
    pub async fn add_worker_state(&self, mut state: WorkerState) {
        let config = state.config.read().await.clone();
        let id = config.id.clone();
        // Preserve the explicitly prepared test state's evidence while making
        // later inventory changes use the same endpoint registry as the pool.
        self.endpoint_transports
            .endpoints
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                WorkerEndpointIdentity::from_config(&config),
                state.transport(),
            );
        state.endpoint_transports = self.endpoint_transports.clone();
        let mut workers = self.workers.write().await;
        if workers.insert(id.clone(), Arc::new(state)).is_none() {
            self.worker_count.fetch_add(1, Ordering::SeqCst);
        }
        debug!("Added worker: {}", id);
    }

    /// Remove a worker from the pool.
    pub async fn remove_worker(&self, id: &WorkerId) -> bool {
        let mut workers = self.workers.write().await;
        if let Some(worker) = workers.get(id) {
            worker.retire_endpoint().await;
            workers.remove(id);
            self.worker_count.fetch_sub(1, Ordering::SeqCst);
            debug!("Removed worker: {}", id);
            true
        } else {
            false
        }
    }

    /// Prune workers that were removed from config and have finished draining.
    ///
    /// Returns the number of workers removed.
    pub async fn prune_drained(&self) -> usize {
        let snapshot: Vec<(WorkerId, Arc<WorkerState>)> = {
            let workers = self.workers.read().await;
            workers
                .iter()
                .map(|(id, worker)| (id.clone(), Arc::clone(worker)))
                .collect()
        };

        let mut to_remove = Vec::new();
        for (id, worker) in snapshot {
            worker.check_drain_complete().await;
            let status = worker.status().await;

            if matches!(status, WorkerStatus::Drained | WorkerStatus::Disabled)
                && worker.used_slots() == 0
                && worker.remove_after_drain_pending().await
            {
                to_remove.push((id, worker));
            }
        }

        let mut count = 0;
        let mut workers = self.workers.write().await;
        for (id, worker) in to_remove {
            let still_same_worker = workers
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &worker));
            if !still_same_worker {
                continue;
            }

            worker.check_drain_complete().await;
            let should_remove = matches!(
                worker.status().await,
                WorkerStatus::Drained | WorkerStatus::Disabled
            ) && worker.used_slots() == 0
                && worker.remove_after_drain_pending().await;
            if should_remove {
                worker.retire_endpoint().await;
                workers.remove(&id);
                count += 1;
                debug!("Pruned drained worker: {}", id);
            }
        }

        if count > 0 {
            self.worker_count.fetch_sub(count, Ordering::SeqCst);
        }

        count
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
            if (status == WorkerStatus::Healthy || status == WorkerStatus::Degraded)
                && worker.connection_is_ready()
            {
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
            let mut absent = self.recovered_absent_slots.write().await;
            if let Some(used) = absent.get_mut(id) {
                *used = used.saturating_sub(slots);
                if *used == 0 {
                    absent.remove(id);
                }
                debug!("Released {} recovered slots on absent worker {}", slots, id);
            } else {
                debug!("Worker {} has no reserved slots to release", id);
            }
        }
    }

    /// Reconstruct one durable build's reservation before daemon admission.
    ///
    /// Returns whether the worker is currently configured. An absent worker's
    /// reservation is retained without inventing a host or making it eligible
    /// for selection. Config reload consumes the remaining count exactly once.
    /// Call once per active build during startup, not periodically: this is an
    /// additive reconstruction, just like WorkerState::restore_slots.
    pub async fn restore_recovered_slots(
        &self,
        id: &WorkerId,
        slots: u32,
    ) -> std::io::Result<bool> {
        let workers = self.workers.read().await;
        if let Some(worker) = workers.get(id) {
            worker.restore_slots(slots)?;
            return Ok(true);
        }
        let mut absent = self.recovered_absent_slots.write().await;
        let used = absent.get(id).copied().unwrap_or(0);
        let restored = used.checked_add(slots).ok_or_else(|| {
            std::io::Error::other(format!("recovered slot count overflow for worker {id}"))
        })?;
        if restored != 0 {
            absent.insert(id.clone(), restored);
        }
        Ok(false)
    }
}

fn current_unix_secs_for_disabled_at() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(duration_secs_i64)
        .unwrap_or(1)
        .max(1)
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

fn current_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(duration_millis_i64)
        .unwrap_or_default()
}

fn refresh_preserved_pressure_age(
    assessment: &mut PressureAssessment,
    config: &DiskPressurePolicyConfig,
    now_ms: i64,
) -> bool {
    if !assessment.telemetry_fresh {
        return false;
    }

    let Some(previous_age_secs) = assessment.telemetry_age_secs else {
        return false;
    };

    let elapsed_secs = now_ms
        .saturating_sub(assessment.evaluated_at_unix_ms)
        .max(0) as u64
        / 1_000;
    let age_secs = previous_age_secs.saturating_add(elapsed_secs);
    assessment.telemetry_age_secs = Some(age_secs);
    assessment.telemetry_fresh = age_secs <= config.telemetry_stale_after.as_secs();
    assessment.telemetry_fresh
}

// ============================================================================
// Worker API Response Types
// ============================================================================

/// Worker capabilities information.
#[derive(Debug, Serialize)]
pub struct WorkerCapabilitiesInfo {
    pub id: String,
    pub host: String,
    pub user: String,
    pub capabilities: WorkerCapabilities,
    pub pressure_assessment: PressureAssessment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh: Option<WorkerCapabilitiesRefreshInfo>,
}

/// Freshness information for a capabilities refresh request.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerCapabilitiesRefreshInfo {
    pub attempted: bool,
    pub live: bool,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl WorkerCapabilitiesRefreshInfo {
    fn live_probe() -> Self {
        Self {
            attempted: true,
            live: true,
            source: "live_probe".to_string(),
            message: None,
        }
    }

    fn cached_after_probe_failure(message: impl Into<String>) -> Self {
        Self {
            attempted: true,
            live: false,
            source: "cached_after_probe_failure".to_string(),
            message: Some(message.into()),
        }
    }
}

/// Worker capabilities response.
#[derive(Debug, Serialize)]
pub struct WorkerCapabilitiesResponse {
    pub workers: Vec<WorkerCapabilitiesInfo>,
}

/// Response for worker state changes (drain/enable/disable).
#[derive(Debug, Serialize)]
pub struct WorkerStateResponse {
    pub status: String,
    pub worker_id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_slots: Option<u32>,
}

// ============================================================================
// Worker API Handlers
// ============================================================================

/// Collect worker capabilities, optionally refreshing via SSH probe.
pub async fn get_workers_capabilities(
    ctx: &DaemonContext,
    refresh: bool,
) -> WorkerCapabilitiesResponse {
    let workers = ctx.pool.all_workers().await;
    let mut entries = Vec::with_capacity(workers.len());
    let mut refresh_results = if refresh {
        refresh_worker_capabilities_concurrently(&workers).await
    } else {
        HashMap::new()
    };

    for worker in workers {
        let (id, host, user) = {
            let config = worker.config.read().await;
            (
                config.id.to_string(),
                config.host.clone(),
                config.user.clone(),
            )
        };
        let capabilities = worker.capabilities().await;
        let pressure_assessment = worker.pressure_assessment().await;
        let refresh = refresh_results.remove(&id);

        entries.push(WorkerCapabilitiesInfo {
            id,
            host,
            user,
            capabilities,
            pressure_assessment,
            refresh,
        });
    }

    WorkerCapabilitiesResponse { workers: entries }
}

async fn refresh_worker_capabilities_concurrently(
    workers: &[Arc<WorkerState>],
) -> HashMap<String, WorkerCapabilitiesRefreshInfo> {
    let mut handles = Vec::with_capacity(workers.len());

    for worker in workers {
        let id = {
            let config = worker.config.read().await;
            config.id.to_string()
        };
        let worker = Arc::clone(worker);
        handles.push((
            id,
            tokio::spawn(async move { refresh_worker_capabilities_for_worker(worker).await }),
        ));
    }

    let mut results = HashMap::with_capacity(handles.len());
    for (id, handle) in handles {
        let refresh = match handle.await {
            Ok(refresh) => refresh,
            Err(err) => WorkerCapabilitiesRefreshInfo::cached_after_probe_failure(format!(
                "capabilities refresh task failed: {err}; returning cached capability snapshot"
            )),
        };
        results.insert(id, refresh);
    }

    results
}

async fn refresh_worker_capabilities_for_worker(
    worker: Arc<WorkerState>,
) -> WorkerCapabilitiesRefreshInfo {
    let probe = tokio::time::timeout(
        CAPABILITIES_REFRESH_WORKER_BUDGET,
        // On-demand capability refresh (the `rch workers capabilities` API path)
        // uses a throwaway SSH session — it is a low-frequency operator query, not
        // one of the ~30s periodic poll loops the shared pool exists to de-flood.
        probe_worker_capabilities(&worker, CAPABILITIES_REFRESH_PROBE_TIMEOUT, None),
    )
    .await;

    match probe {
        Ok(Some(_capabilities)) => WorkerCapabilitiesRefreshInfo::live_probe(),
        Ok(None) => WorkerCapabilitiesRefreshInfo::cached_after_probe_failure(
            "capabilities probe failed; returning cached capability snapshot",
        ),
        Err(_) => WorkerCapabilitiesRefreshInfo::cached_after_probe_failure(format!(
            "capabilities probe exceeded {}s response budget; returning cached capability snapshot",
            CAPABILITIES_REFRESH_WORKER_BUDGET.as_secs()
        )),
    }
}

/// Handle a worker drain request.
pub async fn handle_worker_drain(ctx: &DaemonContext, worker_id: &WorkerId) -> WorkerStateResponse {
    // Keep the resolved incarnation registered through publication, just as
    // enable/disable do. Reload cannot replace it while this action waits on
    // an existing transition and then receive a drain of only its retired Arc.
    let workers = ctx.pool.workers.read().await;
    match workers.get(worker_id) {
        Some(worker) => {
            let active_slots = worker.used_slots();
            worker.drain().await;
            let new_status = worker.status().await;
            WorkerStateResponse {
                status: "ok".to_string(),
                worker_id: worker_id.to_string(),
                action: "drain".to_string(),
                new_status: Some(worker_status_label(new_status).to_string()),
                reason: None,
                message: Some(format!(
                    "Worker is {}. {} slot(s) currently in use.",
                    worker_status_label(new_status),
                    active_slots,
                )),
                active_slots: Some(active_slots),
            }
        }
        None => WorkerStateResponse {
            status: "error".to_string(),
            worker_id: worker_id.to_string(),
            action: "drain".to_string(),
            new_status: None,
            reason: None,
            message: Some(format!("Worker '{}' not found", worker_id)),
            active_slots: None,
        },
    }
}

/// Handle a worker enable request.
pub async fn handle_worker_enable(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
) -> WorkerStateResponse {
    // Historical builds survive inventory removal and daemon restart. Read
    // their ownership before taking administration/registry locks; no history
    // guard may span durable writes or publication of administrative intent.
    let historical_slots = historical_worker_slots(ctx, worker_id);
    // Resolve the ID only after serializing durable intent, and retain the
    // registry lease through the live change. Otherwise reload can replace a
    // worker while this handler waits, and an acknowledged enable can affect
    // only a retired Arc. Match add_worker: durable store -> registry -> worker.
    let mut durable = match &ctx.admin_disable_store {
        Some(store) => Some(store.lock().await),
        None => None,
    };
    let workers = ctx.pool.workers.read().await;
    match workers.get(worker_id) {
        Some(worker) => {
            let old_status = worker.status().await;
            // Operator re-enable must be DURABLE: delete the worker's persisted
            // bypass record too. `worker.enable()` only resets the in-memory
            // lifecycle/circuit; if the record survives, `reconcile_on_start`
            // re-quarantines the worker from it on the next daemon restart (and
            // the live recovery loop can re-touch it). Mirrors `rejoin`'s
            // `store.remove(worker_id)`. (2026-07-16 offload meltdown follow-up.)
            if let Some(store) = &ctx.bypass_store
                && let Err(error) = store.lock().await.remove(worker_id.as_str())
            {
                return WorkerStateResponse {
                    status: "error".into(),
                    worker_id: worker_id.to_string(),
                    action: "enable".into(),
                    new_status: Some(worker_status_label(old_status).into()),
                    reason: None,
                    message: Some(format!(
                        "Worker remains disabled: could not clear durable bypass: {error}"
                    )),
                    active_slots: Some(worker.used_slots()),
                };
            }
            // Same durability rule for the admin-disable record (bd-8zxz7):
            // an enable that leaves the record behind would be undone by the
            // next daemon restart's re-apply pass.
            if let Some(store) = &mut durable
                && let Err(e) = store.remove(worker_id.as_str())
            {
                return WorkerStateResponse {
                    status: "error".into(),
                    worker_id: worker_id.to_string(),
                    action: "enable".into(),
                    new_status: Some(worker_status_label(old_status).into()),
                    reason: None,
                    message: Some(format!(
                        "Worker remains disabled: could not clear durable disable: {e}"
                    )),
                    active_slots: Some(worker.used_slots()),
                };
            }
            worker.enable().await;
            ctx.pool.notify_endpoint_change();
            WorkerStateResponse {
                status: "ok".to_string(),
                worker_id: worker_id.to_string(),
                action: "enable".to_string(),
                new_status: Some(worker_status_label(worker.status().await).to_string()),
                reason: None,
                message: Some(format!("Worker enabled (was {:?})", old_status)),
                active_slots: None,
            }
        }
        None => {
            let mut response = WorkerStateResponse {
                status: "error".to_string(),
                worker_id: worker_id.to_string(),
                action: "enable".to_string(),
                new_status: None,
                reason: None,
                message: Some(format!("Worker '{}' not found", worker_id)),
                active_slots: None,
            };
            let known_disable = durable
                .as_ref()
                .is_some_and(|store| store.effective_disable(worker_id.as_str()).is_some());
            if historical_slots.is_none() && !known_disable {
                return response;
            }
            response.active_slots = Some(historical_slots.unwrap_or(0));
            let Some(store) = &mut durable else {
                response.message = Some(
                    "Historical worker administration requires durable administrative state".into(),
                );
                return response;
            };
            if let Some(bypass) = &ctx.bypass_store
                && let Err(error) = bypass.lock().await.remove(worker_id.as_str())
            {
                response.message = Some(format!(
                    "Could not clear durable bypass for historical worker: {error}"
                ));
                return response;
            }
            if let Err(error) = store.remove(worker_id.as_str()) {
                response.message = Some(format!(
                    "Could not clear durable disable for historical worker: {error}"
                ));
                return response;
            }
            // Clearing intent permits only recovery of already-owned work.
            // Keep the ID absent from inventory and leave its slots/history
            // untouched. A concurrent re-add inherits the durable enable.
            response.status = "ok".into();
            response.message = Some(
                "Historical worker enabled for recovery; it remains absent from inventory".into(),
            );
            response
        }
    }
}

/// Handle a worker disable request.
pub async fn handle_worker_disable(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
    reason: Option<String>,
    drain_first: bool,
) -> WorkerStateResponse {
    let historical_slots = historical_worker_slots(ctx, worker_id);
    // Keep the same store -> registry -> worker order as enable and insertion.
    // A concurrent remove/re-add must either precede this lookup or inherit the
    // disable after publication; it cannot remain active behind a successful
    // response that changed only its retired predecessor.
    let mut durable = match &ctx.admin_disable_store {
        Some(store) => Some(store.lock().await),
        None => None,
    };
    let workers = ctx.pool.workers.read().await;
    match workers.get(worker_id) {
        Some(worker) => {
            let active_slots = worker.used_slots();
            let mut persistence_error = None;

            // Durable admin disable (bd-8zxz7): persist the intent BEFORE the
            // in-memory flip, for both the drain and immediate branches — a
            // disable that only lives in memory evaporates on daemon restart.
            // Persistence failures still stop live traffic, but return an
            // error so the caller knows restart durability was not achieved.
            if let Some(store) = &mut durable {
                let record = rch_common::bypass_record::AdminDisableRecord {
                    worker_id: worker_id.to_string(),
                    reason: reason.clone(),
                    disabled_unix_ms: u64::try_from(chrono::Utc::now().timestamp_millis())
                        .unwrap_or(0),
                };
                if let Err(e) = store.upsert(record) {
                    tracing::warn!(
                        "Failed to persist durable admin-disable record for {}: {}",
                        worker_id,
                        e
                    );
                    persistence_error = Some(e.to_string());
                }
            }

            if let Some(error) = persistence_error {
                // Stop live traffic even when disk persistence fails, but do
                // not promise that this disable will survive a restart.
                worker.disable(reason.clone()).await;
                return WorkerStateResponse {
                    status: "error".into(),
                    worker_id: worker_id.to_string(),
                    action: "disable".into(),
                    new_status: Some("disabled".into()),
                    reason,
                    message: Some(format!(
                        "Worker disabled in this daemon; durable state could not be saved: {error}"
                    )),
                    active_slots: Some(active_slots),
                };
            }

            if drain_first && active_slots > 0 {
                worker.drain_then_disable(reason.clone()).await;
                let new_status = worker.status().await;
                WorkerStateResponse {
                    status: "ok".to_string(),
                    worker_id: worker_id.to_string(),
                    action: "disable".to_string(),
                    new_status: Some(worker_status_label(new_status).to_string()),
                    reason: reason.clone(),
                    message: Some(format!(
                        "Worker is {} before disable. {} slot(s) in use. Reason: {}",
                        worker_status_label(new_status),
                        active_slots,
                        reason.as_deref().unwrap_or("none provided")
                    )),
                    active_slots: Some(active_slots),
                }
            } else {
                // Disable immediately
                worker.disable(reason.clone()).await;
                WorkerStateResponse {
                    status: "ok".to_string(),
                    worker_id: worker_id.to_string(),
                    action: "disable".to_string(),
                    new_status: Some("disabled".to_string()),
                    reason: reason.clone(),
                    message: Some(format!(
                        "Worker disabled. Reason: {}",
                        reason.as_deref().unwrap_or("none provided")
                    )),
                    active_slots: Some(active_slots),
                }
            }
        }
        None => {
            let mut response = WorkerStateResponse {
                status: "error".to_string(),
                worker_id: worker_id.to_string(),
                action: "disable".to_string(),
                new_status: None,
                reason: reason.clone(),
                message: Some(format!("Worker '{}' not found", worker_id)),
                active_slots: None,
            };
            let known_disable = durable
                .as_ref()
                .is_some_and(|store| store.effective_disable(worker_id.as_str()).is_some());
            if historical_slots.is_none() && !known_disable {
                return response;
            }
            response.active_slots = Some(historical_slots.unwrap_or(0));
            let Some(store) = &mut durable else {
                response.message = Some(
                    "Historical worker administration requires durable administrative state".into(),
                );
                return response;
            };
            // An absent worker has no live drain state. Suspend automatic
            // historical recovery immediately even for drain-first requests,
            // retaining the build's exact endpoint and reservation. Upsert
            // revokes active stable-ID permits before its fallible write.
            let saved = store.upsert(rch_common::bypass_record::AdminDisableRecord {
                worker_id: worker_id.to_string(),
                reason,
                disabled_unix_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0),
            });
            response.new_status = Some("disabled".into());
            match saved {
                Ok(()) => {
                    response.status = "ok".into();
                    response.message = Some(
                        "Historical worker disabled for automatic recovery; existing ownership and slots are retained".into(),
                    );
                }
                Err(error) => {
                    response.message = Some(format!(
                        "Worker recovery suspended in this daemon; durable state could not be saved: {error}"
                    ));
                }
            }
            response
        }
    }
}

fn historical_worker_slots(ctx: &DaemonContext, worker_id: &WorkerId) -> Option<u32> {
    ctx.history
        .active_builds()
        .into_iter()
        .filter(|build| build.worker_id == worker_id.as_str())
        .map(|build| build.slots)
        .reduce(u32::saturating_add)
}

fn worker_status_label(status: WorkerStatus) -> &'static str {
    match status {
        WorkerStatus::Healthy => "healthy",
        WorkerStatus::Degraded => "degraded",
        WorkerStatus::Unreachable => "unreachable",
        WorkerStatus::Draining => "draining",
        WorkerStatus::Drained => "drained",
        WorkerStatus::Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovered_worker_config(id: &str, slots: u32) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: slots,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        }
    }

    #[tokio::test]
    async fn offline_worker_racing_registration_cannot_revoke_the_healthy_winner() {
        let pool = WorkerPool::new().with_connection_monitoring();
        let ssh_pool = Arc::new(rch_common::SshPool::new(rch_common::SshOptions {
            connect_timeout: Duration::ZERO,
            ..Default::default()
        }));
        pool.attach_ssh_pool(ssh_pool.clone()).await;
        let config = recovered_worker_config("concurrent-registration", 4);

        // Suspend one actual add after it has observed the ID absent and
        // constructed a candidate. Another add can then publish first.
        let registrations = pool.ssh_pools.write().await;
        let late_registration = pool.add_worker(config.clone());
        tokio::pin!(late_registration);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(late_registration.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(registrations);
        tokio::time::timeout(Duration::from_secs(1), pool.add_worker(config.clone()))
            .await
            .expect("another registration can acquire the shared pool lock and win");

        let winner = pool.get(&config.id).await.unwrap();
        winner
            .record_transport_result(
                true,
                Duration::from_secs(30),
                &CircuitBreakerConfig::default(),
            )
            .await;
        assert!(winner.background_network_allowed().await);
        late_registration.await;
        assert!(Arc::ptr_eq(&winner, &pool.get(&config.id).await.unwrap()));
        assert!(winner.background_network_allowed().await);
        assert_eq!(winner.ssh_pools.read().await.len(), 1);

        // A zero connection budget refuses before any SSH process or socket.
        // Reaching that refusal proves the losing candidate did not revoke
        // the already-healthy winner's shared worker-ID pool admission.
        let error = ssh_pool
            .get_or_connect(&config)
            .await
            .err()
            .expect("the zero connection budget must refuse without dialing");
        assert!(
            format!("{error:#}").contains("SSH connection timed out before spawn"),
            "the healthy winner lost pooled admission: {error:#}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn offline_worker_retired_endpoint_rejects_late_build_reservations() {
        let pool = WorkerPool::new();
        let config = recovered_worker_config("removed-worker", 4);
        pool.add_worker(config.clone()).await;
        let retired = pool.get(&config.id).await.unwrap();
        let old_probe = retired.background_probe().await.unwrap();
        assert!(pool.remove_worker(&config.id).await);
        assert!(!old_probe.is_current());
        assert!(!retired.reserve_slots(1).await);
        assert_eq!(retired.used_slots(), 0);

        pool.add_worker(config.clone()).await;
        let replacement = pool.get(&config.id).await.unwrap();
        assert!(replacement.reserve_slots(1).await);
        assert!(!retired.reserve_slots(1).await);
        replacement.release_slots(1).await;
    }

    #[tokio::test(start_paused = true)]
    async fn offline_worker_owned_recovery_uses_only_matching_transport_evidence() {
        let config = recovered_worker_config("owned-recovery", 4);
        let pool = WorkerPool::new();
        pool.add_worker(config.clone()).await;
        let worker = pool.get(&config.id).await.unwrap();
        worker
            .record_transport_result(
                true,
                Duration::from_secs(30),
                &CircuitBreakerConfig::default(),
            )
            .await;
        worker.require_connection_probe();
        worker.open_circuit().await;
        worker
            .enter_bypass(BypassFailureClass::DiskInodePressure)
            .await;
        assert!(!worker.background_network_allowed().await);
        // Admission/readiness and storage/circuit quarantine cannot prohibit
        // recovery of a process group that this worker already owns.
        let mut permit = pool
            .owned_recovery_admission(&config)
            .await
            .expect("non-transport quarantine blocked authenticated owned recovery");
        let operation = permit.run(std::future::pending::<()>());
        tokio::pin!(operation);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(operation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let circuit = CircuitBreakerConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        worker
            .record_transport_result(false, Duration::from_secs(30), &circuit)
            .await;
        assert!(
            operation.await.is_none(),
            "new outage must revoke in-flight recovery"
        );
        assert!(pool.owned_recovery_admission(&config).await.is_none());

        let historical = WorkerConfig {
            host: "old-owned.example".into(),
            ..config.clone()
        };
        assert!(pool.owned_recovery_admission(&historical).await.is_some());
        worker
            .record_transport_result(true, Duration::from_secs(30), &circuit)
            .await;
        assert!(pool.owned_recovery_admission(&config).await.is_some());
        assert_eq!(
            worker.eligibility().await,
            EligibilityState::TemporaryBypass
        );
        assert_eq!(worker.circuit_state().await, Some(CircuitState::Open));
    }

    fn historical_transport_policy() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            open_cooldown_secs: 900,
            ..Default::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_probe_threshold_and_scans_share_one_clock() {
        let circuit = historical_transport_policy();
        let heartbeat = Duration::from_secs(30);
        let pool = WorkerPool::new().with_recovery_transport_policy(
            circuit.clone(),
            heartbeat,
            Duration::from_secs(10),
        );
        let endpoint = recovered_worker_config("historical-threshold", 16);
        let attempts = AtomicUsize::new(0);

        for failure in 1..=5 {
            // Repeated speculative scans and abandoned permits consume no
            // probe and do not push the shared deadline into the future.
            for _ in 0..16 {
                assert!(pool.owned_recovery_admission(&endpoint).await.is_some());
            }
            let mut admitted = pool.owned_recovery_admission(&endpoint).await.unwrap();
            assert!(
                admitted
                    .run_with_probe(
                        async { panic!("a failed preflight cannot poll owned recovery") },
                        async {
                            attempts.fetch_add(1, Ordering::SeqCst);
                            false
                        },
                    )
                    .await
                    .is_none()
            );
            assert_eq!(attempts.load(Ordering::SeqCst), failure);
            let delay = if failure < 3 {
                heartbeat
            } else {
                Duration::from_secs(900)
            };
            for _ in 0..16 {
                assert!(pool.owned_recovery_admission(&endpoint).await.is_none());
            }
            tokio::time::advance(delay - Duration::from_secs(1)).await;
            assert!(pool.owned_recovery_admission(&endpoint).await.is_none());
            tokio::time::advance(Duration::from_secs(1)).await;
        }

        // An unrelated lookup after the outage deadline has expired must not
        // prune this down endpoint and reset its consecutive-failure history.
        assert!(
            pool.owned_recovery_admission(&recovered_worker_config("other", 4))
                .await
                .is_some()
        );
        let state = pool.endpoint_transports.get(&endpoint);
        assert_eq!(state.state.lock().await.failures, 5);
        assert!(state.state.lock().await.down);

        let mut recovered = pool.owned_recovery_admission(&endpoint).await.unwrap();
        assert_eq!(
            recovered.run_with_probe(async { 7 }, async { true }).await,
            Some(7)
        );
        // Positive evidence is shared, so several owners can finish at the
        // producer cadence rather than one owner per heartbeat interval.
        for owner in 0..16 {
            let mut admitted = pool.owned_recovery_admission(&endpoint).await.unwrap();
            assert_eq!(
                admitted
                    .run_with_probe(async { owner }, async {
                        panic!("fresh evidence should be reused")
                    },)
                    .await,
                Some(owner)
            );
        }
        assert_eq!(state.state.lock().await.failures, 0);
        assert!(!state.state.lock().await.down);
        tokio::time::advance(heartbeat).await;
        let mut stale = pool.owned_recovery_admission(&endpoint).await.unwrap();
        assert!(
            stale
                .run_with_probe(
                    async { panic!("expired positive evidence cannot bypass a failed probe") },
                    async { false },
                )
                .await
                .is_none()
        );
        assert_eq!(state.state.lock().await.failures, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_cancelled_probe_keeps_deadline_and_shared_flight() {
        let heartbeat = Duration::from_secs(30);
        let pool = WorkerPool::new().with_recovery_transport_policy(
            historical_transport_policy(),
            heartbeat,
            Duration::from_secs(10),
        );
        let endpoint = recovered_worker_config("historical-cancelled-probe", 4);
        let mut first = pool.owned_recovery_admission(&endpoint).await.unwrap();
        let mut queued = pool.owned_recovery_admission(&endpoint).await.unwrap();
        let attempts = AtomicUsize::new(0);
        {
            let pending = first.run_with_probe(
                async { panic!("unfinished preflight cannot poll the recovery") },
                async {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    std::future::pending().await
                },
            );
            tokio::pin!(pending);
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            assert!(pool.owned_recovery_admission(&endpoint).await.is_none());
            assert!(
                queued
                    .run_with_probe(async { panic!("competing recovery was polled") }, async {
                        panic!("competing preflight was polled")
                    },)
                    .await
                    .is_none()
            );

            // Reintroducing A cannot create a second health-probe mutex.
            pool.add_worker(endpoint.clone()).await;
            let worker = pool.get(&endpoint.id).await.unwrap();
            assert!(
                worker
                    .health_probe_permit(heartbeat, &historical_transport_policy())
                    .await
                    .is_none()
            );
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        pool.remove_worker(&endpoint.id).await;
        assert!(pool.owned_recovery_admission(&endpoint).await.is_none());
        tokio::time::advance(heartbeat - Duration::from_secs(1)).await;
        assert!(pool.owned_recovery_admission(&endpoint).await.is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(pool.owned_recovery_admission(&endpoint).await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_probe_release_wakes_reintroduced_health_without_resetting_deadline()
     {
        let heartbeat = Duration::from_secs(30);
        let circuit = historical_transport_policy();
        for down in [false, true] {
            for completed in [false, true] {
                let pool = WorkerPool::new()
                    .with_connection_monitoring()
                    .with_recovery_transport_policy(
                        circuit.clone(),
                        heartbeat,
                        Duration::from_secs(10),
                    );
                let endpoint = recovered_worker_config("historical-probe-return", 8);
                if down {
                    for _ in 0..circuit.failure_threshold {
                        pool.record_owned_recovery_transport_result(&endpoint, false)
                            .await;
                    }
                    tokio::time::advance(Duration::from_secs(900)).await;
                }
                let mut admitted = pool.owned_recovery_admission(&endpoint).await.unwrap();
                let mut changes;
                let worker;
                {
                    let (complete, result) = tokio::sync::oneshot::channel();
                    let pending =
                        admitted.run_with_probe(async { 7 }, async { result.await.unwrap() });
                    tokio::pin!(pending);
                    std::future::poll_fn(|context| {
                        assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
                        std::task::Poll::Ready(())
                    })
                    .await;

                    // Health sees the new current A, but its shared flight is
                    // busy and the monitor may choose the 900-second fallback.
                    pool.add_worker(endpoint.clone()).await;
                    pool.restore_recovered_slots(&endpoint.id, 3).await.unwrap();
                    worker = pool.get(&endpoint.id).await.unwrap();
                    assert!(worker.next_health_probe_in().await.is_none());
                    changes = pool.subscribe_endpoint_changes();
                    tokio::time::advance(Duration::from_secs(5)).await;
                    assert!(!changes.has_changed().unwrap());
                    if completed {
                        complete.send(true).unwrap();
                        assert_eq!(pending.await, Some(7));
                    }
                    // Otherwise dropping the actual probe future exercises
                    // the same release path as administrative cancellation.
                }
                assert!(
                    changes.has_changed().unwrap(),
                    "probe completion/cancellation must wake current health"
                );
                changes.changed().await.unwrap();
                let remaining = if down && completed {
                    heartbeat
                } else if down {
                    Duration::from_secs(895)
                } else {
                    Duration::from_secs(25)
                };
                assert_eq!(worker.next_health_probe_in().await, Some(remaining));
                assert!(!worker.background_network_allowed().await);
                assert_eq!(worker.used_slots(), 3);
                tokio::time::advance(remaining).await;
                assert!(
                    worker
                        .health_probe_permit(heartbeat, &circuit)
                        .await
                        .is_some()
                );
                assert_eq!(worker.used_slots(), 3);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_operation_lane_leaves_health_free_and_revocable() {
        let heartbeat = Duration::from_secs(30);
        let circuit = CircuitBreakerConfig {
            failure_threshold: 1,
            ..historical_transport_policy()
        };
        let pool = WorkerPool::new()
            .with_connection_monitoring()
            .with_recovery_transport_policy(circuit.clone(), heartbeat, Duration::from_secs(10));
        let endpoint = recovered_worker_config("historical-active-recovery", 8);
        pool.record_owned_recovery_transport_result(&endpoint, true)
            .await;
        let mut first = pool.owned_recovery_admission(&endpoint).await.unwrap();
        let mut queued = pool.owned_recovery_admission(&endpoint).await.unwrap();
        let pending = first.run_with_probe(std::future::pending::<()>(), async {
            panic!("recent positive evidence should need no probe")
        });
        tokio::pin!(pending);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(
            queued
                .run_with_probe(
                    async { panic!("lease and cancellation must not overlap this endpoint") },
                    async { panic!("a competing operation cannot launch a probe") },
                )
                .await
                .is_none()
        );

        pool.add_worker(endpoint.clone()).await;
        pool.restore_recovered_slots(&endpoint.id, 3).await.unwrap();
        let current = pool.get(&endpoint.id).await.unwrap();
        let probe = current
            .health_probe_permit(heartbeat, &circuit)
            .await
            .expect("owned work must not hold the health probe lane");
        assert_eq!(
            current
                .record_health_transport_result(&probe, false, heartbeat, &circuit)
                .await,
            Some((false, true))
        );
        assert!(
            pending.await.is_none(),
            "current health revokes historical recovery"
        );
        assert_eq!(current.used_slots(), 3);
        assert!(pool.owned_recovery_admission(&endpoint).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_failure_revokes_reintroduced_background_without_rejoining_it() {
        let heartbeat = Duration::from_secs(30);
        let circuit = CircuitBreakerConfig {
            failure_threshold: 1,
            ..historical_transport_policy()
        };
        let pool = WorkerPool::new()
            .with_connection_monitoring()
            .with_recovery_transport_policy(circuit.clone(), heartbeat, Duration::from_secs(10));
        let endpoint = recovered_worker_config("historical-background", 8);
        pool.add_worker(endpoint.clone()).await;
        let worker = pool.get(&endpoint.id).await.unwrap();
        worker
            .record_transport_result(true, heartbeat, &circuit)
            .await;
        assert!(worker.reserve_slots(3).await);
        let mut background = worker.background_probe().await.unwrap();
        let pending = background.run(std::future::pending::<()>());
        tokio::pin!(pending);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;

        // This is the same governor publication a historical probe performs
        // if A returns to inventory while its SSH command is in flight.
        pool.record_owned_recovery_transport_result(&endpoint, false)
            .await;
        assert!(pending.await.is_none());
        assert!(!worker.background_network_allowed().await);
        assert!(!worker.reserve_slots(1).await);
        assert!(pool.healthy_workers().await.is_empty());
        pool.record_owned_recovery_transport_result(&endpoint, true)
            .await;
        assert!(
            !worker.background_network_allowed().await,
            "a historical echo is not current scheduling health"
        );
        assert!(!worker.reserve_slots(1).await);
        assert_eq!(worker.used_slots(), 3);
        worker
            .record_transport_result(true, heartbeat, &circuit)
            .await;
        assert!(worker.background_network_allowed().await);
        assert_eq!(worker.used_slots(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_late_publication_cannot_overwrite_enable_reset() {
        let transport = Arc::new(EndpointTransport::new());
        let network = transport.revision_guard();
        let circuit = historical_transport_policy();
        let state = transport.state.lock().await;
        let reset = transport.reset();
        tokio::pin!(reset);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(reset.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let publication =
            transport.record_probe_result(&network, true, Duration::from_secs(30), &circuit);
        tokio::pin!(publication);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(publication.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(state);
        reset.await;
        assert!(
            publication.await.is_none(),
            "the queued pre-enable result has lost its epoch"
        );
        let state = transport.state.lock().await;
        assert!(!state.connected);
        assert!(state.positive_evidence.is_none());
        assert!(state.next_probe.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_enable_and_late_health_preserve_other_endpoint_clock() {
        let heartbeat = Duration::from_secs(30);
        let circuit = CircuitBreakerConfig {
            failure_threshold: 1,
            ..historical_transport_policy()
        };
        let pool = WorkerPool::new().with_recovery_transport_policy(
            circuit.clone(),
            heartbeat,
            Duration::from_secs(10),
        );
        let original = recovered_worker_config("historical-enable", 8);
        pool.add_worker(original.clone()).await;
        let worker = pool.get(&original.id).await.unwrap();
        assert!(worker.reserve_slots(3).await);
        let old_probe = worker
            .health_probe_permit(heartbeat, &circuit)
            .await
            .unwrap();
        worker
            .record_transport_result(false, heartbeat, &circuit)
            .await;
        let mut replacement = original.clone();
        replacement.host = "replacement.example".into();
        pool.add_worker(replacement).await;
        worker.enable().await;
        assert!(
            worker
                .record_health_transport_result(&old_probe, true, heartbeat, &circuit)
                .await
                .is_none()
        );
        assert!(!worker.background_network_allowed().await);
        assert!(pool.owned_recovery_admission(&original).await.is_none());
        assert_eq!(worker.used_slots(), 3);
        drop(old_probe);
        tokio::time::advance(Duration::from_secs(899)).await;
        pool.add_worker(original.clone()).await;
        assert!(worker.transport_is_down().await);
        assert_eq!(
            worker.next_health_probe_in().await,
            Some(Duration::from_secs(1))
        );
        assert!(pool.owned_recovery_admission(&original).await.is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            worker
                .health_probe_permit(heartbeat, &circuit)
                .await
                .is_some()
        );
        assert_eq!(worker.used_slots(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_startup_unknown_current_waits_for_health_evidence() {
        let pool = WorkerPool::new().with_connection_monitoring();
        let endpoint = recovered_worker_config("historical-startup", 4);
        pool.add_worker(endpoint.clone()).await;
        pool.restore_recovered_slots(&endpoint.id, 3).await.unwrap();
        let worker = pool.get(&endpoint.id).await.unwrap();
        assert!(pool.owned_recovery_admission(&endpoint).await.is_none());
        let circuit = CircuitBreakerConfig::default();
        let probe = worker
            .health_probe_permit(Duration::from_secs(30), &circuit)
            .await
            .unwrap();
        assert!(pool.owned_recovery_admission(&endpoint).await.is_none());
        worker
            .record_health_transport_result(&probe, true, Duration::from_secs(30), &circuit)
            .await
            .unwrap();
        let mut owned = pool.owned_recovery_admission(&endpoint).await.unwrap();
        assert_eq!(
            owned
                .run_with_probe(async { 7 }, async {
                    panic!("current health already proved transport")
                })
                .await,
            Some(7)
        );
        assert_eq!(worker.used_slots(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn offline_worker_day_long_outage_has_one_bounded_probe_per_interval() {
        let worker = Arc::new(WorkerState::new(recovered_worker_config("offline", 4)));
        let config = CircuitBreakerConfig::default();
        let heartbeat = Duration::from_secs(30);
        let mut attempts = 0;
        for failure in 1..=config.failure_threshold {
            let permit = worker
                .health_probe_permit(heartbeat, &config)
                .await
                .unwrap();
            worker
                .record_transport_result(false, heartbeat, &config)
                .await;
            attempts += 1;
            assert!(!worker.background_network_allowed().await);
            assert!(!worker.reserve_slots(1).await);
            assert_eq!(
                worker.transport_is_down().await,
                failure == config.failure_threshold
            );
            drop(permit);
            if failure < config.failure_threshold {
                tokio::time::advance(heartbeat).await;
            }
        }

        // Run an entire virtual day, exercising the real deadline/admission
        // code. No shortened production interval or sleep timing tolerance.
        for _ in 0..288 {
            tokio::time::advance(Duration::from_secs(299)).await;
            assert!(
                worker
                    .health_probe_permit(heartbeat, &config)
                    .await
                    .is_none()
            );
            assert!(worker.background_probe().await.is_none());
            tokio::time::advance(Duration::from_secs(1)).await;
            let permit = worker
                .health_probe_permit(heartbeat, &config)
                .await
                .unwrap();
            assert!(permit.isolated);
            // Concurrent consumers cannot turn the due recovery into a fanout.
            let mut contenders = tokio::task::JoinSet::new();
            for _ in 0..32 {
                let worker = worker.clone();
                let config = config.clone();
                contenders.spawn(async move {
                    worker
                        .health_probe_permit(heartbeat, &config)
                        .await
                        .is_none()
                });
            }
            while let Some(result) = contenders.join_next().await {
                assert!(result.unwrap());
            }
            worker
                .record_transport_result(false, heartbeat, &config)
                .await;
            attempts += 1;
            drop(permit);
        }
        assert_eq!(attempts, 291, "3 initial failures + 288 five-minute probes");
        assert_eq!(worker.lifecycle().await.admin, AdminIntent::Active);
    }

    #[tokio::test(start_paused = true)]
    async fn offline_worker_long_circuit_cooldown_controls_recovery_and_first_success() {
        let worker = WorkerState::new(recovered_worker_config("vpn", 4));
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_cooldown_secs: 900,
            ..Default::default()
        };
        let heartbeat = Duration::from_secs(30);
        let initial = worker
            .health_probe_permit(heartbeat, &config)
            .await
            .unwrap();
        worker
            .record_transport_result(false, heartbeat, &config)
            .await;
        drop(initial);
        tokio::time::advance(Duration::from_secs(899)).await;
        assert!(
            worker
                .health_probe_permit(heartbeat, &config)
                .await
                .is_none()
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let recovery = worker
            .health_probe_permit(heartbeat, &config)
            .await
            .unwrap();
        assert_eq!(
            worker
                .record_transport_result(true, heartbeat, &config)
                .await,
            (true, false)
        );
        assert!(worker.background_network_allowed().await);
        assert!(worker.reserve_slots(1).await);
        worker.release_slots(1).await;
        drop(recovery);
        tokio::time::advance(heartbeat).await;
        assert!(
            worker
                .health_probe_permit(heartbeat, &config)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn offline_worker_disable_revokes_inflight_permission_across_immediate_enable() {
        let worker = Arc::new(WorkerState::new(recovered_worker_config("disabled", 4)));
        let mut old = worker.background_probe().await.unwrap();
        worker.disable(Some("operator maintenance".into())).await;
        worker.enable().await;
        assert!(
            old.run(async { panic!("stale probe reached SSH") })
                .await
                .is_none()
        );
        assert!(
            old.run(async { 42 }).await.is_none(),
            "revocation remains permanent after observing it"
        );
        assert!(
            !worker.reserve_slots(1).await,
            "enable requests a probe; it does not prove reachability"
        );
        assert!(
            worker
                .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn offline_worker_disable_persists_through_inventory_removal_and_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.json");
        let mut store = AdminDisableStore::try_load(&path).unwrap();
        store
            .upsert(rch_common::bypass_record::AdminDisableRecord {
                worker_id: "sleeping".into(),
                reason: Some("operator".into()),
                disabled_unix_ms: 123,
            })
            .unwrap();
        let store = Arc::new(Mutex::new(store));
        let pool = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(store);
        pool.add_worker(recovered_worker_config("sleeping", 4))
            .await;
        let worker = pool.get(&WorkerId::new("sleeping")).await.unwrap();
        assert!(worker.is_disabled().await);
        pool.remove_worker(&WorkerId::new("sleeping")).await;
        pool.add_worker(recovered_worker_config("sleeping", 4))
            .await;
        let worker = pool.get(&WorkerId::new("sleeping")).await.unwrap();
        assert!(worker.is_disabled().await);
        assert!(worker.background_probe().await.is_none());
        assert!(
            worker
                .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                .await
                .is_none()
        );
        let restarted = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(Arc::new(Mutex::new(
                AdminDisableStore::try_load(path).unwrap(),
            )));
        restarted
            .add_worker(recovered_worker_config("sleeping", 4))
            .await;
        assert!(
            restarted
                .get(&WorkerId::new("sleeping"))
                .await
                .unwrap()
                .is_disabled()
                .await
        );
    }

    #[tokio::test]
    async fn offline_worker_enable_racing_replacement_changes_current_incarnation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.json");
        let store = Arc::new(Mutex::new(AdminDisableStore::try_load(&path).unwrap()));
        let pool = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(store.clone());
        let config = recovered_worker_config("replaced", 4);
        let id = config.id.clone();
        pool.add_worker(config.clone()).await;
        let original = pool.get(&id).await.unwrap();
        let mut context = crate::test_daemon_context(pool.clone());
        context.admin_disable_store = Some(store);
        assert_eq!(
            handle_worker_disable(&context, &id, Some("operator".into()), false)
                .await
                .status,
            "ok"
        );

        // Suspend the real API handler while reading the old incarnation's
        // status. Previously it had already resolved an Arc, but had not yet
        // acquired the durable intent lock, so reload could replace that Arc.
        let lifecycle = original.lifecycle.write().await;
        let enable = handle_worker_enable(&context, &id);
        tokio::pin!(enable);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(enable.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;

        let replacement = async {
            assert!(pool.remove_worker(&id).await);
            pool.add_worker(config.clone()).await;
        };
        tokio::pin!(replacement);
        let replaced_early = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(replacement.as_mut(), cx).is_ready())
        })
        .await;

        drop(lifecycle);
        let response = tokio::time::timeout(Duration::from_secs(1), enable)
            .await
            .expect("enable must complete after its status read is released");
        assert_eq!(response.status, "ok");
        if !replaced_early {
            tokio::time::timeout(Duration::from_secs(1), replacement)
                .await
                .expect("replacement must complete after administrative publication");
        }

        let current = pool.get(&id).await.unwrap();
        assert!(!Arc::ptr_eq(&original, &current));
        assert!(original.is_endpoint_retired());
        assert!(
            !current.is_disabled().await,
            "successful enable must affect the current worker, not only a retired Arc"
        );
        assert!(!current.background_network_allowed().await);
        assert!(
            current
                .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                .await
                .is_some(),
            "the replacement may now prove connectivity and automatically resume"
        );
        assert!(
            AdminDisableStore::try_load(&path)
                .unwrap()
                .get(id.as_str())
                .is_none()
        );

        let restarted = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(Arc::new(Mutex::new(
                AdminDisableStore::try_load(path).unwrap(),
            )));
        restarted.add_worker(config.clone()).await;
        assert!(!restarted.get(&id).await.unwrap().is_disabled().await);
    }

    #[tokio::test]
    async fn offline_worker_disable_racing_replacement_remains_durable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.json");
        let store = Arc::new(Mutex::new(AdminDisableStore::try_load(&path).unwrap()));
        let pool = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(store.clone());
        let config = recovered_worker_config("replaced", 4);
        let id = config.id.clone();
        pool.add_worker(config.clone()).await;
        let original = pool.get(&id).await.unwrap();
        original
            .record_transport_result(
                true,
                Duration::from_secs(30),
                &CircuitBreakerConfig::default(),
            )
            .await;
        let mut old_probe = original.background_probe().await.unwrap();
        let mut context = crate::test_daemon_context(pool.clone());
        context.admin_disable_store = Some(store);

        // Keep disable pending at the real transport publication boundary while
        // a remove/re-add tries to publish a replacement for the same worker ID.
        let transition = original.network_transition.lock().await;
        let disable = handle_worker_disable(&context, &id, Some("operator".into()), false);
        tokio::pin!(disable);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(disable.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let replacement = async {
            assert!(pool.remove_worker(&id).await);
            pool.add_worker(config.clone()).await;
        };
        tokio::pin!(replacement);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(replacement.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(transition);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), disable)
                .await
                .expect("disable must complete after transport publication is released")
                .status,
            "ok"
        );
        tokio::time::timeout(Duration::from_secs(1), replacement)
            .await
            .expect("replacement must complete after disable publishes its intent");

        let current = pool.get(&id).await.unwrap();
        assert!(!Arc::ptr_eq(&original, &current));
        assert!(current.is_disabled().await);
        assert!(!current.background_network_allowed().await);
        assert!(
            current
                .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                .await
                .is_none()
        );
        assert!(
            old_probe
                .run(async { panic!("a replaced and disabled probe must never dial") })
                .await
                .is_none()
        );
        let restarted = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(Arc::new(Mutex::new(
                AdminDisableStore::try_load(path).unwrap(),
            )));
        restarted.add_worker(config.clone()).await;
        assert!(restarted.get(&id).await.unwrap().is_disabled().await);
    }

    #[tokio::test]
    async fn offline_worker_failed_durable_enable_never_changes_live_intent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.json");
        let mut store = AdminDisableStore::try_load(&path).unwrap();
        store
            .upsert(rch_common::bypass_record::AdminDisableRecord {
                worker_id: "disabled".into(),
                reason: Some("operator".into()),
                disabled_unix_ms: 123,
            })
            .unwrap();
        let pool = WorkerPool::new();
        pool.add_worker(recovered_worker_config("disabled", 4))
            .await;
        let worker = pool.get(&WorkerId::new("disabled")).await.unwrap();
        worker.disable(Some("operator".into())).await;
        let store = Arc::new(Mutex::new(store));
        let mut context = crate::test_daemon_context(pool);
        context.admin_disable_store = Some(store.clone());
        std::fs::rename(&path, directory.path().join("saved-admin.json")).unwrap();
        std::fs::create_dir(&path).unwrap();
        for _ in 0..2 {
            let response = handle_worker_enable(&context, &WorkerId::new("disabled")).await;
            assert_eq!(response.status, "error");
            assert!(worker.is_disabled().await);
            assert!(worker.background_probe().await.is_none());
            assert!(store.lock().await.get("disabled").is_some());
        }
        assert!(
            AdminDisableStore::try_load(path).is_err(),
            "restart must refuse unreadable intent"
        );
    }

    async fn removed_worker_administration_fixture(
        disabled: bool,
    ) -> (tempfile::TempDir, DaemonContext, WorkerConfig, u64, u64) {
        use crate::history::BuildHistory;

        let directory = tempfile::tempdir().unwrap();
        let history_path = directory.path().join("history.jsonl");
        let admin_path = directory.path().join("admin.json");
        let config = recovered_worker_config("historical-worker", 8);
        let original = WorkerState::new(config.clone());
        let history = BuildHistory::new(10).with_persistence(history_path.clone());
        let wrapper = rch_common::job_identity::JobIdentity::new_local().local_wrapper_id;
        let build = history
            .try_start_active_build_with_waiter(
                "historical-project".into(),
                config.id.to_string(),
                "cargo check".into(),
                0,
                Some(wrapper.clone()),
                3,
                rch_common::BuildLocation::Remote,
                None,
                crate::disk_pressure::DiskHeadroomAdmission::default(),
                Some(original.endpoint_snapshot().await),
            )
            .unwrap()
            .unwrap();
        history
            .record_build_heartbeat(rch_common::BuildHeartbeatRequest {
                build_id: build.id,
                worker_id: config.id.clone(),
                hook_pid: None,
                local_wrapper_id: Some(wrapper),
                remote_pgid_file: Some("/owned/historical-build.pgid".into()),
                phase: rch_common::BuildHeartbeatPhase::Execute,
                detail: None,
                progress_counter: Some(1),
                progress_percent: None,
            })
            .unwrap();
        let peer = history.start_active_build(
            "unrelated-project".into(),
            "peer".into(),
            "cargo test".into(),
            0,
            2,
            rch_common::BuildLocation::Remote,
        );
        if disabled {
            AdminDisableStore::with_path(&admin_path)
                .upsert(rch_common::bypass_record::AdminDisableRecord {
                    worker_id: config.id.to_string(),
                    reason: Some("intentional maintenance".into()),
                    disabled_unix_ms: 1,
                })
                .unwrap();
        }
        drop(history);
        let store = Arc::new(Mutex::new(AdminDisableStore::try_load(admin_path).unwrap()));
        let pool = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(store.clone());
        pool.add_worker(recovered_worker_config("peer", 8)).await;
        let mut context = crate::test_daemon_context(pool.clone());
        context.admin_disable_store = Some(store);
        context.history = Arc::new(BuildHistory::load_from_file(&history_path, 10).unwrap());
        for active in context.history.active_builds() {
            pool.restore_recovered_slots(&WorkerId::new(&active.worker_id), active.slots)
                .await
                .unwrap();
        }
        assert!(pool.get(&config.id).await.is_none());
        assert_eq!(pool.recovered_absent_slots.read().await[&config.id], 3);
        (directory, context, config, build.id, peer.id)
    }

    #[tokio::test]
    async fn offline_worker_removed_restart_can_disable_historical_recovery() {
        for drain in [false, true] {
            let (directory, context, config, build, peer) =
                removed_worker_administration_fixture(false).await;
            let store = context.admin_disable_store.as_ref().unwrap();
            let mut admitted = store
                .lock()
                .await
                .automatic_network_permit(config.id.as_str())
                .unwrap();
            let response = handle_worker_disable(
                &context,
                &config.id,
                Some("stop historical recovery".into()),
                drain,
            )
            .await;
            assert_eq!(response.status, "ok", "{response:?}");
            assert_eq!(response.new_status.as_deref(), Some("disabled"));
            assert_eq!(response.active_slots, Some(3));
            assert!(
                admitted
                    .run(async { panic!("disabled historical recovery was polled") })
                    .await
                    .is_none()
            );
            assert!(context.pool.get(&config.id).await.is_none());
            assert_eq!(
                context.pool.recovered_absent_slots.read().await[&config.id],
                3
            );
            let cancelled = context
                .cancellation
                .cancel_build(
                    &context,
                    build,
                    crate::cancellation::CancelReason::StuckDetector,
                    true,
                )
                .await;
            assert_eq!(cancelled.status, "deferred");
            assert_eq!(cancelled.slots_released, 0);
            assert!(context.history.active_build(build).is_some());
            assert!(context.history.active_build(peer).is_some());
            assert_eq!(
                context
                    .pool
                    .get(&WorkerId::new("peer"))
                    .await
                    .unwrap()
                    .used_slots(),
                2
            );

            let restarted = Arc::new(Mutex::new(
                AdminDisableStore::try_load(directory.path().join("admin.json")).unwrap(),
            ));
            assert!(
                restarted
                    .lock()
                    .await
                    .automatic_network_permit(config.id.as_str())
                    .is_none()
            );
            let pool = WorkerPool::new().with_admin_disable_store(restarted);
            pool.restore_recovered_slots(&config.id, 3).await.unwrap();
            pool.add_worker(config.clone()).await;
            let returned = pool.get(&config.id).await.unwrap();
            assert!(returned.is_disabled().await);
            assert_eq!(returned.used_slots(), 3);
            assert!(
                returned
                    .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                    .await
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn offline_worker_removed_restart_can_enable_historical_recovery() {
        let (directory, context, config, build, peer) =
            removed_worker_administration_fixture(true).await;
        let store = context.admin_disable_store.as_ref().unwrap();
        assert!(
            store
                .lock()
                .await
                .automatic_network_permit(config.id.as_str())
                .is_none()
        );
        let response = handle_worker_enable(&context, &config.id).await;
        assert_eq!(response.status, "ok", "{response:?}");
        assert_eq!(response.active_slots, Some(3));
        assert!(context.pool.get(&config.id).await.is_none());
        assert_eq!(
            context.pool.recovered_absent_slots.read().await[&config.id],
            3
        );
        let mut admitted = store
            .lock()
            .await
            .automatic_network_permit(config.id.as_str())
            .unwrap();
        assert_eq!(admitted.run(async { 7 }).await, Some(7));
        assert!(
            AdminDisableStore::try_load(directory.path().join("admin.json"))
                .unwrap()
                .get(config.id.as_str())
                .is_none()
        );
        let original = context.history.active_build(build).unwrap();
        assert_eq!(original.worker_endpoint.unwrap().config.host, config.host);
        assert!(context.history.active_build(peer).is_some());
        assert_eq!(
            context
                .pool
                .get(&WorkerId::new("peer"))
                .await
                .unwrap()
                .used_slots(),
            2
        );
        context.pool.add_worker(config.clone()).await;
        let returned = context.pool.get(&config.id).await.unwrap();
        assert!(!returned.is_disabled().await);
        assert_eq!(returned.used_slots(), 3);
        assert!(!returned.background_network_allowed().await);
        assert!(
            returned
                .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn offline_worker_absent_admin_failure_retains_suspension_until_durable_enable() {
        let (directory, context, config, build, peer) =
            removed_worker_administration_fixture(false).await;
        let path = directory.path().join("admin.json");
        let store = context.admin_disable_store.as_ref().unwrap();
        let mut old_permit = store
            .lock()
            .await
            .automatic_network_permit(config.id.as_str())
            .unwrap();
        std::fs::create_dir(&path).unwrap();
        let disabled =
            handle_worker_disable(&context, &config.id, Some("maintenance".into()), false).await;
        assert_eq!(disabled.status, "error");
        assert_eq!(disabled.new_status.as_deref(), Some("disabled"));
        assert!(
            disabled
                .message
                .unwrap()
                .contains("durable state could not be saved")
        );
        assert!(store.lock().await.get(config.id.as_str()).is_none());
        assert!(
            store
                .lock()
                .await
                .automatic_network_permit(config.id.as_str())
                .is_none()
        );
        for _ in 0..2 {
            let enabled = handle_worker_enable(&context, &config.id).await;
            assert_eq!(enabled.status, "error");
            assert!(
                enabled
                    .message
                    .unwrap()
                    .contains("Could not clear durable disable")
            );
            assert!(
                store
                    .lock()
                    .await
                    .automatic_network_permit(config.id.as_str())
                    .is_none()
            );
        }
        std::fs::rename(&path, directory.path().join("blocked-admin-path")).unwrap();
        assert_eq!(
            handle_worker_enable(&context, &config.id).await.status,
            "ok"
        );
        assert!(
            store
                .lock()
                .await
                .automatic_network_permit(config.id.as_str())
                .is_some()
        );
        assert!(
            old_permit
                .run(async { panic!("an old permission survived disable/enable") })
                .await
                .is_none()
        );
        assert!(
            AdminDisableStore::try_load(&path)
                .unwrap()
                .get(config.id.as_str())
                .is_none()
        );
        assert!(context.pool.get(&config.id).await.is_none());
        assert_eq!(
            context.pool.recovered_absent_slots.read().await[&config.id],
            3
        );
        assert!(context.history.active_build(build).is_some());
        assert!(context.history.active_build(peer).is_some());
    }

    #[tokio::test]
    async fn offline_worker_absent_administration_rejects_unknown_but_accepts_retained_intent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.json");
        let mut persisted = AdminDisableStore::with_path(&path);
        persisted
            .upsert(rch_common::bypass_record::AdminDisableRecord {
                worker_id: "remembered".into(),
                reason: Some("hardware maintenance".into()),
                disabled_unix_ms: 1,
            })
            .unwrap();
        drop(persisted);
        let store = Arc::new(Mutex::new(AdminDisableStore::try_load(&path).unwrap()));
        let pool = WorkerPool::new().with_admin_disable_store(store.clone());
        let mut context = crate::test_daemon_context(pool.clone());
        context.admin_disable_store = Some(store.clone());
        let before = std::fs::read(&path).unwrap();
        let unknown = WorkerId::new("never-configured-or-owned");
        assert_eq!(
            handle_worker_disable(&context, &unknown, None, false)
                .await
                .status,
            "error"
        );
        assert_eq!(
            handle_worker_enable(&context, &unknown).await.status,
            "error"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(
            store
                .lock()
                .await
                .effective_disable(unknown.as_str())
                .is_none()
        );
        let known = WorkerId::new("remembered");
        let refreshed =
            handle_worker_disable(&context, &known, Some("still offline".into()), true).await;
        assert_eq!(refreshed.status, "ok");
        assert_eq!(refreshed.active_slots, Some(0));
        assert_eq!(
            store
                .lock()
                .await
                .get(known.as_str())
                .unwrap()
                .reason
                .as_deref(),
            Some("still offline")
        );
        let enabled = handle_worker_enable(&context, &known).await;
        assert_eq!(enabled.status, "ok");
        assert_eq!(enabled.active_slots, Some(0));
        assert!(pool.is_empty());
        assert!(AdminDisableStore::try_load(&path).unwrap().all().is_empty());
    }

    #[tokio::test]
    async fn offline_worker_historical_administration_serializes_reintroduction() {
        for enabling in [false, true] {
            let (_directory, context, config, build, peer) =
                removed_worker_administration_fixture(enabling).await;
            let store = context.admin_disable_store.as_ref().unwrap();
            let durable = store.lock().await;
            let transition = async {
                if enabling {
                    handle_worker_enable(&context, &config.id).await
                } else {
                    handle_worker_disable(&context, &config.id, Some("operator".into()), false)
                        .await
                }
            };
            tokio::pin!(transition);
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(transition.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            let replacement = WorkerConfig {
                host: "replacement.example.invalid".into(),
                ..config.clone()
            };
            let addition = context.pool.add_worker(replacement.clone());
            tokio::pin!(addition);
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(addition.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(durable);
            let (response, ()) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(transition, addition)
            })
            .await
            .expect("historical administration and registration must complete");
            assert_eq!(response.status, "ok");
            let current = context.pool.get(&config.id).await.unwrap();
            assert_eq!(current.is_disabled().await, !enabling);
            assert_eq!(current.config.read().await.host, replacement.host);
            assert_eq!(current.used_slots(), 3);
            assert!(context.pool.recovered_absent_slots.read().await.is_empty());
            assert_eq!(
                context
                    .history
                    .active_build(build)
                    .unwrap()
                    .worker_endpoint
                    .unwrap()
                    .config
                    .host,
                config.host
            );
            assert!(context.history.active_build(peer).is_some());
            assert_eq!(
                context
                    .pool
                    .get(&WorkerId::new("peer"))
                    .await
                    .unwrap()
                    .used_slots(),
                2
            );
        }
    }

    #[tokio::test]
    async fn offline_worker_failed_durable_disable_stops_live_network_but_reports_error() {
        let directory = tempfile::tempdir().unwrap();
        let pool = WorkerPool::new();
        pool.add_worker(recovered_worker_config("disabled", 4))
            .await;
        let worker = pool.get(&WorkerId::new("disabled")).await.unwrap();
        let mut old_probe = worker.background_probe().await.unwrap();
        let mut context = crate::test_daemon_context(pool);
        // A directory cannot be atomically replaced with the state document.
        context.admin_disable_store = Some(Arc::new(Mutex::new(AdminDisableStore::with_path(
            directory.path(),
        ))));
        let response = handle_worker_disable(
            &context,
            &WorkerId::new("disabled"),
            Some("operator".into()),
            false,
        )
        .await;
        assert_eq!(response.status, "error");
        assert_eq!(response.new_status.as_deref(), Some("disabled"));
        assert!(worker.is_disabled().await);
        assert!(
            old_probe
                .run(async { panic!("disabled operation dialed") })
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn offline_worker_failed_disable_survives_inventory_replacement_in_this_daemon() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.json");
        let store = Arc::new(Mutex::new(AdminDisableStore::with_path(&path)));
        let pool = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(store.clone());
        let config = recovered_worker_config("failed-save", 4);
        let id = config.id.clone();
        pool.add_worker(config.clone()).await;
        let original = pool.get(&id).await.unwrap();
        let mut context = crate::test_daemon_context(pool.clone());
        context.admin_disable_store = Some(store.clone());
        std::fs::create_dir(&path).unwrap();
        let response =
            handle_worker_disable(&context, &id, Some("operator: powered off".into()), false).await;
        assert_eq!(
            response.status, "error",
            "failed save must remain visible to the operator"
        );
        assert!(store.lock().await.get(id.as_str()).is_none());
        assert!(original.is_disabled().await);
        assert!(pool.remove_worker(&id).await);
        pool.add_worker(config.clone()).await;
        let replacement = pool.get(&id).await.unwrap();
        assert!(!Arc::ptr_eq(&original, &replacement));
        assert!(replacement.is_disabled().await);
        assert_eq!(
            replacement.disabled_reason().await.as_deref(),
            Some("operator: powered off")
        );
        assert!(replacement.background_probe().await.is_none());
        assert!(
            replacement
                .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                .await
                .is_none()
        );
        assert!(
            store
                .lock()
                .await
                .automatic_network_permit(id.as_str())
                .is_none()
        );

        // This was deliberately not a successful durable disable. After the
        // obstruction is moved away, restart sees the unchanged empty disk
        // state; retaining live intent must not invent a persistence guarantee.
        std::fs::rename(&path, directory.path().join("obstruction")).unwrap();
        let restarted = WorkerPool::new()
            .with_connection_monitoring()
            .with_admin_disable_store(Arc::new(Mutex::new(
                AdminDisableStore::try_load(&path).unwrap(),
            )));
        restarted.add_worker(config).await;
        let after_restart = restarted.get(&id).await.unwrap();
        assert!(!after_restart.is_disabled().await);
        assert!(
            after_restart
                .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_freshly_added_worker_gets_no_slots_until_its_disk_is_measured() {
        // Daemon startup: every worker is re-added with unknown disk. Without
        // the hold, a 12 GB-free worker took its full ceiling and one source
        // sync filled it (2026-10-16).
        let selection = rch_common::SelectionConfig {
            min_free_gb: Some(10.0),
            disk_gb_per_slot: 5.0,
            ..Default::default()
        };
        let pool = WorkerPool::with_selection_config(&selection)
            .with_unmeasured_capacity_hold(std::time::Duration::from_secs(120));
        pool.add_worker(recovered_worker_config("unmeasured", 3))
            .await;
        let worker = pool.get(&WorkerId::new("unmeasured")).await.unwrap();
        assert_eq!(worker.effective_total_slots().await, 0);
        assert_eq!(worker.available_slots().await, 0);
        assert!(!worker.reserve_slots(1).await);
        // Startup re-adoption of durable ownership is not an admission.
        worker.restore_slots(1).unwrap();
        assert_eq!(worker.used_slots(), 1);

        // The first sample ends the hold and the normal disk math applies:
        // floor((22 - 10) / 5) = 2 of 3.
        worker
            .set_pressure_assessment(PressureAssessment {
                state: crate::disk_pressure::PressureState::Warning,
                telemetry_fresh: true,
                disk_free_gb: Some(22.0),
                ..Default::default()
            })
            .await;
        assert_eq!(worker.effective_total_slots().await, 2);
        assert!(worker.reserve_slots(1).await);

        // A worker whose telemetry never arrives regains the configured
        // ceiling once the hold lapses (the previous behaviour).
        pool.add_worker(recovered_worker_config("never-measured", 3))
            .await;
        let silent = pool.get(&WorkerId::new("never-measured")).await.unwrap();
        assert_eq!(silent.effective_total_slots().await, 0);
        silent.hold_until_capacity_measured(std::time::Duration::ZERO);
        assert_eq!(silent.effective_total_slots().await, 3);

        // Pools built without a hold (tests, embedded use) are unchanged.
        let plain = WorkerPool::with_selection_config(&selection);
        plain.add_worker(recovered_worker_config("plain", 3)).await;
        let plain = plain.get(&WorkerId::new("plain")).await.unwrap();
        assert_eq!(plain.effective_total_slots().await, 3);
    }

    #[tokio::test]
    async fn declared_disk_budget_observation_is_live_and_invalidated_by_capability_updates() {
        use crate::disk_pressure::{DiskHeadroomAdmission, DiskHeadroomRejection};
        let worker = WorkerState::new(recovered_worker_config("disk-worker", 8));
        assert!(worker.disk_capacity_observation().await.is_none());
        worker
            .set_capabilities(WorkerCapabilities {
                build_disk_free_gb: Some(80.0),
                build_disk_total_gb: Some(100.0),
                ..Default::default()
            })
            .await;
        let first = DiskHeadroomAdmission {
            requested_gib: 64,
            floor_gib: 0,
            capacity: worker.disk_capacity_observation().await,
        };
        assert!(first.check("disk-worker", 0).is_ok());
        // A CPU/pressure cycle cannot manufacture or refresh disk evidence.
        worker
            .set_pressure_assessment(PressureAssessment {
                state: crate::disk_pressure::PressureState::Healthy,
                telemetry_fresh: true,
                build_disk_free_gb: Some(1_000.0),
                ..Default::default()
            })
            .await;
        assert!(first.check("disk-worker", 17).is_err());
        worker
            .set_capabilities(WorkerCapabilities {
                build_disk_free_gb: Some(51.0),
                build_disk_total_gb: Some(100.0),
                ..Default::default()
            })
            .await;
        assert_eq!(
            first.check("disk-worker", 0),
            Err(DiskHeadroomRejection::Stale)
        );
        let second = DiskHeadroomAdmission {
            requested_gib: 64,
            floor_gib: 0,
            capacity: worker.disk_capacity_observation().await,
        };
        assert!(matches!(
            second.check("disk-worker", 0),
            Err(DiskHeadroomRejection::Insufficient { .. })
        ));
        worker.set_capabilities(WorkerCapabilities::default()).await;
        assert!(worker.disk_capacity_observation().await.is_none());
        assert_eq!(
            second.check("disk-worker", 0),
            Err(DiskHeadroomRejection::Stale)
        );
        worker
            .set_pressure_assessment(PressureAssessment {
                telemetry_fresh: true,
                ..Default::default()
            })
            .await;
        assert!(worker.disk_capacity_observation().await.is_none());
        worker
            .set_capabilities(WorkerCapabilities {
                build_disk_free_gb: Some(80.0),
                build_disk_total_gb: Some(100.0),
                ..Default::default()
            })
            .await;
        let before_reload = DiskHeadroomAdmission {
            requested_gib: 64,
            floor_gib: 0,
            capacity: worker.disk_capacity_observation().await,
        };
        let mut config = recovered_worker_config("disk-worker", 8);
        config.host = "different-host".into();
        worker.update_config(config).await;
        assert_eq!(
            before_reload.check("disk-worker", 0),
            Err(DiskHeadroomRejection::Stale)
        );
        assert!(
            WorkerState::new(recovered_worker_config("disk-worker", 8))
                .disk_capacity_observation()
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn declared_disk_budget_probe_cannot_publish_after_retarget_or_newer_probe() {
        use crate::disk_pressure::{DiskHeadroomAdmission, DiskHeadroomRejection};
        let worker = WorkerState::new(recovered_worker_config("disk-worker", 8));
        let old_endpoint = worker.capability_probe_context().await;
        let mut new_config = recovered_worker_config("disk-worker", 8);
        new_config.host = "new-host".into();
        worker.update_config(new_config).await;
        let caps = |free| WorkerCapabilities {
            build_disk_free_gb: Some(free),
            build_disk_total_gb: Some(100.0),
            ..Default::default()
        };
        assert!(!worker.publish_capabilities(old_endpoint, caps(90.0)).await);
        assert!(worker.disk_capacity_observation().await.is_none());
        assert!(worker.capabilities().await.build_disk_free_gb.is_none());
        let superseded = worker.capability_probe_context().await;
        let current = worker.capability_probe_context().await;
        assert!(worker.publish_capabilities(current, caps(51.0)).await);
        assert!(!worker.publish_capabilities(superseded, caps(90.0)).await);
        assert_eq!(worker.capabilities().await.build_disk_free_gb, Some(51.0));
        let mut delayed = worker.capability_probe_context().await;
        delayed.started_at = Instant::now() - Duration::from_secs(91);
        assert!(worker.publish_capabilities(delayed, caps(90.0)).await);
        assert_eq!(
            DiskHeadroomAdmission {
                requested_gib: 64,
                floor_gib: 0,
                capacity: worker.disk_capacity_observation().await,
            }
            .check("disk-worker", 0),
            Err(DiskHeadroomRejection::Stale),
            "probe duration is part of age"
        );
    }

    #[tokio::test]
    async fn absent_reservations_are_invisible_until_reintroduced_with_usage() {
        let pool = WorkerPool::new();
        let id = WorkerId::new("returning");
        assert!(!pool.restore_recovered_slots(&id, 2).await.unwrap());
        assert!(!pool.restore_recovered_slots(&id, 3).await.unwrap());
        assert!(pool.is_empty());
        assert!(pool.get(&id).await.is_none());
        assert!(pool.all_workers().await.is_empty());
        assert!(pool.healthy_workers().await.is_empty());

        pool.add_worker(recovered_worker_config(id.as_str(), 8))
            .await;
        let worker = pool.get(&id).await.unwrap();
        assert_eq!(pool.len(), 1);
        assert_eq!(worker.used_slots(), 5);
        assert_eq!(worker.available_slots().await, 3);
        assert!(!worker.reserve_slots(4).await);
        assert!(worker.reserve_slots(3).await);
        assert_eq!(worker.used_slots(), 8);
        assert!(pool.recovered_absent_slots.read().await.is_empty());
    }

    #[tokio::test]
    async fn completion_before_reintroduction_releases_only_remaining_ownership() {
        for released in [2, 5] {
            let pool = WorkerPool::new();
            let id = WorkerId::new("returning");
            pool.restore_recovered_slots(&id, 5).await.unwrap();
            pool.clone().release_slots(&id, released).await;
            assert!(pool.is_empty());
            pool.add_worker(recovered_worker_config(id.as_str(), 8))
                .await;
            let worker = pool.get(&id).await.unwrap();
            assert_eq!(worker.used_slots(), 5 - released);
            assert_eq!(worker.available_slots().await, 3 + released);
        }
    }

    #[tokio::test]
    async fn restored_usage_can_exceed_new_capacity_and_is_not_applied_twice() {
        let pool = WorkerPool::new();
        let id = WorkerId::new("smaller");
        pool.restore_recovered_slots(&id, 6).await.unwrap();
        pool.add_worker(recovered_worker_config(id.as_str(), 2))
            .await;
        let worker = pool.get(&id).await.unwrap();
        assert_eq!(worker.used_slots(), 6);
        assert_eq!(worker.available_slots().await, 0);
        assert!(!worker.reserve_slots(1).await);

        pool.add_worker(recovered_worker_config(id.as_str(), 8))
            .await;
        assert!(Arc::ptr_eq(&worker, &pool.get(&id).await.unwrap()));
        assert_eq!(worker.used_slots(), 6);
        pool.release_slots(&id, 4).await;
        assert_eq!(worker.used_slots(), 2);
        assert_eq!(worker.available_slots().await, 6);
        pool.add_worker(recovered_worker_config(id.as_str(), 8))
            .await;
        assert_eq!(worker.used_slots(), 2);
    }

    #[tokio::test]
    async fn configured_and_absent_workers_share_checked_reconstruction() {
        for configured in [false, true] {
            let pool = WorkerPool::new();
            let id = WorkerId::new("overflow");
            if configured {
                pool.add_worker(recovered_worker_config(id.as_str(), 8))
                    .await;
            }
            assert_eq!(
                pool.restore_recovered_slots(&id, u32::MAX).await.unwrap(),
                configured
            );
            assert!(pool.restore_recovered_slots(&id, 1).await.is_err());
            if !configured {
                pool.add_worker(recovered_worker_config(id.as_str(), 8))
                    .await;
            }
            let worker = pool.get(&id).await.unwrap();
            assert_eq!(worker.used_slots(), u32::MAX);
            assert_eq!(worker.available_slots().await, 0);
            pool.release_slots(&id, u32::MAX).await;
            assert_eq!(worker.used_slots(), 0);
            assert_eq!(worker.available_slots().await, 8);
        }
    }

    #[tokio::test]
    async fn missing_release_and_zero_reconstruction_cannot_create_inventory() {
        let pool = WorkerPool::new();
        let id = WorkerId::new("unknown");
        pool.release_slots(&id, 7).await;
        assert!(!pool.restore_recovered_slots(&id, 0).await.unwrap());
        assert!(pool.recovered_absent_slots.read().await.is_empty());
        assert!(pool.is_empty());
        pool.add_worker(recovered_worker_config(id.as_str(), 8))
            .await;
        assert_eq!(pool.get(&id).await.unwrap().used_slots(), 0);
    }

    #[tokio::test]
    async fn cancelled_reintroduction_cannot_drop_unpublished_reservations() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        let pool = WorkerPool::new();
        let id = WorkerId::new("cancelled-reload");
        pool.restore_recovered_slots(&id, 5).await.unwrap();
        let held = pool.recovered_absent_slots.write().await;
        let mut adding = Box::pin(pool.add_worker(recovered_worker_config(id.as_str(), 8)));
        poll_fn(|cx| {
            assert!(adding.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // The registry write lock is retained while the transfer waits. No
        // selector can observe the newly allocated state with zero usage.
        assert!(pool.workers.try_read().is_err());
        drop(adding);
        assert_eq!(held.get(&id), Some(&5));
        drop(held);
        assert!(pool.get(&id).await.is_none());
        pool.add_worker(recovered_worker_config(id.as_str(), 8))
            .await;
        assert_eq!(pool.get(&id).await.unwrap().used_slots(), 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn concurrent_reintroductions_and_completion_never_reset_or_duplicate_usage() {
        for iteration in 0..16 {
            let pool = WorkerPool::new();
            let id = WorkerId::new(format!("race-{iteration}"));
            pool.restore_recovered_slots(&id, 6).await.unwrap();
            let barrier = Arc::new(tokio::sync::Barrier::new(3));
            let mut tasks = Vec::new();
            for operation in 0..3 {
                let pool = pool.clone();
                let id = id.clone();
                let barrier = Arc::clone(&barrier);
                tasks.push(tokio::spawn(async move {
                    barrier.wait().await;
                    if operation == 0 {
                        pool.release_slots(&id, 2).await;
                    } else {
                        pool.add_worker(recovered_worker_config(id.as_str(), 8))
                            .await;
                    }
                }));
            }
            for task in tasks {
                tokio::time::timeout(std::time::Duration::from_secs(5), task)
                    .await
                    .unwrap()
                    .unwrap();
            }
            let worker = pool.get(&id).await.unwrap();
            assert_eq!(pool.len(), 1);
            assert_eq!(worker.used_slots(), 4);
            assert_eq!(worker.available_slots().await, 4);
            assert!(pool.recovered_absent_slots.read().await.is_empty());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn durable_ownership_survives_absent_worker_and_real_configuration_reload() {
        let directory = tempfile::tempdir().unwrap();
        let history_path = directory.path().join("history.jsonl");
        let workers_path = directory.path().join("workers.toml");
        let history = crate::history::BuildHistory::new(10).with_persistence(history_path.clone());
        let build = history.start_active_build(
            "recovered-project".into(),
            "returning".into(),
            "cargo check".into(),
            std::process::id(),
            5,
            rch_common::BuildLocation::Remote,
        );
        drop(history);
        let recovered = crate::history::BuildHistory::load_from_file(&history_path, 10).unwrap();
        let pool = WorkerPool::new();
        for active in recovered.active_builds() {
            assert!(
                !pool
                    .restore_recovered_slots(&WorkerId::new(&active.worker_id), active.slots)
                    .await
                    .unwrap()
            );
        }
        std::fs::write(&workers_path, "workers = []\n").unwrap();
        crate::reload::reload_workers(&pool, Some(&workers_path), true)
            .await
            .unwrap();
        assert!(pool.is_empty());
        assert!(recovered.active_build(build.id).is_some());

        std::fs::write(
            &workers_path,
            "[[workers]]\nid = 'returning'\nhost = '127.0.0.1'\nuser = 'user'\nidentity_file = '~/.ssh/id_rsa'\ntotal_slots = 8\n",
        )
        .unwrap();
        let change = crate::reload::reload_workers(&pool, Some(&workers_path), true)
            .await
            .unwrap();
        assert_eq!(change.added, 1);
        let worker = pool.get(&WorkerId::new("returning")).await.unwrap();
        assert_eq!(worker.used_slots(), 5);
        assert_eq!(worker.available_slots().await, 3);
        assert!(!worker.reserve_slots(4).await);

        let completed = recovered
            .complete_durable(
                build.id,
                "returning",
                None,
                crate::history::BuildCompletion {
                    exit_code: 0,
                    duration_ms: None,
                    bytes_transferred: None,
                    disk_peak_output_bytes: None,
                    timing: None,
                    cancellation: None,
                },
            )
            .unwrap()
            .unwrap();
        pool.release_slots(&WorkerId::new("returning"), completed.0.slots)
            .await;
        assert_eq!(worker.used_slots(), 0);
        assert_eq!(worker.available_slots().await, 8);
        assert!(recovered.active_build(build.id).is_none());
    }

    // =========================================================================
    // Worker lifecycle type model (bd-session-history-remediation-ocv9i.1.1)
    // =========================================================================

    /// Every concrete failure class, for exhaustive bypass-attribution tests.
    const ALL_FAILURE_CLASSES: &[BypassFailureClass] = &[
        BypassFailureClass::Ssh,
        BypassFailureClass::WorkerBinary,
        BypassFailureClass::RuntimeToolchain,
        BypassFailureClass::DiskInodePressure,
        BypassFailureClass::StaleTelemetry,
        BypassFailureClass::PathSync,
        BypassFailureClass::ArtifactRetrieval,
        BypassFailureClass::CircuitBreaker,
        BypassFailureClass::OsArchMismatch,
    ];

    #[test]
    fn lifecycle_new_is_active_healthy_and_schedulable() {
        let lc = WorkerLifecycle::new();
        assert_eq!(lc.admin, AdminIntent::Active);
        assert_eq!(lc.eligibility, EligibilityState::Healthy);
        assert_eq!(lc.bypass_cause, None);
        assert!(lc.is_schedulable());
        assert!(!lc.is_canary_pending());
        // Default must match new().
        assert_eq!(WorkerLifecycle::default(), lc);
    }

    #[test]
    fn lifecycle_from_worker_status_maps_both_axes() {
        let cases = [
            (
                WorkerStatus::Healthy,
                AdminIntent::Active,
                EligibilityState::Healthy,
            ),
            (
                WorkerStatus::Degraded,
                AdminIntent::Active,
                EligibilityState::Degraded,
            ),
            (
                WorkerStatus::Unreachable,
                AdminIntent::Active,
                EligibilityState::Unreachable,
            ),
            (
                WorkerStatus::Draining,
                AdminIntent::Draining,
                EligibilityState::Healthy,
            ),
            (
                WorkerStatus::Drained,
                AdminIntent::Drained,
                EligibilityState::Healthy,
            ),
            (
                WorkerStatus::Disabled,
                AdminIntent::Disabled,
                EligibilityState::Healthy,
            ),
        ];
        for (status, admin, eligibility) in cases {
            let lc = WorkerLifecycle::from_worker_status(status);
            assert_eq!(lc.admin, admin, "admin axis for {status:?}");
            assert_eq!(
                lc.eligibility, eligibility,
                "eligibility axis for {status:?}"
            );
        }
    }

    #[test]
    fn lifecycle_legacy_status_collapses_two_axes() {
        // Admin intent dominates.
        let disabled = WorkerLifecycle {
            admin: AdminIntent::Disabled,
            eligibility: EligibilityState::Healthy,
            bypass_cause: None,
        };
        assert_eq!(disabled.legacy_status(), WorkerStatus::Disabled);
        // New transient states map to their closest legacy equivalent.
        let bypassed = WorkerLifecycle {
            admin: AdminIntent::Active,
            eligibility: EligibilityState::TemporaryBypass,
            bypass_cause: Some(BypassFailureClass::Ssh),
        };
        assert_eq!(bypassed.legacy_status(), WorkerStatus::Unreachable);
        let canary = WorkerLifecycle {
            admin: AdminIntent::Active,
            eligibility: EligibilityState::RecoveredPendingCanary,
            bypass_cause: None,
        };
        // Canary-pending must collapse to Unreachable (NOT Degraded), so the
        // legacy scheduler keeps it out of normal builds (one-canary-first).
        assert_eq!(canary.legacy_status(), WorkerStatus::Unreachable);
        // Round-trip the unambiguous health states.
        for status in [
            WorkerStatus::Healthy,
            WorkerStatus::Degraded,
            WorkerStatus::Disabled,
        ] {
            assert_eq!(
                WorkerLifecycle::from_worker_status(status).legacy_status(),
                status
            );
        }
    }

    #[test]
    fn lifecycle_is_schedulable_matrix() {
        // Active + Healthy/Degraded => schedulable.
        for elig in [EligibilityState::Healthy, EligibilityState::Degraded] {
            let lc = WorkerLifecycle {
                admin: AdminIntent::Active,
                eligibility: elig,
                bypass_cause: None,
            };
            assert!(lc.is_schedulable(), "Active+{elig:?} must schedule");
        }
        // Active + non-eligible => not schedulable.
        for elig in [
            EligibilityState::Unreachable,
            EligibilityState::TemporaryBypass,
            EligibilityState::RecoveredPendingCanary,
        ] {
            let lc = WorkerLifecycle {
                admin: AdminIntent::Active,
                eligibility: elig,
                bypass_cause: None,
            };
            assert!(!lc.is_schedulable(), "Active+{elig:?} must NOT schedule");
        }
        // Any non-Active admin intent => never schedulable, even when Healthy.
        for admin in [
            AdminIntent::Draining,
            AdminIntent::Drained,
            AdminIntent::Disabled,
        ] {
            let lc = WorkerLifecycle {
                admin,
                eligibility: EligibilityState::Healthy,
                bypass_cause: None,
            };
            assert!(!lc.is_schedulable(), "{admin:?}+Healthy must NOT schedule");
        }
    }

    #[test]
    fn lifecycle_enter_bypass_quarantines_for_every_failure_class_without_touching_admin() {
        for &cause in ALL_FAILURE_CLASSES {
            let mut lc = WorkerLifecycle::new();
            let admin_before = lc.admin;
            lc.enter_bypass(cause);
            assert_eq!(lc.eligibility, EligibilityState::TemporaryBypass);
            assert_eq!(lc.bypass_cause, Some(cause), "cause recorded for {cause:?}");
            // The cardinal invariant: transient failure never mutates desired
            // inventory.
            assert_eq!(lc.admin, admin_before, "admin axis must be untouched");
            assert!(!lc.is_schedulable());
        }
    }

    #[test]
    fn lifecycle_legal_recovery_path_healthy_again() {
        let mut lc = WorkerLifecycle::new();
        lc.enter_bypass(BypassFailureClass::DiskInodePressure);
        lc.recover_to_canary().expect("probe success -> canary");
        assert_eq!(lc.eligibility, EligibilityState::RecoveredPendingCanary);
        assert_eq!(lc.bypass_cause, None, "cause cleared on recovery");
        assert!(lc.is_canary_pending());
        assert!(
            !lc.is_schedulable(),
            "canary-pending is not normal scheduling"
        );
        lc.promote_from_canary().expect("canary success -> healthy");
        assert_eq!(lc.eligibility, EligibilityState::Healthy);
        assert!(lc.is_schedulable());
    }

    #[test]
    fn lifecycle_canary_relapse_via_enter_bypass_is_legal() {
        let mut lc = WorkerLifecycle::new();
        lc.enter_bypass(BypassFailureClass::Ssh);
        lc.recover_to_canary().unwrap();
        // Canary build fails -> relapse back to bypass with the new cause.
        lc.enter_bypass(BypassFailureClass::PathSync);
        assert_eq!(lc.eligibility, EligibilityState::TemporaryBypass);
        assert_eq!(lc.bypass_cause, Some(BypassFailureClass::PathSync));
    }

    #[test]
    fn lifecycle_illegal_recover_to_canary_from_non_bypass() {
        for elig in [
            EligibilityState::Healthy,
            EligibilityState::Degraded,
            EligibilityState::Unreachable,
            EligibilityState::RecoveredPendingCanary,
        ] {
            let mut lc = WorkerLifecycle {
                admin: AdminIntent::Active,
                eligibility: elig,
                bypass_cause: None,
            };
            let err = lc
                .recover_to_canary()
                .expect_err("recover_to_canary must be illegal from non-bypass");
            assert_eq!(err.from, elig);
            assert_eq!(err.to, EligibilityState::RecoveredPendingCanary);
            // State unchanged on illegal transition.
            assert_eq!(lc.eligibility, elig);
        }
    }

    #[test]
    fn lifecycle_illegal_promote_from_non_canary() {
        for elig in [
            EligibilityState::Healthy,
            EligibilityState::Degraded,
            EligibilityState::Unreachable,
            EligibilityState::TemporaryBypass,
        ] {
            let mut lc = WorkerLifecycle {
                admin: AdminIntent::Active,
                eligibility: elig,
                bypass_cause: None,
            };
            let err = lc
                .promote_from_canary()
                .expect_err("promote must be illegal from non-canary");
            assert_eq!(err.from, elig);
            assert_eq!(lc.eligibility, elig, "state unchanged on illegal promote");
        }
    }

    #[test]
    fn lifecycle_observe_health_never_clears_quarantine() {
        let mut lc = WorkerLifecycle::new();
        lc.enter_bypass(BypassFailureClass::StaleTelemetry);
        // A "healthy" heartbeat must NOT auto-clear a failure-class bypass.
        assert!(!lc.observe_health(EligibilityState::Healthy));
        assert_eq!(lc.eligibility, EligibilityState::TemporaryBypass);
        assert_eq!(lc.bypass_cause, Some(BypassFailureClass::StaleTelemetry));
        // Same protection while awaiting canary.
        lc.recover_to_canary().unwrap();
        assert!(!lc.observe_health(EligibilityState::Healthy));
        assert_eq!(lc.eligibility, EligibilityState::RecoveredPendingCanary);
    }

    #[test]
    fn lifecycle_observe_health_moves_among_plain_states() {
        let mut lc = WorkerLifecycle::new();
        assert!(lc.observe_health(EligibilityState::Degraded));
        assert_eq!(lc.eligibility, EligibilityState::Degraded);
        assert!(lc.observe_health(EligibilityState::Unreachable));
        assert_eq!(lc.eligibility, EligibilityState::Unreachable);
        assert!(lc.observe_health(EligibilityState::Healthy));
        assert_eq!(lc.eligibility, EligibilityState::Healthy);
        // Passing a non-health state is rejected without mutation.
        assert!(!lc.observe_health(EligibilityState::TemporaryBypass));
        assert_eq!(lc.eligibility, EligibilityState::Healthy);
    }

    #[test]
    fn lifecycle_operator_disabled_worker_never_auto_rejoins() {
        // A worker the operator disabled must stay out of service even if it
        // walks the full recovery path on the eligibility axis.
        let mut lc = WorkerLifecycle::new();
        lc.set_admin(AdminIntent::Disabled);
        lc.enter_bypass(BypassFailureClass::CircuitBreaker);
        lc.recover_to_canary().unwrap();
        lc.promote_from_canary().unwrap();
        assert_eq!(lc.eligibility, EligibilityState::Healthy);
        // Admin intent is the gate: still disabled => never schedulable.
        assert_eq!(lc.admin, AdminIntent::Disabled);
        assert!(!lc.is_schedulable());
        assert!(!lc.is_canary_pending());
    }

    #[test]
    fn lifecycle_admin_axis_is_invariant_across_eligibility_transitions() {
        for admin in [
            AdminIntent::Active,
            AdminIntent::Draining,
            AdminIntent::Drained,
            AdminIntent::Disabled,
        ] {
            let mut lc = WorkerLifecycle {
                admin,
                eligibility: EligibilityState::Healthy,
                bypass_cause: None,
            };
            lc.enter_bypass(BypassFailureClass::OsArchMismatch);
            lc.recover_to_canary().unwrap();
            lc.promote_from_canary().unwrap();
            lc.observe_health(EligibilityState::Degraded);
            assert_eq!(
                lc.admin, admin,
                "eligibility transitions must not move admin"
            );
        }
    }

    #[test]
    fn lifecycle_serde_round_trips_full_state() {
        let lc = WorkerLifecycle {
            admin: AdminIntent::Draining,
            eligibility: EligibilityState::TemporaryBypass,
            bypass_cause: Some(BypassFailureClass::ArtifactRetrieval),
        };
        let json = serde_json::to_string(&lc).expect("serialize");
        assert!(json.contains("temporary_bypass"));
        assert!(json.contains("artifact_retrieval"));
        let back: WorkerLifecycle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, lc);
        // bypass_cause omitted when None.
        let healthy = WorkerLifecycle::new();
        let json = serde_json::to_string(&healthy).expect("serialize");
        assert!(!json.contains("bypass_cause"), "None cause must be omitted");
    }

    #[test]
    fn lifecycle_every_failure_class_serializes_to_distinct_snake_case_token() {
        let mut seen = std::collections::BTreeSet::new();
        for &cause in ALL_FAILURE_CLASSES {
            let token = serde_json::to_string(&cause).expect("serialize cause");
            assert!(seen.insert(token.clone()), "duplicate token {token}");
            // Round-trips.
            let back: BypassFailureClass = serde_json::from_str(&token).expect("deserialize cause");
            assert_eq!(back, cause);
        }
        assert_eq!(seen.len(), ALL_FAILURE_CLASSES.len());
    }

    #[test]
    fn test_duration_millis_i64_saturates() {
        assert_eq!(
            duration_millis_i64(Duration::from_millis(u64::MAX)),
            i64::MAX
        );
    }

    #[test]
    fn test_toolchain_preflight_freshness_saturates_extreme_ttl() {
        let status = ToolchainPreflightStatus {
            usable: true,
            reason: None,
            checked_at_unix_ms: 0,
        };

        assert!(status.is_fresh(Duration::from_millis(u64::MAX)));
    }

    /// Only a probe that ran and failed says the toolchain is broken; an
    /// unreachable or timed-out worker must not be excluded for the full TTL.
    #[test]
    fn test_toolchain_preflight_transport_failures_expire_quickly() {
        let long = Duration::from_secs(600);
        let short = Duration::from_secs(60);
        let two_minutes_ago = current_unix_ms() - 120_000;
        let verdict = |usable: bool, reason: Option<&str>| ToolchainPreflightStatus {
            usable,
            reason: reason.map(str::to_string),
            checked_at_unix_ms: two_minutes_ago,
        };

        let broken = verdict(
            false,
            Some("toolchain_preflight_command_failed:1:no such toolchain"),
        );
        assert!(broken.is_definitive());
        assert!(broken.is_reusable(long, short));

        let unreachable = verdict(false, Some("toolchain_preflight_connect_failed:timed out"));
        assert!(!unreachable.is_definitive());
        assert!(!unreachable.is_reusable(long, short));

        let healthy = verdict(true, None);
        assert!(healthy.is_definitive());
        assert!(healthy.is_reusable(long, short));
    }

    /// Helper to create a test worker config with given id.
    fn test_config(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_refresh_worker_capabilities_marks_live_probe() {
        let _guard = rch_common::test_guard!();
        struct MockOverrideGuard;
        impl Drop for MockOverrideGuard {
            fn drop(&mut self) {
                rch_common::mock::clear_mock_overrides();
            }
        }

        rch_common::mock::set_mock_enabled_override(Some(true));
        let _mock_guard = MockOverrideGuard;
        let state = std::sync::Arc::new(WorkerState::new(test_config("test-worker")));

        let refresh = refresh_worker_capabilities_for_worker(std::sync::Arc::clone(&state)).await;

        assert!(refresh.attempted);
        assert!(refresh.live);
        assert_eq!(refresh.source, "live_probe");
        assert!(state.has_rust().await);
    }

    // ============== WorkerState Tests ==============

    #[tokio::test]
    async fn test_worker_state_new_defaults() {
        let state = WorkerState::new(test_config("test-worker"));

        // Check default values
        assert_eq!(state.status().await, WorkerStatus::Healthy);
        assert_eq!(state.available_slots().await, 8);
        assert_eq!(state.used_slots(), 0);
        assert_eq!(state.get_speed_score(), 50.0);
        assert!(state.last_latency_ms().is_none());
        assert!(state.last_error().await.is_none());
        assert!(!state.is_disabled().await);
        assert!(!state.is_draining().await);
        assert!(state.disabled_reason().await.is_none());
        assert!(state.disabled_at().is_none());
    }

    // =========================================================================
    // WS3.4: Unit tests for atomic field accessors (bd-1gyl)
    //
    // Verify that AtomicU64/AtomicI64 accessors for speed_score,
    // last_latency_ms, and disabled_at correctly roundtrip values including
    // edge cases (NaN, infinity, zero sentinels).
    // =========================================================================

    // --- speed_score (AtomicU64 via f64::to_bits/from_bits) ---

    #[test]
    fn test_speed_score_roundtrip_normal_values() {
        let state = WorkerState::new(test_config("test"));

        // Default should be 50.0
        assert_eq!(state.get_speed_score(), 50.0);

        // Set and get various normal values
        state.set_speed_score(0.0);
        assert_eq!(state.get_speed_score(), 0.0);

        state.set_speed_score(1.0);
        assert_eq!(state.get_speed_score(), 1.0);

        state.set_speed_score(100.0);
        assert_eq!(state.get_speed_score(), 100.0);

        state.set_speed_score(99.5);
        assert_eq!(state.get_speed_score(), 99.5);

        // Negative score (shouldn't happen in practice, but verify roundtrip)
        state.set_speed_score(-1.0);
        assert_eq!(state.get_speed_score(), -1.0);
    }

    #[test]
    fn test_speed_score_roundtrip_extremes() {
        let state = WorkerState::new(test_config("test"));

        // f64::MAX
        state.set_speed_score(f64::MAX);
        assert_eq!(state.get_speed_score(), f64::MAX);

        // f64::MIN (most negative)
        state.set_speed_score(f64::MIN);
        assert_eq!(state.get_speed_score(), f64::MIN);

        // f64::MIN_POSITIVE (smallest positive)
        state.set_speed_score(f64::MIN_POSITIVE);
        assert_eq!(state.get_speed_score(), f64::MIN_POSITIVE);

        // f64::EPSILON
        state.set_speed_score(f64::EPSILON);
        assert_eq!(state.get_speed_score(), f64::EPSILON);
    }

    #[test]
    fn test_speed_score_roundtrip_special_float_values() {
        let state = WorkerState::new(test_config("test"));

        // Positive infinity
        state.set_speed_score(f64::INFINITY);
        assert_eq!(state.get_speed_score(), f64::INFINITY);

        // Negative infinity
        state.set_speed_score(f64::NEG_INFINITY);
        assert_eq!(state.get_speed_score(), f64::NEG_INFINITY);

        // NaN roundtrips via to_bits/from_bits (NaN != NaN, so check bits)
        state.set_speed_score(f64::NAN);
        let retrieved = state.get_speed_score();
        assert!(
            retrieved.is_nan(),
            "NaN should roundtrip via to_bits/from_bits"
        );
        assert_eq!(
            f64::NAN.to_bits(),
            retrieved.to_bits(),
            "NaN bit pattern should be preserved"
        );

        // Negative zero
        state.set_speed_score(-0.0_f64);
        let retrieved = state.get_speed_score();
        assert_eq!(retrieved, 0.0); // -0.0 == 0.0 in f64
        // But bit pattern differs from +0.0
        assert_eq!((-0.0_f64).to_bits(), retrieved.to_bits());
    }

    // --- last_latency_ms (AtomicU64 with 0 as None sentinel) ---

    #[test]
    fn test_last_latency_ms_none_default() {
        let state = WorkerState::new(test_config("test"));
        assert_eq!(state.last_latency_ms(), None);
    }

    #[test]
    fn test_last_latency_ms_roundtrip() {
        let state = WorkerState::new(test_config("test"));

        // Set Some value
        state.set_last_latency_ms(Some(100));
        assert_eq!(state.last_latency_ms(), Some(100));

        // Update to different value
        state.set_last_latency_ms(Some(250));
        assert_eq!(state.last_latency_ms(), Some(250));

        // Large value
        state.set_last_latency_ms(Some(u64::MAX));
        assert_eq!(state.last_latency_ms(), Some(u64::MAX));

        // Set back to None
        state.set_last_latency_ms(None);
        assert_eq!(state.last_latency_ms(), None);
    }

    #[test]
    fn test_last_latency_ms_zero_sentinel_behavior() {
        let state = WorkerState::new(test_config("test"));

        // Some(0) maps to None because 0 is the sentinel value.
        // This is documented behavior: 0ms latency is not meaningful.
        state.set_last_latency_ms(Some(0));
        assert_eq!(
            state.last_latency_ms(),
            None,
            "Some(0) should map to None (0 is sentinel for None)"
        );

        // Some(1) should work fine
        state.set_last_latency_ms(Some(1));
        assert_eq!(state.last_latency_ms(), Some(1));
    }

    // --- disabled_at (AtomicI64 with 0 as None sentinel) ---

    #[test]
    fn test_disabled_at_none_default() {
        let state = WorkerState::new(test_config("test"));
        assert_eq!(state.disabled_at(), None);
    }

    #[tokio::test]
    async fn test_disabled_at_set_on_disable() {
        let state = WorkerState::new(test_config("test"));

        // Initially None
        assert!(state.disabled_at().is_none());

        // Disabling the worker should set disabled_at
        state.disable(Some("test reason".to_string())).await;
        let ts = state.disabled_at();
        assert!(ts.is_some(), "disabled_at should be set after disable()");
        assert!(ts.unwrap() > 0, "timestamp should be positive");
    }

    #[tokio::test]
    async fn test_disabled_at_cleared_on_enable() {
        let state = WorkerState::new(test_config("test"));

        // Disable then enable
        state.disable(Some("test".to_string())).await;
        assert!(state.disabled_at().is_some());

        state.enable().await;
        assert_eq!(
            state.disabled_at(),
            None,
            "disabled_at should be None after enable()"
        );
    }

    #[tokio::test]
    async fn test_record_health_check_drives_authoritative_circuit() {
        // The health monitor's ONLY circuit write path is record_health_check;
        // this is the circuit the scheduler reads via circuit_state(). Failures
        // must open it, and a healthy streak must recover it — all through the
        // shared apply_health_outcome engine.
        let state = WorkerState::new(test_config("test"));
        let cfg = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            open_cooldown_secs: 0,
            ..Default::default()
        };

        // Starts Closed.
        assert_eq!(state.circuit_state().await, Some(CircuitState::Closed));

        // Three failures open the authoritative circuit.
        for _ in 0..3 {
            state.record_health_check(false, false, &cfg).await;
        }
        // With a 0s cooldown the engine immediately re-arms half-open after
        // opening; the point is the circuit is no longer Closed, so selection
        // sees it as non-healthy.
        assert_ne!(state.circuit_state().await, Some(CircuitState::Closed));

        // Two clean probes recover it to Closed.
        state.record_health_check(true, false, &cfg).await;
        let (_, new) = state.record_health_check(true, false, &cfg).await;
        assert_eq!(new, CircuitState::Closed);
        assert_eq!(state.circuit_state().await, Some(CircuitState::Closed));
    }

    #[tokio::test]
    async fn test_enable_resets_authoritative_circuit() {
        // enable() must REALLY reset the circuit the scheduler reads, not just
        // flip lifecycle status — otherwise a re-enabled worker stays
        // short-circuited out of selection.
        let state = WorkerState::new(test_config("test"));

        // Force the circuit Open, then record an error message.
        state.open_circuit().await;
        state.set_error("boom".to_string()).await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::Open));

        // Operator re-enable must close the circuit and clear the error.
        state.enable().await;
        assert_eq!(
            state.circuit_state().await,
            Some(CircuitState::Closed),
            "enable() must reset the authoritative circuit to Closed"
        );
        assert_eq!(state.last_error().await, None);
    }

    // --- Concurrent access tests ---

    #[tokio::test]
    async fn test_speed_score_concurrent_updates() {
        let state = Arc::new(WorkerState::new(test_config("test")));
        let mut handles = vec![];

        // Spawn 10 tasks that each set a different speed score
        for i in 0..10u64 {
            let s = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                s.set_speed_score(i as f64 * 10.0);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // The final value should be one of the set values (last-write-wins)
        let score = state.get_speed_score();
        assert!(
            (0.0..=90.0).contains(&score) && score % 10.0 == 0.0,
            "Final speed score {} should be one of the written values",
            score
        );
    }

    #[tokio::test]
    async fn test_latency_concurrent_updates() {
        let state = Arc::new(WorkerState::new(test_config("test")));
        let mut handles = vec![];

        // Spawn tasks that set latency and None concurrently
        for i in 0..10u64 {
            let s = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    s.set_last_latency_ms(Some(i * 100 + 1)); // Avoid 0
                } else {
                    s.set_last_latency_ms(None);
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Result should be valid (either None or a reasonable value)
        let latency = state.last_latency_ms();
        match latency {
            None => {} // Valid
            Some(v) => assert!(v <= 901, "Latency {} out of expected range", v),
        }
    }

    #[tokio::test]
    async fn test_disabled_at_concurrent_disable_enable() {
        let state = Arc::new(WorkerState::new(test_config("test")));
        let mut handles = vec![];

        for i in 0..10u32 {
            let s = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    s.disable(Some(format!("reason {i}"))).await;
                } else {
                    s.enable().await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // State should be consistent: if disabled, disabled_at is Some; if not, None
        let is_disabled = state.is_disabled().await;
        let disabled_at = state.disabled_at();
        if is_disabled {
            assert!(
                disabled_at.is_some(),
                "disabled worker should have disabled_at set"
            );
        }
        // Note: disabled_at might not be None when !is_disabled due to race
        // between status and atomic checks, which is acceptable for diagnostic data
    }

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
            tools: Vec::new(),
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

    #[tokio::test]
    async fn test_disk_slots_derate_at_floor_and_recover() {
        let state = WorkerState::new(test_config("disk-slots"));
        assert_eq!(state.effective_total_slots().await, 8);
        for (free_gb, expected) in [
            (100.0, 8),
            (80.0, 7),
            (40.0, 3),
            (20.0, 1),
            (19.9, 0),
            (10.0, 0),
            (0.0, 0),
            (-1.0, 0),
            (f64::MAX, 8),
        ] {
            state
                .set_pressure_assessment(PressureAssessment {
                    disk_free_gb: Some(free_gb),
                    ..Default::default()
                })
                .await;
            assert_eq!(
                state.effective_total_slots().await,
                expected,
                "free GiB={free_gb}"
            );
            assert_eq!(state.available_slots().await, expected);
            assert_eq!(state.config.read().await.total_slots, 8);
        }
        for unknown in [None, Some(f64::NAN), Some(f64::INFINITY)] {
            state
                .set_pressure_assessment(PressureAssessment {
                    disk_free_gb: unknown,
                    ..Default::default()
                })
                .await;
            assert_eq!(state.effective_total_slots().await, 8);
        }
    }

    #[tokio::test]
    async fn test_disk_slots_keep_active_reservations_when_capacity_shrinks() {
        let state = WorkerState::new(test_config("disk-shrink"));
        assert!(state.reserve_slots(6).await);
        state
            .set_pressure_assessment(PressureAssessment {
                disk_free_gb: Some(20.0),
                ..Default::default()
            })
            .await;
        assert_eq!(state.effective_total_slots().await, 1);
        assert_eq!(state.used_slots(), 6);
        assert_eq!(state.available_slots().await, 0);
        assert!(!state.reserve_slots(1).await);
        state.release_slots(2).await;
        assert_eq!(state.used_slots(), 4);
        assert_eq!(state.available_slots().await, 0);
        state
            .set_pressure_assessment(PressureAssessment {
                disk_free_gb: Some(70.0),
                ..Default::default()
            })
            .await;
        assert_eq!(state.available_slots().await, 2);
        state.release_slots(4).await;
        assert_eq!(state.available_slots().await, 6);
    }

    #[tokio::test]
    async fn test_disk_slots_budget_survives_worker_reload_and_addition() {
        let config = rch_common::SelectionConfig {
            min_free_gb: Some(5.0),
            disk_gb_per_slot: 2.5,
            ..Default::default()
        };
        let pool = WorkerPool::with_selection_config(&config);
        pool.add_worker(test_config("first")).await;
        let first = pool.get(&WorkerId::new("first")).await.unwrap();
        first
            .set_pressure_assessment(PressureAssessment {
                disk_free_gb: Some(12.5),
                ..Default::default()
            })
            .await;
        assert_eq!(first.effective_total_slots().await, 3);
        let mut reloaded = test_config("first");
        reloaded.total_slots = 2;
        pool.add_worker(reloaded).await;
        assert_eq!(first.effective_total_slots().await, 2);
        pool.add_worker(test_config("later")).await;
        let later = pool.get(&WorkerId::new("later")).await.unwrap();
        later
            .set_pressure_assessment(first.pressure_assessment().await)
            .await;
        assert_eq!(later.effective_total_slots().await, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_disk_slots_concurrent_reservations_respect_capacity() {
        let state = Arc::new(WorkerState::new(test_config("disk-race")));
        state
            .set_pressure_assessment(PressureAssessment {
                disk_free_gb: Some(40.0),
                ..Default::default()
            })
            .await;
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let worker = state.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                worker.reserve_slots(1).await
            }));
        }
        let mut reserved = 0;
        for task in tasks {
            reserved += u32::from(task.await.unwrap());
        }
        assert_eq!(reserved, 3);
        assert_eq!(state.used_slots(), 3);
        assert_eq!(state.available_slots().await, 0);
        state.release_slots(reserved).await;
        assert_eq!(state.available_slots().await, 3);
    }

    #[tokio::test]
    async fn test_slot_reservation_rejects_integer_overflow() {
        let mut config = test_config("slot-overflow");
        config.total_slots = u32::MAX;
        let state = WorkerState::new(config);
        assert!(state.reserve_slots(u32::MAX).await);
        assert!(!state.reserve_slots(1).await);
        assert_eq!(state.used_slots(), u32::MAX);
    }

    #[tokio::test]
    async fn test_zero_slot_reservation_is_rejected() {
        let state = WorkerState::new(test_config("test"));

        assert!(!state.reserve_slots(0).await);
        assert_eq!(state.used_slots(), 0);
        assert_eq!(state.available_slots().await, 8);
    }

    #[tokio::test]
    async fn test_slot_reservation_exact_boundary() {
        let state = WorkerState::new(test_config("test"));

        // Reserve exactly all slots
        assert!(state.reserve_slots(8).await);
        assert_eq!(state.available_slots().await, 0);
        assert_eq!(state.used_slots(), 8);

        // Trying to reserve even 0 more fails when full
        assert!(!state.reserve_slots(1).await);

        // Release all
        state.release_slots(8).await;
        assert_eq!(state.available_slots().await, 8);
    }

    #[tokio::test]
    async fn test_release_slots_more_than_used() {
        let state = WorkerState::new(test_config("test"));

        // Reserve 2 slots
        assert!(state.reserve_slots(2).await);
        assert_eq!(state.used_slots(), 2);

        // Release more than reserved - should saturate to 0
        state.release_slots(10).await;
        assert_eq!(state.used_slots(), 0);
        assert_eq!(state.available_slots().await, 8);
    }

    #[tokio::test]
    async fn test_status_transitions() {
        let state = WorkerState::new(test_config("test"));

        assert_eq!(state.status().await, WorkerStatus::Healthy);

        state.set_status(WorkerStatus::Degraded).await;
        assert_eq!(state.status().await, WorkerStatus::Degraded);

        state.set_status(WorkerStatus::Unreachable).await;
        assert_eq!(state.status().await, WorkerStatus::Unreachable);

        state.set_status(WorkerStatus::Healthy).await;
        assert_eq!(state.status().await, WorkerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_reserve_slots_refuses_draining_worker() {
        // Regression: the selector's `healthy_workers()` filter runs *before*
        // `reserve_slots`, so an operator invoking `drain()` between the two
        // must still prevent the reservation. Previously reserve_slots only
        // compared used + count against total_slots and silently accepted on
        // drained workers — a build could land on a worker we had just asked
        // to stop accepting work, breaking the drain contract.
        let state = WorkerState::new(test_config("drain-race"));
        assert!(state.reserve_slots(1).await, "fresh worker should accept");
        state.release_slots(1).await;

        state.drain().await;
        assert!(
            !state.reserve_slots(1).await,
            "draining worker must refuse new reservations"
        );
        assert_eq!(state.used_slots(), 0);

        state.check_drain_complete().await;
        assert_eq!(state.status().await, WorkerStatus::Drained);
        assert!(
            !state.reserve_slots(1).await,
            "drained worker must refuse new reservations"
        );

        state.disable(Some("maintenance".to_string())).await;
        assert!(
            !state.reserve_slots(1).await,
            "disabled worker must refuse new reservations"
        );
    }

    #[tokio::test]
    async fn test_apply_health_status_updates_non_administrative_states() {
        let state = WorkerState::new(test_config("test"));

        assert_eq!(
            state.apply_health_status(WorkerStatus::Degraded).await,
            WorkerStatus::Degraded
        );
        assert_eq!(state.status().await, WorkerStatus::Degraded);

        assert_eq!(
            state.apply_health_status(WorkerStatus::Unreachable).await,
            WorkerStatus::Unreachable
        );
        assert_eq!(state.status().await, WorkerStatus::Unreachable);

        assert_eq!(
            state.apply_health_status(WorkerStatus::Healthy).await,
            WorkerStatus::Healthy
        );
        assert_eq!(state.status().await, WorkerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_apply_health_status_preserves_administrative_states() {
        let state = WorkerState::new(test_config("test"));

        assert!(state.reserve_slots(1).await);
        state.drain().await;
        assert_eq!(
            state.apply_health_status(WorkerStatus::Healthy).await,
            WorkerStatus::Draining
        );
        assert_eq!(state.status().await, WorkerStatus::Draining);

        state.release_slots(1).await;
        assert_eq!(state.status().await, WorkerStatus::Drained);
        assert_eq!(
            state.apply_health_status(WorkerStatus::Healthy).await,
            WorkerStatus::Drained
        );
        assert_eq!(state.status().await, WorkerStatus::Drained);

        state.disable(Some("maintenance".to_string())).await;
        assert_eq!(
            state.apply_health_status(WorkerStatus::Healthy).await,
            WorkerStatus::Disabled
        );
        assert_eq!(state.status().await, WorkerStatus::Disabled);
    }

    #[tokio::test]
    async fn test_enter_bypass_excludes_from_scheduling() {
        // A worker quarantined into TemporaryBypass must look `Unreachable` to
        // every legacy consumer, report not-schedulable, and refuse new slot
        // reservations — all derived from the single lifecycle source of truth.
        let state = WorkerState::new(test_config("bypassed"));
        assert!(state.reserve_slots(1).await);
        state.release_slots(1).await;

        state.enter_bypass(BypassFailureClass::Ssh).await;

        assert_eq!(state.eligibility().await, EligibilityState::TemporaryBypass);
        assert_eq!(state.status().await, WorkerStatus::Unreachable);
        assert!(!state.lifecycle().await.is_schedulable());
        assert_eq!(
            state.lifecycle().await.bypass_cause,
            Some(BypassFailureClass::Ssh)
        );
        assert!(
            !state.reserve_slots(1).await,
            "a bypassed worker must refuse new reservations"
        );
    }

    #[tokio::test]
    async fn test_health_probe_never_clears_bypass() {
        // The cardinal safety invariant: lucky health observations routed
        // through the health monitor must NOT auto-rejoin a bypassed worker.
        // Only the recovery probe/canary loop may clear a quarantine.
        let state = WorkerState::new(test_config("flapper"));
        state
            .enter_bypass(BypassFailureClass::DiskInodePressure)
            .await;

        for _ in 0..5 {
            let effective = state.apply_health_status(WorkerStatus::Healthy).await;
            assert_eq!(effective, WorkerStatus::Unreachable);
            assert_eq!(state.eligibility().await, EligibilityState::TemporaryBypass);
        }
    }

    #[tokio::test]
    async fn test_recover_to_canary_then_promote() {
        // The full recovery path: bypass -> canary-pending -> healthy. The
        // canary-pending worker is still excluded from *normal* scheduling
        // (status reads Unreachable, reservations refused) while
        // is_canary_pending gates the single allowed canary build.
        let state = WorkerState::new(test_config("recoverer"));
        state.enter_bypass(BypassFailureClass::CircuitBreaker).await;

        state
            .recover_to_canary()
            .await
            .expect("bypass -> canary is legal");
        assert!(state.is_canary_pending().await);
        assert_eq!(
            state.eligibility().await,
            EligibilityState::RecoveredPendingCanary
        );
        assert_eq!(state.status().await, WorkerStatus::Unreachable);
        assert!(
            !state.reserve_slots(1).await,
            "canary-pending worker must not take normal builds"
        );

        state
            .promote_from_canary()
            .await
            .expect("canary-pending -> healthy is legal");
        assert_eq!(state.status().await, WorkerStatus::Healthy);
        assert!(state.lifecycle().await.is_schedulable());
        assert!(!state.is_canary_pending().await);
        assert!(state.reserve_slots(1).await, "rejoined worker accepts work");
    }

    #[tokio::test]
    async fn test_recover_to_canary_illegal_from_healthy() {
        // recover_to_canary is only legal from TemporaryBypass; a healthy worker
        // can never shortcut into the canary gate.
        let state = WorkerState::new(test_config("healthy"));
        let err = state.recover_to_canary().await.unwrap_err();
        assert_eq!(err.from, EligibilityState::Healthy);
        assert_eq!(err.to, EligibilityState::RecoveredPendingCanary);
    }

    #[tokio::test]
    async fn test_enable_clears_bypass() {
        // Operator re-enable is an authoritative override that clears a
        // quarantine (both axes back to Active + Healthy).
        let state = WorkerState::new(test_config("reenabled"));
        state
            .enter_bypass(BypassFailureClass::RuntimeToolchain)
            .await;
        assert_eq!(state.status().await, WorkerStatus::Unreachable);

        state.enable().await;
        assert_eq!(state.status().await, WorkerStatus::Healthy);
        assert!(state.lifecycle().await.is_schedulable());
        assert_eq!(state.lifecycle().await.bypass_cause, None);
    }

    #[tokio::test]
    async fn test_pool_healthy_workers_excludes_bypassed() {
        // The pool's healthy_workers() filter (the selector's candidate source)
        // must drop TemporaryBypass and RecoveredPendingCanary workers just like
        // an Unreachable one.
        let pool = WorkerPool::new();
        pool.add_worker(test_config("healthy")).await;
        pool.add_worker(test_config("bypassed")).await;
        pool.add_worker(test_config("canary")).await;

        pool.get(&WorkerId::new("bypassed"))
            .await
            .unwrap()
            .enter_bypass(BypassFailureClass::Ssh)
            .await;
        let canary = pool.get(&WorkerId::new("canary")).await.unwrap();
        canary.enter_bypass(BypassFailureClass::Ssh).await;
        canary.recover_to_canary().await.unwrap();

        let healthy = pool.healthy_workers().await;
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].config.read().await.id, WorkerId::new("healthy"));
    }

    #[tokio::test]
    async fn test_disable_enable_cycle() {
        let state = WorkerState::new(test_config("test"));

        // Disable with reason
        state.disable(Some("Maintenance".to_string())).await;
        assert!(state.is_disabled().await);
        assert_eq!(state.status().await, WorkerStatus::Disabled);
        assert_eq!(
            state.disabled_reason().await,
            Some("Maintenance".to_string())
        );
        assert!(state.disabled_at().is_some());

        // Enable again
        state.enable().await;
        assert!(!state.is_disabled().await);
        assert_eq!(state.status().await, WorkerStatus::Healthy);
        assert!(state.disabled_reason().await.is_none());
        assert!(state.disabled_at().is_none());
    }

    #[tokio::test]
    async fn test_disable_without_reason() {
        let state = WorkerState::new(test_config("test"));

        state.disable(None).await;
        assert!(state.is_disabled().await);
        assert!(state.disabled_reason().await.is_none());
        assert!(state.disabled_at().is_some());
    }

    #[tokio::test]
    async fn test_drain_state() {
        let state = WorkerState::new(test_config("test"));

        assert!(state.reserve_slots(1).await);
        state.drain().await;
        assert!(state.is_draining().await);
        assert_eq!(state.status().await, WorkerStatus::Draining);
        assert!(!state.is_disabled().await);

        // Enable clears draining
        state.enable().await;
        assert!(!state.is_draining().await);
        assert_eq!(state.status().await, WorkerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_drained_state() {
        let state = WorkerState::new(test_config("test"));

        // No slots are in use, so drain completes immediately.
        state.drain().await;
        assert!(!state.is_draining().await);
        assert!(state.is_drained().await);
        assert_eq!(state.status().await, WorkerStatus::Drained);

        // Enable clears drained
        state.enable().await;
        assert!(!state.is_drained().await);
        assert_eq!(state.status().await, WorkerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_drain_complete_with_active_jobs() {
        let state = WorkerState::new(test_config("test"));

        // Reserve a slot to simulate an active job
        assert!(state.reserve_slots(1).await);
        assert_eq!(state.used_slots(), 1);

        state.drain().await;
        assert!(state.is_draining().await);

        // With active jobs, calling check_drain_complete() should NOT transition to Drained
        state.check_drain_complete().await;
        assert!(state.is_draining().await);
        assert!(!state.is_drained().await);

        // Release the slot (job completes) - this automatically calls check_drain_complete()
        state.release_slots(1).await;
        assert_eq!(state.used_slots(), 0);

        // Worker should now be Drained (automatic transition via release_slots)
        assert!(!state.is_draining().await);
        assert!(state.is_drained().await);
        assert_eq!(state.status().await, WorkerStatus::Drained);
    }

    #[tokio::test]
    async fn test_drain_then_disable_disables_after_active_jobs_finish() {
        let state = WorkerState::new(test_config("test"));

        assert!(state.reserve_slots(1).await);
        state
            .drain_then_disable(Some("maintenance".to_string()))
            .await;
        assert_eq!(state.status().await, WorkerStatus::Draining);
        assert!(state.disabled_reason().await.is_none());
        assert!(state.disabled_at().is_none());

        state.release_slots(1).await;

        assert_eq!(state.status().await, WorkerStatus::Disabled);
        assert_eq!(
            state.disabled_reason().await,
            Some("maintenance".to_string())
        );
        assert!(state.disabled_at().is_some());
        assert!(!state.remove_after_drain_pending().await);
    }

    #[tokio::test]
    async fn operator_disable_dominates_subsequent_drain_requests() {
        for drain_first in [false, true] {
            for removal in [false, true] {
                let state = WorkerState::new(test_config("disabled"));
                assert!(state.reserve_slots(3).await);
                if drain_first {
                    state.drain_then_disable(Some("maintenance".into())).await;
                } else {
                    state.disable(Some("maintenance".into())).await;
                }
                let status = state.status().await;
                if removal {
                    state.drain_for_removal().await;
                }
                state.drain().await;
                assert_eq!(state.status().await, status);
                assert!(state.background_probe().await.is_none());
                assert!(state.next_health_probe_in().await.is_none());
                assert!(
                    state
                        .health_probe_permit(
                            Duration::from_secs(30),
                            &CircuitBreakerConfig::default()
                        )
                        .await
                        .is_none(),
                    "drain_first={drain_first}, removal={removal}: disable must still forbid SSH"
                );
                assert!(!state.reserve_slots(1).await);
                assert_eq!(state.used_slots(), 3);
                assert_eq!(state.remove_after_drain_pending().await, removal);
                state.release_slots(3).await;
                assert!(state.is_disabled().await);
                assert_eq!(
                    state.disabled_reason().await.as_deref(),
                    Some("maintenance")
                );
                assert_eq!(state.remove_after_drain_pending().await, removal);
            }
        }
    }

    #[tokio::test]
    async fn removal_reintroduction_preserves_later_operator_intent() {
        for intent in ["drain", "disable", "disable-after-drain"] {
            let config = test_config("operator");
            let state = WorkerState::new(config.clone());
            assert!(state.reserve_slots(1).await);
            state.drain_for_removal().await;
            match intent {
                "disable" => state.disable(Some("maintenance".into())).await,
                "disable-after-drain" => {
                    state.drain_then_disable(Some("maintenance".into())).await;
                }
                _ => state.drain().await,
            }
            assert!(state.remove_after_drain_pending().await, "{intent}");
            let status = state.status().await;
            state.update_config(config).await;
            assert_eq!(state.status().await, status, "{intent}");
            assert!(!state.remove_after_drain_pending().await);
            assert_eq!(state.used_slots(), 1);
            state.release_slots(1).await;
            if intent == "drain" {
                assert!(state.is_drained().await);
            } else {
                assert!(state.is_disabled().await);
                assert_eq!(
                    state.disabled_reason().await.as_deref(),
                    Some("maintenance")
                );
            }
        }
    }

    #[tokio::test]
    async fn inventory_drain_keeps_owned_monitoring_and_restores_pools_on_return() {
        for enable_while_absent in [false, true] {
            let config = test_config("returning");
            let state = WorkerState::new(config.clone());
            let mut pools = Vec::new();
            for _ in 0..2 {
                let pool = Arc::new(rch_common::SshPool::new(rch_common::SshOptions {
                    connect_timeout: Duration::ZERO,
                    ..Default::default()
                }));
                state.attach_ssh_pool(pool.clone()).await;
                pools.push(pool);
            }
            assert!(state.reserve_slots(1).await);
            state.drain_for_removal().await;
            if enable_while_absent {
                state.enable().await;
            }
            assert!(state.is_draining().await);
            assert!(state.remove_after_drain_pending().await);
            assert_eq!(state.used_slots(), 1);
            assert!(!state.reserve_slots(1).await);
            assert!(state.background_probe().await.is_some());
            assert!(
                state
                    .health_probe_permit(Duration::from_secs(30), &CircuitBreakerConfig::default())
                    .await
                    .is_some(),
                "reachable draining builds still require normal monitoring"
            );
            state.release_slots(1).await;
            assert!(state.is_drained().await);
            for pool in &pools {
                let error = pool.get_or_connect(&config).await.err().unwrap();
                assert!(
                    format!("{error:#}").contains("disabled or its pool admission was revoked")
                );
            }

            // Config reappears after the last owner finishes but before prune.
            // The endpoint remains verified; both pools must match its resumed
            // admission instead of causing a false transport failure at health.
            state.update_config(config.clone()).await;
            assert!(!state.remove_after_drain_pending().await);
            assert!(state.lifecycle().await.is_schedulable());
            assert!(state.background_probe().await.is_some());
            for pool in pools {
                let error = pool.get_or_connect(&config).await.err().unwrap();
                assert!(
                    format!("{error:#}").contains("SSH connection timed out before spawn"),
                    "verified inventory return must restore pool admission without dialing: {error:#}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_cached_projects() {
        let state = WorkerState::new(test_config("test"));

        assert!(!state.has_cached_project("project-a").await);

        state.add_cached_project("project-a".to_string()).await;
        assert!(state.has_cached_project("project-a").await);
        assert!(!state.has_cached_project("project-b").await);

        // Adding same project again should not duplicate
        state.add_cached_project("project-a".to_string()).await;
        let projects = state.cached_projects.read().await;
        assert_eq!(projects.len(), 1);
        drop(projects);

        state.add_cached_project("project-b".to_string()).await;
        assert!(state.has_cached_project("project-b").await);
        let projects = state.cached_projects.read().await;
        assert_eq!(projects.len(), 2);
    }

    #[tokio::test]
    async fn test_speed_score() {
        let state = WorkerState::new(test_config("test"));

        // Default is 50.0
        assert_eq!(state.get_speed_score(), 50.0);

        state.set_speed_score(85.5);
        assert_eq!(state.get_speed_score(), 85.5);

        state.set_speed_score(0.0);
        assert_eq!(state.get_speed_score(), 0.0);

        state.set_speed_score(100.0);
        assert_eq!(state.get_speed_score(), 100.0);
    }

    #[tokio::test]
    async fn test_latency_tracking() {
        let state = WorkerState::new(test_config("test"));

        assert!(state.last_latency_ms().is_none());

        state.set_last_latency_ms(Some(42));
        assert_eq!(state.last_latency_ms(), Some(42));

        state.set_last_latency_ms(Some(100));
        assert_eq!(state.last_latency_ms(), Some(100));

        state.set_last_latency_ms(None);
        assert!(state.last_latency_ms().is_none());
    }

    #[tokio::test]
    async fn test_error_tracking() {
        let state = WorkerState::new(test_config("test"));

        assert!(state.last_error().await.is_none());

        state.set_error("Connection refused".to_string()).await;
        assert_eq!(
            state.last_error().await,
            Some("Connection refused".to_string())
        );

        // Recording failure with error message updates last_error
        state.record_failure(Some("Timeout".to_string())).await;
        assert_eq!(state.last_error().await, Some("Timeout".to_string()));

        // Recording failure without message keeps previous error
        state.record_failure(None).await;
        assert_eq!(state.last_error().await, Some("Timeout".to_string()));
    }

    #[tokio::test]
    async fn test_circuit_breaker_basic() {
        let state = WorkerState::new(test_config("test"));

        // Initial state is Closed
        assert_eq!(state.circuit_state().await, Some(CircuitState::Closed));

        // Record success
        state.record_success().await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::Closed));

        // Open circuit
        state.open_circuit().await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::Open));

        // Half-open
        state.half_open_circuit().await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::HalfOpen));

        // Close circuit clears error
        state.set_error("Test error".to_string()).await;
        state.close_circuit().await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::Closed));
        assert!(state.last_error().await.is_none());
    }

    #[tokio::test]
    async fn test_capabilities() {
        let state = WorkerState::new(test_config("test"));

        // Default capabilities: nothing installed
        assert!(!state.has_bun().await);
        assert!(!state.has_node().await);
        assert!(!state.has_rust().await);
        assert!(!state.has_nix().await);

        // Set capabilities with Rust
        let mut caps = WorkerCapabilities::new();
        caps.rustc_version = Some("1.87.0-nightly".to_string());
        caps.disk_free_gb = Some(4.0);
        caps.disk_total_gb = Some(120.0);
        state.set_capabilities(caps).await;

        assert!(state.has_rust().await);
        assert!(!state.has_bun().await);
        assert!(!state.has_node().await);
        let pressure = state.pressure_assessment().await;
        assert_eq!(
            pressure.state,
            crate::disk_pressure::PressureState::Critical
        );
        assert_eq!(
            pressure.reason_code,
            "disk_critical_without_fresh_telemetry"
        );

        // Set capabilities with all runtimes
        let mut caps = WorkerCapabilities::new();
        caps.rustc_version = Some("1.87.0".to_string());
        caps.bun_version = Some("1.2.0".to_string());
        caps.node_version = Some("22.0.0".to_string());
        state.set_capabilities(caps.clone()).await;

        assert!(state.has_rust().await);
        assert!(state.has_bun().await);
        assert!(state.has_node().await);

        // Verify capabilities retrieval
        let retrieved = state.capabilities().await;
        assert_eq!(retrieved.rustc_version, Some("1.87.0".to_string()));
        assert_eq!(retrieved.bun_version, Some("1.2.0".to_string()));
    }

    #[tokio::test]
    async fn test_capability_refresh_preserves_fresh_pressure_telemetry() {
        let state = WorkerState::new(test_config("test"));
        state
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                state: crate::disk_pressure::PressureState::Healthy,
                confidence: crate::disk_pressure::PressureConfidence::High,
                reason_code: "all_pressure_rules_within_threshold".to_string(),
                policy_rule: "fresh_telemetry".to_string(),
                disk_free_gb: Some(50.0),
                disk_total_gb: Some(100.0),
                disk_free_ratio: Some(0.5),
                build_disk_free_gb: None,
                build_disk_total_gb: None,
                disk_io_util_pct: Some(0.0),
                memory_pressure: Some(10.0),
                telemetry_age_secs: Some(10),
                telemetry_fresh: true,
                evaluated_at_unix_ms: current_unix_ms(),
            })
            .await;

        let mut caps = WorkerCapabilities::new();
        caps.rustc_version = Some("1.87.0-nightly".to_string());
        caps.disk_free_gb = Some(90.0);
        caps.disk_total_gb = Some(120.0);
        state.set_capabilities(caps).await;

        let pressure = state.pressure_assessment().await;
        assert_eq!(pressure.state, crate::disk_pressure::PressureState::Healthy);
        assert_eq!(pressure.reason_code, "all_pressure_rules_within_threshold");
        assert_eq!(pressure.disk_free_gb, Some(90.0));
        assert_eq!(pressure.disk_total_gb, Some(120.0));
        assert_eq!(pressure.disk_free_ratio, Some(0.75));
        assert_eq!(pressure.disk_io_util_pct, Some(0.0));
        assert_eq!(pressure.memory_pressure, Some(10.0));
        assert!(pressure.telemetry_fresh);
        assert!(pressure.telemetry_age_secs.unwrap_or(u64::MAX) <= 11);
    }

    #[tokio::test]
    async fn test_capability_refresh_critical_disk_overrides_fresh_pressure() {
        let state = WorkerState::new(test_config("test"));
        state
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                state: crate::disk_pressure::PressureState::Healthy,
                confidence: crate::disk_pressure::PressureConfidence::High,
                reason_code: "all_pressure_rules_within_threshold".to_string(),
                policy_rule: "fresh_telemetry".to_string(),
                disk_free_gb: Some(50.0),
                disk_total_gb: Some(100.0),
                disk_free_ratio: Some(0.5),
                build_disk_free_gb: None,
                build_disk_total_gb: None,
                disk_io_util_pct: Some(0.0),
                memory_pressure: Some(10.0),
                telemetry_age_secs: Some(10),
                telemetry_fresh: true,
                evaluated_at_unix_ms: current_unix_ms(),
            })
            .await;

        let mut caps = WorkerCapabilities::new();
        caps.rustc_version = Some("1.87.0-nightly".to_string());
        caps.disk_free_gb = Some(2.0);
        caps.disk_total_gb = Some(120.0);
        state.set_capabilities(caps).await;

        let pressure = state.pressure_assessment().await;
        assert_eq!(
            pressure.state,
            crate::disk_pressure::PressureState::Critical
        );
        assert_eq!(
            pressure.reason_code,
            "disk_critical_without_fresh_telemetry"
        );
        assert_eq!(pressure.disk_free_gb, Some(2.0));
        assert!(!pressure.telemetry_fresh);
    }

    #[tokio::test]
    async fn test_toolchain_preflight_cache_records_fail_closed_reason() {
        let state = WorkerState::new(test_config("test"));

        state
            .record_toolchain_preflight(
                "nightly-2026-04-30".to_string(),
                false,
                Some("cargo binary not applicable".to_string()),
            )
            .await;

        let cached = state
            .toolchain_preflight_status("nightly-2026-04-30")
            .await
            .expect("toolchain preflight verdict should be cached");

        assert!(!cached.usable);
        assert_eq!(
            cached.reason.as_deref(),
            Some("cargo binary not applicable")
        );
        assert!(cached.is_fresh(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn test_update_config() {
        let state = WorkerState::new(test_config("test"));

        {
            let config = state.config.read().await;
            assert_eq!(config.total_slots, 8);
            assert_eq!(config.priority, 100);
        }

        // Update config
        let mut new_config = test_config("test");
        new_config.total_slots = 16;
        new_config.priority = 200;
        state.update_config(new_config).await;

        let config = state.config.read().await;
        assert_eq!(config.total_slots, 16);
        assert_eq!(config.priority, 200);
    }

    #[tokio::test]
    async fn endpoint_retarget_invalidates_old_and_aba_probe_results() {
        let state = WorkerState::new(test_config("retarget"));
        let original = state.endpoint_snapshot().await;
        let mut replacement = original.config.clone();
        replacement.host = "replacement.host".to_string();
        assert!(state.update_config(replacement).await);
        assert!(state.lock_current_endpoint(&original).await.is_none());

        let intermediate = state.endpoint_snapshot().await;
        assert!(state.update_config(original.config.clone()).await);
        assert!(state.lock_current_endpoint(&original).await.is_none());
        assert!(state.lock_current_endpoint(&intermediate).await.is_none());
        let current = state.endpoint_snapshot().await;
        assert!(state.lock_current_endpoint(&current).await.is_some());

        let mut capacity_edit = current.config.clone();
        capacity_edit.total_slots += 1;
        capacity_edit.priority += 1;
        assert!(!state.update_config(capacity_edit).await);
        assert!(state.lock_current_endpoint(&current).await.is_some());
    }

    #[tokio::test]
    async fn endpoint_retarget_resets_observations_but_preserves_ownership_and_admin_intent() {
        for disabled in [false, true] {
            let state = WorkerState::new(test_config("retarget"));
            assert!(state.reserve_slots(2).await);
            state
                .record_failure(Some("old host authentication stalled".into()))
                .await;
            state.set_last_latency_ms(Some(25_000));
            state
                .cached_projects
                .write()
                .await
                .push("old-project".into());
            state
                .record_toolchain_preflight("old-toolchain".into(), false, Some("old host".into()))
                .await;
            let mut capabilities = WorkerCapabilities::new();
            capabilities.rustc_version = Some("old-rustc".into());
            state.set_capabilities(capabilities).await;
            state.enter_bypass(BypassFailureClass::Ssh).await;
            if disabled {
                state.disable(Some("operator maintenance".into())).await;
            }
            let previous_admin = state.lifecycle().await.admin;
            let previous_reason = state.disabled_reason().await;
            let mut replacement = state.endpoint_snapshot().await.config;
            replacement.host = "new-lan-address".into();
            replacement.total_slots = 1;
            assert!(state.update_config(replacement).await);

            assert_eq!(state.used_slots(), 2, "old builds retain slot ownership");
            assert_eq!(state.available_slots().await, 0);
            assert_eq!(state.lifecycle().await.admin, previous_admin);
            assert_eq!(state.disabled_reason().await, previous_reason);
            assert_eq!(state.eligibility().await, EligibilityState::TemporaryBypass);
            assert_eq!(state.circuit_stats().await.consecutive_failures(), 0);
            assert!(state.last_error().await.is_none());
            assert!(state.last_latency_ms().is_none());
            assert!(state.cached_projects.read().await.is_empty());
            assert!(
                state
                    .toolchain_preflight_status("old-toolchain")
                    .await
                    .is_none()
            );
            assert!(state.capabilities().await.rustc_version.is_none());
            state.release_slots(2).await;
            assert_eq!(state.used_slots(), 0);
        }
    }

    #[tokio::test]
    async fn endpoint_changes_notify_all_monitors_without_losing_busy_subscribers() {
        let pool = WorkerPool::new();
        let mut config = test_config("watched");
        pool.add_worker(config.clone()).await;
        let mut health = pool.subscribe_endpoint_changes();
        let mut recovery = pool.subscribe_endpoint_changes();
        config.priority += 1;
        pool.add_worker(config.clone()).await;
        assert!(!health.has_changed().unwrap());
        config.identity_file = "/new/key".into();
        pool.add_worker(config).await;
        assert!(health.has_changed().unwrap());
        assert!(recovery.has_changed().unwrap());
        health.changed().await.unwrap();
        recovery.changed().await.unwrap();
        assert_eq!(*health.borrow_and_update(), *recovery.borrow_and_update());
    }

    #[tokio::test(start_paused = true)]
    async fn inventory_resume_wakes_health_without_resetting_recovery_deadline() {
        let heartbeat = Duration::from_secs(30);
        let circuit = CircuitBreakerConfig {
            failure_threshold: 1,
            open_cooldown_secs: 900,
            ..Default::default()
        };
        for connected in [true, false] {
            let pool = WorkerPool::new().with_connection_monitoring();
            let config = test_config("returning");
            pool.add_worker(config.clone()).await;
            let worker = pool.get(&config.id).await.unwrap();
            worker
                .record_transport_result(true, heartbeat, &circuit)
                .await;
            assert!(worker.reserve_slots(1).await);
            let initial = worker
                .health_probe_permit(heartbeat, &circuit)
                .await
                .unwrap();
            worker
                .record_transport_result(connected, heartbeat, &circuit)
                .await;
            drop(initial);

            worker.drain_for_removal().await;
            worker.release_slots(1).await;
            assert!(worker.is_drained().await);
            assert!(worker.next_health_probe_in().await.is_none());
            let mut changes = pool.subscribe_endpoint_changes();
            tokio::time::advance(heartbeat).await;

            // With its sole worker drained, the monitor may be asleep for the
            // 900s fallback. Returning identical inventory must wake it even
            // though the connection endpoint and its existing clock are intact.
            pool.add_worker(config.clone()).await;
            assert!(
                changes.has_changed().unwrap(),
                "inventory resume must wake health"
            );
            changes.changed().await.unwrap();
            assert!(Arc::ptr_eq(&worker, &pool.get(&config.id).await.unwrap()));
            assert_eq!(worker.transport_is_down().await, !connected);
            assert_eq!(
                worker.next_health_probe_in().await,
                Some(if connected {
                    Duration::ZERO
                } else {
                    Duration::from_secs(870)
                })
            );
            pool.add_worker(config.clone()).await;
            assert!(
                !changes.has_changed().unwrap(),
                "unchanged active inventory needs no wake"
            );

            if connected {
                let due = worker
                    .health_probe_permit(heartbeat, &circuit)
                    .await
                    .unwrap();
                assert!(
                    !due.isolated,
                    "the verified healthy endpoint is immediately due"
                );
            } else {
                assert!(
                    worker
                        .health_probe_permit(heartbeat, &circuit)
                        .await
                        .is_none()
                );
                tokio::time::advance(Duration::from_secs(869)).await;
                assert_eq!(
                    worker.next_health_probe_in().await,
                    Some(Duration::from_secs(1))
                );
                assert!(
                    worker
                        .health_probe_permit(heartbeat, &circuit)
                        .await
                        .is_none()
                );
                tokio::time::advance(Duration::from_secs(1)).await;
                let due = worker
                    .health_probe_permit(heartbeat, &circuit)
                    .await
                    .unwrap();
                assert!(
                    due.isolated,
                    "outage recovery still waits the full 900 seconds"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_update_config_cancels_pending_removal_drain() {
        let state = WorkerState::new(test_config("test"));

        assert!(state.reserve_slots(1).await);
        state.drain_for_removal().await;
        assert_eq!(state.status().await, WorkerStatus::Draining);
        assert!(state.remove_after_drain_pending().await);

        let mut new_config = test_config("test");
        new_config.priority = 250;
        state.update_config(new_config).await;

        assert_eq!(state.status().await, WorkerStatus::Healthy);
        assert!(!state.remove_after_drain_pending().await);
        state.release_slots(1).await;
        assert_eq!(state.status().await, WorkerStatus::Healthy);
    }

    // ============== WorkerPool Tests ==============

    #[tokio::test]
    async fn test_pool_new_empty() {
        let pool = WorkerPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn test_pool_add_and_get() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("worker-1")).await;
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());

        let worker = pool.get(&WorkerId::new("worker-1")).await;
        assert!(worker.is_some());
        let worker = worker.unwrap();
        assert_eq!(worker.config.read().await.total_slots, 8);

        // Non-existent worker
        assert!(pool.get(&WorkerId::new("worker-2")).await.is_none());
    }

    #[tokio::test]
    async fn test_pool_add_duplicate_updates() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("worker-1")).await;
        assert_eq!(pool.len(), 1);

        // Adding same id again updates config, doesn't add new worker
        let mut updated_config = test_config("worker-1");
        updated_config.total_slots = 16;
        pool.add_worker(updated_config).await;

        assert_eq!(pool.len(), 1);

        let worker = pool.get(&WorkerId::new("worker-1")).await.unwrap();
        assert_eq!(worker.config.read().await.total_slots, 16);
    }

    #[tokio::test]
    async fn test_pool_remove_worker() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("worker-1")).await;
        pool.add_worker(test_config("worker-2")).await;
        assert_eq!(pool.len(), 2);

        // Remove existing
        assert!(pool.remove_worker(&WorkerId::new("worker-1")).await);
        assert_eq!(pool.len(), 1);
        assert!(pool.get(&WorkerId::new("worker-1")).await.is_none());
        assert!(pool.get(&WorkerId::new("worker-2")).await.is_some());

        // Remove non-existent
        assert!(!pool.remove_worker(&WorkerId::new("worker-1")).await);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn test_pool_all_workers() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("worker-1")).await;
        pool.add_worker(test_config("worker-2")).await;

        // Disable one
        pool.get(&WorkerId::new("worker-1"))
            .await
            .unwrap()
            .disable(None)
            .await;

        let all = pool.all_workers().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_pool_healthy_workers() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("healthy")).await;
        pool.add_worker(test_config("degraded")).await;
        pool.add_worker(test_config("unreachable")).await;
        pool.add_worker(test_config("disabled")).await;
        pool.add_worker(test_config("draining")).await;

        // Set statuses
        pool.get(&WorkerId::new("degraded"))
            .await
            .unwrap()
            .set_status(WorkerStatus::Degraded)
            .await;
        pool.get(&WorkerId::new("unreachable"))
            .await
            .unwrap()
            .set_status(WorkerStatus::Unreachable)
            .await;
        pool.get(&WorkerId::new("disabled"))
            .await
            .unwrap()
            .disable(None)
            .await;
        pool.get(&WorkerId::new("draining"))
            .await
            .unwrap()
            .drain()
            .await;

        let healthy = pool.healthy_workers().await;

        // Should include Healthy and Degraded only
        assert_eq!(healthy.len(), 2);

        // Collect worker ids manually
        let mut ids = Vec::new();
        for w in &healthy {
            ids.push(w.config.read().await.id.clone());
        }

        assert!(ids.contains(&WorkerId::new("healthy")));
        assert!(ids.contains(&WorkerId::new("degraded")));
    }

    #[tokio::test]
    async fn test_pool_set_status() {
        let pool = WorkerPool::new();
        pool.add_worker(test_config("worker-1")).await;

        pool.set_status(&WorkerId::new("worker-1"), WorkerStatus::Unreachable)
            .await;

        let worker = pool.get(&WorkerId::new("worker-1")).await.unwrap();
        assert_eq!(worker.status().await, WorkerStatus::Unreachable);

        // Setting status on non-existent worker is a no-op
        pool.set_status(&WorkerId::new("nonexistent"), WorkerStatus::Healthy)
            .await;
    }

    #[tokio::test]
    async fn test_pool_release_slots() {
        let pool = WorkerPool::new();
        pool.add_worker(test_config("worker-1")).await;

        let worker = pool.get(&WorkerId::new("worker-1")).await.unwrap();
        worker.reserve_slots(4).await;
        assert_eq!(worker.available_slots().await, 4);

        pool.release_slots(&WorkerId::new("worker-1"), 2).await;
        assert_eq!(worker.available_slots().await, 6);

        // Release on non-existent worker is a no-op
        pool.release_slots(&WorkerId::new("nonexistent"), 10).await;
    }

    #[tokio::test]
    async fn test_prune_drained() {
        let pool = WorkerPool::new();

        // Active worker
        let active = WorkerState::new(WorkerConfig {
            id: WorkerId::new("active"),
            host: "localhost".to_string(),
            user: "u".to_string(),
            identity_file: "i".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        });
        pool.add_worker_state(active).await;

        // User-drained worker with 0 slots used. This must remain in the pool
        // so `rch workers enable <id>` can bring it back.
        let user_drained_empty = WorkerState::new(WorkerConfig {
            id: WorkerId::new("user_drained_empty"),
            host: "localhost".to_string(),
            user: "u".to_string(),
            identity_file: "i".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        });
        user_drained_empty.drain().await;
        pool.add_worker_state(user_drained_empty).await;

        // Config-removal drain with 0 slots used. This is the only kind of
        // drained worker the background cleanup should prune.
        let removed_empty = WorkerState::new(WorkerConfig {
            id: WorkerId::new("removed_empty"),
            host: "localhost".to_string(),
            user: "u".to_string(),
            identity_file: "i".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        });
        removed_empty.drain_for_removal().await;
        pool.add_worker_state(removed_empty).await;

        // Config-removal drain with slots in use (should NOT be pruned yet).
        //
        // In production, slot reservation happens while the worker is
        // still healthy (selection path) and a subsequent removal drain just
        // stops new reservations without releasing the in-flight ones.
        // `reserve_slots` (correctly) refuses after drain, so the test
        // must mirror that ordering.
        let removed_busy = WorkerState::new(WorkerConfig {
            id: WorkerId::new("removed_busy"),
            host: "localhost".to_string(),
            user: "u".to_string(),
            identity_file: "i".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        });
        assert!(removed_busy.reserve_slots(1).await);
        removed_busy.drain_for_removal().await;
        pool.add_worker_state(removed_busy).await;

        assert_eq!(pool.len(), 4);

        let pruned = pool.prune_drained().await;
        assert_eq!(pruned, 1);
        assert_eq!(pool.len(), 3);

        assert!(pool.get(&WorkerId::new("active")).await.is_some());
        assert!(
            pool.get(&WorkerId::new("user_drained_empty"))
                .await
                .is_some()
        );
        assert!(pool.get(&WorkerId::new("removed_busy")).await.is_some());
        assert!(pool.get(&WorkerId::new("removed_empty")).await.is_none());

        let removed_busy = pool.get(&WorkerId::new("removed_busy")).await.unwrap();
        removed_busy.release_slots(1).await;
        assert_eq!(pool.prune_drained().await, 1);
        assert!(pool.get(&WorkerId::new("removed_busy")).await.is_none());
    }

    #[tokio::test]
    async fn test_prune_drained_empty_pool() {
        let pool = WorkerPool::new();
        let pruned = pool.prune_drained().await;
        assert_eq!(pruned, 0);
    }

    #[tokio::test]
    async fn test_prune_drained_no_draining_workers() {
        let pool = WorkerPool::new();
        pool.add_worker(test_config("worker-1")).await;
        pool.add_worker(test_config("worker-2")).await;

        let pruned = pool.prune_drained().await;
        assert_eq!(pruned, 0);
        assert_eq!(pool.len(), 2);
    }

    #[tokio::test]
    async fn test_pool_default() {
        let pool = WorkerPool::default();
        assert!(pool.is_empty());
    }
}
