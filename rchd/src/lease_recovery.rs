//! Background recovery of dead client leases with unfinished ownership
//! (bd-nalyr).
//!
//! The lease scan keeps a lease whose wrapper died while its recovery recipe
//! still names worker-side source (bd-dmg2k): that lease is the only authority
//! able to release the worker's source-authority claim. Keeping it is correct,
//! but until now only an operator running `rch jobs recover` finished it, so
//! claims piled up (~15 per half hour across the fleet) and fenced overlapping
//! builds. This task runs that same recovery for leases whose owner is provably
//! gone, a few per cycle, backing off per lease after a failure.
//! Source retirement can precede the daemon handoff: those unacknowledged
//! journals still need recovery, even though no worker filesystem work remains.
//! Older acknowledged cancellations also remain candidates until their exact
//! worker-side cancellation state has been reconciled (#111).

#[cfg(test)]
use crate::api::is_process_alive;
use crate::api::lease_owns_unretired_source;
use crate::events::EventBus;
use crate::workers::{OwnedRecoveryPermit, WorkerPool};
use rch_common::WorkerConfig;
use rch_common::bypass_record::{AdminDisableStore, AdminNetworkPermit};
use rch_common::job_identity::{
    DurableJobLease, default_job_lease_directory, local_terminal_settlement_candidate,
    source_recovery_resources_retired,
};
use rch_common::job_recovery::{
    AUTOMATIC_RECOVERY_DEFERRED_EXIT_CODE, AUTOMATIC_RECOVERY_PENDING_EXIT_CODE,
};
use rch_common::process_identity::{OwnerPresence, owner_presence};
use rch_common::ssh::{OwnedProcessGroup, ssh_can_disable_background};
use rch_common::timing::{MAX_CONTROL_TIMEOUT, TIMING_SCALE_ENV, TimingScale, ceil_seconds};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::Mutex;
use tokio::task::{Id, JoinSet};
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// A dead wrapper can fence every worker for its project even after its slots
/// have been released. Inspect promptly; ownership evidence, not heartbeat age,
/// authorizes a recovery attempt. Failed attempts keep their longer backoff.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(30);
/// Bound both starts per scan interval and total in-flight recovery clients.
/// A worker gets at most one client, so a stalled worker cannot consume every
/// lane or serialize independent workers behind its timeout.
const MAX_RECOVERIES_PER_CYCLE: usize = 4;
/// Base control budget handed to `rch jobs recover`. This is recovery of an
/// already-owned operation, not a new compiler/test lifetime.
const RECOVER_TIMEOUT_SECS: u64 = 300;
/// Local SSH inspection and a readiness-only scan use the same bounded phase
/// allowance. Neither scan starts worker-side recovery.
const RECOVERY_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
/// Local parent-lifetime/exit slack stays fixed when remote latency is scaled.
const RECOVER_EXIT_SLACK: Duration = Duration::from_secs(30);
/// Keep diagnostics bounded even when a recovery produces gigabytes of output.
const RECOVER_STDERR_TAIL_BYTES: usize = 16 * 1024;
/// Reap the direct child after timeout without wedging the recovery service.
const RECOVER_REAP_TIMEOUT: Duration = Duration::from_secs(5);
/// Retry delay after the first failure; doubles per failure up to the cap.
const BACKOFF_BASE: Duration = Duration::from_secs(10 * 60);
const BACKOFF_MAX: Duration = Duration::from_secs(6 * 60 * 60);

/// Snapshot one policy and deadline before admission. Every later phase,
/// including the child CLI, consumes this window instead of renewing it.
#[derive(Clone, Copy)]
struct RecoveryWindow {
    scale: TimingScale,
    deadline: Instant,
}

impl RecoveryWindow {
    fn new(scale: TimingScale) -> Result<Self, String> {
        let budget = scale
            .duration(Duration::from_secs(RECOVER_TIMEOUT_SECS))
            .saturating_add(RECOVER_EXIT_SLACK)
            .min(MAX_CONTROL_TIMEOUT);
        let deadline = Instant::now().checked_add(budget).ok_or_else(|| {
            "automatic lease recovery deadline exceeds the clock range".to_owned()
        })?;
        Ok(Self { scale, deadline })
    }

    fn remaining(self) -> Result<Duration, String> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err("automatic lease recovery exceeded its total deadline".into())
        } else {
            Ok(remaining)
        }
    }

    fn child_timeout_secs(self) -> Result<u64, String> {
        // The CLI accepts whole seconds. Its rounding never extends the
        // parent's original elapsed deadline or authorizes late confirmation.
        Ok(ceil_seconds(
            self.remaining()?.min(
                self.scale
                    .duration(Duration::from_secs(RECOVER_TIMEOUT_SECS)),
            ),
        ))
    }
}

/// Expiry wins before polling a ready operation; synchronous work finishing
/// across the boundary is also refused. No result here proves worker exit.
async fn before_recovery_deadline<F: Future>(deadline: Instant, operation: F) -> Option<F::Output> {
    if Instant::now() >= deadline {
        return None;
    }
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(deadline) => None,
        result = operation => (Instant::now() < deadline).then_some(result),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryOutcome {
    Recovered,
    /// The worker still owns an execution or its completion raced the probe.
    /// Keep ownership and retry on the next scan, without failure backoff.
    SettlementPending,
    /// Administrative disable, transport backoff, an owned recovery flight,
    /// or contention for the exact journal's exclusive ownership gate.
    /// Neither establishes lease completion nor counts as a failed recovery.
    Deferred,
}

enum RecoveryAdmission {
    /// All worker obligations are settled. The child must use its enforced
    /// local-only path and reload this evidence after claiming the journal.
    Local,
    Network {
        admin: AdminNetworkPermit,
        network: Option<Box<OwnedRecoveryPermit>>,
    },
}

impl RecoveryAdmission {
    async fn run_until<F: Future>(&mut self, operation: F, deadline: Instant) -> Option<F::Output> {
        // Keep large recovery operations out of each nested revocation
        // guard's future. Dropping the box still cancels the owned operation.
        let operation = Box::pin(operation);
        before_recovery_deadline(deadline, async {
            match self {
                Self::Local => Some(operation.await),
                Self::Network { admin, network } => admin
                    .run(async {
                        match network {
                            Some(network) => network.run_until(operation, deadline).await,
                            None => Some(operation.await),
                        }
                    })
                    .await
                    .flatten(),
            }
        })
        .await
        .flatten()
    }
}

#[derive(Clone, Copy)]
enum RecoveryClientPolicy {
    #[cfg(test)]
    Unmanaged,
    Network {
        can_disable_background: bool,
    },
    Local,
}

/// A settled, identity-bound delivery result whose source resources are retired.
/// This selects a reconciliation attempt; the client still reloads under its
/// exclusive recovery lock and requires the daemon's exact terminal receipt.
fn retired_delivery(lease: &DurableJobLease) -> Option<i32> {
    let recipe = lease.recovery.as_ref()?;
    let build_id = lease.identity.remote_build_id.filter(|id| *id > 0)?;
    let worker = lease.worker_id.as_deref().filter(|id| !id.is_empty())?;
    if recipe["version"].as_u64() != Some(2)
        || recipe["wrapper_id"].as_str() != Some(lease.identity.local_wrapper_id.as_str())
        || recipe["build_id"].as_u64() != Some(build_id)
        || recipe["worker"]["id"].as_str() != Some(worker)
        || recipe["retired"].as_bool() != Some(true)
        || !source_recovery_resources_retired(recipe)
    {
        return None;
    }
    recipe["returned"]
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
}

fn source_cancellation_pending(recipe: &serde_json::Value) -> Option<bool> {
    let preparation_cancelled = match recipe.get("preparation_cancelled") {
        None => false,
        Some(serde_json::Value::Bool(cancelled)) => *cancelled,
        _ => return None,
    };
    match recipe.get("source_cancellation_settled") {
        None | Some(serde_json::Value::Null) => Some(preparation_cancelled),
        Some(serde_json::Value::Bool(settled)) => Some(!settled),
        _ => None,
    }
}

fn terminal_cancellation_unsettled(lease: &DurableJobLease) -> bool {
    lease
        .recovery
        .as_ref()
        .and_then(source_cancellation_pending)
        == Some(true)
        && lease.terminal_acknowledged
        && lease.state == rch_common::job_identity::JobLifecycleState::Finished
        && retired_delivery(lease).is_some_and(|exit| exit != 0 && lease.exit_code == Some(exit))
}

/// Matches rchd's stuck-build hard cap (`should_remediate`) and the client's
/// `DAEMON_ABSENCE_MIN_AGE_MS` threshold (bd-ey7fr).
const DAEMON_ABSENCE_MIN_AGE_MS: u64 = 24 * 60 * 60 * 1000;

fn abandoned_without_recovery(lease: &DurableJobLease, now_unix_ms: u64) -> bool {
    lease.recovery.is_none()
        && lease.identity.remote_build_id.is_some_and(|id| id > 0)
        && lease.worker_id.as_deref().is_some_and(|id| !id.is_empty())
        && lease.heartbeat_unix_ms > 0
        && now_unix_ms.saturating_sub(lease.heartbeat_unix_ms) >= DAEMON_ABSENCE_MIN_AGE_MS
}

/// A successful CLI exit can mean only that a live wrapper was asked to resume.
/// Count recovery as complete only after reading the original journal back.
fn verify_recovery_completion(
    before: &DurableJobLease,
    after: &DurableJobLease,
) -> Result<(), String> {
    if before.identity != after.identity
        || before.worker_id != after.worker_id
        || before.wrapper_pid != after.wrapper_pid
        || before.process_start_ticks != after.process_start_ticks
        || before.boot_id != after.boot_id
        || before.process_birth != after.process_birth
        || before.command_fingerprint != after.command_fingerprint
    {
        return Err("recovery journal identity changed; completion not confirmed".into());
    }
    let before_namespace =
        before.recovery.as_ref().map_or(
            &serde_json::Value::Null,
            |recipe| &recipe["source_authority_namespace"],
        );
    let after_namespace =
        after.recovery.as_ref().map_or(
            &serde_json::Value::Null,
            |recipe| &recipe["source_authority_namespace"],
        );
    let valid_namespace = |value: &serde_json::Value| {
        value.is_null() || matches!(value.as_str(), Some("current" | "legacy"))
    };
    if !valid_namespace(before_namespace)
        || !valid_namespace(after_namespace)
        || (!before_namespace.is_null() && before_namespace != after_namespace)
    {
        return Err("source ownership namespace changed or is malformed".into());
    }
    if let Some(recipe) = after.recovery.as_ref() {
        // Discovery can add an obligation after this daemon selected an
        // ordinary unacknowledged handoff. Re-read that obligation too: an
        // acknowledged CLI result cannot conceal a pending cancellation.
        match source_cancellation_pending(recipe) {
            Some(false) => {}
            Some(true) => {
                return Err("recovery command left worker cancellation unsettled".into());
            }
            None => return Err("recovery command left malformed cancellation evidence".into()),
        }
        if recipe["source_cancellation_settled"].as_bool() == Some(true) {
            if !retired_delivery(after).is_some_and(|exit| exit != 0) {
                return Err(
                    "worker cancellation settlement contradicts retired failed delivery".into(),
                );
            }
            if recipe["source_roots"]
                .as_array()
                .is_some_and(|roots| !roots.is_empty())
                && !matches!(after_namespace.as_str(), Some("current" | "legacy"))
            {
                return Err("worker cancellation settlement has no exact source namespace".into());
            }
        }
    }
    if terminal_cancellation_unsettled(before) {
        // This lease already completed daemon accounting. The only remaining
        // obligation is worker cancellation; a zero CLI exit with the old
        // terminal flags is exactly the false success reported in #111.
        let before_recipe = before.recovery.as_ref().expect("validated cancellation");
        let Some(after_recipe) = after.recovery.as_ref() else {
            return Err("terminal cancellation lost its recovery recipe".into());
        };
        if after_recipe["source_cancellation_settled"].as_bool() != Some(true)
            || (after_recipe["source_roots"]
                .as_array()
                .is_some_and(|roots| !roots.is_empty())
                && !matches!(after_namespace.as_str(), Some("current" | "legacy")))
            || !after.terminal_acknowledged
            || after.state != before.state
            || after.exit_code != before.exit_code
            || retired_delivery(after) != before.exit_code
            || [
                "identity",
                "worker",
                "source_roots",
                "completion",
                "pair",
                "retire_root",
                "retained_root",
                "retained_materialized",
                "sources_released",
                "tree_retired",
                "pair_released",
                "execution_started",
                "preparation_cancelled",
            ]
            .iter()
            .any(|key| before_recipe[*key] != after_recipe[*key])
        {
            return Err(
                "terminal cancellation exited without exact worker settlement evidence".into(),
            );
        }
        return Ok(());
    }
    if before.recovery.is_none() && after.recovery.is_none() {
        if before.heartbeat_unix_ms == 0
            || !after.terminal_acknowledged
            || after.state != rch_common::job_identity::JobLifecycleState::Finished
            || after.exit_code.is_none()
            || before
                .exit_code
                .is_some_and(|observed| Some(observed) != after.exit_code)
        {
            return Err(
                "recovery command exited without durable daemon/delivery acknowledgement".into(),
            );
        }
        return Ok(());
    }
    let daemon_exit = after.recovery.as_ref().and_then(|recipe| {
        recipe["daemon_exit_code"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok())
    });
    // A long-dead build the daemon no longer knew held no reservation; the
    // client accepts that absence only after the 24h stuck cap (bd-ey7fr).
    let daemon_record_absent = after
        .recovery
        .as_ref()
        .is_some_and(|recipe| recipe["daemon_record_absent"].as_bool() == Some(true));
    if !after.terminal_acknowledged
        || after.state != rch_common::job_identity::JobLifecycleState::Finished
        || retired_delivery(after).is_none()
        || retired_delivery(after) != after.exit_code
        || (daemon_exit.is_none() && !daemon_record_absent)
    {
        return Err(
            "recovery command exited without durable daemon/delivery acknowledgement".into(),
        );
    }
    Ok(())
}

fn read_lease(lease_dir: &Path, wrapper_id: &str) -> Result<DurableJobLease, String> {
    // Never let a malformed journal name select a path outside the lease root.
    let suffix = wrapper_id
        .strip_prefix(rch_common::job_identity::LOCAL_WRAPPER_ID_PREFIX)
        .ok_or_else(|| "invalid recovery wrapper id".to_owned())?;
    let uuid =
        uuid::Uuid::parse_str(suffix).map_err(|_| "invalid recovery wrapper id".to_owned())?;
    if uuid.to_string() != suffix {
        return Err("noncanonical recovery wrapper id".into());
    }
    let path = lease_dir.join(format!("{wrapper_id}.json"));
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("recovery journal is not a regular file".into());
    }
    let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
    let lease: DurableJobLease =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if lease.schema_version != 1 || lease.identity.local_wrapper_id != wrapper_id {
        return Err("recovery journal schema or filename identity is invalid".into());
    }
    Ok(lease)
}

/// Small scheduling record; the full journal is reloaded before client launch.
#[derive(Clone, Debug)]
struct RecoveryCandidate {
    wrapper_id: String,
    build_id: u64,
    worker_id: String,
    heartbeat_unix_ms: u64,
}

/// Only dead source owners, pending daemon handoffs, or acknowledged
/// cancellations lacking worker settlement enter the queue. Unreadable or
/// noncanonical journals are not execution authority; the separate restart
/// scan retains its fail-closed treatment of bad evidence.
fn recoverable_candidates(
    lease_dir: &Path,
    now_unix_ms: u64,
    presence: impl Fn(&DurableJobLease) -> OwnerPresence,
) -> Vec<RecoveryCandidate> {
    let Ok(entries) = std::fs::read_dir(lease_dir) else {
        return Vec::new();
    };
    let mut candidates: Vec<RecoveryCandidate> = entries
        .filter_map(Result::ok)
        // Never open a named pipe, socket, directory or symlink as a journal.
        // The client rechecks the exact canonical identity before spawning.
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .filter_map(|path| read_lease(lease_dir, path.file_stem()?.to_str()?).ok())
        .filter(|lease| {
            let unfinished = terminal_cancellation_unsettled(lease)
                || (!lease.terminal_acknowledged
                    && (lease_owns_unretired_source(lease)
                        || retired_delivery(lease).is_some()
                        || abandoned_without_recovery(lease, now_unix_ms)));
            // A recent heartbeat cannot keep a provably dead owner alive.
            // Reusing the restart barrier's fifteen-minute grace stranded
            // execute/finalize leases after wrapper death or a build deadline
            // (GH #134). Recovery still claims the journal's exclusive gate
            // and confirms exact worker/daemon receipts before releasing any
            // source fence; merely scheduling it changes no durable evidence.
            unfinished && presence(lease) == OwnerPresence::Absent
        })
        .filter_map(|lease| {
            Some(RecoveryCandidate {
                wrapper_id: lease.identity.local_wrapper_id,
                build_id: lease.identity.remote_build_id.filter(|id| *id > 0)?,
                worker_id: lease.worker_id.filter(|id| !id.is_empty())?,
                heartbeat_unix_ms: lease.heartbeat_unix_ms,
            })
        })
        .collect();
    // Prioritize the oldest abandoned ownership; UUID ordering is only a
    // deterministic tie-break, not a priority that can starve old recoveries.
    candidates.sort_by(|left, right| {
        left.heartbeat_unix_ms
            .cmp(&right.heartbeat_unix_ms)
            .then_with(|| left.wrapper_id.cmp(&right.wrapper_id))
    });
    candidates
}

/// Delay before retrying a lease that has failed `failures` times.
fn backoff_after(failures: u32) -> Duration {
    BACKOFF_BASE
        .saturating_mul(1u32 << failures.saturating_sub(1).min(16))
        .min(BACKOFF_MAX)
}

#[derive(Default)]
struct Backoff {
    failures: HashMap<String, (u32, Instant)>,
}

impl Backoff {
    fn ready(&self, id: &str, now: Instant) -> bool {
        self.failures.get(id).is_none_or(|(_, next)| now >= *next)
    }

    fn record_failure(&mut self, id: &str, now: Instant) -> u32 {
        let failures = self.failures.get(id).map_or(1, |(count, _)| count + 1);
        self.failures
            .insert(id.to_string(), (failures, now + backoff_after(failures)));
        failures
    }

    /// Forget leases that are no longer candidates (recovered, or reaped).
    fn retain(&mut self, candidates: &[String]) {
        let candidates: HashSet<&str> = candidates.iter().map(String::as_str).collect();
        self.failures
            .retain(|id, _| candidates.contains(id.as_str()));
    }
}

/// Own every recovery task across scans. A scan is admission, not a barrier:
/// completions on healthy workers are processed while another worker waits.
#[derive(Default)]
struct RecoveryQueue {
    pending: VecDeque<RecoveryCandidate>,
    running: HashMap<Id, RecoveryCandidate>,
    tasks: JoinSet<Result<RecoveryOutcome, String>>,
    backoff: Backoff,
    last_started: HashMap<String, Instant>,
    starts_remaining: usize,
}

impl RecoveryQueue {
    fn refresh(&mut self, mut candidates: Vec<RecoveryCandidate>) {
        let ids: Vec<String> = candidates
            .iter()
            .chain(self.running.values())
            .map(|candidate| candidate.wrapper_id.clone())
            .collect();
        self.backoff.retain(&ids);
        let retained: HashSet<&str> = ids.iter().map(String::as_str).collect();
        self.last_started
            .retain(|id, _| retained.contains(id.as_str()));
        // Pending executions do not fail, so they have no retry backoff. Give
        // unattempted and least-recently attempted leases the next turn rather
        // than letting the oldest four consume every scan indefinitely.
        // Stable sorting preserves journal age order for equal priorities.
        candidates.sort_by_key(|candidate| self.last_started.get(&candidate.wrapper_id).copied());
        self.pending = candidates.into();
        self.starts_remaining = MAX_RECOVERIES_PER_CYCLE;
    }

    #[cfg(test)]
    fn start_ready<F, R>(&mut self, now: Instant, mut run: F)
    where
        F: FnMut(RecoveryCandidate) -> R,
        R: Future<Output = Result<(), String>> + Send + 'static,
    {
        self.start_ready_if(
            now,
            |_| true,
            move |candidate| {
                let operation = run(candidate);
                async move { operation.await.map(|()| RecoveryOutcome::Recovered) }
            },
        );
    }

    fn start_ready_if<F, R>(
        &mut self,
        now: Instant,
        allowed: impl Fn(&RecoveryCandidate) -> bool,
        mut run: F,
    ) where
        F: FnMut(RecoveryCandidate) -> R,
        R: Future<Output = Result<RecoveryOutcome, String>> + Send + 'static,
    {
        while self.starts_remaining > 0 && self.running.len() < MAX_RECOVERIES_PER_CYCLE {
            let next = self.pending.iter().position(|candidate| {
                allowed(candidate)
                    && self.backoff.ready(&candidate.wrapper_id, now)
                    && !self.running.values().any(|running| {
                        running.wrapper_id == candidate.wrapper_id
                            || running.worker_id == candidate.worker_id
                    })
            });
            let Some(next) = next else { break };
            let candidate = self
                .pending
                .remove(next)
                .expect("selected pending recovery");
            let task = self.tasks.spawn(run(candidate.clone()));
            self.last_started.insert(candidate.wrapper_id.clone(), now);
            self.running.insert(task.id(), candidate);
            self.starts_remaining -= 1;
        }
    }

    async fn next_completed(
        &mut self,
    ) -> Option<(RecoveryCandidate, Result<RecoveryOutcome, String>)> {
        let joined = self.tasks.join_next_with_id().await?;
        let (task_id, outcome) = match joined {
            Ok((id, outcome)) => (id, outcome),
            Err(error) => (error.id(), Err(format!("recovery task failed: {error}"))),
        };
        let candidate = self.running.remove(&task_id).expect("owned recovery task");
        // A scan during the task may have queued its old snapshot. Do not
        // relaunch that snapshot after success or lose backoff after a panic.
        self.pending
            .retain(|pending| pending.wrapper_id != candidate.wrapper_id);
        if outcome.is_err() {
            self.backoff
                .record_failure(&candidate.wrapper_id, Instant::now());
        } else if outcome == Ok(RecoveryOutcome::Recovered) {
            self.backoff.failures.remove(&candidate.wrapper_id);
            self.last_started.remove(&candidate.wrapper_id);
        }
        Some((candidate, outcome))
    }
}

fn recovery_scan_interval() -> tokio::time::Interval {
    // The first tick is immediate: a daemon restart must not introduce a new
    // grace window for leases whose recorded owner is already gone.
    let mut ticker = tokio::time::interval(RECOVERY_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker
}

/// Start the recovery loop. `socket` is this daemon's socket; the child
/// `rch` is pointed at it so it never reconciles against another daemon.
pub(crate) fn start(
    events: EventBus,
    socket: PathBuf,
    admin_store: Arc<Mutex<AdminDisableStore>>,
    pool: WorkerPool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let rch = match std::env::current_exe() {
            Ok(exe) => exe.with_file_name("rch"),
            Err(error) => {
                warn!("Lease auto-recovery disabled: cannot resolve rchd path: {error}");
                return;
            }
        };
        let mut queue = RecoveryQueue::default();
        let mut ticker = recovery_scan_interval();
        loop {
            tokio::select! {
                completed = queue.next_completed(), if !queue.running.is_empty() => {
                    if let Some((candidate, outcome)) = completed {
                        let id = candidate.wrapper_id;
                        match outcome {
                            Ok(RecoveryOutcome::Recovered) => {
                                info!(wrapper_id = %id, "Recovered dead client lease");
                                events.emit("lease_auto_recovered", &serde_json::json!({
                                    "wrapper_id": id,
                                }));
                            }
                            Ok(RecoveryOutcome::SettlementPending) => {
                                debug!(wrapper_id = %id, "Worker settlement pending; retaining lease ownership until the next scan");
                            }
                            Ok(RecoveryOutcome::Deferred) => {}
                            Err(error) => {
                                let failures = queue.backoff.failures[&id].0;
                                warn!(wrapper_id = %id, failures, "Dead client lease recovery failed: {error}");
                                events.emit("lease_auto_recovery_failed", &serde_json::json!({
                                    "wrapper_id": id, "failures": failures, "error": error,
                                }));
                            }
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !rch.exists() {
                        continue;
                    }
                    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
                    match tokio::task::spawn_blocking(move || {
                        recoverable_candidates(&default_job_lease_directory(), now, |lease| {
                            owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
                        })
                    }).await {
                        Ok(candidates) => queue.refresh(candidates),
                        Err(error) => warn!(%error, "Lease recovery scan failed; retaining in-flight tasks"),
                    }
                }
            }
            // Dormant workers consume neither the per-scan budget nor a lane.
            // Keep them queued, with existing backoff and durable ownership,
            // so enabling/recovery resumes them on the next normal scan.
            let eligible = eligible_recoveries(
                &queue.pending,
                &admin_store,
                &pool,
                &default_job_lease_directory(),
            )
            .await;
            queue.start_ready_if(
                Instant::now(),
                |candidate| eligible.contains(&candidate.wrapper_id),
                |candidate| {
                    let rch = rch.clone();
                    let socket = socket.clone();
                    let admin_store = admin_store.clone();
                    let pool = pool.clone();
                    async move { recover(&rch, &socket, &candidate, &admin_store, &pool).await }
                },
            );
        }
    })
}

async fn eligible_recoveries(
    candidates: &VecDeque<RecoveryCandidate>,
    admin_store: &Mutex<AdminDisableStore>,
    pool: &WorkerPool,
    lease_dir: &Path,
) -> HashSet<String> {
    let mut eligible = HashSet::new();
    let Some(deadline) = Instant::now().checked_add(rch_common::timing::scale_duration(
        RECOVERY_PREFLIGHT_TIMEOUT,
    )) else {
        return eligible;
    };
    for candidate in candidates {
        // Readiness is speculative. A queued local lock defers only this
        // candidate; actual recovery rechecks and claims its flight in run_until.
        let Some(admitted) = before_recovery_deadline(deadline, async {
            // A fresh cooperative budget keeps later ready peers from looking
            // contended after a long prefix. This yields within the original
            // shared deadline instead of granting each candidate a new budget.
            tokio::task::yield_now().await;
            let mut admission =
                std::pin::pin!(recovery_admission(admin_store, pool, lease_dir, candidate));
            std::future::poll_fn(|cx| std::task::Poll::Ready(admission.as_mut().poll(cx))).await
        })
        .await
        else {
            // A queued scan must not wedge completion accounting for all
            // workers. Keep uninspected candidates for the next normal scan.
            break;
        };
        // Pending observations drop their queued locks without claiming a
        // transport lane. Ready errors keep the ordinary error/backoff path.
        if matches!(admitted, std::task::Poll::Ready(Ok(Some(_)) | Err(_))) {
            eligible.insert(candidate.wrapper_id.clone());
        }
    }
    eligible
}

/// Run `rch jobs recover` for one lease; the error is the tail of its stderr.
async fn recover(
    rch: &Path,
    socket: &Path,
    candidate: &RecoveryCandidate,
    admin_store: &Mutex<AdminDisableStore>,
    pool: &WorkerPool,
) -> Result<RecoveryOutcome, String> {
    let directory = default_job_lease_directory();
    let window = RecoveryWindow::new(rch_common::timing::configured())?;
    recover_before(
        rch,
        socket,
        &directory,
        candidate,
        admin_store,
        pool,
        window,
    )
    .await
}

async fn recover_before(
    rch: &Path,
    socket: &Path,
    directory: &Path,
    candidate: &RecoveryCandidate,
    admin_store: &Mutex<AdminDisableStore>,
    pool: &WorkerPool,
    window: RecoveryWindow,
) -> Result<RecoveryOutcome, String> {
    let Some(admission) = before_recovery_deadline(
        window.deadline,
        recovery_admission(admin_store, pool, directory, candidate),
    )
    .await
    else {
        return Ok(RecoveryOutcome::Deferred);
    };
    let Some(mut admission) = admission? else {
        return Ok(RecoveryOutcome::Deferred);
    };
    let local_only = matches!(admission, RecoveryAdmission::Local);
    let mut started = false;
    let result = admission
        .run_until(
            async {
                started = true;
                window.remaining()?;
                let policy = if local_only {
                    // No SSH process is needed to reconcile already-retired
                    // delivery, including the local capability query below.
                    RecoveryClientPolicy::Local
                } else {
                    // Inspect in the daemon's owned process before spawning
                    // the CLI. Admission consumes this same original window.
                    let inspection = window
                        .remaining()?
                        .min(window.scale.duration(RECOVERY_PREFLIGHT_TIMEOUT));
                    let can_disable_background =
                        ssh_can_disable_background(Path::new("ssh"), inspection)
                            .await
                            .map_err(|error| {
                                format!("recovery SSH capability probe failed: {error:#}")
                            })?;
                    window.remaining()?;
                    RecoveryClientPolicy::Network {
                        can_disable_background,
                    }
                };
                recover_in_with_policy(
                    rch,
                    socket,
                    directory,
                    &candidate.wrapper_id,
                    Some(candidate),
                    policy,
                    window,
                )
                .await
            },
            window.deadline,
        )
        .await;
    match result {
        None if started && Instant::now() >= window.deadline => {
            Err("automatic lease recovery exceeded its total deadline".into())
        }
        None => Ok(RecoveryOutcome::Deferred),
        Some(result) => result,
    }
}

async fn recovery_admission(
    admin_store: &Mutex<AdminDisableStore>,
    pool: &WorkerPool,
    lease_dir: &Path,
    candidate: &RecoveryCandidate,
) -> Result<Option<RecoveryAdmission>, String> {
    let before = read_lease(lease_dir, &candidate.wrapper_id)?;
    check_candidate(&before, &candidate.wrapper_id, Some(candidate))?;
    if local_terminal_settlement_candidate(&before) {
        return Ok(Some(RecoveryAdmission::Local));
    }
    let Some(admin) = admin_store
        .lock()
        .await
        .automatic_network_permit(&candidate.worker_id)
    else {
        return Ok(None);
    };
    let network = if let Some(recipe) = &before.recovery {
        let endpoint: WorkerConfig = serde_json::from_value(recipe["worker"].clone())
            .map_err(|error| format!("recovery has no valid admitted worker endpoint: {error}"))?;
        if endpoint.id.as_str() != candidate.worker_id {
            return Err("recovery worker endpoint contradicts its admitted worker ID".into());
        }
        let Some(network) = pool.owned_recovery_admission(&endpoint).await else {
            return Ok(None);
        };
        Some(Box::new(network))
    } else {
        None
    };
    if !admin.is_current() {
        return Ok(None);
    }
    Ok(Some(RecoveryAdmission::Network { admin, network }))
}

fn check_candidate(
    before: &DurableJobLease,
    wrapper_id: &str,
    candidate: Option<&RecoveryCandidate>,
) -> Result<(), String> {
    if let Some(candidate) = candidate
        && (candidate.wrapper_id != wrapper_id
            || before.identity.remote_build_id != Some(candidate.build_id)
            || before.worker_id.as_deref() != Some(candidate.worker_id.as_str()))
    {
        return Err("recovery admission changed after scanning; client was not started".into());
    }
    Ok(())
}

#[cfg(test)]
async fn recover_in(
    rch: &Path,
    socket: &Path,
    lease_dir: &Path,
    wrapper_id: &str,
    candidate: Option<&RecoveryCandidate>,
) -> Result<(), String> {
    recover_in_with_policy(
        rch,
        socket,
        lease_dir,
        wrapper_id,
        candidate,
        RecoveryClientPolicy::Unmanaged,
        RecoveryWindow::new(rch_common::timing::configured())?,
    )
    .await
    .map(|_| ())
}

async fn recover_in_with_policy(
    rch: &Path,
    socket: &Path,
    lease_dir: &Path,
    wrapper_id: &str,
    candidate: Option<&RecoveryCandidate>,
    policy: RecoveryClientPolicy,
    window: RecoveryWindow,
) -> Result<RecoveryOutcome, String> {
    window.remaining()?;
    let before = read_lease(lease_dir, wrapper_id)?;
    check_candidate(&before, wrapper_id, candidate)?;
    if matches!(policy, RecoveryClientPolicy::Local)
        && !local_terminal_settlement_candidate(&before)
    {
        return Err(
            "local recovery obligations changed before launch; client was not started".into(),
        );
    }
    let automatic_ssh = match policy {
        #[cfg(test)]
        RecoveryClientPolicy::Unmanaged => None,
        RecoveryClientPolicy::Network {
            can_disable_background,
        } => Some(can_disable_background),
        RecoveryClientPolicy::Local => Some(false),
    };
    let mut command = tokio::process::Command::new(rch);
    command
        .args(["jobs", "recover", wrapper_id, "--timeout-secs"])
        .arg(window.child_timeout_secs()?.to_string())
        .env("RCH_SOCKET_PATH", socket)
        .env(TIMING_SCALE_ENV, window.scale.env_value())
        .stdin(if automatic_ssh.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(can_disable_background) = automatic_ssh {
        command
            .arg("--daemon-managed")
            .arg(can_disable_background.to_string());
    }
    if matches!(policy, RecoveryClientPolicy::Local) {
        command.arg("--daemon-local-only");
    }
    // Journal validation and command preparation can stall synchronously.
    // No expired window may create a recovery client or fresh SSH work.
    window.remaining()?;
    let child = OwnedProcessGroup::spawn(&mut command)
        .map_err(|error| format!("cannot run {}: {error}", rch.display()))?;
    let (status, stderr) = collect_recovery_child(child, window.deadline).await?;
    window.remaining()?;
    if automatic_ssh.is_some() && status.code() == Some(AUTOMATIC_RECOVERY_PENDING_EXIT_CODE) {
        // This status never confirms completion, releases a reservation, or
        // retires a source fence. Only the exact journal check below can do so.
        return Ok(RecoveryOutcome::SettlementPending);
    }
    if automatic_ssh.is_some() && status.code() == Some(AUTOMATIC_RECOVERY_DEFERRED_EXIT_CODE) {
        // Another handle owns the journal gate. Do not turn momentary local
        // contention into ten minutes of failure backoff, or infer anything
        // about the worker from an attempt that could not claim the journal.
        debug!(
            wrapper_id,
            "Job journal is busy; deferring automatic recovery until the next scan"
        );
        return Ok(RecoveryOutcome::Deferred);
    }
    if status.success() {
        let after = read_lease(lease_dir, wrapper_id)?;
        return confirm_recovery_before(&before, &after, window)
            .map(|()| RecoveryOutcome::Recovered);
    }
    Err(format!("{status}: {}", diagnostic_tail(&stderr)))
}

fn confirm_recovery_before(
    before: &DurableJobLease,
    after: &DurableJobLease,
    window: RecoveryWindow,
) -> Result<(), String> {
    window.remaining()?;
    let verified = verify_recovery_completion(before, after);
    window.remaining()?;
    verified
}

fn diagnostic_tail(bytes: &[u8]) -> String {
    // A byte-bounded tail may begin inside a UTF-8 codepoint. Lossy decoding
    // keeps diagnostics printable without interpreting bytes as authority.
    String::from_utf8_lossy(bytes)
        .trim()
        .chars()
        .rev()
        .take(400)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

async fn drain_recovery_stderr(
    reader: &mut (impl AsyncRead + Unpin),
    tail: &mut Vec<u8>,
) -> std::io::Result<()> {
    let mut chunk = [0u8; 4096];
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            return Ok(());
        }
        let retained = RECOVER_STDERR_TAIL_BYTES - count;
        if tail.len() > retained {
            tail.drain(..tail.len() - retained);
        }
        tail.extend_from_slice(&chunk[..count]);
        // Continue draining after the cap: stopping here would block the child
        // on a full pipe and turn noisy but healthy recovery into a timeout.
    }
}

/// One deadline covers both exit and stderr EOF. A descendant can retain the
/// pipe after its parent exits; neither a completed wait nor full diagnostics
/// alone establishes recovery completion. No reader task is detached.
async fn collect_recovery_child(
    mut child: OwnedProcessGroup,
    deadline: Instant,
) -> Result<(ExitStatus, Vec<u8>), String> {
    let stderr = child
        .take_stderr()
        .ok_or_else(|| "recovery child has no diagnostic pipe".to_owned())?;
    collect_recovery_child_stream(child, stderr, deadline).await
}

async fn collect_recovery_child_stream(
    mut child: OwnedProcessGroup,
    mut stderr: impl AsyncRead + Unpin,
    deadline: Instant,
) -> Result<(ExitStatus, Vec<u8>), String> {
    // Child::wait closes its stdin on some platforms. Keep the parent lifetime
    // pipe independently owned until collection ends or admission is revoked.
    let _parent_lifetime = child.take_stdin();
    let mut tail = Vec::with_capacity(RECOVER_STDERR_TAIL_BYTES);
    let completed = before_recovery_deadline(deadline, async {
        tokio::try_join!(child.wait(), drain_recovery_stderr(&mut stderr, &mut tail))
    })
    .await;
    let failure = match completed {
        Some(Ok((status, ()))) => return Ok((status, tail)),
        Some(Err(error)) => format!("cannot collect recovery child: {error}"),
        None => "recovery timed out waiting for child exit and diagnostic EOF".to_owned(),
    };
    // The owned group covers cancellation of this entire future, including
    // SSH and ProxyCommand descendants. On timeout/error also reap its leader.
    // Worker processes are governed by durable source ownership, not by this
    // local child's PID, and no remote completion is inferred from killing it.
    let _ = child.start_kill();
    let cleanup = match tokio::time::timeout(RECOVER_REAP_TIMEOUT, child.wait()).await {
        Ok(Ok(_)) => String::new(),
        Ok(Err(error)) => format!("; child reap failed: {error}"),
        Err(_) => "; child reap remains unconfirmed".to_owned(),
    };
    Err(format!("{failure}{cleanup}: {}", diagnostic_tail(&tail)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::WorkerId;
    use rch_common::job_identity::JobIdentity;

    fn test_recovery_window() -> RecoveryWindow {
        RecoveryWindow::new(TimingScale::default()).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_scan_runs_immediately_and_skips_missed_ticks() {
        let started = Instant::now();
        let mut ticker = recovery_scan_interval();
        assert_eq!(ticker.tick().await, started);
        assert_eq!(Instant::now(), started, "startup must not delay recovery");
        assert_eq!(ticker.tick().await, started + Duration::from_secs(30));

        // A stalled scan must not replay a burst of missed admission budgets.
        tokio::time::advance(Duration::from_secs(95)).await;
        assert_eq!(ticker.tick().await, started + Duration::from_secs(60));
        assert_eq!(ticker.tick().await, started + Duration::from_secs(150));
    }

    /// A fake `rch` for recovery: a hard link to one shim written once per
    /// process, whose behavior is the data file `body` beside the link.
    /// Writing a fresh executable and exec'ing it at once fails with ETXTBSY
    /// when a concurrent test forks while the write fd is open (the child holds
    /// a copy until it execs); see `launchd_singleton_tests` in main.rs.
    #[cfg(unix)]
    fn fake_rch(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        static SHIM: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        let shim = SHIM.get_or_init(|| {
            let shim = tempfile::tempdir().unwrap().keep().join("rch-shim");
            std::fs::write(
                &shim,
                "#!/bin/sh\nexec /bin/sh \"$(dirname \"$0\")/body\" \"$@\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
            shim
        });
        std::fs::write(dir.join("body"), body).unwrap();
        let child = dir.join("rch");
        if !child.exists() {
            std::fs::hard_link(shim, &child).unwrap();
        }
        child
    }

    fn recoverable_lease_ids(
        directory: &Path,
        now: u64,
        alive: impl Fn(u32) -> bool,
    ) -> Vec<String> {
        recoverable_candidates(directory, now, |lease| {
            if lease.wrapper_pid == 0 {
                // The legacy test probe cannot establish ownership when no
                // PID was recorded. Model the production tri-state result.
                OwnerPresence::Unknown
            } else if alive(lease.wrapper_pid) {
                OwnerPresence::Live
            } else {
                OwnerPresence::Absent
            }
        })
        .into_iter()
        .map(|candidate| candidate.wrapper_id)
        .collect()
    }

    fn candidate(id: &str, worker: &str) -> RecoveryCandidate {
        RecoveryCandidate {
            wrapper_id: id.to_owned(),
            build_id: 7,
            worker_id: worker.to_owned(),
            heartbeat_unix_ms: 0,
        }
    }

    fn owned_recovery_fixture(
        directory: &Path,
        endpoint: &WorkerConfig,
    ) -> (DurableJobLease, RecoveryCandidate) {
        let mut owned = lease(
            1,
            4242,
            serde_json::json!({
                "worker": endpoint,
                "source_roots": ["/owned/source"],
                "retired": false,
            }),
        );
        owned.worker_id = Some(endpoint.id.to_string());
        std::fs::write(
            directory.join(format!("{}.json", owned.identity.local_wrapper_id)),
            serde_json::to_vec(&owned).unwrap(),
        )
        .unwrap();
        let candidate = candidate(&owned.identity.local_wrapper_id, endpoint.id.as_str());
        (owned, candidate)
    }

    fn recovery_worker(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "historical-owned.invalid".into(),
            user: "builder".into(),
            identity_file: "/owned/key".into(),
            total_slots: 8,
            ..Default::default()
        }
    }

    fn operator_disable(worker_id: &str) -> rch_common::bypass_record::AdminDisableRecord {
        rch_common::bypass_record::AdminDisableRecord {
            worker_id: worker_id.to_owned(),
            reason: Some("intentional maintenance".into()),
            disabled_unix_ms: 1,
        }
    }

    fn retired_recovery_fixture(
        directory: &Path,
        endpoint: &WorkerConfig,
    ) -> (DurableJobLease, RecoveryCandidate) {
        let (mut owned, candidate) = owned_recovery_fixture(directory, endpoint);
        owned.recovery = Some(serde_json::json!({
            "version": 2,
            "wrapper_id": owned.identity.local_wrapper_id,
            "build_id": candidate.build_id,
            "worker": endpoint,
            "prepared": true,
            "execution_started": true,
            "exit_code": 0,
            "source_roots": ["/owned/source"],
            "sources_released": true,
            "retired": true,
            "returned": 0
        }));
        std::fs::write(
            directory.join(format!("{}.json", candidate.wrapper_id)),
            serde_json::to_vec(&owned).unwrap(),
        )
        .unwrap();
        (owned, candidate)
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_window_scales_control_budget_and_preserves_fixed_exit_slack() {
        for (scale, client_seconds, total_seconds) in
            [(1.0, 300, 330), (2.5, 750, 780), (10.0, 3000, 3030)]
        {
            let now = Instant::now();
            let window = RecoveryWindow::new(TimingScale::try_from(scale).unwrap()).unwrap();
            assert_eq!(window.deadline - now, Duration::from_secs(total_seconds));
            assert_eq!(window.child_timeout_secs().unwrap(), client_seconds);
            assert!(window.remaining().unwrap() <= MAX_CONTROL_TIMEOUT);
            assert_eq!(RECOVER_REAP_TIMEOUT, Duration::from_secs(5));
        }

        let window = RecoveryWindow {
            scale: TimingScale::try_from(2.5).unwrap(),
            deadline: Instant::now() + Duration::from_millis(1250),
        };
        assert_eq!(window.child_timeout_secs().unwrap(), 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(window.child_timeout_secs().unwrap(), 1);
        tokio::time::advance(Duration::from_millis(250)).await;
        assert!(window.remaining().is_err());
        assert!(window.child_timeout_secs().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn lease_readiness_scan_expires_without_consuming_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("queued-readiness");
        let (owned, candidate) = owned_recovery_fixture(directory.path(), &endpoint);
        let store = Mutex::new(AdminDisableStore::with_path(directory.path().join("admin")));
        let pool = WorkerPool::new();
        pool.add_worker(endpoint.clone()).await;
        let pending = VecDeque::from([candidate.clone()]);
        let blocked = store.lock().await;
        let mut scan = Box::pin(eligible_recoveries(
            &pending,
            &store,
            &pool,
            directory.path(),
        ));
        std::future::poll_fn(|cx| {
            assert!(Future::poll(scan.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        tokio::time::advance(rch_common::timing::scale_duration(
            RECOVERY_PREFLIGHT_TIMEOUT,
        ))
        .await;
        drop(blocked);
        assert!(scan.await.is_empty());
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.front().unwrap().wrapper_id, candidate.wrapper_id);
        assert_eq!(
            read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
            owned
        );
        assert!(
            eligible_recoveries(&pending, &store, &pool, directory.path())
                .await
                .contains(&candidate.wrapper_id),
            "a fresh scan can admit the same still-owned candidate"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lease_readiness_defers_only_the_contended_worker_and_preserves_singleflight() {
        let directory = tempfile::tempdir().unwrap();
        let slow_endpoint = recovery_worker("queued-readiness-worker");
        let healthy_endpoint = recovery_worker("ready-readiness-worker");
        let retired_endpoint = recovery_worker("retired-readiness-worker");
        let (slow_lease, slow) = owned_recovery_fixture(directory.path(), &slow_endpoint);
        let (healthy_lease, healthy) = owned_recovery_fixture(directory.path(), &healthy_endpoint);
        let (retired_lease, retired) =
            retired_recovery_fixture(directory.path(), &retired_endpoint);
        let store = Mutex::new(AdminDisableStore::with_path(directory.path().join("admin")));
        let pool = WorkerPool::new();
        for endpoint in [&slow_endpoint, &healthy_endpoint, &retired_endpoint] {
            pool.add_worker(endpoint.clone()).await;
            pool.get(&endpoint.id)
                .await
                .unwrap()
                .restore_slots(2)
                .unwrap();
        }
        let slow_worker = pool.get(&slow_endpoint.id).await.unwrap();
        let held_config = slow_worker.config.write().await;
        let mut queue = RecoveryQueue::default();
        queue.refresh(vec![slow.clone(), healthy.clone(), retired.clone()]);
        queue
            .backoff
            .record_failure(&slow.wrapper_id, Instant::now());
        let original_backoff = queue.backoff.failures[&slow.wrapper_id];
        let ready_peers = HashSet::from([healthy.wrapper_id.clone(), retired.wrapper_id.clone()]);

        for _ in 0..3 {
            let started = Instant::now();
            assert_eq!(
                eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await,
                ready_peers,
                "a queued oldest worker must not hide independent recovery work"
            );
            assert_eq!(
                Instant::now(),
                started,
                "readiness must not wait for a worker lock"
            );
            assert_eq!(queue.starts_remaining, MAX_RECOVERIES_PER_CYCLE);
            assert!(queue.running.is_empty());
            assert_eq!(queue.backoff.failures[&slow.wrapper_id], original_backoff);
        }

        // Cancellation between observations drops the pending lock request;
        // the pool must remain writable even while this worker stays blocked.
        let mut scan = Box::pin(eligible_recoveries(
            &queue.pending,
            &store,
            &pool,
            directory.path(),
        ));
        for _ in 0..2 {
            std::future::poll_fn(|cx| {
                assert!(Future::poll(scan.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        drop(scan);
        assert!(store.try_lock().is_ok());
        tokio::time::timeout(
            Duration::from_secs(1),
            pool.add_worker(recovery_worker("after-readiness-cancellation")),
        )
        .await
        .expect("cancelled readiness must not retain the pool read guard");

        // Scanning grants no transport lane. The real admission owns it only
        // while run_until is polled, and dropping that operation returns it.
        let mut admission = recovery_admission(&store, &pool, directory.path(), &healthy)
            .await
            .unwrap()
            .unwrap();
        let (entered, observed) = tokio::sync::oneshot::channel();
        let mut running = Box::pin(admission.run_until(
            async {
                entered.send(()).unwrap();
                std::future::pending::<()>().await;
            },
            test_recovery_window().deadline,
        ));
        std::future::poll_fn(|cx| {
            assert!(Future::poll(running.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        observed.await.unwrap();
        assert_eq!(
            eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await,
            HashSet::from([retired.wrapper_id.clone()]),
            "an in-flight healthy worker must retain its singleflight lane"
        );
        let mut local = recovery_admission(&store, &pool, directory.path(), &retired)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(local, RecoveryAdmission::Local));
        assert_eq!(
            local
                .run_until(
                    async { read_lease(directory.path(), &retired.wrapper_id) },
                    test_recovery_window().deadline,
                )
                .await
                .unwrap()
                .unwrap(),
            retired_lease
        );
        drop(running);
        assert_eq!(
            eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await,
            ready_peers
        );
        drop(held_config);
        assert_eq!(
            eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await,
            HashSet::from([
                slow.wrapper_id.clone(),
                healthy.wrapper_id.clone(),
                retired.wrapper_id.clone(),
            ])
        );
        assert_eq!(queue.backoff.failures[&slow.wrapper_id], original_backoff);
        assert!(!queue.backoff.ready(&slow.wrapper_id, Instant::now()));
        for lease in [slow_lease, healthy_lease, retired_lease] {
            assert_eq!(
                read_lease(directory.path(), &lease.identity.local_wrapper_id).unwrap(),
                lease
            );
            assert_eq!(
                pool.get(&WorkerId::new(lease.worker_id.as_ref().unwrap()))
                    .await
                    .unwrap()
                    .used_slots(),
                2,
                "readiness and cancellation supply no reservation-release authority"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lease_readiness_busy_admin_does_not_block_local_handoff() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("admin-queued-readiness");
        let (owned, network) = owned_recovery_fixture(directory.path(), &endpoint);
        let (settled, local) = retired_recovery_fixture(directory.path(), &endpoint);
        let store = Mutex::new(AdminDisableStore::with_path(directory.path().join("admin")));
        let pool = WorkerPool::new();
        pool.add_worker(endpoint.clone()).await;
        pool.get(&endpoint.id)
            .await
            .unwrap()
            .restore_slots(3)
            .unwrap();
        let pending = VecDeque::from([network.clone(), local.clone()]);
        let blocked = store.lock().await;
        let started = Instant::now();
        assert_eq!(
            eligible_recoveries(&pending, &store, &pool, directory.path()).await,
            HashSet::from([local.wrapper_id.clone()])
        );
        assert_eq!(Instant::now(), started);
        assert!(blocked.all().is_empty());
        assert_eq!(
            read_lease(directory.path(), &network.wrapper_id).unwrap(),
            owned
        );
        assert_eq!(
            read_lease(directory.path(), &local.wrapper_id).unwrap(),
            settled
        );
        assert_eq!(pool.get(&endpoint.id).await.unwrap().used_slots(), 3);
        drop(blocked);
        assert_eq!(
            eligible_recoveries(&pending, &store, &pool, directory.path()).await,
            HashSet::from([network.wrapper_id, local.wrapper_id])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lease_readiness_keeps_one_deadline_across_candidates() {
        for lateness in [Duration::ZERO, Duration::from_millis(1)] {
            let directory = tempfile::tempdir().unwrap();
            let endpoint = recovery_worker("readiness-deadline");
            let (first_lease, first) = retired_recovery_fixture(directory.path(), &endpoint);
            let (second_lease, second) = retired_recovery_fixture(directory.path(), &endpoint);
            let pending = VecDeque::from([first.clone(), second.clone()]);
            let store = Mutex::new(AdminDisableStore::with_path(directory.path().join("admin")));
            let pool = WorkerPool::new();
            let mut scan = Box::pin(eligible_recoveries(
                &pending,
                &store,
                &pool,
                directory.path(),
            ));
            // Finish the first observation and stop at the second candidate's
            // cooperative yield. It must not receive a fresh full allowance.
            for _ in 0..2 {
                std::future::poll_fn(|cx| {
                    assert!(Future::poll(scan.as_mut(), cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
            }
            tokio::time::advance(
                rch_common::timing::scale_duration(RECOVERY_PREFLIGHT_TIMEOUT) + lateness,
            )
            .await;
            assert_eq!(scan.await, HashSet::from([first.wrapper_id.clone()]));
            for lease in [first_lease, second_lease] {
                assert_eq!(
                    read_lease(directory.path(), &lease.identity.local_wrapper_id).unwrap(),
                    lease
                );
            }
            assert_eq!(
                eligible_recoveries(&pending, &store, &pool, directory.path()).await,
                HashSet::from([first.wrapper_id, second.wrapper_id])
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lease_readiness_yields_through_a_large_deferred_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let offline_endpoint = recovery_worker("deferred-prefix-worker");
        let healthy_endpoint = recovery_worker("after-deferred-prefix-worker");
        let store = Mutex::new(AdminDisableStore::with_path(directory.path().join("admin")));
        let pool = WorkerPool::new();
        pool.add_worker(offline_endpoint.clone()).await;
        pool.add_worker(healthy_endpoint.clone()).await;
        let offline = pool.get(&offline_endpoint.id).await.unwrap();
        offline.restore_slots(2).unwrap();
        offline
            .record_transport_result(
                false,
                Duration::from_secs(30),
                &rch_common::CircuitBreakerConfig {
                    failure_threshold: 1,
                    ..Default::default()
                },
            )
            .await;
        // These completed local lock acquisitions exceed one Tokio task's
        // cooperative budget. Exhaustion must not masquerade as a busy peer.
        let mut pending: VecDeque<_> = (0..160)
            .map(|_| owned_recovery_fixture(directory.path(), &offline_endpoint).1)
            .collect();
        let (healthy_lease, healthy) = owned_recovery_fixture(directory.path(), &healthy_endpoint);
        pending.push_back(healthy.clone());
        for _ in 0..2 {
            let started = Instant::now();
            assert_eq!(
                eligible_recoveries(&pending, &store, &pool, directory.path()).await,
                HashSet::from([healthy.wrapper_id.clone()])
            );
            assert_eq!(Instant::now(), started);
            assert_eq!(offline.used_slots(), 2);
            assert!(offline.transport_is_down().await);
            assert_eq!(
                read_lease(directory.path(), &healthy.wrapper_id).unwrap(),
                healthy_lease
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lease_readiness_invalid_journal_keeps_existing_error_backoff() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("invalid-readiness-journal");
        let (mut owned, candidate) = owned_recovery_fixture(directory.path(), &endpoint);
        owned.schema_version = 0;
        let bytes = serde_json::to_vec(&owned).unwrap();
        let path = directory
            .path()
            .join(format!("{}.json", candidate.wrapper_id));
        std::fs::write(&path, &bytes).unwrap();
        let store = Arc::new(Mutex::new(AdminDisableStore::with_path(
            directory.path().join("admin"),
        )));
        let pool = WorkerPool::new();
        pool.add_worker(endpoint.clone()).await;
        pool.get(&endpoint.id)
            .await
            .unwrap()
            .restore_slots(2)
            .unwrap();
        let mut queue = RecoveryQueue::default();
        queue.refresh(vec![candidate.clone()]);
        let eligible = eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await;
        assert_eq!(eligible, HashSet::from([candidate.wrapper_id.clone()]));
        queue.start_ready_if(
            Instant::now(),
            |candidate| eligible.contains(&candidate.wrapper_id),
            |candidate| {
                let store = store.clone();
                let pool = pool.clone();
                let directory = directory.path().to_owned();
                async move {
                    recover_before(
                        Path::new("/must-not-spawn-a-recovery-client"),
                        &directory.join("unused.sock"),
                        &directory,
                        &candidate,
                        &store,
                        &pool,
                        test_recovery_window(),
                    )
                    .await
                }
            },
        );
        let (completed, outcome) = queue.next_completed().await.unwrap();
        assert_eq!(completed.wrapper_id, candidate.wrapper_id);
        assert_eq!(
            outcome.unwrap_err(),
            "recovery journal schema or filename identity is invalid"
        );
        assert_eq!(queue.backoff.failures[&candidate.wrapper_id].0, 1);
        assert!(!queue.backoff.ready(&candidate.wrapper_id, Instant::now()));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(pool.get(&endpoint.id).await.unwrap().used_slots(), 2);
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn lease_admission_expiry_defers_without_spawning_and_allows_fresh_retry() {
        for lateness in [Duration::ZERO, Duration::from_millis(1)] {
            let directory = tempfile::tempdir().unwrap();
            let endpoint = recovery_worker("queued-lease");
            let (owned, candidate) = owned_recovery_fixture(directory.path(), &endpoint);
            let store = Mutex::new(AdminDisableStore::with_path(directory.path().join("admin")));
            let pool = WorkerPool::new();
            pool.add_worker(endpoint.clone()).await;
            let child = fake_rch(
                directory.path(),
                "printf 'started\\n' >\"$(dirname \"$0\")/started\"\n",
            );
            let socket = directory.path().join("unused.sock");
            let window = RecoveryWindow {
                scale: TimingScale::default(),
                deadline: Instant::now() + Duration::from_secs(2),
            };
            let blocked = store.lock().await;
            let mut recovery = Box::pin(recover_before(
                &child,
                &socket,
                directory.path(),
                &candidate,
                &store,
                &pool,
                window,
            ));
            std::future::poll_fn(|cx| {
                assert!(Future::poll(recovery.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            tokio::time::advance(Duration::from_secs(2) + lateness).await;
            drop(blocked);
            assert_eq!(recovery.await, Ok(RecoveryOutcome::Deferred));
            assert!(!directory.path().join("started").exists());
            assert_eq!(
                read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
                owned
            );
            let mut fresh = recovery_admission(&store, &pool, directory.path(), &candidate)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                fresh
                    .run_until(async { 7 }, test_recovery_window().deadline)
                    .await,
                Some(7)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lease_recovery_never_resumes_ready_work_at_or_after_expiry() {
        use std::sync::atomic::{AtomicBool, Ordering};

        for local_only in [true, false] {
            for lateness in [Duration::ZERO, Duration::from_millis(1)] {
                let directory = tempfile::tempdir().unwrap();
                let mut store = AdminDisableStore::with_path(directory.path().join("admin"));
                let mut admission = if local_only {
                    RecoveryAdmission::Local
                } else {
                    RecoveryAdmission::Network {
                        admin: store.automatic_network_permit("owned-worker").unwrap(),
                        network: None,
                    }
                };
                let resumed = AtomicBool::new(false);
                let (resume, ready) = tokio::sync::oneshot::channel();
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut operation = Box::pin(admission.run_until(
                    async {
                        ready.await.unwrap();
                        resumed.store(true, Ordering::SeqCst);
                        7
                    },
                    deadline,
                ));
                std::future::poll_fn(|cx| {
                    assert!(Future::poll(operation.as_mut(), cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                tokio::time::advance(Duration::from_secs(2) + lateness).await;
                resume.send(()).unwrap();
                assert!(operation.await.is_none());
                assert!(!resumed.load(Ordering::SeqCst));
                assert_eq!(
                    admission
                        .run_until(async { 7 }, test_recovery_window().deadline)
                        .await,
                    Some(7)
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expired_lease_window_never_spawns_the_recovery_client() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("expired-client");
        let (owned, candidate) = retired_recovery_fixture(directory.path(), &endpoint);
        let child = fake_rch(
            directory.path(),
            "printf 'started\\n' >\"$(dirname \"$0\")/started\"\n",
        );
        let window = RecoveryWindow {
            scale: TimingScale::try_from(10.0).unwrap(),
            deadline: Instant::now(),
        };
        let error = recover_in_with_policy(
            &child,
            &directory.path().join("unused.sock"),
            directory.path(),
            &candidate.wrapper_id,
            Some(&candidate),
            RecoveryClientPolicy::Local,
            window,
        )
        .await
        .unwrap_err();
        assert!(error.contains("deadline"), "{error}");
        assert!(!directory.path().join("started").exists());
        assert_eq!(
            read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
            owned
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lease_recovery_client_receives_the_effective_policy_and_scaled_limit() {
        for (scale, timeout) in [(1.0, "300"), (2.5, "750"), (10.0, "3000")] {
            let directory = tempfile::tempdir().unwrap();
            let endpoint = recovery_worker("policy-client");
            let (owned, candidate) = retired_recovery_fixture(directory.path(), &endpoint);
            let completed = completed_lease(&owned, 0, 0);
            std::fs::write(
                directory.path().join("settled"),
                serde_json::to_vec(&completed).unwrap(),
            )
            .unwrap();
            let child = fake_rch(
                directory.path(),
                "printf '%s\\n' \"$RCH_TIMING_SCALE\" >\"$(dirname \"$0\")/scale\"\n\
                 printf '%s\\n' \"$@\" >\"$(dirname \"$0\")/args\"\n\
                 cp \"$(dirname \"$0\")/settled\" \"$(dirname \"$0\")/$3.json\"\n",
            );
            let scale = TimingScale::try_from(scale).unwrap();
            tokio::time::timeout(
                Duration::from_secs(30),
                recover_in_with_policy(
                    &child,
                    &directory.path().join("unused.sock"),
                    directory.path(),
                    &candidate.wrapper_id,
                    Some(&candidate),
                    RecoveryClientPolicy::Local,
                    RecoveryWindow::new(scale).unwrap(),
                ),
            )
            .await
            .expect("the local fixture must not wait for the remote allowance")
            .unwrap();
            assert_eq!(
                std::fs::read_to_string(directory.path().join("scale"))
                    .unwrap()
                    .trim(),
                scale.env_value()
            );
            let args = std::fs::read_to_string(directory.path().join("args")).unwrap();
            let args: Vec<_> = args.lines().collect();
            assert_eq!(
                args[3..],
                [
                    "--timeout-secs",
                    timeout,
                    "--daemon-managed",
                    "false",
                    "--daemon-local-only"
                ]
            );
            assert_eq!(
                read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
                completed
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lease_completion_requires_both_timely_and_exact_journal_evidence() {
        let before = handoff_lease(1, 42, 0);
        let complete = completed_lease(&before, 0, 0);
        for (delay, accepted) in [
            (Duration::from_millis(1999), true),
            (Duration::from_secs(2), false),
            (Duration::from_millis(2001), false),
        ] {
            let window = RecoveryWindow {
                scale: TimingScale::default(),
                deadline: Instant::now() + Duration::from_secs(2),
            };
            tokio::time::advance(delay).await;
            assert_eq!(
                confirm_recovery_before(&before, &complete, window).is_ok(),
                accepted
            );
        }
        let mut wrong_identity = complete.clone();
        wrong_identity.command_fingerprint.push_str("-different");
        assert!(confirm_recovery_before(&before, &wrong_identity, test_recovery_window()).is_err());
        assert!(
            confirm_recovery_before(&before, &before, test_recovery_window()).is_err(),
            "an unchanged incomplete journal is not confirmation"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_recovery_launch_keeps_strict_mode_and_rejects_changed_journal() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("disabled-worker");
        let (owned, candidate) = retired_recovery_fixture(directory.path(), &endpoint);
        let store = Arc::new(Mutex::new(AdminDisableStore::with_path(
            directory.path().join("admin"),
        )));
        store
            .lock()
            .await
            .upsert(operator_disable(endpoint.id.as_str()))
            .unwrap();
        let pool = WorkerPool::new().with_admin_disable_store(store.clone());
        pool.add_worker(endpoint.clone()).await;
        let mut admission = recovery_admission(&store, &pool, directory.path(), &candidate)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(admission, RecoveryAdmission::Local));
        let child = fake_rch(
            directory.path(),
            "printf '%s\\n' \"$@\" >\"$(dirname \"$0\")/args\"\n\
             cp \"$(dirname \"$0\")/settled\" \"$(dirname \"$0\")/$3.json\"\n",
        );
        let journal = directory
            .path()
            .join(format!("{}.json", candidate.wrapper_id));
        let socket = directory.path().join("daemon.sock");
        for changed in [
            "unreleased",
            "unretired",
            "pending-cancellation",
            "legacy-failure",
        ] {
            let mut pending = owned.clone();
            let recipe = pending.recovery.as_mut().unwrap();
            match changed {
                "unreleased" => recipe["sources_released"] = serde_json::json!(false),
                "unretired" => recipe["retired"] = serde_json::json!(false),
                "pending-cancellation" => {
                    recipe["source_cancellation_settled"] = serde_json::json!(false);
                }
                "legacy-failure" => {
                    recipe["exit_code"] = serde_json::json!(137);
                    recipe["returned"] = serde_json::json!(101);
                }
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&pending).unwrap();
            std::fs::write(&journal, &bytes).unwrap();
            let window = test_recovery_window();
            let error = admission
                .run_until(
                    recover_in_with_policy(
                        &child,
                        &socket,
                        directory.path(),
                        &candidate.wrapper_id,
                        Some(&candidate),
                        RecoveryClientPolicy::Local,
                        window,
                    ),
                    window.deadline,
                )
                .await
                .unwrap()
                .unwrap_err();
            assert!(
                error.contains("local recovery obligations changed"),
                "{error}"
            );
            assert!(!directory.path().join("args").exists(), "{changed}");
            assert_eq!(std::fs::read(&journal).unwrap(), bytes);
            assert!(
                recovery_admission(&store, &pool, directory.path(), &candidate)
                    .await
                    .unwrap()
                    .is_none(),
                "{changed}"
            );
        }
        std::fs::write(&journal, serde_json::to_vec(&owned).unwrap()).unwrap();
        let mut settled = owned.clone();
        settled.exit_code = Some(0);
        settled.acknowledge_terminal(2);
        settled.recovery.as_mut().unwrap()["daemon_exit_code"] = serde_json::json!(0);
        std::fs::write(
            directory.path().join("settled"),
            serde_json::to_vec(&settled).unwrap(),
        )
        .unwrap();
        let window = test_recovery_window();
        admission
            .run_until(
                recover_in_with_policy(
                    &child,
                    &socket,
                    directory.path(),
                    &candidate.wrapper_id,
                    Some(&candidate),
                    RecoveryClientPolicy::Local,
                    window,
                ),
                window.deadline,
            )
            .await
            .unwrap()
            .unwrap();
        let args = std::fs::read_to_string(directory.path().join("args")).unwrap();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            [
                "jobs",
                "recover",
                candidate.wrapper_id.as_str(),
                "--timeout-secs",
                "300",
                "--daemon-managed",
                "false",
                "--daemon-local-only",
            ]
        );
        assert_eq!(
            read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
            settled
        );
        assert!(pool.get(&endpoint.id).await.unwrap().is_disabled().await);
    }

    #[tokio::test]
    async fn local_recovery_admission_survives_worker_disable_during_settlement() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("retired-worker");
        let (_, candidate) = retired_recovery_fixture(directory.path(), &endpoint);
        let store = Arc::new(Mutex::new(AdminDisableStore::with_path(
            directory.path().join("admin"),
        )));
        let pool = WorkerPool::new().with_admin_disable_store(store.clone());
        pool.add_worker(endpoint.clone()).await;
        let mut admission = recovery_admission(&store, &pool, directory.path(), &candidate)
            .await
            .unwrap()
            .unwrap();
        let (started, entered) = tokio::sync::oneshot::channel();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        let operation = admission.run_until(
            async {
                started.send(()).unwrap();
                resumed.await.unwrap();
                7
            },
            test_recovery_window().deadline,
        );
        let disable = async {
            entered.await.unwrap();
            store
                .lock()
                .await
                .upsert(operator_disable(endpoint.id.as_str()))
                .unwrap();
            pool.get(&endpoint.id)
                .await
                .unwrap()
                .disable(Some("maintenance".into()))
                .await;
            resume.send(()).unwrap();
        };
        let (settled, ()) = tokio::join!(operation, disable);
        assert_eq!(settled, Some(7));
        assert!(pool.get(&endpoint.id).await.unwrap().is_disabled().await);
    }

    #[tokio::test]
    async fn retired_local_recovery_settles_disabled_reservations_after_restart() {
        use crate::history::BuildHistory;
        use tokio::io::AsyncWriteExt;

        for dormant in ["disabled", "outage", "removed-disabled"] {
            let directory = tempfile::tempdir().unwrap();
            let history_path = directory.path().join("history.jsonl");
            let admin_path = directory.path().join("admin.json");
            let endpoint = recovery_worker("retired-worker");
            let mut owned = lease(1, 4242, serde_json::json!({}));
            let history = BuildHistory::new(10).with_persistence(history_path.clone());
            let build = history.start_active_build_with_wrapper(
                "completed-project".into(),
                endpoint.id.to_string(),
                "cargo check".into(),
                owned.wrapper_pid,
                Some(owned.identity.local_wrapper_id.clone()),
                3,
                rch_common::BuildLocation::Remote,
            );
            let peer = history.start_active_build_with_wrapper(
                "unrelated-project".into(),
                "peer".into(),
                "cargo test".into(),
                0,
                Some(JobIdentity::new_local().local_wrapper_id),
                1,
                rch_common::BuildLocation::Remote,
            );
            owned.admit(build.id, endpoint.id.to_string(), 1);
            owned.recovery = Some(serde_json::json!({
                "version": 2,
                "wrapper_id": owned.identity.local_wrapper_id,
                "build_id": build.id,
                "worker": endpoint,
                "prepared": true,
                "execution_started": true,
                "preparation_cancelled": false,
                "exit_code": 0,
                "source_roots": ["/owned/source"],
                "sources_released": true,
                "pair": null,
                "retire_root": null,
                "retired": true,
                "returned": 0
            }));
            let journal = directory
                .path()
                .join(format!("{}.json", owned.identity.local_wrapper_id));
            std::fs::write(&journal, serde_json::to_vec(&owned).unwrap()).unwrap();
            let mut store = AdminDisableStore::with_path(&admin_path);
            if dormant != "outage" {
                store
                    .upsert(operator_disable(endpoint.id.as_str()))
                    .unwrap();
            }
            drop(history);
            drop(store);

            // Restore the actual durable reservation after the wrapper died
            // between resource retirement and local daemon release/readback.
            let store = Arc::new(Mutex::new(
                AdminDisableStore::try_load(&admin_path).unwrap(),
            ));
            let pool = WorkerPool::new().with_admin_disable_store(store.clone());
            if dormant != "removed-disabled" {
                pool.add_worker(endpoint.clone()).await;
            }
            pool.add_worker(recovery_worker("peer")).await;
            let mut context = crate::test_daemon_context(pool.clone());
            context.admin_disable_store = Some(store.clone());
            context.history = Arc::new(BuildHistory::load_from_file(&history_path, 10).unwrap());
            for active in context.history.active_builds() {
                pool.restore_recovered_slots(&WorkerId::new(&active.worker_id), active.slots)
                    .await
                    .unwrap();
            }
            if dormant == "outage" {
                pool.get(&endpoint.id)
                    .await
                    .unwrap()
                    .record_transport_result(
                        false,
                        Duration::from_secs(30),
                        &rch_common::CircuitBreakerConfig {
                            failure_threshold: 1,
                            open_cooldown_secs: 900,
                            ..Default::default()
                        },
                    )
                    .await;
            }
            let candidates =
                recoverable_candidates(directory.path(), 3_600_001, |_| OwnerPresence::Absent);
            assert_eq!(candidates.len(), 1);
            let selected = &candidates[0];
            let mut admission = recovery_admission(&store, &pool, directory.path(), selected)
                .await
                .unwrap()
                .expect(
                    "retired delivery needs local accounting even while its worker stays dormant",
                );
            let (_, remote) = owned_recovery_fixture(directory.path(), &endpoint);
            assert!(
                recovery_admission(&store, &pool, directory.path(), &remote)
                    .await
                    .unwrap()
                    .is_none()
            );

            let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
            let (shutdown, _) = tokio::sync::mpsc::channel(1);
            let release = format!(
                "POST /release-worker?worker={}&build_id={}&local_wrapper_id={}&exit_code=0\n",
                endpoint.id, build.id, owned.identity.local_wrapper_id
            );
            let (completed, response) = tokio::join!(
                admission.run_until(
                    crate::api::handle_connection(server, context.clone(), shutdown),
                    test_recovery_window().deadline,
                ),
                async {
                    client.write_all(release.as_bytes()).await.unwrap();
                    client.shutdown().await.unwrap();
                    let mut response = String::new();
                    client.read_to_string(&mut response).await.unwrap();
                    response
                }
            );
            completed
                .expect("local settlement is not revoked by dormant transport")
                .unwrap();
            assert!(response.starts_with("HTTP/1.0 200"), "{response}");
            assert!(context.history.active_build(build.id).is_none());
            assert_eq!(
                context
                    .history
                    .terminal_build(build.id, &owned.identity.local_wrapper_id)
                    .unwrap()
                    .exit_code,
                0
            );
            assert!(context.history.active_build(peer.id).is_some());
            assert_eq!(
                pool.get(&WorkerId::new("peer")).await.unwrap().used_slots(),
                1
            );
            if dormant == "removed-disabled" {
                pool.add_worker(endpoint.clone()).await;
            }
            let worker = pool.get(&endpoint.id).await.unwrap();
            assert_eq!(worker.used_slots(), 0);
            assert!(!worker.background_network_allowed().await);
            assert_eq!(worker.is_disabled().await, dormant != "outage");
            assert_eq!(
                read_lease(directory.path(), &selected.wrapper_id).unwrap(),
                owned
            );
            let restored = BuildHistory::load_from_file(&history_path, 10).unwrap();
            assert!(restored.active_build(build.id).is_none());
            assert!(restored.active_build(peer.id).is_some());
        }
    }

    fn persist_recovery_fixture(directory: &Path, lease: &DurableJobLease) {
        std::fs::write(
            directory.join(format!("{}.json", lease.identity.local_wrapper_id)),
            serde_json::to_vec(lease).unwrap(),
        )
        .unwrap();
    }

    /// Worker settlement is the injected boundary in this daemon test. The
    /// real registry/activity-lock protocol has separate worker-side tests;
    /// local absence alone never produces these receipts in production.
    fn preparation_settlement_fixture(before: &DurableJobLease) -> DurableJobLease {
        let mut settled = before.clone();
        let recipe = settled.recovery.as_mut().unwrap();
        assert_eq!(recipe["prepared"], false);
        assert_eq!(recipe["execution_started"], false);
        for field in [
            "preparation_cancelled",
            "source_cancellation_settled",
            "sources_released",
            "tree_retired",
            "pair_released",
            "retired",
        ] {
            recipe[field] = serde_json::json!(true);
        }
        recipe["returned"] = serde_json::json!(1);
        settled.exit_code = Some(1);
        settled
    }

    async fn recovery_accounting_request(
        context: &crate::DaemonContext,
        request: String,
    ) -> serde_json::Value {
        use tokio::io::AsyncWriteExt;

        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let (shutdown, _) = tokio::sync::mpsc::channel(1);
        let (served, response) = tokio::join!(
            crate::api::handle_connection(server, context.clone(), shutdown),
            async {
                client.write_all(request.as_bytes()).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = String::new();
                client.read_to_string(&mut response).await.unwrap();
                response
            }
        );
        served.unwrap();
        assert!(response.starts_with("HTTP/1.0 200"), "{response}");
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
    }

    async fn restore_recovery_fleet(
        directory: &Path,
        endpoints: &[WorkerConfig],
    ) -> crate::DaemonContext {
        let pool = WorkerPool::new();
        for endpoint in endpoints {
            pool.add_worker(endpoint.clone()).await;
        }
        let mut context = crate::test_daemon_context(pool.clone());
        context.client_lease_dir = directory.to_owned();
        context.history = Arc::new(
            crate::history::BuildHistory::load_from_file(&directory.join("history.jsonl"), 32)
                .unwrap(),
        );
        Arc::make_mut(&mut context.worker_selector).set_build_history(context.history.clone());
        for active in context.history.active_builds() {
            pool.restore_recovered_slots(&WorkerId::new(&active.worker_id), active.slots)
                .await
                .unwrap();
        }
        context
    }

    /// Supply a verified worker result, then exercise real daemon release and
    /// exact terminal readback. This adapter never runs a compiler or SSH.
    async fn settle_preparation_fixture(
        context: crate::DaemonContext,
        directory: PathBuf,
        candidate: RecoveryCandidate,
    ) -> Result<(), String> {
        let before = read_lease(&directory, &candidate.wrapper_id)?;
        check_candidate(&before, &candidate.wrapper_id, Some(&candidate))?;
        let mut settled = preparation_settlement_fixture(&before);
        persist_recovery_fixture(&directory, &settled);
        let query = format!(
            "GET /builds/{}?local_wrapper_id={}\n",
            candidate.build_id, candidate.wrapper_id
        );
        let mut receipt = recovery_accounting_request(&context, query.clone()).await;
        if receipt["status"] == "active" {
            recovery_accounting_request(
                &context,
                format!(
                    "POST /release-worker?worker={}&build_id={}&local_wrapper_id={}&exit_code=1\n",
                    candidate.worker_id, candidate.build_id, candidate.wrapper_id
                ),
            )
            .await;
            receipt = recovery_accounting_request(&context, query).await;
        }
        assert_eq!(receipt["status"], "completed");
        assert_eq!(receipt["record"]["id"], candidate.build_id);
        assert_eq!(receipt["record"]["worker_id"], candidate.worker_id);
        assert_eq!(receipt["local_wrapper_id"], candidate.wrapper_id);
        assert_eq!(receipt["record"]["exit_code"], 1);
        settled.recovery.as_mut().unwrap()["daemon_exit_code"] =
            receipt["record"]["exit_code"].clone();
        settled.acknowledge_terminal(before.heartbeat_unix_ms + 1);
        persist_recovery_fixture(&directory, &settled);
        verify_recovery_completion(&before, &read_lease(&directory, &candidate.wrapper_id)?)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(start_paused = true)]
    async fn nine_abandoned_preparations_recover_capacity_after_failures_and_restarts() {
        use rch_common::process_identity::{
            ProcessObservation, current_process_identity, observe_process,
        };

        let directory = tempfile::tempdir().unwrap();
        let now_ms = 100 * 60 * 60 * 1000;
        let endpoints: Vec<_> = [4, 2, 2, 3]
            .into_iter()
            .enumerate()
            .map(|(index, slots)| WorkerConfig {
                total_slots: slots,
                ..recovery_worker(&format!("preparation-worker-{index}"))
            })
            .collect();
        let pool = WorkerPool::new();
        for endpoint in &endpoints {
            pool.add_worker(endpoint.clone()).await;
        }
        let history = crate::history::BuildHistory::new(32)
            .with_persistence(directory.path().join("history.jsonl"));
        let mut leases = Vec::new();
        for index in 0..11 {
            // Real local process births make dead/live/reused PID distinctions
            // independent of a canned bool probe. PID 1 without a recorded
            // birth models an unverified owner and must remain protected too.
            let (pid, birth) = if index < 9 {
                let mut child = std::process::Command::new("/bin/sh")
                    .args(["-c", "read -r gate"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let pid = child.id();
                let observed = observe_process(pid);
                drop(child.stdin.take());
                child.wait().unwrap();
                let ProcessObservation::Present(birth) = observed else {
                    panic!("fixture wrapper has no kernel birth identity: {observed:?}");
                };
                assert_eq!(owner_presence(pid, Some(&birth)), OwnerPresence::Absent);
                (pid, Some(birth))
            } else if index == 9 {
                (std::process::id(), current_process_identity())
            } else {
                (1, None)
            };
            let worker_index = if index == 9 {
                0
            } else if index == 10 {
                3
            } else {
                index % 4
            };
            let endpoint = &endpoints[worker_index];
            let worker = pool.get(&endpoint.id).await.unwrap();
            assert!(worker.reserve_slots(1).await);
            let age_tenths_of_an_hour = [217, 190, 165, 140, 115, 90, 65, 40, 21, 21, 21][index];
            let heartbeat = now_ms - age_tenths_of_an_hour * 360_000;
            let mut owned = lease(heartbeat, pid, serde_json::Value::Null);
            owned.process_birth = birth;
            let build = history
                .try_start_active_build_with_waiter(
                    format!("preparation-project-{index}"),
                    endpoint.id.to_string(),
                    "cargo +nightly test".into(),
                    pid,
                    Some(owned.identity.local_wrapper_id.clone()),
                    1,
                    rch_common::BuildLocation::Remote,
                    None,
                    crate::disk_pressure::DiskHeadroomAdmission::default(),
                    Some(worker.endpoint_snapshot().await),
                )
                .unwrap()
                .unwrap();
            owned.admit(build.id, endpoint.id.to_string(), heartbeat);
            owned.recovery = Some(serde_json::json!({
                "version": 2, "wrapper_id": owned.identity.local_wrapper_id,
                "build_id": build.id, "worker": endpoint,
                "identity": format!("aa-{index:x}"),
                "prepared": false, "execution_started": false, "phases": [],
                "preparation_cancelled": index < 5,
                "source_cancellation_settled": false,
                "source_authority_namespace": if index % 2 == 0 { "current" } else { "legacy" },
                "source_roots": [format!("/owned/source-{index}")],
                "pair": [format!("/owned/pair-{index}"), format!("aa-{index:x}")],
                "retire_root": format!("/owned/tree-{index}"),
                "sources_released": false, "tree_retired": false, "pair_released": false,
                "retired": false, "returned": (index < 3).then_some(1)
            }));
            persist_recovery_fixture(directory.path(), &owned);
            leases.push(owned);
        }
        let scan = || {
            recoverable_candidates(directory.path(), now_ms, |lease| {
                owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
            })
        };
        let original_ids: Vec<_> = leases[..9]
            .iter()
            .map(|lease| lease.identity.local_wrapper_id.clone())
            .collect();
        assert_eq!(
            scan()
                .iter()
                .map(|job| job.wrapper_id.clone())
                .collect::<Vec<_>>(),
            original_ids
        );
        assert_eq!(
            owner_presence(leases[9].wrapper_pid, leases[9].owner_identity().as_ref()),
            OwnerPresence::Live
        );
        assert_eq!(
            owner_presence(leases[10].wrapper_pid, leases[10].owner_identity().as_ref()),
            OwnerPresence::Unknown
        );
        for endpoint in &endpoints {
            assert!(!pool.get(&endpoint.id).await.unwrap().reserve_slots(1).await);
        }

        // A zero-status client without new settlement/acknowledgement evidence
        // is a failed recovery. Scans over the same 45-minute retry window
        // must back off, keep every durable reservation, and eventually
        // inspect all nine wrappers even with the shorter polling interval.
        let mut queue = RecoveryQueue::default();
        let retry_window_end = Instant::now() + Duration::from_secs(45 * 60);
        while Instant::now() < retry_window_end {
            queue.refresh(scan());
            queue.start_ready(Instant::now(), |job| {
                let before = read_lease(directory.path(), &job.wrapper_id).unwrap();
                async move { verify_recovery_completion(&before, &before) }
            });
            assert!(queue.running.len() <= MAX_RECOVERIES_PER_CYCLE);
            assert_eq!(
                queue
                    .running
                    .values()
                    .map(|job| &job.worker_id)
                    .collect::<HashSet<_>>()
                    .len(),
                queue.running.len()
            );
            while !queue.running.is_empty() {
                let (job, outcome) = queue.next_completed().await.unwrap();
                assert!(outcome.unwrap_err().contains("cancellation unsettled"));
                assert!(!queue.backoff.ready(&job.wrapper_id, Instant::now()));
            }
            tokio::time::advance(RECOVERY_INTERVAL).await;
        }
        for original in &leases {
            assert_eq!(
                read_lease(directory.path(), &original.identity.local_wrapper_id).unwrap(),
                *original
            );
            assert!(
                history
                    .active_build(original.identity.remote_build_id.unwrap())
                    .is_some()
            );
        }
        for id in &original_ids {
            assert!(queue.backoff.failures[id].0 >= 2);
        }
        for endpoint in &endpoints {
            assert_eq!(
                pool.get(&endpoint.id).await.unwrap().used_slots(),
                endpoint.total_slots
            );
        }
        drop(queue);
        drop(history);
        drop(pool);

        // Only retry scheduling uses virtual time. Native UnixStream readiness
        // must not race Tokio's automatic jumps to an otherwise idle deadline.
        tokio::time::resume();

        let context = restore_recovery_fleet(directory.path(), &endpoints).await;
        assert_eq!(context.history.active_builds().len(), 11);
        for endpoint in &endpoints {
            assert_eq!(
                context.pool.get(&endpoint.id).await.unwrap().used_slots(),
                endpoint.total_slots
            );
        }

        // Lose a release acknowledgement after verified worker settlement.
        // A second daemon restart must retain the terminal receipt and restore
        // only active reservations; the unacknowledged journal remains eligible.
        let lost = preparation_settlement_fixture(&leases[8]);
        persist_recovery_fixture(directory.path(), &lost);
        recovery_accounting_request(
            &context,
            format!(
                "POST /release-worker?worker={}&build_id={}&local_wrapper_id={}&exit_code=1\n",
                lost.worker_id.as_ref().unwrap(),
                lost.identity.remote_build_id.unwrap(),
                lost.identity.local_wrapper_id
            ),
        )
        .await;
        assert!(verify_recovery_completion(&leases[8], &lost).is_err());
        assert!(
            !read_lease(directory.path(), &lost.identity.local_wrapper_id)
                .unwrap()
                .terminal_acknowledged
        );
        drop(context);
        let context = restore_recovery_fleet(directory.path(), &endpoints).await;
        assert_eq!(context.history.active_builds().len(), 10);
        assert_eq!(
            context
                .pool
                .get(&endpoints[0].id)
                .await
                .unwrap()
                .used_slots(),
            3
        );
        assert_eq!(scan().len(), 9);
        let lost_candidate = scan()
            .into_iter()
            .find(|job| job.wrapper_id == lost.identity.local_wrapper_id)
            .unwrap();
        let admin = Mutex::new(AdminDisableStore::with_path(
            directory.path().join("admin.json"),
        ));
        assert!(matches!(
            recovery_admission(&admin, &context.pool, directory.path(), &lost_candidate)
                .await
                .unwrap(),
            Some(RecoveryAdmission::Local)
        ));
        let foreign_receipt = recovery_accounting_request(
            &context,
            format!(
                "GET /builds/{}?local_wrapper_id={}\n",
                lost_candidate.build_id, leases[9].identity.local_wrapper_id
            ),
        )
        .await;
        assert_eq!(foreign_receipt["status"], "identity_mismatch");

        // Hold one worker's reply while the other three settle. A rescan cannot
        // duplicate that flight or let its queued peers consume other lanes.
        let slow = leases[0].identity.local_wrapper_id.clone();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let run = |job: RecoveryCandidate| {
            let context = context.clone();
            let directory = directory.path().to_owned();
            let gate = gate.clone();
            let delayed = job.wrapper_id == slow;
            async move {
                if delayed {
                    gate.acquire().await.unwrap().forget();
                }
                settle_preparation_fixture(context, directory, job).await
            }
        };
        let mut queue = RecoveryQueue::default();
        let mut completed = HashSet::new();
        for _ in 0..2 {
            queue.refresh(scan());
            queue.start_ready(Instant::now(), run);
            while queue.running.len() > 1 {
                let (job, outcome) =
                    tokio::time::timeout(Duration::from_secs(5), queue.next_completed())
                        .await
                        .expect("responsive workers must not wait behind the delayed recovery")
                        .unwrap();
                assert_eq!(outcome, Ok(RecoveryOutcome::Recovered));
                assert!(completed.insert(job.wrapper_id));
            }
            assert_eq!(queue.running.values().next().unwrap().wrapper_id, slow);
        }
        assert_eq!(completed.len(), 6);
        assert_eq!(
            context
                .pool
                .get(&endpoints[1].id)
                .await
                .unwrap()
                .used_slots(),
            0
        );
        assert_eq!(
            context
                .pool
                .get(&endpoints[2].id)
                .await
                .unwrap()
                .used_slots(),
            0
        );
        assert_eq!(read_lease(directory.path(), &slow).unwrap(), leases[0]);
        queue.refresh(scan());
        queue.start_ready(Instant::now(), run);
        assert_eq!(queue.running.len(), 1);
        gate.add_permits(1);
        while !queue.running.is_empty() {
            let (job, outcome) =
                tokio::time::timeout(Duration::from_secs(5), queue.next_completed())
                    .await
                    .expect("released recovery must complete within its local accounting window")
                    .unwrap();
            assert_eq!(outcome, Ok(RecoveryOutcome::Recovered));
            assert!(completed.insert(job.wrapper_id));
            queue.start_ready(Instant::now(), run);
        }
        assert_eq!(completed.len(), 9);
        assert!(scan().is_empty());
        for original in &leases[..9] {
            let after = read_lease(directory.path(), &original.identity.local_wrapper_id).unwrap();
            verify_recovery_completion(original, &after).unwrap();
            assert_eq!(after.recovery.as_ref().unwrap()["prepared"], false);
            assert_eq!(after.recovery.as_ref().unwrap()["execution_started"], false);
            assert_eq!(
                after.recovery.as_ref().unwrap()["phases"],
                serde_json::json!([])
            );
            assert!(
                context
                    .history
                    .terminal_build(
                        original.identity.remote_build_id.unwrap(),
                        &original.identity.local_wrapper_id
                    )
                    .is_some()
            );
        }
        for protected in &leases[9..] {
            assert_eq!(
                read_lease(directory.path(), &protected.identity.local_wrapper_id).unwrap(),
                *protected
            );
            assert!(
                context
                    .history
                    .active_build(protected.identity.remote_build_id.unwrap())
                    .is_some()
            );
        }
        drop(queue);
        drop(context);
        let restarted = restore_recovery_fleet(directory.path(), &endpoints).await;
        assert_eq!(restarted.history.active_builds().len(), 2);
        for (endpoint, expected) in endpoints.iter().zip([1, 0, 0, 1]) {
            let worker = restarted.pool.get(&endpoint.id).await.unwrap();
            assert_eq!(worker.used_slots(), expected);
            assert!(
                worker.reserve_slots(1).await,
                "verified settlement must make capacity usable"
            );
        }
    }

    #[tokio::test]
    async fn offline_worker_lease_recovery_keeps_operator_disable_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("removed-worker");
        let (owned, candidate) = owned_recovery_fixture(directory.path(), &endpoint);
        let store_path = directory.path().join("admin.json");
        let store = Mutex::new(AdminDisableStore::with_path(&store_path));
        let pool = WorkerPool::new();
        // Historical ownership is recoverable even with no current inventory.
        // Seed the transport observation explicitly: this test exercises the
        // durable operator gate, not a connection to the fixture hostname.
        pool.record_owned_recovery_transport_result(&endpoint, true)
            .await;
        let mut admitted = recovery_admission(&store, &pool, directory.path(), &candidate)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            admitted
                .run_until(async { 7 }, test_recovery_window().deadline)
                .await,
            Some(7)
        );
        store
            .lock()
            .await
            .upsert(operator_disable(endpoint.id.as_str()))
            .unwrap();
        assert!(
            admitted
                .run_until(
                    async { panic!("revoked recovery was polled") },
                    test_recovery_window().deadline,
                )
                .await
                .is_none()
        );
        assert!(
            recovery_admission(&store, &pool, directory.path(), &candidate)
                .await
                .unwrap()
                .is_none()
        );
        drop(store);

        let restarted = Mutex::new(AdminDisableStore::try_load(&store_path).unwrap());
        pool.add_worker(endpoint.clone()).await;
        assert!(
            recovery_admission(&restarted, &pool, directory.path(), &candidate)
                .await
                .unwrap()
                .is_none()
        );
        pool.remove_worker(&endpoint.id).await;
        assert!(
            recovery_admission(&restarted, &pool, directory.path(), &candidate)
                .await
                .unwrap()
                .is_none()
        );
        restarted.lock().await.remove(endpoint.id.as_str()).unwrap();
        assert!(
            recovery_admission(&restarted, &pool, directory.path(), &candidate)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
            owned
        );
    }

    #[tokio::test(start_paused = true)]
    async fn offline_worker_lease_recovery_defers_only_matching_transport_outages() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("same-id");
        let (owned, candidate) = owned_recovery_fixture(directory.path(), &endpoint);
        let store = Mutex::new(AdminDisableStore::with_path(
            directory.path().join("admin.json"),
        ));
        let pool = WorkerPool::new();
        pool.add_worker(endpoint.clone()).await;
        let worker = pool.get(&endpoint.id).await.unwrap();
        worker.restore_slots(2).unwrap();
        worker
            .enter_bypass(rch_common::bypass_record::BypassFailureClass::DiskInodePressure)
            .await;
        worker.open_circuit().await;
        assert!(
            recovery_admission(&store, &pool, directory.path(), &candidate)
                .await
                .unwrap()
                .is_some(),
            "storage/circuit quarantine must not suppress owned recovery"
        );
        let circuit = rch_common::CircuitBreakerConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        worker
            .record_transport_result(false, Duration::from_secs(30), &circuit)
            .await;
        let mut queue = RecoveryQueue::default();
        let mut same_worker_leases = vec![candidate.clone()];
        for _ in 0..20 {
            same_worker_leases.push(owned_recovery_fixture(directory.path(), &endpoint).1);
        }
        queue
            .backoff
            .record_failure(&candidate.wrapper_id, Instant::now());
        let original_backoff = queue.backoff.failures[&candidate.wrapper_id];
        for _ in 0..12 {
            queue.refresh(same_worker_leases.clone());
            let eligible =
                eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await;
            assert!(eligible.is_empty());
            queue.start_ready_if(
                Instant::now(),
                |item| eligible.contains(&item.wrapper_id),
                |_| async {
                    panic!("a different lease bypassed the worker's slow transport recovery")
                },
            );
            assert!(queue.running.is_empty());
            assert_eq!(queue.starts_remaining, MAX_RECOVERIES_PER_CYCLE);
            assert_eq!(
                queue.backoff.failures[&candidate.wrapper_id],
                original_backoff
            );
            // Preserve coverage of an hour-long outage independently of the
            // shorter automatic recovery polling interval.
            tokio::time::advance(Duration::from_secs(5 * 60)).await;
        }
        let (_, healthy_peer) =
            owned_recovery_fixture(directory.path(), &recovery_worker("healthy-peer"));
        same_worker_leases.push(healthy_peer.clone());
        queue.refresh(same_worker_leases);
        let eligible = eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await;
        assert_eq!(eligible, HashSet::from([healthy_peer.wrapper_id.clone()]));
        queue.start_ready_if(
            Instant::now(),
            |item| eligible.contains(&item.wrapper_id),
            |_| async { Ok(RecoveryOutcome::Recovered) },
        );
        assert_eq!(queue.running.len(), 1);
        assert_eq!(
            queue.next_completed().await.unwrap().0.wrapper_id,
            healthy_peer.wrapper_id
        );
        assert_eq!(
            queue.backoff.failures[&candidate.wrapper_id],
            original_backoff
        );
        assert_eq!(worker.used_slots(), 2);
        worker
            .record_transport_result(true, Duration::from_secs(30), &circuit)
            .await;
        assert!(
            recovery_admission(&store, &pool, directory.path(), &candidate)
                .await
                .unwrap()
                .is_some()
        );

        // Reusing an ID at another host cannot redirect or suppress the old
        // endpoint named by the durable recipe, even when today's host is down.
        pool.remove_worker(&endpoint.id).await;
        pool.add_worker(WorkerConfig {
            host: "new-unrelated.invalid".into(),
            ..endpoint.clone()
        })
        .await;
        let replacement = pool.get(&endpoint.id).await.unwrap();
        replacement.restore_slots(3).unwrap();
        replacement
            .record_transport_result(false, Duration::from_secs(30), &circuit)
            .await;
        let historical = recovery_admission(&store, &pool, directory.path(), &candidate)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            historical,
            RecoveryAdmission::Network {
                network: Some(_),
                ..
            }
        ));
        assert_eq!(worker.used_slots(), 2);
        assert_eq!(replacement.used_slots(), 3);
        assert_eq!(
            read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
            owned
        );
    }

    #[tokio::test(start_paused = true)]
    async fn historical_endpoint_lease_scans_preserve_outage_backoff_after_inventory_changes() {
        for change in ["retargeted", "removed"] {
            let directory = tempfile::tempdir().unwrap();
            let endpoint = recovery_worker("historical-worker");
            let (owned, candidate) = owned_recovery_fixture(directory.path(), &endpoint);
            let store = Mutex::new(AdminDisableStore::with_path(
                directory.path().join("admin.json"),
            ));
            let pool = WorkerPool::new();
            pool.add_worker(endpoint.clone()).await;
            let original = pool.get(&endpoint.id).await.unwrap();
            original.restore_slots(2).unwrap();
            let circuit = rch_common::CircuitBreakerConfig {
                failure_threshold: 3,
                open_cooldown_secs: 900,
                ..Default::default()
            };
            for _ in 0..3 {
                original
                    .record_transport_result(false, Duration::from_secs(30), &circuit)
                    .await;
            }
            assert!(original.transport_is_down().await);

            if change == "retargeted" {
                original
                    .update_config(WorkerConfig {
                        host: "healthy-replacement.invalid".into(),
                        ..endpoint.clone()
                    })
                    .await;
            } else {
                pool.remove_worker(&endpoint.id).await;
            }

            let mut pending = vec![candidate.clone()];
            for _ in 0..12 {
                pending.push(owned_recovery_fixture(directory.path(), &endpoint).1);
            }
            let mut queue = RecoveryQueue::default();
            queue
                .backoff
                .record_failure(&candidate.wrapper_id, Instant::now());
            let previous_backoff = queue.backoff.failures[&candidate.wrapper_id];
            // Different old journals must not turn three scans within one
            // 900-second endpoint outage into independent recovery attempts.
            for scan in 0..3 {
                queue.refresh(pending.clone());
                let eligible =
                    eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await;
                assert!(
                    eligible.is_empty(),
                    "{change}, scan={scan}: historical leases bypassed the endpoint cooldown: {eligible:?}"
                );
                queue.start_ready_if(
                    Instant::now(),
                    |item| eligible.contains(&item.wrapper_id),
                    |_| async { panic!("dormant historical recovery consumed a lane") },
                );
                assert!(queue.running.is_empty());
                assert_eq!(queue.starts_remaining, MAX_RECOVERIES_PER_CYCLE);
                assert_eq!(
                    queue.backoff.failures[&candidate.wrapper_id],
                    previous_backoff
                );
                if scan < 2 {
                    tokio::time::advance(Duration::from_secs(5 * 60)).await;
                }
            }

            let (_, local) = retired_recovery_fixture(directory.path(), &endpoint);
            let peer = WorkerConfig {
                host: "healthy-peer.invalid".into(),
                ..recovery_worker("healthy-peer")
            };
            pool.add_worker(peer.clone()).await;
            let (_, independent) = owned_recovery_fixture(directory.path(), &peer);
            pending.extend([local.clone(), independent.clone()]);
            queue.refresh(pending);
            let eligible =
                eligible_recoveries(&queue.pending, &store, &pool, directory.path()).await;
            assert_eq!(
                eligible,
                HashSet::from([local.wrapper_id, independent.wrapper_id]),
                "historical transport backoff must preserve local settlement and healthy peers"
            );
            assert_eq!(
                queue.backoff.failures[&candidate.wrapper_id],
                previous_backoff
            );
            assert_eq!(original.used_slots(), 2);
            assert_eq!(
                read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
                owned
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn offline_worker_lease_deferral_preserves_existing_retry_backoff() {
        let mut queue = RecoveryQueue::default();
        let candidate = candidate("already-failed", "worker");
        queue
            .backoff
            .record_failure(&candidate.wrapper_id, Instant::now());
        let original = queue.backoff.failures[&candidate.wrapper_id];
        tokio::time::advance(BACKOFF_BASE).await;
        queue.refresh(vec![candidate.clone()]);
        queue.start_ready_if(
            Instant::now(),
            |_| true,
            |_| async { Ok(RecoveryOutcome::Deferred) },
        );
        let (finished, outcome) = queue.next_completed().await.unwrap();
        assert_eq!(finished.wrapper_id, candidate.wrapper_id);
        assert_eq!(outcome, Ok(RecoveryOutcome::Deferred));
        assert_eq!(queue.backoff.failures[&candidate.wrapper_id], original);
        assert!(queue.running.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn historical_endpoint_lease_and_cancellation_share_the_full_operation() {
        use crate::cancellation::{CancelReason, CancellationConfig, CancellationOrchestrator};
        use crate::history::BuildHistory;

        let Some(root) =
            std::env::var_os("RCH_ADMIN_CANCEL_TEST_ROOT").map(std::path::PathBuf::from)
        else {
            crate::cancellation::run_automatic_cancellation_fixture(
                "lease_recovery::tests::historical_endpoint_lease_and_cancellation_share_the_full_operation",
            )
            .await;
            return;
        };
        for transition in ["retargeted", "absent"] {
            let directory = root.join(transition);
            std::fs::create_dir_all(&directory).unwrap();
            let endpoint = recovery_worker(&format!("shared-recovery-{transition}"));
            let store = Arc::new(Mutex::new(AdminDisableStore::with_path(
                directory.join("admin.json"),
            )));
            let pool = WorkerPool::new()
                .with_admin_disable_store(store.clone())
                .with_recovery_transport_policy(
                    rch_common::CircuitBreakerConfig {
                        failure_threshold: 1,
                        open_cooldown_secs: 900,
                        ..Default::default()
                    },
                    Duration::from_secs(30),
                    Duration::from_secs(5),
                );
            pool.add_worker(endpoint.clone()).await;
            let original = pool.get(&endpoint.id).await.unwrap();
            original.restore_slots(2).unwrap();
            let history_path = directory.join("history.jsonl");
            let history = Arc::new(BuildHistory::new(10).with_persistence(history_path.clone()));
            let build = history
                .try_start_active_build_with_waiter(
                    "historical-cancellation".into(),
                    endpoint.id.to_string(),
                    "cargo test".into(),
                    0,
                    None,
                    2,
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
                    worker_id: endpoint.id.clone(),
                    hook_pid: None,
                    local_wrapper_id: None,
                    remote_pgid_file: Some("/original/owned.pgid".into()),
                    phase: rch_common::BuildHeartbeatPhase::Execute,
                    detail: None,
                    progress_counter: Some(1),
                    progress_percent: None,
                })
                .unwrap();
            if transition == "retargeted" {
                pool.add_worker(WorkerConfig {
                    host: "replacement.invalid".into(),
                    ..endpoint.clone()
                })
                .await;
            } else {
                assert!(pool.remove_worker(&endpoint.id).await);
                pool.restore_recovered_slots(&endpoint.id, 2).await.unwrap();
            }
            let mut context = crate::test_daemon_context(pool.clone());
            context.history = history.clone();
            context.admin_disable_store = Some(store.clone());
            context.cancellation = Arc::new(CancellationOrchestrator::new(
                CancellationConfig {
                    remote_kill_timeout: Duration::from_secs(10),
                    cleanup_timeout: Duration::from_secs(15),
                    ..Default::default()
                },
                context.events.clone(),
            ));

            let (mut owned, candidate) = retired_recovery_fixture(&directory, &endpoint);
            let recipe = owned.recovery.as_mut().unwrap();
            recipe["retired"] = serde_json::json!(false);
            recipe["sources_released"] = serde_json::json!(false);
            let journal = directory.join(format!("{}.json", candidate.wrapper_id));
            std::fs::write(&journal, serde_json::to_vec(&owned).unwrap()).unwrap();
            let mut settled = completed_lease(&owned, 0, 0);
            let recipe = settled.recovery.as_mut().unwrap();
            recipe["retired"] = serde_json::json!(true);
            recipe["sources_released"] = serde_json::json!(true);
            std::fs::write(
                directory.join("settled"),
                serde_json::to_vec(&settled).unwrap(),
            )
            .unwrap();
            let child = fake_rch(
                &directory,
                "printf started >\"$(dirname \"$0\")/cli-started\"\n\
                 cp \"$(dirname \"$0\")/settled\" \"$(dirname \"$0\")/$3.json\"\n",
            );
            let socket = directory.join("daemon.sock");
            let pending = VecDeque::from([candidate.clone()]);
            let before = std::fs::read_to_string(root.join("dials")).unwrap_or_default();
            for _ in 0..3 {
                assert_eq!(
                    eligible_recoveries(&pending, &store, &pool, &directory).await,
                    HashSet::from([candidate.wrapper_id.clone()]),
                    "readiness scans must not consume a historical probe"
                );
            }
            let mut queued = recovery_admission(&store, &pool, &directory, &candidate)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                std::fs::read_to_string(root.join("dials")).unwrap_or_default(),
                before,
                "speculative admission must not start SSH"
            );

            let proxy_path = root.join("proxy-pid");
            if proxy_path.exists() {
                std::fs::rename(&proxy_path, directory.join("previous-proxy-pid")).unwrap();
            }
            std::fs::write(root.join("build-id"), build.id.to_string()).unwrap();
            std::fs::write(root.join("mode"), "hang").unwrap();
            let cancel_context = context.clone();
            let cancellation = tokio::spawn(async move {
                cancel_context
                    .cancellation
                    .cancel_build(&cancel_context, build.id, CancelReason::StuckDetector, true)
                    .await
            });
            let proxy: u32 = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(text) = std::fs::read_to_string(&proxy_path)
                        && let Ok(pid) = text.trim().parse()
                    {
                        break pid;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the admitted cancellation must reach its real SSH operation");
            let active_dials = std::fs::read_to_string(root.join("dials")).unwrap();
            assert!(active_dials.len() > before.len());
            assert!(
                eligible_recoveries(&pending, &store, &pool, &directory)
                    .await
                    .is_empty(),
                "a held cancellation must also exclude lease recovery"
            );
            let window = test_recovery_window();
            assert!(
                queued
                    .run_until(
                        recover_in_with_policy(
                            &child,
                            &socket,
                            &directory,
                            &candidate.wrapper_id,
                            Some(&candidate),
                            RecoveryClientPolicy::Network {
                                can_disable_background: true,
                            },
                            window,
                        ),
                        window.deadline,
                    )
                    .await
                    .is_none(),
                "an earlier readiness snapshot must not bypass the active endpoint owner"
            );
            assert!(!directory.join("cli-started").exists());
            assert_eq!(
                read_lease(&directory, &candidate.wrapper_id).unwrap(),
                owned
            );
            assert_eq!(
                std::fs::read_to_string(root.join("dials")).unwrap(),
                active_dials
            );

            let (_, local) = retired_recovery_fixture(&directory, &endpoint);
            let mut local = recovery_admission(&store, &pool, &directory, &local)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                local
                    .run_until(async { 7 }, test_recovery_window().deadline)
                    .await,
                Some(7)
            );
            assert_eq!(
                crate::workers::handle_worker_disable(
                    &context,
                    &endpoint.id,
                    Some("pause historical recovery".into()),
                    false,
                )
                .await
                .status,
                "ok"
            );
            assert_eq!(
                crate::workers::handle_worker_enable(&context, &endpoint.id)
                    .await
                    .status,
                "ok"
            );
            let response = tokio::time::timeout(Duration::from_secs(5), cancellation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status, "deferred", "{response:?}");
            assert_eq!(response.slots_released, 0);
            assert!(
                queued
                    .run_until(
                        async { panic!("old admin permit survived ABA") },
                        test_recovery_window().deadline,
                    )
                    .await
                    .is_none()
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let stopped = match std::fs::read_to_string(format!("/proc/{proxy}/stat")) {
                        Ok(stat) => matches!(
                            stat.rsplit_once(") ")
                                .and_then(|(_, tail)| tail.chars().next()),
                            Some('Z' | 'X')
                        ),
                        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
                    };
                    if stopped {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("administrative revocation must stop the cancellation proxy");

            // The first operation's probe already proved the original endpoint
            // reachable. A new admin generation may finish another lease after
            // that operation releases its flight; no build is replayed.
            std::fs::write(root.join("mode"), "confirmed").unwrap();
            let mut recovered = recovery_admission(&store, &pool, &directory, &candidate)
                .await
                .unwrap()
                .unwrap();
            let window = test_recovery_window();
            recovered
                .run_until(
                    recover_in_with_policy(
                        &child,
                        &socket,
                        &directory,
                        &candidate.wrapper_id,
                        Some(&candidate),
                        RecoveryClientPolicy::Network {
                            can_disable_background: true,
                        },
                        window,
                    ),
                    window.deadline,
                )
                .await
                .unwrap()
                .unwrap();
            assert!(directory.join("cli-started").is_file());
            assert_eq!(
                read_lease(&directory, &candidate.wrapper_id).unwrap(),
                settled
            );
            assert!(history.active_build(build.id).is_some());
            assert!(!history.has_terminal_build(build.id));
            let restored = BuildHistory::load_from_file(&history_path, 10).unwrap();
            assert_eq!(restored.active_build(build.id).unwrap().slots, 2);
            if transition == "absent" {
                assert!(pool.get(&endpoint.id).await.is_none());
                pool.add_worker(endpoint.clone()).await;
            }
            assert_eq!(pool.get(&endpoint.id).await.unwrap().used_slots(), 2);
        }
        std::fs::write(root.join("child-completed"), "ok").unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn offline_worker_lease_recovery_revocation_stops_owned_cli_and_proxy() {
        struct AbortOnDrop(tokio::task::AbortHandle);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        for cause in ["disable", "disable-enable", "transport-down"] {
            let directory = tempfile::tempdir().unwrap();
            let endpoint = recovery_worker("owned-worker");
            let (owned, candidate) = owned_recovery_fixture(directory.path(), &endpoint);
            let store = Arc::new(Mutex::new(AdminDisableStore::with_path(
                directory.path().join("admin.json"),
            )));
            let pool = WorkerPool::new();
            pool.add_worker(endpoint.clone()).await;
            let worker = pool.get(&endpoint.id).await.unwrap();
            worker.restore_slots(2).unwrap();
            pool.record_owned_recovery_transport_result(&endpoint, true)
                .await;
            let mut admitted = recovery_admission(&store, &pool, directory.path(), &candidate)
                .await
                .unwrap()
                .unwrap();
            let child = fake_rch(
                directory.path(),
                "sleep 30 &\nprintf '%s %s\\n' $$ $! >\"$(dirname \"$0\")/pids\"\nwait\n",
            );
            let pid_path = directory.path().join("pids");
            let lease_dir = directory.path().to_owned();
            let socket = directory.path().join("daemon.sock");
            let id = candidate.wrapper_id.clone();
            let task = tokio::spawn(async move {
                let window = test_recovery_window();
                admitted
                    .run_until(
                        recover_in_with_policy(
                            &child,
                            &socket,
                            &lease_dir,
                            &id,
                            Some(&candidate),
                            RecoveryClientPolicy::Network {
                                can_disable_background: true,
                            },
                            window,
                        ),
                        window.deadline,
                    )
                    .await
            });
            let _abort = AbortOnDrop(task.abort_handle());
            let identities: Vec<u32> = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(pids) = std::fs::read_to_string(&pid_path) {
                        let pids: Vec<u32> = pids
                            .split_whitespace()
                            .filter_map(|pid| pid.parse().ok())
                            .collect();
                        if pids.len() == 2 {
                            break pids;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("recovery fixture started both CLI and proxy");
            let mut unrelated = tokio::process::Command::new("sleep")
                .arg("30")
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            if cause == "transport-down" {
                let circuit = rch_common::CircuitBreakerConfig {
                    failure_threshold: 1,
                    ..Default::default()
                };
                worker
                    .record_transport_result(false, Duration::from_secs(30), &circuit)
                    .await;
            } else {
                let mut store = store.lock().await;
                store
                    .upsert(operator_disable(endpoint.id.as_str()))
                    .unwrap();
                if cause == "disable-enable" {
                    store.remove(endpoint.id.as_str()).unwrap();
                }
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(5), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_none(),
                "{cause}"
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let leader_reaped = !Path::new(&format!("/proc/{}", identities[0])).exists();
                    let proxy_stopped =
                        match std::fs::read_to_string(format!("/proc/{}/stat", identities[1])) {
                            Ok(stat) => matches!(
                                stat.rsplit_once(") ")
                                    .and_then(|(_, fields)| fields.chars().next()),
                                Some('Z' | 'X')
                            ),
                            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
                        };
                    if leader_reaped && proxy_stopped {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("revocation must reap the CLI and stop its ProxyCommand");
            assert!(unrelated.try_wait().unwrap().is_none());
            unrelated.kill().await.unwrap();
            assert_eq!(worker.used_slots(), 2, "{cause}");
            assert_eq!(
                read_lease(directory.path(), &owned.identity.local_wrapper_id).unwrap(),
                owned
            );
        }
    }

    #[tokio::test]
    async fn recovery_queue_limits_global_and_per_worker_concurrency_across_scans() {
        let candidates = vec![
            candidate("a1", "a"),
            candidate("a2", "a"),
            candidate("b1", "b"),
            candidate("c1", "c"),
            candidate("d1", "d"),
            candidate("e1", "e"),
        ];
        let mut queue = RecoveryQueue::default();
        queue.refresh(candidates.clone());
        queue.start_ready(Instant::now(), |_| std::future::pending());
        assert_eq!(queue.running.len(), MAX_RECOVERIES_PER_CYCLE);
        let workers: HashSet<_> = queue.running.values().map(|job| &job.worker_id).collect();
        assert_eq!(workers.len(), MAX_RECOVERIES_PER_CYCLE);
        assert_eq!(queue.starts_remaining, 0);
        // A fresh scan cannot duplicate running wrappers or allocate more lanes.
        queue.refresh(candidates);
        queue.start_ready(Instant::now(), |_| async {
            Err("exceeded in-flight cap".into())
        });
        assert_eq!(queue.running.len(), MAX_RECOVERIES_PER_CYCLE);
        queue.tasks.shutdown().await;
    }

    #[tokio::test]
    async fn stalled_worker_does_not_block_other_worker_completion_or_next_job() {
        let mut queue = RecoveryQueue::default();
        queue.refresh(vec![
            candidate("slow", "blocked-worker"),
            candidate("first", "healthy-worker"),
            candidate("second", "healthy-worker"),
        ]);
        let run = |job: RecoveryCandidate| async move {
            if job.worker_id == "blocked-worker" {
                std::future::pending::<()>().await;
            }
            Ok(())
        };
        queue.start_ready(Instant::now(), run);
        assert_eq!(queue.running.len(), 2);
        for expected in ["first", "second"] {
            let (job, result) =
                tokio::time::timeout(Duration::from_secs(2), queue.next_completed())
                    .await
                    .unwrap()
                    .unwrap();
            result.unwrap();
            assert_eq!(job.wrapper_id, expected);
            assert!(queue.running.values().any(|job| job.wrapper_id == "slow"));
            queue.start_ready(Instant::now(), run);
        }
        queue.tasks.shutdown().await;
    }

    #[tokio::test]
    async fn recovery_task_panic_releases_its_lane_and_keeps_retry_backoff() {
        let mut queue = RecoveryQueue::default();
        queue.refresh(vec![candidate("panic", "worker")]);
        queue.start_ready(Instant::now(), |job| async move {
            if job.wrapper_id == "panic" {
                panic!("test-owned recovery task panic");
            }
            Ok(())
        });
        let (job, result) = queue.next_completed().await.unwrap();
        assert_eq!(job.wrapper_id, "panic");
        assert!(result.unwrap_err().contains("recovery task failed"));
        assert!(queue.running.is_empty());
        assert!(!queue.backoff.ready("panic", Instant::now()));
        queue.refresh(vec![
            candidate("panic", "worker"),
            candidate("next", "worker"),
        ]);
        queue.start_ready(Instant::now(), |job| async move {
            assert_eq!(job.wrapper_id, "next", "failed wrapper bypassed backoff");
            Ok(())
        });
        queue.next_completed().await.unwrap().1.unwrap();
    }

    #[tokio::test]
    async fn fast_recoveries_do_not_bypass_the_per_scan_start_budget() {
        let candidates: Vec<_> = (0..6)
            .map(|index| candidate(&format!("job-{index}"), "worker"))
            .collect();
        let mut queue = RecoveryQueue::default();
        queue.refresh(candidates.clone());
        for _ in 0..MAX_RECOVERIES_PER_CYCLE {
            queue.start_ready(Instant::now(), |_| async { Ok(()) });
            assert_eq!(queue.running.len(), 1);
            queue.next_completed().await.unwrap().1.unwrap();
        }
        queue.start_ready(Instant::now(), |_| async {
            Err("exceeded per-scan start budget".into())
        });
        assert!(queue.running.is_empty());
        assert_eq!(queue.pending.len(), 2);
        queue.refresh(
            candidates
                .into_iter()
                .skip(MAX_RECOVERIES_PER_CYCLE)
                .collect(),
        );
        queue.start_ready(Instant::now(), |_| async { Ok(()) });
        assert_eq!(queue.next_completed().await.unwrap().0.wrapper_id, "job-4");
    }

    #[tokio::test]
    async fn completion_discards_a_running_snapshot_reintroduced_by_a_scan() {
        let mut queue = RecoveryQueue::default();
        let job = candidate("once", "worker");
        queue.refresh(vec![job.clone()]);
        queue.start_ready(Instant::now(), |_| async { Ok(()) });
        queue.refresh(vec![job]);
        queue.next_completed().await.unwrap().1.unwrap();
        queue.start_ready(Instant::now(), |_| async {
            Err("replayed a completed scan snapshot".into())
        });
        assert!(queue.pending.is_empty());
        assert!(queue.running.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn retryable_recovery_outcomes_wait_for_next_scan_without_failure_backoff() {
        for retryable in [
            RecoveryOutcome::SettlementPending,
            RecoveryOutcome::Deferred,
        ] {
            let job = candidate("pending-recovery", "worker");
            let mut queue = RecoveryQueue::default();
            queue
                .backoff
                .record_failure(&job.wrapper_id, Instant::now());
            let previous_failure = queue.backoff.failures[&job.wrapper_id];
            tokio::time::advance(BACKOFF_BASE).await;

            for _ in 0..3 {
                queue.refresh(vec![job.clone()]);
                queue.start_ready_if(
                    Instant::now(),
                    |_| true,
                    move |_| async move { Ok(retryable) },
                );
                assert_eq!(queue.running.len(), 1);
                assert_eq!(queue.next_completed().await.unwrap().1, Ok(retryable));
                assert_eq!(queue.backoff.failures[&job.wrapper_id], previous_failure);
                queue.start_ready_if(
                    Instant::now(),
                    |_| true,
                    |_| async { panic!("deferred recovery must wait for another scan") },
                );
                assert!(queue.running.is_empty());
                assert!(queue.pending.is_empty());
                tokio::time::advance(RECOVERY_INTERVAL).await;
            }

            queue.refresh(vec![job.clone()]);
            queue.start_ready(Instant::now(), |_| async { Err("transport failed".into()) });
            assert!(queue.next_completed().await.unwrap().1.is_err());
            assert_eq!(queue.backoff.failures[&job.wrapper_id].0, 2);
            tokio::time::advance(RECOVERY_INTERVAL).await;
            queue.refresh(vec![job]);
            queue.start_ready(Instant::now(), |_| async {
                panic!("a genuine failure must retain exponential backoff")
            });
            assert!(queue.running.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retryable_recoveries_cannot_starve_unattempted_leases_on_the_same_worker() {
        let candidates: Vec<_> = (0..2 * MAX_RECOVERIES_PER_CYCLE + 1)
            .map(|index| candidate(&format!("job-{index}"), "same-worker"))
            .collect();
        let expected: Vec<_> = candidates
            .iter()
            .map(|job| job.wrapper_id.clone())
            .collect();
        for retryable in [
            RecoveryOutcome::SettlementPending,
            RecoveryOutcome::Deferred,
        ] {
            let mut queue = RecoveryQueue::default();
            let mut attempted = Vec::new();
            for _ in 0..3 {
                queue.refresh(candidates.clone());
                for _ in 0..MAX_RECOVERIES_PER_CYCLE {
                    queue.start_ready_if(
                        Instant::now(),
                        |_| true,
                        move |_| async move { Ok(retryable) },
                    );
                    assert_eq!(queue.running.len(), 1, "one recovery per worker");
                    let (job, outcome) = queue.next_completed().await.unwrap();
                    assert_eq!(outcome, Ok(retryable));
                    attempted.push(job.wrapper_id);
                }
                queue.start_ready_if(
                    Instant::now(),
                    |_| true,
                    |_| async { panic!("deferred recovery bypassed the per-scan budget") },
                );
                assert!(queue.running.is_empty());
                assert!(queue.backoff.failures.is_empty());
                tokio::time::advance(RECOVERY_INTERVAL).await;
            }
            assert_eq!(&attempted[..expected.len()], expected.as_slice());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_retryable_exits_retain_ownership_and_do_not_confirm_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = recovery_worker("pending-client");
        let (owned, candidate) = owned_recovery_fixture(directory.path(), &endpoint);
        let socket = directory.path().join("unused.sock");
        for (exit_code, expected) in [
            (
                AUTOMATIC_RECOVERY_PENDING_EXIT_CODE,
                RecoveryOutcome::SettlementPending,
            ),
            (
                AUTOMATIC_RECOVERY_DEFERRED_EXIT_CODE,
                RecoveryOutcome::Deferred,
            ),
        ] {
            let child = fake_rch(directory.path(), &format!("exit {exit_code}\n"));
            let outcome = recover_in_with_policy(
                &child,
                &socket,
                directory.path(),
                &candidate.wrapper_id,
                Some(&candidate),
                RecoveryClientPolicy::Network {
                    can_disable_background: false,
                },
                test_recovery_window(),
            )
            .await
            .unwrap();
            assert_eq!(outcome, expected);
            assert_eq!(
                read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
                owned
            );
            assert!(verify_recovery_completion(&owned, &owned).is_err());
            assert!(
                recover_in(
                    &child,
                    &socket,
                    directory.path(),
                    &candidate.wrapper_id,
                    Some(&candidate)
                )
                .await
                .is_err(),
                "retryable exit codes are reserved for the managed protocol"
            );
        }

        let child = fake_rch(directory.path(), "echo 'job journal is busy' >&2\nexit 1\n");
        assert!(
            recover_in_with_policy(
                &child,
                &socket,
                directory.path(),
                &candidate.wrapper_id,
                Some(&candidate),
                RecoveryClientPolicy::Network {
                    can_disable_background: false
                },
                test_recovery_window(),
            )
            .await
            .is_err()
        );
        assert_eq!(
            read_lease(directory.path(), &candidate.wrapper_id).unwrap(),
            owned
        );
    }

    #[tokio::test]
    async fn recovery_stderr_drains_beyond_capacity_and_keeps_only_the_tail() {
        use tokio::io::AsyncWriteExt as _;

        let (mut sender, mut receiver) = tokio::io::duplex(128);
        let mut tail = Vec::with_capacity(RECOVER_STDERR_TAIL_BYTES);
        let expected = vec![0xfe; RECOVER_STDERR_TAIL_BYTES];
        let producer = async {
            for _ in 0..512 {
                sender.write_all(&[b'x'; 4096]).await.unwrap();
            }
            sender.write_all(&expected).await.unwrap();
            sender.shutdown().await.unwrap();
        };
        let consumer = drain_recovery_stderr(&mut receiver, &mut tail);
        // Only a hang guard: 2 MiB through a 128-byte pipe is ~16k wakeups,
        // which exceeded 10 s on a Mac at load 64.
        let ((), drained) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(producer, consumer)
        })
        .await
        .unwrap();
        drained.unwrap();
        assert_eq!(tail, expected);
        assert_eq!(tail.capacity(), RECOVER_STDERR_TAIL_BYTES);
        assert_eq!(diagnostic_tail(&tail).chars().count(), 400);
    }

    #[cfg(unix)]
    async fn fixture_child(script: &str) -> (OwnedProcessGroup, u32) {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("pid");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                &format!("printf '%s\\n' $$ >\"$1\"; {script}"),
                "rch-recovery-test",
            ])
            .arg(&pid_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let child = OwnedProcessGroup::spawn(&mut command).unwrap();
        let pid = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(bytes) = std::fs::read_to_string(&pid_path)
                    && let Ok(pid) = bytes.trim().parse()
                {
                    break pid;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("fixture wrote its owned process identity");
        (child, pid)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_child_streams_large_diagnostics_and_preserves_nonzero_exit() {
        let (child, _) = fixture_child(
            "awk 'BEGIN { for (i=0; i<32768; i++) print \"0123456789abcdef\" }' >&2; \
             printf 'final recovery failure\\n' >&2; exit 7",
        )
        .await;
        let (status, tail) =
            collect_recovery_child(child, Instant::now() + Duration::from_secs(10))
                .await
                .unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(tail.len(), RECOVER_STDERR_TAIL_BYTES);
        assert!(diagnostic_tail(&tail).ends_with("final recovery failure"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_timeout_reaps_the_direct_child_before_returning() {
        let (child, pid) = fixture_child("exec sleep 30").await;
        let error = collect_recovery_child(child, Instant::now() + Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        assert!(!is_process_alive(pid), "timed-out recovery child survived");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_deadline_also_bounds_a_pipe_retained_after_child_exit() {
        // Keep the pipe open in a separately owned child so cleanup is explicit,
        // while presenting the same EOF condition as an inherited descriptor.
        let (mut holder, _) = fixture_child("exec sleep 30").await;
        let (mut child, _) = fixture_child("exit 0").await;
        assert!(child.wait().await.unwrap().success());
        let error = collect_recovery_child_stream(
            child,
            holder.take_stderr().unwrap(),
            Instant::now() + Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        holder.start_kill().unwrap();
        holder.wait().await.unwrap();
        assert!(error.contains("diagnostic EOF"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_recovery_does_not_detach_its_child_or_pipe_reader() {
        let (child, pid) = fixture_child("exec sleep 30").await;
        let task = tokio::spawn(collect_recovery_child(
            child,
            Instant::now() + Duration::from_secs(60),
        ));
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), async {
            while is_process_alive(pid) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled recovery child must exit");
    }

    fn lease(heartbeat_unix_ms: u64, pid: u32, recipe: serde_json::Value) -> DurableJobLease {
        let mut identity = JobIdentity::new_local();
        identity.admit(7);
        let mut lease = DurableJobLease::new(
            identity,
            pid,
            None,
            None,
            heartbeat_unix_ms,
            false,
            true,
            "blake3:test".to_string(),
        );
        lease.admit(7, "worker1".to_string(), heartbeat_unix_ms);
        lease.recovery = Some(recipe);
        lease
    }

    #[test]
    fn only_provably_dead_unacknowledged_source_owners_are_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let now = 100 * 60 * 60 * 1000;
        let stale = now - 60 * 60 * 1000;
        let owning = serde_json::json!({ "source_roots": ["/p"], "pair": null, "retire_root": null, "retired": false });
        let retired = serde_json::json!({ "source_roots": ["/p"], "pair": null, "retire_root": null, "retired": true });
        let (dead, live) = (11, 22);
        let mut acknowledged = lease(stale, dead, owning.clone());
        acknowledged.acknowledge_terminal(stale);
        let leases = [
            ("dead", lease(stale, dead, owning.clone())),
            ("live", lease(stale, live, owning.clone())),
            ("fresh", lease(now - 1000, dead, owning.clone())),
            ("retired", lease(stale, dead, retired)),
            ("no-pid", lease(stale, 0, owning)),
            ("acked", acknowledged),
        ];
        for (_name, lease) in &leases {
            std::fs::write(
                dir.path()
                    .join(format!("{}.json", lease.identity.local_wrapper_id)),
                serde_json::to_vec(lease).unwrap(),
            )
            .unwrap();
        }
        std::fs::write(dir.path().join("junk.json"), b"{").unwrap();

        let ids = recoverable_lease_ids(dir.path(), now, |pid| pid == live);

        assert_eq!(
            ids,
            vec![
                leases[0].1.identity.local_wrapper_id.clone(),
                leases[2].1.identity.local_wrapper_id.clone(),
            ]
        );
    }

    #[test]
    fn missing_lease_directory_has_no_candidates() {
        let dir = tempfile::tempdir().unwrap();
        assert!(recoverable_lease_ids(&dir.path().join("absent"), 0, |_| false).is_empty());
    }

    #[test]
    fn uncertain_ownership_never_authorizes_source_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let now = 100 * 60 * 60 * 1000;
        let candidate = lease(
            now - 60 * 60 * 1000,
            4242,
            serde_json::json!({"source_roots":["/p"],"retired":false}),
        );
        std::fs::write(
            dir.path()
                .join(format!("{}.json", candidate.identity.local_wrapper_id)),
            serde_json::to_vec(&candidate).unwrap(),
        )
        .unwrap();

        for heartbeat in [0, now - 60 * 60 * 1000, now, now + 60 * 60 * 1000] {
            let mut lease = candidate.clone();
            lease.heartbeat_unix_ms = heartbeat;
            std::fs::write(
                dir.path()
                    .join(format!("{}.json", lease.identity.local_wrapper_id)),
                serde_json::to_vec(&lease).unwrap(),
            )
            .unwrap();
            for presence in [OwnerPresence::Live, OwnerPresence::Unknown] {
                assert!(recoverable_candidates(dir.path(), now, |_| presence).is_empty());
            }
            let recovered = recoverable_candidates(dir.path(), now, |_| OwnerPresence::Absent);
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].wrapper_id, candidate.identity.local_wrapper_id);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn freshly_killed_execute_and_finalize_owners_are_queued_without_releasing_evidence() {
        use rch_common::process_identity::{ProcessObservation, observe_process};

        let directory = tempfile::tempdir().unwrap();
        let now = 100 * 60 * 60 * 1000;
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "read -r gate"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let ProcessObservation::Present(birth) = observe_process(pid) else {
            panic!("test wrapper must have a native process birth identity");
        };
        let mut journals = Vec::new();
        let mut expected = Vec::new();
        for phase in ["execute", "finalize"] {
            let mut lease = lease(
                now,
                pid,
                serde_json::json!({"source_roots":["/owned/source"],"retired":false}),
            );
            lease.phase = phase.into();
            lease.process_birth = Some(birth.clone());
            let path = directory
                .path()
                .join(format!("{}.json", lease.identity.local_wrapper_id));
            let bytes = serde_json::to_vec(&lease).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            expected.push(lease.identity.local_wrapper_id);
            journals.push((path, bytes));
        }
        let scan = || {
            recoverable_candidates(directory.path(), now, |lease| {
                owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
            })
        };
        assert!(scan().is_empty(), "the live wrapper still owns both leases");
        child.start_kill().unwrap();
        child.wait().await.unwrap();
        assert_eq!(owner_presence(pid, Some(&birth)), OwnerPresence::Absent);

        expected.sort();
        assert_eq!(
            scan()
                .into_iter()
                .map(|candidate| candidate.wrapper_id)
                .collect::<Vec<_>>(),
            expected,
            "a fresh heartbeat must not defer a provably dead execute/finalize owner"
        );
        for (path, bytes) in journals {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fresh_heartbeat_does_not_hide_recycled_wrapper_identity() {
        use rch_common::process_identity::{ProcessStart, current_process_identity};

        let directory = tempfile::tempdir().unwrap();
        let now = 100 * 60 * 60 * 1000;
        let birth = current_process_identity().unwrap();
        let mut previous_birth = birth.clone();
        match &mut previous_birth.start {
            ProcessStart::Linux { ticks } => *ticks = ticks.checked_add(1).unwrap(),
            ProcessStart::Darwin { seconds, .. } => {
                *seconds = seconds.checked_add(1).unwrap();
            }
        }
        let mut expected = None;
        for (identity, presence) in [
            (Some(birth), OwnerPresence::Live),
            (None, OwnerPresence::Unknown),
            (Some(previous_birth), OwnerPresence::Absent),
        ] {
            let mut lease = lease(
                now,
                std::process::id(),
                serde_json::json!({"source_roots":["/owned/source"],"retired":false}),
            );
            lease.process_birth = identity;
            std::fs::write(
                directory
                    .path()
                    .join(format!("{}.json", lease.identity.local_wrapper_id)),
                serde_json::to_vec(&lease).unwrap(),
            )
            .unwrap();
            assert_eq!(
                owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref()),
                presence
            );
            if presence == OwnerPresence::Absent {
                assert!(expected.is_none());
                expected = Some(lease.identity.local_wrapper_id);
            }
        }
        let candidates = recoverable_candidates(directory.path(), now, |lease| {
            owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
        });
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].wrapper_id, expected.unwrap());
    }

    #[test]
    fn backoff_doubles_to_a_cap_and_forgets_resolved_leases() {
        assert_eq!(backoff_after(1), BACKOFF_BASE);
        assert_eq!(backoff_after(2), BACKOFF_BASE * 2);
        assert_eq!(backoff_after(40), BACKOFF_MAX);

        let mut backoff = Backoff::default();
        let now = Instant::now();
        assert!(backoff.ready("a", now));
        assert_eq!(backoff.record_failure("a", now), 1);
        assert!(!backoff.ready("a", now));
        assert!(backoff.ready("a", now + BACKOFF_BASE));
        assert_eq!(backoff.record_failure("a", now), 2);
        backoff.retain(&[]);
        assert!(backoff.ready("a", now));
    }

    fn handoff_lease(stale: u64, pid: u32, exit: i32) -> DurableJobLease {
        let mut result = lease(stale, pid, serde_json::Value::Null);
        result.recovery = Some(serde_json::json!({
            "version":2, "wrapper_id":result.identity.local_wrapper_id,
            "build_id":7, "worker":{"id":"worker1"}, "returned":exit,
            "retired":true, "sources_released":true, "source_roots":["/p"],
        }));
        result
    }

    fn completed_lease(before: &DurableJobLease, exit: i32, daemon_exit: i32) -> DurableJobLease {
        let mut after = before.clone();
        after.recovery.as_mut().unwrap()["returned"] = serde_json::json!(exit);
        after.recovery.as_mut().unwrap()["daemon_exit_code"] = serde_json::json!(daemon_exit);
        after.exit_code = Some(exit);
        after.acknowledge_terminal(before.heartbeat_unix_ms + 1);
        after
    }

    fn terminal_cancellation_lease(stale: u64, pid: u32) -> DurableJobLease {
        let mut before = handoff_lease(stale, pid, 1);
        let recipe = before.recovery.as_mut().unwrap();
        recipe["identity"] = serde_json::json!("0123456789abcdef0123456789abcdef");
        recipe["preparation_cancelled"] = serde_json::json!(true);
        recipe["tree_retired"] = serde_json::json!(true);
        recipe["pair_released"] = serde_json::json!(true);
        // Live wrappers historically acknowledged without a detached daemon
        // receipt in the recipe. Their worker settlement is independent.
        before.exit_code = Some(1);
        before.acknowledge_terminal(stale);
        before
    }

    #[test]
    fn acknowledged_cancellations_are_recovered_after_restart_until_worker_settlement() {
        let dir = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let now = 100 * 60 * 60 * 1000;
        let stale = now - 60 * 60 * 1000;
        let legacy = terminal_cancellation_lease(stale, 11);
        let mut interrupted = terminal_cancellation_lease(stale, 12);
        interrupted.recovery.as_mut().unwrap()["preparation_cancelled"] = serde_json::json!(false);
        interrupted.recovery.as_mut().unwrap()["source_cancellation_settled"] =
            serde_json::json!(false);
        let live = terminal_cancellation_lease(stale, 22);
        let unknown = terminal_cancellation_lease(stale, 33);
        let fresh = terminal_cancellation_lease(now, 11);
        let mut settled = terminal_cancellation_lease(stale, 11);
        settled.recovery.as_mut().unwrap()["source_cancellation_settled"] = serde_json::json!(true);
        let ordinary = completed_lease(&handoff_lease(stale, 11, 102), 102, 102);
        let mut incomplete = terminal_cancellation_lease(stale, 11);
        incomplete.recovery.as_mut().unwrap()["retire_root"] = serde_json::json!("/unretired-tree");
        incomplete.recovery.as_mut().unwrap()["tree_retired"] = serde_json::json!(false);
        for candidate in [
            &legacy,
            &interrupted,
            &live,
            &unknown,
            &fresh,
            &settled,
            &ordinary,
            &incomplete,
        ] {
            std::fs::write(
                dir.path()
                    .join(format!("{}.json", candidate.identity.local_wrapper_id)),
                serde_json::to_vec(candidate).unwrap(),
            )
            .unwrap();
        }
        let presence = |lease: &DurableJobLease| match lease.wrapper_pid {
            22 => OwnerPresence::Live,
            33 => OwnerPresence::Unknown,
            _ => OwnerPresence::Absent,
        };
        let mut expected = vec![
            legacy.identity.local_wrapper_id.clone(),
            interrupted.identity.local_wrapper_id.clone(),
        ];
        expected.sort();
        expected.push(fresh.identity.local_wrapper_id.clone());
        for _restart in 0..2 {
            let candidates = recoverable_candidates(dir.path(), now, presence);
            assert_eq!(
                candidates
                    .iter()
                    .map(|candidate| candidate.wrapper_id.clone())
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn terminal_cancellation_recovery_preserves_absent_resource_defaults_after_restart() {
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let now = 100 * 60 * 60 * 1000;
        let stale = now - 60 * 60 * 1000;
        let mut expected = Vec::new();
        let mut journals = Vec::new();
        for explicit_defaults in [false, true] {
            for explicit_pending in [false, true] {
                let mut before = terminal_cancellation_lease(stale, 11);
                let recipe = before.recovery.as_mut().unwrap();
                if explicit_defaults {
                    recipe["pair"] = serde_json::Value::Null;
                    recipe["retire_root"] = serde_json::Value::Null;
                    recipe["pair_released"] = serde_json::json!(false);
                    recipe["tree_retired"] = serde_json::json!(false);
                } else {
                    recipe.as_object_mut().unwrap().remove("pair_released");
                    recipe.as_object_mut().unwrap().remove("tree_retired");
                }
                if explicit_pending {
                    recipe["preparation_cancelled"] = serde_json::json!(false);
                    recipe["source_cancellation_settled"] = serde_json::json!(false);
                }
                recipe["future_custody"] = serde_json::json!({"keep": "original"});
                assert_eq!(retired_delivery(&before), Some(1));
                assert!(terminal_cancellation_unsettled(&before));
                assert!(verify_recovery_completion(&before, &before).is_err());

                let mut after = before.clone();
                after.recovery.as_mut().unwrap()["source_cancellation_settled"] =
                    serde_json::json!(true);
                after.recovery.as_mut().unwrap()["source_authority_namespace"] =
                    serde_json::json!("current");
                verify_recovery_completion(&before, &after).unwrap();
                assert!(!terminal_cancellation_unsettled(&after));

                let path = directory
                    .path()
                    .join(format!("{}.json", before.identity.local_wrapper_id));
                let bytes = serde_json::to_vec(&before).unwrap();
                std::fs::write(&path, &bytes).unwrap();
                expected.push(before.identity.local_wrapper_id);
                journals.push((path, bytes));
            }
        }
        expected.sort();
        for _restart in 0..2 {
            assert_eq!(
                recoverable_candidates(directory.path(), now, |_| OwnerPresence::Absent)
                    .into_iter()
                    .map(|candidate| candidate.wrapper_id)
                    .collect::<Vec<_>>(),
                expected,
            );
            for (path, bytes) in &journals {
                assert_eq!(&std::fs::read(path).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn retired_delivery_refuses_live_and_malformed_resource_evidence() {
        let before = handoff_lease(1, 11, 137);
        let complete = completed_lease(&before, 137, 137);
        verify_recovery_completion(&before, &complete).unwrap();
        for (key, value) in [
            ("source_roots", serde_json::Value::Null),
            ("source_roots", serde_json::json!("/p")),
            ("source_roots", serde_json::json!([null])),
            ("source_roots", serde_json::json!([""])),
            ("source_roots", serde_json::json!(["/p\nother"])),
            ("sources_released", serde_json::json!(false)),
            ("sources_released", serde_json::Value::Null),
            ("pair", serde_json::json!(["/p", "aa"])),
            ("pair", serde_json::json!(["/p"])),
            ("pair", serde_json::json!(["/p", false])),
            ("pair_released", serde_json::Value::Null),
            ("pair_released", serde_json::json!("true")),
            ("retire_root", serde_json::json!("/p")),
            ("retire_root", serde_json::json!([])),
            ("tree_retired", serde_json::Value::Null),
        ] {
            let mut after = complete.clone();
            after.recovery.as_mut().unwrap()[key] = value;
            let unchanged = after.clone();
            assert!(retired_delivery(&after).is_none(), "{key}");
            assert!(
                verify_recovery_completion(&before, &after).is_err(),
                "{key}"
            );
            assert_eq!(after, unchanged);
        }
    }

    #[test]
    fn handoff_completion_refuses_new_pending_or_malformed_cancellation() {
        let before = handoff_lease(1, 11, 137);
        let mut complete = completed_lease(&before, 137, 130);
        complete.recovery.as_mut().unwrap()["preparation_cancelled"] = serde_json::json!(false);
        complete.recovery.as_mut().unwrap()["source_authority_namespace"] =
            serde_json::json!("current");
        verify_recovery_completion(&before, &complete).unwrap();
        for (key, value) in [
            ("source_cancellation_settled", serde_json::json!(false)),
            ("source_cancellation_settled", serde_json::json!("true")),
            ("source_cancellation_settled", serde_json::json!(0)),
            ("preparation_cancelled", serde_json::json!(true)),
            ("preparation_cancelled", serde_json::Value::Null),
            ("preparation_cancelled", serde_json::json!("false")),
        ] {
            let mut after = complete.clone();
            after.recovery.as_mut().unwrap()[key] = value;
            let unchanged = after.clone();
            assert!(after.terminal_acknowledged);
            assert!(
                verify_recovery_completion(&before, &after).is_err(),
                "{key}"
            );
            assert_eq!(after, unchanged);
        }
        complete.recovery.as_mut().unwrap()["source_cancellation_settled"] =
            serde_json::json!(true);
        verify_recovery_completion(&before, &complete).unwrap();
        let mut unbound = complete.clone();
        unbound.recovery.as_mut().unwrap()["source_authority_namespace"] = serde_json::Value::Null;
        assert!(verify_recovery_completion(&before, &unbound).is_err());
        let mut no_source_before = before.clone();
        no_source_before.recovery.as_mut().unwrap()["source_roots"] = serde_json::json!([]);
        let mut local_settlement = completed_lease(&no_source_before, 137, 130);
        local_settlement.recovery.as_mut().unwrap()["source_cancellation_settled"] =
            serde_json::json!(true);
        verify_recovery_completion(&no_source_before, &local_settlement).unwrap();
        let mut false_success = complete;
        false_success.recovery.as_mut().unwrap()["returned"] = serde_json::json!(0);
        false_success.exit_code = Some(0);
        assert!(verify_recovery_completion(&before, &false_success).is_err());
    }

    #[test]
    fn terminal_cancellation_recovery_requires_new_exact_worker_evidence() {
        let before = terminal_cancellation_lease(1, 11);
        assert!(verify_recovery_completion(&before, &before).is_err());
        let mut after = before.clone();
        after.recovery.as_mut().unwrap()["source_cancellation_settled"] = serde_json::json!(true);
        after.recovery.as_mut().unwrap()["source_authority_namespace"] =
            serde_json::json!("current");
        verify_recovery_completion(&before, &after).unwrap();
        for (key, value) in [
            ("source_cancellation_settled", serde_json::json!("true")),
            ("source_cancellation_settled", serde_json::json!(false)),
            ("source_authority_namespace", serde_json::json!(null)),
            ("source_authority_namespace", serde_json::json!("elsewhere")),
            ("source_authority_namespace", serde_json::json!(false)),
            ("identity", serde_json::json!("another-attempt")),
            ("source_roots", serde_json::json!(["/another-project"])),
            (
                "worker",
                serde_json::json!({"id":"worker1", "host":"other"}),
            ),
            ("tree_retired", serde_json::json!(false)),
            ("returned", serde_json::json!(0)),
        ] {
            let mut changed = after.clone();
            changed.recovery.as_mut().unwrap()[key] = value;
            assert!(
                verify_recovery_completion(&before, &changed).is_err(),
                "{key}"
            );
        }
        let mut changed = after;
        changed.exit_code = Some(0);
        assert!(verify_recovery_completion(&before, &changed).is_err());
    }

    #[test]
    fn terminal_recovery_can_bind_legacy_namespace_but_never_change_it() {
        for namespace in ["current", "legacy"] {
            let before = terminal_cancellation_lease(1, 11);
            let mut after = before.clone();
            after.recovery.as_mut().unwrap()["source_cancellation_settled"] =
                serde_json::json!(true);
            after.recovery.as_mut().unwrap()["source_authority_namespace"] =
                serde_json::json!(namespace);
            verify_recovery_completion(&before, &after).unwrap();
            let mut bound = before;
            bound.recovery.as_mut().unwrap()["source_authority_namespace"] =
                serde_json::json!(namespace);
            verify_recovery_completion(&bound, &after).unwrap();
            after.recovery.as_mut().unwrap()["source_authority_namespace"] =
                serde_json::json!(if namespace == "current" {
                    "legacy"
                } else {
                    "current"
                });
            assert!(verify_recovery_completion(&bound, &after).is_err());
        }
        let mut empty = terminal_cancellation_lease(1, 11);
        empty.recovery.as_mut().unwrap()["source_roots"] = serde_json::json!([]);
        let mut settled = empty.clone();
        settled.recovery.as_mut().unwrap()["source_cancellation_settled"] = serde_json::json!(true);
        verify_recovery_completion(&empty, &settled).unwrap();
        assert!(settled.recovery.as_ref().unwrap()["source_authority_namespace"].is_null());
    }

    #[test]
    fn retired_handoffs_stay_eligible_until_acknowledged_but_live_owners_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let now = 100 * 60 * 60 * 1000;
        let stale = now - 30 * 60 * 1000;
        let pending = handoff_lease(stale, 11, 102);
        // A crash can occur after retirement but before record_exit. The
        // recovery entry point resumes that boundary from recipe.returned.
        assert!(pending.exit_code.is_none());
        let live = handoff_lease(stale, 22, 102);
        let fresh = handoff_lease(now, 11, 102);
        let unknown = handoff_lease(stale, 0, 102);
        let acknowledged = completed_lease(&handoff_lease(stale, 11, 102), 102, 130);
        for (_name, candidate) in [
            ("pending", &pending),
            ("live", &live),
            ("fresh", &fresh),
            ("unknown", &unknown),
            ("acknowledged", &acknowledged),
        ] {
            std::fs::write(
                dir.path()
                    .join(format!("{}.json", candidate.identity.local_wrapper_id)),
                serde_json::to_vec(candidate).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            recoverable_lease_ids(dir.path(), now, |pid| pid == 22),
            [
                pending.identity.local_wrapper_id,
                fresh.identity.local_wrapper_id,
            ]
        );
    }

    #[test]
    fn incomplete_or_foreign_retired_recipes_do_not_authorize_a_handoff() {
        let original = handoff_lease(0, 11, 102);
        for (key, value) in [
            ("version", serde_json::json!(3)),
            ("wrapper_id", serde_json::json!("another-wrapper")),
            ("build_id", serde_json::json!(8)),
            ("worker", serde_json::json!({"id":"another-worker"})),
            ("retired", serde_json::json!(false)),
            ("sources_released", serde_json::json!(false)),
            ("pair", serde_json::json!(["/pair", "token"])),
            ("retire_root", serde_json::json!("/unretired-tree")),
            ("returned", serde_json::Value::Null),
            ("returned", serde_json::json!(i64::MAX)),
        ] {
            let mut changed = original.clone();
            changed.recovery.as_mut().unwrap()[key] = value;
            assert!(retired_delivery(&changed).is_none(), "{key}");
        }
        let mut unadmitted = original;
        unadmitted.identity.remote_build_id = None;
        assert!(retired_delivery(&unadmitted).is_none());
    }

    #[test]
    fn recovery_success_requires_both_delivery_and_daemon_evidence_without_conflating_exits() {
        let before = handoff_lease(0, 11, 102);
        assert!(verify_recovery_completion(&before, &before).is_err());
        let complete = completed_lease(&before, 102, 130);
        verify_recovery_completion(&before, &complete).unwrap();
        let mut no_daemon_receipt = complete.clone();
        no_daemon_receipt.recovery.as_mut().unwrap()["daemon_exit_code"] = serde_json::Value::Null;
        assert!(verify_recovery_completion(&before, &no_daemon_receipt).is_err());
        // bd-ey7fr: a long-dead build the daemon no longer knew settles on
        // the client's recorded absence instead of a terminal receipt.
        let mut forgotten = no_daemon_receipt.clone();
        forgotten.recovery.as_mut().unwrap()["daemon_record_absent"] = serde_json::json!(true);
        verify_recovery_completion(&before, &forgotten).unwrap();
        forgotten.recovery.as_mut().unwrap()["daemon_record_absent"] = serde_json::json!("true");
        assert!(verify_recovery_completion(&before, &forgotten).is_err());
        let mut false_success = complete.clone();
        false_success.exit_code = Some(0);
        assert!(verify_recovery_completion(&before, &false_success).is_err());
        let mut replaced = complete;
        replaced.identity.remote_build_id = Some(8);
        assert!(verify_recovery_completion(&before, &replaced).is_err());
        let mut replaced = completed_lease(&before, 102, 130);
        replaced.process_birth = rch_common::process_identity::ProcessIdentity::from_record(
            "3f1c2a9e-5b7d-4e2a-9c1f-0a1b2c3d4e5f:darwin:1791280000:123456",
        );
        assert!(verify_recovery_completion(&before, &replaced).is_err());
    }

    #[test]
    fn handoff_retry_keeps_existing_backoff_after_source_retirement() {
        let dir = tempfile::tempdir().unwrap();
        let now_ms = 100 * 60 * 60 * 1000;
        let pending = handoff_lease(now_ms - 30 * 60 * 1000, 11, 102);
        let id = &pending.identity.local_wrapper_id;
        std::fs::write(
            dir.path().join(format!("{id}.json")),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();
        let now = Instant::now();
        let mut backoff = Backoff::default();
        backoff.record_failure(id, now);
        backoff.retain(&recoverable_lease_ids(dir.path(), now_ms, |_| false));
        assert!(!backoff.ready(id, now));
        assert!(backoff.ready(id, now + BACKOFF_BASE));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn child_exit_zero_without_journal_completion_is_not_auto_recovery_success() {
        let dir = tempfile::tempdir().unwrap();
        let pending = handoff_lease(0, 11, 102);
        let id = &pending.identity.local_wrapper_id;
        let path = dir.path().join(format!("{id}.json"));
        std::fs::write(&path, serde_json::to_vec(&pending).unwrap()).unwrap();
        let child = fake_rch(dir.path(), "exit 0\n");
        let error = recover_in(
            &child,
            &dir.path().join("unused.sock"),
            dir.path(),
            id,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.contains("without durable daemon/delivery acknowledgement"));
        assert_eq!(read_lease(dir.path(), id).unwrap(), pending);

        let complete = completed_lease(&pending, 102, 130);
        let receipt = dir.path().join("completed.fixture");
        std::fs::write(&receipt, serde_json::to_vec(&complete).unwrap()).unwrap();
        // The test-owned child simulates writing the final durable journal;
        // the daemon must inspect that journal rather than its exit alone.
        fake_rch(
            dir.path(),
            &format!(
                "cp -- {} {}\n",
                shell_escape::escape(receipt.to_str().unwrap().into()),
                shell_escape::escape(path.to_str().unwrap().into())
            ),
        );
        recover_in(
            &child,
            &dir.path().join("unused.sock"),
            dir.path(),
            id,
            None,
        )
        .await
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn recovery_scan_uses_canonical_regular_journals_and_oldest_owner_first() {
        // The socket fixture's path must fit sockaddr_un (104 bytes on macOS,
        // where the default TMPDIR alone is ~49).
        let dir = tempfile::Builder::new()
            .prefix("rch-lease-")
            .tempdir_in("/tmp")
            .unwrap();
        let now = 100 * 60 * 60 * 1000;
        let oldest = handoff_lease(0, 11, 102);
        let newer = handoff_lease(now - 30 * 60 * 1000, 11, 102);
        for lease in [&oldest, &newer] {
            std::fs::write(
                dir.path()
                    .join(format!("{}.json", lease.identity.local_wrapper_id)),
                serde_json::to_vec(lease).unwrap(),
            )
            .unwrap();
        }
        let original = dir
            .path()
            .join(format!("{}.json", oldest.identity.local_wrapper_id));
        let alias = format!("{}.json", JobIdentity::new_local().local_wrapper_id);
        std::os::unix::fs::symlink(&original, dir.path().join(alias)).unwrap();
        std::fs::write(
            dir.path().join("not-a-wrapper.json"),
            std::fs::read(&original).unwrap(),
        )
        .unwrap();
        let socket = dir.path().join(format!(
            "{}.json",
            JobIdentity::new_local().local_wrapper_id
        ));
        let _listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        let mut unknown_schema = handoff_lease(0, 11, 102);
        unknown_schema.schema_version = 2;
        std::fs::write(
            dir.path()
                .join(format!("{}.json", unknown_schema.identity.local_wrapper_id)),
            serde_json::to_vec(&unknown_schema).unwrap(),
        )
        .unwrap();
        assert_eq!(
            recoverable_lease_ids(dir.path(), now, |_| false),
            [
                oldest.identity.local_wrapper_id,
                newer.identity.local_wrapper_id
            ]
        );
    }

    #[tokio::test]
    async fn a_changed_worker_or_build_is_refused_before_spawning_a_recovery_client() {
        let dir = tempfile::tempdir().unwrap();
        let lease = handoff_lease(0, 11, 102);
        let id = &lease.identity.local_wrapper_id;
        let journal = serde_json::to_vec(&lease).unwrap();
        let path = dir.path().join(format!("{id}.json"));
        std::fs::write(&path, &journal).unwrap();
        for (worker, build) in [("other-worker", 7), ("worker1", 8)] {
            let mut candidate = candidate(id, worker);
            candidate.build_id = build;
            let error = recover_in(
                &dir.path().join("client-that-must-not-start"),
                &dir.path().join("unused.sock"),
                dir.path(),
                id,
                Some(&candidate),
            )
            .await
            .unwrap_err();
            assert!(
                error.contains("admission changed after scanning"),
                "{error}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), journal);
        }
    }

    #[test]
    fn recipeless_dead_leases_become_recoverable_after_24h_and_verify_completion() {
        let dir = tempfile::tempdir().unwrap();
        let now = 100 * 60 * 60 * 1000;
        let twenty_four_hours_ago = now - DAEMON_ABSENCE_MIN_AGE_MS;
        let too_young = twenty_four_hours_ago + 1;

        let mut mature = lease(twenty_four_hours_ago, 11, serde_json::Value::Null);
        mature.recovery = None;
        let mut young = lease(too_young, 11, serde_json::Value::Null);
        young.recovery = None;
        let mut live_owner = lease(twenty_four_hours_ago, 22, serde_json::Value::Null);
        live_owner.recovery = None;

        for candidate in [&mature, &young, &live_owner] {
            std::fs::write(
                dir.path()
                    .join(format!("{}.json", candidate.identity.local_wrapper_id)),
                serde_json::to_vec(candidate).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            recoverable_lease_ids(dir.path(), now, |pid| pid == 22),
            std::slice::from_ref(&mature.identity.local_wrapper_id)
        );

        assert!(verify_recovery_completion(&mature, &mature).is_err());
        let mut settled = mature.clone();
        settled.exit_code = Some(102);
        settled.acknowledge_terminal(now);
        verify_recovery_completion(&mature, &settled).unwrap();

        let mut with_observed_exit = mature.clone();
        with_observed_exit.exit_code = Some(101);
        let mut mismatched_exit = settled.clone();
        mismatched_exit.exit_code = Some(102);
        assert!(verify_recovery_completion(&with_observed_exit, &mismatched_exit).is_err());
        let mut matching_exit = settled;
        matching_exit.exit_code = Some(101);
        verify_recovery_completion(&with_observed_exit, &matching_exit).unwrap();
    }
}
