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
use crate::api::{lease_blocks_restart, lease_owns_unretired_source};
use crate::events::EventBus;
use rch_common::job_identity::{
    DurableJobLease, default_job_lease_directory, source_recovery_resources_retired,
};
use rch_common::process_identity::{OwnerPresence, owner_presence};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::{Id, JoinSet};
use tokio::time::Instant;
use tracing::{info, warn};

/// How often the lease directory is checked for recoverable leases.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Do not contend with a just-finished wrapper's journal. This is a scheduling
/// grace only; activity-lock and durable worker receipts authorize settlement.
const TERMINAL_CANCELLATION_GRACE_MS: u64 = 15 * 60 * 1000;
/// Bound both starts per scan interval and total in-flight recovery clients.
/// A worker gets at most one client, so a stalled worker cannot consume every
/// lane or serialize independent workers behind its timeout.
const MAX_RECOVERIES_PER_CYCLE: usize = 4;
/// Deadline handed to `rch jobs recover`, plus slack before the child is killed.
const RECOVER_TIMEOUT_SECS: u64 = 300;
const RECOVER_KILL_AFTER: Duration = Duration::from_secs(RECOVER_TIMEOUT_SECS + 30);
/// Keep diagnostics bounded even when a recovery produces gigabytes of output.
const RECOVER_STDERR_TAIL_BYTES: usize = 16 * 1024;
/// Reap the direct child after timeout without wedging the recovery service.
const RECOVER_REAP_TIMEOUT: Duration = Duration::from_secs(5);
/// Retry delay after the first failure; doubles per failure up to the cap.
const BACKOFF_BASE: Duration = Duration::from_secs(10 * 60);
const BACKOFF_MAX: Duration = Duration::from_secs(6 * 60 * 60);

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

/// Only dead, stale source owners, pending daemon handoffs, or acknowledged
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
            if terminal_cancellation_unsettled(lease) {
                // lease_blocks_restart deliberately ignores terminal leases.
                // Recovery must still exclude live or unverified wrappers.
                return presence(lease) == OwnerPresence::Absent
                    && lease.heartbeat_unix_ms > 0
                    && (lease.heartbeat_unix_ms > now_unix_ms
                        || now_unix_ms.saturating_sub(lease.heartbeat_unix_ms)
                            >= TERMINAL_CANCELLATION_GRACE_MS);
            }
            !lease.terminal_acknowledged
                && (lease_owns_unretired_source(lease)
                    || retired_delivery(lease).is_some()
                    || abandoned_without_recovery(lease, now_unix_ms))
                && !lease_blocks_restart(lease, now_unix_ms, || presence(lease))
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
    tasks: JoinSet<Result<(), String>>,
    backoff: Backoff,
    starts_remaining: usize,
}

impl RecoveryQueue {
    fn refresh(&mut self, candidates: Vec<RecoveryCandidate>) {
        let ids: Vec<String> = candidates
            .iter()
            .chain(self.running.values())
            .map(|candidate| candidate.wrapper_id.clone())
            .collect();
        self.backoff.retain(&ids);
        self.pending = candidates.into();
        self.starts_remaining = MAX_RECOVERIES_PER_CYCLE;
    }

    fn start_ready<F, R>(&mut self, now: Instant, mut run: F)
    where
        F: FnMut(RecoveryCandidate) -> R,
        R: Future<Output = Result<(), String>> + Send + 'static,
    {
        while self.starts_remaining > 0 && self.running.len() < MAX_RECOVERIES_PER_CYCLE {
            let next = self.pending.iter().position(|candidate| {
                self.backoff.ready(&candidate.wrapper_id, now)
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
            self.running.insert(task.id(), candidate);
            self.starts_remaining -= 1;
        }
    }

    async fn next_completed(&mut self) -> Option<(RecoveryCandidate, Result<(), String>)> {
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
        } else {
            self.backoff.failures.remove(&candidate.wrapper_id);
        }
        Some((candidate, outcome))
    }
}

/// Start the recovery loop. `socket` is this daemon's socket; the child
/// `rch` is pointed at it so it never reconciles against another daemon.
pub(crate) fn start(events: EventBus, socket: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let rch = match std::env::current_exe() {
            Ok(exe) => exe.with_file_name("rch"),
            Err(error) => {
                warn!("Lease auto-recovery disabled: cannot resolve rchd path: {error}");
                return;
            }
        };
        let mut queue = RecoveryQueue::default();
        let mut ticker =
            tokio::time::interval_at(Instant::now() + RECOVERY_INTERVAL, RECOVERY_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                completed = queue.next_completed(), if !queue.running.is_empty() => {
                    if let Some((candidate, outcome)) = completed {
                        let id = candidate.wrapper_id;
                        match outcome {
                            Ok(()) => {
                                info!(wrapper_id = %id, "Recovered dead client lease");
                                events.emit("lease_auto_recovered", &serde_json::json!({
                                    "wrapper_id": id,
                                }));
                            }
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
            queue.start_ready(Instant::now(), |candidate| {
                let rch = rch.clone();
                let socket = socket.clone();
                async move { recover(&rch, &socket, &candidate).await }
            });
        }
    })
}

/// Run `rch jobs recover` for one lease; the error is the tail of its stderr.
async fn recover(rch: &Path, socket: &Path, candidate: &RecoveryCandidate) -> Result<(), String> {
    recover_in(
        rch,
        socket,
        &default_job_lease_directory(),
        &candidate.wrapper_id,
        Some(candidate),
    )
    .await
}

async fn recover_in(
    rch: &Path,
    socket: &Path,
    lease_dir: &Path,
    wrapper_id: &str,
    candidate: Option<&RecoveryCandidate>,
) -> Result<(), String> {
    let before = read_lease(lease_dir, wrapper_id)?;
    if let Some(candidate) = candidate
        && (candidate.wrapper_id != wrapper_id
            || before.identity.remote_build_id != Some(candidate.build_id)
            || before.worker_id.as_deref() != Some(candidate.worker_id.as_str()))
    {
        return Err("recovery admission changed after scanning; client was not started".into());
    }
    let child = tokio::process::Command::new(rch)
        .args(["jobs", "recover", wrapper_id, "--timeout-secs"])
        .arg(RECOVER_TIMEOUT_SECS.to_string())
        .env("RCH_SOCKET_PATH", socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("cannot run {}: {error}", rch.display()))?;
    let (status, stderr) = collect_recovery_child(child, RECOVER_KILL_AFTER).await?;
    if status.success() {
        let after = read_lease(lease_dir, wrapper_id)?;
        return verify_recovery_completion(&before, &after);
    }
    Err(format!("{status}: {}", diagnostic_tail(&stderr)))
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
    mut child: tokio::process::Child,
    budget: Duration,
) -> Result<(ExitStatus, Vec<u8>), String> {
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "recovery child has no diagnostic pipe".to_owned())?;
    let mut tail = Vec::with_capacity(RECOVER_STDERR_TAIL_BYTES);
    let completed = tokio::time::timeout(budget, async {
        tokio::try_join!(child.wait(), drain_recovery_stderr(&mut stderr, &mut tail))
    })
    .await;
    let failure = match completed {
        Ok(Ok((status, ()))) => return Ok((status, tail)),
        Ok(Err(error)) => format!("cannot collect recovery child: {error}"),
        Err(_) => format!(
            "recovery timed out after {}ms waiting for child exit and diagnostic EOF",
            budget.as_millis()
        ),
    };
    // kill_on_drop covers cancellation of this entire future. On our own
    // timeout/error path, explicitly wait for the direct child to be reaped.
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
    use rch_common::job_identity::JobIdentity;

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
    fn fixture_child(script: &str) -> tokio::process::Child {
        tokio::process::Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_child_streams_large_diagnostics_and_preserves_nonzero_exit() {
        let child = fixture_child(
            "awk 'BEGIN { for (i=0; i<32768; i++) print \"0123456789abcdef\" }' >&2; \
             printf 'final recovery failure\\n' >&2; exit 7",
        );
        let (status, tail) = collect_recovery_child(child, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(tail.len(), RECOVER_STDERR_TAIL_BYTES);
        assert!(diagnostic_tail(&tail).ends_with("final recovery failure"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_timeout_reaps_the_direct_child_before_returning() {
        let child = fixture_child("exec sleep 30");
        let pid = child.id().unwrap();
        let error = collect_recovery_child(child, Duration::from_millis(100))
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
        let mut holder = fixture_child("exec sleep 30");
        let mut child = fixture_child("exit 0");
        assert!(child.wait().await.unwrap().success());
        child.stderr = holder.stderr.take();
        let error = collect_recovery_child(child, Duration::from_millis(100))
            .await
            .unwrap_err();
        holder.kill().await.unwrap();
        assert!(error.contains("diagnostic EOF"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_recovery_does_not_detach_its_child_or_pipe_reader() {
        let child = fixture_child("exec sleep 30");
        let pid = child.id().unwrap();
        let task = tokio::spawn(collect_recovery_child(child, Duration::from_secs(60)));
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
    fn only_dead_stale_unacknowledged_source_owners_are_recoverable() {
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

        assert_eq!(ids, vec![leases[0].1.identity.local_wrapper_id.clone()]);
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

        for presence in [OwnerPresence::Live, OwnerPresence::Unknown] {
            assert!(recoverable_candidates(dir.path(), now, |_| presence).is_empty());
        }
        let recovered = recoverable_candidates(dir.path(), now, |_| OwnerPresence::Absent);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].wrapper_id, candidate.identity.local_wrapper_id);
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
            std::slice::from_ref(&pending.identity.local_wrapper_id)
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
