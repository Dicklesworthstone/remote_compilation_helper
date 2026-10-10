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

use crate::api::{is_process_alive, lease_blocks_restart, lease_owns_unretired_source};
use crate::events::EventBus;
use rch_common::job_identity::{DurableJobLease, default_job_lease_directory};
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
    let roots = recipe["source_roots"].as_array()?;
    if recipe["version"].as_u64() != Some(2)
        || recipe["wrapper_id"].as_str() != Some(lease.identity.local_wrapper_id.as_str())
        || recipe["build_id"].as_u64() != Some(build_id)
        || recipe["worker"]["id"].as_str() != Some(worker)
        || recipe["retired"].as_bool() != Some(true)
        || (!roots.is_empty() && recipe["sources_released"].as_bool() != Some(true))
        || (!recipe["pair"].is_null() && recipe["pair_released"].as_bool() != Some(true))
        || (!recipe["retire_root"].is_null() && recipe["tree_retired"].as_bool() != Some(true))
    {
        return None;
    }
    recipe["returned"]
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
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
    let daemon_exit = after.recovery.as_ref().and_then(|recipe| {
        recipe["daemon_exit_code"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok())
    });
    if !after.terminal_acknowledged
        || after.state != rch_common::job_identity::JobLifecycleState::Finished
        || retired_delivery(after).is_none()
        || retired_delivery(after) != after.exit_code
        || daemon_exit.is_none()
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

/// Only dead, stale, unacknowledged source owners or pending daemon handoffs
/// enter the queue. Unreadable/noncanonical journals are not execution authority;
/// the separate restart scan retains its fail-closed treatment of bad evidence.
fn recoverable_candidates(
    lease_dir: &Path,
    now_unix_ms: u64,
    alive: impl Fn(u32) -> bool,
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
            !lease.terminal_acknowledged
                && (lease_owns_unretired_source(lease) || retired_delivery(lease).is_some())
                && !lease_blocks_restart(lease, now_unix_ms, || alive(lease.wrapper_pid))
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
                        recoverable_candidates(&default_job_lease_directory(), now, is_process_alive)
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

    fn recoverable_lease_ids(
        directory: &Path,
        now: u64,
        alive: impl Fn(u32) -> bool,
    ) -> Vec<String> {
        recoverable_candidates(directory, now, alive)
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
        let ((), drained) = tokio::time::timeout(Duration::from_secs(10), async {
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
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let pending = handoff_lease(0, 11, 102);
        let id = &pending.identity.local_wrapper_id;
        let path = dir.path().join(format!("{id}.json"));
        std::fs::write(&path, serde_json::to_vec(&pending).unwrap()).unwrap();
        let child = dir.path().join("rch");
        std::fs::write(&child, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
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
        std::fs::write(
            &child,
            format!(
                "#!/bin/sh\ncp -- {} {}\n",
                shell_escape::escape(receipt.to_str().unwrap().into()),
                shell_escape::escape(path.to_str().unwrap().into())
            ),
        )
        .unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
}
