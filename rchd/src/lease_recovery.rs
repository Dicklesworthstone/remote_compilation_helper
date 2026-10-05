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
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{info, warn};

/// How often the lease directory is checked for recoverable leases.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Recoveries per cycle; each is serial, so a bad cycle costs at most this many
/// timeouts.
const MAX_RECOVERIES_PER_CYCLE: usize = 4;
/// Deadline handed to `rch jobs recover`, plus slack before the child is killed.
const RECOVER_TIMEOUT_SECS: u64 = 300;
const RECOVER_KILL_AFTER: Duration = Duration::from_secs(RECOVER_TIMEOUT_SECS + 30);
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
        return Err("recovery command exited without durable daemon/delivery acknowledgement".into());
    }
    Ok(())
}

fn read_lease(lease_dir: &Path, wrapper_id: &str) -> Result<DurableJobLease, String> {
    // Never let a malformed journal name select a path outside the lease root.
    let suffix = wrapper_id
        .strip_prefix(rch_common::job_identity::LOCAL_WRAPPER_ID_PREFIX)
        .ok_or_else(|| "invalid recovery wrapper id".to_owned())?;
    let uuid = uuid::Uuid::parse_str(suffix)
        .map_err(|_| "invalid recovery wrapper id".to_owned())?;
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
    if lease.identity.local_wrapper_id != wrapper_id {
        return Err("recovery journal filename and identity disagree".into());
    }
    Ok(lease)
}

/// Leases in `lease_dir` that the daemon may recover on the owner's behalf:
/// the owner is provably gone (the same evidence that stops the lease blocking
/// a restart), the recipe owns worker source OR awaits its daemon handoff,
/// and the wrapper never
/// acknowledged a terminal state (`rch jobs recover` returns early on those).
/// Unreadable entries are skipped; the restart scan already fails closed on
/// them.
pub(crate) fn recoverable_lease_ids(
    lease_dir: &Path,
    now_unix_ms: u64,
    alive: impl Fn(u32) -> bool,
) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(lease_dir) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .filter_map(|path| std::fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<DurableJobLease>(&bytes).ok())
        .filter(|lease| {
            !lease.terminal_acknowledged
                && (lease_owns_unretired_source(lease) || retired_delivery(lease).is_some())
                && !lease_blocks_restart(lease, now_unix_ms, || alive(lease.wrapper_pid))
        })
        .map(|lease| lease.identity.local_wrapper_id)
        .collect();
    ids.sort();
    ids
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
        self.failures.retain(|id, _| candidates.contains(id));
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
        let mut backoff = Backoff::default();
        let mut ticker =
            tokio::time::interval_at(Instant::now() + RECOVERY_INTERVAL, RECOVERY_INTERVAL);
        loop {
            ticker.tick().await;
            if !rch.exists() {
                continue;
            }
            let now_unix_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
            let candidates = tokio::task::spawn_blocking(move || {
                recoverable_lease_ids(
                    &default_job_lease_directory(),
                    now_unix_ms,
                    is_process_alive,
                )
            })
            .await
            .unwrap_or_default();
            backoff.retain(&candidates);
            let now = Instant::now();
            let due: Vec<&String> = candidates
                .iter()
                .filter(|id| backoff.ready(id, now))
                .take(MAX_RECOVERIES_PER_CYCLE)
                .collect();
            for id in due {
                match recover(&rch, &socket, id).await {
                    Ok(()) => {
                        info!(wrapper_id = %id, "Recovered dead client lease");
                        events.emit(
                            "lease_auto_recovered",
                            &serde_json::json!({ "wrapper_id": id }),
                        );
                    }
                    Err(error) => {
                        let failures = backoff.record_failure(id, Instant::now());
                        warn!(wrapper_id = %id, failures, "Dead client lease recovery failed: {error}");
                        events.emit(
                            "lease_auto_recovery_failed",
                            &serde_json::json!({
                                "wrapper_id": id,
                                "failures": failures,
                                "error": error,
                            }),
                        );
                    }
                }
            }
        }
    })
}

/// Run `rch jobs recover` for one lease; the error is the tail of its stderr.
async fn recover(rch: &Path, socket: &Path, wrapper_id: &str) -> Result<(), String> {
    recover_in(rch, socket, &default_job_lease_directory(), wrapper_id).await
}

async fn recover_in(
    rch: &Path,
    socket: &Path,
    lease_dir: &Path,
    wrapper_id: &str,
) -> Result<(), String> {
    let before = read_lease(lease_dir, wrapper_id)?;
    let child = tokio::process::Command::new(rch)
        .args(["jobs", "recover", wrapper_id, "--timeout-secs"])
        .arg(RECOVER_TIMEOUT_SECS.to_string())
        .env("RCH_SOCKET_PATH", socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();
    let output = match tokio::time::timeout(RECOVER_KILL_AFTER, child).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Err(format!("cannot run {}: {error}", rch.display())),
        Err(_) => return Err(format!("timed out after {}s", RECOVER_KILL_AFTER.as_secs())),
    };
    if output.status.success() {
        let after = read_lease(lease_dir, wrapper_id)?;
        return verify_recovery_completion(&before, &after);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail: String = stderr
        .trim()
        .chars()
        .rev()
        .take(400)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Err(format!("{}: {tail}", output.status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::job_identity::JobIdentity;

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
        for (name, lease) in &leases {
            std::fs::write(
                dir.path().join(format!("{name}.json")),
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
        let mut live = pending.clone();
        live.wrapper_pid = 22;
        let mut fresh = pending.clone();
        fresh.heartbeat_unix_ms = now;
        let mut unknown = pending.clone();
        unknown.wrapper_pid = 0;
        let acknowledged = completed_lease(&pending, 102, 130);
        for (name, candidate) in [
            ("pending", &pending), ("live", &live), ("fresh", &fresh),
            ("unknown", &unknown), ("acknowledged", &acknowledged),
        ] {
            std::fs::write(dir.path().join(format!("{name}.json")), serde_json::to_vec(candidate).unwrap()).unwrap();
        }
        assert_eq!(recoverable_lease_ids(dir.path(), now, |pid| pid == 22),
            [pending.identity.local_wrapper_id.clone()]);
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
    }

    #[test]
    fn handoff_retry_keeps_existing_backoff_after_source_retirement() {
        let dir = tempfile::tempdir().unwrap();
        let now_ms = 100 * 60 * 60 * 1000;
        let pending = handoff_lease(now_ms - 30 * 60 * 1000, 11, 102);
        let id = &pending.identity.local_wrapper_id;
        std::fs::write(dir.path().join(format!("{id}.json")), serde_json::to_vec(&pending).unwrap()).unwrap();
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
        let error = recover_in(&child, &dir.path().join("unused.sock"), dir.path(), id).await.unwrap_err();
        assert!(error.contains("without durable daemon/delivery acknowledgement"));
        assert_eq!(read_lease(dir.path(), id).unwrap(), pending);

        let complete = completed_lease(&pending, 102, 130);
        let receipt = dir.path().join("completed.fixture");
        std::fs::write(&receipt, serde_json::to_vec(&complete).unwrap()).unwrap();
        // The test-owned child simulates writing the final durable journal;
        // the daemon must inspect that journal rather than its exit alone.
        std::fs::write(&child, format!("#!/bin/sh\ncp -- {} {}\n",
            shell_escape::escape(receipt.to_str().unwrap().into()),
            shell_escape::escape(path.to_str().unwrap().into()))).unwrap();
        recover_in(&child, &dir.path().join("unused.sock"), dir.path(), id).await.unwrap();
    }
}
