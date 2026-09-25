//! Same-identity job observation and recovery. No command execution/replay path.
use crate::ui::context::OutputContext;
use anyhow::{Context, Result};
use clap::Subcommand;
use rch_common::job_identity::{DurableJobLease, default_job_lease_directory};
use serde_json::{Value, json};
#[cfg(unix)]
use std::time::{Duration, Instant};

#[derive(Debug, Subcommand)]
pub enum JobsAction {
    /// Follow the original wrapper/result, without starting another build
    Attach {
        wrapper_id: String,
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },
    /// Cancel the exact daemon build and cooperatively stop its wrapper
    Cancel { wrapper_id: String },
    /// Reconcile completion and retrieve outstanding outputs; never replay
    Recover {
        wrapper_id: String,
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },
}

pub async fn run(action: Option<JobsAction>, ctx: &OutputContext) -> Result<()> {
    #[cfg(unix)]
    {
        run_unix(action, ctx).await
    }
    #[cfg(not(unix))]
    {
        let _ = (action, ctx);
        anyhow::bail!("durable jobs require Unix daemon IPC")
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OwnerPresence {
    Live,
    Absent,
    Unknown,
}

fn owner_from_proc_stat(stat: &str, expected_ticks: u64) -> OwnerPresence {
    let Some((_, rest)) = stat.rsplit_once(") ") else {
        return OwnerPresence::Unknown;
    };
    let mut fields = rest.split_whitespace();
    let state = fields.next();
    let Some(ticks) = fields.nth(18).and_then(|value| value.parse::<u64>().ok()) else {
        return OwnerPresence::Unknown;
    };
    if ticks != expected_ticks || matches!(state, Some("Z" | "X" | "x")) {
        return OwnerPresence::Absent;
    }
    match state {
        Some("R" | "S" | "D" | "T" | "t" | "K" | "W" | "P" | "I") => OwnerPresence::Live,
        _ => OwnerPresence::Unknown,
    }
}

fn owner_presence(lease: &DurableJobLease) -> OwnerPresence {
    let Some(ticks) = lease.process_start_ticks else {
        return OwnerPresence::Unknown;
    };
    let Some(boot) = lease.boot_id.as_deref().filter(|boot| !boot.is_empty()) else {
        return OwnerPresence::Unknown;
    };
    let Ok(current_boot) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") else {
        return OwnerPresence::Unknown;
    };
    if current_boot.trim().is_empty() {
        return OwnerPresence::Unknown;
    }
    if current_boot.trim() != boot {
        return OwnerPresence::Absent;
    }
    match std::fs::read_to_string(format!("/proc/{}/stat", lease.wrapper_pid)) {
        Ok(stat) => owner_from_proc_stat(&stat, ticks),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => OwnerPresence::Absent,
        Err(_) => OwnerPresence::Unknown,
    }
}

pub(crate) fn process_matches(lease: &DurableJobLease) -> bool {
    owner_presence(lease) == OwnerPresence::Live
}

#[cfg(unix)]
pub(crate) async fn query(lease: &DurableJobLease) -> Result<Value> {
    let id = lease
        .identity
        .remote_build_id
        .context("job was never admitted; no remote execution to attach")?;
    let response = super::send_daemon_command(&format!(
        "GET /builds/{id}?local_wrapper_id={}\n",
        lease.identity.local_wrapper_id
    ))
    .await?;
    let body = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .map(|(_, body)| body)
        .context("daemon response has no body")?;
    let payload: Value = serde_json::from_str(body)?;
    match payload.get("status").and_then(Value::as_str) {
        Some("active") => validate_identity(lease, &payload["active"])?,
        Some("completed") => {
            validate_completion(lease, &payload)?;
        }
        Some("not_found") => {}
        Some("identity_mismatch") => {
            anyhow::bail!("daemon build identity mismatch; no action taken")
        }
        _ => anyhow::bail!("daemon did not provide authoritative job status: {payload}"),
    }
    Ok(payload)
}

fn validate_identity(lease: &DurableJobLease, record: &Value) -> Result<()> {
    anyhow::ensure!(
        record.get("local_wrapper_id").and_then(Value::as_str)
            == Some(lease.identity.local_wrapper_id.as_str()),
        "daemon wrapper identity mismatch"
    );
    anyhow::ensure!(
        record.get("worker_id").and_then(Value::as_str) == lease.worker_id.as_deref(),
        "daemon worker identity mismatch"
    );
    anyhow::ensure!(
        record["id"].as_u64() == lease.identity.remote_build_id,
        "daemon build identity mismatch"
    );
    Ok(())
}

/// Completion may win before cancellation or while its request is in flight.
/// Accept only a complete receipt for the original wrapper/build/worker tuple;
/// a status string alone is not authority to stop a wrapper or retire its work.
fn validate_completion(lease: &DurableJobLease, reply: &Value) -> Result<i32> {
    anyhow::ensure!(
        reply["status"] == "completed"
            && reply["local_wrapper_id"].as_str()
                == Some(lease.identity.local_wrapper_id.as_str()),
        "daemon completion identity mismatch"
    );
    let id = lease
        .identity
        .remote_build_id
        .filter(|id| *id > 0)
        .context("completion requires an admitted build identity")?;
    let worker = lease
        .worker_id
        .as_deref()
        .filter(|worker| !worker.is_empty())
        .context("completion requires an admitted worker identity")?;
    anyhow::ensure!(
        reply["record"]["id"].as_u64() == Some(id)
            && reply["record"]["worker_id"].as_str() == Some(worker),
        "daemon completion build/worker mismatch"
    );
    reply["record"]["exit_code"]
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
        .context("completion has no valid exit code")
}

#[derive(Debug, PartialEq, Eq)]
enum AdmittedCancellation {
    StopWrapper,
    AlreadyCompleted(i32),
}

fn validate_admitted_cancellation(
    lease: &DurableJobLease,
    reply: &Value,
) -> Result<AdmittedCancellation> {
    if reply["status"] == "completed" {
        return validate_completion(lease, reply).map(AdmittedCancellation::AlreadyCompleted);
    }
    anyhow::ensure!(
        reply["status"] == "cancelled",
        "cancellation was not acknowledged: {reply}"
    );
    let id = lease
        .identity
        .remote_build_id
        .filter(|id| *id > 0)
        .context("cancellation requires an admitted build identity")?;
    let worker = lease
        .worker_id
        .as_deref()
        .filter(|worker| !worker.is_empty())
        .context("cancellation requires an admitted worker identity")?;
    anyhow::ensure!(
        reply["build_id"].as_u64() == Some(id)
            && reply["worker_id"].as_str() == Some(worker),
        "daemon cancellation build/worker mismatch; no wrapper stop requested"
    );
    // The build endpoint fences the wrapper in its request and does not
    // currently echo it. If a peer does echo it, disagreement is fatal.
    if let Some(wrapper) = reply.get("local_wrapper_id") {
        anyhow::ensure!(
            wrapper.as_str() == Some(lease.identity.local_wrapper_id.as_str()),
            "daemon cancellation wrapper identity mismatch"
        );
    }
    Ok(AdmittedCancellation::StopWrapper)
}

/// Once the original owner is positively absent, reload before reconciling:
/// it may have persisted a recovery intent or final acknowledgement while the
/// daemon status request was in flight. Never erase that newer evidence.
fn same_unfinished_owner_without_recovery(
    observed: &DurableJobLease,
    latest: &DurableJobLease,
) -> bool {
    observed.identity == latest.identity
        && observed.worker_id == latest.worker_id
        && observed.wrapper_pid == latest.wrapper_pid
        && observed.process_start_ticks == latest.process_start_ticks
        && observed.boot_id == latest.boot_id
        && latest.recovery.is_none()
        && !latest.terminal_acknowledged
}

fn completed_cancellation_report(lease: &DurableJobLease, code: i32) -> Value {
    // Remote completion is not evidence that local artifact retrieval or
    // terminal acknowledgement finished. Leave the owner's journal intact.
    json!({
        "status": "completed",
        "identity": lease.identity,
        "exit_code": code,
        "terminal_acknowledged": lease.terminal_acknowledged,
        "has_recovery_journal": lease.recovery.is_some(),
        "wrapper_stop_requested": false,
    })
}

fn validate_queued_cancellation(wrapper: &str, reply: &Value) -> Result<()> {
    anyhow::ensure!(
        reply["local_wrapper_id"].as_str() == Some(wrapper),
        "daemon cancellation wrapper identity mismatch"
    );
    match reply["status"].as_str() {
        Some("cancelled_before_start") => anyhow::ensure!(
            reply["exit_code"].as_i64() == Some(130) && reply["build_id"].is_null(),
            "invalid cancellation-before-start receipt"
        ),
        Some("cancelled") => anyhow::ensure!(
            reply["build_id"].as_u64().is_some_and(|id| id > 0),
            "admitted cancellation has no build identity"
        ),
        Some("completed") => anyhow::ensure!(
            reply["record"]["id"].as_u64().is_some_and(|id| id > 0),
            "completion has no build identity"
        ),
        _ => anyhow::bail!("cancellation was not acknowledged: {reply}"),
    }
    Ok(())
}

fn emit(ctx: &OutputContext, payload: &Value) {
    if ctx.is_json() {
        let _ = ctx.json(payload);
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(payload).unwrap_or_default()
        );
    }
}

/// A durable identity exists before the daemon admits the build. A live
/// owner in that state is still waiting, not a failed or missing remote job.
/// In particular, attach/recover must not query a nonexistent build id or
/// submit another command while admission is in progress.
fn waiting_for_admission(lease: &DurableJobLease, owner_alive: bool) -> Result<bool> {
    if lease.identity.remote_build_id.is_some() || lease.terminal_acknowledged {
        return Ok(false);
    }
    anyhow::ensure!(
        owner_alive,
        "original wrapper is absent or unverified before daemon admission; outcome remains uncertain; no command replayed"
    );
    Ok(true)
}

/// Bound the whole observation/recovery operation, not each IPC request
/// independently. An expired deadline must not even poll a mutating future.
#[cfg(unix)]
async fn within_job_deadline<T>(
    deadline: Instant,
    operation: &str,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    anyhow::ensure!(
        Instant::now() < deadline,
        "same-id job deadline elapsed before {operation}; journal retained; no command replayed"
    );
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .with_context(|| {
            format!(
                "same-id job deadline elapsed during {operation}; journal retained; no command replayed"
            )
        })?
}

#[cfg(unix)]
async fn wait_for_job_poll(deadline: Instant) -> Result<()> {
    anyhow::ensure!(
        Instant::now() < deadline,
        "same-id job is still pending; no command replayed (use jobs cancel or recover)"
    );
    // Never oversleep a short remaining budget. The next iteration can still
    // observe an already-persisted terminal acknowledgement at the boundary.
    let wake = (Instant::now() + Duration::from_secs(1)).min(deadline);
    tokio::time::sleep_until(tokio::time::Instant::from_std(wake)).await;
    Ok(())
}

#[cfg(unix)]
async fn run_unix(action: Option<JobsAction>, ctx: &OutputContext) -> Result<()> {
    use crate::hook::DurableLeaseWriter;
    let Some(action) = action else {
        let mut jobs = Vec::new();
        match std::fs::read_dir(default_job_lease_directory()) {
            Ok(entries) => {
                for entry in entries {
                    let path = entry?.path();
                    if path.extension().and_then(|v| v.to_str()) != Some("json") {
                        continue;
                    }
                    let lease: DurableJobLease = serde_json::from_slice(&std::fs::read(&path)?)?;
                    jobs.push(json!({"lease": lease, "wrapper_alive": process_matches(&lease)}));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        emit(ctx, &json!({"jobs": jobs}));
        return Ok(());
    };
    let (wrapper_id, recover, cancel, timeout_secs) = match action {
        JobsAction::Attach {
            wrapper_id,
            timeout_secs,
        } => (wrapper_id, false, false, timeout_secs),
        JobsAction::Recover {
            wrapper_id,
            timeout_secs,
        } => (wrapper_id, true, false, timeout_secs),
        JobsAction::Cancel { wrapper_id } => (wrapper_id, false, true, 30),
    };
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.min(86400));
    loop {
        let writer = DurableLeaseWriter::load(&wrapper_id)?;
        let lease = writer.snapshot();
        if lease.terminal_acknowledged {
            emit(
                ctx,
                &json!({"status":"completed", "identity":lease.identity, "exit_code":lease.exit_code, "terminal_acknowledged":true}),
            );
            return Ok(());
        }
        if !cancel && waiting_for_admission(&lease, process_matches(&lease))? {
            wait_for_job_poll(deadline).await?;
            continue;
        }
        if cancel && lease.identity.remote_build_id.is_none() {
            // Admission may win after this snapshot. The daemon serializes the
            // decision with registration and cancels that exact active build.
            let response = within_job_deadline(
                deadline,
                "queued cancellation",
                super::send_daemon_command(&format!("POST /jobs/{wrapper_id}/cancel\n")),
            )
            .await?;
            let body = response
                .split_once("\r\n\r\n")
                .or_else(|| response.split_once("\n\n"))
                .map(|(_, body)| body)
                .context("missing queued cancellation response")?;
            let reply: Value = serde_json::from_str(body)?;
            validate_queued_cancellation(&wrapper_id, &reply)?;
            if reply["status"] == "cancelled_before_start" {
                writer.record_exit(130)?;
                writer.acknowledge_terminal()?;
            } else if reply["status"] == "cancelled" {
                let mut identity = lease.identity.clone();
                identity.admit(
                    reply["build_id"]
                        .as_u64()
                        .context("missing cancelled build id")?,
                );
                let path = default_job_lease_directory().join(format!("{wrapper_id}.cancel"));
                crate::state::primitives::atomic_write(&path, &serde_json::to_vec(&identity)?)?;
            }
            emit(ctx, &reply);
            return Ok(());
        }
        let status = within_job_deadline(deadline, "job status", query(&lease)).await?;
        if cancel {
            if status["status"] == "completed" {
                let code = validate_completion(&lease, &status)?;
                emit(ctx, &completed_cancellation_report(&lease, code));
                return Ok(());
            }
            let id = lease
                .identity
                .remote_build_id
                .context("job has no admitted build")?;
            anyhow::ensure!(
                status["status"] == "active",
                "daemon has no identity evidence for cancellation (status: {}); no process was signalled",
                status["status"]
            );
            let response = within_job_deadline(
                deadline,
                "admitted cancellation",
                super::send_daemon_command(&format!(
                    "POST /builds/{id}/cancel?local_wrapper_id={}\n",
                    wrapper_id
                )),
            )
            .await?;
            let body = response
                .split_once("\r\n\r\n")
                .or_else(|| response.split_once("\n\n"))
                .map(|(_, b)| b)
                .context("missing cancellation response")?;
            let reply: Value = serde_json::from_str(body)?;
            if let AdmittedCancellation::AlreadyCompleted(code) =
                validate_admitted_cancellation(&lease, &reply)?
            {
                emit(ctx, &completed_cancellation_report(&lease, code));
                return Ok(());
            }
            // The original wrapper consumes this exact-identity receipt itself.
            // Never signal a PID obtained from a persisted lease.
            let path = default_job_lease_directory().join(format!("{wrapper_id}.cancel"));
            crate::state::primitives::atomic_write(&path, &serde_json::to_vec(&lease.identity)?)?;
            emit(
                ctx,
                &json!({"status":"cancelled", "identity":lease.identity, "wrapper_stop_requested":true}),
            );
            return Ok(());
        }
        if recover && process_matches(&lease) && lease.recovery.is_some() {
            // The live wrapper's retrieval select consumes this exact-identity
            // receipt and re-drives its interrupted retrieval itself.
            let receipt = default_job_lease_directory().join(format!("{wrapper_id}.recover"));
            if !receipt.exists() {
                crate::state::primitives::atomic_write(
                    &receipt,
                    &serde_json::to_vec(&lease.identity)?,
                )?;
                emit(
                    ctx,
                    &json!({"status":"recover_requested", "identity":lease.identity}),
                );
                return Ok(());
            }
        }
        if !process_matches(&lease) && recover && lease.recovery.is_some() {
            let code = within_job_deadline(
                deadline,
                "artifact recovery (use the retained journal for same-id retry)",
                crate::hook::recover_job(&writer),
            )
            .await?;
            emit(
                ctx,
                &json!({"status":"recovered", "identity":lease.identity, "exit_code":code, "terminal_acknowledged":writer.snapshot().terminal_acknowledged}),
            );
            return Ok(());
        }
        if status["status"] == "completed"
            && lease.recovery.is_none()
            && owner_presence(&lease) == OwnerPresence::Absent
        {
            let latest_writer = DurableLeaseWriter::load(&wrapper_id)?;
            let latest = latest_writer.snapshot();
            if !same_unfinished_owner_without_recovery(&lease, &latest) {
                wait_for_job_poll(deadline).await?;
                continue;
            }
            let code = validate_completion(&latest, &status)?;
            anyhow::ensure!(
                latest.exit_code.is_none_or(|observed| observed == code),
                "local and daemon completion disagree; no journal rewritten; no command replayed"
            );
            latest_writer.record_exit(code)?;
            latest_writer.acknowledge_terminal()?;
            emit(
                ctx,
                &json!({"status":"completed", "identity":latest.identity, "exit_code":code, "terminal_acknowledged":true}),
            );
            return Ok(());
        }
        if !process_matches(&lease) {
            anyhow::bail!(
                "original wrapper is absent or its identity cannot be verified; use jobs recover with retained retrieval evidence (daemon status: {}); command will not be replayed",
                status["status"]
            );
        }
        wait_for_job_poll(deadline).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queued_cancellation_receipt_requires_exact_identity_and_terminal_evidence() {
        let valid = json!({"status":"cancelled_before_start", "local_wrapper_id":"wrapper", "exit_code":130});
        validate_queued_cancellation("wrapper", &valid).unwrap();
        assert!(validate_queued_cancellation("other", &valid).is_err());
        for reply in [
            json!({"status":"not_queued", "local_wrapper_id":"wrapper"}),
            json!({"status":"cancelled_before_start", "local_wrapper_id":"wrapper", "exit_code":0}),
            json!({"status":"cancelled_before_start", "local_wrapper_id":"wrapper", "exit_code":130, "build_id":42}),
            json!({"status":"cancelled", "local_wrapper_id":"wrapper"}),
        ] {
            assert!(validate_queued_cancellation("wrapper", &reply).is_err());
        }
        validate_queued_cancellation(
            "wrapper",
            &json!({"status":"cancelled", "local_wrapper_id":"wrapper", "build_id":42}),
        )
        .unwrap();
    }

    #[test]
    fn mismatched_identity_cannot_authorize_action() {
        let mut lease = DurableJobLease::new(
            rch_common::job_identity::JobIdentity::new_local(),
            1,
            None,
            None,
            0,
            true,
            false,
            "hash".into(),
        );
        lease.admit(1, "worker-a".into(), 0);
        assert!(
            validate_identity(
                &lease,
                &json!({"local_wrapper_id":"other", "worker_id":"worker-a"})
            )
            .is_err()
        );
        assert!(
            validate_identity(
                &lease,
                &json!({"local_wrapper_id":lease.identity.local_wrapper_id, "worker_id":"worker-b"})
            )
            .is_err()
        );
        assert!(!process_matches(&lease));
    }

    fn queued_lease() -> DurableJobLease {
        DurableJobLease::new(
            rch_common::job_identity::JobIdentity::new_local(),
            1,
            None,
            None,
            0,
            true,
            false,
            "hash".into(),
        )
    }

    #[test]
    fn live_pre_admission_job_is_followed_until_admitted() {
        let mut lease = queued_lease();
        let wrapper = lease.identity.local_wrapper_id.clone();
        assert!(waiting_for_admission(&lease, true).unwrap());
        lease.admit(42, "worker-a".into(), 1);
        assert!(!waiting_for_admission(&lease, true).unwrap());
        assert_eq!(lease.identity.local_wrapper_id, wrapper);
        assert_eq!(lease.identity.remote_build_id, Some(42));
    }

    #[test]
    fn absent_pre_admission_owner_is_uncertain_not_replayed() {
        let error = waiting_for_admission(&queued_lease(), false).unwrap_err();
        assert!(error.to_string().contains("outcome remains uncertain"));
    }

    #[test]
    fn terminal_pre_admission_job_does_not_need_a_live_owner() {
        let mut lease = queued_lease();
        lease.acknowledge_terminal(1);
        assert!(!waiting_for_admission(&lease, false).unwrap());
    }

    #[test]
    fn admitted_job_is_reconciled_even_after_owner_disappears() {
        let mut lease = queued_lease();
        lease.admit(42, "worker-a".into(), 1);
        assert!(!waiting_for_admission(&lease, false).unwrap());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expired_job_deadline_does_not_poll_mutating_operation() {
        let polled = std::cell::Cell::new(false);
        let result = within_job_deadline(Instant::now(), "cancel", async {
            polled.set(true);
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert!(!polled.get());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn job_deadline_bounds_a_stalled_daemon_call() {
        let result = within_job_deadline(
            Instant::now() + Duration::from_millis(10),
            "job status",
            std::future::pending::<Result<()>>(),
        )
        .await;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("deadline elapsed during job status"));
        assert!(error.contains("journal retained"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn job_deadline_preserves_completed_results_and_inner_errors() {
        let deadline = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            within_job_deadline(deadline, "status", async { Ok(42) })
                .await
                .unwrap(),
            42
        );
        let error: Result<()> = within_job_deadline(deadline, "status", async {
            anyhow::bail!("identity mismatch")
        })
        .await;
        assert_eq!(error.unwrap_err().to_string(), "identity mismatch");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expired_poll_budget_is_an_error() {
        assert!(wait_for_job_poll(Instant::now()).await.is_err());
    }

    fn admitted_lease() -> DurableJobLease {
        let mut lease = queued_lease();
        lease.admit(42, "worker-a".into(), 1);
        lease
    }

    fn completion(lease: &DurableJobLease, code: i32) -> Value {
        json!({
            "status": "completed",
            "local_wrapper_id": lease.identity.local_wrapper_id,
            "record": {"id": 42, "worker_id": "worker-a", "exit_code": code},
        })
    }

    #[test]
    fn cancellation_accepts_same_identity_completion_without_a_stop_receipt() {
        let lease = admitted_lease();
        for code in [0, 1, 101, 102, 130, 137] {
            assert_eq!(
                validate_admitted_cancellation(&lease, &completion(&lease, code)).unwrap(),
                AdmittedCancellation::AlreadyCompleted(code)
            );
        }
    }

    #[test]
    fn cancellation_completion_does_not_claim_artifacts_or_retire_the_journal() {
        let mut lease = admitted_lease();
        lease.recovery = Some(json!({"retired": false}));
        let before = lease.clone();
        let report = completed_cancellation_report(&lease, 0);
        assert_eq!(report["exit_code"], 0);
        assert_eq!(report["terminal_acknowledged"], false);
        assert_eq!(report["has_recovery_journal"], true);
        assert_eq!(report["wrapper_stop_requested"], false);
        assert_eq!(lease, before);
    }

    #[test]
    fn cancellation_completion_rejects_missing_or_foreign_identity_components() {
        let lease = admitted_lease();
        for pointer in ["/local_wrapper_id", "/record/id", "/record/worker_id"] {
            let mut reply = completion(&lease, 0);
            *reply.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(validate_admitted_cancellation(&lease, &reply).is_err());
        }
        for (pointer, wrong) in [
            ("/local_wrapper_id", json!("different-wrapper")),
            ("/record/id", json!(43)),
            ("/record/worker_id", json!("worker-b")),
        ] {
            let mut reply = completion(&lease, 0);
            *reply.pointer_mut(pointer).unwrap() = wrong;
            assert!(validate_admitted_cancellation(&lease, &reply).is_err());
        }
    }

    #[test]
    fn completion_requires_a_representable_exit_code() {
        let lease = admitted_lease();
        for code in [Value::Null, json!("0"), json!(i64::MAX), json!(0.5)] {
            let mut reply = completion(&lease, 0);
            reply["record"]["exit_code"] = code;
            assert!(validate_completion(&lease, &reply).is_err());
        }
    }

    #[test]
    fn stopped_wrapper_requires_exact_admitted_build_and_worker_receipt() {
        let lease = admitted_lease();
        let valid = json!({"status": "cancelled", "build_id": 42, "worker_id": "worker-a"});
        assert_eq!(
            validate_admitted_cancellation(&lease, &valid).unwrap(),
            AdmittedCancellation::StopWrapper
        );
        for reply in [
            json!({"status": "cancelled"}),
            json!({"status": "cancelled", "build_id": 43, "worker_id": "worker-a"}),
            json!({"status": "cancelled", "build_id": 42, "worker_id": "worker-b"}),
            json!({"status": "cancelled", "build_id": 42}),
            json!({"status": "not_found", "build_id": 42, "worker_id": "worker-a"}),
            json!({"status": "error", "build_id": 42, "worker_id": "worker-a"}),
            json!({"status": "cancelled_before_start", "local_wrapper_id": lease.identity.local_wrapper_id, "exit_code": 130}),
            json!({"status": "cancelled", "build_id": 42, "worker_id": "worker-a", "local_wrapper_id": "different-wrapper"}),
        ] {
            assert!(validate_admitted_cancellation(&lease, &reply).is_err());
        }
    }

    #[test]
    fn cancellation_cannot_invent_an_admitted_identity() {
        let lease = queued_lease();
        let reply = json!({"status": "cancelled", "build_id": 42, "worker_id": "worker-a"});
        assert!(validate_admitted_cancellation(&lease, &reply).is_err());
        let mut lease = admitted_lease();
        lease.worker_id = None;
        assert!(validate_admitted_cancellation(&lease, &reply).is_err());
    }

    fn proc_stat(state: &str, ticks: u64) -> String {
        // Fields 3 (state) through 22 (starttime); the command deliberately
        // contains spaces and parentheses, so splitting at the first ')' fails.
        format!("123 (rch (wrapper)) {state} {} {ticks}", vec!["0"; 18].join(" "))
    }

    #[test]
    fn owner_observation_distinguishes_live_dead_reused_and_unknown() {
        assert_eq!(owner_from_proc_stat(&proc_stat("S", 42), 42), OwnerPresence::Live);
        for state in ["Z", "X", "x"] {
            assert_eq!(owner_from_proc_stat(&proc_stat(state, 42), 42), OwnerPresence::Absent);
        }
        assert_eq!(owner_from_proc_stat(&proc_stat("R", 43), 42), OwnerPresence::Absent);
        assert_eq!(owner_from_proc_stat(&proc_stat("?", 42), 42), OwnerPresence::Unknown);
        assert_eq!(owner_from_proc_stat("unreadable or truncated", 42), OwnerPresence::Unknown);
        assert_eq!(owner_presence(&queued_lease()), OwnerPresence::Unknown);
    }

    #[test]
    fn reconciliation_reloads_and_preserves_newer_owner_evidence() {
        let observed = admitted_lease();
        assert!(same_unfinished_owner_without_recovery(&observed, &observed));
        let mut latest = observed.clone();
        latest.recovery = Some(json!({"retired": false}));
        assert!(!same_unfinished_owner_without_recovery(&observed, &latest));
        latest = observed.clone();
        latest.acknowledge_terminal(2);
        assert!(!same_unfinished_owner_without_recovery(&observed, &latest));
        latest = observed.clone();
        latest.identity.admit(43);
        assert!(!same_unfinished_owner_without_recovery(&observed, &latest));
        latest = observed.clone();
        latest.wrapper_pid += 1;
        assert!(!same_unfinished_owner_without_recovery(&observed, &latest));
    }
}
