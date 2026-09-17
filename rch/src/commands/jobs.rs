//! Same-identity job observation and recovery. No command execution/replay path.
use crate::ui::context::OutputContext;
use anyhow::{Context, Result};
use clap::Subcommand;
use rch_common::job_identity::{DurableJobLease, default_job_lease_directory};
use serde_json::{Value, json};

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

pub(crate) fn process_matches(lease: &DurableJobLease) -> bool {
    let Some(ticks) = lease.process_start_ticks else {
        return false;
    };
    let Some(boot) = lease.boot_id.as_deref() else {
        return false;
    };
    if std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .as_deref()
        .map(str::trim)
        != Some(boot)
    {
        return false;
    }
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", lease.wrapper_pid)) else {
        return false;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|s| s.parse::<u64>().ok())
        == Some(ticks)
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
            anyhow::ensure!(
                payload["local_wrapper_id"].as_str()
                    == Some(lease.identity.local_wrapper_id.as_str()),
                "daemon completion identity mismatch"
            );
            anyhow::ensure!(
                payload["record"]["id"].as_u64() == lease.identity.remote_build_id
                    && payload["record"]["worker_id"].as_str() == lease.worker_id.as_deref(),
                "daemon completion build/worker mismatch"
            );
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

#[cfg(unix)]
async fn run_unix(action: Option<JobsAction>, ctx: &OutputContext) -> Result<()> {
    use crate::hook::DurableLeaseWriter;
    use std::time::{Duration, Instant};
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
        let status = query(&lease).await?;
        if cancel {
            let id = lease
                .identity
                .remote_build_id
                .context("job has no admitted build")?;
            anyhow::ensure!(
                status["status"] == "active",
                "daemon has no identity evidence for cancellation (status: {}); no process was signalled",
                status["status"]
            );
            let response = super::send_daemon_command(&format!(
                "POST /builds/{id}/cancel?local_wrapper_id={}\n",
                wrapper_id
            ))
            .await?;
            let body = response
                .split_once("\r\n\r\n")
                .or_else(|| response.split_once("\n\n"))
                .map(|(_, b)| b)
                .context("missing cancellation response")?;
            let reply: Value = serde_json::from_str(body)?;
            anyhow::ensure!(
                reply["status"] == "cancelled",
                "cancellation was not acknowledged: {reply}"
            );
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
            let code = tokio::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                crate::hook::recover_job(&writer),
            )
            .await
            .context("recovery timed out; journal retained for same-id retry")??;
            emit(
                ctx,
                &json!({"status":"recovered", "identity":lease.identity, "exit_code":code, "terminal_acknowledged":writer.snapshot().terminal_acknowledged}),
            );
            return Ok(());
        }
        if status["status"] == "completed" && lease.recovery.is_none() {
            let code = status["record"]["exit_code"]
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .context("completion has no exit code")?;
            writer.record_exit(code)?;
            writer.acknowledge_terminal()?;
            emit(
                ctx,
                &json!({"status":"completed", "identity":lease.identity, "exit_code":code, "terminal_acknowledged":true}),
            );
            return Ok(());
        }
        if !process_matches(&lease) {
            anyhow::bail!(
                "original wrapper is absent; use jobs recover with retained retrieval evidence (daemon status: {}); command will not be replayed",
                status["status"]
            );
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "same-id job is still pending; no command replayed (use jobs cancel or recover)"
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
