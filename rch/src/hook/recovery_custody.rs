//! Final handoff of disposable evidence from one uninterrupted live wrapper.
//!
//! Retirement releases worker resources, not every local recovery obligation.
//! Only the creator can also prove it never retained an earlier journal epoch.
//! Recovered, retried and legacy jobs keep their existing evidence indefinitely.

use super::{DurableJobLease, decode_recipe_value, recovery_completion, recovery_owner};
use anyhow::{Context, Result, ensure};
use rch_common::job_identity::{JobLeaseCustodyRelease, JobLeasePayload};
use std::path::Path;

pub(in crate::hook) fn completed_custody_release(
    lease: &DurableJobLease,
    journal_path: &Path,
    owner: &recovery_owner::RecoveryOwnership,
) -> Result<Option<JobLeaseCustodyRelease>> {
    if !owner.has_fresh_custody() || !lease.terminal_acknowledged || lease.exit_code != Some(0) {
        return Ok(None);
    }
    let Some(value) = &lease.recovery else {
        // The existing no-recipe history policy already covers these jobs.
        return Ok(None);
    };
    owner.verify()?;
    let recipe = decode_recipe_value(value.clone(), Some(owner))?;
    // Explicit caller JSON promises replay of the first reply, including
    // after a broken stdout pipe. Terminal accounting does not acknowledge
    // that the caller consumed it; retain that distinct custody obligation.
    if recipe.caller_json_policy.is_some() || recipe.caller_delivery.is_some() {
        return Ok(None);
    }
    recovery_completion::validate_successful_delivery(&recipe)?;
    ensure!(
        recipe.wrapper_id == lease.identity.local_wrapper_id
            && Some(recipe.build_id) == lease.identity.remote_build_id
            && lease.worker_id.as_deref() == Some(recipe.worker.id.as_str())
            && (recipe.exit_code == Some(0)
                || (recipe.source_sync.is_some() && recipe.exit_code.is_none()))
            && recipe.returned == Some(0)
            && recipe.retired
            && recipe.source_resources_retired()
            && !recipe.retain_staging_evidence()
            && recipe.phases.iter().all(|phase| {
                phase.complete && phase.pending.is_none() && phase.missing_result.is_none()
            }),
        "final custody release requires complete same-admission successful retirement"
    );
    ensure!(
        recipe.source_sync.is_some()
            || (recipe.staging_ownership.is_some() && recipe.staging_released),
        "unowned or unreleased retrieval staging retains its recovery index"
    );
    // A future/unknown field could carry another custody obligation. Do not
    // grant deletion authority by silently dropping it during typed decode.
    ensure!(
        recipe.storage_value()? == *value,
        "unrecognized or uncommitted recovery evidence retains custody"
    );

    let parent = journal_path.parent().context("job journal has no parent")?;
    let mut payloads = Vec::new();
    if let Some(stdout) = &recipe.cargo_stdout {
        payloads.push(local_payload(
            parent,
            &stdout.path,
            stdout.bytes,
            &stdout.blake3,
        )?);
    }
    if let Some(stderr) = &recipe.cargo_stderr {
        payloads.push(local_payload(
            parent,
            &stderr.path,
            stderr.bytes,
            &stderr.blake3,
        )?);
    }
    let directory = owner.publication_directory()?;
    for phase in &recipe.phases {
        if let Some(journal) = &phase.publication_journal {
            payloads.push(journal.released_payload(directory)?);
        }
    }
    let receipt = JobLeaseCustodyRelease {
        version: 1,
        recovery_blake3: blake3::hash(&serde_json::to_vec(value)?)
            .to_hex()
            .to_string(),
        payloads,
    };
    receipt.validate_for(lease)?;
    owner.verify()?;
    Ok(Some(receipt))
}

fn local_payload(parent: &Path, path: &Path, bytes: u64, hash: &str) -> Result<JobLeasePayload> {
    // The common receipt validator also requires a canonical, wrapper-bound
    // role/UUID filename. No absolute path reaches the daemon's unlink helper.
    ensure!(
        path.parent() == Some(parent),
        "retained payload is outside the held lease directory"
    );
    Ok(JobLeasePayload {
        name: path
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid retained payload name")?
            .to_owned(),
        bytes,
        blake3: hash.to_owned(),
    })
}
