//! Recover an owned, complete LOCAL delivery without opening a worker connection.
//!
//! A receiver may have acknowledged the worker before output installation or
//! daemon completion persistence fails. Downloading again then cannot recover
//! the only remaining bytes. This path reuses the ordinary verifier/installer,
//! but never calls a transport, reads the old bundle, or queues an execution.
//! A durable linear claim excludes concurrent recovery and reserves uncertainty
//! across crashes. Offline verification does not manufacture a remote release ACK.

use super::{
    OperationClaim, OperationOutcome, OperationState, OperationStatus, PreparedOperationStore,
    StoredMode, MAX_RUNNING, invalid, ordinary_directory, overlap, path_shape, require, valid_id,
};
use crate::coord::delivery_recovery::{DeliveryTrust, install_delivery_outputs, recover_existing_delivery};
use crate::coord::secure_worker_delivery::{OperationCancellation, parse_worker_pin};
use serde_json::{Value, json};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

impl PreparedOperationStore {
    /// Reverify a delivery already owned by this job and finish its installation.
    /// Run on the bounded filesystem lane, never the reactor or control lane.
    /// The saved request/pin and output destination remain fixed. No fallback
    /// exists when local bytes are absent, corrupt, or conflict with the output.
    pub fn recover_local(self: &Arc<Self>, id: &str, delivery: PathBuf) -> io::Result<OperationStatus> {
        let (claim, acceptance_confirmed) = self.claim_local(id, delivery)?;
        match local_result(&claim, acceptance_confirmed) {
            Ok(result) => claim.finish(OperationOutcome::Completed { result }),
            Err(error) => {
                // Persist the failed local attempt before reporting it. This
                // failure says nothing new about the original compiler's run.
                claim.finish(OperationOutcome::Failed {
                    detail: format!("local recovery: {error}"),
                    execution_may_have_run: true,
                })?;
                Err(error)
            }
        }
    }

    /// Mark Running BEFORE any filesystem access or installation. Unlike a
    /// resume, local recovery is never Queued: no daemon executor may interpret
    /// it as permission to contact a worker. The same linear owner/Drop path
    /// used by network operations fences panic, cancellation and daemon loss.
    pub(super) fn claim_local(
        self: &Arc<Self>, id: &str, delivery: PathBuf,
    ) -> io::Result<(OperationClaim, bool)> {
        require(valid_id(id) && path_shape(&delivery), "invalid local recovery identity or path")?;
        let mut state = self.lock_state()?;
        require(state.accepting, "prepared operation service is stopping")?;
        require(state.active.len() < MAX_RUNNING, "prepared operation capacity exhausted")?;
        require(!state.active.contains_key(id), "operation already has an active owner")?;
        let mut record = self.read_record(&state, id)?
            .ok_or_else(|| invalid("unknown prepared operation"))?;
        require(record.execution_may_have_run && matches!(record.state,
            OperationState::Uncertain | OperationState::Completed | OperationState::Cancelled),
            "local recovery requires a previously dispatched execution")?;
        require(delivery == record.delivery || record.prior_deliveries.contains(&delivery),
            "local recovery requires a delivery already owned by this job")?;
        // Membership is checked before traversing a caller-supplied path.
        // A bad preflight cannot turn this API into arbitrary file inspection.
        for other in state.records.values().filter(|other| other.spec.id != id) {
            if state.active.contains_key(&other.spec.id) {
                require(other.paths().iter().all(|path|
                    !overlap(&delivery, path) && !overlap(&record.spec.output, path)),
                    "local recovery paths overlap an active operation")?;
            }
        }
        // An archived record owns the same paths but no live memory slot.
        // Restore only after all eligibility checks, under this same lock, and
        // before either Running persistence or an installation can occur.
        self.restore_record(&mut state, &record)?;
        // Keep proven acceptance only for this exact recorded delivery. A local
        // receipt by itself cannot prove the worker received its release ACKs.
        let acceptance_confirmed = record.delivery == delivery
            && record.acknowledgments_confirmed == Some(true);
        if record.delivery != delivery {
            record.prior_deliveries.retain(|path| path != &delivery);
            record.prior_deliveries.push(record.delivery.clone());
            record.delivery = delivery;
        }
        record.attempt = record.attempt.checked_add(1)
            .ok_or_else(|| invalid("operation attempts exhausted"))?;
        record.state = OperationState::Running;
        record.mode = StoredMode::LocalRecovery;
        record.resume_from = None;
        record.listen_address = None;
        record.cancel_requested = false;
        record.detail = None;
        // A different owned directory does not inherit the current one's ACK.
        if !acceptance_confirmed { record.acknowledgments_confirmed = None; }
        let cancellation = OperationCancellation::default();
        let mut spec = record.spec.clone();
        spec.delivery = record.delivery.clone();
        self.replace(&mut state, record.clone())?;
        state.active.insert(id.to_owned(), cancellation.clone());
        Ok((OperationClaim {
            store: Arc::clone(self), spec, request: record.request,
            mode: StoredMode::LocalRecovery, resume_from: None,
            attempt: record.attempt, cancellation, finished: false,
            preview: None,
        }, acceptance_confirmed))
    }
}

fn checkpoint(claim: &OperationClaim) -> io::Result<()> {
    if claim.cancellation().is_cancelled() {
        Err(io::Error::new(io::ErrorKind::Interrupted, "local recovery cancelled; original execution remains unchanged"))
    } else {
        Ok(())
    }
}

fn local_result(claim: &OperationClaim, acceptance_confirmed: bool) -> io::Result<Value> {
    checkpoint(claim)?;
    let spec = claim.spec();
    ordinary_directory(&spec.delivery, false)?;
    ordinary_directory(&spec.output, true)?;
    let trust = DeliveryTrust::PinnedWorker(parse_worker_pin(&spec.worker_spki_sha256)?);
    let mut delivery = recover_existing_delivery(claim.request(), &spec.worker, &spec.delivery, trust)
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("owned delivery is missing; local recovery never downloads or executes"))?;
    {
        let state = claim.store.lock_state()?;
        let recorded = claim.current(&state)?;
        if let Some(exit_code) = recorded.exit_code {
            require(delivery.receipt["exit_code"].as_i64() == Some(i64::from(exit_code))
                && delivery.receipt["stop_reason"].as_str() == recorded.stop_reason.as_deref(),
                "local delivery contradicts the previously recorded compiler outcome")?;
        }
    }
    checkpoint(claim)?;
    let installed = if delivery.receipt["exit_code"] == 0 && delivery.receipt["stop_reason"].is_null() {
        Some(install_delivery_outputs(claim.request(), &spec.worker, &spec.delivery, &spec.output, trust)
            .map_err(io::Error::other)?.to_json())
    } else {
        None
    };
    // Do not turn cancellation arriving AFTER successful installation into an
    // invented cancelled compiler. Return the observed original result. Kernel
    // filesystem calls are not claimed interruptible; accepted writers drain.
    delivery.acknowledgments_confirmed = acceptance_confirmed;
    delivery.acknowledgment_error = if acceptance_confirmed {
        None
    } else {
        Some("local recovery did not contact the worker; release acceptance remains unconfirmed".to_owned())
    };
    Ok(json!({
        "kind":"worker-build", "operation":"recover-local", "bundle":spec.bundle,
        "delivery":delivery.to_json(), "installed_outputs":installed,
        "publication_authorized":false, "reexecute":false,
    }))
}
