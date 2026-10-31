//! Bounded alternate-worker placement before the compiler execution frontier.
//!
//! A single producer retains its input bytes, action claim and subscriber
//! cohort. Only the actual transport's typed interruption plus no-execution
//! evidence permits another worker. Admitted attempts keep the same actor and
//! generation, with the old lease/session explicitly released before a Retry.

use super::{
    AdmittedRemote, ExecutionAttempt, LiveDependencyLane, LiveDependencyRequest, LiveWorkerSession,
    OperationCancellation, PoolReservation, RemoteDependencies, RemoteInvocation, RemoteValidation,
    RetainedToolchain, SourceUpload, WorkerSessionOffer, dependency_execution_request, recovery,
    verify_request,
};
use crate::coord::action_actor::{AttemptPurpose, MAX_RETRIES_PER_GENERATION};
use crate::coord::worker_delivery::{Delivery, DeliveryFailure};
use serde_json::Value;
use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};

/// Field order is ownership order: release the admitted action/session and
/// private delivery custody before returning physical capacity to the pool.
pub(super) struct Completed {
    pub(super) owned: AdmittedRemote,
    pub(super) directory: recovery::ResultDirectory,
    pub(super) delivery: Delivery,
    pub(super) wire: Value,
    _reservation: PoolReservation,
}

fn may_retry(failure: &DeliveryFailure, cancelled: bool, remaining: u32) -> bool {
    remaining != 0 && !cancelled && failure.transport_interrupted && !failure.execution_may_have_run
}

fn settled_failure(owned: &mut Option<AdmittedRemote>, reason: String) -> (String, bool) {
    if let Some(owned) = owned
        && let Err(error) = owned.settle_checked()
    {
        return (
            format!("{reason}; remote ownership retirement: {error}"),
            false,
        );
    }
    (reason, true)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn deliver(
    lane: &LiveDependencyLane,
    request: &LiveDependencyRequest,
    remote: &RemoteDependencies,
    invocation: &RemoteInvocation,
    retained: &RetainedToolchain,
    mut upload: SourceUpload,
    mut reservation: PoolReservation,
    cancellation: OperationCancellation,
) -> Result<Completed, (String, bool)> {
    let source_manifest = upload.wire_manifest();
    let mut toolchain_attached = false;
    let mut attempted = HashSet::new();
    let mut remaining = MAX_RETRIES_PER_GENERATION;
    let mut lineage = None;
    loop {
        if cancellation.is_cancelled() {
            return Err(settled_failure(
                &mut lineage,
                "remote execution cancelled before worker placement".into(),
            ));
        }
        verify_request(request)
            .and_then(|()| {
                // The caller validated the initial complete runtime/toolchain
                // before preparing this upload. Recheck it after a failed
                // transport; never refresh bytes or substitute a newer key.
                if attempted.is_empty() {
                    Ok(())
                } else {
                    invocation.validation.verify(request)
                }
            })
            .map_err(|reason| settled_failure(&mut lineage, reason))?;
        let mut directory = recovery::ResultDirectory::new(&remote.state)
            .map_err(|error| settled_failure(&mut lineage, error.to_string()))?;
        let destination = directory.path().join("delivery");
        let request_id = reservation.allocate_request_id().map_err(|error| {
            settled_failure(&mut lineage, format!("allocate worker request: {error}"))
        })?;
        let wire = dependency_execution_request(
            &request.plan,
            &invocation.argv,
            &invocation.context,
            source_manifest.clone(),
            retained.image().identity(),
            request_id,
        )
        .map_err(|reason| settled_failure(&mut lineage, reason))?;
        if !toolchain_attached {
            upload = retained.attach(upload, &wire).map_err(|error| {
                settled_failure(&mut lineage, format!("prepare worker upload: {error}"))
            })?;
            toolchain_attached = true;
        }
        // Every worker has its own durable request high-water mark. Preserve
        // each exact request in a fresh directory before any execution write;
        // a failed request is never rebound or overwritten for another worker.
        directory
            .record_request(
                &wire,
                &rabs_cas::metadata_store::digest_key(&request.key.action_key),
                &reservation.worker_configuration(invocation.context.version()),
            )
            .map_err(|error| {
                settled_failure(
                    &mut lineage,
                    format!("persist remote recovery request: {error}"),
                )
            })?;
        let selected = reservation.worker().to_owned();
        attempted.insert(selected.clone());
        // The outer Arc keeps a retry-ready owner even if this connection
        // fails before invoking its FnOnce admission callback. The callback
        // alone must never own and prematurely drop the action lineage.
        let owner = Arc::new(Mutex::new(lineage.take()));
        let admitted_owner = Arc::clone(&owner);
        let admitted_lane = lane.clone();
        let admitted_request = request.clone();
        let validation = invocation.validation.clone();
        let admitted_worker = selected.clone();
        let outcome = reservation.execute(
            &wire,
            &upload,
            &destination,
            cancellation.clone(),
            move |worker| {
                admit(
                    &admitted_owner,
                    &admitted_lane,
                    admitted_request,
                    validation,
                    &admitted_worker,
                    worker,
                )
            },
        );
        let mut owned = owner
            .lock()
            .map_err(|_| ("remote attempt owner poisoned".to_owned(), false))?
            .take();
        match outcome {
            Ok(delivery) => {
                let owned = owned
                    .ok_or_else(|| ("delivery has no live admitted attempt".to_owned(), false))?;
                return Ok(Completed {
                    owned,
                    directory,
                    delivery,
                    wire,
                    _reservation: reservation,
                });
            }
            Err(failure) => {
                if let Some(owned) = owned.as_mut()
                    && !owned.retry_admission_failed
                {
                    owned.execution_finished = !failure.execution_may_have_run;
                }
                if failure.execution_may_have_run {
                    return Err((
                        format!(
                            "{}; retained remote recovery directory: {}",
                            failure.detail,
                            directory.path().display(),
                        ),
                        false,
                    ));
                }
                directory.execution_finished();
                if !may_retry(&failure, cancellation.is_cancelled(), remaining) {
                    return Err(settled_failure(&mut owned, failure.detail));
                }
                if let Some(owned) = owned.as_mut() {
                    owned.prepare_retry().map_err(|error| {
                        (
                            format!("{}; remote retry retirement: {error}", failure.detail),
                            false,
                        )
                    })?;
                }
                // prepare_retry checked the exact prior lease and session.
                // Their release must precede the physical pool notification.
                drop(reservation);
                if cancellation.is_cancelled() {
                    return Err(settled_failure(
                        &mut owned,
                        "remote execution cancelled before alternate worker placement".into(),
                    ));
                }
                let next = remote
                    .workers
                    .try_reserve_worker_excluding(&attempted)
                    .map_err(|error| {
                        settled_failure(
                            &mut owned,
                            format!("{}; no ready alternate worker: {error}", failure.detail),
                        )
                    })?;
                let key = rabs_cas::metadata_store::digest_key(&request.key.action_key);
                crate::edge::server::log_line(
                    "rabsd-remote-dependency-failover",
                    &[
                        ("key", &key),
                        ("failed_worker_id", &selected),
                        ("next_worker_id", next.worker()),
                        ("reason", &failure.detail),
                    ],
                );
                remaining -= 1;
                lineage = owned;
                reservation = next;
            }
        }
    }
}

fn admit(
    owner: &Mutex<Option<AdmittedRemote>>,
    lane: &LiveDependencyLane,
    request: LiveDependencyRequest,
    validation: RemoteValidation,
    selected: &str,
    worker: &WorkerSessionOffer,
) -> io::Result<()> {
    let (admission, started) = lane
        .coord
        .admit_worker_session(worker)
        .map_err(io::Error::other)?;
    let started = started.ok_or_else(|| {
        io::Error::other(format!("live worker session not admitted: {admission:?}"))
    })?;
    let session = LiveWorkerSession {
        coord: Arc::clone(&lane.coord),
        offer: worker.clone(),
        started,
        released: false,
    };
    let mut slot = owner
        .lock()
        .map_err(|_| io::Error::other("remote attempt owner poisoned"))?;
    if let Some(owned) = slot.as_mut() {
        // A failed transition must retain the old authority as unresolved;
        // no-execution evidence for this connection cannot repair it.
        owned.retry_admission_failed = true;
        if owned.session.is_some() || !owned.execution_finished {
            return Err(io::Error::other(
                "remote retry still owns a prior worker session",
            ));
        }
        owned.session = Some(session);
        let attempt = owned
            .attempt
            .as_mut()
            .ok_or_else(|| io::Error::other("remote retry lost its action owner"))?;
        if let Err(reason) = attempt.retry_on(worker) {
            let settleable = attempt.retry_is_settleable();
            owned
                .session
                .as_mut()
                .expect("new admitted worker session")
                .release_checked()
                .map_err(|error| {
                    io::Error::other(format!("{reason}; retry session release: {error}"))
                })?;
            owned.session = None;
            owned.retry_admission_failed = !settleable;
            return Err(io::Error::other(reason));
        }
        owned.retry_admission_failed = false;
        owned.execution_finished = false;
    } else {
        let attempt = lane
            .begin_execution_on(request, worker, Some(validation))
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another subscriber owns the remote action",
                )
            })?;
        *slot = Some(AdmittedRemote {
            attempt: Some(attempt),
            session: Some(session),
            execution_finished: false,
            retry_admission_failed: false,
        });
    }
    let attempt = slot
        .as_ref()
        .and_then(|owned| owned.attempt.as_ref())
        .ok_or_else(|| io::Error::other("admitted remote action owner missing"))?;
    log_admission(lane, attempt, selected)
}

fn log_admission(
    lane: &LiveDependencyLane,
    attempt: &ExecutionAttempt,
    selected: &str,
) -> io::Result<()> {
    let authority = attempt
        .authority
        .as_ref()
        .ok_or_else(|| io::Error::other("admitted remote authority missing"))?;
    let actor = lane
        .coord
        .submitted_actor(&authority.action_key)
        .map_err(|error| io::Error::other(format!("admitted remote actor: {error:?}")))?
        .ok_or_else(|| io::Error::other("admitted remote actor missing"))?;
    let purpose = actor
        .attempts()
        .find(|entry| entry.attempt == authority.attempt_id)
        .map(|entry| entry.purpose)
        .ok_or_else(|| io::Error::other("admitted remote attempt missing from its actor"))?;
    let purpose = match purpose {
        AttemptPurpose::Primary => "primary",
        AttemptPurpose::Retry => "retry",
        _ => return Err(io::Error::other("unexpected live remote attempt purpose")),
    };
    let key = rabs_cas::metadata_store::digest_key(&authority.action_key);
    let generation = format!("{:032x}", authority.action_generation.generation_id.0);
    let attempt_id = format!("{:032x}", authority.attempt_id.0);
    let lease = format!("{:032x}", authority.execution_lease_id.0);
    crate::edge::server::log_line(
        "rabsd-remote-dependency-admitted",
        &[
            ("key", &key),
            ("worker_id", selected),
            ("worker_spki_sha256", &authority.worker_peer_id.0),
            ("generation_id", &generation),
            ("attempt_id", &attempt_id),
            ("execution_lease_id", &lease),
            ("purpose", purpose),
        ],
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coord::worker_delivery::{transport_interrupted, worker_transport_error};
    use std::path::PathBuf;

    #[test]
    fn unmarked_errors_partial_dispatch_cancellation_and_exhaustion_cannot_retry() {
        // Exercise the actual transport provenance marker. These error inputs
        // are policy fixtures, never claimed TLS or compiler executions.
        let interrupted = || io::Error::new(io::ErrorKind::TimedOut, "worker connection timeout");
        let failure = |error: io::Error| DeliveryFailure {
            directory: PathBuf::from("/private/attempt"),
            execution_may_have_run: false,
            transport_interrupted: transport_interrupted(&error),
            detail: error.to_string(),
        };
        assert!(!may_retry(
            &failure(interrupted()),
            false,
            MAX_RETRIES_PER_GENERATION
        ));
        let mut before_dispatch = failure(worker_transport_error(interrupted()));
        assert!(may_retry(
            &before_dispatch,
            false,
            MAX_RETRIES_PER_GENERATION
        ));
        assert!(!may_retry(
            &before_dispatch,
            true,
            MAX_RETRIES_PER_GENERATION
        ));
        assert!(!may_retry(&before_dispatch, false, 0));
        before_dispatch.execution_may_have_run = true;
        assert!(!may_retry(
            &before_dispatch,
            false,
            MAX_RETRIES_PER_GENERATION
        ));
    }
}
