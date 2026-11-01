//! Two-phase delivery of an already committed result. One full destination
//! reservation covers both phases. Cached delivery spends one durable replay
//! admission; a current published producer spends none. The metadata callback
//! runs without the store lock, before bulk outputs are even staged.

use super::{
    CoordLive, ReplayInstallPermit, ServeError, ServeOutcome, declare_coordinator_domains,
    live_producer_gate, live_replay_gate_for_install, live_replay_permit_or_continuation,
    output_install, workspace_ancestors,
};
use crate::edge::live_facts::digest_stable;
use rabs_cas::materialization::staged::SelectedActionOutputs;
use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};
use rabs_cas::publication::authority_digest;
use rabs_cas::serving_sample_gate::SamplingPolicy;
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_protocol::authority::CoordinatorAuthority;
use rabs_protocol::release_authorization::authorization as release_standing;
use rabs_protocol::result_identity::{OutputRole, TypedDigest};
use std::path::PathBuf;
use std::time::Instant;

#[cfg(test)]
mod tests;

pub(super) type MetadataCallback<'a> = dyn FnMut(&[PathBuf]) -> Result<(), String> + 'a;

pub(super) struct CommittedResult<'manifest, 'callback, 'env> {
    pub(super) manifest_key: &'manifest str,
    pub(super) metadata_ready: Option<&'callback mut MetadataCallback<'env>>,
}

/// Immutable identity of this installation; mutable admission is re-read at
/// each phase. Elapsed wall time counts toward release/serving expiry.
pub(super) struct InstallContext<'a> {
    pub(super) action: &'a TypedDigest,
    pub(super) manifest_key: &'a str,
    pub(super) authority: Option<&'a CoordinatorAuthority>,
    pub(super) now_unix_micros: i64,
    pub(super) now_epoch: u64,
    pub(super) started: Instant,
    pub(super) sampling: Option<SamplingPolicy>,
    pub(super) producer: bool,
}

impl InstallContext<'_> {
    pub(super) fn recheck(
        &self,
        coord: &CoordLive,
        store: &mut dyn RabsMetadataStore,
        continuing: Option<&ReplayInstallPermit>,
    ) -> Result<Option<ServeOutcome>, ServeError> {
        declare_coordinator_domains(store);
        if let Some(held) = self.authority {
            if !coord.available() {
                return Err(ServeError::CoordinatorUnavailable);
            }
            match store.active_authority().map_err(store_error)? {
                Some(active) if active.digest == authority_digest(held) => {}
                _ => return Err(ServeError::CoordinatorUnavailable),
            }
        }
        let now = self
            .now_unix_micros
            .saturating_add(i64::try_from(self.started.elapsed().as_micros()).unwrap_or(i64::MAX));
        let standing = release_standing(
            store
                .release_verdict(&coord.build_identity)
                .map_err(store_error)?
                .as_ref(),
            &coord.build_identity,
            now,
            self.now_epoch,
        );
        if !standing.permits_serving(coord.release_mode) {
            return Ok(Some(ServeOutcome::ReleaseUnauthorized { standing }));
        }
        match serving_gate(store, &digest_key(self.action), now, self.now_epoch)
            .map_err(store_error)?
        {
            ServeDecision::Servable => {}
            decision => return Ok(Some(ServeOutcome::NotServable(decision))),
        }
        if let Some(policy) = self.sampling
            && let Some(refusal) =
                live_replay_gate_for_install(store, self.action, &policy, continuing)
                    .map_err(store_error)?
        {
            return Ok(Some(ServeOutcome::ExecutePrivately(refusal)));
        }
        if self.producer
            && let Some(refusal) = live_producer_gate(store, self.action).map_err(store_error)?
        {
            return Ok(Some(ServeOutcome::ExecutePrivately(refusal)));
        }
        if let Err(reason) =
            workspace_ancestors::check_serving(store, self.action, now, self.now_epoch)
        {
            return Ok(Some(ServeOutcome::ExecutePrivately(
                super::ReplayRefusal::CommittedDependency(reason),
            )));
        }
        match store
            .published_manifest_key(self.action)
            .map_err(store_error)?
        {
            Some(current) if current == self.manifest_key => Ok(None),
            Some(current) => Ok(Some(ServeOutcome::ManifestUnavailable { key: current })),
            None => Ok(Some(ServeOutcome::NoCommit)),
        }
    }
}

fn store_error(error: rabs_cas::metadata_store::StoreError) -> ServeError {
    ServeError::Store(format!("{error:?}"))
}

/// Preserve the installed delivery frontier, including a partially installed
/// tail. No post-metadata failure may be represented as an unwritten decline.
pub(super) fn exposed_failure(files: &[PathBuf], error: ServeError) -> ServeError {
    if matches!(error, ServeError::MetadataExposed { .. }) {
        return error;
    }
    let mut installed = files.to_vec();
    if let ServeError::Materialize(failure) = &error {
        installed.extend(
            failure
                .installed
                .iter()
                .map(|output| output.destination.clone()),
        );
    }
    ServeError::MetadataExposed {
        installed,
        reason: error.to_string(),
    }
}

/// Revalidate the complete installed head while the destination reservation is
/// still held. A metadata ACK or slow archive copy can outlive the files that
/// were verified before notification. Dep-info uses its exact prepared bytes,
/// including subscriber derivation; metadata keeps its committed object digest.
/// This performs stable reads outside the store lock and grants no authority.
pub(super) fn verify_installed_head(
    plan: &output_install::PreparedOutputs,
    installed: &[PathBuf],
) -> Result<(), ServeError> {
    output_install::verify_installed_dep_info(plan, installed)?;
    for output in plan
        .outputs
        .iter()
        .filter(|output| output.role == OutputRole::ProvisionalMetadata)
    {
        let failure = |reason: String| ServeError::Preparation {
            path: output.destination.to_string_lossy().into_owned(),
            reason,
        };
        if !installed.contains(&output.destination) {
            return Err(failure("metadata is absent from the installed head".into()));
        }
        let (_, digest) =
            digest_stable(&output.destination).map_err(|error| failure(error.to_string()))?;
        if digest != output.object {
            return Err(failure(
                "installed metadata differs from its prepared object".into(),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish(
    coord: &CoordLive,
    context: &InstallContext<'_>,
    plan: &output_install::PreparedOutputs,
    tail: SelectedActionOutputs,
    permit: Option<&ReplayInstallPermit>,
    mut files: Vec<PathBuf>,
    metadata_ready: &mut MetadataCallback<'_>,
) -> Result<ServeOutcome, ServeError> {
    let continue_install = || -> Result<Vec<PathBuf>, ServeError> {
        verify_installed_head(plan, &files)?;
        metadata_ready(&files).map_err(|reason| ServeError::MetadataExposed {
            installed: files.clone(),
            reason,
        })?;
        // Cargo may have observed the head while its acknowledgment waited.
        // Missing or changed outputs cannot authorize the tail or success.
        verify_installed_head(plan, &files)?;
        let cas = coord.cas.as_ref().ok_or(ServeError::NoStore)?;
        // Even an empty tail must recheck the gates after the callback: emitting
        // metadata does not authorize success after a concurrent revocation.
        let prepared = match output_install::stage_for_install(tail, plan) {
            Ok(prepared) => prepared,
            Err(failure) => {
                let mut store = cas
                    .store()
                    .lock()
                    .map_err(|_| ServeError::StoreUnavailable)?;
                return Err(output_install::settle_stage_failure(&mut *store, failure));
            }
        };
        // Staging bulk archives can be slow; retain the same complete head
        // contract through that second unlocked interval, even for an empty tail.
        verify_installed_head(plan, &files)?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| ServeError::StoreUnavailable)?;
        if let Some(permit) = permit
            && live_replay_permit_or_continuation(
                &mut *store,
                context.action,
                context.manifest_key,
                Some(permit),
            )
            .map_err(store_error)?
            .is_none()
        {
            return Err(ServeError::MetadataExposed {
                installed: files.clone(),
                reason: "metadata installation replay admission changed".into(),
            });
        }
        if let Some(refusal) = context.recheck(coord, &mut *store, permit)? {
            return Err(ServeError::MetadataExposed {
                installed: files.clone(),
                reason: format!("{refusal:?}"),
            });
        }
        output_install::install_prepared(&mut *store, plan, prepared)
    };
    let tail_files = continue_install().map_err(|error| exposed_failure(&files, error))?;
    files.extend(tail_files);
    // The final renames and any wait for the metadata lock also separate the
    // last check from success. Preserve the whole installed frontier if the
    // head changed meanwhile; a completed archive does not repair its metadata.
    verify_installed_head(plan, &files).map_err(|error| exposed_failure(&files, error))?;
    Ok(ServeOutcome::Served { files })
}
