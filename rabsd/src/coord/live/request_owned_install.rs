//! Install one acknowledged fresh execution without creating cache authority.
//!
//! The opaque input owns verified result objects from a successful authenticated
//! workspace compiler. Its worker has drained and its action generation has
//! retired. Only this coordinator incarnation and the original request's live
//! input guards may authorize target writes; a publication pointer, serving
//! record, verification sample or old recovery receipt cannot create this owner.

use super::{CoordLive, ExpectedOutputs, ServeError, output_install};
use crate::coord::live_dependency::remote::RequestOwnedResult;
use crate::edge::destination_arbiter::{BundleId, reserve_scoped};
use rabs_cas::metadata_store::RabsMetadataStore;
use rabs_cas::publication::authority_digest;
use rabs_protocol::authority::CoordinatorAuthority;
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::TypedDigest;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(in crate::coord) enum RequestOwnedInstallError {
    /// Private preparation failed before any final output was installed.
    Declined(String),
    /// Installation returned after possibly exposing a prefix. Only the
    /// existing settled-writer fallback protocol may authorize a compiler run.
    Fault(String),
}

fn decline(error: impl std::fmt::Display) -> RequestOwnedInstallError {
    RequestOwnedInstallError::Declined(format!("request-owned install: {error}"))
}

impl CoordLive {
    /// Consume a fresh result after the same wrapper acknowledges its exact
    /// manifest. The capture pins remain alive through every private copy and
    /// final rename. This endpoint cannot be reached by an edge cache reader.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::coord) fn install_request_owned_result(
        &self,
        result: RequestOwnedResult,
        action_key: &TypedDigest,
        manifest_key: &str,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        verify_request: impl Fn() -> Result<(), String>,
    ) -> Result<Vec<PathBuf>, RequestOwnedInstallError> {
        result
            .verify_binding(action_key, manifest_key)
            .map_err(decline)?;
        verify_request().map_err(decline)?;
        let coordinator = &result.authority().coordinator;
        self.require_request_owner(coordinator).map_err(decline)?;
        let cas = self
            .cas
            .as_ref()
            .ok_or_else(|| decline(ServeError::NoStore))?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| decline(ServeError::StoreUnavailable))?;
        require_active_owner(&mut *store, coordinator).map_err(decline)?;
        let plan = match output_install::prepare(
            &mut *store,
            result.manifest(),
            destination_root,
            expected,
        )
        .map_err(decline)?
        {
            Ok(plan) => plan,
            Err(refusal) => return Err(decline(format!("output contract: {refusal:?}"))),
        };
        if plan.outputs.is_empty() {
            return Err(decline(
                "fresh compiler result contains no declared outputs",
            ));
        }
        let paths = plan
            .outputs
            .iter()
            .map(|output| output.destination.as_os_str().as_bytes().to_vec())
            .collect::<Vec<_>>();
        let bundle = BundleId(format!(
            "request-owned:{:032x}:{}",
            result.authority().attempt_id.0,
            self.next_seq(),
        ));
        let _reservation = reserve_scoped(&self.arbiter, bundle, &paths).map_err(|conflict| {
            decline(ServeError::DestinationConflict {
                path: RawBytes::new(conflict.path).escaped(),
                holder: conflict.holder.0,
            })
        })?;
        let selected = output_install::select_for_install(&mut *store, &plan).map_err(decline)?;
        drop(store);
        let prepared = match output_install::stage_for_install(selected, &plan) {
            Ok(prepared) => prepared,
            Err(failure) => {
                let mut store = cas
                    .store()
                    .lock()
                    .map_err(|_| decline(ServeError::StoreUnavailable))?;
                return Err(decline(output_install::settle_stage_failure(
                    &mut *store,
                    failure,
                )));
            }
        };

        // Copying and dep-info derivation can be slow. Recheck the complete
        // original source, dependency and toolchain/runtime generation outside
        // the store lock, then fence coordinator ownership under that lock just
        // before the first rename. The action lease is deliberately retired;
        // it is not resurrected or mistaken for publication authority here.
        verify_request().map_err(decline)?;
        self.require_request_owner(coordinator).map_err(decline)?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| decline(ServeError::StoreUnavailable))?;
        require_active_owner(&mut *store, coordinator).map_err(decline)?;
        output_install::install_prepared(&mut *store, &plan, prepared).map_err(|error| {
            RequestOwnedInstallError::Fault(format!("request-owned install: {error}",))
        })
    }

    fn require_request_owner(&self, expected: &CoordinatorAuthority) -> Result<(), ServeError> {
        if !self.available() || self.authority().as_ref() != Some(expected) {
            return Err(ServeError::CoordinatorUnavailable);
        }
        Ok(())
    }
}

fn require_active_owner(
    store: &mut dyn RabsMetadataStore,
    expected: &CoordinatorAuthority,
) -> Result<(), ServeError> {
    match store
        .active_authority()
        .map_err(|error| ServeError::Store(format!("{error:?}")))?
    {
        Some(active) if active.digest == authority_digest(expected) => Ok(()),
        _ => Err(ServeError::CoordinatorUnavailable),
    }
}
