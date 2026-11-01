//! Install one acknowledged fresh execution without creating cache authority.
//!
//! The opaque input owns verified result objects from a successful authenticated
//! workspace compiler. Its worker has drained and its action generation has
//! retired. Only this coordinator incarnation and the original request's live
//! input guards may authorize target writes; a publication pointer, serving
//! record, verification sample or old recovery receipt cannot create this owner.

use super::metadata_replay::{MetadataCallback, verify_installed_head};
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
    /// A metadata head may already have been observed. No subsequent failure
    /// can authorize a fallback compiler, including failure before the ACK.
    MetadataExposed(String),
}

fn decline(error: impl std::fmt::Display) -> RequestOwnedInstallError {
    RequestOwnedInstallError::Declined(format!("request-owned install: {error}"))
}

impl CoordLive {
    /// Consume a fresh result after the same wrapper acknowledges its exact
    /// manifest. The capture pins remain alive through every private copy and
    /// final rename. With a metadata callback, one complete destination
    /// reservation spans head installation, acknowledgment and tail staging.
    /// This endpoint cannot be reached by an edge cache reader.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::coord) fn install_request_owned_result(
        &self,
        result: RequestOwnedResult,
        action_key: &TypedDigest,
        manifest_key: &str,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        verify_request: impl Fn() -> Result<(), String>,
        mut metadata_ready: Option<&mut MetadataCallback<'_>>,
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
        let (selected, metadata_tail) = if metadata_ready.is_some() {
            let (head, tail) = selected.split_metadata();
            match head {
                Some(head) => (head, Some(tail)),
                None => (tail, None),
            }
        } else {
            (selected, None)
        };
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
        let mut files = output_install::install_prepared(&mut *store, &plan, prepared).map_err(
            |error| {
                let reason = format!("request-owned install: {error}");
                if metadata_tail.is_some()
                    && matches!(&error, ServeError::Materialize(failure) if !failure.installed.is_empty())
                {
                    RequestOwnedInstallError::MetadataExposed(reason)
                } else {
                    RequestOwnedInstallError::Fault(reason)
                }
            },
        )?;
        drop(store);
        if let Some(tail) = metadata_tail {
            // A complete verified head is already installed. Every error from
            // this frontier is sticky even if the receiver never ACKs it. The
            // affine result owner, capture pins and full reservation stay on
            // this stack; no cache admission or publication is manufactured.
            let finish = || -> Result<Vec<PathBuf>, String> {
                verify_installed_head(&plan, &files).map_err(|error| error.to_string())?;
                metadata_ready
                    .as_mut()
                    .ok_or("request-owned metadata callback ownership lost")?(
                    &files
                )?;

                // A callback can wait for the wrapper's exact ACK. Check the
                // original request and coordinator before reading any tail
                // payload, and again after potentially expensive staging.
                verify_request()?;
                verify_installed_head(&plan, &files).map_err(|error| error.to_string())?;
                self.require_request_owner(coordinator)
                    .map_err(|error| error.to_string())?;
                {
                    let mut store = cas
                        .store()
                        .lock()
                        .map_err(|_| ServeError::StoreUnavailable.to_string())?;
                    require_active_owner(&mut *store, coordinator)
                        .map_err(|error| error.to_string())?;
                }
                let prepared = match output_install::stage_for_install(tail, &plan) {
                    Ok(prepared) => prepared,
                    Err(failure) => {
                        let mut store = cas
                            .store()
                            .lock()
                            .map_err(|_| ServeError::StoreUnavailable.to_string())?;
                        return Err(
                            output_install::settle_stage_failure(&mut *store, failure).to_string()
                        );
                    }
                };
                verify_request()?;
                verify_installed_head(&plan, &files).map_err(|error| error.to_string())?;
                self.require_request_owner(coordinator)
                    .map_err(|error| error.to_string())?;
                let mut store = cas
                    .store()
                    .lock()
                    .map_err(|_| ServeError::StoreUnavailable.to_string())?;
                require_active_owner(&mut *store, coordinator)
                    .map_err(|error| error.to_string())?;
                output_install::install_prepared(&mut *store, &plan, prepared)
                    .map_err(|error| error.to_string())
            };
            let tail_files = finish().map_err(|reason| {
                RequestOwnedInstallError::MetadataExposed(format!(
                    "request-owned metadata delivery: {reason}"
                ))
            })?;
            files.extend(tail_files);
            // The head remains Cargo-visible throughout tail installation.
            // Check the complete delivered frontier before reporting success;
            // a changed dependency file cannot become Cargo freshness state.
            verify_installed_head(&plan, &files).map_err(|error| {
                RequestOwnedInstallError::MetadataExposed(format!(
                    "request-owned metadata delivery: {error}"
                ))
            })?;
        }
        Ok(files)
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
