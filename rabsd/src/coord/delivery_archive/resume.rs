//! Explicit completion of a retained, fully verified CAS restore. This path
//! hashes staged bytes but never copies artifact replicas, connects to a worker,
//! or treats a missing/partial staging tree as permission to execute again.

use super::{
    ATP_OBJECT_CONTENT_DOMAIN, Delivery, DeliveryTrust, LiveCas, RESTORE_STAGING_PREFIX,
    Value, invalid, load_archive, publish_restore, require, sync_dirs, validate_request,
    verify_archive_directory,
};
use rabs_cas::metadata_store::RabsMetadataStore;
use std::io;
use std::path::{Component, Path};

/// Finish one explicitly named, complete restore staging directory without
/// recopying its artifacts. Both paths must be absolute siblings; staging must
/// have the private `.rabs-delivery-restore-` name used by [`super::restore_delivery`].
/// No discovery, adoption of partial trees, repair, or compiler execution occurs.
///
/// The active archive pin, logical quarantines, exact archive/result identity,
/// original request and worker trust remain mandatory. Every staged byte and
/// mode is reverified. Writable hardlink aliases refuse before publication.
/// Only after syncing the complete private tree is it exclusively renamed into
/// place. Existing matching destinations are verified idempotently; differing,
/// incomplete, or racing destinations are never overwritten.
///
/// The caller must own the local directories and exclude concurrent edits, as
/// with ordinary delivery recovery. This is not hostile-process isolation. A
/// post-rename sync error is uncertain durability: retry this same operation to
/// verify the final destination, never rerun the compiler.
pub fn finish_staged_restore(
    cas: &LiveCas,
    root_key: &str,
    request: &Value,
    worker: &str,
    staging: &Path,
    destination: &Path,
    trust: DeliveryTrust,
) -> Result<Delivery, String> {
    let result = (|| -> io::Result<Delivery> {
        validate_request(request)?;
        require(
            !cas.serving_refused,
            "CAS startup reconciliation refused the store",
        )?;
        for path in [staging, destination] {
            require(
                path.is_absolute()
                    && path.file_name().is_some()
                    && path
                        .components()
                        .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
                "restore paths must be named absolute directories without traversal",
            )?;
        }
        require(
            staging != destination && staging.parent() == destination.parent(),
            "restore staging and destination must be distinct siblings",
        )?;
        require(
            staging
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(RESTORE_STAGING_PREFIX)
                        && name.len() > RESTORE_STAGING_PREFIX.len()
                }),
            "not a named private restore staging directory",
        )?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| invalid("CAS metadata lock poisoned"))?;
        store.intern_domain(ATP_OBJECT_CONTENT_DOMAIN);
        let archive = load_archive(&mut *store, root_key, request, worker)?;
        if let Some(mut existing) =
            verify_archive_directory(request, worker, destination, trust, &archive)?
        {
            // A successful rename consumes staging. Do not require it to exist,
            // and do not touch a later directory that happens to reuse its name.
            existing.acknowledgment_error = Some(
                "verified completed staged CAS restore; remote acknowledgments were not rechecked"
                    .to_owned(),
            );
            return Ok(existing);
        }
        let verified = verify_archive_directory(request, worker, staging, trust, &archive)?
            .ok_or_else(|| invalid("restore staging is absent; no execution is attempted"))?;
        // Unlike a new restore, this path keeps the staged inodes. They must
        // not alias mutable source deliveries or immutable CAS replicas. Sync
        // each opened file as well as the directory tree before publication.
        for relative in archive
            .plan
            .keys()
            .map(String::as_str)
            .chain(std::iter::once("delivery.json"))
        {
            let file = super::ordinary_file(&staging.join(relative))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                require(
                    file.metadata()?.nlink() == 1,
                    "restore staging has a writable hardlink alias",
                )?;
            }
            file.sync_all()?;
        }
        sync_dirs(staging)?;
        publish_restore(staging, destination)?;
        Ok(Delivery {
            directory: destination.to_path_buf(),
            receipt: verified.receipt,
            acknowledgments_confirmed: false,
            acknowledgment_interrupted: false,
            acknowledgment_error: Some(
                "completed staged CAS restore; remote acknowledgments were not rechecked".to_owned(),
            ),
        })
    })();
    result.map_err(|error| {
        format!(
            "staged restore refused; no execution or copy was attempted; staging={}; destination={}: {error}",
            staging.display(),
            destination.display(),
        )
    })
}
