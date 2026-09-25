//! Retire resolved jobs from bounded live admission without forgetting history.
//!
//! Every ID has one full record in either live storage or this private archive.
//! Moving it preserves request identity and path ownership; no tombstone is
//! deleted and no archive entry grants permission to execute. History is read
//! one bounded record at a time on the existing filesystem lane.

use super::{
    MAX_DETAIL_BYTES, MAX_OPERATIONS, MAX_RECORD_BYTES, MAX_RETAINED_BYTES, OperationState,
    PreparedOperationStore, Record, State, StoredMode, invalid, ordinary_directory, overlap,
    path_shape, read_bounded, request_digest, require, valid_id, validate_bound_request,
    validate_spec_shape,
};
use std::fs::{self, File};
use std::io;
use std::net::SocketAddr;
use std::path::Path;

pub(super) fn prepare_archive(root: &Path) -> io::Result<()> {
    let archive = root.join("archive");
    ordinary_directory(&archive, true)?;
    if !archive.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&archive)?;
        File::open(&archive)?.sync_all()?;
        File::open(root)?.sync_all()?;
    }
    validate_archive(&archive)
}

fn validate_archive(archive: &Path) -> io::Result<()> {
    ordinary_directory(archive, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        require(
            fs::metadata(archive)?.permissions().mode() & 0o077 == 0,
            "operation archive must be private (0700)",
        )?;
    }
    Ok(())
}

/// Use exactly the same complete validation for live and archived records.
/// Neither a filename nor an archived state bypasses request/frontier checks.
pub(super) fn load_record(root: &Path, path: &Path) -> io::Result<Record> {
    let bytes = read_bounded(path, MAX_RECORD_BYTES, true)?;
    let record: Record = serde_json::from_slice(&bytes)?;
    validate_spec_shape(&record.spec)?;
    validate_bound_request(&record.request)?;
    require(
        record.version == 1
            && record.request_sha256 == request_digest(&record.request)?
            && path.file_stem().and_then(|s| s.to_str()) == Some(record.spec.id.as_str())
            && record.prior_deliveries.len() <= 16
            && record
                .detail
                .as_ref()
                .is_none_or(|s| s.len() <= MAX_DETAIL_BYTES)
            && record.stop_reason.as_ref().is_none_or(|s| s.len() <= 128),
        "invalid prepared operation record",
    )?;
    require(
        record
            .paths()
            .iter()
            .all(|path| path_shape(path) && !overlap(path, root))
            && !overlap(&record.delivery, &record.spec.bundle)
            && !overlap(&record.delivery, &record.spec.output)
            && record
                .listen_address
                .as_ref()
                .is_none_or(|address| address.parse::<SocketAddr>().is_ok())
            && record.bound_address.as_ref().is_none_or(|address| {
                address
                    .parse::<SocketAddr>()
                    .is_ok_and(|address| address.port() != 0)
            }),
        "invalid recovered operation paths",
    )?;
    require(
        match record.mode {
            StoredMode::Execute => {
                record.prior_deliveries.is_empty()
                    && record.resume_from.is_none()
                    && (record.state != OperationState::Queued
                        || (record.attempt == 0 && !record.execution_may_have_run))
            }
            StoredMode::Resume => {
                !record.prior_deliveries.is_empty()
                    && record.attempt > 0
                    && record.execution_may_have_run
            }
            StoredMode::Acknowledge => {
                record.attempt > 0 && record.execution_may_have_run && record.resume_from.is_none()
            }
            StoredMode::LocalRecovery => {
                record.attempt > 0
                    && record.execution_may_have_run
                    && record.resume_from.is_none()
                    && record.state != OperationState::Queued
            }
        },
        "invalid recovered operation execution frontier",
    )?;
    require(
        record
            .exit_code
            .is_none_or(|code| (0..=255).contains(&code))
            && (!record.outputs_installed
                || (record.exit_code == Some(0)
                    && record.stop_reason.is_none()
                    && record.execution_may_have_run))
            && match record.state {
                OperationState::Queued => true,
                OperationState::Running | OperationState::Uncertain => {
                    record.attempt > 0 && record.execution_may_have_run
                }
                OperationState::Cancelling => {
                    record.attempt > 0 && record.execution_may_have_run && record.cancel_requested
                }
                OperationState::Completed => {
                    record.attempt > 0
                        && record.execution_may_have_run
                        && record.exit_code.is_some()
                        && record.acknowledgments_confirmed.is_some()
                        && record.stop_reason.as_deref() != Some("cancelled")
                        && (record.exit_code != Some(0)
                            || record.stop_reason.is_some()
                            || record.outputs_installed
                            || record.mode == StoredMode::Acknowledge)
                }
                OperationState::Cancelled => {
                    if record.execution_may_have_run {
                        record.attempt > 0
                            && record.exit_code.is_some()
                            && record.stop_reason.as_deref() == Some("cancelled")
                            && record.acknowledgments_confirmed.is_some()
                    } else {
                        record.mode == StoredMode::Execute
                            && record.exit_code == Some(130)
                            && record.cancel_requested
                            && !record.outputs_installed
                            && record.acknowledgments_confirmed.is_none()
                    }
                }
                OperationState::FailedBeforeStart => {
                    record.mode == StoredMode::Execute
                        && record.attempt > 0
                        && !record.execution_may_have_run
                        && record.exit_code.is_none()
                        && record.acknowledgments_confirmed.is_none()
                        && !record.outputs_installed
                }
            },
        "invalid recovered operation outcome",
    )?;
    Ok(record)
}

impl Record {
    pub(super) fn archivable(&self) -> bool {
        match self.state {
            OperationState::FailedBeforeStart => true,
            OperationState::Completed => self.acknowledgments_confirmed == Some(true),
            OperationState::Cancelled => {
                !self.execution_may_have_run || self.acknowledgments_confirmed == Some(true)
            }
            _ => false,
        }
    }
}

impl PreparedOperationStore {
    pub(super) fn poison(&self, state: &mut State) {
        state.poisoned = true;
        state.accepting = false;
        self.previews.stop();
        for cancellation in state.active.values() {
            cancellation.cancel();
        }
        self.changed.notify_all();
    }

    pub(super) fn read_record(&self, state: &State, id: &str) -> io::Result<Option<Record>> {
        require(valid_id(id), "invalid operation id")?;
        if let Some(record) = state.records.get(id) {
            return Ok(Some(record.clone()));
        }
        let archive = self.root.join("archive");
        validate_archive(&archive)?;
        let path = archive.join(format!("{id}.json"));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let record = load_record(&self.root, &path)?;
        require(
            record.archivable(),
            "archived operation has unresolved ownership",
        )?;
        Ok(Some(record))
    }

    pub(super) fn for_each_archived(
        &self,
        mut visit: impl FnMut(&Record) -> io::Result<()>,
    ) -> io::Result<()> {
        let archive = self.root.join("archive");
        validate_archive(&archive)?;
        for entry in fs::read_dir(&archive)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let record = load_record(&self.root, &path)?;
            require(
                record.archivable(),
                "archived operation has unresolved ownership",
            )?;
            visit(&record)?;
        }
        Ok(())
    }

    pub(super) fn lock_after_archived_check(
        &self,
        mut visit: impl FnMut(&Record) -> io::Result<()>,
    ) -> io::Result<std::sync::MutexGuard<'_, State>> {
        // The revision changes only while State is held, after a durable move.
        // A scan racing that move retries even if a disappearing filename made
        // it fail. No caller admits paths from an incomplete archive view, and
        // repeated movement cannot keep an admission thread retrying forever.
        for _ in 0..4 {
            let revision = self.lock_state()?.archive_revision;
            let checked = self.for_each_archived(&mut visit);
            let state = self.lock_state()?;
            if state.archive_revision != revision {
                continue;
            }
            checked?;
            return Ok(state);
        }
        Err(invalid(
            "operation archive changed during admission; retry the request",
        ))
    }

    /// No destination is replaced. Both parents belong to the same exclusively
    /// locked private store. A failure after rename fences the store; reopening
    /// discovers the complete record at whichever location survived the crash.
    fn move_record(&self, record: &Record, source: &Path, destination: &Path) -> io::Result<()> {
        validate_archive(&self.root.join("archive"))?;
        match fs::symlink_metadata(destination) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                require(
                    load_record(&self.root, source)? == *record,
                    "operation changed before archival move",
                )?;
                fs::rename(source, destination)?;
            }
            Err(error) => return Err(error),
            Ok(_) => {
                // An already completed rename can be reconciled only from the
                // exact full record, and only if the old name is absent. Never
                // overwrite either copy of conflicting or duplicate history.
                require(
                    load_record(&self.root, destination)? == *record,
                    "operation archive destination belongs to another record",
                )?;
                match fs::symlink_metadata(source) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                    Ok(_) => return Err(invalid("operation exists at both archival move paths")),
                }
            }
        }
        #[cfg(test)]
        if self
            .fail_after_archive_rename
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(io::Error::other(
                "injected failure after operation archive rename",
            ));
        }
        File::open(destination)?.sync_all()?;
        File::open(
            destination
                .parent()
                .ok_or_else(|| invalid("archive destination parent"))?,
        )?
        .sync_all()?;
        File::open(
            source
                .parent()
                .ok_or_else(|| invalid("archive source parent"))?,
        )?
        .sync_all()
    }

    /// Admission evicts only fully resolved history, oldest first, and only
    /// until this one new live record fits. Queued/active/recovery work keeps its
    /// original limits and all unresolved worker/path ownership fences.
    pub(super) fn make_room(&self, state: &mut State, weight: usize) -> io::Result<()> {
        require(
            weight <= MAX_RETAINED_BYTES,
            "prepared operation byte capacity exhausted",
        )?;
        while state.records.len() >= MAX_OPERATIONS
            || weight > MAX_RETAINED_BYTES.saturating_sub(state.retained_bytes)
        {
            let record = state
                .records
                .values()
                .filter(|record| record.archivable() && !state.active.contains_key(&record.spec.id))
                .min_by_key(|record| record.order)
                .cloned()
                .ok_or_else(|| {
                    invalid("prepared operation capacity exhausted by unresolved work")
                })?;
            let remaining = state
                .retained_bytes
                .checked_sub(record.weight()?)
                .ok_or_else(|| invalid("prepared operation accounting underflow"))?;
            let revision = state
                .archive_revision
                .checked_add(1)
                .ok_or_else(|| invalid("operation archive revision exhausted"))?;
            let source = self.root.join(format!("{}.json", record.spec.id));
            let destination = self
                .root
                .join("archive")
                .join(format!("{}.json", record.spec.id));
            if let Err(error) = self.move_record(&record, &source, &destination) {
                self.poison(state);
                return Err(error);
            }
            state.records.remove(&record.spec.id);
            state.retained_bytes = remaining;
            state.archive_revision = revision;
        }
        Ok(())
    }

    /// Re-enter bounded ownership only for an explicit local recovery. Restore
    /// the terminal record durably before the caller writes Running; a crash at
    /// either boundary cannot produce a queued compiler execution.
    pub(super) fn restore_record(&self, state: &mut State, record: &Record) -> io::Result<()> {
        if state.records.contains_key(&record.spec.id) {
            return Ok(());
        }
        require(
            record.archivable(),
            "only a resolved archive may restore ownership",
        )?;
        let weight = record.weight()?;
        self.make_room(state, weight)?;
        let revision = state
            .archive_revision
            .checked_add(1)
            .ok_or_else(|| invalid("operation archive revision exhausted"))?;
        let source = self
            .root
            .join("archive")
            .join(format!("{}.json", record.spec.id));
        let destination = self.root.join(format!("{}.json", record.spec.id));
        if let Err(error) = self.move_record(record, &source, &destination) {
            self.poison(state);
            return Err(error);
        }
        state.records.insert(record.spec.id.clone(), record.clone());
        state.retained_bytes += weight;
        state.archive_revision = revision;
        Ok(())
    }
}
