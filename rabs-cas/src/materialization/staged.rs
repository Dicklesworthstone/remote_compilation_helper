//! Split-phase raw-object delivery for a coordinator with a shared metadata lock.
//!
//! Selection and installation require metadata access; private copying does not.
//! A selected location is NOT serving authority. Callers must retain destination
//! ownership and recheck their action/release/lease gates after staging. This
//! layer additionally rechecks logical quarantine and the selected raw location
//! before publishing any prepared file. It never installs unverified bytes.

use super::{
    ActionMaterializationReceipt, ActionMaterializeFailure, MaterializationMode, MaterializeError,
    OutputMaterialized, PlannedActionOutput, copy_verified, digest_key, io_err, planned_order_key,
    validate_action_destinations,
};
use crate::blob_store::RAW_PROFILE_V1;
use crate::metadata_store::{RabsMetadataStore, SqlValue};
use rabs_protocol::result_identity::{OutputRole, TypedDigest};
use std::fs::{File, Metadata};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Identity {
    fn file(metadata: &Metadata) -> std::io::Result<Self> {
        if !metadata.is_file() {
            return Err(std::io::Error::other(
                "prepared object is not a regular file",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

/// One unexposed sibling directory. Only its exact owned file and directory
/// generations can be cleaned; a replacement is retained, never recursively
/// removed. A same-user hostile writer is not isolated by this ownership check.
#[derive(Debug)]
struct PrivateStage {
    directory: PathBuf,
    directory_file: File,
    path: PathBuf,
    file: Option<File>,
    identity: Option<Identity>,
    created_parents: Vec<PathBuf>,
    installed: bool,
}

impl PrivateStage {
    fn create(parent: &Path) -> Result<Self, MaterializeError> {
        let created_parents: Vec<PathBuf> = parent
            .ancestors()
            .take_while(|ancestor| !ancestor.as_os_str().is_empty() && !ancestor.exists())
            .map(Path::to_path_buf)
            .collect();
        std::fs::create_dir_all(parent).map_err(io_err("create-destination-dir"))?;
        let cleanup_parents = |parents: &[PathBuf]| {
            for dir in parents {
                let _ = std::fs::remove_dir(dir);
            }
        };
        for _ in 0..8 {
            let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
            let directory = parent.join(format!(".rabs-stage-{}-{sequence}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => {
                    use rustix::fs::{Mode, OFlags, open};
                    let directory_file = match open(
                        &directory,
                        OFlags::RDONLY
                            | OFlags::DIRECTORY
                            | OFlags::CLOEXEC
                            | OFlags::NOFOLLOW
                            | OFlags::NONBLOCK,
                        Mode::empty(),
                    ) {
                        Ok(fd) => File::from(fd),
                        Err(error) => {
                            let _ = std::fs::remove_dir(&directory);
                            cleanup_parents(&created_parents);
                            return Err(io_err("open-stage-dir")(error.into()));
                        }
                    };
                    let held = match directory_file.metadata() {
                        Ok(meta) => meta,
                        Err(error) => {
                            let _ = std::fs::remove_dir(&directory);
                            cleanup_parents(&created_parents);
                            return Err(io_err("stat-stage-dir")(error));
                        }
                    };
                    if held.mode() & 0o077 != 0 {
                        let _ = std::fs::remove_dir(&directory);
                        cleanup_parents(&created_parents);
                        return Err(io_err("private-stage-dir")(std::io::Error::other(
                            "staging directory is not private",
                        )));
                    }
                    let path = directory.join("object");
                    return Ok(Self {
                        directory,
                        directory_file,
                        path,
                        file: None,
                        identity: None,
                        created_parents,
                        installed: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    cleanup_parents(&created_parents);
                    return Err(io_err("create-stage-dir")(error));
                }
            }
        }
        cleanup_parents(&created_parents);
        Err(io_err("create-stage-dir")(std::io::Error::other(
            "staging namespace exhausted",
        )))
    }

    fn directory_current(&self) -> std::io::Result<()> {
        let named = std::fs::symlink_metadata(&self.directory)?;
        let held = self.directory_file.metadata()?;
        if !named.is_dir()
            || named.mode() & 0o077 != 0
            || (named.dev(), named.ino()) != (held.dev(), held.ino())
        {
            return Err(std::io::Error::other("prepared directory changed"));
        }
        Ok(())
    }

    fn retain(&mut self) -> Result<(), MaterializeError> {
        self.directory_current()
            .map_err(io_err("verify-stage-dir"))?;
        use rustix::fs::{Mode, OFlags, open};
        let file = open(
            &self.path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| io_err("open-prepared-file")(error.into()))?;
        let identity = Identity::file(&file.metadata().map_err(io_err("stat-prepared-file"))?)
            .map_err(io_err("stat-prepared-file"))?;
        self.file = Some(file);
        self.identity = Some(identity);
        self.verify()
    }

    fn verify(&self) -> Result<(), MaterializeError> {
        self.directory_current()
            .map_err(io_err("verify-stage-dir"))?;
        let file = self.file.as_ref().ok_or_else(|| {
            io_err("verify-prepared-file")(std::io::Error::other("no prepared descriptor"))
        })?;
        let held = Identity::file(&file.metadata().map_err(io_err("stat-prepared-file"))?)
            .map_err(io_err("stat-prepared-file"))?;
        let named = Identity::file(
            &std::fs::symlink_metadata(&self.path).map_err(io_err("stat-prepared-name"))?,
        )
        .map_err(io_err("stat-prepared-name"))?;
        if Some(held) != self.identity || named != held {
            return Err(io_err("verify-prepared-file")(std::io::Error::other(
                "prepared file generation changed",
            )));
        }
        Ok(())
    }
}

impl Drop for PrivateStage {
    fn drop(&mut self) {
        if self.directory_current().is_err() {
            return;
        }
        // On success the file was renamed out. On failure remove only a
        // retained, unchanged inode; unexpected entries preserve the directory.
        if !self.installed && self.identity.is_some() && self.verify().is_ok() {
            self.file.take();
            let _ = std::fs::remove_file(&self.path);
        }
        let _ = std::fs::remove_dir(&self.directory);
        if !self.installed {
            for dir in &self.created_parents {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
}

fn usable_locations(
    store: &mut dyn RabsMetadataStore,
    object: &TypedDigest,
) -> Result<Vec<String>, MaterializeError> {
    let key = digest_key(object);
    if !store
        .query(
            "SELECT 1 FROM quarantines WHERE scope = 'logical-object' AND subject = ?1 LIMIT 1",
            &[SqlValue::Text(key.clone())],
        )
        .map_err(|error| MaterializeError::Store(format!("{error:?}")))?
        .is_empty()
    {
        return Err(MaterializeError::QuarantinedObject { object: key });
    }
    let locations: Vec<_> = store
        .object_locations(object)
        .map_err(|error| MaterializeError::Store(format!("{error:?}")))?
        .into_iter()
        .filter(|(_, encoding, _)| encoding == RAW_PROFILE_V1)
        .map(|(path, _, _)| path)
        .collect();
    if locations.is_empty() {
        return Err(MaterializeError::NoUsableCopy { object: key });
    }
    Ok(locations)
}

#[derive(Debug)]
struct SelectedOutput {
    output: PlannedActionOutput,
    locations: Vec<String>,
}

/// Metadata-only selection. It neither reserves destinations nor authorizes
/// a serve. All selected outputs are validated before private copying begins.
#[derive(Debug)]
pub struct SelectedActionOutputs {
    selected: Vec<SelectedOutput>,
    mode: MaterializationMode,
    freshness: SystemTime,
}

/// A staging failure retains the exact object/location attribution needed to
/// durably quarantine a corrupt replica. The caller must settle it under the
/// original store lock before returning the failure. No destination was installed.
#[derive(Debug)]
pub struct PreparationFailure {
    error: MaterializeError,
    corrupt: Option<(TypedDigest, String)>,
}

impl PreparationFailure {
    /// Persist corruption containment, then return the original typed error.
    /// An unavailable quarantine write takes precedence over an ordinary error.
    pub fn settle(self, store: &mut dyn RabsMetadataStore) -> ActionMaterializeFailure {
        let mut error = self.error;
        if let Some((object, path)) = self.corrupt
            && let Err(failure) = store.set_location_quarantined(&object, &path, true)
        {
            error = MaterializeError::Store(format!("{failure:?}"));
        }
        ActionMaterializeFailure {
            installed: Vec::new(),
            error,
        }
    }
}

impl SelectedActionOutputs {
    /// Select non-quarantined raw copies under the caller's metadata lock.
    /// The complete destination namespace is checked before filesystem effects.
    pub fn select(
        store: &mut dyn RabsMetadataStore,
        outputs: &[PlannedActionOutput],
        mode: MaterializationMode,
        freshness: SystemTime,
    ) -> Result<Self, ActionMaterializeFailure> {
        let mut select = || -> Result<Self, MaterializeError> {
            validate_action_destinations(outputs)?;
            for output in outputs {
                if !output.destination.is_absolute() {
                    return Err(MaterializeError::UnsafeDestination {
                        path: output.destination.to_string_lossy().into_owned(),
                    });
                }
            }
            if mode == MaterializationMode::ReadOnlyBind && !outputs.is_empty() {
                return Err(MaterializeError::ModeUnsupported(mode));
            }
            let mut ordered: Vec<_> = outputs.iter().collect();
            ordered.sort_by_key(|output| {
                (
                    output.role != OutputRole::ProvisionalMetadata,
                    planned_order_key(output),
                )
            });
            let selected = ordered
                .into_iter()
                .map(|output| {
                    Ok(SelectedOutput {
                        locations: usable_locations(store, &output.object)?,
                        output: output.clone(),
                    })
                })
                .collect::<Result<_, MaterializeError>>()?;
            Ok(Self {
                selected,
                mode,
                freshness,
            })
        };
        select().map_err(|error| ActionMaterializeFailure {
            installed: Vec::new(),
            error,
        })
    }

    /// Partition a completely selected action before any payload staging.
    /// When declared metadata exists, it and every declared dep-info output
    /// enter the head: rustc can announce dep-info before metadata. All selected
    /// outputs retain their exact locations, ordering, copy mode and freshness.
    /// Without metadata, the original complete selection remains unchanged.
    ///
    /// This grants no early exposure authority. The caller must retain its
    /// reservation for the COMPLETE destination set across both phases, recheck
    /// the committed action and serving gates before each installation, and
    /// treat any failure after exposing metadata as a terminal delivery failure.
    /// The tail has been namespace/location-validated, but its bytes have not
    /// been read or copied and may still fail verification when staged.
    #[must_use]
    pub fn split_metadata(self) -> (Option<Self>, Self) {
        if !self
            .selected
            .iter()
            .any(|output| output.output.role == OutputRole::ProvisionalMetadata)
        {
            return (None, self);
        }
        let (metadata, remainder) = self.selected.into_iter().partition(|output| {
            matches!(
                output.output.role,
                OutputRole::ProvisionalMetadata | OutputRole::DepInfo
            )
        });
        (
            Some(Self {
                selected: metadata,
                mode: self.mode,
                freshness: self.freshness,
            }),
            Self {
                selected: remainder,
                mode: self.mode,
                freshness: self.freshness,
            },
        )
    }

    /// Whether this selection owns no outputs, including an empty phase tail.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }

    /// Copy, hash, derive and freshness-stamp private files WITHOUT metadata
    /// access. The existing materializer is the sole byte-verification/CoW path.
    /// Retain the returned owner until the caller rechecks action authority.
    // The failure carries the typed error plus the corrupt location that
    // `settle` must quarantine; it is returned once, on the failure path.
    #[allow(clippy::result_large_err)]
    pub fn stage(
        self,
        prepare: &impl Fn(&PlannedActionOutput, &File) -> std::io::Result<()>,
    ) -> Result<PreparedActionOutputs, PreparationFailure> {
        let mut out = PreparedActionOutputs {
            prepared: Vec::with_capacity(self.selected.len()),
            started: Instant::now(),
        };
        for selected in self.selected {
            let output = selected.output;
            let parent = output
                .destination
                .parent()
                .ok_or_else(|| PreparationFailure {
                    error: MaterializeError::UnsafeDestination {
                        path: output.destination.to_string_lossy().into_owned(),
                    },
                    corrupt: None,
                })?;
            let mut last = MaterializeError::NoUsableCopy {
                object: digest_key(&output.object),
            };
            let mut ready = None;
            for source in selected.locations {
                let mut stage =
                    PrivateStage::create(parent).map_err(|error| PreparationFailure {
                        error,
                        corrupt: None,
                    })?;
                let result = copy_verified(
                    &source,
                    &output.object,
                    &digest_key(&output.object),
                    &stage.directory,
                    &stage.path,
                    self.mode,
                    &|file| {
                        prepare(&output, file)?;
                        file.set_modified(self.freshness)
                    },
                );
                match result {
                    Ok((bytes, _)) => {
                        stage.retain().map_err(|error| PreparationFailure {
                            error,
                            corrupt: None,
                        })?;
                        ready = Some(PreparedOutput {
                            output: output.clone(),
                            source,
                            bytes,
                            stage,
                        });
                        break;
                    }
                    Err(error @ MaterializeError::ContentMismatch { .. }) => {
                        return Err(PreparationFailure {
                            error,
                            corrupt: Some((output.object.clone(), source)),
                        });
                    }
                    Err(error) => last = error,
                }
            }
            out.prepared.push(ready.ok_or(PreparationFailure {
                error: last,
                corrupt: None,
            })?);
        }
        Ok(out)
    }
}

#[derive(Debug)]
struct PreparedOutput {
    output: PlannedActionOutput,
    source: String,
    bytes: u64,
    stage: PrivateStage,
}

/// Verified private bytes, not serving permission. No public path or writable
/// file handle is exposed. Dropping the owner abandons only its private staging.
#[derive(Debug)]
pub struct PreparedActionOutputs {
    prepared: Vec<PreparedOutput>,
    started: Instant,
}

impl Drop for PreparedActionOutputs {
    fn drop(&mut self) {
        while let Some(prepared) = self.prepared.pop() {
            drop(prepared);
        }
    }
}

impl PreparedActionOutputs {
    /// Recheck every quarantine/location and staged generation before the FIRST
    /// destination write. The caller holds its store lock and destination claim
    /// across these checks and installation, after rerunning its serving gates.
    /// No payload reads or hashing occur here. A rename failure reports the exact
    /// installed prefix; it NEVER grants fallback execution authority.
    pub fn install(
        mut self,
        store: &mut dyn RabsMetadataStore,
    ) -> Result<ActionMaterializationReceipt, ActionMaterializeFailure> {
        for prepared in &self.prepared {
            let mut validate = || -> Result<(), MaterializeError> {
                if !usable_locations(store, &prepared.output.object)?.contains(&prepared.source) {
                    return Err(MaterializeError::NoUsableCopy {
                        object: digest_key(&prepared.output.object),
                    });
                }
                prepared.stage.verify()
            };
            validate().map_err(|error| ActionMaterializeFailure {
                installed: Vec::new(),
                error,
            })?;
        }
        let mut installed = Vec::with_capacity(self.prepared.len());
        let mut head_nanos = 0;
        let mut tail_started = None;
        for prepared in &mut self.prepared {
            if prepared.output.role != OutputRole::ProvisionalMetadata && tail_started.is_none() {
                tail_started = Some(Instant::now());
            }
            let began = Instant::now();
            if let Err(error) = prepared.stage.verify().and_then(|()| {
                std::fs::rename(&prepared.stage.path, &prepared.output.destination)
                    .map_err(io_err("rename-into-place"))
            }) {
                return Err(ActionMaterializeFailure { installed, error });
            }
            prepared.stage.installed = true;
            if prepared.output.role == OutputRole::ProvisionalMetadata {
                // Include staging and the caller's authorization handoff, not
                // just the cheap rename. This is not an early-metadata stream.
                head_nanos = self.started.elapsed().as_nanos();
            }
            installed.push(OutputMaterialized {
                role: prepared.output.role,
                virtual_path: std::mem::take(&mut prepared.output.virtual_path),
                destination: std::mem::take(&mut prepared.output.destination),
                bytes: prepared.bytes,
                nanos: began.elapsed().as_nanos(),
            });
        }
        Ok(ActionMaterializationReceipt {
            total_nanos: self.started.elapsed().as_nanos(),
            head_nanos,
            tail_nanos: tail_started.map_or(0, |started| started.elapsed().as_nanos()),
            installed,
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod metadata_pipeline_tests;
