//! Pre-observe raw duplicate bytes without holding the metadata-store mutex.
//!
//! This is a short-lived file-generation witness, not a persisted digest memo.
//! The held descriptor prevents inode reuse; every use checks the same name,
//! descriptor, size, mode and nanosecond mtime/ctime. A changed or newly appeared
//! target refuses this publication attempt so callers can reobserve OUTSIDE the
//! lock. Both matching and mismatching digests go through the ordinary publisher:
//! a checksum mismatch still preserves the candidate and quarantines the object.
//!
//! Linux/macOS have the required acquisition and change witnesses. Other hosts
//! retain the existing publisher API, not a weaker approximation of this proof.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::RAW_PROFILE_V1;
use super::{BlobStoreLayout, PutError};
use rabs_protocol::result_identity::TypedDigest;
use std::path::{Path, PathBuf};

/// A descriptor-backed observation of one raw-v1 publication destination.
///
/// The private representation is deliberately neither Clone nor serializable.
/// Observation never creates metadata, pins, locations or publication authority.
/// Keep this only across the short observation-to-publication handoff, not as a
/// long-lived cache of mutable filesystem state.
#[derive(Debug)]
pub struct RawTargetObservation {
    target: PathBuf,
    expected: TypedDigest,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    file: Option<native::ObservedFile>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn changed(path: &Path) -> PutError {
    PutError::Io {
        step: "raw-target-observation-changed",
        error: format!("raw publication target changed: {}", path.display()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unsupported() -> PutError {
    PutError::Io {
        step: "raw-target-observation-unsupported",
        error: "descriptor-backed raw target observation requires Linux or macOS".into(),
    }
}

impl RawTargetObservation {
    /// Read and hash a possible duplicate before acquiring the metadata lock.
    /// Absence is recorded only to detect a later create race, not as a digest.
    ///
    /// # Errors
    /// Non-regular, symlinked, oversized, unreadable or moving destinations fail
    /// closed. A digest mismatch is retained as evidence for the existing
    /// collision handler rather than returned here or silently treated as absent.
    pub fn observe(
        layout: &BlobStoreLayout,
        expected: &TypedDigest,
        maximum_bytes: u64,
    ) -> Result<Self, PutError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let target = layout.published_path(expected, RAW_PROFILE_V1, expected);
            let file = native::ObservedFile::observe(&target, expected.domain, maximum_bytes)?;
            Ok(Self {
                target,
                expected: expected.clone(),
                file,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (layout, expected, maximum_bytes);
            Err(unsupported())
        }
    }

    /// Whether an observation can be retried after releasing the metadata lock.
    /// All other failures retain their ordinary error/collision semantics.
    #[must_use]
    pub fn changed(error: &PutError) -> bool {
        matches!(
            error,
            PutError::Io {
                step: "raw-target-observation-changed",
                ..
            }
        )
    }

    pub(super) fn check_binding(
        &self,
        target: &Path,
        expected: &TypedDigest,
    ) -> Result<(), PutError> {
        if self.target != target || self.expected != *expected {
            return Err(PutError::Io {
                step: "raw-target-observation-binding",
                error: "observation belongs to a different target or typed object identity".into(),
            });
        }
        Ok(())
    }

    pub(super) fn validate(&self, target: &Path, expected: &TypedDigest) -> Result<(), PutError> {
        self.check_binding(target, expected)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.file
                .as_ref()
                .ok_or_else(|| changed(target))?
                .validate(target)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(unsupported())
        }
    }

    pub(super) fn digest(
        &self,
        target: &Path,
        expected: &TypedDigest,
    ) -> Result<TypedDigest, PutError> {
        self.validate(target, expected)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.file
                .as_ref()
                .map(|file| file.digest.clone())
                .ok_or_else(|| changed(target))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(unsupported())
        }
    }

    pub(super) fn sync(&self, target: &Path, expected: &TypedDigest) -> Result<(), PutError> {
        self.validate(target, expected)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.file
                .as_ref()
                .ok_or_else(|| changed(target))?
                .file
                .sync_all()
                .map_err(super::io_err("fsync-existing"))?;
            self.validate(target, expected)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(unsupported())
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;
    use rustix::fs::{Mode, OFlags};
    use sha2::{Digest as _, Sha256};
    use std::fs::{File, Metadata};
    use std::io::{self, Read};
    use std::os::unix::fs::MetadataExt;

    const BUFFER_BYTES: usize = 64 * 1024;

    #[derive(Debug, PartialEq, Eq)]
    struct Version {
        dev: u64,
        ino: u64,
        size: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        mtime: (i64, i64),
        ctime: (i64, i64),
    }

    impl Version {
        fn of(metadata: &Metadata) -> Self {
            Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
                size: metadata.size(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                links: metadata.nlink(),
                mtime: (metadata.mtime(), metadata.mtime_nsec()),
                ctime: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
    }

    #[derive(Debug)]
    pub(super) struct ObservedFile {
        pub(super) file: File,
        version: Version,
        pub(super) digest: TypedDigest,
    }

    fn read_retry(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match file.read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }

    impl ObservedFile {
        pub(super) fn observe(
            path: &Path,
            domain: &'static str,
            maximum: u64,
        ) -> Result<Option<Self>, PutError> {
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(super::super::io_err("stat-existing")(error)),
            };
            if !metadata.is_file() || metadata.nlink() == 0 {
                return Err(PutError::Io {
                    step: "observe-existing-type",
                    error: "raw duplicate is not a named regular file".into(),
                });
            }
            if metadata.len() > maximum {
                return Err(PutError::LogicalLimitExceeded { limit: maximum });
            }
            let version = Version::of(&metadata);
            // Do not follow a leaf symlink or wait for a FIFO substituted after
            // the lstat. Validate the actual open object before consuming bytes.
            let descriptor = rustix::fs::open(
                path,
                OFlags::RDONLY
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::empty(),
            )
            .map_err(|error| super::super::io_err("open-existing-observation")(error.into()))?;
            let mut file = File::from(descriptor);
            validate_file(&file, path, &version)?;
            let mut hasher = Sha256::new();
            hasher.update((domain.len() as u64).to_be_bytes());
            hasher.update(domain.as_bytes());
            let mut buffer = vec![0_u8; BUFFER_BYTES];
            let mut remaining = version.size;
            while remaining != 0 {
                let bound =
                    usize::try_from(remaining.min(BUFFER_BYTES as u64)).map_err(|error| {
                        PutError::Io {
                            step: "observe-existing-size",
                            error: error.to_string(),
                        }
                    })?;
                let count = read_retry(&mut file, &mut buffer[..bound])
                    .map_err(super::super::io_err("read-existing-observation"))?;
                if count == 0 {
                    return Err(changed(path));
                }
                hasher.update(&buffer[..count]);
                remaining -= count as u64;
            }
            // Separate EOF probe avoids size + 1 overflow, even at u64::MAX.
            if read_retry(&mut file, &mut buffer[..1])
                .map_err(super::super::io_err("read-existing-observation"))?
                != 0
            {
                return Err(changed(path));
            }
            validate_file(&file, path, &version)?;
            Ok(Some(Self {
                file,
                version,
                digest: TypedDigest {
                    algorithm: DigestAlgorithm::Sha256V1,
                    domain,
                    bytes: hasher.finalize().into(),
                },
            }))
        }

        pub(super) fn validate(&self, path: &Path) -> Result<(), PutError> {
            validate_file(&self.file, path, &self.version)
        }
    }

    fn validate_file(file: &File, path: &Path, version: &Version) -> Result<(), PutError> {
        let held = file.metadata().map_err(|_| changed(path))?;
        let named = std::fs::symlink_metadata(path).map_err(|_| changed(path))?;
        if !held.is_file()
            || !named.is_file()
            || Version::of(&held) != *version
            || Version::of(&named) != *version
        {
            return Err(changed(path));
        }
        Ok(())
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;
