//! Storage lifetime for disposable remote input bytes.
//!
//! Durable storage preserves only byte objects. Its exclusive owner survives
//! every cache lease so a replacement service cannot apply a different quota
//! while an earlier upload still owns a writer or a frozen snapshot.

use super::{private_directory, require};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const OWNER_LOCK: &str = "canonical-input-cache.lock";

fn private_lock(metadata: &Metadata) -> bool {
    metadata.is_file()
        && metadata.nlink() == 1
        && metadata.len() == 0
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.mode() & 0o777 == 0o600
}

pub(super) enum InputCacheStorage {
    Ephemeral(tempfile::TempDir),
    Persistent {
        path: PathBuf,
        identity: (u64, u64),
        lock: File,
    },
}

impl InputCacheStorage {
    pub(super) fn ephemeral(parent: &Path, prefix: &str) -> io::Result<Self> {
        private_directory(parent)?;
        Ok(Self::Ephemeral(
            tempfile::Builder::new()
                .prefix(prefix)
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)?,
        ))
    }

    pub(super) fn persistent(path: &Path) -> io::Result<Self> {
        private_directory(path)?;
        let metadata = fs::symlink_metadata(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path.join(OWNER_LOCK))?;
        require(
            private_lock(&lock.metadata()?),
            "persistent input cache ownership lock must be an empty private ordinary file",
        )?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "persistent input cache is still owned by another service or upload",
                ));
            }
            Err(fs::TryLockError::Error(error)) => return Err(error),
        }
        let storage = Self::Persistent {
            path: path.to_path_buf(),
            identity: (metadata.dev(), metadata.ino()),
            lock,
        };
        storage.verify()?;
        Ok(storage)
    }

    pub(super) fn path(&self) -> &Path {
        match self {
            Self::Ephemeral(owner) => owner.path(),
            Self::Persistent { path, .. } => path,
        }
    }

    pub(super) fn verify(&self) -> io::Result<()> {
        private_directory(self.path())?;
        if let Self::Persistent {
            path,
            identity,
            lock,
        } = self
        {
            let directory = fs::symlink_metadata(path)?;
            require(
                *identity == (directory.dev(), directory.ino()),
                "persistent input cache directory changed",
            )?;
            let held = lock.metadata()?;
            let named = fs::symlink_metadata(path.join(OWNER_LOCK))?;
            require(
                private_lock(&held)
                    && named.is_file()
                    && held.dev() == named.dev()
                    && held.ino() == named.ino(),
                "persistent input cache ownership lock changed or is unsafe",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;

    fn private() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn persistent_storage_reopens_only_after_the_last_input_lease() {
        let parent = private();
        let owner = Arc::new(InputCacheStorage::persistent(parent.path()).unwrap());
        let lease = Arc::clone(&owner);
        drop(owner);
        assert_eq!(
            InputCacheStorage::persistent(parent.path())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(lease);
        let reopened = InputCacheStorage::persistent(parent.path()).unwrap();
        reopened.verify().unwrap();
        drop(reopened);
        assert!(parent.path().join(OWNER_LOCK).is_file());
    }

    #[test]
    fn persistent_storage_refuses_foreign_or_replaced_lock_files() {
        for kind in ["symlink", "hardlink", "contents", "mode", "fifo"] {
            let parent = private();
            let other = parent.path().join("other");
            let path = parent.path().join(OWNER_LOCK);
            fs::write(&other, []).unwrap();
            fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
            match kind {
                "symlink" => symlink(&other, &path).unwrap(),
                "hardlink" => fs::hard_link(&other, &path).unwrap(),
                "contents" => fs::write(&path, b"unrelated state").unwrap(),
                "mode" => {
                    fs::write(&path, []).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                "fifo" => rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .unwrap(),
                _ => unreachable!(),
            }
            assert!(
                InputCacheStorage::persistent(parent.path()).is_err(),
                "{kind}"
            );
        }

        let parent = private();
        let owner = InputCacheStorage::persistent(parent.path()).unwrap();
        fs::rename(
            parent.path().join(OWNER_LOCK),
            parent.path().join("replaced-lock"),
        )
        .unwrap();
        fs::write(parent.path().join(OWNER_LOCK), []).unwrap();
        assert!(owner.verify().is_err());
    }
}
