//! Exclusive lifetime ownership of a local Unix-socket pathname.
//!
//! A refused connect is necessary, but not sufficient, to retire a stale
//! socket: the endpoint lock and directory/socket generations must still
//! agree. Timeout, permissions, malformed state and replacement are not proof
//! of death. The lock inode is permanent, not PID-file state to delete.
//!
//! Networking and deadlines belong to the caller. Retain this lease until the
//! listener AND all admitted sessions/writers have ended. These advisory locks
//! fence participating daemons, not a hostile process with the same UID.

use rustix::fs::{AtFlags, Mode, OFlags, chmodat, open, openat, unlinkat};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

fn refused(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, detail)
}

fn inode(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

/// An observed socket generation; callers cannot manufacture one from a PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketStamp {
    inode: (u64, u64),
    ctime: (i64, i64),
    uid: u32,
    gid: u32,
    mode: u32,
}

impl SocketStamp {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            inode: inode(metadata),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
        }
    }
}

/// A fork can retain a duplicate open description until exec despite CLOEXEC.
/// Explicit unlock makes release a property of this owner, not the last child.
#[derive(Debug)]
struct Locked(File);

impl Drop for Locked {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// Non-clone endpoint lease, shared only by an outer lifetime owner. Dropping
/// it releases the lock but does NOT blindly remove a socket.
#[derive(Debug)]
pub struct EndpointLease {
    requested_parent: PathBuf,
    parent: PathBuf,
    directory: File,
    name: OsString,
    path: PathBuf,
    lock_name: OsString,
    uid: u32,
    bound: Option<SocketStamp>,
    // Release after the other owned descriptors and state.
    lock: Locked,
}

impl EndpointLease {
    /// Acquire without waiting, before probing, binding, chmod or retirement.
    /// New parents are private; existing parents must be same-user and not
    /// group/world writable. Parent aliases converge on one lock inode.
    ///
    /// # Errors
    /// Invalid paths, unsafe ownership/types, contention or filesystem errors.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        if !path.is_absolute()
            || path.file_name().is_none()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(refused("endpoint must be absolute without traversal"));
        }
        let requested_parent = path
            .parent()
            .ok_or_else(|| refused("endpoint parent"))?
            .to_owned();
        let name = path
            .file_name()
            .ok_or_else(|| refused("endpoint name"))?
            .to_owned();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&requested_parent)?;
        let parent = fs::canonicalize(&requested_parent)?;
        let directory = File::from(open(
            &parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let uid = rustix::process::geteuid().as_raw();
        validate_directory(&directory.metadata()?, uid)?;
        // NOT cargo-rabs's startup lock: that descriptor is deliberately
        // inherited by the daemon. A new open description would contend.
        let mut lock_name = OsString::from(".rabs-");
        lock_name.push(&name);
        lock_name.push(".endpoint.lock");
        let file = File::from(openat(
            &directory,
            lock_name.as_os_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        validate_lock(&file.metadata()?, uid)?;
        file.try_lock()
            .map_err(|error| io::Error::other(format!("endpoint lock unavailable: {error}")))?;
        // Install the explicit-unlock guard immediately, including on every
        // validation error below.
        let lock = Locked(file);
        let lease = Self {
            path: parent.join(&name),
            requested_parent,
            parent,
            directory,
            name,
            lock_name,
            uid,
            bound: None,
            lock,
        };
        lease.verify()?;
        Ok(lease)
    }

    /// Canonical parent spelling of the leased directory entry.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Kernel effective UID used for every ownership check.
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.uid
    }

    /// Revalidate namespace and lock identity before each endpoint mutation.
    /// Directory timestamps are not identities: unrelated sibling entries can
    /// legitimately change while a daemon is alive.
    ///
    /// # Errors
    /// Replaced/retargeted parents, unsafe metadata or lost lock identity.
    pub fn verify(&self) -> io::Result<()> {
        let held = self.directory.metadata()?;
        validate_directory(&held, self.uid)?;
        for named in [
            fs::symlink_metadata(&self.parent)?,
            fs::metadata(&self.requested_parent)?,
        ] {
            validate_directory(&named, self.uid)?;
            if inode(&named) != inode(&held) {
                return Err(refused("endpoint parent was replaced or retargeted"));
            }
        }
        let held = self.lock.0.metadata()?;
        let named = fs::symlink_metadata(self.parent.join(&self.lock_name))?;
        validate_lock(&held, self.uid)?;
        validate_lock(&named, self.uid)?;
        if inode(&held) != inode(&named) {
            return Err(refused(
                "endpoint lock pathname no longer names its held inode",
            ));
        }
        Ok(())
    }

    fn socket(&self, require_private: bool) -> io::Result<Option<SocketStamp>> {
        self.verify()?;
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_socket()
            || metadata.uid() != self.uid
            || metadata.nlink() != 1
            || (require_private && metadata.mode() & 0o777 != 0o600)
        {
            return Err(refused(
                "endpoint must be a same-user, single-link private socket",
            ));
        }
        self.verify()?;
        Ok(Some(SocketStamp::of(&metadata)))
    }

    /// Observe without following a final symlink. Unsafe entries are refusals,
    /// never something startup may repair.
    ///
    /// # Errors
    /// Filesystem errors, unsafe metadata or lost endpoint ownership.
    pub fn observe(&self) -> io::Result<Option<SocketStamp>> {
        self.socket(true)
    }

    /// Retire exactly the socket that returned ConnectionRefused. Pass the
    /// actual connection error, not a timeout or failed status read.
    ///
    /// # Errors
    /// Wrong probe result, changed generation, lost ownership or unlink error.
    pub fn retire_refused(&self, observed: SocketStamp, error: &io::Error) -> io::Result<()> {
        if self.bound.is_some() || error.kind() != io::ErrorKind::ConnectionRefused {
            return Err(refused(
                "retirement requires a refused connect before binding",
            ));
        }
        if self.observe()? != Some(observed) {
            return Err(refused("endpoint changed during its liveness probe"));
        }
        // Use the held directory, never a potentially retargeted parent alias.
        // Participating creators hold this lock across their entire lifetime.
        unlinkat(&self.directory, self.name.as_os_str(), AtFlags::empty())?;
        Ok(())
    }

    /// Call once after successfully binding a NEW listener. Record its final
    /// post-chmod generation for identity-checked teardown.
    ///
    /// # Errors
    /// Repeated claim, disappearance, replacement, unsafe type or chmod error.
    pub fn claim_bound(&mut self) -> io::Result<()> {
        if self.bound.is_some() {
            return Err(refused("endpoint already bound by this lease"));
        }
        let before = self
            .socket(false)?
            .ok_or_else(|| refused("new endpoint disappeared"))?;
        // The held private parent, not its absolute pathname. Even if an
        // ancestor is renamed concurrently, chmod cannot follow that new
        // ancestor to an unrelated file. Same-UID hostile mutation is outside
        // this advisory lease's boundary.
        chmodat(
            &self.directory,
            self.name.as_os_str(),
            Mode::from_raw_mode(0o600),
            AtFlags::empty(),
        )?;
        let after = self
            .observe()?
            .ok_or_else(|| refused("new endpoint disappeared after chmod"))?;
        if before.inode != after.inode || before.uid != after.uid || before.gid != after.gid {
            return Err(refused(
                "endpoint changed while claiming the bound listener",
            ));
        }
        self.bound = Some(after);
        Ok(())
    }

    /// Retire our exact generation only after listener and sessions end.
    /// False means absent/replaced, not permission to repair the replacement.
    ///
    /// # Errors
    /// Unsafe replacement, lost ownership or filesystem errors; nothing else
    /// is removed on their account.
    pub fn retire_bound(&self) -> io::Result<bool> {
        let Some(bound) = self.bound else {
            return Ok(false);
        };
        if self.observe()? != Some(bound) {
            return Ok(false);
        }
        unlinkat(&self.directory, self.name.as_os_str(), AtFlags::empty())?;
        Ok(true)
    }
}

fn validate_directory(metadata: &fs::Metadata, uid: u32) -> io::Result<()> {
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(refused(
            "endpoint parent must be same-user and not group/world writable",
        ));
    }
    Ok(())
}

fn validate_lock(metadata: &fs::Metadata, uid: u32) -> io::Result<()> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(refused(
            "endpoint lock must be a same-user private single-link regular file",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "socket_endpoint_tests.rs"]
mod tests;
