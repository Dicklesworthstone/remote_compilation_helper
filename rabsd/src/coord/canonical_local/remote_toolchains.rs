//! Process-lifetime reuse of received SDKs for the canonical remote service.
//!
//! The authenticated edge key and complete toolchain identity select a lease.
//! Every hit verifies its private owner and rehashes the retained bytes outside
//! the cache lock. Source trees, diagnostics and operation paths never enter the
//! cache. This is input reuse, with no action-result or publication authority.
//!
//! Active, invalidated and retiring images remain charged to the entry/byte
//! limits. Eviction requires exclusive ownership of the lease AND its image and
//! directory Arcs, because downstream compiler work can retain those separately.
//! Filesystem cleanup runs outside the mutex before its capacity is released.
//! Failed cleanup stays charged for this cache's lifetime; it cannot fund another
//! retained image. No catalogue or prior-process tree is adopted on restart.

use super::{ordinary_directory, private_directory};
use rabs_sandbox::toolchain_dataset::{PreparedToolchain, ToolchainIdentity};
use rustix::fs::{CWD, Dir, Mode, OFlags, ResolveFlags, openat2};
use std::collections::VecDeque;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(crate) const MAX_CACHE_ENTRIES: usize = 32;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote toolchain acquisition cancelled",
        ))
    } else {
        Ok(())
    }
}

fn same_directory(first: &Metadata, second: &Metadata) -> bool {
    first.is_dir()
        && second.is_dir()
        && (
            first.dev(),
            first.ino(),
            first.uid(),
            first.mode(),
            first.nlink(),
            first.mtime(),
            first.mtime_nsec(),
            first.ctime(),
            first.ctime_nsec(),
        ) == (
            second.dev(),
            second.ino(),
            second.uid(),
            second.mode(),
            second.nlink(),
            second.mtime(),
            second.mtime_nsec(),
            second.ctime(),
            second.ctime_nsec(),
        )
}

/// Exact received image and its independently owned, SDK-only directory.
/// Keep this lease through use, or retain BOTH image and owner when handing
/// their existing typed custody to a downstream compiler lease.
#[derive(Debug)]
pub(crate) struct ReceivedToolchain {
    // Close image and owner descriptors before releasing the private directory.
    image: Arc<PreparedToolchain>,
    directory: File,
    stamp: Metadata,
    owner: Arc<tempfile::TempDir>,
}

impl ReceivedToolchain {
    /// The sealed receiver/capture already verified the image's complete bytes.
    /// Bind that exact generation to its sole direct-child owner; this does not
    /// refresh the image witness or copy the SDK again.
    pub(crate) fn new(
        owner: Arc<tempfile::TempDir>,
        image: Arc<PreparedToolchain>,
        stopped: impl Fn() -> bool,
    ) -> io::Result<Self> {
        checkpoint(&stopped)?;
        private_directory(owner.path())?;
        if image.root().parent() != Some(owner.path()) {
            return Err(invalid(
                "received compiler must be a direct child of its private SDK owner",
            ));
        }
        ordinary_directory(image.root())?;
        let directory = File::from(openat2(
            CWD,
            owner.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?);
        let stamp = directory.metadata()?;
        let received = Self {
            image,
            directory,
            stamp,
            owner,
        };
        received.verify(&stopped)?;
        let expected = received
            .root()
            .file_name()
            .ok_or_else(|| invalid("received compiler has no owned child name"))?;
        let mut count = 0;
        let mut entries = Dir::read_from(&received.directory)?;
        for entry in &mut entries {
            checkpoint(&stopped)?;
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            if name != expected.as_bytes() {
                return Err(invalid(
                    "received compiler owner must contain only its SDK tree",
                ));
            }
            count += 1;
        }
        if count != 1 {
            return Err(invalid(
                "received compiler owner must contain exactly one SDK tree",
            ));
        }
        received.verify(&stopped)?;
        Ok(received)
    }

    pub(crate) fn image(&self) -> &Arc<PreparedToolchain> {
        &self.image
    }

    pub(crate) fn owner(&self) -> &Arc<tempfile::TempDir> {
        &self.owner
    }

    pub(crate) fn root(&self) -> &Path {
        self.image.root()
    }

    pub(crate) fn identity(&self) -> &ToolchainIdentity {
        self.image.identity()
    }

    fn verify_owner(&self) -> io::Result<()> {
        private_directory(self.owner.path())?;
        let named = fs::symlink_metadata(self.owner.path())?;
        let held = self.directory.metadata()?;
        if !same_directory(&self.stamp, &held) || !same_directory(&self.stamp, &named) {
            return Err(invalid("received compiler directory ownership changed"));
        }
        if self.root().parent() != Some(self.owner.path()) {
            return Err(invalid("received compiler lost its private owner"));
        }
        Ok(())
    }

    /// Recheck the original owner and complete retained inode/mutation witness.
    /// Later execution/delivery phases use this barrier without rehashing the
    /// same bytes repeatedly. Cache acquisition performs a fresh full scan.
    pub(crate) fn verify(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        checkpoint(&stopped)?;
        self.verify_owner()?;
        self.image.verify_retained_generation(&stopped)?;
        self.verify_owner()?;
        checkpoint(&stopped)
    }

    fn verify_bytes(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        self.verify_owner()?;
        self.image.verify(stopped)?;
        self.verify_owner()?;
        checkpoint(stopped)
    }

    fn idle(lease: &mut Arc<Self>) -> bool {
        Arc::get_mut(lease).is_some_and(|received| {
            Arc::get_mut(&mut received.image).is_some()
                && Arc::get_mut(&mut received.owner).is_some()
        })
    }

    fn reclaim(lease: Arc<Self>) -> io::Result<()> {
        // Selection proved exclusive outer and inner ownership while locked.
        // No escaped strong or weak reference can create another reader now.
        let received = Arc::try_unwrap(lease)
            .map_err(|_| invalid("retiring compiler still has an active lease"))?;
        // A corrupt SDK may be removed, but only beneath its exact owned parent.
        // Do not require an intact image generation merely to reclaim it.
        let owner_witness = received.verify_owner();
        let Self {
            image,
            directory,
            stamp: _,
            owner,
        } = received;
        drop(image);
        let owner = Arc::try_unwrap(owner)
            .map_err(|_| invalid("retiring compiler still has an active owner"))?;
        if let Err(error) = owner_witness {
            // TempDir's ordinary Drop would follow the old pathname even when
            // it now names someone else's replacement. Disarm that cleanup.
            let _retained_path = owner.keep();
            drop(directory);
            return Err(error);
        }
        // Keep the directory descriptor alive through explicit close. As with
        // TempDir itself, the private pathname must not be concurrently replaced
        // after this owner check; no path-based close claims race-free deletion.
        let result = owner.close();
        drop(directory);
        result
    }
}

struct Entry {
    peer: [u8; 32],
    lease: Arc<ReceivedToolchain>,
    invalidated: bool,
}

#[derive(Default)]
struct State {
    entries: VecDeque<Entry>,
    // Retiring owners have left lookup but retain their quota until successful
    // cleanup. Failed cleanup permanently consumes its process-lifetime quota.
    retiring_entries: usize,
    retained_bytes: u64,
}

/// Bounded service-owned input retention. Zero bytes disables retention while
/// leaving normal private uploads usable. A full cache never blocks admission.
pub(crate) struct RemoteToolchainCache {
    max_bytes: u64,
    max_entries: usize,
    state: Mutex<State>,
}

enum Adoption<'a> {
    Existing(Arc<ReceivedToolchain>),
    Retained,
    Private,
    Retire(Retirement<'a>),
}

/// Explicit filesystem cleanup can block. Keep its quota charged until close
/// succeeds, without holding the cache mutex or exposing the retired owners.
struct Retirement<'a> {
    cache: &'a RemoteToolchainCache,
    entries: Vec<Entry>,
}

impl Retirement<'_> {
    fn reclaim(&mut self) -> io::Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let mut released_entries = 0;
        let mut released_bytes = 0;
        let mut failure = None;
        for entry in self.entries.drain(..) {
            let bytes = entry.lease.identity().bytes;
            match ReceivedToolchain::reclaim(entry.lease) {
                Ok(()) => {
                    released_entries += 1;
                    released_bytes += bytes;
                }
                Err(error) => {
                    // Neither best-effort Drop nor an uncertain pathname can
                    // authorize releasing capacity. Keep failed owners charged.
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }
        let mut state = self
            .cache
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.retiring_entries -= released_entries;
        state.retained_bytes -= released_bytes;
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn finish(mut self) -> io::Result<()> {
        self.reclaim()
    }
}

impl Drop for Retirement<'_> {
    fn drop(&mut self) {
        // Cancellation or unwinding cannot release unconfirmed cleanup quota.
        let _ = self.reclaim();
    }
}

impl RemoteToolchainCache {
    pub(crate) fn new(max_bytes: u64, max_entries: usize) -> io::Result<Self> {
        if max_bytes > MAX_CACHE_BYTES || !(1..=MAX_CACHE_ENTRIES).contains(&max_entries) {
            return Err(invalid("remote toolchain cache limits outside their bounds"));
        }
        Ok(Self {
            max_bytes,
            max_entries,
            state: Mutex::new(State::default()),
        })
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| invalid("remote toolchain cache ownership is poisoned"))
    }

    fn select(
        state: &mut State,
        peer: [u8; 32],
        identity: &ToolchainIdentity,
    ) -> Option<Arc<ReceivedToolchain>> {
        let index = state.entries.iter().rposition(|entry| {
            entry.peer == peer && !entry.invalidated && entry.lease.identity() == identity
        })?;
        let entry = state.entries.remove(index).expect("selected SDK entry");
        let lease = Arc::clone(&entry.lease);
        state.entries.push_back(entry);
        Some(lease)
    }

    fn invalidate(&self, peer: [u8; 32], failed: &Arc<ReceivedToolchain>) -> io::Result<()> {
        if let Some(entry) = self
            .lock()?
            .entries
            .iter_mut()
            .find(|entry| entry.peer == peer && Arc::ptr_eq(&entry.lease, failed))
        {
            // Keep an invalid predecessor charged while any escaped reader or
            // ownership witness still exists. Never invalidate its replacement.
            entry.invalidated = true;
        }
        Ok(())
    }

    fn verified(
        &self,
        peer: [u8; 32],
        lease: Arc<ReceivedToolchain>,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Arc<ReceivedToolchain>> {
        if let Err(error) = lease.verify_bytes(stopped) {
            if error.kind() != io::ErrorKind::Interrupted && !stopped() {
                self.invalidate(peer, &lease)?;
            }
            return Err(error);
        }
        checkpoint(stopped)?;
        if !self.lock()?.entries.iter().any(|entry| {
            entry.peer == peer && !entry.invalidated && Arc::ptr_eq(&entry.lease, &lease)
        }) {
            return Err(invalid("received compiler was invalidated during acquisition"));
        }
        Ok(lease)
    }

    /// Only this authenticated edge's complete identity may reuse a received
    /// image. Verification failures refuse this operation, never hide as misses.
    /// Cancellation leaves a ready entry available to other callers.
    pub(crate) fn lookup(
        &self,
        peer: [u8; 32],
        identity: &ToolchainIdentity,
        stopped: impl Fn() -> bool,
    ) -> io::Result<Option<Arc<ReceivedToolchain>>> {
        checkpoint(&stopped)?;
        if self.max_bytes == 0 || identity.bytes > self.max_bytes {
            return Ok(None);
        }
        let selected = {
            let mut state = self.lock()?;
            Self::select(&mut state, peer, identity)
        };
        selected
            .map(|lease| self.verified(peer, lease, &stopped))
            .transpose()
    }

    /// Retain a completed upload without copying bytes. A concurrently retained
    /// same-identity image wins only after its own full verification. Disabled,
    /// oversized or fully leased retention returns the caller's private upload.
    pub(crate) fn adopt(
        &self,
        peer: [u8; 32],
        uploaded: Arc<ReceivedToolchain>,
        stopped: impl Fn() -> bool,
    ) -> io::Result<Arc<ReceivedToolchain>> {
        uploaded.verify(&stopped)?;
        if self.max_bytes == 0 || uploaded.identity().bytes > self.max_bytes {
            return Ok(uploaded);
        }
        let mut may_retire = true;
        loop {
            checkpoint(&stopped)?;
            match self.plan_adoption(peer, &uploaded, may_retire)? {
                Adoption::Existing(lease) => return self.verified(peer, lease, &stopped),
                Adoption::Retained | Adoption::Private => {
                    checkpoint(&stopped)?;
                    return Ok(uploaded);
                }
                Adoption::Retire(retired) => {
                    retired.finish()?;
                    // At most one bounded cleanup pass. Concurrent admissions
                    // may claim the released room; use private custody then.
                    may_retire = false;
                }
            }
        }
    }

    fn plan_adoption<'a>(
        &'a self,
        peer: [u8; 32],
        uploaded: &Arc<ReceivedToolchain>,
        may_retire: bool,
    ) -> io::Result<Adoption<'a>> {
        let identity = uploaded.identity();
        let available = self.max_bytes - identity.bytes;
        let mut state = self.lock()?;
        if let Some(existing) = Self::select(&mut state, peer, identity) {
            return Ok(Adoption::Existing(existing));
        }
        let occupied = state.entries.len() + state.retiring_entries;
        if occupied < self.max_entries && state.retained_bytes <= available {
            state.retained_bytes += identity.bytes;
            state.entries.push_back(Entry {
                peer,
                lease: Arc::clone(uploaded),
                invalidated: false,
            });
            return Ok(Adoption::Retained);
        }
        if !may_retire {
            return Ok(Adoption::Private);
        }

        // Plan a sufficient set before evicting anything. An unrelated live
        // lease or cleanup reservation must not cause pointless cache churn.
        let mut candidates = state
            .entries
            .iter_mut()
            .enumerate()
            .filter_map(|(index, entry)| {
                ReceivedToolchain::idle(&mut entry.lease).then_some((
                    !entry.invalidated,
                    index,
                    entry.lease.identity().bytes,
                ))
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|(valid, index, _)| (*valid, *index));
        let mut projected_entries = occupied;
        let mut projected_bytes = state.retained_bytes;
        let mut selected = Vec::new();
        for (_, index, bytes) in candidates {
            projected_entries -= 1;
            projected_bytes -= bytes;
            selected.push(index);
            if projected_entries < self.max_entries && projected_bytes <= available {
                break;
            }
        }
        if projected_entries >= self.max_entries || projected_bytes > available {
            return Ok(Adoption::Private);
        }
        selected.sort_unstable_by(|first, second| second.cmp(first));
        let mut entries = Vec::with_capacity(selected.len());
        for index in selected {
            entries.push(state.entries.remove(index).expect("idle SDK entry"));
        }
        state.retiring_entries += entries.len();
        drop(state);
        Ok(Adoption::Retire(Retirement {
            cache: self,
            entries,
        }))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rabs_sandbox::toolchain_dataset::{ToolchainLimits, capture_toolchain};
    use std::cell::Cell;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::time::{Duration, Instant};

    const EDGE_A: [u8; 32] = [1; 32];
    const EDGE_B: [u8; 32] = [2; 32];

    fn private() -> tempfile::TempDir {
        crate::test_util::private_tempdir()
    }

    fn capture(owner: &Arc<tempfile::TempDir>, bytes: &[u8]) -> Arc<PreparedToolchain> {
        let source = private();
        fs::write(source.path().join("compiler"), bytes).unwrap();
        Arc::new(
            capture_toolchain(
                source.path(),
                &owner.path().join("toolchain"),
                None,
                &ToolchainLimits::default(),
                || false,
            )
            .unwrap(),
        )
    }

    fn fixture(bytes: &[u8]) -> Arc<ReceivedToolchain> {
        let owner = Arc::new(private());
        let image = capture(&owner, bytes);
        Arc::new(ReceivedToolchain::new(owner, image, || false).unwrap())
    }

    fn counts(cache: &RemoteToolchainCache) -> (usize, usize, u64) {
        let state = cache.lock().unwrap();
        (
            state.entries.len(),
            state.retiring_entries,
            state.retained_bytes,
        )
    }

    #[test]
    fn configuration_bounds_and_disabled_or_oversized_retention_keep_private_custody() {
        assert!(RemoteToolchainCache::new(MAX_CACHE_BYTES, MAX_CACHE_ENTRIES).is_ok());
        assert!(RemoteToolchainCache::new(MAX_CACHE_BYTES + 1, 1).is_err());
        for entries in [0, MAX_CACHE_ENTRIES + 1, usize::MAX] {
            assert!(RemoteToolchainCache::new(1, entries).is_err());
        }
        for budget in [0, 3] {
            let cache = RemoteToolchainCache::new(budget, 1).unwrap();
            let uploaded = fixture(b"four");
            let lease = cache.adopt(EDGE_A, Arc::clone(&uploaded), || false).unwrap();
            assert!(Arc::ptr_eq(&lease, &uploaded));
            assert!(lease.root().is_dir());
            assert!(cache.lookup(EDGE_A, lease.identity(), || false).unwrap().is_none());
            assert_eq!(counts(&cache), (0, 0, 0));
        }
    }

    #[test]
    fn exact_authenticated_identity_reuses_without_copy_and_other_edges_remain_isolated() {
        let cache = RemoteToolchainCache::new(64, 4).unwrap();
        let uploaded = fixture(b"same immutable SDK");
        let identity = *uploaded.identity();
        let root = uploaded.root().to_path_buf();
        let lease = cache.adopt(EDGE_A, Arc::clone(&uploaded), || false).unwrap();
        let hit = cache.lookup(EDGE_A, &identity, || false).unwrap().unwrap();
        assert!(Arc::ptr_eq(&hit, &uploaded));
        assert_eq!(hit.root(), root);
        assert!(cache.lookup(EDGE_B, &identity, || false).unwrap().is_none());

        for changed in [
            ToolchainIdentity { sha256: [0; 32], ..identity },
            ToolchainIdentity { files: identity.files + 1, ..identity },
            ToolchainIdentity { bytes: identity.bytes + 1, ..identity },
        ] {
            assert!(cache.lookup(EDGE_A, &changed, || false).unwrap().is_none());
        }

        let duplicate = fixture(b"same immutable SDK");
        assert_eq!(*duplicate.identity(), identity);
        let same_edge = cache.adopt(EDGE_A, Arc::clone(&duplicate), || false).unwrap();
        assert!(Arc::ptr_eq(&same_edge, &lease));
        assert_eq!(counts(&cache), (1, 0, identity.bytes));
        let other_edge = cache.adopt(EDGE_B, duplicate, || false).unwrap();
        assert!(!Arc::ptr_eq(&other_edge, &lease));
        assert_ne!(other_edge.root(), lease.root());
        assert!(Arc::ptr_eq(
            &cache.lookup(EDGE_B, &identity, || false).unwrap().unwrap(),
            &other_edge,
        ));
        assert_eq!(counts(&cache), (2, 0, 2 * identity.bytes));
    }

    #[test]
    fn received_constructor_refuses_foreign_nested_shared_and_nonprivate_owners() {
        let lease = fixture(b"compiler bytes");
        assert!(ReceivedToolchain::new(
            Arc::new(private()),
            Arc::clone(lease.image()),
            || false,
        ).is_err());

        let nested_owner = Arc::new(private());
        let nested = nested_owner.path().join("nested");
        fs::DirBuilder::new().mode(0o700).create(&nested).unwrap();
        let source = private();
        fs::write(source.path().join("compiler"), b"nested image").unwrap();
        let nested_image = Arc::new(capture_toolchain(
            source.path(),
            &nested.join("toolchain"),
            None,
            &ToolchainLimits::default(),
            || false,
        ).unwrap());
        assert!(ReceivedToolchain::new(nested_owner, nested_image, || false).is_err());

        let shared_owner = Arc::new(private());
        let shared_image = capture(&shared_owner, b"compiler bytes");
        fs::write(shared_owner.path().join("source"), b"private project input").unwrap();
        assert!(ReceivedToolchain::new(shared_owner, shared_image, || false).is_err());

        let nonprivate = Arc::new(private());
        let image = capture(&nonprivate, b"compiler bytes");
        fs::set_permissions(nonprivate.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ReceivedToolchain::new(nonprivate, image, || false).is_err());
    }

    #[test]
    fn owner_replacement_and_new_siblings_cannot_rebind_a_received_generation() {
        let parent = private();
        let owner = Arc::new(
            tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(parent.path())
                .unwrap(),
        );
        let image = capture(&owner, b"original compiler");
        let lease = ReceivedToolchain::new(Arc::clone(&owner), image, || false).unwrap();
        let original = owner.path().to_path_buf();
        let displaced = parent.path().join("displaced");
        fs::rename(&original, &displaced).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&original).unwrap();
        assert!(lease.verify(|| false).is_err());
        assert!(displaced.join("toolchain/compiler").is_file());

        let lease = fixture(b"another compiler");
        fs::write(lease.owner().path().join("unexpected-source"), b"not SDK").unwrap();
        assert!(lease.verify(|| false).is_err());
    }

    fn corrupt(lease: &ReceivedToolchain) {
        let file = lease.root().join("compiler");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(file, b"changed compiler bytes").unwrap();
    }

    #[test]
    fn corrupt_hit_refuses_then_keeps_invalidated_active_bytes_charged() {
        let cache = RemoteToolchainCache::new(64, 1).unwrap();
        let stale = cache.adopt(EDGE_A, fixture(b"original"), || false).unwrap();
        let identity = *stale.identity();
        corrupt(&stale);
        let error = cache.lookup(EDGE_A, &identity, || false).unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(counts(&cache), (1, 0, identity.bytes));
        assert!(cache.lock().unwrap().entries[0].invalidated);
        assert!(cache.lookup(EDGE_A, &identity, || false).unwrap().is_none());

        let fresh = fixture(b"original");
        assert_eq!(*fresh.identity(), identity);
        let private = cache.adopt(EDGE_A, Arc::clone(&fresh), || false).unwrap();
        assert!(Arc::ptr_eq(&private, &fresh));
        assert!(cache.lookup(EDGE_A, &identity, || false).unwrap().is_none());
        assert_eq!(counts(&cache), (1, 0, identity.bytes));

        drop(stale);
        let retained = cache.adopt(EDGE_A, fresh, || false).unwrap();
        assert!(Arc::ptr_eq(
            &cache.lookup(EDGE_A, &identity, || false).unwrap().unwrap(),
            &retained,
        ));
        assert_eq!(counts(&cache), (1, 0, identity.bytes));
    }

    #[test]
    fn late_validation_failure_cannot_invalidate_a_newer_same_identity_owner() {
        let cache = RemoteToolchainCache::new(64, 2).unwrap();
        let old = cache.adopt(EDGE_A, fixture(b"original"), || false).unwrap();
        let identity = *old.identity();
        corrupt(&old);
        assert!(cache.lookup(EDGE_A, &identity, || false).is_err());
        let new = cache.adopt(EDGE_A, fixture(b"original"), || false).unwrap();
        assert!(!Arc::ptr_eq(&old, &new));
        assert_eq!(counts(&cache), (2, 0, identity.bytes * 2));
        cache.invalidate(EDGE_A, &old).unwrap();
        assert!(Arc::ptr_eq(
            &cache.lookup(EDGE_A, &identity, || false).unwrap().unwrap(),
            &new,
        ));
        let overflow = fixture(b"other");
        let overflow_id = *overflow.identity();
        let private = cache.adopt(EDGE_A, Arc::clone(&overflow), || false).unwrap();
        assert!(Arc::ptr_eq(&private, &overflow));
        assert!(cache.lookup(EDGE_A, &overflow_id, || false).unwrap().is_none());
        assert_eq!(counts(&cache), (2, 0, identity.bytes * 2));
    }

    #[test]
    fn escaped_image_owner_and_weak_handles_prevent_retention_capacity_escape() {
        for escape in 0..5 {
            let cache = RemoteToolchainCache::new(64, 1).unwrap();
            let original = cache.adopt(EDGE_A, fixture(b"first"), || false).unwrap();
            let identity = *original.identity();
            let path = original.owner().path().to_path_buf();
            let handles = (
                (escape == 0).then(|| Arc::clone(original.image())),
                (escape == 1).then(|| Arc::downgrade(original.image())),
                (escape == 2).then(|| Arc::clone(original.owner())),
                (escape == 3).then(|| Arc::downgrade(original.owner())),
                (escape == 4).then(|| Arc::downgrade(&original)),
            );
            drop(original);

            let replacement = fixture(b"second");
            let replacement_id = *replacement.identity();
            let private = cache.adopt(EDGE_A, Arc::clone(&replacement), || false).unwrap();
            assert!(Arc::ptr_eq(&private, &replacement));
            assert!(cache.lookup(EDGE_A, &identity, || false).unwrap().is_some());
            assert!(cache.lookup(EDGE_A, &replacement_id, || false).unwrap().is_none());
            assert!(path.is_dir());
            assert_eq!(counts(&cache), (1, 0, identity.bytes));

            drop(handles);
            let retained = cache.adopt(EDGE_A, replacement, || false).unwrap();
            assert!(Arc::ptr_eq(
                &cache.lookup(EDGE_A, &replacement_id, || false).unwrap().unwrap(),
                &retained,
            ));
            assert!(!path.exists(), "idle predecessor cleanup was not completed");
            assert_eq!(counts(&cache), (1, 0, replacement_id.bytes));
        }
    }

    #[test]
    fn cancellation_is_checked_outside_mutex_and_does_not_invalidate_shared_inputs() {
        let cache = RemoteToolchainCache::new(64, 1).unwrap();
        let lease = cache.adopt(EDGE_A, fixture(b"retained"), || false).unwrap();
        let identity = *lease.identity();
        for stop_after in 1..=8 {
            let checks = Cell::new(0);
            let error = cache.lookup(EDGE_A, &identity, || {
                assert!(cache.state.try_lock().is_ok());
                checks.set(checks.get() + 1);
                checks.get() >= stop_after
            }).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(!cache.lock().unwrap().entries[0].invalidated);
            assert!(Arc::ptr_eq(
                &cache.lookup(EDGE_A, &identity, || false).unwrap().unwrap(),
                &lease,
            ));
        }
        assert_eq!(
            cache.adopt(EDGE_A, fixture(b"other"), || true).unwrap_err().kind(),
            io::ErrorKind::Interrupted,
        );
        assert_eq!(counts(&cache), (1, 0, identity.bytes));
    }

    #[test]
    fn lru_eviction_obeys_the_byte_bound_and_preserves_recent_owners() {
        let cache = RemoteToolchainCache::new(8, 3).unwrap();
        let first = cache.adopt(EDGE_A, fixture(b"aaaa"), || false).unwrap();
        let first_id = *first.identity();
        let second = cache.adopt(EDGE_A, fixture(b"bbbb"), || false).unwrap();
        let second_id = *second.identity();
        drop((first, second));
        drop(cache.lookup(EDGE_A, &first_id, || false).unwrap().unwrap());

        let third = cache.adopt(EDGE_A, fixture(b"cccc"), || false).unwrap();
        assert!(cache.lookup(EDGE_A, &first_id, || false).unwrap().is_some());
        assert!(cache.lookup(EDGE_A, &second_id, || false).unwrap().is_none());
        assert!(Arc::ptr_eq(
            &cache.lookup(EDGE_A, third.identity(), || false).unwrap().unwrap(),
            &third,
        ));
        assert_eq!(counts(&cache), (2, 0, 8));
    }

    #[test]
    fn insufficient_idle_bytes_do_not_evict_an_unrelated_usable_image() {
        let cache = RemoteToolchainCache::new(8, 3).unwrap();
        let active = cache.adopt(EDGE_A, fixture(b"busy"), || false).unwrap();
        let idle = cache.adopt(EDGE_A, fixture(b"idle"), || false).unwrap();
        let idle_id = *idle.identity();
        drop(idle);
        let incoming = fixture(b"large SDK");
        // This image is too large for the configured budget at all.
        let private = cache.adopt(EDGE_A, Arc::clone(&incoming), || false).unwrap();
        assert!(Arc::ptr_eq(&private, &incoming));
        assert!(cache.lookup(EDGE_A, &idle_id, || false).unwrap().is_some());

        let incoming = fixture(b"larger");
        let incoming_id = *incoming.identity();
        let private = cache.adopt(EDGE_A, Arc::clone(&incoming), || false).unwrap();
        assert!(Arc::ptr_eq(&private, &incoming));
        assert!(cache.lookup(EDGE_A, &incoming_id, || false).unwrap().is_none());
        assert!(cache.lookup(EDGE_A, &idle_id, || false).unwrap().is_some());
        assert!(cache.lookup(EDGE_A, active.identity(), || false).unwrap().is_some());
        assert_eq!(counts(&cache), (2, 0, 8));
    }

    #[test]
    fn retiring_owners_stay_charged_and_cleanup_does_not_hold_the_cache_mutex() {
        let cache = RemoteToolchainCache::new(8, 1).unwrap();
        let old = cache.adopt(EDGE_A, fixture(b"old"), || false).unwrap();
        let path = old.owner().path().to_path_buf();
        let identity = *old.identity();
        drop(old);
        let incoming = fixture(b"new");
        let retirement = match cache.plan_adoption(EDGE_A, &incoming, true).unwrap() {
            Adoption::Retire(retirement) => retirement,
            _ => panic!("an idle owner must be retired before replacement"),
        };
        assert_eq!(counts(&cache), (0, 1, identity.bytes));
        assert!(path.is_dir());
        let private = cache.adopt(EDGE_A, Arc::clone(&incoming), || false).unwrap();
        assert!(Arc::ptr_eq(&private, &incoming));
        assert_eq!(counts(&cache), (0, 1, identity.bytes));

        std::thread::scope(|scope| {
            let guard = cache.lock().unwrap();
            let cleanup = scope.spawn(move || drop(retirement));
            // Cleanup must finish unlinking even while admission is locked;
            // releasing its accounting is the only step that waits for us.
            let deadline = Instant::now() + Duration::from_secs(5);
            while path.exists() {
                assert!(Instant::now() < deadline, "cleanup waited for the cache mutex");
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(guard.retiring_entries, 1);
            assert_eq!(guard.retained_bytes, identity.bytes);
            drop(guard);
            cleanup.join().unwrap();
        });
        assert_eq!(counts(&cache), (0, 0, 0));
        let retained = cache.adopt(EDGE_A, incoming, || false).unwrap();
        assert!(cache.lookup(EDGE_A, retained.identity(), || false).unwrap().is_some());
        assert_eq!(counts(&cache), (1, 0, retained.identity().bytes));
    }

    #[test]
    fn failed_owner_reclamation_keeps_quota_and_preserves_replacement_paths() {
        for replacement_is_directory in [false, true] {
            let parent = private();
            let owner = Arc::new(
                tempfile::Builder::new()
                    .prefix("received-sdk-")
                    .tempdir_in(parent.path())
                    .unwrap(),
            );
            let image = capture(&owner, b"old compiler");
            let old = Arc::new(ReceivedToolchain::new(owner, image, || false).unwrap());
            let cache = RemoteToolchainCache::new(64, 1).unwrap();
            let old = cache.adopt(EDGE_A, old, || false).unwrap();
            let identity = *old.identity();
            let path = old.owner().path().to_path_buf();
            let displaced = parent.path().join("displaced-sdk");
            fs::rename(&path, &displaced).unwrap();
            let sentinel = if replacement_is_directory {
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                path.join("unrelated-sentinel")
            } else {
                path.clone()
            };
            fs::write(&sentinel, b"not the received SDK").unwrap();

            assert!(cache.lookup(EDGE_A, &identity, || false).is_err());
            assert!(cache.lock().unwrap().entries[0].invalidated);
            drop(old);
            let incoming = fixture(b"new compiler");
            assert!(cache.adopt(EDGE_A, Arc::clone(&incoming), || false).is_err());
            assert_eq!(counts(&cache), (0, 1, identity.bytes));
            assert_eq!(fs::read(&sentinel).unwrap(), b"not the received SDK");
            assert_eq!(
                fs::read(displaced.join("toolchain/compiler")).unwrap(),
                b"old compiler",
            );

            // Failed cleanup cannot finance another retained image. Ordinary
            // admission remains usable with its independent uploaded owner.
            let private = cache.adopt(EDGE_A, Arc::clone(&incoming), || false).unwrap();
            assert!(Arc::ptr_eq(&private, &incoming));
            assert!(cache.lookup(EDGE_A, incoming.identity(), || false).unwrap().is_none());
            assert_eq!(counts(&cache), (0, 1, identity.bytes));
            drop(cache);
            assert_eq!(fs::read(&sentinel).unwrap(), b"not the received SDK");
            assert!(displaced.join("toolchain/compiler").is_file());
        }
    }

    #[test]
    fn dropping_the_pool_preserves_an_active_lease_and_does_not_adopt_restart_paths() {
        let cache = RemoteToolchainCache::new(64, 1).unwrap();
        let lease = cache.adopt(EDGE_A, fixture(b"retained compiler"), || false).unwrap();
        let identity = *lease.identity();
        let path = lease.owner().path().to_path_buf();
        drop(cache);
        assert!(path.is_dir());
        lease.verify(|| false).unwrap();

        let restarted = RemoteToolchainCache::new(64, 1).unwrap();
        assert!(restarted.lookup(EDGE_A, &identity, || false).unwrap().is_none());
        assert_eq!(counts(&restarted), (0, 0, 0));
        drop(lease);
        assert!(!path.exists());
    }
}
