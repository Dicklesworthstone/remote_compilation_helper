//! Bounded ownership of prepared toolchains for concurrent project toolchains.
//!
//! Keys select a preparation, never establish its validity. The live caller
//! rechecks the complete source/toolchain witness after every lookup and keeps
//! that same owner through execution and installation. Only unleased images may
//! be evicted. One background capture at a time preserves the original copy-I/O
//! bound; ready images remain usable while a different toolchain is preparing.
//! Invalidated generations remain owned and counted, but do not block a fresh
//! capture under the same path when another retention slot is available.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::toolchain_dataset::{PreparedToolchain, ToolchainLimits, capture_toolchain_with_cloner};

/// Includes a pending capture and invalidated images still held by requests.
/// Each image also retains the existing ToolchainLimits. This is an image-count
/// bound, not filesystem free-space admission or an on-disk quota.
pub const CAPACITY: usize = 4;

#[derive(Debug)]
struct Entry<K, V> {
    key: K,
    value: Result<Arc<V>, String>,
    invalidated: bool,
}

impl<K, V> Entry<K, V> {
    fn idle(&mut self) -> bool {
        match &mut self.value {
            // One atomic exclusivity decision: separate strong/weak count
            // reads could race an external Weak upgrade and then its drop.
            Ok(value) => Arc::get_mut(value).is_some(),
            Err(_) => true,
        }
    }
}

#[derive(Debug)]
struct Capture<K, V> {
    key: Option<K>,
    cancelled: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<Arc<V>, String>>>,
}

impl<K, V> Drop for Capture<K, V> {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// LRU of complete owners, with singleflight preparation and no detached work.
/// All methods are called under the live lane's short-held preparation mutex;
/// expensive source validation happens after the caller releases that mutex.
#[derive(Debug)]
pub struct Cache<K, V> {
    entries: VecDeque<Entry<K, V>>,
    pending: Option<Capture<K, V>>,
    capacity: usize,
}

impl<K, V> Drop for Cache<K, V> {
    fn drop(&mut self) {
        // Cancel/join the copy before releasing idle retained images.
        drop(self.pending.take());
    }
}

impl<K: Eq, V: Send + Sync + 'static> Cache<K, V> {
    /// Create a positive-capacity owner cache. Typed pools validate their
    /// externally configured capacity before constructing this primitive.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "toolchain retention requires positive capacity"
        );
        Self {
            entries: VecDeque::new(),
            pending: None,
            capacity,
        }
    }

    fn harvest(&mut self) {
        if !self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.handle.as_ref().is_some_and(JoinHandle::is_finished))
        {
            return;
        }
        let mut pending = self.pending.take().expect("finished capture owner");
        let handle = pending.handle.take().expect("finished capture handle");
        let value = handle
            .join()
            .unwrap_or_else(|_| Err("toolchain warmup panicked".to_owned()));
        // Capture's Drop still owns cancellation, but the completed thread is
        // already joined. Move its key without requiring K: Clone.
        let key = pending.key.take();
        self.entries.push_back(Entry {
            key: key.expect("capture key"),
            value,
            invalidated: false,
        });
    }

    /// Return the exact shared owner, pending preparation/capacity, or an error
    /// from THIS key's capture. Failure of another project's capture cannot
    /// turn a ready toolchain into a refusal. Merely polling never starts a
    /// second copy or evicts an image that an execution/upload still holds.
    pub fn poll(
        &mut self,
        key: K,
        prepare: impl FnOnce(&AtomicBool) -> Result<V, String> + Send + 'static,
    ) -> Result<Option<Arc<V>>, String> {
        self.harvest();
        // An invalidated predecessor may still be leased by an earlier build.
        // It retains its backing and slot, but is not a hit or a per-key lock.
        // Select only the latest usable generation (or its one-shot error).
        let matched = self
            .entries
            .iter()
            .rposition(|entry| entry.key == key && !entry.invalidated);
        if let Some(index) = matched {
            let entry = self.entries.remove(index).expect("matched entry");
            let value = entry.value.clone();
            if value.is_ok() {
                self.entries.push_back(entry);
            }
            return value.map(Some);
        }
        if self.pending.is_some() {
            return Ok(None);
        }
        // Reclaim an unleased invalidated generation before displacing a useful
        // image. Every retained predecessor and the pending capture count toward
        // the SAME global bound, even when they all have the same path key.
        let retired = self
            .entries
            .iter_mut()
            .position(|entry| entry.invalidated && entry.idle());
        let victim = retired.or_else(|| {
            (self.entries.len() >= self.capacity)
                .then(|| self.entries.iter_mut().position(Entry::idle))
                .flatten()
        });
        if self.entries.len() >= self.capacity && victim.is_none() {
            return Ok(None);
        }
        let retired = victim
            .and_then(|index| self.entries.remove(index))
            .and_then(|entry| entry.value.ok());
        let cancelled = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&cancelled);
        let handle = std::thread::Builder::new()
            .name("rabs-remote-toolchain".into())
            .spawn(move || {
                // Owned TempDir cleanup can be large too. Reclaim idle backing
                // on the same capture lane, before allocating its replacement.
                drop(retired);
                prepare(&stopped).map(Arc::new)
            })
            .map_err(|error| format!("start toolchain capture: {error}"))?;
        self.pending = Some(Capture {
            key: Some(key),
            cancelled,
            handle: Some(handle),
        });
        Ok(None)
    }

    /// Reject only the exact generation the caller actually checked. A late
    /// validator cannot invalidate a newer image under the same path key.
    pub fn invalidate(&mut self, key: &K, value: &Arc<V>) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| {
            &entry.key == key
                && entry
                    .value
                    .as_ref()
                    .is_ok_and(|current| Arc::ptr_eq(current, value))
        }) {
            entry.invalidated = true;
        }
    }
}

/// Optional verified private copy-on-write primitive. Returning false uses
/// the dataset capture's ordinary complete-copy fallback and byte verification.
pub type ToolchainCloner = fn(&File, &File, &Path) -> bool;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
// A disappearing waiter must not leave admitted preparation without a bound.
// This is the service's deadline, independent of each caller's shorter wait.
const WARMUP_TIMEOUT: Duration = Duration::from_secs(120);

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn require_plain(path: &Path) -> io::Result<()> {
    let plain = path.to_str().is_some_and(|text| {
        text.starts_with('/')
            && text.len() > 1
            && text.len() <= 4096
            && !text.contains(['\\', '\0'])
            && text
                .split('/')
                .skip(1)
                .all(|part| !matches!(part, "" | "." | ".."))
    });
    if plain {
        Ok(())
    } else {
        Err(invalid(
            "toolchain pool paths must be ordinary absolute paths",
        ))
    }
}

fn ordinary_ancestors(path: &Path) -> io::Result<()> {
    require_plain(path)?;
    for ancestor in path
        .ancestors()
        .take_while(|ancestor| ancestor.parent().is_some())
    {
        if !fs::symlink_metadata(ancestor)?.is_dir() {
            return Err(invalid(
                "toolchain pool path ancestry contains a non-directory or symlink",
            ));
        }
    }
    Ok(())
}

/// Directory generation, not its mtime: adding another owned image is normal.
#[derive(Debug)]
struct DirectoryOwner {
    path: PathBuf,
    directory: File,
}

impl DirectoryOwner {
    fn open(path: &Path) -> io::Result<Self> {
        ordinary_ancestors(path)?;
        let owner = Self {
            path: path.to_path_buf(),
            directory: File::open(path)?,
        };
        owner.verify()?;
        Ok(owner)
    }

    fn verify(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ordinary_ancestors(&self.path)?;
            let named = fs::symlink_metadata(&self.path)?;
            let held = self.directory.metadata()?;
            if named.is_dir()
                && named.uid() == rustix::process::geteuid().as_raw()
                && named.mode() & 0o077 == 0
                && (named.dev(), named.ino()) == (held.dev(), held.ino())
            {
                Ok(())
            } else {
                Err(invalid(
                    "toolchain pool directory ownership or generation changed",
                ))
            }
        }
        #[cfg(not(unix))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "toolchain pools require Unix directory ownership",
            ))
        }
    }
}

/// Opaque lease for one completely captured toolchain generation.
///
/// Keep this Arc through every planning, execution and upload using its image.
/// Borrowing the image cannot extract an independent owner that escapes the
/// pool's capacity accounting or outlives its private backing directory.
#[derive(Debug)]
pub struct RetainedToolchain {
    source: PathBuf,
    image: PreparedToolchain,
    owner: DirectoryOwner,
    parent: Arc<DirectoryOwner>,
    // Image descriptors and ownership witnesses close before TempDir cleanup.
    _directory: tempfile::TempDir,
}

impl RetainedToolchain {
    /// Exact original source spelling used by this generation's witness.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Independently retained, read-only toolchain tree.
    pub fn root(&self) -> &Path {
        self.image.root()
    }

    /// Borrow the content-identified image while retaining this lease.
    pub fn image(&self) -> &PreparedToolchain {
        &self.image
    }

    /// Private parent whose lifetime is owned by this lease.
    pub fn owner_path(&self) -> &Path {
        &self.owner.path
    }

    /// Check the exact original source and retained generations without
    /// rehashing their bytes. Never substitutes or refreshes either witness.
    pub fn verify(&self, source: &Path, cancelled: impl Fn() -> bool) -> io::Result<()> {
        if source.as_os_str() != self.source.as_os_str() {
            return Err(invalid(
                "retained toolchain lease names another original source",
            ));
        }
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "toolchain lease validation cancelled",
            ));
        }
        self.parent.verify()?;
        self.owner.verify()?;
        ordinary_ancestors(source)?;
        self.image.verify_source_unchanged(source, &cancelled)?;
        self.image.verify_retained_generation(&cancelled)?;
        self.parent.verify()?;
        self.owner.verify()?;
        Ok(())
    }
}

/// Bounded service-owned toolchain preparation shared by independent builds.
///
/// A cancelled waiter leaves the single owned warmup available to other
/// callers. Shutdown closes admission and cancels/joins that warmup. Validation
/// runs outside the cache mutex; an invalid result rejects only that observed
/// generation, and live predecessor leases remain charged until released.
#[derive(Debug)]
pub struct ToolchainPool {
    parent: Arc<DirectoryOwner>,
    cache: Mutex<Option<Cache<PathBuf, RetainedToolchain>>>,
    shutdown: Mutex<()>,
    closed: AtomicBool,
    cloner: ToolchainCloner,
}

impl ToolchainPool {
    /// Open a pool beneath an existing owned private directory. Capacity
    /// includes ready, leased, invalidated and currently preparing images.
    pub fn new(parent: &Path, capacity: usize, cloner: ToolchainCloner) -> io::Result<Self> {
        if !(1..=32).contains(&capacity) {
            return Err(invalid("toolchain pool capacity must be between 1 and 32"));
        }
        Ok(Self {
            parent: Arc::new(DirectoryOwner::open(parent)?),
            cache: Mutex::new(Some(Cache::new(capacity))),
            shutdown: Mutex::new(()),
            closed: AtomicBool::new(false),
            cloner,
        })
    }

    fn checkpoint(&self, deadline: Instant, cancelled: &impl Fn() -> bool) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) || cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "toolchain pool acquisition cancelled",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "toolchain pool acquisition timed out",
            ));
        }
        Ok(())
    }

    /// Acquire the current validated generation for one original source path.
    /// Timeout/cancellation abandons only this wait, not another caller's
    /// capture. An invalid source/copy is never returned as a cache hit.
    pub fn acquire(
        &self,
        source: &Path,
        timeout: Duration,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<Arc<RetainedToolchain>> {
        require_plain(source)?;
        if source.starts_with(&self.parent.path) || self.parent.path.starts_with(source) {
            return Err(invalid(
                "toolchain pool and original source must not overlap",
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid("toolchain acquisition deadline overflow"))?;
        loop {
            self.checkpoint(deadline, &cancelled)?;
            self.parent.verify()?;
            ordinary_ancestors(source)?;
            let parent = Arc::clone(&self.parent);
            let original = source.to_path_buf();
            let cloner = self.cloner;
            let prepared = {
                let mut slot = self
                    .cache
                    .lock()
                    .map_err(|_| io::Error::other("toolchain pool lock poisoned"))?;
                let cache = slot.as_mut().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Interrupted, "toolchain pool is shut down")
                })?;
                cache
                    .poll(source.to_path_buf(), move |stopped| {
                        let deadline = Instant::now() + WARMUP_TIMEOUT;
                        let cancelled =
                            || stopped.load(Ordering::Acquire) || Instant::now() >= deadline;
                        if cancelled() {
                            return Err("toolchain preparation cancelled".into());
                        }
                        parent.verify().map_err(|error| error.to_string())?;
                        let mut builder = tempfile::Builder::new();
                        builder.prefix("retained-toolchain-");
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            builder.permissions(fs::Permissions::from_mode(0o700));
                        }
                        let directory = builder
                            .tempdir_in(&parent.path)
                            .map_err(|error| error.to_string())?;
                        let owner = DirectoryOwner::open(directory.path())
                            .map_err(|error| error.to_string())?;
                        let image = capture_toolchain_with_cloner(
                            &original,
                            &directory.path().join("tree"),
                            None,
                            &ToolchainLimits::default(),
                            cancelled,
                            cloner,
                        )
                        .map_err(|error| error.to_string())?;
                        let lease = RetainedToolchain {
                            source: original,
                            image,
                            owner,
                            parent,
                            _directory: directory,
                        };
                        lease
                            .verify(lease.source(), cancelled)
                            .map_err(|error| error.to_string())?;
                        Ok(lease)
                    })
                    .map_err(io::Error::other)?
            };
            if let Some(prepared) = prepared {
                let stopped = || {
                    cancelled() || self.closed.load(Ordering::Acquire) || Instant::now() >= deadline
                };
                match prepared.verify(source, stopped) {
                    Ok(()) => {
                        self.checkpoint(deadline, &cancelled)?;
                        return Ok(prepared);
                    }
                    Err(error) => {
                        // Cancellation is not evidence that this image changed.
                        self.checkpoint(deadline, &cancelled)?;
                        let mut slot = self
                            .cache
                            .lock()
                            .map_err(|_| io::Error::other("toolchain pool lock poisoned"))?;
                        if let Some(cache) = slot.as_mut() {
                            cache.invalidate(&source.to_path_buf(), &prepared);
                        } else {
                            return Err(error);
                        }
                    }
                }
            }
            std::thread::sleep(
                POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    /// Close admission and cancel/join shared preparation before returning.
    /// Previously returned leases continue owning their exact backing trees.
    pub fn shutdown(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::Release);
        // Every concurrent shutdown waits for the outstanding join, even after
        // the first caller has taken the cache out of its admission mutex.
        let _shutdown = self
            .shutdown
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (cache, poisoned) = match self.cache.lock() {
            Ok(mut cache) => (cache.take(), false),
            Err(poisoned) => (poisoned.into_inner().take(), true),
        };
        // Joining and filesystem cleanup never hold the cache mutex.
        drop(cache);
        if poisoned {
            Err(io::Error::other(
                "toolchain pool lock poisoned during shutdown",
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for ToolchainPool {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod pool_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Barrier, mpsc};

    // Actual retained filesystem owners, with tiny toolchain-shaped trees.
    // These are ownership/capture regressions, not compiler or sandbox proof.
    fn private() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn write(root: &Path, path: &str, contents: &[u8], mode: u32) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn fixture(root: &Path) {
        write(root, "bin/rustc", b"compiler A", 0o755);
        write(root, "lib/runtime", b"runtime A", 0o644);
        write(root, "lib/other", b"runtime B", 0o644);
        fs::create_dir(root.join("empty")).unwrap();
        symlink("../lib/runtime", root.join("bin/runtime")).unwrap();
    }

    fn ordinary_copy(_: &File, _: &File, _: &Path) -> bool {
        false
    }

    fn acquire(pool: &ToolchainPool, source: &Path) -> Arc<RetainedToolchain> {
        pool.acquire(source, Duration::from_secs(5), || false)
            .unwrap()
    }

    #[test]
    fn exact_source_hits_share_one_private_owner_but_distinct_roots_do_not() {
        let sources = private();
        let first_source = sources.path().join("first");
        let second_source = sources.path().join("second");
        fixture(&first_source);
        fixture(&second_source);
        let parent = private();
        let pool = ToolchainPool::new(parent.path(), 2, ordinary_copy).unwrap();
        let first = acquire(&pool, &first_source);
        let second = acquire(&pool, &second_source);
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(first.image().identity(), second.image().identity());
        assert_eq!(first.source(), first_source);
        assert!(first.root().starts_with(first.owner_path()));
        assert_ne!(first.owner_path(), second.owner_path());
        for _ in 0..8 {
            assert!(Arc::ptr_eq(&first, &acquire(&pool, &first_source)));
            assert!(Arc::ptr_eq(&second, &acquire(&pool, &second_source)));
        }
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 2);
        assert!(first.verify(&second_source, || false).is_err());
        assert!(first.verify(&first_source.join("."), || false).is_err());
        first.image().verify(|| false).unwrap();
    }

    fn rewrite_compiler(root: &Path) {
        fs::set_permissions(root.join("bin/rustc"), fs::Permissions::from_mode(0o755)).unwrap();
        write(root, "bin/rustc", b"compiler B", 0o755);
    }

    fn replace_compiler(root: &Path) {
        write(root, "replacement", b"compiler A", 0o755);
        fs::rename(root.join("replacement"), root.join("bin/rustc")).unwrap();
    }

    fn add_member(root: &Path) {
        write(root, "lib/new-runtime", b"new member", 0o644);
    }

    fn change_mode(root: &Path) {
        fs::set_permissions(root.join("lib/runtime"), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn retarget_alias(root: &Path) {
        fs::remove_file(root.join("bin/runtime")).unwrap();
        symlink("../lib/other", root.join("bin/runtime")).unwrap();
    }

    fn replace_root(root: &Path) {
        fs::rename(root, root.with_extension("retired")).unwrap();
        fixture(root);
    }

    #[test]
    fn source_mutations_replace_only_the_checked_generation_and_preserve_readers() {
        type Mutation = (&'static str, fn(&Path), bool);
        let mutations: [Mutation; 6] = [
            ("bytes", rewrite_compiler, true),
            ("inode", replace_compiler, false),
            ("membership", add_member, true),
            ("mode", change_mode, false),
            ("alias", retarget_alias, true),
            ("root", replace_root, false),
        ];
        for (name, mutate, content_changed) in mutations {
            let sources = private();
            let source = sources.path().join(name);
            fixture(&source);
            let parent = private();
            let pool = ToolchainPool::new(parent.path(), 2, ordinary_copy).unwrap();
            let old = acquire(&pool, &source);
            let old_path = old.owner_path().to_path_buf();
            mutate(&source);
            assert!(old.verify(&source, || false).is_err(), "{name}");
            old.image().verify_retained_generation(|| false).unwrap();
            let current = acquire(&pool, &source);
            assert!(!Arc::ptr_eq(&old, &current), "{name}");
            assert_eq!(
                old.image().identity() != current.image().identity(),
                content_changed,
                "{name}"
            );
            assert_eq!(
                fs::read(old.root().join("bin/rustc")).unwrap(),
                b"compiler A"
            );
            assert!(old_path.is_dir());
            // A late failed validator cannot retire the newer capture.
            pool.cache
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .invalidate(&source, &old);
            assert!(Arc::ptr_eq(&current, &acquire(&pool, &source)), "{name}");
            pool.shutdown().unwrap();
            assert!(old_path.is_dir());
            drop(old);
            assert!(!old_path.exists());
            current
                .image()
                .verify_retained_generation(|| false)
                .unwrap();
        }
    }

    #[test]
    fn retained_mutation_is_never_a_hit_and_recaptures_the_unchanged_original() {
        for mutate in [rewrite_compiler, add_member, change_mode, retarget_alias] {
            let sources = private();
            let source = sources.path().join("toolchain");
            fixture(&source);
            let parent = private();
            let pool = ToolchainPool::new(parent.path(), 2, ordinary_copy).unwrap();
            let old = acquire(&pool, &source);
            // The private tree is read-only to compilation; its owner can still
            // chmod it. A changed owner must be refused, never re-blessed.
            mutate(old.root());
            old.image()
                .verify_source_unchanged(&source, || false)
                .unwrap();
            assert!(old.image().verify_retained_generation(|| false).is_err());
            let current = acquire(&pool, &source);
            assert!(!Arc::ptr_eq(&old, &current));
            assert_eq!(old.image().identity(), current.image().identity());
            current.verify(&source, || false).unwrap();
            current.image().verify(|| false).unwrap();
        }
    }

    #[test]
    fn leased_and_weak_retired_owners_remain_charged_until_replacement_can_reclaim_them() {
        let sources = private();
        let source = sources.path().join("toolchain");
        fixture(&source);
        let parent = private();
        let pool = ToolchainPool::new(parent.path(), 1, ordinary_copy).unwrap();
        let old = acquire(&pool, &source);
        let weak = Arc::downgrade(&old);
        let old_path = old.owner_path().to_path_buf();
        rewrite_compiler(&source);
        assert_eq!(
            pool.acquire(&source, Duration::from_millis(40), || false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        drop(old);
        assert_eq!(
            pool.acquire(&source, Duration::from_millis(40), || false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        weak.upgrade()
            .unwrap()
            .image()
            .verify_retained_generation(|| false)
            .unwrap();
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
        drop(weak);
        let current = acquire(&pool, &source);
        assert!(!old_path.exists());
        assert_eq!(
            fs::read(current.root().join("bin/rustc")).unwrap(),
            b"compiler B"
        );
        let current_path = current.owner_path().to_path_buf();
        pool.shutdown().unwrap();
        assert!(current_path.is_dir());
        assert_eq!(
            pool.acquire(&source, Duration::from_secs(1), || false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        current
            .image()
            .verify_retained_generation(|| false)
            .unwrap();
        drop(current);
        assert!(!current_path.exists());
    }

    #[test]
    fn cancelled_validation_does_not_invalidate_a_ready_owner() {
        let sources = private();
        let source = sources.path().join("toolchain");
        fixture(&source);
        let parent = private();
        let pool = ToolchainPool::new(parent.path(), 1, ordinary_copy).unwrap();
        let retained = acquire(&pool, &source);
        let checks = AtomicUsize::new(0);
        let error = pool
            .acquire(&source, Duration::from_secs(5), || {
                checks.fetch_add(1, Ordering::Relaxed) >= 2
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(Arc::ptr_eq(&retained, &acquire(&pool, &source)));
    }

    #[test]
    fn parent_generation_and_source_aliases_cannot_redirect_pool_ownership() {
        let outer = private();
        let source = outer.path().join("toolchain");
        fixture(&source);
        let parent = outer.path().join("pool");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(ToolchainPool::new(&parent, 0, ordinary_copy).is_err());
        assert!(ToolchainPool::new(&parent, 33, ordinary_copy).is_err());
        let pool = ToolchainPool::new(&parent, 1, ordinary_copy).unwrap();
        let alias = outer.path().join("alias");
        symlink(&source, &alias).unwrap();
        assert!(
            pool.acquire(&alias, Duration::from_secs(1), || false)
                .is_err()
        );
        assert!(
            pool.acquire(&source.join("."), Duration::from_secs(1), || false)
                .is_err()
        );
        assert!(
            pool.acquire(outer.path(), Duration::from_secs(1), || false)
                .is_err()
        );
        let retained = acquire(&pool, &source);
        fs::rename(&parent, outer.path().join("retired-pool")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            pool.acquire(&source, Duration::from_secs(1), || false)
                .is_err()
        );
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        assert!(retained.verify(&source, || false).is_err());
    }

    struct CaptureGate {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    static CAPTURE_GATE: Mutex<Option<CaptureGate>> = Mutex::new(None);
    static CLONE_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn gated_copy(_: &File, _: &File, _: &Path) -> bool {
        CLONE_CALLS.fetch_add(1, Ordering::Relaxed);
        let gate = CAPTURE_GATE
            .lock()
            .unwrap()
            .take()
            .expect("one admitted copy");
        gate.started.send(()).unwrap();
        gate.release
            .recv_timeout(Duration::from_secs(5))
            .expect("release blocked copy");
        false
    }

    fn capture_gate() -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (started, observe) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        assert!(
            CAPTURE_GATE
                .lock()
                .unwrap()
                .replace(CaptureGate {
                    started,
                    release: wait
                })
                .is_none()
        );
        (observe, release)
    }

    #[test]
    fn cancelled_waiter_preserves_shared_capture_and_every_shutdown_joins_it() {
        let sources = private();
        let ready_source = sources.path().join("ready");
        let first_source = sources.path().join("first");
        let next_source = sources.path().join("next");
        for source in [&ready_source, &first_source, &next_source] {
            fixture(source);
        }
        // Only these two files cross the dataset cloner threshold. Returning
        // false exercises actual complete-copy fallback and byte verification.
        write(&first_source, "bin/rustc", &vec![1; 128 * 1024], 0o755);
        write(&next_source, "bin/rustc", &vec![2; 128 * 1024], 0o755);
        let parent = private();
        let pool = Arc::new(ToolchainPool::new(parent.path(), 3, gated_copy).unwrap());
        let ready = acquire(&pool, &ready_source);
        let (started, release) = capture_gate();
        let stopped = Arc::new(AtomicBool::new(false));
        let first = {
            let pool = Arc::clone(&pool);
            let stopped = Arc::clone(&stopped);
            let source = first_source.clone();
            std::thread::spawn(move || {
                pool.acquire(&source, Duration::from_secs(5), || {
                    stopped.load(Ordering::Acquire)
                })
            })
        };
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(Arc::ptr_eq(&ready, &acquire(&pool, &ready_source)));
        stopped.store(true, Ordering::Release);
        assert_eq!(
            first.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        let second = {
            let pool = Arc::clone(&pool);
            let source = first_source.clone();
            std::thread::spawn(move || acquire(&pool, &source))
        };
        release.send(()).unwrap();
        let retained = second.join().unwrap();
        assert!(Arc::ptr_eq(&retained, &acquire(&pool, &first_source)));
        assert_eq!(CLONE_CALLS.load(Ordering::Relaxed), 1);

        let (started, release) = capture_gate();
        let pending = {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || pool.acquire(&next_source, Duration::from_secs(5), || false))
        };
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let (finished, observe) = mpsc::channel();
        let mut shutdowns = Vec::new();
        for _ in 0..2 {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            let finished = finished.clone();
            shutdowns.push(std::thread::spawn(move || {
                barrier.wait();
                finished.send(pool.shutdown()).unwrap();
            }));
        }
        barrier.wait();
        assert_eq!(
            pending.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(
            matches!(
                observe.recv_timeout(Duration::from_millis(40)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "shutdown returned before the owned copy joined"
        );
        release.send(()).unwrap();
        for _ in 0..2 {
            observe
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
        }
        for shutdown in shutdowns {
            shutdown.join().unwrap();
        }
        assert_eq!(CLONE_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(
            fs::read_dir(parent.path()).unwrap().count(),
            2,
            "cancelled backing leaked after shutdown"
        );
        retained
            .image()
            .verify_retained_generation(|| false)
            .unwrap();
        ready.image().verify_retained_generation(|| false).unwrap();
        drop(retained);
        drop(ready);
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Barrier, Mutex, mpsc};
    use std::time::{Duration, Instant};

    // These exercise the actual ownership/thread cache, with small values in
    // place of compiler images. They do not assert a compiler or TLS execution.
    fn finish<K: Eq + Clone, V: Send + Sync + 'static>(cache: &mut Cache<K, V>, key: K) -> Arc<V> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(value) = cache
                .poll(key.clone(), |_| Err("unexpected extra preparation".into()))
                .unwrap_or_else(|error| panic!("preparation failed: {error}"))
            {
                return value;
            }
            assert!(Instant::now() < deadline, "preparation did not finish");
            std::thread::yield_now();
        }
    }

    fn ready(
        cache: &mut Cache<&'static str, usize>,
        key: &'static str,
        value: usize,
    ) -> Arc<usize> {
        assert!(cache.poll(key, move |_| Ok(value)).unwrap().is_none());
        finish(cache, key)
    }

    #[test]
    fn alternating_toolchains_reuse_both_exact_owners() {
        let mut cache = Cache::new(CAPACITY);
        let first = ready(&mut cache, "stable", 17);
        let second = ready(&mut cache, "nightly", 29);
        for _ in 0..128 {
            assert!(Arc::ptr_eq(&first, &finish(&mut cache, "stable")));
            assert!(Arc::ptr_eq(&second, &finish(&mut cache, "nightly")));
        }
        assert_eq!(cache.entries.len(), 2);
        assert!(cache.pending.is_none());
    }

    #[test]
    fn a_different_warmup_does_not_block_a_ready_toolchain() {
        let mut cache = Cache::new(3);
        let existing = ready(&mut cache, "a", 1);
        let (release, wait) = mpsc::channel();
        assert!(
            cache
                .poll("b", move |_| {
                    wait.recv_timeout(Duration::from_secs(5))
                        .map_err(|e| e.to_string())?;
                    Ok(2)
                })
                .unwrap()
                .is_none()
        );
        assert!(Arc::ptr_eq(&existing, &finish(&mut cache, "a")));
        // One capture globally, even for independent misses.
        assert!(
            cache
                .poll("c", |_| panic!("second capture started"))
                .unwrap()
                .is_none()
        );
        assert!(
            cache
                .poll("b", |_| panic!("duplicate capture started"))
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.entries.len(), 1);
        release.send(()).unwrap();
        assert_eq!(*finish(&mut cache, "b"), 2);
    }

    #[test]
    fn active_images_and_weak_owners_cannot_be_evicted() {
        let mut cache = Cache::new(2);
        let first = ready(&mut cache, "a", 1);
        let second = ready(&mut cache, "b", 2);
        let weak = Arc::downgrade(&first);
        assert!(
            cache
                .poll("c", |_| panic!("capacity exceeded"))
                .unwrap()
                .is_none()
        );
        drop(first);
        assert!(
            cache
                .poll("c", |_| panic!("late upgrade could escape the bound"))
                .unwrap()
                .is_none()
        );
        assert_eq!(*weak.upgrade().unwrap(), 1);
        drop(weak);
        assert!(cache.poll("c", |_| Ok(3)).unwrap().is_none());
        assert_eq!(*finish(&mut cache, "c"), 3);
        assert_eq!(*second, 2);
        assert_eq!(cache.entries.len(), 2);
        assert!(!cache.entries.iter().any(|entry| entry.key == "a"));
    }

    #[test]
    fn least_recently_used_idle_image_is_the_only_victim() {
        let mut cache = Cache::new(2);
        drop(ready(&mut cache, "a", 1));
        drop(ready(&mut cache, "b", 2));
        drop(finish(&mut cache, "a"));
        drop(ready(&mut cache, "c", 3));
        assert!(cache.entries.iter().any(|entry| entry.key == "a"));
        assert!(cache.entries.iter().any(|entry| entry.key == "c"));
        assert!(!cache.entries.iter().any(|entry| entry.key == "b"));
    }

    #[test]
    fn invalidated_generation_stays_counted_until_its_users_leave() {
        // Saturate retention: a replacement must not disown the old image.
        // Spare-capacity replacement is covered separately below.
        let mut cache = Cache::new(1);
        let first = ready(&mut cache, "a", 1);
        let lease = Arc::clone(&first);
        cache.invalidate(&"a", &first);
        assert!(
            cache
                .poll("a", |_| panic!("old generation is still leased"))
                .unwrap()
                .is_none()
        );
        drop(first);
        assert!(
            cache
                .poll("a", |_| panic!("one lease remains"))
                .unwrap()
                .is_none()
        );
        assert_eq!(*lease, 1);
        drop(lease);
        let replaced = ready(&mut cache, "a", 2);
        assert_eq!(*replaced, 2);
        assert_eq!(cache.entries.len(), 1);
        assert!(!cache.entries[0].invalidated);
    }

    #[test]
    fn failed_validation_cannot_invalidate_an_unrelated_owner_or_key() {
        let mut cache = Cache::new(2);
        let current = ready(&mut cache, "a", 1);
        cache.invalidate(&"a", &Arc::new(1));
        cache.invalidate(&"different-compiler", &current);
        assert!(Arc::ptr_eq(&current, &finish(&mut cache, "a")));
        assert!(!cache.entries[0].invalidated);
    }

    #[test]
    fn original_compiler_and_sysroot_spellings_are_distinct_preparations() {
        let mut cache = Cache::new(3);
        let a = ("/stable/bin/rustc", "/stable");
        let b = ("/nightly/bin/rustc", "/nightly");
        let c = ("/alias/bin/rustc", "/stable");
        for (key, value) in [(a, 1), (b, 2), (c, 3)] {
            assert!(cache.poll(key, move |_| Ok(value)).unwrap().is_none());
            assert_eq!(*finish(&mut cache, key), value);
        }
        for (key, value) in [(a, 1), (b, 2), (c, 3)] {
            assert_eq!(*finish(&mut cache, key), value);
        }
    }

    #[test]
    fn failed_capture_is_reported_only_to_its_own_key_and_can_retry() {
        let mut cache = Cache::new(2);
        let good = ready(&mut cache, "good", 1);
        assert!(
            cache
                .poll("bad", |_| Err("capture rejected changed bytes".into()))
                .unwrap()
                .is_none()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.pending.is_some() {
            assert!(Arc::ptr_eq(&good, &finish(&mut cache, "good")));
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(
            cache
                .poll("bad", |_| panic!("error has not been consumed"))
                .unwrap_err(),
            "capture rejected changed bytes",
        );
        assert_eq!(*ready(&mut cache, "bad", 2), 2);
        assert!(Arc::ptr_eq(&good, &finish(&mut cache, "good")));
    }

    #[test]
    fn concurrent_same_key_requests_start_one_capture() {
        let cache = Arc::new(Mutex::new(Cache::new(2)));
        let calls = Arc::new(AtomicUsize::new(0));
        let all_polled = Arc::new(Barrier::new(16));
        let release = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let cache = Arc::clone(&cache);
                let calls = Arc::clone(&calls);
                let all_polled = Arc::clone(&all_polled);
                let release = Arc::clone(&release);
                scope.spawn(move || {
                    assert!(
                        cache
                            .lock()
                            .unwrap()
                            .poll("same", move |stopped| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                while !release.load(Ordering::Acquire) {
                                    if stopped.load(Ordering::Acquire) {
                                        return Err("cancelled".into());
                                    }
                                    std::thread::yield_now();
                                }
                                Ok(42)
                            })
                            .unwrap()
                            .is_none()
                    );
                    all_polled.wait();
                });
            }
        });
        release.store(true, Ordering::Release);
        assert_eq!(*finish(&mut cache.lock().unwrap(), "same"), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_drop_cancels_and_joins_the_owned_capture() {
        let completed = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&completed);
        let mut cache = Cache::<&str, usize>::new(1);
        assert!(
            cache
                .poll("pending", move |cancelled| {
                    while !cancelled.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    stopped.store(true, Ordering::Release);
                    Err("cancelled".into())
                })
                .unwrap()
                .is_none()
        );
        drop(cache);
        assert!(completed.load(Ordering::Acquire));
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn panicked_capture_is_joined_and_does_not_strand_capacity() {
        let mut cache = Cache::<&str, usize>::new(1);
        assert!(
            cache
                .poll("panic", |_| panic!("capture fixture panic"))
                .unwrap()
                .is_none()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let result = cache.poll("panic", |_| panic!("unexpected second capture"));
            if let Err(error) = result {
                assert_eq!(error, "toolchain warmup panicked");
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(*ready(&mut cache, "healthy", 7), 7);
    }

    #[test]
    fn eviction_reclaims_idle_backing_on_the_capture_thread_before_replacement() {
        #[derive(Debug)]
        struct Owner {
            dropped: mpsc::Sender<std::thread::ThreadId>,
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                let _ = self.dropped.send(std::thread::current().id());
            }
        }
        let mut cache = Cache::new(1);
        let (dropped, observe) = mpsc::channel();
        let original = dropped.clone();
        assert!(
            cache
                .poll("old", move |_| Ok(Owner { dropped: original }))
                .unwrap()
                .is_none()
        );
        drop(finish(&mut cache, "old"));
        let caller = std::thread::current().id();
        assert!(
            cache
                .poll("new", move |_| {
                    let evictor = observe
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|e| e.to_string())?;
                    assert_ne!(evictor, caller);
                    assert_eq!(evictor, std::thread::current().id());
                    Ok(Owner { dropped })
                })
                .unwrap()
                .is_none()
        );
        drop(finish(&mut cache, "new"));
    }

    #[test]
    fn invalidated_lease_does_not_block_replacement_with_spare_capacity() {
        let mut cache = Cache::new(2);
        let original = ready(&mut cache, "compiler", 1);
        cache.invalidate(&"compiler", &original);
        let replacement = ready(&mut cache, "compiler", 2);
        assert!(!Arc::ptr_eq(&original, &replacement));
        assert_eq!(*original, 1, "a prior request retains its exact image");
        assert_eq!(*replacement, 2);
        assert_eq!(cache.entries.len(), 2, "both generations remain charged");
        assert!(cache.entries.iter().any(|entry| {
            entry.invalidated
                && entry
                    .value
                    .as_ref()
                    .is_ok_and(|value| Arc::ptr_eq(value, &original))
        }));
        // A late validator names a generation, not whichever image now occupies
        // the same compiler path. It cannot invalidate or shadow the new owner.
        cache.invalidate(&"compiler", &original);
        for _ in 0..16 {
            assert!(Arc::ptr_eq(&replacement, &finish(&mut cache, "compiler")));
        }
        assert_eq!(*original, 1);
    }

    #[test]
    fn repeated_replacements_and_weak_readers_stay_within_the_global_bound() {
        let mut cache = Cache::new(CAPACITY);
        let mut readers = VecDeque::new();
        for generation in 0..CAPACITY {
            let owner = ready(&mut cache, "compiler", generation);
            cache.invalidate(&"compiler", &owner);
            readers.push_back(owner);
            assert_eq!(cache.entries.len(), generation + 1);
            assert!(cache.pending.is_none());
        }
        for _ in 0..16 {
            assert!(
                cache
                    .poll("compiler", |_| panic!("all generations are leased"))
                    .unwrap()
                    .is_none()
            );
            assert!(
                cache
                    .poll("another", |_| panic!("same bound applies across keys"))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(cache.entries.len(), CAPACITY);
            assert!(cache.pending.is_none());
        }
        let oldest = readers.pop_front().unwrap();
        let weak = Arc::downgrade(&oldest);
        drop(oldest);
        assert!(
            cache
                .poll("compiler", |_| panic!("weak owner can still upgrade"))
                .unwrap()
                .is_none()
        );
        assert_eq!(*weak.upgrade().unwrap(), 0);
        drop(weak);
        assert!(cache.poll("compiler", |_| Ok(CAPACITY)).unwrap().is_none());
        assert_eq!(
            cache.entries.len() + usize::from(cache.pending.is_some()),
            CAPACITY
        );
        let latest = finish(&mut cache, "compiler");
        assert_eq!(*latest, CAPACITY);
        for (index, reader) in readers.iter().enumerate() {
            assert_eq!(**reader, index + 1);
        }
        assert_eq!(cache.entries.len(), CAPACITY);
        assert!(Arc::ptr_eq(&latest, &finish(&mut cache, "compiler")));
    }

    #[test]
    fn an_idle_retired_generation_is_evicted_before_an_unrelated_warm_image() {
        let mut cache = Cache::new(3);
        drop(ready(&mut cache, "warm-oldest", 10));
        let retired = ready(&mut cache, "retired", 20);
        cache.invalidate(&"retired", &retired);
        drop(ready(&mut cache, "warm-newest", 30));
        drop(retired);
        assert_eq!(*ready(&mut cache, "new", 40), 40);
        assert_eq!(cache.entries.len(), 3);
        assert!(!cache.entries.iter().any(|entry| entry.key == "retired"));
        assert_eq!(*finish(&mut cache, "warm-oldest"), 10);
        assert_eq!(*finish(&mut cache, "warm-newest"), 30);
    }

    #[test]
    fn a_failed_replacement_reports_its_error_without_reviving_the_old_image() {
        let mut cache = Cache::new(3);
        let old = ready(&mut cache, "compiler", 1);
        let independent = ready(&mut cache, "independent", 9);
        cache.invalidate(&"compiler", &old);
        assert!(
            cache
                .poll("compiler", |_| Err("new source capture refused".into()))
                .unwrap()
                .is_none()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.pending.is_some() {
            assert!(Arc::ptr_eq(
                &independent,
                &finish(&mut cache, "independent")
            ));
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(cache.entries.len(), 3);
        assert_eq!(
            cache
                .poll("compiler", |_| panic!(
                    "error must be returned before retry"
                ))
                .unwrap_err(),
            "new source capture refused",
        );
        assert_eq!(*old, 1);
        assert_eq!(cache.entries.len(), 2);
        let replacement = ready(&mut cache, "compiler", 2);
        assert_eq!(*replacement, 2);
        assert_eq!(cache.entries.len(), 3);
        cache.invalidate(&"compiler", &old);
        assert!(Arc::ptr_eq(&replacement, &finish(&mut cache, "compiler")));
    }

    #[test]
    fn replacement_capture_remains_singleflight_with_live_predecessor_readers() {
        let mut cache = Cache::new(3);
        let old = ready(&mut cache, "compiler", 1);
        let independent = ready(&mut cache, "independent", 9);
        cache.invalidate(&"compiler", &old);
        let (entered, started) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        assert!(
            cache
                .poll("compiler", move |_| {
                    count.fetch_add(1, Ordering::SeqCst);
                    entered.send(()).map_err(|error| error.to_string())?;
                    wait.recv_timeout(Duration::from_secs(5))
                        .map_err(|error| error.to_string())?;
                    Ok(2)
                })
                .unwrap()
                .is_none()
        );
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..128 {
            assert!(
                cache
                    .poll("compiler", |_| panic!("duplicate replacement"))
                    .unwrap()
                    .is_none()
            );
            assert!(
                cache
                    .poll("another", |_| panic!("second capture lane"))
                    .unwrap()
                    .is_none()
            );
            assert!(Arc::ptr_eq(
                &independent,
                &finish(&mut cache, "independent")
            ));
            assert_eq!(
                cache.entries.len() + usize::from(cache.pending.is_some()),
                3
            );
            assert_eq!(*old, 1);
        }
        release.send(()).unwrap();
        assert_eq!(*finish(&mut cache, "compiler"), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(*old, 1);
    }

    #[test]
    fn cache_shutdown_joins_replacement_but_does_not_disown_external_readers() {
        let completed = Arc::new(AtomicBool::new(false));
        let joined = Arc::clone(&completed);
        let mut cache = Cache::new(2);
        let old = ready(&mut cache, "compiler", 1);
        cache.invalidate(&"compiler", &old);
        assert!(
            cache
                .poll("compiler", move |cancelled| {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !cancelled.load(Ordering::Acquire) {
                        assert!(Instant::now() < deadline, "replacement was not cancelled");
                        std::thread::yield_now();
                    }
                    joined.store(true, Ordering::Release);
                    Err("replacement cancelled".into())
                })
                .unwrap()
                .is_none()
        );
        drop(cache);
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(
            *old, 1,
            "the old request still owns its image after shutdown"
        );
    }

    #[test]
    fn retired_backing_is_reclaimed_on_the_capture_lane_after_its_last_reader() {
        #[derive(Debug)]
        struct Image {
            generation: usize,
            dropped: mpsc::Sender<(usize, std::thread::ThreadId)>,
        }
        impl Drop for Image {
            fn drop(&mut self) {
                let _ = self
                    .dropped
                    .send((self.generation, std::thread::current().id()));
            }
        }
        let mut cache = Cache::new(2);
        let (dropped, observe) = mpsc::channel();
        let first = dropped.clone();
        assert!(
            cache
                .poll("compiler", move |_| Ok(Image {
                    generation: 1,
                    dropped: first
                }))
                .unwrap()
                .is_none()
        );
        let old = finish(&mut cache, "compiler");
        cache.invalidate(&"compiler", &old);
        let second = dropped.clone();
        assert!(
            cache
                .poll("compiler", move |_| Ok(Image {
                    generation: 2,
                    dropped: second
                }))
                .unwrap()
                .is_none()
        );
        let current = finish(&mut cache, "compiler");
        assert_eq!(current.generation, 2);
        assert!(matches!(observe.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(old);
        assert!(
            matches!(observe.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "the cache still owns and charges retired backing"
        );
        let caller = std::thread::current().id();
        assert!(
            cache
                .poll("another", move |_| {
                    let (generation, thread) = observe
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|error| error.to_string())?;
                    assert_eq!(generation, 1);
                    assert_ne!(thread, caller);
                    assert_eq!(thread, std::thread::current().id());
                    Ok(Image {
                        generation: 3,
                        dropped,
                    })
                })
                .unwrap()
                .is_none()
        );
        assert_eq!(finish(&mut cache, "another").generation, 3);
        assert!(Arc::ptr_eq(&current, &finish(&mut cache, "compiler")));
        assert_eq!(cache.entries.len(), 2);
    }
}
