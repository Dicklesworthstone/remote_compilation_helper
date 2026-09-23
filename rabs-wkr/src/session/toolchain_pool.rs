//! Bounded process-local reuse of pinned, independently captured toolchains.
//!
//! Only a complete ToolchainIdentity selects reuse. A pathname, compiler version,
//! timestamp or cache hit never substitutes for content verification. Unpinned
//! requests keep their private capture. Pooled bytes are rehashed on acquisition
//! and by the executor before/after execution, and every lease retains the real
//! private directory owner through process cleanup. No persistent cache format,
//! action publication, network operation or compiler-result reuse is introduced.
//!
//! The pool serializes admission, not filesystem work. Same-identity misses join
//! one capture; different identities can capture concurrently. Reservations count
//! against both bounds. Eviction touches only idle datasets; a busy/full pool
//! uses a private capture rather than waiting for an unrelated compiler to exit.

use rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec;
use rabs_sandbox::toolchain_dataset::{
    PreparedToolchain, ToolchainIdentity, ToolchainLimits, capture_toolchain,
};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;

const MAX_POOL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_POOL_ENTRIES: usize = 8;
const WAIT_SLICE: Duration = Duration::from_millis(20);
const CONFIG_NAME: &str = "RABS_WORKER_TOOLCHAIN_CACHE_BYTES";

// Only the worker supervisor holds the strong pool owner. A static strong owner
// would skip TempDir cleanup at ordinary process exit and leak whole toolchains.
static ACTIVE_POOL: Mutex<Weak<ToolchainPool>> = Mutex::new(Weak::new());

type Key = ([u8; 32], u64, u64);

fn key(identity: &ToolchainIdentity) -> Key {
    (identity.sha256, identity.files, identity.bytes)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(io::ErrorKind::Interrupted, "toolchain acquisition interrupted"))
    } else {
        Ok(())
    }
}
fn private_directory(parent: Option<&Path>) -> io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("rabs-toolchain-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    match parent {
        Some(parent) => builder.tempdir_in(parent),
        None => builder.tempdir(),
    }
}

/// The parent must outlive every dataset, even after a test/embedded pool drops.
struct PoolDirectory(tempfile::TempDir);
struct Dataset {
    // Field order closes inventory descriptors before removing the private tree,
    // and removes the child before dropping its last parent-directory reference.
    toolchain: PreparedToolchain,
    _directory: tempfile::TempDir,
    pool: Arc<PoolDirectory>,
}
impl Dataset {
    fn capture(
        pool: &Arc<PoolDirectory>, source: &Path, expected: Option<&ToolchainIdentity>,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Arc<Self>> {
        checkpoint(stopped)?;
        let directory = private_directory(Some(pool.0.path()))?;
        let mut limits = ToolchainLimits::default();
        if let Some(expected) = expected {
            // A peer's understated byte count must not reserve a tiny slot and
            // then fill it with a much larger, ultimately mismatching dataset.
            // Inventory enforces this bound before copying any source bytes.
            limits.max_bytes = limits.max_bytes.min(expected.bytes);
        }
        let toolchain = capture_toolchain(
            source, &directory.path().join("dataset"), expected,
            &limits, stopped,
        )?;
        checkpoint(stopped)?;
        Ok(Arc::new(Self { toolchain, _directory:directory, pool:Arc::clone(pool) }))
    }
}

/// Scope-owned execution input; nothing can evict its backing while it is used.
pub(super) struct ToolchainLease {
    dataset: Arc<Dataset>,
    disposition: &'static str,
}
impl ToolchainLease {
    pub(super) fn root(&self) -> &Path { self.dataset.toolchain.root() }
    pub(super) fn disposition(&self) -> &'static str { self.disposition }
    pub(super) fn verify(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        self.dataset.toolchain.verify(stopped)
    }

    /// Read-only at its canonical name is insufficient when another writable
    /// bind exposes the same tree. Check the FINAL spec, after source/Cargo-home
    /// selection, without changing it. Protect the whole pool, not just this
    /// lease: a build must not write another retained toolchain through HOME or
    /// a broad workspace bind. Host processes with our credentials remain outside
    /// this boundary; the existing inode/mutation verification still applies.
    pub(super) fn validate_namespace(&self, spec: &CanonicalNamespaceSpec) -> io::Result<()> {
        let visible = Path::new(rabs_sandbox::layout::TOOLCHAIN);
        let root = std::fs::canonicalize(self.root())?;
        let pool = std::fs::canonicalize(self.dataset.pool.0.path())?;
        let overlap = |a: &Path, b: &Path| a.starts_with(b) || b.starts_with(a);
        let mut owned = 0;
        for bind in &spec.ro_binds {
            if bind.visible == visible {
                if bind.backing != self.root() {
                    return Err(invalid("toolchain mount differs from its retained lease"));
                }
                owned += 1;
            } else if overlap(&bind.visible, visible) {
                return Err(invalid("read-only mount shadows the retained toolchain"));
            }
        }
        if owned != 1 { return Err(invalid("execution requires one retained read-only toolchain mount")); }
        for bind in &spec.rw_binds {
            if overlap(&bind.visible, visible) {
                return Err(invalid("writable mount shadows the retained toolchain"));
            }
            let backing = std::fs::canonicalize(&bind.backing)?;
            if overlap(&backing, &pool) || overlap(&backing, &root) {
                return Err(invalid("writable mount exposes retained toolchain storage"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let candidate = std::fs::metadata(&backing)?;
                for protected in [&pool, &root] {
                    let metadata = std::fs::metadata(protected)?;
                    if candidate.dev() == metadata.dev() && candidate.ino() == metadata.ino() {
                        return Err(invalid("writable mount aliases retained toolchain storage"));
                    }
                }
            }
        }
        Ok(())
    }
}

enum Slot {
    Capturing,
    Ready { dataset:Arc<Dataset>, touched:u64 },
}
#[derive(Default)]
struct State {
    entries: BTreeMap<Key, Slot>,
    reserved_bytes: u64,
    clock: u64,
}
struct ToolchainPool {
    directory: Arc<PoolDirectory>,
    max_bytes: u64,
    max_entries: usize,
    state: Mutex<State>,
    changed: Condvar,
}

/// Remove a failed/panicking capture reservation and wake its waiters. This
/// guard is never held by a waiter, so cancellation cannot clear another owner's
/// capture. Poisoned state refuses future acquisitions rather than being trusted.
struct Reservation<'a> {
    pool: &'a ToolchainPool,
    key: Key,
    armed: bool,
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.armed && let Ok(mut state) = self.pool.state.lock()
            && matches!(state.entries.get(&self.key), Some(Slot::Capturing))
        {
            state.entries.remove(&self.key);
            state.reserved_bytes -= self.key.2;
        }
        self.pool.changed.notify_all();
    }
}

impl ToolchainPool {
    fn new(max_bytes: u64, max_entries: usize) -> io::Result<Self> {
        if max_bytes > MAX_POOL_BYTES || max_entries == 0 || max_entries > MAX_POOL_ENTRIES {
            return Err(invalid("toolchain pool limits outside their bounds"));
        }
        Ok(Self {
            directory:Arc::new(PoolDirectory(private_directory(None)?)),
            max_bytes, max_entries, state:Mutex::new(State::default()), changed:Condvar::new(),
        })
    }
    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| invalid("toolchain pool ownership is poisoned"))
    }
    fn private(
        &self, source: &Path, expected: Option<&ToolchainIdentity>, stopped: &impl Fn() -> bool,
    ) -> io::Result<ToolchainLease> {
        Dataset::capture(&self.directory, source, expected, stopped)
            .map(|dataset| ToolchainLease { dataset, disposition:"private" })
    }
    fn discard_failed(&self, identity: Key, failed: &Arc<Dataset>) -> io::Result<()> {
        let mut state = self.lock()?;
        // A concurrent verifier may already have retired this entry and another
        // capture may now own the same identity. Never remove that replacement.
        if matches!(state.entries.get(&identity), Some(Slot::Ready { dataset, .. })
            if Arc::ptr_eq(dataset, failed))
        {
            state.entries.remove(&identity);
            state.reserved_bytes -= identity.2;
        }
        self.changed.notify_all();
        Ok(())
    }
    fn acquire(
        &self, source: &Path, expected: Option<&ToolchainIdentity>, stopped: impl Fn() -> bool,
    ) -> io::Result<ToolchainLease> {
        checkpoint(&stopped)?;
        let Some(expected) = expected.filter(|expected| self.max_bytes != 0 && expected.bytes <= self.max_bytes) else {
            return self.private(source, expected, &stopped);
        };
        let identity = key(expected);
        loop {
            checkpoint(&stopped)?;
            let mut state = self.lock()?;
            state.clock = state.clock.saturating_add(1);
            let touched = state.clock;
            match state.entries.get_mut(&identity) {
                Some(Slot::Ready { dataset, touched:last }) => {
                    *last = touched;
                    let dataset = Arc::clone(dataset);
                    drop(state);
                    // Never consult the mutable original installation on a hit:
                    // the request selected these exact bytes, not that pathname.
                    if let Err(error) = dataset.toolchain.verify(&stopped) {
                        if !stopped() { self.discard_failed(identity, &dataset)?; }
                        return Err(error);
                    }
                    return Ok(ToolchainLease { dataset, disposition:"reused" });
                }
                Some(Slot::Capturing) => {
                    let (state, _) = self.changed.wait_timeout(state, WAIT_SLICE)
                        .map_err(|_| invalid("toolchain pool ownership is poisoned"))?;
                    drop(state);
                    continue; // The execution deadline/cancel is checked again.
                }
                None => {}
            }
            let mut retired = Vec::new();
            while state.entries.len() >= self.max_entries
                || state.reserved_bytes > self.max_bytes - expected.bytes
            {
                let victim = state.entries.iter().filter_map(|(key, slot)| match slot {
                    Slot::Ready { dataset, touched } if Arc::strong_count(dataset) == 1 => Some((*key, *touched)),
                    _ => None,
                }).min_by_key(|(key, touched)| (*touched, *key)).map(|(key, _)| key);
                let Some(victim) = victim else {
                    drop(state);
                    drop(retired);
                    return self.private(source, Some(expected), &stopped);
                };
                if let Some(Slot::Ready { dataset, .. }) = state.entries.remove(&victim) {
                    state.reserved_bytes -= victim.2;
                    retired.push(dataset);
                }
            }
            state.entries.insert(identity, Slot::Capturing);
            state.reserved_bytes += expected.bytes;
            let mut reservation = Reservation { pool:self, key:identity, armed:true };
            drop(state);
            // Potentially slow filesystem cleanup and capture never hold the
            // admission mutex or block hits for another retained identity.
            drop(retired);
            let dataset = Dataset::capture(&self.directory, source, Some(expected), &stopped)?;
            checkpoint(&stopped)?;
            let mut state = self.lock()?;
            if !matches!(state.entries.get(&identity), Some(Slot::Capturing)) {
                return Err(invalid("toolchain capture lost its reservation"));
            }
            state.clock = state.clock.saturating_add(1);
            let touched = state.clock;
            state.entries.insert(identity, Slot::Ready { dataset:Arc::clone(&dataset), touched });
            reservation.armed = false;
            drop(state);
            self.changed.notify_all();
            return Ok(ToolchainLease { dataset, disposition:"captured" });
        }
    }
}

fn configured_bytes(value: Option<&str>) -> io::Result<u64> {
    let Some(value) = value else { return Ok(0); };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("RABS_WORKER_TOOLCHAIN_CACHE_BYTES must be an unsigned decimal byte count"));
    }
    value.parse::<u64>().ok().filter(|bytes| *bytes <= MAX_POOL_BYTES)
        .ok_or_else(|| invalid("RABS_WORKER_TOOLCHAIN_CACHE_BYTES exceeds the 64 GiB bound"))
}

/// The worker supervisor retains this scope across reconnects and drops it only
/// after session-owned execution has drained. Idle datasets then disappear;
/// outstanding library leases still retain their own backing until cleanup.
/// No global strong reference or detached janitor extends this lifetime.
#[must_use = "retain the toolchain scope through worker shutdown"]
pub struct ToolchainReuseScope {
    pool: Arc<ToolchainPool>,
}

impl ToolchainReuseScope {
    /// Read worker-local configuration once, before starting its session loop.
    /// Zero/absence disables retained reuse. No request JSON can change limits.
    pub fn from_environment() -> io::Result<Self> {
        let value = std::env::var_os(CONFIG_NAME);
        let text = value.as_ref().map(|value| value.to_str()
            .ok_or_else(|| invalid("RABS_WORKER_TOOLCHAIN_CACHE_BYTES is not UTF-8"))).transpose()?;
        let max_bytes = configured_bytes(text)?;
        let mut registry = ACTIVE_POOL.lock()
            .map_err(|_| invalid("toolchain pool registry is poisoned"))?;
        if registry.upgrade().is_some() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists,
                "one worker supervisor already owns the toolchain pool"));
        }
        let pool = Arc::new(ToolchainPool::new(max_bytes, MAX_POOL_ENTRIES)?);
        *registry = Arc::downgrade(&pool);
        Ok(Self { pool })
    }
}

impl Drop for ToolchainReuseScope {
    fn drop(&mut self) {
        // Poison recovery is cleanup-only, never authorization to use entries.
        let mut registry = ACTIVE_POOL.lock().unwrap_or_else(|error| error.into_inner());
        if registry.upgrade().is_some_and(|pool| Arc::ptr_eq(&pool, &self.pool)) {
            *registry = Weak::new();
        }
    }
}

/// Embedded callers without a worker scope retain the original private-capture
/// behavior. A registered pool error fails; it never selects an unpinned lane.
pub(super) fn prepare(
    source: &Path, expected: Option<&ToolchainIdentity>, stopped: impl Fn() -> bool,
) -> io::Result<ToolchainLease> {
    checkpoint(&stopped)?;
    let pool = ACTIVE_POOL.lock()
        .map_err(|_| invalid("toolchain pool registry is poisoned"))?.upgrade();
    match pool {
        Some(pool) => pool.acquire(source, expected, stopped),
        None => ToolchainPool::new(0, MAX_POOL_ENTRIES)?.acquire(source, expected, stopped),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_configuration_is_explicit_bounded_and_fail_closed() {
        assert_eq!(configured_bytes(None).unwrap(), 0);
        assert_eq!(configured_bytes(Some("0")).unwrap(), 0);
        assert_eq!(configured_bytes(Some("1024")).unwrap(), 1024);
        assert_eq!(configured_bytes(Some(&MAX_POOL_BYTES.to_string())).unwrap(), MAX_POOL_BYTES);
        for invalid in ["", "-1", "+1", " 1", "1 ", "1GiB", "18446744073709551616", "68719476737"] {
            assert!(configured_bytes(Some(invalid)).is_err(), "{invalid}");
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use rabs_sandbox::toolchain_dataset::fingerprint_toolchain;
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::thread;
        use std::time::Instant;

        fn source(bytes: &[u8]) -> (tempfile::TempDir, ToolchainIdentity) {
            let source = tempfile::tempdir().unwrap();
            fs::create_dir_all(source.path().join("bin")).unwrap();
            fs::create_dir_all(source.path().join("lib/empty")).unwrap();
            fs::write(source.path().join("bin/compiler"), bytes).unwrap();
            fs::set_permissions(source.path().join("bin/compiler"), fs::Permissions::from_mode(0o755)).unwrap();
            symlink("compiler", source.path().join("bin/rustc")).unwrap();
            let identity = fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false).unwrap();
            (source, identity)
        }
        fn pool(bytes: u64, entries: usize) -> ToolchainPool { ToolchainPool::new(bytes, entries).unwrap() }
        fn spec(lease: &ToolchainLease, writable: &Path) -> CanonicalNamespaceSpec {
            use rabs_sandbox::canonical_namespace::Bind;
            let mut spec = CanonicalNamespaceSpec::new();
            spec.ro_binds.push(Bind::new(lease.root(), rabs_sandbox::layout::TOOLCHAIN));
            spec.rw_binds.push(Bind::new(writable, rabs_sandbox::layout::WORKSPACE));
            spec
        }

        #[test]
        fn pinned_reuse_keeps_inodes_and_bytes_after_original_installation_disappears() {
            let (source, identity) = source(b"compiler\0\xff");
            let pool = pool(1024, 2);
            let first = pool.acquire(source.path(), Some(&identity), || false).unwrap();
            assert_eq!(first.disposition(), "captured");
            let inode = fs::metadata(first.root().join("bin/compiler")).unwrap().ino();
            assert_ne!(inode, fs::metadata(source.path().join("bin/compiler")).unwrap().ino());
            let missing = source.path().join("not-an-installation");
            let second = pool.acquire(&missing, Some(&identity), || false).unwrap();
            assert_eq!(second.disposition(), "reused");
            assert_eq!(second.root(), first.root());
            assert_eq!(fs::metadata(second.root().join("bin/compiler")).unwrap().ino(), inode);
            assert_eq!(fs::read(second.root().join("bin/compiler")).unwrap(), b"compiler\0\xff");
            assert_eq!(fs::read_link(second.root().join("bin/rustc")).unwrap(), Path::new("compiler"));
            assert!(second.root().join("lib/empty").is_dir());
            assert_eq!(pool.lock().unwrap().reserved_bytes, identity.bytes);
            let retained = second.root().to_path_buf();
            drop(first);
            drop(pool);
            assert!(retained.is_dir(), "a live lease owns its parent even after pool shutdown");
            second.verify(|| false).unwrap();
            drop(second);
            assert!(!retained.exists());
        }

        #[test]
        fn missing_pin_disabled_pool_and_oversize_entries_stay_private() {
            let (source, identity) = source(b"compiler");
            for (budget, expected) in [(0, Some(&identity)), (1, Some(&identity)), (1024, None)] {
                let pool = pool(budget, 2);
                let first = pool.acquire(source.path(), expected, || false).unwrap();
                let second = pool.acquire(source.path(), expected, || false).unwrap();
                assert_eq!(first.disposition(), "private");
                assert_eq!(second.disposition(), "private");
                assert_ne!(first.root(), second.root());
                assert!(pool.lock().unwrap().entries.is_empty());
            }
            let pool = pool(1024, 2);
            let first = pool.acquire(source.path(), Some(&identity), || false).unwrap();
            let mut changed = identity;
            changed.files += 1;
            assert!(pool.acquire(source.path(), Some(&changed), || false).is_err());
            first.verify(|| false).unwrap();
            assert_eq!(pool.lock().unwrap().entries.len(), 1);
            assert_eq!(pool.lock().unwrap().reserved_bytes, identity.bytes);
        }

        #[test]
        fn busy_capacity_never_evicts_a_live_dataset_and_idle_lru_is_reclaimed() {
          for (budget, entries) in [(8, 8), (1024, 2)] {
            let (a, a_id) = source(b"aaaa");
            let (b, b_id) = source(b"bbbb");
            let (c, c_id) = source(b"cccc");
            let pool = pool(budget, entries);
            let a = pool.acquire(a.path(), Some(&a_id), || false).unwrap();
            let b = pool.acquire(b.path(), Some(&b_id), || false).unwrap();
            let a_root = a.root().to_path_buf();
            let b_root = b.root().to_path_buf();
            let overflow = pool.acquire(c.path(), Some(&c_id), || false).unwrap();
            assert_eq!(overflow.disposition(), "private");
            assert_eq!(pool.lock().unwrap().reserved_bytes, 8);
            assert!(a_root.is_dir() && b_root.is_dir());
            drop(overflow);
            drop(a);
            drop(b);
            // Refresh B; A is the unique least recently used idle entry.
            drop(pool.acquire(Path::new("/absent"), Some(&b_id), || false).unwrap());
            let c = pool.acquire(c.path(), Some(&c_id), || false).unwrap();
            assert_eq!(c.disposition(), "captured");
            assert!(!a_root.exists());
            assert!(b_root.is_dir());
            assert_eq!(pool.lock().unwrap().reserved_bytes, 8);
          }
        }

        #[test]
        fn failed_and_cancelled_captures_release_their_exact_reservations() {
            let (source, identity) = source(b"compiler");
            let pool = pool(1024, 2);
            assert!(pool.acquire(&source.path().join("missing"), Some(&identity), || false).is_err());
            assert!(pool.lock().unwrap().entries.is_empty());
            let understated = ToolchainIdentity { bytes:identity.bytes - 1, ..identity };
            let error = pool.acquire(source.path(), Some(&understated), || false).err().unwrap();
            assert!(error.to_string().contains("byte limit exceeded"));
            assert!(pool.lock().unwrap().entries.is_empty());
            assert_eq!(fs::read_dir(pool.directory.0.path()).unwrap().count(), 0);
            let cancelled = AtomicBool::new(false);
            let error = pool.acquire(source.path(), Some(&identity), || {
                // Stop only after the admission transaction has reserved space.
                if pool.lock().unwrap().entries.contains_key(&key(&identity)) {
                    cancelled.store(true, Ordering::Release);
                }
                cancelled.load(Ordering::Acquire)
            }).err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(pool.lock().unwrap().entries.is_empty());
            assert_eq!(pool.lock().unwrap().reserved_bytes, 0);
            assert_eq!(pool.acquire(source.path(), Some(&identity), || false).unwrap().disposition(), "captured");
        }

        #[test]
        fn same_identity_waiters_share_one_capture_and_cancel_without_stealing_ownership() {
            let (source, identity) = source(b"compiler");
            let pool = Arc::new(pool(1024, 2));
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let leader_pool = Arc::clone(&pool);
            let source_path = source.path().to_path_buf();
            let leader = thread::spawn(move || {
                let paused = AtomicBool::new(false);
                leader_pool.acquire(&source_path, Some(&identity), || {
                    let reserved = {
                        leader_pool.lock().unwrap().entries.contains_key(&key(&identity))
                    };
                    if reserved && !paused.swap(true, Ordering::AcqRel) {
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    false
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let until = Instant::now() + Duration::from_millis(60);
            let error = pool.acquire(Path::new("/absent"), Some(&identity), || Instant::now() >= until)
                .err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(matches!(pool.lock().unwrap().entries.get(&key(&identity)), Some(Slot::Capturing)));
            let follower_pool = Arc::clone(&pool);
            let follower = thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(5);
                follower_pool.acquire(Path::new("/absent"), Some(&identity), || Instant::now() >= until)
            });
            release_tx.send(()).unwrap();
            let first = leader.join().unwrap().unwrap();
            let second = follower.join().unwrap().unwrap();
            assert_eq!(first.root(), second.root());
            assert_eq!(second.disposition(), "reused");
            assert_eq!(pool.lock().unwrap().reserved_bytes, identity.bytes);
        }

        #[test]
        fn corrupt_retained_bytes_refuse_instead_of_using_the_original_or_another_pin() {
            let (source, identity) = source(b"compiler");
            let pool = pool(1024, 2);
            let lease = pool.acquire(source.path(), Some(&identity), || false).unwrap();
            let path = lease.root().join("bin/compiler");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&path, b"tampered").unwrap();
            assert!(pool.acquire(source.path(), Some(&identity), || false).is_err());
            assert!(lease.verify(|| false).is_err());
            assert!(pool.lock().unwrap().entries.is_empty());
            let replacement = pool.acquire(source.path(), Some(&identity), || false).unwrap();
            assert_ne!(lease.root(), replacement.root());
            assert_eq!(fs::read(replacement.root().join("bin/compiler")).unwrap(), b"compiler");
            pool.discard_failed(key(&identity), &lease.dataset).unwrap();
            assert_eq!(pool.lock().unwrap().entries.len(), 1, "late failure cannot retire a replacement");
        }

        #[test]
        fn final_namespace_cannot_expose_any_pool_storage_through_writable_mounts() {
            use rabs_sandbox::canonical_namespace::Bind;
            let (source, identity) = source(b"compiler");
            let pool = pool(1024, 2);
            let lease = pool.acquire(source.path(), Some(&identity), || false).unwrap();
            let writable = tempfile::tempdir().unwrap();
            let valid = spec(&lease, writable.path());
            lease.validate_namespace(&valid).unwrap();
            let alias = writable.path().join("alias");
            symlink(lease.root(), &alias).unwrap();
            for case in 0..7 {
                let mut bad = valid.clone();
                match case {
                    0 => bad.ro_binds[0].backing = source.path().to_path_buf(),
                    1 => bad.ro_binds.push(bad.ro_binds[0].clone()),
                    2 => bad.rw_binds.push(Bind::new(writable.path(), "/__rabs/toolchain/bin")),
                    3 => bad.rw_binds[0].backing = pool.directory.0.path().to_path_buf(),
                    4 => bad.rw_binds[0].backing = lease.root().join("lib"),
                    5 => bad.rw_binds[0].backing = alias.clone(),
                    _ => bad.rw_binds[0].backing = pool.directory.0.path().parent().unwrap().to_path_buf(),
                }
                let before = bad.clone();
                assert!(lease.validate_namespace(&bad).is_err(), "case {case}");
                assert_eq!(bad, before);
            }
        }
    }
}
