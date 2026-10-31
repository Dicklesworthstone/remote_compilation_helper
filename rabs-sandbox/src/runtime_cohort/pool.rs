//! Bounded, process-owned reuse of independently retained ELF runtime bytes.
//!
//! A key only selects a candidate. Every acquisition checks its full bytes and
//! current output-filesystem contract; callers still reobserve the host before
//! and after execution. No host library or mutable toolchain path is served as
//! a retained image. Capture and cleanup run outside the short admission lock.

use super::{RetainedRuntime, RuntimeCohortError, retain_runtime_cohort};
use crate::toolchain_dataset::ToolchainIdentity;
use std::fmt;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// Maximum retained images, counting in-progress captures and quarantined
/// storage. Each capture retains the existing 256 MiB external-runtime bound.
/// Private overflow copies retain their ordinary per-execution lifetime.
pub const MAX_RETAINED_RUNTIMES: usize = 4;
const WAIT_SLICE: Duration = Duration::from_millis(20);

fn invalid(detail: &'static str) -> RuntimeCohortError {
    RuntimeCohortError::Invalid(detail)
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), RuntimeCohortError> {
    if cancelled() {
        Err(invalid("runtime acquisition cancelled"))
    } else {
        Ok(())
    }
}

fn filesystem_profile(root: &Path) -> Result<Vec<u8>, RuntimeCohortError> {
    #[cfg(target_os = "linux")]
    {
        super::linux::filesystem_profile(root)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        Err(RuntimeCohortError::Unsupported(
            "Linux ELF runtime required",
        ))
    }
}

/// The request's verified compiler dataset and exact runtime contract.
///
/// The caller must hold the independently verified toolchain through execution.
/// Its identity selects reuse, never proves the supplied path's contents.
#[derive(Clone, Copy)]
pub struct RuntimeRequest<'a> {
    /// Actual compiler within the retained toolchain.
    pub compiler: &'a Path,
    /// Independently retained toolchain root.
    pub toolchain_root: &'a Path,
    /// Complete content identity of that retained toolchain.
    pub toolchain_identity: &'a ToolchainIdentity,
    /// Ordered physical loader paths, all within the retained toolchain.
    pub loader_search_paths: &'a [PathBuf],
    /// Runtime cohort already bound into this execution's request.
    pub expected_cohort: &'a [u8; 32],
    /// This attempt's current private output directory, never a prior attempt.
    pub filesystem_root: &'a Path,
}

#[derive(Clone, PartialEq, Eq)]
struct Key {
    toolchain: ([u8; 32], u64, u64),
    compiler: PathBuf,
    loader: Vec<PathBuf>,
    cohort: [u8; 32],
    filesystem: Vec<u8>,
}

impl RuntimeRequest<'_> {
    fn key(&self) -> Result<Key, RuntimeCohortError> {
        if !self.toolchain_root.is_absolute()
            || !self.compiler.is_absolute()
            || self.toolchain_identity.files == 0
            || self.toolchain_identity.bytes == 0
            || self.loader_search_paths.len() > 128
        {
            return Err(invalid(
                "runtime reuse requires a complete retained toolchain",
            ));
        }
        let relative = |path: &Path| {
            let relative = path
                .strip_prefix(self.toolchain_root)
                .map_err(|_| invalid("runtime reuse loader path leaves retained toolchain"))?;
            if relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err(invalid("runtime reuse path is not normalized"));
            }
            Ok(relative.to_path_buf())
        };
        let compiler = relative(self.compiler)?;
        if compiler.as_os_str().is_empty() {
            return Err(invalid("runtime reuse compiler is not a toolchain member"));
        }
        let loader = self
            .loader_search_paths
            .iter()
            .map(|path| relative(path))
            .collect::<Result<_, _>>()?;
        let filesystem = filesystem_profile(self.filesystem_root)?;
        Ok(Key {
            toolchain: (
                self.toolchain_identity.sha256,
                self.toolchain_identity.files,
                self.toolchain_identity.bytes,
            ),
            compiler,
            loader,
            cohort: *self.expected_cohort,
            filesystem,
        })
    }

    fn capture(
        &self,
        parent: &Path,
        cancelled: &impl Fn() -> bool,
    ) -> Result<RetainedRuntime, RuntimeCohortError> {
        let runtime = retain_runtime_cohort(
            self.compiler,
            self.toolchain_root,
            self.loader_search_paths,
            self.filesystem_root,
            parent,
            cancelled,
        )?;
        if runtime.cohort().bytes != *self.expected_cohort {
            return Err(invalid(
                "captured host runtime differs from requested cohort",
            ));
        }
        checkpoint(cancelled)?;
        Ok(runtime)
    }
}

/// Descriptor-anchored storage; a replaced pathname never grants cleanup rights.
struct Directory {
    #[cfg(target_os = "linux")]
    owner: super::linux::RuntimeDirectory,
}

impl Directory {
    fn new(parent: &Path) -> Result<Self, RuntimeCohortError> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                owner: super::linux::RuntimeDirectory::new(parent)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = parent;
            Err(RuntimeCohortError::Unsupported(
                "Linux ELF runtime required",
            ))
        }
    }

    fn path(&self) -> &Path {
        #[cfg(target_os = "linux")]
        {
            self.owner.path()
        }
        #[cfg(not(target_os = "linux"))]
        {
            unreachable!("runtime pool directories require Linux")
        }
    }

    fn verify(&self) -> Result<(), RuntimeCohortError> {
        #[cfg(target_os = "linux")]
        {
            self.owner.verify_owner()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(RuntimeCohortError::Unsupported(
                "Linux ELF runtime required",
            ))
        }
    }

    fn remove_owned(&self) -> Result<(), RuntimeCohortError> {
        #[cfg(target_os = "linux")]
        {
            self.owner.remove_empty()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(RuntimeCohortError::Unsupported(
                "Linux ELF runtime required",
            ))
        }
    }

    fn preserve(&self) {
        #[cfg(target_os = "linux")]
        self.owner.preserve();
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        // An image releases its runtime before its container. Unknown children,
        // replacements and failed cleanup must survive the parent's destructor.
        if self.remove_owned().is_err() {
            self.preserve();
        }
    }
}

struct Allocation {
    directory: Directory,
    // Active and retired images keep the pool directory alive after shutdown.
    parent: Option<Arc<Directory>>,
}

impl Allocation {
    fn new(parent: Arc<Directory>) -> Result<Self, RuntimeCohortError> {
        parent.verify()?;
        let directory = Directory::new(parent.path())?;
        parent.verify()?;
        Ok(Self {
            directory,
            parent: Some(parent),
        })
    }

    fn preserve(&self) {
        self.directory.preserve();
        if let Some(parent) = &self.parent {
            parent.preserve();
        }
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if self.directory.remove_owned().is_err() {
            self.preserve();
        }
    }
}

struct Image {
    // Child cleanup precedes its last private parent reference.
    runtime: RetainedRuntime,
    allocation: Arc<Allocation>,
}

impl Image {
    fn remove_owned(&self) -> Result<(), RuntimeCohortError> {
        if let Err(error) = self.runtime.remove_owned() {
            self.allocation.preserve();
            return Err(error);
        }
        if let Err(error) = self.allocation.directory.remove_owned() {
            self.allocation.preserve();
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        // Never let the parent's recursive cleanup remove a replaced child.
        if self.runtime.remove_owned().is_err() {
            self.allocation.preserve();
        }
    }
}

/// One attempt's owned runtime, with its own output-filesystem binding.
/// Dropping a pool cannot evict this lease, including private overflow copies.
pub struct RuntimeLease {
    image: Arc<Image>,
    filesystem_root: PathBuf,
    disposition: &'static str,
}

impl fmt::Debug for RuntimeLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeLease")
            .field("disposition", &self.disposition)
            .field("cohort", self.image.runtime.cohort())
            .finish_non_exhaustive()
    }
}

impl Deref for RuntimeLease {
    type Target = RetainedRuntime;

    fn deref(&self) -> &Self::Target {
        &self.image.runtime
    }
}

impl RuntimeLease {
    /// Capture without retained reuse, preserving the same cohort verification.
    pub fn private(
        request: RuntimeRequest<'_>,
        retention_parent: &Path,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, RuntimeCohortError> {
        checkpoint(&cancelled)?;
        let allocation = Arc::new(Allocation {
            directory: Directory::new(retention_parent)?,
            parent: None,
        });
        Self::capture(request, allocation, "private", &cancelled)
    }

    fn capture(
        request: RuntimeRequest<'_>,
        allocation: Arc<Allocation>,
        disposition: &'static str,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Self, RuntimeCohortError> {
        let runtime = request.capture(allocation.directory.path(), cancelled)?;
        Ok(Self {
            image: Arc::new(Image {
                runtime,
                allocation,
            }),
            filesystem_root: request.filesystem_root.to_path_buf(),
            disposition,
        })
    }

    /// Whether this attempt captured, reused or privately prepared its runtime.
    pub const fn disposition(&self) -> &'static str {
        self.disposition
    }

    /// Rehash retained bytes and measure this attempt's current filesystem.
    /// The worker must additionally retain its existing host re-observation.
    pub fn verify(&self, cancelled: impl Fn() -> bool) -> Result<(), RuntimeCohortError> {
        self.image
            .runtime
            .verify_on_filesystem(&self.filesystem_root, cancelled)
    }
}

enum Phase {
    Preparing,
    Ready {
        image: Arc<Image>,
        retired: bool,
    },
    Reclaiming,
    // Failed cleanup still occupies its slot. Do not manufacture free space or
    // let a parent owner recursively discard uncertain data on shutdown.
    Quarantined {
        _image: Option<Arc<Image>>,
        _allocation: Option<Arc<Allocation>>,
    },
}

struct Entry {
    key: Key,
    ticket: u64,
    touched: u64,
    phase: Phase,
}

#[derive(Default)]
struct State {
    entries: Vec<Entry>,
    next_ticket: u64,
    clock: u64,
}

/// Small LRU of immutable runtime owners, shared across worker sessions.
///
/// Only idle images may be evicted. Same-key callers join one bounded capture;
/// unrelated full-pool requests use private capture instead of waiting behind a
/// compiler. Captures, active/retired images and failed cleanup share one bound.
/// Any uncertain cleanup closes the pool to new acquisitions, including when a
/// private overflow lease fails cleanup. Already active leases still own their
/// bytes and can finish; failed private reclamation cannot accumulate new copies.
pub struct RuntimePool {
    state: Mutex<State>,
    changed: Condvar,
    directory: Arc<Directory>,
    capacity: usize,
}

impl fmt::Debug for RuntimePool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePool")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

struct Capture<'a> {
    pool: &'a RuntimePool,
    ticket: u64,
    allocation: Option<Arc<Allocation>>,
    allocation_started: bool,
    armed: bool,
}

impl Drop for Capture<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let reclaimed = self
            .allocation
            .as_ref()
            .map_or(!self.allocation_started, |owner| {
                owner.directory.remove_owned().is_ok()
            });
        if !reclaimed {
            if let Some(allocation) = &self.allocation {
                allocation.preserve();
            }
            self.pool.directory.preserve();
        }
        if let Ok(mut state) = self.pool.state.lock()
            && let Some(index) = state.entries.iter().position(|entry| {
                entry.ticket == self.ticket && matches!(entry.phase, Phase::Preparing)
            })
        {
            if reclaimed {
                state.entries.remove(index);
            } else {
                state.entries[index].phase = Phase::Quarantined {
                    _image: None,
                    _allocation: self.allocation.clone(),
                };
            }
        }
        self.pool.changed.notify_all();
    }
}

impl RuntimePool {
    /// Retain at most `capacity` images beneath a private worker-owned parent.
    /// Zero disables reuse; it still uses verified private runtime capture.
    pub fn new(retention_parent: &Path, capacity: usize) -> Result<Self, RuntimeCohortError> {
        if capacity > MAX_RETAINED_RUNTIMES {
            return Err(invalid("runtime pool exceeds its four-image bound"));
        }
        Ok(Self {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            directory: Arc::new(Directory::new(retention_parent)?),
            capacity,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, RuntimeCohortError> {
        self.state
            .lock()
            .map_err(|_| invalid("runtime pool ownership is poisoned"))
    }

    fn private(
        &self,
        request: RuntimeRequest<'_>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<RuntimeLease, RuntimeCohortError> {
        checkpoint(cancelled)?;
        let allocation = match Allocation::new(Arc::clone(&self.directory)) {
            Ok(allocation) => Arc::new(allocation),
            Err(error) => {
                // A directory constructor may have created its child before
                // opening or verifying it failed. Without an Allocation owner
                // there is no destructor to latch this cleanup uncertainty.
                self.directory.preserve();
                return Err(error);
            }
        };
        RuntimeLease::capture(request, allocation, "private", cancelled)
    }

    fn retire(&self, ticket: u64, failed: &Arc<Image>) -> Result<(), RuntimeCohortError> {
        let mut state = self.lock()?;
        if let Some(entry) = state
            .entries
            .iter_mut()
            .find(|entry| entry.ticket == ticket)
            && let Phase::Ready { image, retired } = &mut entry.phase
            && Arc::ptr_eq(image, failed)
        {
            *retired = true;
        }
        self.changed.notify_all();
        Ok(())
    }

    /// Acquire one exact runtime without changing execution or publication policy.
    /// Cancellation stops this caller's wait/capture, never another caller's owner.
    pub fn acquire(
        &self,
        request: RuntimeRequest<'_>,
        cancelled: impl Fn() -> bool,
    ) -> Result<RuntimeLease, RuntimeCohortError> {
        checkpoint(&cancelled)?;
        self.directory.verify()?;
        let key = request.key()?;
        if self.capacity == 0 {
            return self.private(request, &cancelled);
        }
        loop {
            checkpoint(&cancelled)?;
            self.directory.verify()?;
            let mut state = self.lock()?;
            state.clock = state.clock.saturating_add(1);
            let touched = state.clock;
            if let Some(entry) = state.entries.iter_mut().find(|entry| {
                entry.key == key && matches!(entry.phase, Phase::Ready { retired: false, .. })
            }) {
                entry.touched = touched;
                let ticket = entry.ticket;
                let Phase::Ready { image, .. } = &entry.phase else {
                    unreachable!()
                };
                let image = Arc::clone(image);
                drop(state);
                if let Err(error) = image
                    .runtime
                    .verify_on_filesystem(request.filesystem_root, &cancelled)
                {
                    if !cancelled() {
                        self.retire(ticket, &image)?;
                    }
                    return Err(error);
                }
                checkpoint(&cancelled)?;
                return Ok(RuntimeLease {
                    image,
                    filesystem_root: request.filesystem_root.to_path_buf(),
                    disposition: "reused",
                });
            }
            if state.entries.iter().any(|entry| {
                entry.key == key && matches!(entry.phase, Phase::Preparing | Phase::Reclaiming)
            }) {
                let (state, _) = self
                    .changed
                    .wait_timeout(state, WAIT_SLICE)
                    .map_err(|_| invalid("runtime pool ownership is poisoned"))?;
                drop(state);
                continue;
            }
            if state.entries.len() >= self.capacity {
                let victim = state
                    .entries
                    .iter_mut()
                    .enumerate()
                    .filter_map(|(index, entry)| match &mut entry.phase {
                        Phase::Ready { image, retired } => Arc::get_mut(image)
                            .map(|_| (index, !*retired, entry.touched, entry.ticket)),
                        _ => None,
                    })
                    .min_by_key(|(_, ready, touched, ticket)| (*ready, *touched, *ticket))
                    .map(|(index, _, _, _)| index);
                let Some(index) = victim else {
                    drop(state);
                    return self.private(request, &cancelled);
                };
                let ticket = state.entries[index].ticket;
                let Phase::Ready { image, retired } =
                    std::mem::replace(&mut state.entries[index].phase, Phase::Reclaiming)
                else {
                    unreachable!()
                };
                drop(state);
                // No external Weak is exposed, but still make exclusivity one
                // atomic decision before touching the physical image.
                let (reclaimed, phase) = match Arc::try_unwrap(image) {
                    Ok(image) => match image.remove_owned() {
                        Ok(()) => (true, None),
                        Err(_) => (
                            false,
                            Some(Phase::Quarantined {
                                _image: Some(Arc::new(image)),
                                _allocation: None,
                            }),
                        ),
                    },
                    Err(image) => (false, Some(Phase::Ready { image, retired })),
                };
                let mut state = self.lock()?;
                let index = state
                    .entries
                    .iter()
                    .position(|entry| entry.ticket == ticket)
                    .ok_or_else(|| invalid("runtime reclamation lost its ownership slot"))?;
                if reclaimed {
                    state.entries.remove(index);
                } else {
                    state.entries[index].phase = phase.expect("unreclaimed runtime owner");
                }
                drop(state);
                self.changed.notify_all();
                if !reclaimed {
                    return self.private(request, &cancelled);
                }
                continue;
            }
            let ticket = state
                .next_ticket
                .checked_add(1)
                .ok_or_else(|| invalid("runtime ownership ticket exhausted"))?;
            state.next_ticket = ticket;
            state.entries.push(Entry {
                key: key.clone(),
                ticket,
                touched,
                phase: Phase::Preparing,
            });
            let mut capture = Capture {
                pool: self,
                ticket,
                allocation: None,
                allocation_started: false,
                armed: true,
            };
            drop(state);
            checkpoint(&cancelled)?;
            capture.allocation_started = true;
            let allocation = Arc::new(Allocation::new(Arc::clone(&self.directory))?);
            capture.allocation = Some(Arc::clone(&allocation));
            let lease = RuntimeLease::capture(request, allocation, "captured", &cancelled)?;
            checkpoint(&cancelled)?;
            let mut state = self.lock()?;
            let entry = state
                .entries
                .iter_mut()
                .find(|entry| entry.ticket == ticket && matches!(entry.phase, Phase::Preparing))
                .ok_or_else(|| invalid("runtime capture lost its ownership slot"))?;
            entry.phase = Phase::Ready {
                image: Arc::clone(&lease.image),
                retired: false,
            };
            capture.armed = false;
            drop(state);
            self.changed.notify_all();
            return Ok(lease);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::runtime_cohort::observe_runtime_cohort;
    use crate::toolchain_dataset::{PreparedToolchain, ToolchainLimits, capture_toolchain};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // These are real ELF-loader and filesystem component tests. /usr/bin/true
    // supplies an actual dynamic executable; it is never evidence of rustc or
    // Cargo compilation. Both the toolchain copy and external runtime are read,
    // captured and independently verified by their production implementations.
    struct Fixture {
        toolchain: PreparedToolchain,
        compiler: PathBuf,
        cohort: [u8; 32],
        _directory: tempfile::TempDir,
    }

    fn private_directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("rabs-runtime-pool-test-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    impl Fixture {
        fn new(marker: &[u8]) -> Self {
            let directory = private_directory();
            let source = directory.path().join("source");
            fs::create_dir_all(source.join("bin")).unwrap();
            fs::create_dir_all(source.join("lib/first")).unwrap();
            fs::create_dir_all(source.join("lib/second")).unwrap();
            fs::copy("/usr/bin/true", source.join("bin/rustc")).unwrap();
            fs::write(source.join("dataset-marker"), marker).unwrap();
            let toolchain = capture_toolchain(
                &source,
                &directory.path().join("retained"),
                None,
                &ToolchainLimits::default(),
                || false,
            )
            .unwrap();
            toolchain.verify(|| false).unwrap();
            let compiler = toolchain.root().join("bin/rustc");
            let cohort = observe_runtime_cohort(&compiler, toolchain.root(), &[], directory.path())
                .unwrap()
                .bytes;
            Self {
                toolchain,
                compiler,
                cohort,
                _directory: directory,
            }
        }

        fn request<'a>(&'a self, output: &'a Path) -> RuntimeRequest<'a> {
            RuntimeRequest {
                compiler: &self.compiler,
                toolchain_root: self.toolchain.root(),
                toolchain_identity: self.toolchain.identity(),
                loader_search_paths: &[],
                expected_cohort: &self.cohort,
                filesystem_root: output,
            }
        }
    }

    #[test]
    fn warm_lease_uses_current_output_and_outlives_pool_shutdown() {
        let fixture = Fixture::new(b"shared");
        let parent = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let pool_path = pool.directory.path().to_path_buf();
        let first_output = private_directory();
        let first = pool
            .acquire(fixture.request(first_output.path()), || false)
            .unwrap();
        assert_eq!(first.disposition(), "captured");
        let image_path = first.image.runtime.inner.owner.path().to_path_buf();
        let old_output = first_output.path().to_path_buf();
        drop(first_output);
        assert!(!old_output.exists());

        let current_output = private_directory();
        let current = pool
            .acquire(fixture.request(current_output.path()), || false)
            .unwrap();
        assert_eq!(current.disposition(), "reused");
        assert!(Arc::ptr_eq(&first.image, &current.image));
        current.verify(|| false).unwrap();
        assert!(first.verify(|| false).is_err());
        // Namespace construction still refuses writable pool ancestors, even
        // when the active runtime originated in an earlier execution attempt.
        assert!(
            current
                .append_mounts(&mut Vec::new(), &[parent.path().to_path_buf()])
                .is_err()
        );
        drop(first);
        drop(pool);
        assert!(image_path.is_dir());
        current.verify(|| false).unwrap();
        drop(current);
        assert!(!image_path.exists());
        assert!(!pool_path.exists());
        assert!(parent.path().is_dir());
    }

    #[test]
    fn complete_dataset_and_ordered_loader_paths_select_reuse() {
        let first = Fixture::new(b"identity-a");
        let same = Fixture::new(b"identity-a");
        let changed = Fixture::new(b"identity-b");
        let output = private_directory();
        assert_eq!(first.toolchain.identity(), same.toolchain.identity());
        assert_ne!(first.toolchain.identity(), changed.toolchain.identity());
        let first_key = first.request(output.path()).key().unwrap();
        assert!(first_key == same.request(output.path()).key().unwrap());
        assert!(first_key != changed.request(output.path()).key().unwrap());

        let forward = vec![
            first.toolchain.root().join("lib/first"),
            first.toolchain.root().join("lib/second"),
        ];
        let reverse = vec![forward[1].clone(), forward[0].clone()];
        let mut request = first.request(output.path());
        request.loader_search_paths = &forward;
        let forward_key = request.key().unwrap();
        request.loader_search_paths = &reverse;
        assert!(forward_key != request.key().unwrap());

        let parent = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let lease = pool
            .acquire(first.request(output.path()), || false)
            .unwrap();
        let reused = pool.acquire(same.request(output.path()), || false).unwrap();
        assert!(Arc::ptr_eq(&lease.image, &reused.image));
        let private = pool
            .acquire(changed.request(output.path()), || false)
            .unwrap();
        assert_eq!(private.disposition(), "private");
        assert!(!Arc::ptr_eq(&lease.image, &private.image));
        private.verify(|| false).unwrap();
    }

    #[test]
    fn concurrent_same_key_requests_share_one_real_capture() {
        let fixture = Fixture::new(b"concurrent");
        let parent = private_directory();
        let pool = RuntimePool::new(parent.path(), 2).unwrap();
        let barrier = Barrier::new(6);
        let leases = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..6)
                .map(|_| {
                    scope.spawn(|| {
                        let output = private_directory();
                        barrier.wait();
                        let lease = pool
                            .acquire(fixture.request(output.path()), || false)
                            .unwrap();
                        (lease, output)
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            leases
                .iter()
                .filter(|(lease, _)| lease.disposition() == "captured")
                .count(),
            1
        );
        assert_eq!(pool.lock().unwrap().entries.len(), 1);
        for (lease, _) in &leases {
            assert!(Arc::ptr_eq(&lease.image, &leases[0].0.image));
            lease.verify(|| false).unwrap();
        }
    }

    #[test]
    fn waiter_cancellation_does_not_release_another_capture_reservation() {
        let fixture = Fixture::new(b"cancel-wait");
        let parent = private_directory();
        let output = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let request = fixture.request(output.path());
        // Reserve exactly the state a live capture owns. Keeping that owner in
        // this scope makes the cancellation boundary deterministic; the later
        // acquisition below still performs real ELF/filesystem capture.
        {
            let mut state = pool.lock().unwrap();
            state.next_ticket = 1;
            state.entries.push(Entry {
                key: request.key().unwrap(),
                ticket: 1,
                touched: 0,
                phase: Phase::Preparing,
            });
        }
        let capture = Capture {
            pool: &pool,
            ticket: 1,
            allocation: None,
            allocation_started: false,
            armed: true,
        };
        let cancelled = AtomicBool::new(false);
        let checks = AtomicUsize::new(0);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                pool.acquire(request, || {
                    if checks.fetch_add(1, Ordering::Relaxed) == 2 {
                        sender.try_send(()).unwrap();
                    }
                    cancelled.load(Ordering::Acquire)
                })
            });
            let waited = receiver.recv_timeout(Duration::from_secs(10));
            cancelled.store(true, Ordering::Release);
            assert!(waiter.join().unwrap().is_err());
            assert!(waited.is_ok(), "waiter must reach a second admission pass");
        });
        assert!(matches!(
            pool.lock().unwrap().entries[0].phase,
            Phase::Preparing
        ));
        drop(capture);
        assert!(pool.lock().unwrap().entries.is_empty());
        let lease = pool.acquire(request, || false).unwrap();
        assert_eq!(lease.disposition(), "captured");
        lease.verify(|| false).unwrap();
    }

    #[test]
    fn active_images_force_private_overflow_and_only_idle_images_are_evicted() {
        let first = Fixture::new(b"first");
        let second = Fixture::new(b"second");
        let parent = private_directory();
        let output = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let active = pool
            .acquire(first.request(output.path()), || false)
            .unwrap();
        let old_path = active.image.runtime.inner.owner.path().to_path_buf();
        let overflow = pool
            .acquire(second.request(output.path()), || false)
            .unwrap();
        assert_eq!(overflow.disposition(), "private");
        assert!(old_path.is_dir());
        active.verify(|| false).unwrap();
        assert_eq!(pool.lock().unwrap().entries.len(), 1);
        drop(active);
        let retained = pool
            .acquire(second.request(output.path()), || false)
            .unwrap();
        assert_eq!(retained.disposition(), "captured");
        assert!(!old_path.exists());
        assert!(!Arc::ptr_eq(&overflow.image, &retained.image));
        assert_eq!(pool.lock().unwrap().entries.len(), 1);
        overflow.verify(|| false).unwrap();
        retained.verify(|| false).unwrap();
    }

    fn retained_file(root: &Path) -> PathBuf {
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                if metadata.is_file() && metadata.len() > 0 {
                    return path;
                }
                if metadata.is_dir() {
                    pending.push(path);
                }
            }
        }
        panic!("real dynamically loaded runtime has retained regular files")
    }

    #[test]
    fn warm_byte_mutation_retires_the_generation_without_reusing_it() {
        let fixture = Fixture::new(b"mutation");
        let parent = private_directory();
        let output = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let active = pool
            .acquire(fixture.request(output.path()), || false)
            .unwrap();
        let file = retained_file(active.image.runtime.inner.owner.path());
        let original = fs::read(&file).unwrap();
        let mut changed = original.clone();
        changed[0] ^= 1;
        fs::write(&file, changed).unwrap();
        assert!(active.verify(|| false).is_err());
        assert!(
            pool.acquire(fixture.request(output.path()), || false)
                .is_err()
        );
        assert!(matches!(
            pool.lock().unwrap().entries[0].phase,
            Phase::Ready { retired: true, .. }
        ));
        fs::write(&file, original).unwrap();
        // Restoring bytes cannot resurrect a generation already retired by a
        // failed verification, and its live lease prevents reclaiming it.
        let overflow = pool
            .acquire(fixture.request(output.path()), || false)
            .unwrap();
        assert_eq!(overflow.disposition(), "private");
        assert!(!Arc::ptr_eq(&active.image, &overflow.image));
        drop(active);
        let replacement = pool
            .acquire(fixture.request(output.path()), || false)
            .unwrap();
        assert_eq!(replacement.disposition(), "captured");
        replacement.verify(|| false).unwrap();
    }

    #[test]
    fn replaced_allocation_is_quarantined_without_deleting_either_generation() {
        let first = Fixture::new(b"replace-first");
        let second = Fixture::new(b"replace-second");
        let parent = private_directory();
        let output = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let lease = pool
            .acquire(first.request(output.path()), || false)
            .unwrap();
        let allocation = lease.image.allocation.directory.path().to_path_buf();
        let runtime_name = lease
            .image
            .runtime
            .inner
            .owner
            .path()
            .file_name()
            .unwrap()
            .to_owned();
        drop(lease);
        let moved = pool.directory.path().join("moved-owned-generation");
        fs::rename(&allocation, &moved).unwrap();
        fs::create_dir(&allocation).unwrap();
        fs::set_permissions(&allocation, fs::Permissions::from_mode(0o700)).unwrap();
        let marker = allocation.join("replacement-must-survive");
        fs::write(&marker, b"not owned by the old runtime").unwrap();
        assert!(
            pool.acquire(second.request(output.path()), || false)
                .is_err()
        );
        assert_eq!(pool.lock().unwrap().entries.len(), 1);
        assert!(matches!(
            pool.lock().unwrap().entries[0].phase,
            Phase::Quarantined { .. }
        ));
        drop(pool);
        assert_eq!(fs::read(&marker).unwrap(), b"not owned by the old runtime");
        assert!(moved.join(runtime_name).is_dir());
    }

    #[test]
    fn failed_private_cleanup_closes_allocation_without_invalidating_active_leases() {
        let first = Fixture::new(b"active-retained");
        let second = Fixture::new(b"private-failure");
        let parent = private_directory();
        let output = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let active = pool
            .acquire(first.request(output.path()), || false)
            .unwrap();
        let private = pool
            .acquire(second.request(output.path()), || false)
            .unwrap();
        assert_eq!(private.disposition(), "private");
        let allocation = private.image.allocation.directory.path().to_path_buf();
        let moved = pool.directory.path().join("moved-private-generation");
        fs::rename(&allocation, &moved).unwrap();
        fs::create_dir(&allocation).unwrap();
        fs::set_permissions(&allocation, fs::Permissions::from_mode(0o700)).unwrap();
        let marker = allocation.join("replacement-must-survive");
        fs::write(&marker, b"replacement").unwrap();
        drop(private);
        let entries = fs::read_dir(pool.directory.path()).unwrap().count();
        for _ in 0..3 {
            assert!(
                pool.acquire(second.request(output.path()), || false)
                    .is_err()
            );
            assert_eq!(
                fs::read_dir(pool.directory.path()).unwrap().count(),
                entries
            );
        }
        active.verify(|| false).unwrap();
        drop(pool);
        active.verify(|| false).unwrap();
        drop(active);
        assert_eq!(fs::read(&marker).unwrap(), b"replacement");
        assert!(moved.is_dir());
    }

    #[test]
    fn private_allocation_error_closes_pool_without_a_returned_owner() {
        let fixture = Fixture::new(b"private-constructor-error");
        let parent = private_directory();
        let output = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let active = pool
            .acquire(fixture.request(output.path()), || false)
            .unwrap();
        let pool_root = pool.directory.path();
        // Exercise a real ownership rejection in Allocation::new, before it
        // returns an owner. Restoring metadata must not reopen a pool whose
        // private constructor reported uncertain acquisition/cleanup.
        fs::set_permissions(pool_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            pool.private(fixture.request(output.path()), &|| false)
                .is_err()
        );
        fs::set_permissions(pool_root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            pool.acquire(fixture.request(output.path()), || false)
                .is_err()
        );
        assert_eq!(fs::read_dir(pool_root).unwrap().count(), 1);
        active.verify(|| false).unwrap();
    }

    #[test]
    fn mismatched_cohort_cannot_publish_a_candidate_or_leak_a_clean_slot() {
        let fixture = Fixture::new(b"cohort-check");
        let parent = private_directory();
        let output = private_directory();
        let pool = RuntimePool::new(parent.path(), 1).unwrap();
        let mut request = fixture.request(output.path());
        request.expected_cohort = &[0; 32];
        assert!(pool.acquire(request, || false).is_err());
        assert!(pool.lock().unwrap().entries.is_empty());
        assert_eq!(fs::read_dir(pool.directory.path()).unwrap().count(), 0);
        let lease = pool
            .acquire(fixture.request(output.path()), || false)
            .unwrap();
        lease.verify(|| false).unwrap();
        assert_eq!(lease.disposition(), "captured");
    }
}
