//! Bounded reuse of pinned, privately owned toolchains.
//!
//! Only a complete ToolchainIdentity selects reuse. A pathname, compiler version,
//! timestamp or cache hit never substitutes for content verification. Unpinned
//! requests keep their private capture. Pooled bytes are rehashed on acquisition
//! and by the executor before/after execution. Overlapping checks of the exact
//! same live dataset share one full byte verification, with each caller checking
//! its retained generation before joining and after success. Completed checks
//! are never memoized, and cancellation belongs to each caller. Every lease
//! retains the real private directory owner through process cleanup. Optional
//! durable storage retains verified compiler inputs across worker restarts; it
//! does not grant action publication or compiler-result reuse.
//!
//! The pool serializes admission, not filesystem work. Same-identity misses join
//! one capture; different identities can capture concurrently. Reservations count
//! against both bounds. Eviction touches only idle in-memory entries; a busy/full
//! pool uses a private capture rather than waiting for an unrelated compiler.
//! The optional durable catalogue has its own matching byte/entry bounds and
//! never deletes trees or adopts incomplete captures. See [`durable`].

mod durable;

use rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec;
use rabs_sandbox::toolchain_dataset::{
    PreparedToolchain, ToolchainIdentity, ToolchainLimits, capture_toolchain,
};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;

use crate::toolchain_transfer::SealedToolchain;

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
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "toolchain acquisition interrupted",
        ))
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

/// The parent and optional durable-cache lock outlive every execution lease.
struct PoolDirectory(tempfile::TempDir, Option<Arc<durable::DurableCache>>);

#[derive(Clone)]
struct VerificationFailure {
    kind: io::ErrorKind,
    message: String,
}

impl VerificationFailure {
    fn of(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn into_error(self) -> io::Error {
        io::Error::new(self.kind, self.message)
    }
}

#[derive(Default)]
struct VerificationFlight {
    result: Mutex<Option<Result<(), VerificationFailure>>>,
    changed: Condvar,
}

impl VerificationFlight {
    fn wait(&self, stopped: &impl Fn() -> bool) -> io::Result<Result<(), VerificationFailure>> {
        loop {
            // Cancellation belongs to the caller and may inspect other
            // ownership state. Never invoke it while holding the flight mutex.
            checkpoint(stopped)?;
            let result = self
                .result
                .lock()
                .map_err(|_| invalid("toolchain verification result is poisoned"))?;
            if let Some(result) = result.as_ref() {
                return Ok(result.clone());
            }
            let (next, _) = self
                .changed
                .wait_timeout(result, WAIT_SLICE)
                .map_err(|_| invalid("toolchain verification result is poisoned"))?;
            drop(next);
        }
    }
}

struct Dataset {
    // Field order closes inventory descriptors before removing the private tree,
    // and removes the child before dropping its last parent-directory reference.
    toolchain: PreparedToolchain,
    _directory: Option<tempfile::TempDir>,
    pool: Arc<PoolDirectory>,
    // Only overlapping full checks may join. This is neither a digest memo nor
    // an admission lock, and different retained owners never share a flight.
    verification: Mutex<Option<Arc<VerificationFlight>>>,
}

struct VerificationOwner<'a> {
    dataset: &'a Dataset,
    flight: Arc<VerificationFlight>,
    finished: bool,
}

impl VerificationOwner<'_> {
    fn finish(&mut self, result: &io::Result<()>) -> io::Result<()> {
        let mut active = self
            .dataset
            .verification
            .lock()
            .map_err(|_| invalid("toolchain verification ownership is poisoned"))?;
        if active
            .as_ref()
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            active.take();
        }
        // Detach before publishing: a later caller must perform its own full
        // check even if an earlier waiter has not consumed this result yet.
        drop(active);
        *self
            .flight
            .result
            .lock()
            .map_err(|_| invalid("toolchain verification result is poisoned"))? =
            Some(result.as_ref().copied().map_err(VerificationFailure::of));
        self.finished = true;
        self.flight.changed.notify_all();
        Ok(())
    }
}

impl Drop for VerificationOwner<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut active = self
            .dataset
            .verification
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active
            .as_ref()
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            active.take();
        }
        drop(active);
        *self
            .flight
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Err(VerificationFailure {
            kind: io::ErrorKind::Interrupted,
            message: "toolchain verification owner abandoned its check".into(),
        }));
        self.flight.changed.notify_all();
    }
}

impl Dataset {
    fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        self.verify_with(stopped, || self.toolchain.verify(stopped))
    }

    fn verify_with(
        &self,
        stopped: &impl Fn() -> bool,
        verify: impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        loop {
            self.toolchain.verify_retained_generation(stopped)?;
            let (flight, leader) = {
                let mut active = self
                    .verification
                    .lock()
                    .map_err(|_| invalid("toolchain verification ownership is poisoned"))?;
                if let Some(flight) = active.as_ref() {
                    (Arc::clone(flight), false)
                } else {
                    let flight = Arc::new(VerificationFlight::default());
                    *active = Some(Arc::clone(&flight));
                    (flight, true)
                }
            };
            if leader {
                let mut owner = VerificationOwner {
                    dataset: self,
                    flight,
                    finished: false,
                };
                let result = verify();
                owner.finish(&result)?;
                result?;
            } else {
                match flight.wait(stopped)? {
                    Ok(()) => {}
                    // The original caller's cancellation does not cancel an
                    // independent request. A live waiter elects a fresh owner;
                    // no incomplete byte scan can become a successful check.
                    Err(error) if error.kind == io::ErrorKind::Interrupted => {
                        checkpoint(stopped)?;
                        continue;
                    }
                    Err(error) => return Err(error.into_error()),
                }
            }
            return self.toolchain.verify_retained_generation(stopped);
        }
    }

    fn retained(
        pool: &Arc<PoolDirectory>,
        expected: &ToolchainIdentity,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Option<Arc<Self>>> {
        let Some(cache) = &pool.1 else {
            return Ok(None);
        };
        Ok(cache.load(expected, stopped)?.map(|toolchain| {
            Arc::new(Self {
                toolchain,
                _directory: None,
                pool: Arc::clone(pool),
                verification: Mutex::new(None),
            })
        }))
    }

    fn capture(
        pool: &Arc<PoolDirectory>,
        source: &Path,
        expected: Option<&ToolchainIdentity>,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Arc<Self>> {
        checkpoint(stopped)?;
        if let (Some(cache), Some(expected)) = (&pool.1, expected)
            && let Some(toolchain) = cache.capture(source, expected, stopped)?
        {
            return Ok(Arc::new(Self {
                toolchain,
                _directory: None,
                pool: Arc::clone(pool),
                verification: Mutex::new(None),
            }));
        }
        let directory = private_directory(Some(pool.0.path()))?;
        let mut limits = ToolchainLimits::default();
        if let Some(expected) = expected {
            // A peer's understated byte count must not reserve a tiny slot and
            // then fill it with a much larger, ultimately mismatching dataset.
            // Inventory enforces this bound before copying any source bytes.
            limits.max_bytes = limits.max_bytes.min(expected.bytes);
        }
        let toolchain = capture_toolchain(
            source,
            &directory.path().join("dataset"),
            expected,
            &limits,
            stopped,
        )?;
        checkpoint(stopped)?;
        Ok(Arc::new(Self {
            toolchain,
            _directory: Some(directory),
            pool: Arc::clone(pool),
            verification: Mutex::new(None),
        }))
    }

    fn adopt(
        pool: &Arc<PoolDirectory>,
        upload: SealedToolchain,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<(Arc<Self>, &'static str)> {
        checkpoint(stopped)?;
        if let Some(cache) = &pool.1
            && let Some(toolchain) = cache.capture_prepared(upload.prepared(), stopped)?
        {
            // Durable storage still requires its own bounded reservation,
            // synchronous publication and reopen at the final stable name.
            // Keep the upload owner alive throughout that existing capture.
            return Ok((
                Arc::new(Self {
                    toolchain,
                    _directory: None,
                    pool: Arc::clone(pool),
                    verification: Mutex::new(None),
                }),
                "captured",
            ));
        }
        // Capacity or writer contention can decline durable retention. The
        // sealed upload already owns independent bytes: retain that image rather
        // than copying the complete SDK into another temporary tree. Errors from
        // durable verification/publication still propagate and never select this
        // fallback.
        let (toolchain, directory) = upload.into_parts();
        let dataset = Arc::new(Self {
            toolchain,
            _directory: Some(directory),
            pool: Arc::clone(pool),
            verification: Mutex::new(None),
        });
        // Sealing is not an execution acquisition. Recheck the exact retained
        // generation and all bytes, without creating a second private tree.
        dataset.verify(stopped)?;
        checkpoint(stopped)?;
        Ok((dataset, "adopted"))
    }
}

/// Scope-owned execution input; nothing can evict its backing while it is used.
pub(crate) struct ToolchainLease {
    dataset: Arc<Dataset>,
    disposition: &'static str,
}
impl ToolchainLease {
    pub(crate) fn root(&self) -> &Path {
        self.dataset.toolchain.root()
    }
    pub(crate) fn identity(&self) -> &ToolchainIdentity {
        self.dataset.toolchain.identity()
    }
    pub(crate) fn entry_count(&self) -> io::Result<usize> {
        self.dataset
            .toolchain
            .entries()
            .map(|entries| entries.len())
    }
    pub(crate) fn disposition(&self) -> &'static str {
        self.disposition
    }
    pub(crate) fn verify(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        self.dataset.verify(&stopped)
    }

    /// Read-only at its canonical name is insufficient when another writable
    /// bind exposes the same tree. Check the FINAL spec, after source/Cargo-home
    /// selection, without changing it. Protect all temporary AND persistent
    /// cache storage, even when this particular lease is a private overflow copy.
    /// Host processes with our credentials remain outside this boundary; the
    /// existing inode/mutation verification still applies.
    pub(crate) fn validate_namespace(&self, spec: &CanonicalNamespaceSpec) -> io::Result<()> {
        let visible = Path::new(rabs_sandbox::layout::TOOLCHAIN);
        self.validate_namespace_at(spec, visible)
    }

    /// The distinct dependency context validates original aliases without
    /// widening the canonical namespace's fixed toolchain root.
    pub(super) fn validate_dependency_namespace(
        &self,
        spec: &CanonicalNamespaceSpec,
        context: &rabs_sandbox::dependency_context::DependencyExecContext,
    ) -> io::Result<()> {
        self.validate_namespace_at(spec, Path::new(context.toolchain_root()))
    }

    fn validate_namespace_at(
        &self,
        spec: &CanonicalNamespaceSpec,
        visible: &Path,
    ) -> io::Result<()> {
        let root = std::fs::canonicalize(self.root())?;
        let pool = std::fs::canonicalize(self.dataset.pool.0.path())?;
        let durable = self
            .dataset
            .pool
            .1
            .as_ref()
            .map(|cache| std::fs::canonicalize(cache.root()))
            .transpose()?;
        let protected: Vec<_> = [&pool, &root].into_iter().chain(durable.as_ref()).collect();
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
        if owned != 1 {
            return Err(invalid(
                "execution requires one retained read-only toolchain mount",
            ));
        }
        for bind in &spec.rw_binds {
            if overlap(&bind.visible, visible) {
                return Err(invalid("writable mount shadows the retained toolchain"));
            }
            let backing = std::fs::canonicalize(&bind.backing)?;
            if protected.iter().any(|root| overlap(&backing, root)) {
                return Err(invalid("writable mount exposes retained toolchain storage"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let candidate = std::fs::metadata(&backing)?;
                for root in &protected {
                    let metadata = std::fs::metadata(root)?;
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
    Ready { dataset: Arc<Dataset>, touched: u64 },
}
#[derive(Default)]
struct State {
    entries: BTreeMap<Key, Slot>,
    reserved_bytes: u64,
    clock: u64,
}
pub(crate) struct ToolchainPool {
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
        if self.armed
            && let Ok(mut state) = self.pool.state.lock()
            && matches!(state.entries.get(&self.key), Some(Slot::Capturing))
        {
            state.entries.remove(&self.key);
            state.reserved_bytes -= self.key.2;
        }
        self.pool.changed.notify_all();
    }
}

impl ToolchainPool {
    pub(crate) fn new(max_bytes: u64, max_entries: usize) -> io::Result<Self> {
        Self::with_directory(max_bytes, max_entries, None)
    }

    pub(crate) fn with_directory(
        max_bytes: u64,
        max_entries: usize,
        directory: Option<&Path>,
    ) -> io::Result<Self> {
        if max_bytes > MAX_POOL_BYTES || max_entries == 0 || max_entries > MAX_POOL_ENTRIES {
            return Err(invalid("toolchain pool limits outside their bounds"));
        }
        let durable = directory
            .map(|root| durable::DurableCache::open(root, max_bytes, max_entries))
            .transpose()?
            .map(Arc::new);
        Ok(Self {
            directory: Arc::new(PoolDirectory(private_directory(None)?, durable)),
            max_bytes,
            max_entries,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        })
    }
    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| invalid("toolchain pool ownership is poisoned"))
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
    /// Lookup may reopen a published durable tree, but never creates a capture
    /// or waits for one. A bounded memory reservation lets a verified reopen
    /// become a shared ready owner; misses and failures release that reservation.
    /// Hashing stays off the control reactor and outside the admission lock.
    /// In-progress captures and partial disk trees miss. Lookup never evicts an
    /// existing owner: a full pool can still return a verified unpooled disk hit.
    pub(crate) fn lookup(
        &self,
        expected: &ToolchainIdentity,
        stopped: impl Fn() -> bool,
    ) -> io::Result<Option<ToolchainLease>> {
        checkpoint(&stopped)?;
        if self.max_bytes == 0 || expected.bytes > self.max_bytes {
            return Ok(None);
        }
        let identity = key(expected);
        let mut reservation = None;
        let dataset = {
            let mut state = self.lock()?;
            state.clock = state.clock.saturating_add(1);
            let touched = state.clock;
            match state.entries.get_mut(&identity) {
                Some(Slot::Ready {
                    dataset,
                    touched: last,
                }) => {
                    *last = touched;
                    Some(Arc::clone(dataset))
                }
                Some(Slot::Capturing) => return Ok(None),
                None => {
                    // Reserve only spare memory capacity. A speculative disk
                    // miss must not evict a useful ready entry or create a new
                    // dataset. Concurrent acquisitions can join this same
                    // reservation; concurrent lookups remain nonblocking.
                    if self.directory.1.is_some()
                        && state.entries.len() < self.max_entries
                        && state.reserved_bytes <= self.max_bytes - expected.bytes
                    {
                        state.entries.insert(identity, Slot::Capturing);
                        state.reserved_bytes += expected.bytes;
                        reservation = Some(Reservation {
                            pool: self,
                            key: identity,
                            armed: true,
                        });
                    }
                    None
                }
            }
        };
        let dataset = match dataset {
            Some(dataset) => dataset,
            None => match Dataset::retained(&self.directory, expected, &stopped)? {
                Some(dataset) => {
                    checkpoint(&stopped)?;
                    if let Some(reservation) = &mut reservation {
                        let mut state = self.lock()?;
                        if !matches!(state.entries.get(&identity), Some(Slot::Capturing)) {
                            return Err(invalid("toolchain reopen lost its reservation"));
                        }
                        state.clock = state.clock.saturating_add(1);
                        let touched = state.clock;
                        state.entries.insert(
                            identity,
                            Slot::Ready {
                                dataset: Arc::clone(&dataset),
                                touched,
                            },
                        );
                        reservation.armed = false;
                        drop(state);
                        self.changed.notify_all();
                    }
                    // Cancellation may arrive while publication waits for the
                    // admission mutex. Keep the verified ready owner reusable,
                    // but do not return a lease to that cancelled caller.
                    checkpoint(&stopped)?;
                    return Ok(Some(ToolchainLease {
                        dataset,
                        disposition: "reused",
                    }));
                }
                None => return Ok(None),
            },
        };
        // Keep the dataset pinned during verification, outside the admission
        // mutex. A filename or matching identity record is never a cache hit.
        if let Err(error) = dataset.verify(&stopped) {
            if !stopped() {
                self.discard_failed(identity, &dataset)?;
            }
            return Err(error);
        }
        checkpoint(&stopped)?;
        Ok(Some(ToolchainLease {
            dataset,
            disposition: "reused",
        }))
    }

    pub(crate) fn acquire(
        &self,
        source: &Path,
        expected: Option<&ToolchainIdentity>,
        stopped: impl Fn() -> bool,
    ) -> io::Result<ToolchainLease> {
        self.acquire_with(expected, &stopped, || {
            Dataset::capture(&self.directory, source, expected, &stopped)
                .map(|dataset| (dataset, "captured"))
        })
    }

    pub(crate) fn adopt(
        &self,
        upload: SealedToolchain,
        stopped: impl Fn() -> bool,
    ) -> io::Result<ToolchainLease> {
        let expected = *upload.identity();
        self.acquire_with(Some(&expected), &stopped, || {
            Dataset::adopt(&self.directory, upload, &stopped)
        })
    }

    /// Captures and owned uploads share admission, quota and cancellation. The
    /// producer runs at most once, outside the pool lock, and is dropped outside
    /// that lock when an already retained same-identity dataset wins instead.
    fn acquire_with(
        &self,
        expected: Option<&ToolchainIdentity>,
        stopped: &impl Fn() -> bool,
        produce: impl FnOnce() -> io::Result<(Arc<Dataset>, &'static str)>,
    ) -> io::Result<ToolchainLease> {
        checkpoint(stopped)?;
        let Some(expected) =
            expected.filter(|expected| self.max_bytes != 0 && expected.bytes <= self.max_bytes)
        else {
            return produce().map(|(dataset, _)| ToolchainLease {
                dataset,
                disposition: "private",
            });
        };
        let identity = key(expected);
        loop {
            checkpoint(stopped)?;
            let mut state = self.lock()?;
            state.clock = state.clock.saturating_add(1);
            let touched = state.clock;
            match state.entries.get_mut(&identity) {
                Some(Slot::Ready {
                    dataset,
                    touched: last,
                }) => {
                    *last = touched;
                    let dataset = Arc::clone(dataset);
                    drop(state);
                    // Never consult the mutable original installation on a hit:
                    // the request selected these exact bytes, not that pathname.
                    if let Err(error) = dataset.verify(stopped) {
                        if !stopped() {
                            self.discard_failed(identity, &dataset)?;
                        }
                        return Err(error);
                    }
                    return Ok(ToolchainLease {
                        dataset,
                        disposition: "reused",
                    });
                }
                Some(Slot::Capturing) => {
                    let (state, _) = self
                        .changed
                        .wait_timeout(state, WAIT_SLICE)
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
                let victim = state
                    .entries
                    .iter()
                    .filter_map(|(key, slot)| match slot {
                        Slot::Ready { dataset, touched } if Arc::strong_count(dataset) == 1 => {
                            Some((*key, *touched))
                        }
                        _ => None,
                    })
                    .min_by_key(|(key, touched)| (*touched, *key))
                    .map(|(key, _)| key);
                let Some(victim) = victim else {
                    drop(state);
                    drop(retired);
                    return produce().map(|(dataset, _)| ToolchainLease {
                        dataset,
                        disposition: "private",
                    });
                };
                if let Some(Slot::Ready { dataset, .. }) = state.entries.remove(&victim) {
                    state.reserved_bytes -= victim.2;
                    retired.push(dataset);
                }
            }
            state.entries.insert(identity, Slot::Capturing);
            state.reserved_bytes += expected.bytes;
            let mut reservation = Reservation {
                pool: self,
                key: identity,
                armed: true,
            };
            drop(state);
            // Potentially slow filesystem cleanup and capture never hold the
            // admission mutex or block hits for another retained identity.
            drop(retired);
            let (dataset, disposition) = produce()?;
            checkpoint(stopped)?;
            let mut state = self.lock()?;
            if !matches!(state.entries.get(&identity), Some(Slot::Capturing)) {
                return Err(invalid("toolchain capture lost its reservation"));
            }
            state.clock = state.clock.saturating_add(1);
            let touched = state.clock;
            state.entries.insert(
                identity,
                Slot::Ready {
                    dataset: Arc::clone(&dataset),
                    touched,
                },
            );
            reservation.armed = false;
            drop(state);
            self.changed.notify_all();
            return Ok(ToolchainLease {
                dataset,
                disposition,
            });
        }
    }
}

fn configured_bytes(value: Option<&str>) -> io::Result<u64> {
    let Some(value) = value else {
        return Ok(0);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(
            "RABS_WORKER_TOOLCHAIN_CACHE_BYTES must be an unsigned decimal byte count",
        ));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|bytes| *bytes <= MAX_POOL_BYTES)
        .ok_or_else(|| invalid("RABS_WORKER_TOOLCHAIN_CACHE_BYTES exceeds the 64 GiB bound"))
}

/// The worker supervisor retains this scope across reconnects and drops it only
/// after session-owned execution has drained. Private datasets then disappear;
/// explicitly configured durable datasets remain for verified restart reuse.
/// Outstanding library leases retain their backing and the durable cache lock.
/// No global strong reference or detached janitor extends this lifetime.
#[must_use = "retain the toolchain scope through worker shutdown"]
pub struct ToolchainReuseScope {
    pool: Arc<ToolchainPool>,
}

impl ToolchainReuseScope {
    /// Read worker-local configuration once, before starting its session loop.
    /// Zero/absence disables retained reuse. No request JSON can change limits.
    /// CACHE_DIR is an optional private persistent store, requiring a nonzero
    /// CACHE_BYTES budget; invalid or already-owned stores refuse worker startup.
    pub fn from_environment() -> io::Result<Self> {
        let value = std::env::var_os(CONFIG_NAME);
        let text = value
            .as_ref()
            .map(|value| {
                value
                    .to_str()
                    .ok_or_else(|| invalid("RABS_WORKER_TOOLCHAIN_CACHE_BYTES is not UTF-8"))
            })
            .transpose()?;
        let max_bytes = configured_bytes(text)?;
        let directory = std::env::var_os(durable::CONFIG_DIRECTORY).map(std::path::PathBuf::from);
        let mut registry = ACTIVE_POOL
            .lock()
            .map_err(|_| invalid("toolchain pool registry is poisoned"))?;
        if registry.upgrade().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "one worker supervisor already owns the toolchain pool",
            ));
        }
        let pool = Arc::new(ToolchainPool::with_directory(
            max_bytes,
            MAX_POOL_ENTRIES,
            directory.as_deref(),
        )?);
        *registry = Arc::downgrade(&pool);
        Ok(Self { pool })
    }
}

impl Drop for ToolchainReuseScope {
    fn drop(&mut self) {
        // Poison recovery is cleanup-only, never authorization to use entries.
        let mut registry = ACTIVE_POOL
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if registry
            .upgrade()
            .is_some_and(|pool| Arc::ptr_eq(&pool, &self.pool))
        {
            *registry = Weak::new();
        }
    }
}

/// Embedded callers without a worker scope retain the original private-capture
/// behavior. A registered pool error fails; it never selects an unpinned lane.
pub(crate) fn prepare(
    source: &Path,
    expected: Option<&ToolchainIdentity>,
    stopped: impl Fn() -> bool,
) -> io::Result<ToolchainLease> {
    checkpoint(&stopped)?;
    let pool = ACTIVE_POOL
        .lock()
        .map_err(|_| invalid("toolchain pool registry is poisoned"))?
        .upgrade();
    match pool {
        Some(pool) => pool.acquire(source, expected, stopped),
        None => ToolchainPool::new(0, MAX_POOL_ENTRIES)?.acquire(source, expected, stopped),
    }
}

/// Consume an admitted upload's actual private owner. No registry or configured
/// retention still permits private execution, without recapturing owned bytes.
pub(crate) fn adopt(
    upload: SealedToolchain,
    stopped: impl Fn() -> bool,
) -> io::Result<ToolchainLease> {
    checkpoint(&stopped)?;
    let pool = ACTIVE_POOL
        .lock()
        .map_err(|_| invalid("toolchain pool registry is poisoned"))?
        .upgrade();
    match pool {
        Some(pool) => pool.adopt(upload, stopped),
        None => ToolchainPool::new(0, MAX_POOL_ENTRIES)?.adopt(upload, stopped),
    }
}

/// Reuse only an already retained, verified dataset from the active supervisor.
/// An absent scope or disabled pool never creates a private directory on lookup.
pub(crate) fn lookup(
    expected: &ToolchainIdentity,
    stopped: impl Fn() -> bool,
) -> io::Result<Option<ToolchainLease>> {
    checkpoint(&stopped)?;
    let pool = ACTIVE_POOL
        .lock()
        .map_err(|_| invalid("toolchain pool registry is poisoned"))?
        .upgrade();
    match pool {
        Some(pool) => pool.lookup(expected, stopped),
        None => Ok(None),
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
        assert_eq!(
            configured_bytes(Some(&MAX_POOL_BYTES.to_string())).unwrap(),
            MAX_POOL_BYTES
        );
        for invalid in [
            "",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1GiB",
            "18446744073709551616",
            "68719476737",
        ] {
            assert!(configured_bytes(Some(invalid)).is_err(), "{invalid}");
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use rabs_sandbox::toolchain_dataset::fingerprint_toolchain;
        use std::fs::{self, File};
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::mpsc;
        use std::thread;
        use std::time::Instant;

        fn source(bytes: &[u8]) -> (tempfile::TempDir, ToolchainIdentity) {
            let source = tempfile::tempdir().unwrap();
            fs::create_dir_all(source.path().join("bin")).unwrap();
            fs::create_dir_all(source.path().join("lib/empty")).unwrap();
            fs::write(source.path().join("bin/compiler"), bytes).unwrap();
            fs::set_permissions(
                source.path().join("bin/compiler"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            symlink("compiler", source.path().join("bin/rustc")).unwrap();
            let identity =
                fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false)
                    .unwrap();
            (source, identity)
        }
        fn pool(bytes: u64, entries: usize) -> ToolchainPool {
            ToolchainPool::new(bytes, entries).unwrap()
        }
        fn spec(lease: &ToolchainLease, writable: &Path) -> CanonicalNamespaceSpec {
            use rabs_sandbox::canonical_namespace::Bind;
            let mut spec = CanonicalNamespaceSpec::new();
            spec.ro_binds
                .push(Bind::new(lease.root(), rabs_sandbox::layout::TOOLCHAIN));
            spec.rw_binds
                .push(Bind::new(writable, rabs_sandbox::layout::WORKSPACE));
            spec
        }

        fn wait_for_verification_followers(dataset: &Dataset, followers: usize) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                // The active slot and leader each retain one flight reference.
                // Extra references establish that followers joined THIS flight,
                // not merely that their threads have started running.
                if dataset
                    .verification
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|flight| Arc::strong_count(flight) >= followers + 2)
                {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "verification followers did not join"
                );
                thread::yield_now();
            }
        }

        #[test]
        fn overlapping_verifications_share_one_full_scan_but_later_checks_rehash() {
            let (source, identity) = source(b"compiler\0\xff");
            let pool = pool(1024, 2);
            let lease = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            let scans = Arc::new(AtomicUsize::new(0));
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let dataset = Arc::clone(&lease.dataset);
            let leader_scans = Arc::clone(&scans);
            let leader = thread::spawn(move || {
                dataset.verify_with(&|| false, || {
                    leader_scans.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    dataset.toolchain.verify(|| false)
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let followers: Vec<_> = (0..2)
                .map(|_| {
                    let dataset = Arc::clone(&lease.dataset);
                    let scans = Arc::clone(&scans);
                    thread::spawn(move || {
                        let deadline = Instant::now() + Duration::from_secs(5);
                        dataset.verify_with(&|| Instant::now() >= deadline, || {
                            scans.fetch_add(1, Ordering::SeqCst);
                            dataset.toolchain.verify(|| Instant::now() >= deadline)
                        })
                    })
                })
                .collect();
            wait_for_verification_followers(&lease.dataset, followers.len());
            release_tx.send(()).unwrap();
            leader.join().unwrap().unwrap();
            for follower in followers {
                follower.join().unwrap().unwrap();
            }
            assert_eq!(scans.load(Ordering::SeqCst), 1);
            assert!(lease.dataset.verification.lock().unwrap().is_none());
            lease
                .dataset
                .verify_with(&|| false, || {
                    scans.fetch_add(1, Ordering::SeqCst);
                    lease.dataset.toolchain.verify(|| false)
                })
                .unwrap();
            assert_eq!(scans.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn equal_identities_in_distinct_dataset_owners_do_not_share_verification() {
            let (source, identity) = source(b"compiler");
            let pool = pool(0, 2);
            let first = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            let second = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            assert_eq!(first.identity(), second.identity());
            assert_ne!(first.root(), second.root());
            let scans = Arc::new(AtomicUsize::new(0));
            let (entered_tx, entered_rx) = mpsc::sync_channel(2);
            let mut releases = Vec::new();
            let mut threads = Vec::new();
            for dataset in [&first.dataset, &second.dataset] {
                let dataset = Arc::clone(dataset);
                let scans = Arc::clone(&scans);
                let entered_tx = entered_tx.clone();
                let (release_tx, release_rx) = mpsc::sync_channel(1);
                releases.push(release_tx);
                threads.push(thread::spawn(move || {
                    dataset.verify_with(&|| false, || {
                        scans.fetch_add(1, Ordering::SeqCst);
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        dataset.toolchain.verify(|| false)
                    })
                }));
            }
            for _ in 0..2 {
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            for release in releases {
                release.send(()).unwrap();
            }
            for thread in threads {
                thread.join().unwrap().unwrap();
            }
            assert_eq!(scans.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn cancelled_verification_follower_does_not_cancel_the_leader_or_retire_storage() {
            let (source, identity) = source(b"compiler");
            let pool = Arc::new(pool(1024, 2));
            let lease = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let dataset = Arc::clone(&lease.dataset);
            let leader = thread::spawn(move || {
                dataset.verify_with(&|| false, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    dataset.toolchain.verify(|| false)
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let cancelled = Arc::new(AtomicBool::new(false));
            let follower_cancelled = Arc::clone(&cancelled);
            let follower_pool = Arc::clone(&pool);
            let follower = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                follower_pool.lookup(&identity, || {
                    follower_cancelled.load(Ordering::Acquire) || Instant::now() >= deadline
                })
            });
            wait_for_verification_followers(&lease.dataset, 1);
            cancelled.store(true, Ordering::Release);
            let error = follower.join().unwrap().err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(lease.dataset.verification.lock().unwrap().is_some());
            assert_eq!(pool.lock().unwrap().entries.len(), 1);
            assert_eq!(pool.lock().unwrap().reserved_bytes, identity.bytes);
            assert!(lease.root().is_dir());
            release_tx.send(()).unwrap();
            leader.join().unwrap().unwrap();
            lease.verify(|| false).unwrap();
        }

        #[test]
        fn cancelled_or_panicking_verification_leader_allows_a_live_follower_to_retry() {
            for panics in [false, true] {
                let (source, identity) = source(b"compiler");
                let pool = pool(1024, 2);
                let lease = pool
                    .acquire(source.path(), Some(&identity), || false)
                    .unwrap();
                let scans = Arc::new(AtomicUsize::new(0));
                let cancelled = Arc::new(AtomicBool::new(false));
                let (entered_tx, entered_rx) = mpsc::sync_channel(1);
                let (release_tx, release_rx) = mpsc::sync_channel(1);
                let dataset = Arc::clone(&lease.dataset);
                let leader_scans = Arc::clone(&scans);
                let leader_cancelled = Arc::clone(&cancelled);
                let leader = thread::spawn(move || {
                    let stopped = || leader_cancelled.load(Ordering::Acquire);
                    dataset.verify_with(&stopped, || {
                        leader_scans.fetch_add(1, Ordering::SeqCst);
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        assert!(!panics, "injected verification-owner unwind");
                        dataset.toolchain.verify(stopped)
                    })
                });
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let dataset = Arc::clone(&lease.dataset);
                let follower_scans = Arc::clone(&scans);
                let follower = thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let stopped = || Instant::now() >= deadline;
                    dataset.verify_with(&stopped, || {
                        follower_scans.fetch_add(1, Ordering::SeqCst);
                        dataset.toolchain.verify(stopped)
                    })
                });
                wait_for_verification_followers(&lease.dataset, 1);
                if !panics {
                    cancelled.store(true, Ordering::Release);
                }
                release_tx.send(()).unwrap();
                let leader = leader.join();
                if panics {
                    assert!(leader.is_err());
                } else {
                    assert_eq!(
                        leader.unwrap().unwrap_err().kind(),
                        io::ErrorKind::Interrupted
                    );
                }
                follower.join().unwrap().unwrap();
                assert_eq!(scans.load(Ordering::SeqCst), 2);
                assert!(lease.dataset.verification.lock().unwrap().is_none());
                lease.verify(|| false).unwrap();
                assert_eq!(pool.lock().unwrap().reserved_bytes, identity.bytes);
            }
        }

        #[test]
        fn mutation_during_shared_verification_is_rejected_before_or_after_the_byte_scan() {
            for after_scan in [false, true] {
                let (source, identity) = source(b"compiler");
                let pool = pool(1024, 2);
                let lease = pool
                    .acquire(source.path(), Some(&identity), || false)
                    .unwrap();
                let scans = Arc::new(AtomicUsize::new(0));
                let (entered_tx, entered_rx) = mpsc::sync_channel(1);
                let (release_tx, release_rx) = mpsc::sync_channel(1);
                let dataset = Arc::clone(&lease.dataset);
                let leader_scans = Arc::clone(&scans);
                let leader = thread::spawn(move || {
                    dataset.verify_with(&|| false, || {
                        leader_scans.fetch_add(1, Ordering::SeqCst);
                        if after_scan {
                            dataset.toolchain.verify(|| false)?;
                        }
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        if after_scan {
                            Ok(())
                        } else {
                            dataset.toolchain.verify(|| false)
                        }
                    })
                });
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let dataset = Arc::clone(&lease.dataset);
                let follower_scans = Arc::clone(&scans);
                let follower = thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    dataset.verify_with(&|| Instant::now() >= deadline, || {
                        follower_scans.fetch_add(1, Ordering::SeqCst);
                        dataset.toolchain.verify(|| Instant::now() >= deadline)
                    })
                });
                wait_for_verification_followers(&lease.dataset, 1);
                let path = lease.root().join("bin/compiler");
                let modified = fs::metadata(&path).unwrap().modified().unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                fs::write(&path, b"tampered").unwrap();
                File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(modified)
                    .unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
                release_tx.send(()).unwrap();
                for result in [leader.join().unwrap(), follower.join().unwrap()] {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                }
                assert_eq!(scans.load(Ordering::SeqCst), 1);
                assert!(pool.lookup(&identity, || false).is_err());
                assert!(pool.lock().unwrap().entries.is_empty());
                assert_eq!(
                    fs::read(source.path().join("bin/compiler")).unwrap(),
                    b"compiler"
                );
            }
        }

        #[test]
        fn retained_generation_mutations_refuse_lease_lookup_and_acquisition() {
            for operation in 0..3 {
                for fault in 0..5 {
                    let (source, identity) = source(b"compiler");
                    let pool = pool(1024, 2);
                    let lease = pool
                        .acquire(source.path(), Some(&identity), || false)
                        .unwrap();
                    let root = lease.root();
                    let file = root.join("bin/compiler");
                    match fault {
                        0 => {
                            let modified = fs::metadata(&file).unwrap().modified().unwrap();
                            fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
                            fs::write(&file, b"tampered").unwrap();
                            File::options()
                                .write(true)
                                .open(&file)
                                .unwrap()
                                .set_modified(modified)
                                .unwrap();
                            fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
                        }
                        1 => {
                            fs::rename(&file, root.parent().unwrap().join("original-compiler"))
                                .unwrap();
                            fs::write(&file, b"compiler").unwrap();
                            fs::set_permissions(&file, fs::Permissions::from_mode(0o555)).unwrap();
                        }
                        2 => {
                            fs::rename(
                                root.join("bin/rustc"),
                                root.parent().unwrap().join("original-alias"),
                            )
                            .unwrap();
                            symlink("compiler", root.join("bin/rustc")).unwrap();
                        }
                        3 => fs::create_dir(root.join("added-member")).unwrap(),
                        _ => {
                            fs::rename(root, root.parent().unwrap().join("original-dataset"))
                                .unwrap();
                            fs::create_dir(root).unwrap();
                        }
                    }
                    let result = match operation {
                        0 => lease.verify(|| false),
                        1 => pool.lookup(&identity, || false).map(|_| ()),
                        _ => pool
                            .acquire(Path::new("/absent"), Some(&identity), || false)
                            .map(|_| ()),
                    };
                    assert!(result.is_err(), "operation {operation}, fault {fault}");
                    assert_eq!(
                        fs::read(source.path().join("bin/compiler")).unwrap(),
                        b"compiler"
                    );
                }
            }
        }

        #[test]
        fn lookup_misses_do_not_create_captures_reservations_or_waiters() {
            let (_source, identity) = source(b"compiler");
            for budget in [0, identity.bytes - 1, 1024] {
                let pool = pool(budget, 2);
                assert!(pool.lookup(&identity, || false).unwrap().is_none());
                assert!(pool.lock().unwrap().entries.is_empty());
                assert_eq!(pool.lock().unwrap().reserved_bytes, 0);
                assert_eq!(fs::read_dir(pool.directory.0.path()).unwrap().count(), 0);
            }
        }

        #[test]
        fn lookup_uses_full_identity_and_retains_verified_bytes_without_a_source_path() {
            let (source, identity) = source(b"compiler\0\xff");
            let pool = pool(1024, 2);
            let first = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            let root = first.root().to_path_buf();
            fs::rename(source.path().join("bin"), source.path().join("unavailable")).unwrap();
            for foreign in [
                ToolchainIdentity {
                    sha256: [0; 32],
                    ..identity
                },
                ToolchainIdentity {
                    files: identity.files + 1,
                    ..identity
                },
                ToolchainIdentity {
                    bytes: identity.bytes + 1,
                    ..identity
                },
            ] {
                assert!(pool.lookup(&foreign, || false).unwrap().is_none());
            }
            let lease = pool.lookup(&identity, || false).unwrap().unwrap();
            assert_eq!(lease.disposition(), "reused");
            assert_eq!(lease.root(), root);
            assert_eq!(lease.entry_count().unwrap(), 6);
            drop(first);
            drop(pool);
            assert_eq!(
                fs::read(root.join("bin/compiler")).unwrap(),
                b"compiler\0\xff"
            );
            lease.verify(|| false).unwrap();
            drop(lease);
            assert!(!root.exists());
        }

        #[test]
        fn lookup_cancellation_returns_no_lease_without_retiring_valid_storage() {
            use std::sync::atomic::AtomicUsize;
            let (source, identity) = source(b"compiler");
            let pool = pool(1024, 2);
            let first = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            let checkpoints = AtomicUsize::new(0);
            let error = pool
                .lookup(&identity, || {
                    checkpoints.fetch_add(1, Ordering::SeqCst) != 0
                })
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(pool.lock().unwrap().reserved_bytes, identity.bytes);
            assert_eq!(pool.lock().unwrap().entries.len(), 1);
            let next = pool.lookup(&identity, || false).unwrap().unwrap();
            assert_eq!(next.root(), first.root());
        }

        #[test]
        fn pinned_reuse_keeps_inodes_and_bytes_after_original_installation_disappears() {
            let (source, identity) = source(b"compiler\0\xff");
            let pool = pool(1024, 2);
            let first = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            assert_eq!(first.disposition(), "captured");
            let inode = fs::metadata(first.root().join("bin/compiler"))
                .unwrap()
                .ino();
            assert_ne!(
                inode,
                fs::metadata(source.path().join("bin/compiler"))
                    .unwrap()
                    .ino()
            );
            let missing = source.path().join("not-an-installation");
            let second = pool.acquire(&missing, Some(&identity), || false).unwrap();
            assert_eq!(second.disposition(), "reused");
            assert_eq!(second.root(), first.root());
            assert_eq!(
                fs::metadata(second.root().join("bin/compiler"))
                    .unwrap()
                    .ino(),
                inode
            );
            assert_eq!(
                fs::read(second.root().join("bin/compiler")).unwrap(),
                b"compiler\0\xff"
            );
            assert_eq!(
                fs::read_link(second.root().join("bin/rustc")).unwrap(),
                Path::new("compiler")
            );
            assert!(second.root().join("lib/empty").is_dir());
            assert_eq!(pool.lock().unwrap().reserved_bytes, identity.bytes);
            let retained = second.root().to_path_buf();
            drop(first);
            drop(pool);
            assert!(
                retained.is_dir(),
                "a live lease owns its parent even after pool shutdown"
            );
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
            let first = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            let mut changed = identity;
            changed.files += 1;
            assert!(
                pool.acquire(source.path(), Some(&changed), || false)
                    .is_err()
            );
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
                drop(pool.lookup(&b_id, || false).unwrap().unwrap());
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
            assert!(
                pool.acquire(&source.path().join("missing"), Some(&identity), || false)
                    .is_err()
            );
            assert!(pool.lock().unwrap().entries.is_empty());
            let understated = ToolchainIdentity {
                bytes: identity.bytes - 1,
                ..identity
            };
            let error = pool
                .acquire(source.path(), Some(&understated), || false)
                .err()
                .unwrap();
            assert!(error.to_string().contains("byte limit exceeded"));
            assert!(pool.lock().unwrap().entries.is_empty());
            assert_eq!(fs::read_dir(pool.directory.0.path()).unwrap().count(), 0);
            let cancelled = AtomicBool::new(false);
            let error = pool
                .acquire(source.path(), Some(&identity), || {
                    // Stop only after the admission transaction has reserved space.
                    if pool.lock().unwrap().entries.contains_key(&key(&identity)) {
                        cancelled.store(true, Ordering::Release);
                    }
                    cancelled.load(Ordering::Acquire)
                })
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(pool.lock().unwrap().entries.is_empty());
            assert_eq!(pool.lock().unwrap().reserved_bytes, 0);
            assert_eq!(
                pool.acquire(source.path(), Some(&identity), || false)
                    .unwrap()
                    .disposition(),
                "captured"
            );
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
                        leader_pool
                            .lock()
                            .unwrap()
                            .entries
                            .contains_key(&key(&identity))
                    };
                    if reserved && !paused.swap(true, Ordering::AcqRel) {
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    false
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            // Negotiated reuse does not wait for the real concurrent capture.
            assert!(pool.lookup(&identity, || false).unwrap().is_none());
            assert!(matches!(
                pool.lock().unwrap().entries.get(&key(&identity)),
                Some(Slot::Capturing)
            ));
            assert_eq!(pool.lock().unwrap().reserved_bytes, identity.bytes);
            let until = Instant::now() + Duration::from_millis(60);
            let error = pool
                .acquire(Path::new("/absent"), Some(&identity), || {
                    Instant::now() >= until
                })
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(matches!(
                pool.lock().unwrap().entries.get(&key(&identity)),
                Some(Slot::Capturing)
            ));
            let follower_pool = Arc::clone(&pool);
            let follower = thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(5);
                follower_pool.acquire(Path::new("/absent"), Some(&identity), || {
                    Instant::now() >= until
                })
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
            let lease = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            let path = lease.root().join("bin/compiler");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&path, b"tampered").unwrap();
            assert!(pool.lookup(&identity, || false).is_err());
            assert!(lease.verify(|| false).is_err());
            assert!(pool.lock().unwrap().entries.is_empty());
            let replacement = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            assert_ne!(lease.root(), replacement.root());
            assert_eq!(
                fs::read(replacement.root().join("bin/compiler")).unwrap(),
                b"compiler"
            );
            pool.discard_failed(key(&identity), &lease.dataset).unwrap();
            assert_eq!(
                pool.lock().unwrap().entries.len(),
                1,
                "late failure cannot retire a replacement"
            );
        }

        #[test]
        fn final_namespace_cannot_expose_any_pool_storage_through_writable_mounts() {
            use rabs_sandbox::canonical_namespace::Bind;
            let (source, identity) = source(b"compiler");
            let pool = pool(1024, 2);
            let lease = pool
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
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
                    2 => bad
                        .rw_binds
                        .push(Bind::new(writable.path(), "/__rabs/toolchain/bin")),
                    3 => bad.rw_binds[0].backing = pool.directory.0.path().to_path_buf(),
                    4 => bad.rw_binds[0].backing = lease.root().join("lib"),
                    5 => bad.rw_binds[0].backing = alias.clone(),
                    _ => {
                        bad.rw_binds[0].backing =
                            pool.directory.0.path().parent().unwrap().to_path_buf()
                    }
                }
                let before = bad.clone();
                assert!(lease.validate_namespace(&bad).is_err(), "case {case}");
                assert_eq!(bad, before);
            }
        }
    }
}
