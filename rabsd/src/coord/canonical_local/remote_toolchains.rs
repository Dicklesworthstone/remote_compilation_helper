//! Process-lifetime reuse of received SDKs for the canonical remote service.
//!
//! The authenticated edge key and complete toolchain identity select a lease.
//! Every hit verifies its private owner and retained generation before and after
//! a full byte scan outside the cache lock. Overlapping checks of the exact same
//! retained owner share one active scan; completed checks are never memoized.
//! Each caller keeps its own cancellation and deadline. Source trees, diagnostics
//! and operation paths never enter the cache. This is input reuse, with no
//! action-result or publication authority.
//!
//! Already-admitted operations may also share one pending cold upload per peer
//! and complete identity. A separate bounded registry owns only weak references;
//! the admitted publisher and waiting operations own every flight. Publication
//! detaches the pending generation before handing its exact sealed lease to
//! existing waiters. Later callers use ordinary retention or start a new upload,
//! even when earlier waiters still hold a completed flight. Disabled or full
//! retention therefore cannot turn flights into an uncharged persistent cache.
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
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;

pub(crate) const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(crate) const MAX_CACHE_ENTRIES: usize = 32;
const MAX_PENDING_UPLOADS: usize = 32;
const VERIFICATION_WAIT_SLICE: Duration = Duration::from_millis(20);

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

#[derive(Debug, Clone)]
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

#[derive(Debug, Default)]
struct VerificationFlight {
    result: Mutex<Option<Result<(), VerificationFailure>>>,
    changed: Condvar,
}

impl VerificationFlight {
    fn wait(&self, stopped: &impl Fn() -> bool) -> io::Result<Result<(), VerificationFailure>> {
        loop {
            // Every waiter owns its cancellation/deadline. The callback may
            // inspect other state, so never call it while holding either lock.
            checkpoint(stopped)?;
            let result = self
                .result
                .lock()
                .map_err(|_| invalid("remote toolchain verification result is poisoned"))?;
            if let Some(result) = result.as_ref() {
                return Ok(result.clone());
            }
            let (next, _) = self
                .changed
                .wait_timeout(result, VERIFICATION_WAIT_SLICE)
                .map_err(|_| invalid("remote toolchain verification result is poisoned"))?;
            drop(next);
        }
    }
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
    // Only checks of this live owner may join. Never cache a completed result
    // or combine distinct owners merely because their content hashes match.
    verification: Mutex<Option<Arc<VerificationFlight>>>,
    owner: Arc<tempfile::TempDir>,
}

/// One caller performs a full scan on its existing session thread. Dropping
/// that caller cannot leave followers waiting on an abandoned result.
struct VerificationOwner<'a> {
    received: &'a ReceivedToolchain,
    flight: Arc<VerificationFlight>,
    finished: bool,
}

impl VerificationOwner<'_> {
    fn finish(&mut self, result: &io::Result<()>) -> io::Result<()> {
        let mut active = self
            .received
            .verification
            .lock()
            .map_err(|_| invalid("remote toolchain verification ownership is poisoned"))?;
        if active
            .as_ref()
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            active.take();
        }
        // A later acquisition must start its own scan, even if an earlier
        // follower has not yet consumed this completed result.
        drop(active);
        *self
            .flight
            .result
            .lock()
            .map_err(|_| invalid("remote toolchain verification result is poisoned"))? =
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
            .received
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
            message: "remote toolchain verification owner abandoned its check".into(),
        }));
        self.flight.changed.notify_all();
    }
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
            verification: Mutex::new(None),
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
        self.verify_with(stopped, || self.scan_bytes(stopped))
    }

    /// Only the expensive byte scan participates in the flight. Its surrounding
    /// complete generation and owner checks belong independently to each caller.
    fn scan_bytes(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        let observed = self.image.rehash_retained_bytes(stopped)?;
        if observed != *self.identity() {
            return Err(invalid("received compiler content changed"));
        }
        Ok(())
    }

    fn verify_with(
        &self,
        stopped: &impl Fn() -> bool,
        scan: impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        loop {
            self.verify(stopped)?;
            let (flight, leader) = {
                let mut active = self
                    .verification
                    .lock()
                    .map_err(|_| invalid("remote toolchain verification ownership is poisoned"))?;
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
                    received: self,
                    flight,
                    finished: false,
                };
                let result = scan();
                owner.finish(&result)?;
                result?;
            } else {
                match flight.wait(stopped)? {
                    Ok(()) => {}
                    // A cancelled or unwinding owner supplies no byte proof.
                    // A surviving caller may lead a fresh scan, within its own
                    // deadline and after checking this exact generation again.
                    Err(error) if error.kind == io::ErrorKind::Interrupted => {
                        checkpoint(stopped)?;
                        continue;
                    }
                    Err(error) => return Err(error.into_error()),
                }
            }
            return self.verify(stopped);
        }
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
            verification,
            owner,
        } = received;
        drop(image);
        drop(verification);
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
    // Only active uploads are discoverable. The registry never owns a flight
    // or completed SDK; bounded admitted operations retain those capabilities.
    pending_uploads: Vec<Weak<UploadFlight>>,
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

/// One already-admitted operation's next input phase. No receiver or source
/// tree is created until Upload or Ready; Wait owns only this bounded ticket.
pub(crate) enum ToolchainAcquisition<'a> {
    Ready(Arc<ReceivedToolchain>),
    Upload(UploadPublisher<'a>),
    Wait(UploadWaiter<'a>),
}

#[derive(Debug)]
pub(crate) enum UploadPoll {
    Pending,
    Abandoned,
    Ready(Arc<ReceivedToolchain>),
}

#[derive(Debug, Clone)]
enum UploadResult {
    Abandoned,
    Ready(Arc<ReceivedToolchain>),
}

#[derive(Debug)]
struct UploadFlight {
    peer: [u8; 32],
    identity: ToolchainIdentity,
    result: Mutex<Option<UploadResult>>,
}

/// The service keeps its existing operation permit while this ticket is live.
/// Pending polling never waits for the publisher or renews a deadline. Completed
/// results verify under the caller's cancellation budget; transport drives polls.
pub(crate) struct UploadWaiter<'a> {
    cache: &'a RemoteToolchainCache,
    flight: Arc<UploadFlight>,
}

impl UploadWaiter<'_> {
    pub(crate) fn poll(&self, stopped: impl Fn() -> bool) -> io::Result<UploadPoll> {
        checkpoint(&stopped)?;
        let result = self
            .flight
            .result
            .lock()
            .map_err(|_| invalid("remote toolchain upload result is poisoned"))?
            .clone();
        // The flight lock never spans verification, cache admission or caller
        // callbacks. Reuse verifies this exact owner, not a new identity lookup.
        match result {
            None => {
                checkpoint(&stopped)?;
                Ok(UploadPoll::Pending)
            }
            Some(UploadResult::Abandoned) => {
                checkpoint(&stopped)?;
                Ok(UploadPoll::Abandoned)
            }
            Some(UploadResult::Ready(lease)) => {
                if lease.identity() != &self.flight.identity {
                    return Err(invalid("shared compiler differs from its upload declaration"));
                }
                self.cache
                    .verified_upload(self.flight.peer, lease, &stopped)
                    .map(UploadPoll::Ready)
            }
        }
    }
}

/// Owns exactly one pending generation. The normal service-owned receiver and
/// its private SDK directory remain with the admitted operation. Publication
/// follows sealing/adoption; cancellation or unwinding abandons only this
/// generation so surviving waiters can reacquire within their original budget.
pub(crate) struct UploadPublisher<'a> {
    cache: &'a RemoteToolchainCache,
    peer: [u8; 32],
    identity: ToolchainIdentity,
    flight: Option<Arc<UploadFlight>>,
    finished: bool,
}

impl UploadPublisher<'_> {
    pub(crate) fn publish(
        mut self,
        lease: Arc<ReceivedToolchain>,
        stopped: impl Fn() -> bool,
    ) -> io::Result<()> {
        checkpoint(&stopped)?;
        if lease.identity() != &self.identity {
            return Err(invalid("received compiler differs from its upload declaration"));
        }
        // The sealed receiver already hashed every byte; preserve its complete
        // owner/generation witness. Every waiting reuse performs a fresh full
        // byte verification, including independently owned cancellation.
        lease.verify(&stopped)?;
        checkpoint(&stopped)?;
        {
            let mut state = self.cache.lock()?;
            if RemoteToolchainCache::upload_invalidated(&state, self.peer, &lease) {
                return Err(invalid("received compiler was invalidated before publication"));
            }
            if let Some(flight) = &self.flight {
                RemoteToolchainCache::detach_upload(&mut state, flight);
            }
        }
        // Detach before publishing: a later arrival must never join a finished
        // private result just because an earlier waiter still owns its ticket.
        if let Some(flight) = &self.flight {
            let mut result = flight
                .result
                .lock()
                .map_err(|_| invalid("remote toolchain upload result is poisoned"))?;
            if result.is_some() {
                return Err(invalid("remote toolchain upload was already completed"));
            }
            *result = Some(UploadResult::Ready(lease));
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for UploadPublisher<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let Some(flight) = &self.flight else {
            return;
        };
        let mut state = self
            .cache
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        RemoteToolchainCache::detach_upload(&mut state, flight);
        drop(state);
        let mut result = flight
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if result.is_none() {
            *result = Some(UploadResult::Abandoned);
        }
    }
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
            return Err(invalid(
                "remote toolchain cache limits outside their bounds",
            ));
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

    fn detach_upload(state: &mut State, flight: &Arc<UploadFlight>) {
        let selected = Arc::downgrade(flight);
        state.pending_uploads.retain(|pending| {
            pending.strong_count() != 0 && !Weak::ptr_eq(pending, &selected)
        });
    }

    fn upload_invalidated(
        state: &State,
        peer: [u8; 32],
        lease: &Arc<ReceivedToolchain>,
    ) -> bool {
        state.entries.iter().any(|entry| {
            entry.peer == peer && entry.invalidated && Arc::ptr_eq(&entry.lease, lease)
        })
    }

    /// A flight may publish a private upload when persistent retention is full
    /// or disabled. Absence from the cache is valid; an exact invalidated entry
    /// is not. Retained membership is still mandatory for ordinary warm hits.
    fn verified_upload(
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
        let invalidated = {
            let state = self.lock()?;
            Self::upload_invalidated(&state, peer, &lease)
        };
        if invalidated {
            return Err(invalid(
                "received compiler was invalidated during shared acquisition",
            ));
        }
        Ok(lease)
    }

    /// Select a verified warm image or join/elect one cold upload atomically.
    /// Call only after acquiring the service's bounded operation permit, and
    /// keep that permit through upload, every waiter ticket and SDK handoff.
    /// Pending flights have their own count bound, independent of retention.
    pub(crate) fn acquire(
        &self,
        peer: [u8; 32],
        identity: &ToolchainIdentity,
        stopped: impl Fn() -> bool,
    ) -> io::Result<ToolchainAcquisition<'_>> {
        checkpoint(&stopped)?;
        if peer == [0; 32] {
            return Err(invalid("remote compiler acquisition requires an authenticated edge key"));
        }
        let acquisition = {
            let mut state = self.lock()?;
            let retained = if self.max_bytes != 0 && identity.bytes <= self.max_bytes {
                Self::select(&mut state, peer, identity)
            } else {
                None
            };
            if let Some(lease) = retained {
                ToolchainAcquisition::Ready(lease)
            } else {
                state.pending_uploads.retain(|pending| pending.strong_count() != 0);
                let pending = state
                    .pending_uploads
                    .iter()
                    .filter_map(Weak::upgrade)
                    .find(|flight| flight.peer == peer && &flight.identity == identity);
                if let Some(flight) = pending {
                    ToolchainAcquisition::Wait(UploadWaiter { cache: self, flight })
                } else {
                    let flight = (state.pending_uploads.len() < MAX_PENDING_UPLOADS).then(|| {
                        let flight = Arc::new(UploadFlight {
                            peer,
                            identity: *identity,
                            result: Mutex::new(None),
                        });
                        state.pending_uploads.push(Arc::downgrade(&flight));
                        flight
                    });
                    // A full registry falls back to the same private bounded
                    // upload as before. It retains no additional map entry.
                    ToolchainAcquisition::Upload(UploadPublisher {
                        cache: self,
                        peer,
                        identity: *identity,
                        flight,
                        finished: false,
                    })
                }
            }
        };
        match acquisition {
            ToolchainAcquisition::Ready(lease) => self
                .verified(peer, lease, &stopped)
                .map(ToolchainAcquisition::Ready),
            other => {
                // Callbacks run outside the mutex. A cancelled newly elected
                // owner drops here and promptly abandons its exact generation.
                checkpoint(&stopped)?;
                Ok(other)
            }
        }
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
            return Err(invalid(
                "received compiler was invalidated during acquisition",
            ));
        }
        Ok(lease)
    }

    /// Only this authenticated edge's complete identity may reuse a received
    /// image. Verification failures refuse this operation, never hide as misses.
    /// Cancellation leaves a ready entry available to other callers.
    #[cfg(test)]
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
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

    fn upload<'a>(
        cache: &'a RemoteToolchainCache,
        peer: [u8; 32],
        identity: &ToolchainIdentity,
    ) -> UploadPublisher<'a> {
        match cache.acquire(peer, identity, || false).unwrap() {
            ToolchainAcquisition::Upload(owner) => owner,
            _ => panic!("cold SDK should elect an upload owner"),
        }
    }

    fn join_upload<'a>(
        cache: &'a RemoteToolchainCache,
        peer: [u8; 32],
        identity: &ToolchainIdentity,
    ) -> UploadWaiter<'a> {
        match cache.acquire(peer, identity, || false).unwrap() {
            ToolchainAcquisition::Wait(waiter) => waiter,
            _ => panic!("overlapping cold SDK should join its pending owner"),
        }
    }

    #[test]
    fn concurrent_cold_acquisitions_elect_one_upload_and_share_its_exact_sealed_owner() {
        let cache = RemoteToolchainCache::new(0, 1).unwrap();
        let sdk = fixture(b"one complete compiler upload");
        let release = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        thread::scope(|scope| {
            let threads: Vec<_> = (0..4)
                .map(|_| {
                    let cache = &cache;
                    let sdk = Arc::clone(&sdk);
                    let release = Arc::clone(&release);
                    let entered_tx = entered_tx.clone();
                    scope.spawn(move || -> io::Result<Arc<ReceivedToolchain>> {
                        let deadline = Instant::now() + Duration::from_secs(5);
                        let stopped = || Instant::now() >= deadline;
                        match cache.acquire(EDGE_A, sdk.identity(), &stopped)? {
                            ToolchainAcquisition::Upload(owner) => {
                                entered_tx.send(true).unwrap();
                                while !release.load(Ordering::Acquire) {
                                    checkpoint(&stopped)?;
                                    thread::yield_now();
                                }
                                let lease = cache.adopt(EDGE_A, sdk, &stopped)?;
                                owner.publish(Arc::clone(&lease), &stopped)?;
                                Ok(lease)
                            }
                            ToolchainAcquisition::Wait(waiter) => {
                                entered_tx.send(false).unwrap();
                                loop {
                                    match waiter.poll(&stopped)? {
                                        UploadPoll::Pending => thread::yield_now(),
                                        UploadPoll::Abandoned => {
                                            return Err(invalid("fixture upload was abandoned"));
                                        }
                                        UploadPoll::Ready(lease) => return Ok(lease),
                                    }
                                }
                            }
                            ToolchainAcquisition::Ready(_) => {
                                panic!("disabled retention cannot supply a warm hit")
                            }
                        }
                    })
                })
                .collect();
            let elected = (0..4)
                .map(|_| entered_rx.recv_timeout(Duration::from_secs(5)).unwrap())
                .filter(|leader| *leader)
                .count();
            assert_eq!(elected, 1);
            assert_eq!(cache.lock().unwrap().pending_uploads.len(), 1);
            release.store(true, Ordering::Release);
            for thread in threads {
                let received = thread.join().unwrap().unwrap();
                assert!(Arc::ptr_eq(&received, &sdk));
                received.verify(|| false).unwrap();
            }
        });
        assert!(cache.lock().unwrap().pending_uploads.is_empty());
        assert_eq!(counts(&cache), (0, 0, 0));
    }

    #[test]
    fn private_completed_uploads_only_reach_registered_waiters_when_cache_is_disabled_or_full() {
        for full in [false, true] {
            let cache = RemoteToolchainCache::new(if full { 1024 } else { 0 }, 1).unwrap();
            let _busy = full.then(|| cache.adopt(EDGE_B, fixture(b"busy SDK"), || false).unwrap());
            let before = counts(&cache);
            let sdk = fixture(b"shared private SDK");
            let identity = *sdk.identity();
            let path = sdk.owner().path().to_path_buf();
            let owner = upload(&cache, EDGE_A, &identity);
            let waiter = join_upload(&cache, EDGE_A, &identity);
            let completed = Arc::downgrade(&waiter.flight);
            let sdk = cache.adopt(EDGE_A, sdk, || false).unwrap();
            owner.publish(sdk, || false).unwrap();
            assert!(cache.lock().unwrap().pending_uploads.is_empty());
            assert_eq!(counts(&cache), before);

            // The completed ticket is deliberately still alive. New arrivals
            // must upload; they cannot turn private handoff into warm retention.
            let next = upload(&cache, EDGE_A, &identity);
            assert!(!Weak::ptr_eq(
                &completed,
                &Arc::downgrade(next.flight.as_ref().unwrap()),
            ));
            let next_waiter = join_upload(&cache, EDGE_A, &identity);
            let UploadPoll::Ready(received) = waiter
                .poll(|| {
                    assert!(cache.state.try_lock().is_ok());
                    assert!(waiter.flight.result.try_lock().is_ok());
                    false
                })
                .unwrap()
            else {
                panic!("registered waiter lost its completed SDK");
            };
            assert_eq!(received.owner().path(), path);
            drop(received);
            assert!(path.is_dir(), "the registered ticket still owns the SDK");
            drop(waiter);
            assert!(!path.exists(), "weak registry must not retain a private SDK");
            assert_eq!(cache.lock().unwrap().pending_uploads.len(), 1);
            assert!(matches!(next_waiter.poll(|| false).unwrap(), UploadPoll::Pending));
            drop((next_waiter, next));
            assert!(cache.lock().unwrap().pending_uploads.is_empty());
            assert_eq!(counts(&cache), before);
        }
    }

    #[test]
    fn upload_flights_bind_authenticated_peer_and_every_identity_field() {
        let cache = RemoteToolchainCache::new(0, 1).unwrap();
        let sdk = fixture(b"identity-bound SDK");
        let identity = *sdk.identity();
        let mut owners = vec![upload(&cache, EDGE_A, &identity)];
        let waiter = join_upload(&cache, EDGE_A, &identity);
        owners.push(upload(&cache, EDGE_B, &identity));
        for changed in ["hash", "files", "bytes"] {
            let mut other = identity;
            match changed {
                "hash" => other.sha256[0] ^= 1,
                "files" => other.files += 1,
                "bytes" => other.bytes += 1,
                _ => unreachable!(),
            }
            owners.push(upload(&cache, EDGE_A, &other));
        }
        assert_eq!(cache.lock().unwrap().pending_uploads.len(), 5);
        assert!(cache.acquire([0; 32], &identity, || false).is_err());
        assert!(matches!(waiter.poll(|| false).unwrap(), UploadPoll::Pending));
        drop(owners);
        assert!(matches!(waiter.poll(|| false).unwrap(), UploadPoll::Abandoned));
        assert!(cache.lock().unwrap().pending_uploads.is_empty());
    }

    #[test]
    fn abandoned_upload_generation_cannot_remove_its_replacement_or_strand_waiters() {
        for unwind in [false, true] {
            let cache = RemoteToolchainCache::new(0, 1).unwrap();
            let sdk = fixture(b"recoverable compiler");
            let identity = *sdk.identity();
            let owner = upload(&cache, EDGE_A, &identity);
            let abandoned = join_upload(&cache, EDGE_A, &identity);
            if unwind {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        let _owner = owner;
                        panic!("upload owner unwound");
                    }))
                    .is_err()
                );
            } else {
                drop(owner);
            }
            assert!(matches!(abandoned.poll(|| false).unwrap(), UploadPoll::Abandoned));
            let replacement = upload(&cache, EDGE_A, &identity);
            let live = join_upload(&cache, EDGE_A, &identity);
            assert!(!Arc::ptr_eq(&abandoned.flight, &live.flight));
            drop(abandoned);
            assert_eq!(cache.lock().unwrap().pending_uploads.len(), 1);
            replacement.publish(Arc::clone(&sdk), || false).unwrap();
            let UploadPoll::Ready(received) = live.poll(|| false).unwrap() else {
                panic!("surviving waiter did not receive replacement upload");
            };
            assert!(Arc::ptr_eq(&received, &sdk));
            assert!(cache.lock().unwrap().pending_uploads.is_empty());
        }
    }

    #[test]
    fn failing_publication_after_detach_cannot_abandon_a_newer_upload_generation() {
        let cache = RemoteToolchainCache::new(0, 1).unwrap();
        let sdk = fixture(b"replacement survives stale publisher");
        let identity = *sdk.identity();
        let owner = upload(&cache, EDGE_A, &identity);
        let old_waiter = join_upload(&cache, EDGE_A, &identity);
        let old_flight = Arc::clone(&old_waiter.flight);
        let (held_tx, held_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        thread::scope(|scope| {
            // Hold the actual result lock so publication pauses after registry
            // detachment. Poisoning it makes the old publisher's Drop run only
            // after a replacement generation has become discoverable.
            let blocker = scope.spawn(move || {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _result = old_flight.result.lock().unwrap();
                        held_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        panic!("publication result lock poisoned");
                    }))
                    .is_err()
                );
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let uploaded = Arc::clone(&sdk);
            let publisher = scope.spawn(move || owner.publish(uploaded, || false));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cache.lock().unwrap().pending_uploads.is_empty() {
                assert!(Instant::now() < deadline, "publisher did not detach");
                thread::yield_now();
            }
            let next = upload(&cache, EDGE_A, &identity);
            let waiter = join_upload(&cache, EDGE_A, &identity);
            assert!(!Arc::ptr_eq(&old_waiter.flight, &waiter.flight));
            release_tx.send(()).unwrap();
            blocker.join().unwrap();
            assert!(publisher.join().unwrap().is_err());
            assert_eq!(cache.lock().unwrap().pending_uploads.len(), 1);
            assert!(matches!(waiter.poll(|| false).unwrap(), UploadPoll::Pending));
            next.publish(Arc::clone(&sdk), || false).unwrap();
            assert!(matches!(waiter.poll(|| false).unwrap(), UploadPoll::Ready(_)));
        });
        assert!(cache.lock().unwrap().pending_uploads.is_empty());
    }

    #[test]
    fn upload_waiter_cancellation_is_independent_and_cancelled_acquisition_drops_outside_lock() {
        let cache = RemoteToolchainCache::new(0, 1).unwrap();
        let sdk = fixture(b"independent waiter cancellation");
        let owner = upload(&cache, EDGE_A, sdk.identity());
        let survivor = join_upload(&cache, EDGE_A, sdk.identity());
        for expired in [false, true] {
            let waiter = join_upload(&cache, EDGE_A, sdk.identity());
            let deadline = Instant::now();
            let stopped = || !expired || Instant::now() >= deadline;
            assert_eq!(waiter.poll(stopped).unwrap_err().kind(), io::ErrorKind::Interrupted);
            drop(waiter);
            assert!(matches!(survivor.poll(|| false).unwrap(), UploadPoll::Pending));
            assert_eq!(cache.lock().unwrap().pending_uploads.len(), 1);
        }
        owner.publish(Arc::clone(&sdk), || false).unwrap();
        assert!(matches!(survivor.poll(|| false).unwrap(), UploadPoll::Ready(_)));
        drop(survivor);

        let calls = Cell::new(0);
        let result = cache.acquire(EDGE_A, sdk.identity(), || {
            assert!(cache.state.try_lock().is_ok());
            let previous = calls.get();
            calls.set(previous + 1);
            previous != 0
        });
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Interrupted);
        assert!(cache.lock().unwrap().pending_uploads.is_empty());
        let next = upload(&cache, EDGE_A, sdk.identity());
        let waiter = join_upload(&cache, EDGE_A, sdk.identity());
        assert_eq!(
            next.publish(Arc::clone(&sdk), || true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(matches!(waiter.poll(|| false).unwrap(), UploadPoll::Abandoned));
    }

    #[test]
    fn upload_publication_refuses_wrong_identity_changed_sdk_and_changed_owner() {
        for changed in ["hash", "files", "bytes", "sdk", "owner"] {
            let cache = RemoteToolchainCache::new(0, 1).unwrap();
            let sdk = fixture(b"verified compiler generation");
            let mut identity = *sdk.identity();
            match changed {
                "hash" => identity.sha256[0] ^= 1,
                "files" => identity.files += 1,
                "bytes" => identity.bytes += 1,
                _ => {}
            }
            let owner = upload(&cache, EDGE_A, &identity);
            let waiter = join_upload(&cache, EDGE_A, &identity);
            let published = match changed {
                "hash" | "files" | "bytes" => Arc::clone(&sdk),
                "sdk" => {
                    let path = sdk.root().join("compiler");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(path, b"tampered generation").unwrap();
                    Arc::clone(&sdk)
                }
                "owner" => {
                    fs::set_permissions(sdk.owner().path(), fs::Permissions::from_mode(0o755))
                        .unwrap();
                    Arc::clone(&sdk)
                }
                _ => unreachable!(),
            };
            assert!(owner.publish(published, || false).is_err(), "{changed}");
            assert!(matches!(waiter.poll(|| false).unwrap(), UploadPoll::Abandoned));
            assert!(cache.lock().unwrap().pending_uploads.is_empty());
        }
    }

    #[test]
    fn upload_waiters_refuse_invalidated_cached_owners_and_later_mutation() {
        let cache = RemoteToolchainCache::new(1024, 2).unwrap();
        let sdk = fixture(b"shared compiler generation");
        let identity = *sdk.identity();
        let owner = upload(&cache, EDGE_A, &identity);
        let waiter = join_upload(&cache, EDGE_A, &identity);
        let sdk = cache.adopt(EDGE_A, sdk, || false).unwrap();
        owner.publish(Arc::clone(&sdk), || false).unwrap();

        let ToolchainAcquisition::Ready(warm) = cache.acquire(EDGE_A, &identity, || false).unwrap()
        else {
            panic!("retained SDK must win before another cold flight is created");
        };
        assert!(Arc::ptr_eq(&warm, &sdk));
        assert!(cache.lock().unwrap().pending_uploads.is_empty());
        drop(warm);

        // A shared acquisition must respect invalidation even if intact bytes
        // would otherwise pass. It cannot reinterpret this row as a private SDK.
        cache.invalidate(EDGE_A, &sdk).unwrap();
        assert!(waiter.poll(|| false).is_err());
        let replacement_owner = upload(&cache, EDGE_A, &identity);
        let replacement_waiter = join_upload(&cache, EDGE_A, &identity);
        assert!(replacement_owner.publish(Arc::clone(&sdk), || false).is_err());
        assert!(matches!(
            replacement_waiter.poll(|| false).unwrap(),
            UploadPoll::Abandoned
        ));

        let owner = upload(&cache, EDGE_A, &identity);
        let successor_waiter = join_upload(&cache, EDGE_A, &identity);
        let successor = cache
            .adopt(EDGE_A, fixture(b"shared compiler generation"), || false)
            .unwrap();
        owner.publish(Arc::clone(&successor), || false).unwrap();
        assert!(!Arc::ptr_eq(&sdk, &successor));
        let path = sdk.root().join("compiler");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, b"mutated predecessor").unwrap();
        assert!(waiter.poll(|| false).is_err());
        let UploadPoll::Ready(received) = successor_waiter.poll(|| false).unwrap() else {
            panic!("an older generation invalidated its replacement");
        };
        assert!(Arc::ptr_eq(&received, &successor));
        assert!(!cache.lock().unwrap().entries.iter().any(|entry| {
            Arc::ptr_eq(&entry.lease, &successor) && entry.invalidated
        }));

        let private_cache = RemoteToolchainCache::new(0, 1).unwrap();
        let private_sdk = fixture(b"private completed SDK");
        let owner = upload(&private_cache, EDGE_A, private_sdk.identity());
        let waiter = join_upload(&private_cache, EDGE_A, private_sdk.identity());
        owner.publish(Arc::clone(&private_sdk), || false).unwrap();
        let path = private_sdk.root().join("compiler");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, b"tampered private SDK").unwrap();
        assert!(waiter.poll(|| false).is_err());
        assert_eq!(counts(&private_cache), (0, 0, 0));
    }

    #[test]
    fn pending_upload_registry_has_a_separate_bound_and_unshared_fallback_still_checks_identity() {
        let cache = RemoteToolchainCache::new(0, 1).unwrap();
        let sdk = fixture(b"bounded upload registry");
        let identity = *sdk.identity();
        let mut owners = Vec::new();
        for index in 1..=MAX_PENDING_UPLOADS {
            let mut different = identity;
            different.sha256[0] ^= index as u8;
            owners.push(upload(&cache, EDGE_A, &different));
        }
        assert_eq!(cache.lock().unwrap().pending_uploads.len(), MAX_PENDING_UPLOADS);
        let fallback = upload(&cache, EDGE_A, &identity);
        assert!(fallback.flight.is_none());
        assert!(fallback.publish(fixture(b"wrong fallback SDK"), || false).is_err());
        let fallback = upload(&cache, EDGE_A, &identity);
        assert!(fallback.flight.is_none());
        fallback.publish(Arc::clone(&sdk), || false).unwrap();
        assert_eq!(cache.lock().unwrap().pending_uploads.len(), MAX_PENDING_UPLOADS);
        assert_eq!(counts(&cache), (0, 0, 0));

        drop(owners.pop());
        let next = upload(&cache, EDGE_A, &identity);
        assert!(next.flight.is_some());
        let dead = Arc::downgrade(next.flight.as_ref().unwrap());
        drop(next);
        drop(owners);
        assert!(cache.lock().unwrap().pending_uploads.is_empty());
        // Exercise pruning independently of the ordinary Drop removal path.
        cache.lock().unwrap().pending_uploads.push(dead);
        let next = upload(&cache, EDGE_A, &identity);
        assert_eq!(cache.lock().unwrap().pending_uploads.len(), 1);
        drop(next);
        assert!(cache.lock().unwrap().pending_uploads.is_empty());
    }

    fn wait_for_verification_followers(received: &ReceivedToolchain, followers: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // The active slot and leader retain one reference each. Additional
            // references prove followers joined this flight, not just that
            // their threads were scheduled.
            if received
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
                "received SDK verification followers did not join"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn overlapping_received_checks_share_one_byte_scan_and_later_checks_start_fresh() {
        let cache = RemoteToolchainCache::new(1024, 2).unwrap();
        let lease = cache
            .adopt(EDGE_A, fixture(b"compiler\0\xff"), || false)
            .unwrap();
        let scans = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let leader_lease = Arc::clone(&lease);
        let leader_scans = Arc::clone(&scans);
        let leader = thread::spawn(move || {
            leader_lease.verify_with(&|| false, || {
                leader_scans.fetch_add(1, Ordering::SeqCst);
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                leader_lease.scan_bytes(&|| false)
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let followers: Vec<_> = (0..2)
            .map(|_| {
                let lease = Arc::clone(&lease);
                let scans = Arc::clone(&scans);
                thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let stopped = || Instant::now() >= deadline;
                    lease.verify_with(&stopped, || {
                        scans.fetch_add(1, Ordering::SeqCst);
                        lease.scan_bytes(&stopped)
                    })
                })
            })
            .collect();
        wait_for_verification_followers(&lease, followers.len());
        let completed = Arc::clone(lease.verification.lock().unwrap().as_ref().unwrap());
        release_tx.send(()).unwrap();
        leader.join().unwrap().unwrap();
        for follower in followers {
            follower.join().unwrap().unwrap();
        }
        assert_eq!(scans.load(Ordering::SeqCst), 1);
        assert!(lease.verification.lock().unwrap().is_none());
        assert!(completed.result.lock().unwrap().as_ref().unwrap().is_ok());

        // Retaining an earlier completed result must not turn it into a memo.
        // The later scan owns a different active flight and reads the bytes.
        lease
            .verify_with(&|| false, || {
                scans.fetch_add(1, Ordering::SeqCst);
                let current = Arc::clone(lease.verification.lock().unwrap().as_ref().unwrap());
                assert!(!Arc::ptr_eq(&current, &completed));
                lease.scan_bytes(&|| false)
            })
            .unwrap();
        assert_eq!(scans.load(Ordering::SeqCst), 2);
        assert!(lease.verification.lock().unwrap().is_none());
        assert!(Arc::ptr_eq(
            &cache
                .lookup(EDGE_A, lease.identity(), || false)
                .unwrap()
                .unwrap(),
            &lease,
        ));
    }

    #[test]
    fn identical_received_bytes_in_distinct_owners_have_separate_verification_flights() {
        let cache = RemoteToolchainCache::new(1024, 2).unwrap();
        let first = cache.adopt(EDGE_A, fixture(b"same SDK"), || false).unwrap();
        let second = cache.adopt(EDGE_B, fixture(b"same SDK"), || false).unwrap();
        assert_eq!(first.identity(), second.identity());
        assert_ne!(first.root(), second.root());
        let scans = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::sync_channel(2);
        let mut releases = Vec::new();
        let mut threads = Vec::new();
        for lease in [&first, &second] {
            let lease = Arc::clone(lease);
            let scans = Arc::clone(&scans);
            let entered_tx = entered_tx.clone();
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            releases.push(release_tx);
            threads.push(thread::spawn(move || {
                lease.verify_with(&|| false, || {
                    scans.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    lease.scan_bytes(&|| false)
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
        assert_eq!(counts(&cache), (2, 0, first.identity().bytes * 2));
    }

    #[test]
    fn cancelled_or_expired_received_waiter_does_not_cancel_scan_or_retire_custody() {
        for cancel_waiter in [false, true] {
            let cache = Arc::new(RemoteToolchainCache::new(1024, 1).unwrap());
            let lease = cache
                .adopt(EDGE_A, fixture(b"retained SDK"), || false)
                .unwrap();
            let identity = *lease.identity();
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let leader_lease = Arc::clone(&lease);
            let leader = thread::spawn(move || {
                leader_lease.verify_with(&|| false, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    leader_lease.scan_bytes(&|| false)
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let cancelled = Arc::new(AtomicBool::new(false));
            let deadline = Arc::new(Mutex::new(Instant::now() + Duration::from_secs(5)));
            let follower_cancelled = Arc::clone(&cancelled);
            let follower_deadline = Arc::clone(&deadline);
            let follower_cache = Arc::clone(&cache);
            let follower = thread::spawn(move || {
                follower_cache.lookup(EDGE_A, &identity, || {
                    follower_cancelled.load(Ordering::Acquire)
                        || Instant::now() >= *follower_deadline.lock().unwrap()
                })
            });
            wait_for_verification_followers(&lease, 1);
            assert!(
                cache.state.try_lock().is_ok(),
                "a waiting lookup must not hold cache admission"
            );
            if cancel_waiter {
                cancelled.store(true, Ordering::Release);
            } else {
                // Expire only this caller's deadline after it actually joined.
                *deadline.lock().unwrap() = Instant::now();
            }
            let error = follower.join().unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(lease.verification.lock().unwrap().is_some());
            assert_eq!(counts(&cache), (1, 0, identity.bytes));
            assert!(!cache.lock().unwrap().entries[0].invalidated);
            assert!(lease.root().is_dir());

            release_tx.send(()).unwrap();
            leader.join().unwrap().unwrap();
            assert!(Arc::ptr_eq(
                &cache.lookup(EDGE_A, &identity, || false).unwrap().unwrap(),
                &lease,
            ));
            assert!(lease.verification.lock().unwrap().is_none());
        }
    }

    #[test]
    fn cancelled_or_unwound_received_scan_leader_allows_a_live_waiter_to_retry() {
        for panics in [false, true] {
            let cache = RemoteToolchainCache::new(1024, 1).unwrap();
            let lease = cache
                .adopt(EDGE_A, fixture(b"retained SDK"), || false)
                .unwrap();
            let scans = Arc::new(AtomicUsize::new(0));
            let cancelled = Arc::new(AtomicBool::new(false));
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let leader_lease = Arc::clone(&lease);
            let leader_scans = Arc::clone(&scans);
            let leader_cancelled = Arc::clone(&cancelled);
            let leader = thread::spawn(move || {
                let stopped = || leader_cancelled.load(Ordering::Acquire);
                leader_lease.verify_with(&stopped, || {
                    leader_scans.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    assert!(!panics, "injected received-SDK verification-owner unwind");
                    leader_lease.scan_bytes(&stopped)
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let follower_lease = Arc::clone(&lease);
            let follower_scans = Arc::clone(&scans);
            let follower = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let stopped = || Instant::now() >= deadline;
                follower_lease.verify_with(&stopped, || {
                    follower_scans.fetch_add(1, Ordering::SeqCst);
                    follower_lease.scan_bytes(&stopped)
                })
            });
            wait_for_verification_followers(&lease, 1);
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
            assert!(lease.verification.lock().unwrap().is_none());
            lease.verify(|| false).unwrap();
            assert_eq!(counts(&cache), (1, 0, lease.identity().bytes));
            assert!(!cache.lock().unwrap().entries[0].invalidated);
        }
    }

    #[test]
    fn shared_scan_success_never_skips_each_callers_owner_or_sdk_generation_barrier() {
        for owner_mutation in [false, true] {
            for after_scan in [false, true] {
                let cache = RemoteToolchainCache::new(1024, 1).unwrap();
                let lease = cache.adopt(EDGE_A, fixture(b"compiler"), || false).unwrap();
                let identity = *lease.identity();
                let scans = Arc::new(AtomicUsize::new(0));
                let (entered_tx, entered_rx) = mpsc::sync_channel(1);
                let (release_tx, release_rx) = mpsc::sync_channel(1);
                let leader_lease = Arc::clone(&lease);
                let leader_scans = Arc::clone(&scans);
                let leader = thread::spawn(move || {
                    leader_lease.verify_with(&|| false, || {
                        leader_scans.fetch_add(1, Ordering::SeqCst);
                        if after_scan {
                            leader_lease.scan_bytes(&|| false)?;
                        }
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        if after_scan {
                            Ok(())
                        } else {
                            leader_lease.scan_bytes(&|| false)
                        }
                    })
                });
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let follower_lease = Arc::clone(&lease);
                let follower_scans = Arc::clone(&scans);
                let follower = thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let stopped = || Instant::now() >= deadline;
                    follower_lease.verify_with(&stopped, || {
                        follower_scans.fetch_add(1, Ordering::SeqCst);
                        follower_lease.scan_bytes(&stopped)
                    })
                });
                wait_for_verification_followers(&lease, 1);
                if owner_mutation {
                    fs::write(
                        lease.owner().path().join("unexpected-source"),
                        b"not SDK input",
                    )
                    .unwrap();
                } else {
                    let path = lease.root().join("compiler");
                    let modified = fs::metadata(&path).unwrap().modified().unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&path, b"tampered").unwrap();
                    File::options()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_modified(modified)
                        .unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
                }
                release_tx.send(()).unwrap();
                for result in [leader.join().unwrap(), follower.join().unwrap()] {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                }
                assert_eq!(scans.load(Ordering::SeqCst), 1);
                assert!(lease.verification.lock().unwrap().is_none());
                assert!(cache.lookup(EDGE_A, &identity, || false).is_err());
                assert!(cache.lock().unwrap().entries[0].invalidated);
                assert_eq!(counts(&cache), (1, 0, identity.bytes));
            }
        }
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
            let lease = cache
                .adopt(EDGE_A, Arc::clone(&uploaded), || false)
                .unwrap();
            assert!(Arc::ptr_eq(&lease, &uploaded));
            assert!(lease.root().is_dir());
            assert!(
                cache
                    .lookup(EDGE_A, lease.identity(), || false)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(counts(&cache), (0, 0, 0));
        }
    }

    #[test]
    fn exact_authenticated_identity_reuses_without_copy_and_other_edges_remain_isolated() {
        let cache = RemoteToolchainCache::new(64, 4).unwrap();
        let uploaded = fixture(b"same immutable SDK");
        let identity = *uploaded.identity();
        let root = uploaded.root().to_path_buf();
        let lease = cache
            .adopt(EDGE_A, Arc::clone(&uploaded), || false)
            .unwrap();
        let hit = cache.lookup(EDGE_A, &identity, || false).unwrap().unwrap();
        assert!(Arc::ptr_eq(&hit, &uploaded));
        assert_eq!(hit.root(), root);
        assert!(cache.lookup(EDGE_B, &identity, || false).unwrap().is_none());

        for changed in [
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
            assert!(cache.lookup(EDGE_A, &changed, || false).unwrap().is_none());
        }

        let duplicate = fixture(b"same immutable SDK");
        assert_eq!(*duplicate.identity(), identity);
        let same_edge = cache
            .adopt(EDGE_A, Arc::clone(&duplicate), || false)
            .unwrap();
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
        assert!(
            ReceivedToolchain::new(Arc::new(private()), Arc::clone(lease.image()), || false,)
                .is_err()
        );

        let nested_owner = Arc::new(private());
        let nested = nested_owner.path().join("nested");
        fs::DirBuilder::new().mode(0o700).create(&nested).unwrap();
        let source = private();
        fs::write(source.path().join("compiler"), b"nested image").unwrap();
        let nested_image = Arc::new(
            capture_toolchain(
                source.path(),
                &nested.join("toolchain"),
                None,
                &ToolchainLimits::default(),
                || false,
            )
            .unwrap(),
        );
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
        let private = cache
            .adopt(EDGE_A, Arc::clone(&overflow), || false)
            .unwrap();
        assert!(Arc::ptr_eq(&private, &overflow));
        assert!(
            cache
                .lookup(EDGE_A, &overflow_id, || false)
                .unwrap()
                .is_none()
        );
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
            let private = cache
                .adopt(EDGE_A, Arc::clone(&replacement), || false)
                .unwrap();
            assert!(Arc::ptr_eq(&private, &replacement));
            assert!(cache.lookup(EDGE_A, &identity, || false).unwrap().is_some());
            assert!(
                cache
                    .lookup(EDGE_A, &replacement_id, || false)
                    .unwrap()
                    .is_none()
            );
            assert!(path.is_dir());
            assert_eq!(counts(&cache), (1, 0, identity.bytes));

            drop(handles);
            let retained = cache.adopt(EDGE_A, replacement, || false).unwrap();
            assert!(Arc::ptr_eq(
                &cache
                    .lookup(EDGE_A, &replacement_id, || false)
                    .unwrap()
                    .unwrap(),
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
            let error = cache
                .lookup(EDGE_A, &identity, || {
                    assert!(cache.state.try_lock().is_ok());
                    checks.set(checks.get() + 1);
                    checks.get() >= stop_after
                })
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(!cache.lock().unwrap().entries[0].invalidated);
            assert!(Arc::ptr_eq(
                &cache.lookup(EDGE_A, &identity, || false).unwrap().unwrap(),
                &lease,
            ));
        }
        assert_eq!(
            cache
                .adopt(EDGE_A, fixture(b"other"), || true)
                .unwrap_err()
                .kind(),
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
        assert!(
            cache
                .lookup(EDGE_A, &second_id, || false)
                .unwrap()
                .is_none()
        );
        assert!(Arc::ptr_eq(
            &cache
                .lookup(EDGE_A, third.identity(), || false)
                .unwrap()
                .unwrap(),
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
        let private = cache
            .adopt(EDGE_A, Arc::clone(&incoming), || false)
            .unwrap();
        assert!(Arc::ptr_eq(&private, &incoming));
        assert!(cache.lookup(EDGE_A, &idle_id, || false).unwrap().is_some());

        let incoming = fixture(b"larger");
        let incoming_id = *incoming.identity();
        let private = cache
            .adopt(EDGE_A, Arc::clone(&incoming), || false)
            .unwrap();
        assert!(Arc::ptr_eq(&private, &incoming));
        assert!(
            cache
                .lookup(EDGE_A, &incoming_id, || false)
                .unwrap()
                .is_none()
        );
        assert!(cache.lookup(EDGE_A, &idle_id, || false).unwrap().is_some());
        assert!(
            cache
                .lookup(EDGE_A, active.identity(), || false)
                .unwrap()
                .is_some()
        );
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
        let private = cache
            .adopt(EDGE_A, Arc::clone(&incoming), || false)
            .unwrap();
        assert!(Arc::ptr_eq(&private, &incoming));
        assert_eq!(counts(&cache), (0, 1, identity.bytes));

        std::thread::scope(|scope| {
            let guard = cache.lock().unwrap();
            let cleanup = scope.spawn(move || drop(retirement));
            // Cleanup must finish unlinking even while admission is locked;
            // releasing its accounting is the only step that waits for us.
            let deadline = Instant::now() + Duration::from_secs(5);
            while path.exists() {
                assert!(
                    Instant::now() < deadline,
                    "cleanup waited for the cache mutex"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(guard.retiring_entries, 1);
            assert_eq!(guard.retained_bytes, identity.bytes);
            drop(guard);
            cleanup.join().unwrap();
        });
        assert_eq!(counts(&cache), (0, 0, 0));
        let retained = cache.adopt(EDGE_A, incoming, || false).unwrap();
        assert!(
            cache
                .lookup(EDGE_A, retained.identity(), || false)
                .unwrap()
                .is_some()
        );
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
            assert!(
                cache
                    .adopt(EDGE_A, Arc::clone(&incoming), || false)
                    .is_err()
            );
            assert_eq!(counts(&cache), (0, 1, identity.bytes));
            assert_eq!(fs::read(&sentinel).unwrap(), b"not the received SDK");
            assert_eq!(
                fs::read(displaced.join("toolchain/compiler")).unwrap(),
                b"old compiler",
            );

            // Failed cleanup cannot finance another retained image. Ordinary
            // admission remains usable with its independent uploaded owner.
            let private = cache
                .adopt(EDGE_A, Arc::clone(&incoming), || false)
                .unwrap();
            assert!(Arc::ptr_eq(&private, &incoming));
            assert!(
                cache
                    .lookup(EDGE_A, incoming.identity(), || false)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(counts(&cache), (0, 1, identity.bytes));
            drop(cache);
            assert_eq!(fs::read(&sentinel).unwrap(), b"not the received SDK");
            assert!(displaced.join("toolchain/compiler").is_file());
        }
    }

    #[test]
    fn dropping_the_pool_preserves_an_active_lease_and_does_not_adopt_restart_paths() {
        let cache = RemoteToolchainCache::new(64, 1).unwrap();
        let lease = cache
            .adopt(EDGE_A, fixture(b"retained compiler"), || false)
            .unwrap();
        let identity = *lease.identity();
        let path = lease.owner().path().to_path_buf();
        drop(cache);
        assert!(path.is_dir());
        lease.verify(|| false).unwrap();

        let restarted = RemoteToolchainCache::new(64, 1).unwrap();
        assert!(
            restarted
                .lookup(EDGE_A, &identity, || false)
                .unwrap()
                .is_none()
        );
        assert_eq!(counts(&restarted), (0, 0, 0));
        drop(lease);
        assert!(!path.exists());
    }
}
