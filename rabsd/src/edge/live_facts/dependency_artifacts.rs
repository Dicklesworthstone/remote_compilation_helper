//! Reusable, immutable bytes for an already keyed dependency generation.
//!
//! This is a process-local transport optimization, not input or result
//! authority. Every caller still verifies its exact dependency inventory and
//! opens/checks its own source descriptor. An entry is usable only for the
//! same full file generation AND typed content identity. No source path, Cargo
//! operation or namespace inventory is retained globally.
//!
//! The one process cache bounds ready entries, active cached leases and cold
//! reservations together. Leased entries cannot be evicted. A full cache
//! falls back to the ordinary bounded upload capture instead of waiting for
//! capacity while holding other artifacts. There are no background tasks:
//! the existing remote producer owns each capture, and its RAII reservation
//! wakes exact-entry waiters on cancellation, failure or unwinding.

use super::{FileSig, stable_file};
use rabs_cas::digest_set::{DigestRequest, StreamingObjectWriter};
use rabs_protocol::result_identity::TypedDigest;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::Duration;

const READ_CHUNK: usize = 64 * 1024;
const WAIT_SLICE: Duration = Duration::from_millis(25);
pub(super) const MAX_DEPENDENCY_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_DEPENDENCY_FILES: usize = 4096;
static SHARED: LazyLock<ArtifactCache> =
    LazyLock::new(|| ArtifactCache::new(MAX_DEPENDENCY_BYTES, MAX_DEPENDENCY_FILES));

/// Owned immutable transport bytes and the digest of those exact bytes.
/// Selection/action authority stays with `DependencyFacts`, not this object.
/// Only borrowed byte access is exposed, so an upload cannot detach a cached
/// allocation from the Arc owner used to account for its lease.
#[derive(Debug)]
pub(crate) struct RetainedDependencyArtifact {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl RetainedDependencyArtifact {
    /// Seal bytes already owned by an explicit source-upload caller. This
    /// establishes transport identity only, never compiler input authority.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        let sha256 = Sha256::digest(&bytes).into();
        Self { bytes, sha256 }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    signature: FileSig,
    digest: TypedDigest,
}

#[derive(Debug)]
enum Entry {
    Capturing(Arc<()>),
    Ready {
        artifact: Arc<RetainedDependencyArtifact>,
        used: u64,
    },
}

#[derive(Debug, Default)]
struct State {
    entries: HashMap<Key, Entry>,
    bytes: u64,
    clock: u64,
}

impl State {
    fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    fn reserve(&mut self, key: &Key, max_bytes: u64, max_entries: usize) -> Option<Arc<()>> {
        if key.signature.size > max_bytes || max_entries == 0 {
            return None;
        }
        while self.entries.len() >= max_entries
            || key.signature.size > max_bytes.saturating_sub(self.bytes)
        {
            let victim = self
                .entries
                .iter()
                .filter_map(|(key, entry)| match entry {
                    Entry::Ready { artifact, used } if Arc::strong_count(artifact) == 1 => {
                        Some((key.clone(), *used))
                    }
                    _ => None,
                })
                .min_by_key(|(_, used)| *used)
                .map(|(key, _)| key)?;
            self.entries.remove(&victim);
            self.bytes -= victim.signature.size;
        }
        let token = Arc::new(());
        self.entries
            .insert(key.clone(), Entry::Capturing(Arc::clone(&token)));
        self.bytes += key.signature.size;
        Some(token)
    }
}

#[derive(Debug)]
struct Cache {
    max_bytes: u64,
    max_entries: usize,
    state: Mutex<State>,
    changed: Condvar,
    #[cfg(test)]
    captures: std::sync::atomic::AtomicUsize,
}

/// All live fact owners share the same bounded advisory byte cache. Retaining
/// it never retains a Cargo operation, source directory or background worker.
#[derive(Debug, Clone)]
pub(super) struct ArtifactCache(Arc<Cache>);

impl Default for ArtifactCache {
    fn default() -> Self {
        SHARED.clone()
    }
}

impl ArtifactCache {
    fn new(max_bytes: u64, max_entries: usize) -> Self {
        Self(Arc::new(Cache {
            max_bytes,
            max_entries,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            #[cfg(test)]
            captures: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    pub(super) fn acquire(
        &self,
        path: &Path,
        signature: FileSig,
        digest: &TypedDigest,
        stopped: &impl Fn() -> bool,
    ) -> Result<Arc<RetainedDependencyArtifact>, String> {
        checkpoint(stopped)?;
        // Keep this caller's descriptor even while another capture is active.
        // A hit never borrows the producer's path or namespace observation.
        let file = stable_file::open(path, signature)
            .map_err(|error| format!("open retained dependency: {error}"))?;
        let key = Key {
            signature,
            digest: digest.clone(),
        };
        self.acquire_opened(file, path, key, stopped)
    }

    fn acquire_opened(
        &self,
        file: File,
        path: &Path,
        key: Key,
        stopped: &impl Fn() -> bool,
    ) -> Result<Arc<RetainedDependencyArtifact>, String> {
        let reservation = loop {
            checkpoint(stopped)?;
            let Ok(mut state) = self.0.state.lock() else {
                // Poisoning only loses the optimization. A real descriptor-
                // verified read below still establishes all returned bytes.
                break None;
            };
            let used = state.tick();
            match state.entries.get_mut(&key) {
                Some(Entry::Ready {
                    artifact,
                    used: last_used,
                }) => {
                    *last_used = used;
                    let artifact = Arc::clone(artifact);
                    drop(state);
                    checkpoint(stopped)?;
                    stable_file::verify(&file, path, key.signature)
                        .map_err(|error| format!("recheck retained dependency: {error}"))?;
                    return Ok(artifact);
                }
                Some(Entry::Capturing(_)) => {
                    let waited = self.0.changed.wait_timeout(state, WAIT_SLICE);
                    if waited.is_err() {
                        break None;
                    }
                    drop(waited);
                }
                None => {
                    break state
                        .reserve(&key, self.0.max_bytes, self.0.max_entries)
                        .map(|token| Reservation {
                            cache: Arc::clone(&self.0),
                            key: key.clone(),
                            token,
                        });
                }
            }
        };
        #[cfg(test)]
        self.0
            .captures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let artifact = Arc::new(capture(file, path, &key, stopped)?);
        if let Some(reservation) = reservation {
            reservation.finish(Arc::clone(&artifact));
        }
        Ok(artifact)
    }
}

struct Reservation {
    cache: Arc<Cache>,
    key: Key,
    token: Arc<()>,
}

impl Reservation {
    fn finish(self, artifact: Arc<RetainedDependencyArtifact>) {
        if let Ok(mut state) = self.cache.state.lock()
            && matches!(state.entries.get(&self.key), Some(Entry::Capturing(token))
                if Arc::ptr_eq(token, &self.token))
        {
            let used = state.tick();
            state
                .entries
                .insert(self.key.clone(), Entry::Ready { artifact, used });
        }
        self.cache.changed.notify_all();
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.cache.state.lock()
            && matches!(state.entries.get(&self.key), Some(Entry::Capturing(token))
                if Arc::ptr_eq(token, &self.token))
        {
            state.entries.remove(&self.key);
            state.bytes -= self.key.signature.size;
        }
        self.cache.changed.notify_all();
    }
}

fn checkpoint(stopped: &impl Fn() -> bool) -> Result<(), String> {
    if stopped() {
        Err("dependency artifact retention cancelled".into())
    } else {
        Ok(())
    }
}

fn capture(
    mut file: File,
    path: &Path,
    key: &Key,
    stopped: &impl Fn() -> bool,
) -> Result<RetainedDependencyArtifact, String> {
    checkpoint(stopped)?;
    stable_file::verify(&file, path, key.signature)
        .map_err(|error| format!("recheck dependency before capture: {error}"))?;
    let size = usize::try_from(key.signature.size)
        .map_err(|error| format!("retained dependency size: {error}"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|error| format!("reserve retained dependency bytes: {error}"))?;
    let mut writer = StreamingObjectWriter::new(
        DigestRequest {
            raw_sha256: true,
            ..DigestRequest::default()
        },
        Some(key.signature.size),
    );
    let mut chunk = [0_u8; READ_CHUNK];
    while bytes.len() < size {
        checkpoint(stopped)?;
        let limit = chunk.len().min(size - bytes.len());
        let count = file
            .read(&mut chunk[..limit])
            .map_err(|error| format!("read retained dependency: {error}"))?;
        if count == 0 {
            return Err("dependency shrank during retention".into());
        }
        writer
            .write(&chunk[..count])
            .map_err(|error| format!("hash retained dependency: {error:?}"))?;
        bytes.extend_from_slice(&chunk[..count]);
    }
    checkpoint(stopped)?;
    if file
        .read(&mut chunk[..1])
        .map_err(|error| format!("finish retained dependency read: {error}"))?
        != 0
    {
        return Err("dependency grew during retention".into());
    }
    let digests = writer
        .finish()
        .map_err(|error| format!("seal retained dependency: {error:?}"))?;
    if digests.atp_content_id != key.digest {
        return Err("retained dependency bytes differ from the keyed content".into());
    }
    checkpoint(stopped)?;
    stable_file::verify(&file, path, key.signature)
        .map_err(|error| format!("recheck captured dependency: {error}"))?;
    Ok(RetainedDependencyArtifact {
        bytes,
        sha256: digests
            .raw_sha256
            .ok_or("retained dependency transport digest is missing")?
            .0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs::{self, FileTimes};
    use std::io::Seek;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Instant;

    const DEADLINE: Duration = Duration::from_secs(8);

    fn fixture() -> (tempfile::TempDir, PathBuf, Key, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("libinput.rmeta");
        let bytes = (0..READ_CHUNK * 3 + 17)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&path, &bytes).unwrap();
        let (signature, digest) = stable_file::digest_stable(&path).unwrap();
        (directory, path, Key { signature, digest }, bytes)
    }

    fn acquire(cache: &ArtifactCache, path: &Path, key: &Key) -> Arc<RetainedDependencyArtifact> {
        cache
            .acquire(path, key.signature, &key.digest, &|| false)
            .unwrap()
    }

    fn reads(cache: &ArtifactCache) -> usize {
        cache.0.captures.load(Ordering::Relaxed)
    }

    fn until(mut ready: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + DEADLINE;
        while !ready() {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(2));
        }
        true
    }

    #[derive(Default)]
    struct Gate {
        entered: AtomicBool,
        released: Mutex<bool>,
        changed: Condvar,
    }

    impl Gate {
        fn hold(&self) -> bool {
            if self.entered.swap(true, Ordering::AcqRel) {
                return false;
            }
            let (released, _) = self
                .changed
                .wait_timeout_while(self.released.lock().unwrap(), DEADLINE, |released| {
                    !*released
                })
                .unwrap();
            // A test failure must release the real reader within a deadline.
            !*released
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    #[test]
    fn unchanged_real_generation_reuses_one_byte_owner_and_both_digest_roles() {
        let (_directory, path, key, bytes) = fixture();
        let cache = ArtifactCache::new(key.signature.size * 2, 8);
        let first = acquire(&cache, &path, &key);
        let second = acquire(&cache, &path, &key);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(reads(&cache), 1);
        assert_eq!(first.bytes(), bytes);
        let raw: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(first.sha256(), raw);
        assert_eq!(
            first.sha256(),
            RetainedDependencyArtifact::from_bytes(bytes).sha256()
        );

        // A contradictory keyed digest cannot select an unrelated warm object.
        let mut wrong = key.digest.clone();
        wrong.bytes[0] ^= 1;
        assert!(
            cache
                .acquire(&path, key.signature, &wrong, &|| false)
                .is_err()
        );
        assert_eq!(reads(&cache), 2);
        assert!(Arc::ptr_eq(&first, &acquire(&cache, &path, &key)));
        let state = cache.0.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.bytes, key.signature.size);
    }

    #[test]
    fn hardlink_aliases_share_bytes_only_after_each_path_is_verified() {
        let (directory, path, _, bytes) = fixture();
        let alias = directory.path().join("libalias.rmeta");
        fs::hard_link(&path, &alias).unwrap();
        let (signature, digest) = stable_file::digest_stable(&path).unwrap();
        let key = Key { signature, digest };
        let cache = ArtifactCache::new(key.signature.size, 1);
        let first = acquire(&cache, &path, &key);
        assert!(Arc::ptr_eq(&first, &acquire(&cache, &alias, &key)));
        assert_eq!(reads(&cache), 1);
        fs::rename(&alias, directory.path().join("retained-alias")).unwrap();
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(
            cache
                .acquire(&alias, key.signature, &key.digest, &|| false)
                .is_err()
        );
        assert_eq!(first.bytes(), bytes);
    }

    #[test]
    fn warm_entries_cannot_hide_rewrites_or_equal_byte_inode_replacement() {
        for rewrite in [false, true] {
            let (directory, path, key, bytes) = fixture();
            let cache = ArtifactCache::new(key.signature.size * 2, 2);
            let retained = acquire(&cache, &path, &key);
            if rewrite {
                let times = fs::metadata(&path).unwrap();
                fs::write(&path, vec![99; bytes.len()]).unwrap();
                File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_times(FileTimes::new().set_modified(times.modified().unwrap()))
                    .unwrap();
            } else {
                fs::rename(&path, directory.path().join("old-inode")).unwrap();
                fs::write(&path, &bytes).unwrap();
            }
            assert!(
                cache
                    .acquire(&path, key.signature, &key.digest, &|| false)
                    .is_err()
            );
            assert_eq!(retained.bytes(), bytes);
            let (signature, digest) = stable_file::digest_stable(&path).unwrap();
            let fresh = acquire(&cache, &path, &Key { signature, digest });
            assert!(!Arc::ptr_eq(&retained, &fresh));
            assert_eq!(fresh.bytes(), fs::read(&path).unwrap());
        }
    }

    #[test]
    fn cancellation_after_a_real_chunk_releases_reservation_and_allows_retry() {
        let (_directory, path, key, bytes) = fixture();
        let cache = ArtifactCache::new(key.signature.size, 1);
        let file = stable_file::open(&path, key.signature).unwrap();
        // File::try_clone shares the actual descriptor offset. The cancellation
        // observes real read progress, rather than a synthetic accepted result
        // or a count of implementation checkpoints.
        let monitor = file.try_clone().unwrap();
        let result = cache.acquire_opened(file, &path, key.clone(), &|| {
            (&monitor).stream_position().unwrap() >= READ_CHUNK as u64
        });
        assert!(result.unwrap_err().contains("cancelled"));
        assert_eq!((&monitor).stream_position().unwrap(), READ_CHUNK as u64);
        {
            let state = cache.0.state.lock().unwrap();
            assert!(state.entries.is_empty());
            assert_eq!(state.bytes, 0);
        }
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(acquire(&cache, &path, &key).bytes(), bytes);
        assert_eq!(reads(&cache), 2);
    }

    #[test]
    fn mutation_during_real_capture_never_publishes_a_warm_owner() {
        let (_directory, path, key, bytes) = fixture();
        let cache = ArtifactCache::new(key.signature.size, 1);
        let file = stable_file::open(&path, key.signature).unwrap();
        let monitor = file.try_clone().unwrap();
        let changed = Cell::new(false);
        let result = cache.acquire_opened(file, &path, key, &|| {
            if (&monitor).stream_position().unwrap() >= READ_CHUNK as u64 && !changed.replace(true)
            {
                fs::write(&path, vec![87; bytes.len()]).unwrap();
            }
            false
        });
        assert!(changed.get());
        assert!(result.is_err());
        let state = cache.0.state.lock().unwrap();
        assert!(state.entries.is_empty());
        assert_eq!(state.bytes, 0);
    }

    #[test]
    fn real_overlapping_captures_coalesce_without_holding_the_cache_mutex() {
        let (_directory, path, key, bytes) = fixture();
        let cache = ArtifactCache::new(key.signature.size, 1);
        let gate = Gate::default();
        let file = stable_file::open(&path, key.signature).unwrap();
        let monitor = file.try_clone().unwrap();
        let polls: Vec<_> = (0..6).map(|_| AtomicUsize::new(0)).collect();
        thread::scope(|scope| {
            let owner = scope.spawn(|| {
                cache.acquire_opened(file, &path, key.clone(), &|| {
                    assert!(cache.0.state.try_lock().is_ok());
                    (&monitor).stream_position().unwrap() >= READ_CHUNK as u64 && gate.hold()
                })
            });
            assert!(until(|| gate.entered.load(Ordering::Acquire)));
            let waiters: Vec<_> = polls
                .iter()
                .map(|polls| {
                    scope.spawn(|| {
                        cache.acquire(&path, key.signature, &key.digest, &|| {
                            polls.fetch_add(1, Ordering::Relaxed);
                            false
                        })
                    })
                })
                .collect();
            let joined = until(|| polls.iter().all(|polls| polls.load(Ordering::Relaxed) >= 3));
            gate.release();
            assert!(joined, "all callers must actually wait on the real capture");
            let first = owner.join().unwrap().unwrap();
            for waiter in waiters {
                assert!(Arc::ptr_eq(&first, &waiter.join().unwrap().unwrap()));
            }
            assert_eq!(first.bytes(), bytes);
        });
        assert_eq!(reads(&cache), 1);
    }

    #[test]
    fn cancelling_one_waiter_does_not_cancel_the_real_capture() {
        let (_directory, path, key, bytes) = fixture();
        let cache = ArtifactCache::new(key.signature.size, 1);
        let gate = Gate::default();
        let cancelled = AtomicBool::new(false);
        let polls = AtomicUsize::new(0);
        let file = stable_file::open(&path, key.signature).unwrap();
        let monitor = file.try_clone().unwrap();
        thread::scope(|scope| {
            let owner = scope.spawn(|| {
                cache.acquire_opened(file, &path, key.clone(), &|| {
                    (&monitor).stream_position().unwrap() >= READ_CHUNK as u64 && gate.hold()
                })
            });
            assert!(until(|| gate.entered.load(Ordering::Acquire)));
            let waiter = scope.spawn(|| {
                cache.acquire(&path, key.signature, &key.digest, &|| {
                    polls.fetch_add(1, Ordering::Relaxed);
                    cancelled.load(Ordering::Acquire)
                })
            });
            let joined = until(|| polls.load(Ordering::Relaxed) >= 3);
            cancelled.store(true, Ordering::Release);
            let result = waiter.join().unwrap();
            gate.release();
            assert!(joined);
            assert!(result.unwrap_err().contains("cancelled"));
            let first = owner.join().unwrap().unwrap();
            assert!(Arc::ptr_eq(&first, &acquire(&cache, &path, &key)));
            assert_eq!(first.bytes(), bytes);
        });
        assert_eq!(reads(&cache), 1);
    }

    #[test]
    fn cancelled_capture_wakes_another_caller_to_capture_the_same_generation() {
        let (_directory, path, key, bytes) = fixture();
        let cache = ArtifactCache::new(key.signature.size, 1);
        let gate = Gate::default();
        let cancelled = AtomicBool::new(false);
        let polls = AtomicUsize::new(0);
        let file = stable_file::open(&path, key.signature).unwrap();
        let monitor = file.try_clone().unwrap();
        thread::scope(|scope| {
            let owner = scope.spawn(|| {
                cache.acquire_opened(file, &path, key.clone(), &|| {
                    if (&monitor).stream_position().unwrap() >= READ_CHUNK as u64 {
                        gate.hold() || cancelled.load(Ordering::Acquire)
                    } else {
                        false
                    }
                })
            });
            assert!(until(|| gate.entered.load(Ordering::Acquire)));
            let waiter = scope.spawn(|| {
                cache.acquire(&path, key.signature, &key.digest, &|| {
                    polls.fetch_add(1, Ordering::Relaxed);
                    false
                })
            });
            let joined = until(|| polls.load(Ordering::Relaxed) >= 3);
            cancelled.store(true, Ordering::Release);
            gate.release();
            assert!(joined);
            assert!(owner.join().unwrap().unwrap_err().contains("cancelled"));
            let retained = waiter.join().unwrap().unwrap();
            assert_eq!(retained.bytes(), bytes);
            assert!(Arc::ptr_eq(&retained, &acquire(&cache, &path, &key)));
        });
        assert_eq!(reads(&cache), 2);
    }

    #[test]
    fn leased_capacity_falls_back_and_evicts_only_after_release() {
        let directory = tempfile::tempdir().unwrap();
        let paths = [
            directory.path().join("liba.rmeta"),
            directory.path().join("libb.rmeta"),
        ];
        for (index, path) in paths.iter().enumerate() {
            fs::write(path, [index as u8; 8]).unwrap();
        }
        let keys: Vec<_> = paths
            .iter()
            .map(|path| {
                let (signature, digest) = stable_file::digest_stable(path).unwrap();
                Key { signature, digest }
            })
            .collect();
        let cache = ArtifactCache::new(8, 1);
        let leased = acquire(&cache, &paths[0], &keys[0]);
        let first_fallback = acquire(&cache, &paths[1], &keys[1]);
        let second_fallback = acquire(&cache, &paths[1], &keys[1]);
        assert!(!Arc::ptr_eq(&first_fallback, &second_fallback));
        assert!(Arc::ptr_eq(&leased, &acquire(&cache, &paths[0], &keys[0])));
        assert_eq!(reads(&cache), 3);
        {
            let state = cache.0.state.lock().unwrap();
            assert_eq!(state.bytes, 8);
            assert_eq!(state.entries.len(), 1);
            assert!(state.entries.contains_key(&keys[0]));
        }
        drop(leased);
        let retained = acquire(&cache, &paths[1], &keys[1]);
        assert!(Arc::ptr_eq(
            &retained,
            &acquire(&cache, &paths[1], &keys[1])
        ));
        assert_eq!(reads(&cache), 4);
        assert_eq!(first_fallback.bytes(), retained.bytes());
        assert_eq!(second_fallback.bytes(), retained.bytes());
        let state = cache.0.state.lock().unwrap();
        assert_eq!(state.bytes, 8);
        assert_eq!(state.entries.len(), 1);
        assert!(state.entries.contains_key(&keys[1]));
    }

    #[test]
    fn panic_cleanup_and_poisoned_advisory_state_never_supply_partial_bytes() {
        let (_directory, path, key, bytes) = fixture();
        let cache = ArtifactCache::new(key.signature.size, 1);
        let file = stable_file::open(&path, key.signature).unwrap();
        let monitor = file.try_clone().unwrap();
        let result = std::panic::catch_unwind(|| {
            cache.acquire_opened(file, &path, key.clone(), &|| {
                assert!(
                    (&monitor).stream_position().unwrap() < READ_CHUNK as u64,
                    "cancel callback panicked"
                );
                false
            })
        });
        assert!(result.is_err());
        assert!(cache.0.state.lock().unwrap().entries.is_empty());
        assert_eq!(acquire(&cache, &path, &key).bytes(), bytes);
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = cache.0.state.lock().unwrap();
            panic!("poison optional memo");
        });
        assert!(poisoned.is_err());
        assert_eq!(acquire(&cache, &path, &key).bytes(), bytes);
        assert_eq!(reads(&cache), 3);
    }
}
