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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

/// Includes a pending capture and invalidated images still held by requests.
/// Each image also retains the existing ToolchainLimits. This is an image-count
/// bound, not filesystem free-space admission or an on-disk quota.
pub(super) const CAPACITY: usize = 4;

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
pub(super) struct Cache<K, V> {
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
    pub(super) fn new(capacity: usize) -> Self {
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
    pub(super) fn poll(
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
    pub(super) fn invalidate(&mut self, key: &K, value: &Arc<V>) {
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
