//! Edge-local (L1) dependency-action-key cache (bead K003; plan Epic K;
//! the quantitative sub-ms metadata-lookup target).
//!
//! The edge consults the action cache for DEPENDENCY action keys on
//! every key resolution — the hottest read path in the system. The L2
//! metadata store (SQLite-compatible reference backend, FrankenSQLite
//! dogfood) is durable truth but pays query-planning and page costs on
//! every probe; the L1 keeps the hot working set of
//! [`ActionEntryRow`]s in process memory with read-through semantics
//! and MEASURED latency, so the bead's sub-ms-to-low-single-digit-ms
//! target is a property we observe, not one we assume.
//!
//! What may be cached and why it is safe:
//! - [`ActionEntryRow`] is (action key, key epoch, projection epoch) —
//!   immutable once published (publications are append-only identity;
//!   I10). Caching it cannot serve a stale DISPOSITION: serving/trust
//!   state lives in `serving_state`/`trust_evidence`, read through the
//!   store, never through this cache.
//! - Coherence: the edge routes its own `upsert_action_entry` through
//!   [`L1ActionCache::insert`] (write-through) and external writers are
//!   covered by the TTL plus explicit
//!   [`L1ActionCache::invalidate`]/[`L1ActionCache::invalidate_all`]
//!   hooks the edge already runs at generation-fence events.
//!
//! Bounded by construction: `capacity` is hard (FIFO eviction) — an
//! unbounded cache on a long-lived daemon is a leak with good PR.

use crate::metadata_store::{ActionEntryRow, StoreError};
use rabs_protocol::result_identity::TypedDigest;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// One latency sample class's bounded ring.
#[derive(Debug)]
struct LatencyRing {
    samples: Vec<u128>,
    next: usize,
    overflows: u64,
}

impl LatencyRing {
    const CAP: usize = 4096;

    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(Self::CAP),
            next: 0,
            overflows: 0,
        }
    }

    fn record(&mut self, nanos: u128) {
        if self.samples.len() < Self::CAP {
            self.samples.push(nanos);
        } else {
            self.samples[self.next] = nanos;
            self.next = (self.next + 1) % Self::CAP;
            self.overflows += 1;
        }
    }
}

/// Cumulative lookup statistics + latency percentiles.
///
/// Percentiles are over the most recent [`LatencyRing::CAP`] samples of
/// each class (a daemon's tail behavior matters more than its birth).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LookupStats {
    /// Lookups served from L1 (backend untouched).
    pub hits: u64,
    /// Lookups that reached the backend (absent or expired in L1).
    pub misses: u64,
    /// Backend answers of `None` (a true negative, still a miss).
    pub negatives: u64,
    /// Entries evicted by the capacity bound.
    pub evictions: u64,
    /// Entries dropped for exceeding their TTL.
    pub expired: u64,
    /// p50 hit latency, nanoseconds (0 when no samples).
    pub hit_p50_nanos: u128,
    /// p99 hit latency, nanoseconds (0 when no samples).
    pub hit_p99_nanos: u128,
    /// Max hit latency, nanoseconds (0 when no samples).
    pub hit_max_nanos: u128,
    /// p50 miss latency, nanoseconds (0 when no samples).
    pub miss_p50_nanos: u128,
    /// p99 miss latency, nanoseconds (0 when no samples).
    pub miss_p99_nanos: u128,
}
/// A cached action entry with its insertion stamp.
#[derive(Debug)]
struct Entry {
    row: ActionEntryRow,
    inserted_at: Instant,
}

/// Bounded L1 action-entry cache (edge-local; one per edge process).
#[derive(Debug)]
pub struct L1ActionCache {
    capacity: usize,
    ttl: Option<Duration>,
    entries: HashMap<TypedDigest, Entry>,
    /// FIFO eviction order (front = oldest insertion still present).
    order: VecDeque<TypedDigest>,
    hits: u64,
    misses: u64,
    negatives: u64,
    evictions: u64,
    expired: u64,
    hit_latencies: LatencyRing,
    miss_latencies: LatencyRing,
}

fn percentile(samples: &[u128], p: f64) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted: Vec<u128> = samples.to_vec();
    sorted.sort_unstable();
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

impl L1ActionCache {
    /// A cache holding at most `capacity` entries, each for at most
    /// `ttl` (None = until evicted/invalidated).
    ///
    /// # Panics
    /// Zero capacity would evict every insert immediately — refused.
    #[must_use]
    pub fn new(capacity: usize, ttl: Option<Duration>) -> Self {
        assert!(capacity > 0, "zero-capacity cache is an expensive no-op");
        Self {
            capacity,
            ttl,
            entries: HashMap::new(),
            order: VecDeque::new(),
            hits: 0,
            misses: 0,
            negatives: 0,
            evictions: 0,
            expired: 0,
            hit_latencies: LatencyRing::new(),
            miss_latencies: LatencyRing::new(),
        }
    }

    /// Read-through lookup for one dependency action key.
    ///
    /// L1 hit: returns the cached row, backend closure NOT invoked,
    /// hit latency recorded. L1 miss/expiry: invokes `backend` (the
    /// store's `lookup_action`), records miss latency, populates on
    /// `Some`. The closure receives the key by clone because the cache
    /// may outlive the borrow during eviction.
    pub fn lookup_through<E>(
        &mut self,
        key: &TypedDigest,
        mut backend: impl FnMut(&TypedDigest) -> Result<Option<ActionEntryRow>, E>,
    ) -> Result<Option<ActionEntryRow>, E> {
        let start = Instant::now();
        // Expired entries are misses, not hits.
        if let Some(entry) = self.entries.get(key) {
            let fresh = self.ttl.is_none_or(|ttl| entry.inserted_at.elapsed() < ttl);
            if fresh {
                self.hits += 1;
                self.hit_latencies.record(start.elapsed().as_nanos());
                return Ok(Some(entry.row.clone()));
            }
            self.entries.remove(key);
            self.expired += 1;
        }
        self.misses += 1;
        let backend_result = backend(key);
        let nanos = start.elapsed().as_nanos();
        self.miss_latencies.record(nanos);
        match backend_result? {
            Some(row) => {
                self.insert(key.clone(), row.clone());
                Ok(Some(row))
            }
            None => {
                self.negatives += 1;
                Ok(None)
            }
        }
    }

    /// Write-through insert (the edge's own `upsert_action_entry` path
    /// calls this AFTER the store write succeeds, so L1 can never be
    /// fresher than L2).
    pub fn insert(&mut self, key: TypedDigest, row: ActionEntryRow) {
        while self.entries.len() >= self.capacity {
            // FIFO: drop the oldest insertion still present.
            while let Some(oldest) = self.order.pop_front() {
                if self.entries.remove(&oldest).is_some() {
                    self.evictions += 1;
                    break;
                }
            }
        }
        self.entries.insert(
            key.clone(),
            Entry {
                row,
                inserted_at: Instant::now(),
            },
        );
        self.order.push_back(key);
    }

    /// Drop one key (generation-fence / external-write hooks).
    pub fn invalidate(&mut self, key: &TypedDigest) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Drop everything (authority change, lab reset).
    pub fn invalidate_all(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// Live entry count (never above `capacity`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot of counters + latency percentiles (for status surfaces
    /// and this bead's latency acceptance).
    #[must_use]
    pub fn stats(&self) -> LookupStats {
        LookupStats {
            hits: self.hits,
            misses: self.misses,
            negatives: self.negatives,
            evictions: self.evictions,
            expired: self.expired,
            hit_p50_nanos: percentile(&self.hit_latencies.samples, 50.0),
            hit_p99_nanos: percentile(&self.hit_latencies.samples, 99.0),
            hit_max_nanos: self
                .hit_latencies
                .samples
                .iter()
                .copied()
                .max()
                .unwrap_or(0),
            miss_p50_nanos: percentile(&self.miss_latencies.samples, 50.0),
            miss_p99_nanos: percentile(&self.miss_latencies.samples, 99.0),
        }
    }
}

/// Convenience alias so callers can express "the store's error type"
/// without naming [`StoreError`] twice in one signature.
pub type L1StoreError = StoreError;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn digest(n: u8) -> TypedDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        TypedDigest {
            algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes,
        }
    }

    fn row(n: u8) -> ActionEntryRow {
        ActionEntryRow {
            action_key: digest(n),
            key_epoch: 1,
            projection_epoch: 0,
        }
    }

    #[test]
    fn read_through_populates_and_second_lookup_skips_backend() {
        let mut cache = L1ActionCache::new(16, None);
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&backend_calls);

        let key = digest(1);
        let first = cache
            .lookup_through(&key, |k| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, StoreError>(Some(row(k.bytes[0])))
            })
            .expect("miss path");
        assert_eq!(first.as_ref().map(|r| r.action_key.bytes[0]), Some(1));
        assert_eq!(calls.load(Ordering::Relaxed), 1, "miss must hit backend");

        let second = cache
            .lookup_through(&key, |k| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, StoreError>(Some(row(k.bytes[0])))
            })
            .expect("hit path");
        assert_eq!(second, first);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "hit must NOT re-read backend"
        );
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn true_negatives_are_counted_and_not_cached_as_ghost_rows() {
        let mut cache = L1ActionCache::new(16, None);
        let key = digest(9);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let out = cache
            .lookup_through(&key, move |_k| {
                calls2.fetch_add(1, Ordering::Relaxed);
                Ok::<_, StoreError>(None)
            })
            .expect("negative");
        assert!(out.is_none());
        // A negative is NOT cached: next lookup consults the backend
        // again (the row may appear at any time).
        let _ = cache
            .lookup_through(&key, |_| Ok::<_, StoreError>(None))
            .expect("negative again");
        assert_eq!(calls.load(Ordering::Relaxed) + 1, 2);
        // BOTH backend probes returned None, so both count.
        assert_eq!(cache.stats().negatives, 2);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn ttl_expiry_forces_backend_reread() {
        let mut cache = L1ActionCache::new(16, Some(Duration::from_millis(20)));
        let key = digest(2);
        cache
            .lookup_through(&key, |_| Ok::<_, StoreError>(Some(row(2))))
            .expect("populate");
        assert_eq!(cache.stats().hits, 0);
        // Still fresh: a hit.
        cache
            .lookup_through(&key, |_| Ok::<_, StoreError>(Some(row(2))))
            .expect("fresh hit");
        assert_eq!(cache.stats().hits, 1);
        std::thread::sleep(Duration::from_millis(25));
        cache
            .lookup_through(&key, |_| Ok::<_, StoreError>(Some(row(2))))
            .expect("expired -> miss");
        assert_eq!(cache.stats().expired, 1);
        assert_eq!(cache.stats().misses, 2);
    }

    #[test]
    fn capacity_bound_holds_and_evicts_fifo() {
        let mut cache = L1ActionCache::new(4, None);
        for n in 0..6u8 {
            cache.insert(digest(n), row(n));
        }
        assert_eq!(cache.len(), 4, "capacity must be a hard bound");
        assert_eq!(cache.stats().evictions, 2);
        // FIFO: the two oldest (keys 0, 1) are gone; key 2 survives.
        assert!(cache.invalidate(&digest(2)), "key 2 should still live");
        assert!(!cache.invalidate(&digest(0)), "key 0 was evicted");
    }

    #[test]
    fn invalidate_all_clears_everything() {
        let mut cache = L1ActionCache::new(8, None);
        for n in 0..5u8 {
            cache.insert(digest(n), row(n));
        }
        cache.invalidate_all();
        assert!(cache.is_empty());
        assert_eq!(cache.stats().hits, 0);
    }

    #[test]
    fn latency_acceptance_hits_are_sub_millisecond_at_p99() {
        let mut cache = L1ActionCache::new(256, None);
        for n in 0..=255u8 {
            cache.insert(digest(n), row(n));
        }
        const ROUNDS: usize = 20_000;
        for round in 0..ROUNDS {
            let key = digest((round % 256) as u8);
            let hit = cache
                .lookup_through(&key, |_| Ok::<_, StoreError>(None))
                .expect("hit");
            assert!(hit.is_some());
        }
        let stats = cache.stats();
        assert_eq!(stats.hits, ROUNDS as u64);
        assert!(
            stats.hit_p99_nanos < 1_000_000,
            "p99 hit latency {}ns exceeds the 1ms target",
            stats.hit_p99_nanos
        );
        assert!(
            stats.hit_max_nanos < 10_000_000,
            "max hit latency {}ns exceeds even the scheduler-noise sanity \
             bound (p99 is the acceptance gate; a lone preemption spike \
             on a shared worker is not a cache property)",
            stats.hit_max_nanos
        );
    }

    #[test]
    fn latency_against_real_in_memory_sqlite_backend_meets_target() {
        // The honest version of the acceptance: misses measured against
        // the REAL reference backend (in-memory SQLite), hits from L1.
        use crate::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore};

        let engine = RusqliteEngine::open_in_memory().expect("in-memory engine");
        let mut store = SqlMetadataStore::open(engine).expect("metadata store");
        let mut cache = L1ActionCache::new(1024, None);

        // Seed 64 dependency action keys.
        for n in 0..64u8 {
            store
                .upsert_action_entry(&row(n))
                .expect("seed action entry");
        }

        // Cold pass (all misses), then hot pass (all hits).
        for n in 0..64u8 {
            let key = digest(n);
            cache
                .lookup_through(&key, |k| store.lookup_action(k))
                .expect("cold lookup")
                .expect("seeded row");
        }
        const HOT_ROUNDS: usize = 5_000;
        for round in 0..HOT_ROUNDS {
            let key = digest((round % 64) as u8);
            cache
                .lookup_through(&key, |k| store.lookup_action(k))
                .expect("hot lookup")
                .expect("seeded row");
        }
        let stats = cache.stats();
        assert!(
            stats.miss_p99_nanos < 10_000_000,
            "p99 MISS latency {}ns exceeds the low-single-digit-ms target",
            stats.miss_p99_nanos
        );
        assert!(
            stats.hit_p99_nanos < 1_000_000,
            "p99 hit latency {}ns exceeds the 1ms target",
            stats.hit_p99_nanos
        );
    }
}
