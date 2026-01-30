//! Classification cache for repeated command decisions.
//!
//! This module provides an LRU cache with TTL expiration for caching
//! command classification results. This reduces CPU overhead when agents
//! run the same build/test commands repeatedly.
//!
//! # Design
//!
//! - **LRU eviction**: Least recently used entries are evicted when capacity is reached.
//! - **TTL expiration**: Entries expire after a configurable time (default 30s).
//! - **Config-aware**: Cache is invalidated when relevant config changes.
//!
//! # Thread Safety
//!
//! The cache uses `std::sync::Mutex` for thread safety. In practice, the hook
//! runs single-threaded per invocation, but the cache is global and may be
//! accessed across invocations in long-running processes.

use lru::LruCache;
use rch_common::Classification;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default cache capacity (number of entries).
const DEFAULT_CACHE_CAPACITY: usize = 1000;

/// Default TTL for cache entries (30 seconds).
const DEFAULT_TTL_SECS: u64 = 30;

/// A cached classification result with expiration timestamp.
#[derive(Debug, Clone)]
struct CachedClassification {
    /// The cached classification result.
    classification: Classification,
    /// When this entry was inserted.
    inserted_at: Instant,
    /// TTL for this entry.
    ttl: Duration,
}

impl CachedClassification {
    /// Check if this cached entry has expired.
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// Configuration for the classification cache.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in the cache.
    pub max_entries: usize,
    /// Time-to-live for cache entries.
    pub ttl: Duration,
    /// Whether the cache is enabled.
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_CACHE_CAPACITY,
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
            enabled: true,
        }
    }
}

/// An LRU cache with TTL expiration for command classifications.
pub struct ClassificationCache {
    cache: Mutex<LruCache<String, CachedClassification>>,
    config: CacheConfig,
    /// Tracks cache hits for metrics.
    hits: Mutex<u64>,
    /// Tracks cache misses for metrics.
    misses: Mutex<u64>,
}

impl ClassificationCache {
    /// Create a new classification cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        let capacity = NonZeroUsize::new(config.max_entries.max(1))
            .unwrap_or(NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            config,
            hits: Mutex::new(0),
            misses: Mutex::new(0),
        }
    }

    /// Create a new cache with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Get a cached classification for a command.
    ///
    /// Returns `None` if:
    /// - The command is not in the cache
    /// - The cached entry has expired
    /// - The cache is disabled
    pub fn get(&self, command: &str) -> Option<Classification> {
        if !self.config.enabled {
            return None;
        }

        // Use &str directly for lookup — LruCache supports Borrow<str> on
        // String keys, avoiding a String allocation on every cache probe.
        let key = command.trim();
        let mut cache = self.cache.lock().ok()?;

        // Check if entry exists and is not expired
        if let Some(entry) = cache.get(key) {
            if entry.is_expired() {
                // Remove expired entry
                cache.pop(key);
                if let Ok(mut misses) = self.misses.lock() {
                    *misses += 1;
                }
                tracing::trace!(command = %command, "Classification cache miss (expired)");
                None
            } else {
                if let Ok(mut hits) = self.hits.lock() {
                    *hits += 1;
                }
                tracing::trace!(command = %command, "Classification cache hit");
                Some(entry.classification.clone())
            }
        } else {
            if let Ok(mut misses) = self.misses.lock() {
                *misses += 1;
            }
            tracing::trace!(command = %command, "Classification cache miss");
            None
        }
    }

    /// Store a classification result in the cache.
    pub fn put(&self, command: &str, classification: Classification) {
        if !self.config.enabled {
            return;
        }

        // Only put() needs an owned String for the LRU key.
        let key = command.trim().to_string();
        let entry = CachedClassification {
            classification,
            inserted_at: Instant::now(),
            ttl: self.config.ttl,
        };

        if let Ok(mut cache) = self.cache.lock() {
            cache.put(key, entry);
            tracing::trace!(command = %command, "Classification cached");
        }
    }

    /// Clear the entire cache.
    #[allow(dead_code)] // Available for future cache invalidation
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// Get cache statistics.
    #[allow(dead_code)] // Available for future metrics integration
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.lock().map(|g| *g).unwrap_or(0);
        let misses = self.misses.lock().map(|g| *g).unwrap_or(0);
        let len = self.cache.lock().map(|c| c.len()).unwrap_or(0);

        CacheStats { hits, misses, len }
    }

}

impl Default for ClassificationCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Cache statistics for monitoring.
#[allow(dead_code)] // Available for future metrics integration
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Current number of entries in the cache.
    pub len: usize,
}

impl CacheStats {
    /// Calculate the hit rate as a percentage (0.0 - 100.0).
    #[allow(dead_code)] // Available for future metrics integration
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// Global classification cache instance.
///
/// This is initialized lazily on first use with default configuration.
static GLOBAL_CACHE: std::sync::OnceLock<ClassificationCache> = std::sync::OnceLock::new();

/// Get the global classification cache.
pub fn global_cache() -> &'static ClassificationCache {
    GLOBAL_CACHE.get_or_init(ClassificationCache::with_defaults)
}

/// Get a cached classification or compute it.
///
/// This is the main entry point for cached classification. It:
/// 1. Checks the cache for an existing result
/// 2. If not found, calls the classify function
/// 3. Stores the result in the cache
/// 4. Returns the classification
pub fn classify_cached<F>(command: &str, classify_fn: F) -> Classification
where
    F: FnOnce(&str) -> Classification,
{
    let cache = global_cache();

    // Try cache first
    if let Some(cached) = cache.get(command) {
        return cached;
    }

    // Compute and cache
    let classification = classify_fn(command);
    cache.put(command, classification.clone());
    classification
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::CompilationKind;
    use std::borrow::Cow;

    fn make_classification(is_compilation: bool) -> Classification {
        Classification {
            is_compilation,
            confidence: if is_compilation { 0.95 } else { 0.0 },
            kind: if is_compilation {
                Some(CompilationKind::CargoBuild)
            } else {
                None
            },
            reason: Cow::Borrowed("test"),
        }
    }

    #[test]
    fn test_cache_basic_operations() {
        let cache = ClassificationCache::with_defaults();

        // Initially empty
        assert!(cache.get("cargo build").is_none());

        // Store a classification
        let class = make_classification(true);
        cache.put("cargo build", class.clone());

        // Should be retrievable
        let cached = cache.get("cargo build");
        assert!(cached.is_some());
        assert!(cached.unwrap().is_compilation);

        // Different command should not be cached
        assert!(cache.get("cargo test").is_none());
    }

    #[test]
    fn test_cache_ttl_expiration() {
        let config = CacheConfig {
            max_entries: 100,
            ttl: Duration::from_millis(50), // Very short TTL for testing
            enabled: true,
        };
        let cache = ClassificationCache::new(config);

        let class = make_classification(true);
        cache.put("cargo build", class);

        // Should be cached immediately
        assert!(cache.get("cargo build").is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(60));

        // Should be expired now
        assert!(cache.get("cargo build").is_none());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let config = CacheConfig {
            max_entries: 2, // Very small cache
            ttl: Duration::from_secs(30),
            enabled: true,
        };
        let cache = ClassificationCache::new(config);

        // Fill the cache
        cache.put("cmd1", make_classification(true));
        cache.put("cmd2", make_classification(true));

        // Both should be present
        assert!(cache.get("cmd1").is_some());
        assert!(cache.get("cmd2").is_some());

        // Access cmd1 to make it most recently used
        cache.get("cmd1");

        // Add a third entry, should evict cmd2 (least recently used)
        cache.put("cmd3", make_classification(true));

        // cmd1 and cmd3 should be present, cmd2 evicted
        assert!(cache.get("cmd1").is_some());
        assert!(cache.get("cmd3").is_some());
        assert!(cache.get("cmd2").is_none());
    }

    #[test]
    fn test_cache_disabled() {
        let config = CacheConfig {
            max_entries: 100,
            ttl: Duration::from_secs(30),
            enabled: false,
        };
        let cache = ClassificationCache::new(config);

        let class = make_classification(true);
        cache.put("cargo build", class);

        // Should not be cached when disabled
        assert!(cache.get("cargo build").is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = ClassificationCache::with_defaults();

        // Initial stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.len, 0);

        // Miss
        cache.get("cargo build");
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);

        // Put and hit
        cache.put("cargo build", make_classification(true));
        cache.get("cargo build");
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.len, 1);
    }

    #[test]
    fn test_cache_key_normalization() {
        let cache = ClassificationCache::with_defaults();

        // Whitespace should be normalized
        cache.put("  cargo build  ", make_classification(true));
        assert!(cache.get("cargo build").is_some());
        assert!(cache.get("  cargo build  ").is_some());
    }

    #[test]
    fn test_classify_cached() {
        // Reset global cache state for this test
        let call_count = std::sync::atomic::AtomicUsize::new(0);

        let classify = |_cmd: &str| {
            call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            make_classification(true)
        };

        // First call should invoke the function
        let result = classify_cached("cargo build", classify);
        assert!(result.is_compilation);
        // Note: can't easily test call count with global cache,
        // but we can verify the result is correct
    }

    #[test]
    fn test_hit_rate_calculation() {
        let stats = CacheStats {
            hits: 80,
            misses: 20,
            len: 10,
        };
        assert!((stats.hit_rate() - 80.0).abs() < 0.001);

        let empty_stats = CacheStats::default();
        assert_eq!(empty_stats.hit_rate(), 0.0);
    }

    // ==================== Additional Coverage Tests ====================

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert_eq!(config.max_entries, DEFAULT_CACHE_CAPACITY);
        assert_eq!(config.ttl, Duration::from_secs(DEFAULT_TTL_SECS));
        assert!(config.enabled);
    }

    #[test]
    fn test_cache_config_clone() {
        let config = CacheConfig {
            max_entries: 500,
            ttl: Duration::from_secs(60),
            enabled: false,
        };

        let cloned = config.clone();
        assert_eq!(cloned.max_entries, 500);
        assert_eq!(cloned.ttl, Duration::from_secs(60));
        assert!(!cloned.enabled);
    }

    #[test]
    fn test_cache_config_debug() {
        let config = CacheConfig {
            max_entries: 100,
            ttl: Duration::from_secs(10),
            enabled: true,
        };

        let debug = format!("{:?}", config);
        assert!(debug.contains("max_entries"));
        assert!(debug.contains("100"));
        assert!(debug.contains("enabled"));
    }

    #[test]
    fn test_cache_stats_clone() {
        let stats = CacheStats {
            hits: 100,
            misses: 50,
            len: 25,
        };

        let cloned = stats.clone();
        assert_eq!(cloned.hits, 100);
        assert_eq!(cloned.misses, 50);
        assert_eq!(cloned.len, 25);
    }

    #[test]
    fn test_cache_stats_debug() {
        let stats = CacheStats {
            hits: 42,
            misses: 13,
            len: 10,
        };

        let debug = format!("{:?}", stats);
        assert!(debug.contains("hits"));
        assert!(debug.contains("42"));
        assert!(debug.contains("misses"));
        assert!(debug.contains("13"));
    }

    #[test]
    fn test_cache_stats_default() {
        let stats = CacheStats::default();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.len, 0);
        assert_eq!(stats.hit_rate(), 0.0);
    }

    #[test]
    fn test_classification_cache_default() {
        let cache = ClassificationCache::default();
        // Default cache should be enabled with default capacity
        let stats = cache.stats();
        assert_eq!(stats.len, 0);

        // Should be able to store and retrieve
        cache.put("test cmd", make_classification(true));
        assert!(cache.get("test cmd").is_some());
    }

    #[test]
    fn test_cache_clear() {
        let cache = ClassificationCache::with_defaults();

        // Add some entries
        cache.put("cmd1", make_classification(true));
        cache.put("cmd2", make_classification(true));
        cache.put("cmd3", make_classification(false));

        let stats = cache.stats();
        assert_eq!(stats.len, 3);

        // Clear the cache
        cache.clear();

        let stats = cache.stats();
        assert_eq!(stats.len, 0);

        // All entries should be gone
        assert!(cache.get("cmd1").is_none());
        assert!(cache.get("cmd2").is_none());
        assert!(cache.get("cmd3").is_none());
    }

    #[test]
    fn test_cache_zero_capacity() {
        // Zero capacity should be clamped to 1
        let config = CacheConfig {
            max_entries: 0,
            ttl: Duration::from_secs(30),
            enabled: true,
        };
        let cache = ClassificationCache::new(config);

        // Should still be able to cache one entry
        cache.put("cmd1", make_classification(true));
        assert!(cache.get("cmd1").is_some());

        // Adding another will evict the first
        cache.put("cmd2", make_classification(true));
        assert!(cache.get("cmd2").is_some());
        assert!(cache.get("cmd1").is_none());
    }

    #[test]
    fn test_global_cache_returns_same_instance() {
        let cache1 = global_cache();
        let cache2 = global_cache();

        // Should be the same instance (pointer equality)
        assert!(std::ptr::eq(cache1, cache2));
    }

    #[test]
    fn test_cache_hit_rate_various_scenarios() {
        // 50% hit rate
        let stats = CacheStats {
            hits: 50,
            misses: 50,
            len: 10,
        };
        assert!((stats.hit_rate() - 50.0).abs() < 0.001);

        // 100% hit rate
        let stats = CacheStats {
            hits: 100,
            misses: 0,
            len: 5,
        };
        assert!((stats.hit_rate() - 100.0).abs() < 0.001);

        // 0% hit rate
        let stats = CacheStats {
            hits: 0,
            misses: 100,
            len: 0,
        };
        assert!((stats.hit_rate() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_cache_put_overwrites_existing() {
        let cache = ClassificationCache::with_defaults();

        // Store initial classification
        let class1 = make_classification(true);
        cache.put("cmd", class1);

        let cached = cache.get("cmd").unwrap();
        assert!(cached.is_compilation);

        // Overwrite with different classification
        let class2 = make_classification(false);
        cache.put("cmd", class2);

        let cached = cache.get("cmd").unwrap();
        assert!(!cached.is_compilation);
    }

    #[test]
    fn test_cache_normalize_key_consistency() {
        let cache = ClassificationCache::with_defaults();

        // All these should normalize to the same key
        cache.put("  command  ", make_classification(true));
        assert!(cache.get("command").is_some());
        assert!(cache.get("  command").is_some());
        assert!(cache.get("command  ").is_some());
        assert!(cache.get("  command  ").is_some());

        // Stats should show only 1 entry
        let stats = cache.stats();
        assert_eq!(stats.len, 1);
    }

    #[test]
    fn test_cache_multiple_misses_tracked() {
        let cache = ClassificationCache::with_defaults();

        // Multiple misses on different commands
        cache.get("missing1");
        cache.get("missing2");
        cache.get("missing3");
        cache.get("missing4");
        cache.get("missing5");

        let stats = cache.stats();
        assert_eq!(stats.misses, 5);
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn test_cache_multiple_hits_tracked() {
        let cache = ClassificationCache::with_defaults();

        cache.put("cmd", make_classification(true));

        // Multiple hits on same command
        cache.get("cmd");
        cache.get("cmd");
        cache.get("cmd");

        let stats = cache.stats();
        assert_eq!(stats.hits, 3);
    }

    #[test]
    fn test_cached_classification_debug() {
        // Test CachedClassification Debug trait
        let entry = CachedClassification {
            classification: make_classification(true),
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(30),
        };

        let debug = format!("{:?}", entry);
        assert!(debug.contains("classification"));
        assert!(debug.contains("inserted_at"));
        assert!(debug.contains("ttl"));
    }

    #[test]
    fn test_cached_classification_clone() {
        let entry = CachedClassification {
            classification: make_classification(true),
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(60),
        };

        let cloned = entry.clone();
        assert_eq!(
            cloned.classification.is_compilation,
            entry.classification.is_compilation
        );
        assert_eq!(cloned.ttl, entry.ttl);
    }

    #[test]
    fn test_cached_classification_is_expired() {
        let entry = CachedClassification {
            classification: make_classification(true),
            inserted_at: Instant::now(),
            ttl: Duration::from_millis(10),
        };

        // Should not be expired immediately
        assert!(!entry.is_expired());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(15));

        // Should be expired now
        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_non_compilation_classification() {
        let cache = ClassificationCache::with_defaults();

        // Cache a non-compilation command
        let class = make_classification(false);
        cache.put("echo hello", class);

        let cached = cache.get("echo hello").unwrap();
        assert!(!cached.is_compilation);
        assert!(cached.kind.is_none());
    }
}
