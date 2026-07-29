//! Build-timing history and offload-gating estimation.
//!
//! Persists per-project/kind build durations (ring-buffered, LRU-capped)
//! to `~/.cache/rch/timing_history.json` and reads them back to estimate
//! local build time + expected speedup for offload gating.
//!
//! Principal items: [`record_build_timing`] (the live write path, called
//! from the remote-classification path after every offloaded build) and the
//! estimator surface ([`estimate_timing_for_build`] / [`TimingEstimate`],
//! currently exercised only by tests). [`TimingHistory`] / [`ProjectTimingData`]
//! / [`TimingRecord`] are the on-disk model; [`timing_cache`] is the
//! process-global `OnceLock` that coalesces disk I/O within a process.
use super::*;

// ============================================================================
// Timing History (bd-2m7j Phase 2)
// ============================================================================

use std::collections::HashMap;

// Timing infrastructure: feeds the global `TIMING_CACHE` (live; populated
// by `record_build_timing` after every offloaded build). The estimator
// surface that consumes the cache (`estimate_timing_for_build`,
// `TimingEstimate`) is currently exercised only by unit tests — those
// items keep `#[allow(dead_code)]` until production callers materialize.
//
// `MAX_TIMING_SAMPLES` bounds the per-project sample ring buffer (enforced in
// `ProjectTimingData::add_sample`). `MAX_TIMING_PROJECTS` bounds the
// project-keyed map for LRU-eviction (enforced in `TimingHistory::record`).
pub(super) const MAX_TIMING_SAMPLES: usize = 20;

const MAX_TIMING_PROJECTS: usize = 500;

/// A single timing record for a completed build.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TimingRecord {
    /// Timestamp when the build completed (Unix seconds).
    pub timestamp: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Whether this was a remote build (true) or local (false).
    pub remote: bool,
}

/// Timing data for a specific project+kind combination.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct ProjectTimingData {
    /// Recent local build durations (ring buffer).
    pub local_samples: Vec<TimingRecord>,
    /// Recent remote build durations (ring buffer).
    pub remote_samples: Vec<TimingRecord>,
}

#[allow(dead_code)]
impl ProjectTimingData {
    /// Add a timing sample, maintaining ring buffer size.
    pub(super) fn add_sample(&mut self, duration_ms: u64, remote: bool) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = TimingRecord {
            timestamp,
            duration_ms,
            remote,
        };

        let samples = if remote {
            &mut self.remote_samples
        } else {
            &mut self.local_samples
        };

        samples.push(record);
        if samples.len() > MAX_TIMING_SAMPLES {
            samples.remove(0);
        }
    }

    /// Calculate median duration from samples.
    pub(super) fn median_duration(&self, remote: bool) -> Option<u64> {
        let samples = if remote {
            &self.remote_samples
        } else {
            &self.local_samples
        };

        if samples.is_empty() {
            return None;
        }

        let mut durations: Vec<u64> = samples.iter().map(|r| r.duration_ms).collect();
        durations.sort_unstable();
        let mid = durations.len() / 2;
        Some(if durations.len().is_multiple_of(2) {
            (durations[mid - 1] + durations[mid]) / 2
        } else {
            durations[mid]
        })
    }

    /// Calculate speedup ratio (local_time / remote_time).
    pub(super) fn speedup_ratio(&self) -> Option<f64> {
        let local_median = self.median_duration(false)?;
        let remote_median = self.median_duration(true)?;
        if remote_median == 0 {
            return None;
        }
        Some(local_median as f64 / remote_median as f64)
    }

    /// Get the most recent timestamp from any sample (used for LRU eviction).
    fn most_recent_timestamp(&self) -> u64 {
        let local_max = self
            .local_samples
            .iter()
            .map(|r| r.timestamp)
            .max()
            .unwrap_or(0);
        let remote_max = self
            .remote_samples
            .iter()
            .map(|r| r.timestamp)
            .max()
            .unwrap_or(0);
        local_max.max(remote_max)
    }
}

/// Full timing history, keyed by project+kind.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct TimingHistory {
    /// Map from "project_id:kind" to timing data.
    #[serde(default)]
    pub entries: HashMap<String, ProjectTimingData>,
}

/// Process-global in-memory cache for `TimingHistory`.
///
/// **Lifetime:** the hook is a fresh process per invocation, so the cache
/// is rebuilt at the start of every hook call. Within a single hook call
/// (or within `rchd` / a long-running `rch exec` session), `record_build_timing`
/// can fire multiple times across `tokio::task::spawn_blocking` blocks; the
/// `OnceLock` coalesces disk I/O for that batch — first call pays the
/// `load_from_disk` cost; subsequent calls in the same process operate on
/// the in-memory copy and write through to disk on update.
///
/// Consumers (live as of t19 close): two `record_build_timing` call sites
/// in `hook::handle_selection_response`. The estimator surface
/// (`estimate_timing_for_build`, `TimingEstimate`) is currently exercised
/// only by unit tests; those keep their `#[allow(dead_code)]` annotation
/// until a production consumer wires them up.
static TIMING_CACHE: std::sync::OnceLock<std::sync::RwLock<TimingHistory>> =
    std::sync::OnceLock::new();

/// Get or initialize the global `TimingHistory` cache.
///
/// First call loads from disk (blocking); subsequent calls in the same
/// process return the cached copy.
pub(super) fn timing_cache() -> &'static std::sync::RwLock<TimingHistory> {
    TIMING_CACHE.get_or_init(|| std::sync::RwLock::new(TimingHistory::load_from_disk()))
}

impl TimingHistory {
    /// Load timing history from disk. Returns empty history on error.
    fn load_from_disk() -> Self {
        let Some(path) = timing_history_path() else {
            return Self::default();
        };

        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save timing history to disk. Logs warnings on error but does not propagate.
    fn save_to_disk(&self) {
        let Some(path) = timing_history_path() else {
            return;
        };

        // Ensure parent directory exists
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            warn!(
                "Failed to create timing history directory {}: {}",
                parent.display(),
                e
            );
            return;
        }

        // Write atomically using temp file
        let temp_path = path.with_extension("tmp");
        let content = match serde_json::to_string_pretty(self) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to serialize timing history: {}", e);
                return;
            }
        };
        if let Err(e) = std::fs::write(&temp_path, &content) {
            warn!(
                "Failed to write timing history to {}: {}",
                temp_path.display(),
                e
            );
            return;
        }
        if let Err(e) = std::fs::rename(&temp_path, &path) {
            warn!(
                "Failed to rename timing history {} -> {}: {}",
                temp_path.display(),
                path.display(),
                e
            );
        }
    }

    /// Get the key for a project+kind combination.
    pub(super) fn key(project: &str, kind: Option<CompilationKind>) -> String {
        let kind_str = kind
            .map(|k| format!("{:?}", k))
            .unwrap_or_else(|| "Unknown".to_string());
        format!("{}:{}", project, kind_str)
    }

    /// Get timing data for a project+kind.
    pub(super) fn get(
        &self,
        project: &str,
        kind: Option<CompilationKind>,
    ) -> Option<&ProjectTimingData> {
        self.entries.get(&Self::key(project, kind))
    }

    /// Record a timing sample.
    ///
    /// Implements LRU eviction to prevent unbounded memory growth:
    /// if entries exceed MAX_TIMING_PROJECTS, evicts the least recently used entry.
    pub(super) fn record(
        &mut self,
        project: &str,
        kind: Option<CompilationKind>,
        duration_ms: u64,
        remote: bool,
    ) {
        let key = Self::key(project, kind);
        let data = self.entries.entry(key).or_default();
        data.add_sample(duration_ms, remote);

        // LRU eviction: if over limit, remove the entry with oldest timestamp
        if self.entries.len() > MAX_TIMING_PROJECTS {
            // Find the key with the oldest most_recent_timestamp
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, data)| data.most_recent_timestamp())
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
    }
}

/// Get the path to the timing history file.
fn timing_history_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("rch").join("timing_history.json"))
}

/// Record a build timing to the history store.
///
/// Updates the in-memory cache immediately, then persists to disk.
/// Called after a build completes to update the timing history.
/// This is used by `estimate_timing_for_build` for future predictions.
///
/// **Lock-scope discipline (t18):** we acquire the write guard, mutate
/// the in-memory state, CLONE a snapshot, drop the guard, THEN write
/// to disk. The original implementation held the write guard across
/// `save_to_disk()` which serialized every other reader/writer on a
/// disk-I/O (~50ms on slow disks) — fine when nothing else needed the
/// cache, catastrophic under any concurrent access. The clone cost is
/// bounded by `MAX_TIMING_PROJECTS` (500) × `MAX_TIMING_SAMPLES` (20)
/// = at most ~10K small structs; ~µs vs the lock contention's ms.
pub(super) fn record_build_timing(
    project: &str,
    kind: Option<CompilationKind>,
    duration_ms: u64,
    remote: bool,
) {
    let cache = timing_cache();
    // Step 1: mutate in-memory state under the write guard. Snapshot
    // for disk persistence. Then drop the guard before any I/O.
    let snapshot = {
        let mut history = match cache.write() {
            Ok(g) => g,
            Err(poison) => {
                // Poisoned RwLock — another caller panicked while
                // holding the write guard. Recover the value and
                // continue; failing here would deny the build a
                // timing record but isn't worth blocking the user.
                tracing::warn!(
                    target: "rch::hook::timing",
                    "timing cache RwLock poisoned; recovering"
                );
                poison.into_inner()
            }
        };
        history.record(project, kind, duration_ms, remote);
        history.clone()
        // guard dropped here
    };
    // Step 2: persist to disk WITHOUT holding the lock. Other readers
    // and writers can proceed in parallel with the fsync.
    snapshot.save_to_disk();
}

/// Timing estimate for offload gating decisions.
///
/// Used to determine whether a build is worth offloading based on
/// predicted local execution time and expected speedup.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(super) struct TimingEstimate {
    /// Predicted local build time in milliseconds.
    pub predicted_local_ms: u64,
    /// Predicted speedup ratio (local_time / remote_time), if available.
    /// None indicates insufficient data to estimate speedup.
    pub predicted_speedup: Option<f64>,
}

/// Estimate timing for a build to support offload gating.
///
/// This function attempts to estimate how long a build would take locally
/// and what speedup we might achieve by offloading. The estimation uses
/// this fallback order:
/// 1. Historical timing data for this project/kind
/// 2. Conservative defaults (allow offload)
///
/// When no historical data is available, returns None to trigger fail-open
/// behavior (allow offload attempt).
#[allow(dead_code)]
#[allow(unused_variables)] // config used for future speedscore integration
pub(super) fn estimate_timing_for_build(
    project: &str,
    kind: Option<CompilationKind>,
    config: &rch_common::RchConfig,
) -> Option<TimingEstimate> {
    // Read from in-memory cache (zero disk I/O after first load)
    let cache = timing_cache();
    let history = cache.read().ok()?;

    // Look up timing data for this project+kind
    let data = history.get(project, kind)?;

    // Need at least local samples to estimate
    let local_median = data.median_duration(false)?;

    // Speedup is optional (requires both local and remote history)
    let speedup = data.speedup_ratio();

    Some(TimingEstimate {
        predicted_local_ms: local_median,
        predicted_speedup: speedup,
    })
}
