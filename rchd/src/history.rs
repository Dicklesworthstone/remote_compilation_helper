//! Build history tracking.
//!
//! Maintains a ring buffer of recent builds for status reporting and analytics.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::{BuildLocation, BuildRecord, BuildStats, CommandTimingBreakdown, SavedTimeStats};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::fs::OpenOptions as AsyncOpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

/// Default maximum number of builds to retain.
const DEFAULT_CAPACITY: usize = 100;

/// In-flight build state tracked for active build visibility.
#[derive(Debug, Clone)]
pub struct ActiveBuildState {
    pub id: u64,
    pub project_id: String,
    pub worker_id: String,
    pub command: String,
    pub started_at: String,
    pub started_at_mono: Instant,
    pub hook_pid: u32,
    pub slots: u32,
    pub location: BuildLocation,
}

/// Queued build state for builds waiting for available workers.
///
/// When all workers are busy and `queue_when_busy` is enabled,
/// builds are queued here instead of falling back to local execution.
#[derive(Debug, Clone)]
pub struct QueuedBuildState {
    /// Queue position ID (monotonically increasing).
    pub id: u64,
    /// Project identifier (hash or path).
    pub project_id: String,
    /// Command to execute.
    pub command: String,
    /// When the build was queued (ISO 8601).
    pub queued_at: String,
    /// Monotonic timestamp for duration calculations.
    pub queued_at_mono: Instant,
    /// Hook process ID (for cancellation).
    pub hook_pid: u32,
    /// Number of slots needed.
    pub slots_needed: u32,
    /// Estimated start time (ISO 8601), updated as queue advances.
    pub estimated_start: Option<String>,
}

/// Build history manager.
///
/// Thread-safe ring buffer of recent builds with optional persistence.
pub struct BuildHistory {
    /// Ring buffer of recent builds.
    records: RwLock<VecDeque<BuildRecord>>,
    /// Active builds (in-flight).
    active: RwLock<HashMap<u64, ActiveBuildState>>,
    /// Queued builds (waiting for workers).
    queued: RwLock<VecDeque<QueuedBuildState>>,
    /// Maximum capacity for history.
    capacity: usize,
    /// Maximum queue depth (0 = unlimited).
    max_queue_depth: usize,
    /// Next build ID.
    next_id: AtomicU64,
    /// Next queue ID.
    next_queue_id: AtomicU64,
    /// Persistence path (optional).
    persistence_path: Option<PathBuf>,
}

/// Default maximum queue depth.
const DEFAULT_MAX_QUEUE_DEPTH: usize = 100;

impl BuildHistory {
    /// Create a new build history with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            records: RwLock::new(VecDeque::with_capacity(capacity)),
            active: RwLock::new(HashMap::new()),
            queued: RwLock::new(VecDeque::new()),
            capacity,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            next_id: AtomicU64::new(1),
            next_queue_id: AtomicU64::new(1),
            persistence_path: None,
        }
    }

    /// Create a new build history with default capacity.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Set the maximum queue depth.
    pub fn with_max_queue_depth(mut self, depth: usize) -> Self {
        self.max_queue_depth = depth;
        self
    }

    /// Enable persistence to the given path.
    pub fn with_persistence(mut self, path: PathBuf) -> Self {
        self.persistence_path = Some(path);
        self
    }

    /// Get the next build ID.
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Record a completed build.
    ///
    /// Returns a handle to the persistence task if persistence is enabled.
    pub fn record(&self, record: BuildRecord) -> Option<tokio::task::JoinHandle<()>> {
        debug!(
            "Recording build {}: {} ({:?}, {} ms)",
            record.id, record.command, record.location, record.duration_ms
        );

        // Prepare for persistence before locking
        let persistence_task = self
            .persistence_path
            .as_ref()
            .map(|path| (path.clone(), record.clone()));

        // Update memory state under lock
        {
            let mut records = self.records.write().unwrap();

            // Evict oldest if at capacity
            if records.len() >= self.capacity {
                records.pop_front();
            }

            records.push_back(record);
        }

        // Persist asynchronously (fire and forget or awaitable)
        if let Some((path, record)) = persistence_task {
            Some(tokio::spawn(async move {
                if let Err(e) = Self::persist_record_async(&path, &record).await {
                    warn!("Failed to persist build record: {}", e);
                }
            }))
        } else {
            None
        }
    }

    /// Register a new active build and return its state.
    pub fn start_active_build(
        &self,
        project_id: String,
        worker_id: String,
        command: String,
        hook_pid: u32,
        slots: u32,
        location: BuildLocation,
    ) -> ActiveBuildState {
        let id = self.next_id();
        let started_at = Utc::now().to_rfc3339();
        let state = ActiveBuildState {
            id,
            project_id,
            worker_id,
            command,
            started_at,
            started_at_mono: Instant::now(),
            hook_pid,
            slots,
            location,
        };

        let mut active = self.active.write().unwrap();
        active.insert(id, state.clone());
        state
    }

    /// Complete an active build, moving it into history.
    pub fn finish_active_build(
        &self,
        build_id: u64,
        exit_code: i32,
        duration_ms: Option<u64>,
        bytes_transferred: Option<u64>,
        timing: Option<CommandTimingBreakdown>,
    ) -> Option<BuildRecord> {
        let state = {
            let mut active = self.active.write().unwrap();
            active.remove(&build_id)
        }?;

        let duration_ms =
            duration_ms.unwrap_or_else(|| state.started_at_mono.elapsed().as_millis() as u64);
        let record = BuildRecord {
            id: state.id,
            started_at: state.started_at,
            completed_at: Utc::now().to_rfc3339(),
            project_id: state.project_id,
            worker_id: Some(state.worker_id),
            command: state.command,
            exit_code,
            duration_ms,
            location: state.location,
            bytes_transferred,
            timing,
        };

        self.record(record.clone());
        Some(record)
    }

    /// Cancel an active build, moving it into history with a cancel exit code.
    pub fn cancel_active_build(
        &self,
        build_id: u64,
        bytes_transferred: Option<u64>,
    ) -> Option<BuildRecord> {
        let state = {
            let mut active = self.active.write().unwrap();
            active.remove(&build_id)
        }?;

        let duration_ms = state.started_at_mono.elapsed().as_millis() as u64;
        let record = BuildRecord {
            id: state.id,
            started_at: state.started_at,
            completed_at: Utc::now().to_rfc3339(),
            project_id: state.project_id,
            worker_id: Some(state.worker_id),
            command: state.command,
            exit_code: 130,
            duration_ms,
            location: state.location,
            bytes_transferred,
            timing: None,
        };

        self.record(record.clone());
        Some(record)
    }

    /// Get a specific active build by ID.
    pub fn active_build(&self, build_id: u64) -> Option<ActiveBuildState> {
        self.active.read().unwrap().get(&build_id).cloned()
    }

    /// Get all active builds.
    pub fn active_builds(&self) -> Vec<ActiveBuildState> {
        self.active.read().unwrap().values().cloned().collect()
    }

    // =========================================================================
    // Queue Management
    // =========================================================================

    /// Get the next queue ID.
    pub fn next_queue_id(&self) -> u64 {
        self.next_queue_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Enqueue a build waiting for an available worker.
    ///
    /// Returns `None` if the queue is full (when max_queue_depth > 0).
    pub fn enqueue_build(
        &self,
        project_id: String,
        command: String,
        hook_pid: u32,
        slots_needed: u32,
    ) -> Option<QueuedBuildState> {
        let mut queue = self.queued.write().unwrap();

        // Check queue depth limit
        if self.max_queue_depth > 0 && queue.len() >= self.max_queue_depth {
            debug!(
                "Queue full ({}/{}), rejecting build for {}",
                queue.len(),
                self.max_queue_depth,
                project_id
            );
            return None;
        }

        let id = self.next_queue_id();
        let queued_at = Utc::now().to_rfc3339();
        let state = QueuedBuildState {
            id,
            project_id,
            command,
            queued_at,
            queued_at_mono: Instant::now(),
            hook_pid,
            slots_needed,
            estimated_start: None,
        };

        queue.push_back(state.clone());
        debug!(
            "Build queued: id={}, position={}, project={}",
            id,
            queue.len(),
            state.project_id
        );

        Some(state)
    }

    /// Dequeue the next build (FIFO).
    ///
    /// Called when a worker becomes available.
    pub fn dequeue_build(&self) -> Option<QueuedBuildState> {
        let mut queue = self.queued.write().unwrap();
        let state = queue.pop_front()?;
        debug!(
            "Build dequeued: id={}, waited {:?}, project={}",
            state.id,
            state.queued_at_mono.elapsed(),
            state.project_id
        );
        Some(state)
    }

    /// Remove a specific queued build by ID (e.g., for cancellation).
    pub fn remove_queued_build(&self, queue_id: u64) -> Option<QueuedBuildState> {
        let mut queue = self.queued.write().unwrap();
        let pos = queue.iter().position(|b| b.id == queue_id)?;
        queue.remove(pos)
    }

    /// Remove a queued build by hook PID.
    pub fn remove_queued_build_by_pid(&self, hook_pid: u32) -> Option<QueuedBuildState> {
        let mut queue = self.queued.write().unwrap();
        let pos = queue.iter().position(|b| b.hook_pid == hook_pid)?;
        queue.remove(pos)
    }

    /// Get all queued builds (in queue order).
    pub fn queued_builds(&self) -> Vec<QueuedBuildState> {
        self.queued.read().unwrap().iter().cloned().collect()
    }

    /// Get a specific queued build by ID.
    pub fn queued_build(&self, queue_id: u64) -> Option<QueuedBuildState> {
        self.queued
            .read()
            .unwrap()
            .iter()
            .find(|b| b.id == queue_id)
            .cloned()
    }

    /// Get the queue position of a build (1-indexed, None if not found).
    pub fn queue_position(&self, queue_id: u64) -> Option<usize> {
        self.queued
            .read()
            .unwrap()
            .iter()
            .position(|b| b.id == queue_id)
            .map(|p| p + 1)
    }

    /// Get the current queue depth.
    pub fn queue_depth(&self) -> usize {
        self.queued.read().unwrap().len()
    }

    /// Check if the queue is empty.
    pub fn queue_is_empty(&self) -> bool {
        self.queued.read().unwrap().is_empty()
    }

    /// Update estimated start times for all queued builds.
    ///
    /// Uses average build duration from history and active build state.
    pub fn update_queue_estimates(&self) {
        let avg_duration = self.stats().avg_duration_ms;
        let active_count = self.active.read().unwrap().len();

        let mut queue = self.queued.write().unwrap();

        // Estimate when each queued build will start
        let now = Utc::now();
        for (i, build) in queue.iter_mut().enumerate() {
            // Simple estimate: position * avg_duration, adjusted for active builds
            let position = i + 1;
            let wait_ms = if active_count > 0 {
                // Assume active builds are half-done on average
                let remaining_active_ms = (avg_duration / 2) as i64;
                let queue_wait_ms = (position as u64 * avg_duration) as i64;
                remaining_active_ms + queue_wait_ms
            } else {
                0 // No active builds, next in queue starts immediately
            };

            let estimated = now + chrono::Duration::milliseconds(wait_ms.max(0));
            build.estimated_start = Some(estimated.to_rfc3339());
        }
    }

    /// Get recent builds (most recent first).
    pub fn recent(&self, limit: usize) -> Vec<BuildRecord> {
        let records = self.records.read().unwrap();
        records.iter().rev().take(limit).cloned().collect()
    }

    /// Get all builds (most recent first).
    pub fn all(&self) -> Vec<BuildRecord> {
        let records = self.records.read().unwrap();
        records.iter().rev().cloned().collect()
    }

    /// Get builds by worker (most recent first).
    pub fn by_worker(&self, worker_id: &str, limit: usize) -> Vec<BuildRecord> {
        let records = self.records.read().unwrap();
        records
            .iter()
            .rev()
            .filter(|r| r.worker_id.as_deref() == Some(worker_id))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get builds by project (most recent first).
    pub fn by_project(&self, project_id: &str, limit: usize) -> Vec<BuildRecord> {
        let records = self.records.read().unwrap();
        records
            .iter()
            .rev()
            .filter(|r| r.project_id == project_id)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get aggregate statistics.
    pub fn stats(&self) -> BuildStats {
        let records = self.records.read().unwrap();
        let total = records.len();

        if total == 0 {
            return BuildStats::default();
        }

        let successes = records.iter().filter(|r| r.exit_code == 0).count();
        let remote = records
            .iter()
            .filter(|r| r.location == BuildLocation::Remote)
            .count();
        let total_duration: u64 = records.iter().map(|r| r.duration_ms).sum();
        let avg_duration = total_duration / total as u64;

        BuildStats {
            total_builds: total,
            success_count: successes,
            failure_count: total - successes,
            remote_count: remote,
            local_count: total - remote,
            avg_duration_ms: avg_duration,
        }
    }

    /// Calculate saved time statistics from remote builds.
    ///
    /// Uses local build history to estimate what remote builds would have taken
    /// locally, then computes time saved. If no local builds exist, uses a
    /// default speedup factor (2.0x) based on typical remote worker performance.
    pub fn saved_time_stats(&self) -> SavedTimeStats {
        const DEFAULT_SPEEDUP: f64 = 2.0;

        let records = self.records.read().unwrap();
        let now = Utc::now();
        let today_start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
        let week_start = today_start - ChronoDuration::days(7);

        // Separate local and remote builds
        let local_builds: Vec<_> = records
            .iter()
            .filter(|r| r.location == BuildLocation::Local && r.exit_code == 0)
            .collect();
        let remote_builds: Vec<_> = records
            .iter()
            .filter(|r| r.location == BuildLocation::Remote && r.exit_code == 0)
            .collect();

        if remote_builds.is_empty() {
            return SavedTimeStats::default();
        }

        // Calculate average local build duration (if we have local builds)
        let avg_local_duration_ms = if !local_builds.is_empty() {
            let total_local: u64 = local_builds.iter().map(|r| r.duration_ms).sum();
            total_local / local_builds.len() as u64
        } else {
            0
        };

        // Calculate totals and time saved
        let mut total_remote_duration_ms: u64 = 0;
        let mut estimated_local_duration_ms: u64 = 0;
        let mut today_remote_ms: u64 = 0;
        let mut today_estimated_local_ms: u64 = 0;
        let mut week_remote_ms: u64 = 0;
        let mut week_estimated_local_ms: u64 = 0;

        for build in &remote_builds {
            let remote_ms = build.duration_ms;
            total_remote_duration_ms += remote_ms;

            // Estimate local duration: use exec time * speedup or avg_local
            let estimated_local_ms = if avg_local_duration_ms > 0 {
                // Use the ratio of this build's exec time to average, then scale
                avg_local_duration_ms
            } else {
                // No local builds: use remote exec time * default speedup
                (remote_ms as f64 * DEFAULT_SPEEDUP) as u64
            };
            estimated_local_duration_ms += estimated_local_ms;

            // Parse timestamp for daily/weekly aggregation
            if let Ok(completed) = DateTime::parse_from_rfc3339(&build.completed_at) {
                let completed_naive = completed.naive_utc();
                if completed_naive >= today_start.and_utc().naive_utc() {
                    today_remote_ms += remote_ms;
                    today_estimated_local_ms += estimated_local_ms;
                }
                if completed_naive >= week_start.and_utc().naive_utc() {
                    week_remote_ms += remote_ms;
                    week_estimated_local_ms += estimated_local_ms;
                }
            }
        }

        let time_saved_ms = estimated_local_duration_ms.saturating_sub(total_remote_duration_ms);
        let today_saved_ms = today_estimated_local_ms.saturating_sub(today_remote_ms);
        let week_saved_ms = week_estimated_local_ms.saturating_sub(week_remote_ms);

        let avg_speedup = if total_remote_duration_ms > 0 {
            estimated_local_duration_ms as f64 / total_remote_duration_ms as f64
        } else {
            0.0
        };

        SavedTimeStats {
            total_remote_duration_ms,
            estimated_local_duration_ms,
            time_saved_ms,
            builds_counted: remote_builds.len(),
            avg_speedup,
            today_saved_ms,
            week_saved_ms,
        }
    }

    /// Get the number of builds in history.
    pub fn len(&self) -> usize {
        self.records.read().unwrap().len()
    }

    /// Check if history is empty.
    pub fn is_empty(&self) -> bool {
        self.records.read().unwrap().is_empty()
    }

    /// Clear all build records.
    #[allow(dead_code)] // May be used for testing or admin operations
    pub fn clear(&self) {
        let mut records = self.records.write().unwrap();
        records.clear();
    }

    /// Load history from a JSONL file.
    pub fn load_from_file(path: &Path, capacity: usize) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut records = VecDeque::with_capacity(capacity);
        let mut max_id = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<BuildRecord>(&line) {
                Ok(record) => {
                    max_id = max_id.max(record.id);
                    if records.len() >= capacity {
                        records.pop_front();
                    }
                    records.push_back(record);
                }
                Err(e) => {
                    warn!("Skipping invalid history line: {}", e);
                }
            }
        }

        debug!("Loaded {} build records from {:?}", records.len(), path);

        Ok(Self {
            records: RwLock::new(records),
            active: RwLock::new(HashMap::new()),
            queued: RwLock::new(VecDeque::new()),
            capacity,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            next_id: AtomicU64::new(max_id + 1),
            next_queue_id: AtomicU64::new(1),
            persistence_path: Some(path.to_path_buf()),
        })
    }

    /// Persist a single record to the JSONL file (append mode).
    async fn persist_record_async(path: &Path, record: &BuildRecord) -> std::io::Result<()> {
        let mut file = AsyncOpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        let json = serde_json::to_string(record)?;
        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }

    /// Compact the persistence file to only contain current records.
    #[allow(dead_code)] // May be used for maintenance operations
    pub fn compact(&self) -> std::io::Result<()> {
        let Some(ref path) = self.persistence_path else {
            return Ok(());
        };

        let records = self.records.read().unwrap();
        let temp_path = path.with_extension("tmp");

        {
            let mut file = File::create(&temp_path)?;
            for record in records.iter() {
                writeln!(file, "{}", serde_json::to_string(record)?)?;
            }
        }

        std::fs::rename(temp_path, path)?;
        debug!("Compacted history file: {:?}", path);

        Ok(())
    }
}

impl Default for BuildHistory {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    fn now_iso() -> String {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("2024-01-01T00:00:{}Z", since_epoch % 60)
    }

    fn make_build_record(id: u64) -> BuildRecord {
        BuildRecord {
            id,
            started_at: now_iso(),
            completed_at: now_iso(),
            project_id: "test-project".to_string(),
            worker_id: None,
            command: "cargo build".to_string(),
            exit_code: 0,
            duration_ms: 100,
            location: BuildLocation::Local,
            bytes_transferred: None,
            timing: None,
        }
    }

    #[test]
    fn test_ring_buffer_capacity() {
        let history = BuildHistory::new(3);

        for i in 1..=5 {
            history.record(make_build_record(i));
        }

        let recent = history.recent(10);
        assert_eq!(recent.len(), 3); // Capped at capacity
        assert_eq!(recent[0].id, 5); // Most recent first
        assert_eq!(recent[2].id, 3); // Oldest retained
    }

    #[test]
    fn test_recent_ordering() {
        let history = BuildHistory::new(10);
        history.record(make_build_record(1));
        history.record(make_build_record(2));
        history.record(make_build_record(3));

        let recent = history.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id, 3); // Most recent first
        assert_eq!(recent[1].id, 2);
    }

    #[test]
    fn test_by_worker_filter() {
        let history = BuildHistory::new(10);

        let mut record1 = make_build_record(1);
        record1.worker_id = Some("worker-1".to_string());
        history.record(record1);

        let mut record2 = make_build_record(2);
        record2.worker_id = Some("worker-2".to_string());
        history.record(record2);

        let mut record3 = make_build_record(3);
        record3.worker_id = Some("worker-1".to_string());
        history.record(record3);

        let worker1_builds = history.by_worker("worker-1", 10);
        assert_eq!(worker1_builds.len(), 2);
        assert!(
            worker1_builds
                .iter()
                .all(|b| b.worker_id.as_deref() == Some("worker-1"))
        );
    }

    #[test]
    fn test_by_project_filter() {
        let history = BuildHistory::new(10);

        let mut record1 = make_build_record(1);
        record1.project_id = "proj-a".to_string();
        history.record(record1);

        let mut record2 = make_build_record(2);
        record2.project_id = "proj-b".to_string();
        history.record(record2);

        let mut record3 = make_build_record(3);
        record3.project_id = "proj-a".to_string();
        history.record(record3);

        let proj_a_builds = history.by_project("proj-a", 10);
        assert_eq!(proj_a_builds.len(), 2);
        assert!(proj_a_builds.iter().all(|b| b.project_id == "proj-a"));
    }

    #[test]
    fn test_stats_calculation() {
        let history = BuildHistory::new(10);

        // 2 successes, 1 failure, 2 remote, 1 local
        let mut record1 = make_build_record(1);
        record1.exit_code = 0;
        record1.location = BuildLocation::Remote;
        record1.duration_ms = 1000;
        history.record(record1);

        let mut record2 = make_build_record(2);
        record2.exit_code = 0;
        record2.location = BuildLocation::Remote;
        record2.duration_ms = 2000;
        history.record(record2);

        let mut record3 = make_build_record(3);
        record3.exit_code = 1;
        record3.location = BuildLocation::Local;
        record3.duration_ms = 500;
        history.record(record3);

        let stats = history.stats();
        assert_eq!(stats.total_builds, 3);
        assert_eq!(stats.success_count, 2);
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.remote_count, 2);
        assert_eq!(stats.local_count, 1);
        assert_eq!(stats.avg_duration_ms, 1166); // (1000+2000+500)/3
    }

    #[test]
    fn test_empty_history() {
        let history = BuildHistory::new(10);

        assert!(history.recent(10).is_empty());
        assert!(history.by_worker("any", 10).is_empty());

        let stats = history.stats();
        assert_eq!(stats.total_builds, 0);
        assert_eq!(stats.avg_duration_ms, 0);
    }

    #[test]
    fn test_next_id() {
        let history = BuildHistory::new(10);

        assert_eq!(history.next_id(), 1);
        assert_eq!(history.next_id(), 2);
        assert_eq!(history.next_id(), 3);
    }

    #[tokio::test]
    async fn test_thread_safety() {
        use std::sync::Arc;

        let history = Arc::new(BuildHistory::new(100));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let h = Arc::clone(&history);
                tokio::spawn(async move {
                    for j in 0..10 {
                        h.record(make_build_record((i * 10 + j) as u64));
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        let recent = history.recent(200);
        assert_eq!(recent.len(), 100); // All 100 recorded
    }

    #[tokio::test]
    async fn test_persistence_save_load() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");

        // Create and populate history
        let history = BuildHistory::new(5).with_persistence(path.clone());
        for i in 1..=3 {
            if let Some(handle) = history.record(make_build_record(i)) {
                handle.await.unwrap();
            }
        }

        // Load into new instance
        let loaded = BuildHistory::load_from_file(&path, 5).unwrap();
        let recent = loaded.recent(10);

        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].id, 3);
    }

    #[tokio::test]
    async fn test_persistence_append_mode() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");

        // First session
        {
            let history = BuildHistory::new(10).with_persistence(path.clone());
            if let Some(handle) = history.record(make_build_record(1)) {
                handle.await.unwrap();
            }
            if let Some(handle) = history.record(make_build_record(2)) {
                handle.await.unwrap();
            }
        }

        // Second session - load and add more
        {
            let history = BuildHistory::load_from_file(&path, 10).unwrap();
            // Use next_id to ensure we don't duplicate IDs
            let id = history.next_id();
            if let Some(handle) = history.record(make_build_record(id)) {
                handle.await.unwrap();
            }
        }

        // Third session - verify all records
        let history = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(history.len(), 3);
    }

    #[tokio::test]
    async fn test_compaction() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");

        // Create history with 3 records but capacity 2
        let history = BuildHistory::new(2).with_persistence(path.clone());
        for i in 1..=3 {
            if let Some(handle) = history.record(make_build_record(i)) {
                handle.await.unwrap();
            }
        }

        // Compact
        history.compact().unwrap();

        // Verify file only has 2 records
        let loaded = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_clear() {
        let history = BuildHistory::new(10);
        history.record(make_build_record(1));
        history.record(make_build_record(2));

        assert_eq!(history.len(), 2);

        history.clear();

        assert_eq!(history.len(), 0);
        assert!(history.is_empty());
    }

    // =========================================================================
    // Queue Tests
    // =========================================================================

    #[test]
    fn test_enqueue_dequeue_fifo() {
        let history = BuildHistory::new(10);

        // Enqueue three builds
        let b1 = history
            .enqueue_build("proj-a".into(), "cargo build".into(), 1001, 4)
            .unwrap();
        let b2 = history
            .enqueue_build("proj-b".into(), "cargo test".into(), 1002, 8)
            .unwrap();
        let b3 = history
            .enqueue_build("proj-c".into(), "cargo check".into(), 1003, 2)
            .unwrap();

        assert_eq!(history.queue_depth(), 3);

        // Dequeue in FIFO order
        let d1 = history.dequeue_build().unwrap();
        assert_eq!(d1.id, b1.id);
        assert_eq!(d1.project_id, "proj-a");

        let d2 = history.dequeue_build().unwrap();
        assert_eq!(d2.id, b2.id);

        let d3 = history.dequeue_build().unwrap();
        assert_eq!(d3.id, b3.id);

        assert!(history.queue_is_empty());
        assert!(history.dequeue_build().is_none());
    }

    #[test]
    fn test_queue_depth_limit() {
        let history = BuildHistory::new(10).with_max_queue_depth(2);

        // First two should succeed
        assert!(
            history
                .enqueue_build("proj-a".into(), "build".into(), 1, 4)
                .is_some()
        );
        assert!(
            history
                .enqueue_build("proj-b".into(), "build".into(), 2, 4)
                .is_some()
        );

        // Third should fail
        assert!(
            history
                .enqueue_build("proj-c".into(), "build".into(), 3, 4)
                .is_none()
        );

        // Dequeue one, then third should succeed
        history.dequeue_build();
        assert!(
            history
                .enqueue_build("proj-c".into(), "build".into(), 3, 4)
                .is_some()
        );
    }

    #[test]
    fn test_queue_position() {
        let history = BuildHistory::new(10);

        let b1 = history
            .enqueue_build("proj-a".into(), "build".into(), 1, 4)
            .unwrap();
        let b2 = history
            .enqueue_build("proj-b".into(), "build".into(), 2, 4)
            .unwrap();
        let b3 = history
            .enqueue_build("proj-c".into(), "build".into(), 3, 4)
            .unwrap();

        // Positions are 1-indexed
        assert_eq!(history.queue_position(b1.id), Some(1));
        assert_eq!(history.queue_position(b2.id), Some(2));
        assert_eq!(history.queue_position(b3.id), Some(3));
        assert_eq!(history.queue_position(999), None);
    }

    #[test]
    fn test_remove_queued_build() {
        let history = BuildHistory::new(10);

        let b1 = history
            .enqueue_build("proj-a".into(), "build".into(), 1001, 4)
            .unwrap();
        let b2 = history
            .enqueue_build("proj-b".into(), "build".into(), 1002, 4)
            .unwrap();
        let b3 = history
            .enqueue_build("proj-c".into(), "build".into(), 1003, 4)
            .unwrap();

        // Remove middle build by ID
        let removed = history.remove_queued_build(b2.id).unwrap();
        assert_eq!(removed.project_id, "proj-b");
        assert_eq!(history.queue_depth(), 2);

        // Remove by PID
        let removed = history.remove_queued_build_by_pid(1003).unwrap();
        assert_eq!(removed.id, b3.id);
        assert_eq!(history.queue_depth(), 1);

        // Only b1 remains
        let d = history.dequeue_build().unwrap();
        assert_eq!(d.id, b1.id);
    }

    #[test]
    fn test_queued_builds_list() {
        let history = BuildHistory::new(10);

        history.enqueue_build("proj-a".into(), "build".into(), 1, 4);
        history.enqueue_build("proj-b".into(), "test".into(), 2, 8);

        let queued = history.queued_builds();
        assert_eq!(queued.len(), 2);
        assert_eq!(queued[0].project_id, "proj-a");
        assert_eq!(queued[1].project_id, "proj-b");
    }

    #[test]
    fn test_queued_build_lookup() {
        let history = BuildHistory::new(10);

        let b = history
            .enqueue_build("proj-a".into(), "cargo build".into(), 1001, 4)
            .unwrap();

        let found = history.queued_build(b.id).unwrap();
        assert_eq!(found.command, "cargo build");
        assert_eq!(found.hook_pid, 1001);
        assert_eq!(found.slots_needed, 4);

        assert!(history.queued_build(999).is_none());
    }

    #[test]
    fn test_queue_unlimited_depth() {
        // max_queue_depth = 0 means unlimited
        let history = BuildHistory::new(10).with_max_queue_depth(0);

        // Should be able to enqueue many
        for i in 0..1000 {
            assert!(
                history
                    .enqueue_build(format!("proj-{}", i), "build".into(), i, 4)
                    .is_some()
            );
        }

        assert_eq!(history.queue_depth(), 1000);
    }

    // =========================================================================
    // Saved Time Stats Tests
    // =========================================================================

    #[test]
    fn test_saved_time_stats_empty_history() {
        let history = BuildHistory::new(10);
        let stats = history.saved_time_stats();

        assert_eq!(stats.builds_counted, 0);
        assert_eq!(stats.time_saved_ms, 0);
        assert_eq!(stats.total_remote_duration_ms, 0);
        assert_eq!(stats.estimated_local_duration_ms, 0);
    }

    #[test]
    fn test_saved_time_stats_only_local_builds() {
        let history = BuildHistory::new(10);

        // Add local builds only
        for i in 1..=3 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Local;
            record.duration_ms = 1000;
            history.record(record);
        }

        let stats = history.saved_time_stats();
        assert_eq!(stats.builds_counted, 0);
        assert_eq!(stats.time_saved_ms, 0);
    }

    #[test]
    fn test_saved_time_stats_only_remote_builds_default_speedup() {
        let history = BuildHistory::new(10);

        // Add remote builds only (no local for comparison, uses default 2x speedup)
        for i in 1..=3 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Remote;
            record.worker_id = Some("worker-1".to_string());
            record.duration_ms = 1000;
            history.record(record);
        }

        let stats = history.saved_time_stats();
        assert_eq!(stats.builds_counted, 3);
        assert_eq!(stats.total_remote_duration_ms, 3000);
        // With default 2x speedup: estimated local = 3 * 1000 * 2 = 6000
        assert_eq!(stats.estimated_local_duration_ms, 6000);
        assert_eq!(stats.time_saved_ms, 3000);
        assert!((stats.avg_speedup - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_saved_time_stats_mixed_builds() {
        let history = BuildHistory::new(10);

        // Add local builds
        for i in 1..=2 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Local;
            record.duration_ms = 2000; // Local takes 2s
            history.record(record);
        }

        // Add remote builds
        for i in 3..=4 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Remote;
            record.worker_id = Some("worker-1".to_string());
            record.duration_ms = 1000; // Remote takes 1s
            history.record(record);
        }

        let stats = history.saved_time_stats();
        assert_eq!(stats.builds_counted, 2);
        assert_eq!(stats.total_remote_duration_ms, 2000);
        // With avg local duration 2000ms: estimated local = 2 * 2000 = 4000
        assert_eq!(stats.estimated_local_duration_ms, 4000);
        assert_eq!(stats.time_saved_ms, 2000);
        assert!((stats.avg_speedup - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_saved_time_stats_failed_builds_excluded() {
        let history = BuildHistory::new(10);

        // Add successful remote build
        let mut record1 = make_build_record(1);
        record1.location = BuildLocation::Remote;
        record1.worker_id = Some("worker-1".to_string());
        record1.duration_ms = 1000;
        record1.exit_code = 0;
        history.record(record1);

        // Add failed remote build
        let mut record2 = make_build_record(2);
        record2.location = BuildLocation::Remote;
        record2.worker_id = Some("worker-1".to_string());
        record2.duration_ms = 5000;
        record2.exit_code = 1;
        history.record(record2);

        let stats = history.saved_time_stats();
        // Only successful remote builds are counted
        assert_eq!(stats.builds_counted, 1);
        assert_eq!(stats.total_remote_duration_ms, 1000);
    }

    #[test]
    fn test_saved_time_stats_no_negative_savings() {
        let history = BuildHistory::new(10);

        // Add fast local builds (500ms)
        for i in 1..=2 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Local;
            record.duration_ms = 500;
            history.record(record);
        }

        // Add slow remote builds (1000ms - slower than local!)
        for i in 3..=4 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Remote;
            record.worker_id = Some("worker-1".to_string());
            record.duration_ms = 1000;
            history.record(record);
        }

        let stats = history.saved_time_stats();
        // estimated_local = 500ms * 2 = 1000ms
        // time_saved = max(0, 1000 - 2000) = 0 (no negative savings)
        assert_eq!(stats.time_saved_ms, 0);
    }
}
