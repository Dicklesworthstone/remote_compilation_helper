//! Build history tracking.
//!
//! Maintains a ring buffer of recent builds for status reporting and analytics.

use rch_common::{BuildLocation, BuildRecord, BuildStats};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs::OpenOptions as AsyncOpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

/// Default maximum number of builds to retain.
const DEFAULT_CAPACITY: usize = 100;

/// Build history manager.
///
/// Thread-safe ring buffer of recent builds with optional persistence.
pub struct BuildHistory {
    /// Ring buffer of recent builds.
    records: RwLock<VecDeque<BuildRecord>>,
    /// Maximum capacity.
    capacity: usize,
    /// Next build ID.
    next_id: AtomicU64,
    /// Persistence path (optional).
    persistence_path: Option<PathBuf>,
}

impl BuildHistory {
    /// Create a new build history with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            records: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity,
            next_id: AtomicU64::new(1),
            persistence_path: None,
        }
    }

    /// Create a new build history with default capacity.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
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
            capacity,
            next_id: AtomicU64::new(max_id + 1),
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
}
