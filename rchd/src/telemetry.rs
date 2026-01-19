//! Telemetry storage and polling for worker metrics.

use crate::events::EventBus;
use crate::workers::{WorkerPool, WorkerState};
use anyhow::Context;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use directories::ProjectDirs;
use rch_common::{SshClient, SshOptions, WorkerStatus};
use rch_telemetry::protocol::{
    ReceivedTelemetry, TelemetrySource, TestRunRecord, TestRunStats, WorkerTelemetry,
};
use rch_telemetry::speedscore::SpeedScore;
use rch_telemetry::storage::{SpeedScoreHistoryPage, TelemetryStorage};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::task;
use tokio::time::interval;
use tracing::{debug, warn};

/// In-memory telemetry store with time-based eviction.
pub struct TelemetryStore {
    retention: ChronoDuration,
    recent: RwLock<HashMap<String, VecDeque<ReceivedTelemetry>>>,
    test_runs: RwLock<VecDeque<TestRunRecord>>,
    storage: Option<Arc<TelemetryStorage>>,
    event_bus: Option<EventBus>,
}

impl TelemetryStore {
    /// Create a new telemetry store.
    pub fn new(retention: Duration, storage: Option<Arc<TelemetryStorage>>) -> Self {
        let retention =
            ChronoDuration::from_std(retention).unwrap_or_else(|_| ChronoDuration::seconds(300));
        Self {
            retention,
            recent: RwLock::new(HashMap::new()),
            test_runs: RwLock::new(VecDeque::new()),
            storage,
            event_bus: None,
        }
    }

    /// Create a new telemetry store with an event bus for WebSocket notifications.
    pub fn with_event_bus(
        retention: Duration,
        storage: Option<Arc<TelemetryStorage>>,
        event_bus: EventBus,
    ) -> Self {
        let retention =
            ChronoDuration::from_std(retention).unwrap_or_else(|_| ChronoDuration::seconds(300));
        Self {
            retention,
            recent: RwLock::new(HashMap::new()),
            test_runs: RwLock::new(VecDeque::new()),
            storage,
            event_bus: Some(event_bus),
        }
    }

    /// Ingest telemetry into the store.
    ///
    /// Stores the telemetry, persists to SQLite (if configured), and emits
    /// a "telemetry:update" event for WebSocket subscribers (if configured).
    pub fn ingest(&self, telemetry: WorkerTelemetry, source: TelemetrySource) {
        let received = ReceivedTelemetry::new(telemetry, source);
        let worker_id = received.telemetry.worker_id.clone();

        // Get summary for event emission before moving into storage
        let summary = received.telemetry.summary();

        let mut recent = self.recent.write().unwrap();
        let entries = recent.entry(worker_id).or_default();
        entries.push_back(received);

        self.evict_old(entries);

        // Emit WebSocket event for real-time dashboard updates
        if let Some(event_bus) = &self.event_bus {
            event_bus.emit("telemetry:update", &summary);
        }

        if let Some(storage) = self.storage.as_ref() {
            let storage = Arc::clone(storage);
            let telemetry = entries.back().map(|e| e.telemetry.clone());
            if let Some(telemetry) = telemetry {
                task::spawn(async move {
                    let result =
                        task::spawn_blocking(move || storage.insert_telemetry(&telemetry)).await;
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => warn!("Failed to persist telemetry: {}", e),
                        Err(e) => warn!("Telemetry persistence task failed: {}", e),
                    }
                });
            }
        }
    }

    /// Get the most recent telemetry for a worker.
    pub fn latest(&self, worker_id: &str) -> Option<ReceivedTelemetry> {
        let recent = self.recent.read().unwrap();
        recent
            .get(worker_id)
            .and_then(|entries| entries.back().cloned())
    }

    /// Get the most recent telemetry for all workers.
    pub fn latest_all(&self) -> Vec<ReceivedTelemetry> {
        let recent = self.recent.read().unwrap();
        recent
            .values()
            .filter_map(|entries| entries.back().cloned())
            .collect()
    }

    /// Get the last received timestamp for a worker.
    pub fn last_received_at(&self, worker_id: &str) -> Option<DateTime<Utc>> {
        self.latest(worker_id).map(|entry| entry.received_at)
    }

    /// Record a test run for telemetry and optional persistence.
    pub fn record_test_run(&self, record: TestRunRecord) {
        let mut test_runs = self.test_runs.write().unwrap();
        if test_runs.len() >= 200 {
            test_runs.pop_front();
        }
        test_runs.push_back(record.clone());

        if let Some(storage) = self.storage.as_ref() {
            let storage = Arc::clone(storage);
            task::spawn(async move {
                let result = task::spawn_blocking(move || storage.insert_test_run(&record)).await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!("Failed to persist test run: {}", e),
                    Err(e) => warn!("Test run persistence task failed: {}", e),
                }
            });
        }
    }

    /// Fetch aggregate test run stats.
    pub fn test_run_stats(&self) -> TestRunStats {
        if let Some(storage) = self.storage.as_ref() {
            if let Ok(stats) = storage.test_run_stats() {
                return stats;
            }
        }

        let test_runs = self.test_runs.read().unwrap();
        let mut stats = TestRunStats::default();
        for record in test_runs.iter() {
            stats.record(record);
        }
        stats
    }

    /// Fetch latest SpeedScore for a worker from persistent storage.
    pub fn latest_speedscore(&self, worker_id: &str) -> anyhow::Result<Option<SpeedScore>> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(None);
        };
        storage.latest_speedscore(worker_id)
    }

    /// Fetch SpeedScore history for a worker from persistent storage.
    pub fn speedscore_history(
        &self,
        worker_id: &str,
        since: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<SpeedScoreHistoryPage> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(SpeedScoreHistoryPage {
                total: 0,
                entries: Vec::new(),
            });
        };
        storage.speedscore_history(worker_id, since, limit, offset)
    }

    fn evict_old(&self, entries: &mut VecDeque<ReceivedTelemetry>) {
        let cutoff = Utc::now() - self.retention;
        while entries
            .front()
            .map(|entry| entry.received_at < cutoff)
            .unwrap_or(false)
        {
            entries.pop_front();
        }
    }
}

/// Default path for the telemetry database.
pub fn default_telemetry_db_path() -> anyhow::Result<PathBuf> {
    let dirs = ProjectDirs::from("com", "rch", "rch")
        .context("Failed to resolve telemetry data directory")?;
    let base = dirs.data_local_dir().join("telemetry");
    std::fs::create_dir_all(&base)
        .with_context(|| format!("Failed to create telemetry directory {:?}", base))?;
    Ok(base.join("telemetry.db"))
}

/// Start background maintenance for the telemetry database.
pub fn start_storage_maintenance(storage: Arc<TelemetryStorage>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            let storage = Arc::clone(&storage);
            let result = task::spawn_blocking(move || storage.maintenance()).await;
            match result {
                Ok(Ok(stats)) => debug!(
                    aggregated_hours = stats.aggregated_hours,
                    deleted_raw = stats.deleted_raw,
                    deleted_hourly = stats.deleted_hourly,
                    vacuumed = stats.vacuumed,
                    "Telemetry storage maintenance completed"
                ),
                Ok(Err(e)) => warn!("Telemetry maintenance failed: {}", e),
                Err(e) => warn!("Telemetry maintenance task failed: {}", e),
            }
        }
    })
}

/// Telemetry polling configuration.
#[derive(Debug, Clone)]
pub struct TelemetryPollerConfig {
    pub poll_interval: Duration,
    pub ssh_timeout: Duration,
    pub skip_after: Duration,
}

impl Default for TelemetryPollerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            ssh_timeout: Duration::from_secs(5),
            skip_after: Duration::from_secs(60),
        }
    }
}

/// Periodic SSH poller for worker telemetry.
pub struct TelemetryPoller {
    pool: WorkerPool,
    store: Arc<TelemetryStore>,
    config: TelemetryPollerConfig,
}

impl TelemetryPoller {
    /// Create a new telemetry poller.
    pub fn new(
        pool: WorkerPool,
        store: Arc<TelemetryStore>,
        config: TelemetryPollerConfig,
    ) -> Self {
        Self {
            pool,
            store,
            config,
        }
    }

    /// Start the polling loop in the background.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(self.config.poll_interval);
            loop {
                ticker.tick().await;
                if let Err(e) = self.poll_once().await {
                    warn!("Telemetry poll cycle failed: {}", e);
                }
            }
        })
    }

    async fn poll_once(&self) -> anyhow::Result<()> {
        let workers = self.pool.all_workers().await;

        for worker in workers {
            if !self.should_poll_worker(&worker).await {
                continue;
            }

            let store = self.store.clone();
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = poll_worker(worker, store, config).await {
                    warn!("Telemetry poll failed: {}", e);
                }
            });
        }

        Ok(())
    }

    async fn should_poll_worker(&self, worker: &WorkerState) -> bool {
        let status = worker.status().await;
        if matches!(status, WorkerStatus::Unreachable | WorkerStatus::Disabled) {
            return false;
        }

        let worker_id = worker.config.read().await.id.clone();
        if let Some(last_received) = self.store.last_received_at(worker_id.as_str()) {
            let since = Utc::now() - last_received;
            if since.to_std().unwrap_or_default() < self.config.skip_after {
                return false;
            }
        }

        true
    }
}

/// Collect telemetry from a worker via SSH.
///
/// Executes `rch-telemetry collect` on the remote worker and parses the result.
pub async fn collect_telemetry_from_worker(
    worker: &WorkerState,
    ssh_timeout: Duration,
) -> anyhow::Result<WorkerTelemetry> {
    let config = worker.config.read().await;
    let worker_id = config.id.as_str();
    let command = format!(
        "rch-telemetry collect --format json --worker-id {}",
        worker_id
    );

    let options = SshOptions {
        connect_timeout: ssh_timeout,
        command_timeout: ssh_timeout,
        ..Default::default()
    };

    let mut client = SshClient::new(config.clone(), options);
    client.connect().await?;
    let result = client.execute(&command).await;
    client.disconnect().await?;

    let result = result?;

    if !result.success() {
        return Err(anyhow::anyhow!(
            "Telemetry command failed (exit {}): {}",
            result.exit_code,
            result.stderr.trim()
        ));
    }

    let payload = result.stdout.trim();
    if payload.is_empty() {
        return Err(anyhow::anyhow!("Telemetry command returned empty output"));
    }

    let telemetry =
        WorkerTelemetry::from_json(payload).context("Failed to parse telemetry JSON")?;

    if !telemetry.is_compatible() {
        warn!(worker = worker_id, "Telemetry protocol version mismatch");
    }

    Ok(telemetry)
}

async fn poll_worker(
    worker: Arc<WorkerState>,
    store: Arc<TelemetryStore>,
    config: TelemetryPollerConfig,
) -> anyhow::Result<()> {
    let worker_id = worker.config.read().await.id.clone();

    match collect_telemetry_from_worker(&worker, config.ssh_timeout).await {
        Ok(telemetry) => {
            debug!(
                worker = worker_id.as_str(),
                cpu = %telemetry.cpu.overall_percent,
                memory = %telemetry.memory.used_percent,
                "Telemetry collected via SSH"
            );
            store.ingest(telemetry, TelemetrySource::SshPoll);
        }
        Err(e) => {
            warn!(worker = worker_id.as_str(), "Telemetry poll failed: {}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::CompilationKind;
    use rch_telemetry::collect::cpu::{CpuTelemetry, LoadAverage};
    use rch_telemetry::collect::memory::MemoryTelemetry;

    fn make_telemetry(worker_id: &str, cpu_pct: f64, mem_pct: f64) -> WorkerTelemetry {
        let cpu = CpuTelemetry {
            timestamp: Utc::now(),
            overall_percent: cpu_pct,
            per_core_percent: vec![cpu_pct],
            num_cores: 1,
            load_average: LoadAverage {
                one_min: 0.5,
                five_min: 0.3,
                fifteen_min: 0.2,
                running_processes: 1,
                total_processes: 100,
            },
            psi: None,
        };

        let memory = MemoryTelemetry {
            timestamp: Utc::now(),
            total_gb: 32.0,
            available_gb: 16.0,
            used_percent: mem_pct,
            pressure_score: mem_pct,
            swap_used_gb: 0.0,
            dirty_mb: 0.0,
            psi: None,
        };

        WorkerTelemetry::new(worker_id.to_string(), cpu, memory, None, None, 1)
    }

    #[test]
    fn test_ingest_and_latest() {
        let store = TelemetryStore::new(Duration::from_secs(300), None);

        store.ingest(make_telemetry("w1", 10.0, 20.0), TelemetrySource::SshPoll);
        store.ingest(make_telemetry("w1", 55.0, 65.0), TelemetrySource::SshPoll);

        let latest = store.latest("w1").expect("expected latest telemetry");
        assert!((latest.telemetry.cpu.overall_percent - 55.0).abs() < f64::EPSILON);
        assert!((latest.telemetry.memory.used_percent - 65.0).abs() < f64::EPSILON);
        assert!(store.last_received_at("w1").is_some());
    }

    #[test]
    fn test_latest_all_returns_one_per_worker() {
        let store = TelemetryStore::new(Duration::from_secs(300), None);

        store.ingest(make_telemetry("w1", 12.0, 22.0), TelemetrySource::Piggyback);
        store.ingest(make_telemetry("w2", 34.0, 44.0), TelemetrySource::SshPoll);
        store.ingest(make_telemetry("w2", 45.0, 55.0), TelemetrySource::SshPoll);

        let latest = store.latest_all();
        assert_eq!(latest.len(), 2);

        let mut ids: Vec<_> = latest
            .iter()
            .map(|t| t.telemetry.worker_id.as_str())
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["w1", "w2"]);
    }

    #[test]
    fn test_eviction_removes_old_entries() {
        let store = TelemetryStore::new(Duration::from_secs(1), None);

        store.ingest(make_telemetry("w1", 10.0, 20.0), TelemetrySource::SshPoll);

        {
            let mut recent = store.recent.write().unwrap();
            let entries = recent.get_mut("w1").expect("missing worker entry");
            entries[0].received_at = Utc::now() - ChronoDuration::seconds(120);
        }

        store.ingest(make_telemetry("w1", 30.0, 40.0), TelemetrySource::SshPoll);

        let recent = store.recent.read().unwrap();
        let entries = recent.get("w1").expect("missing worker entry");
        assert_eq!(entries.len(), 1);
        assert!((entries[0].telemetry.cpu.overall_percent - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_test_run_stats() {
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        let record = TestRunRecord::new(
            "proj".to_string(),
            "worker-1".to_string(),
            "cargo test".to_string(),
            CompilationKind::CargoTest,
            0,
            1234,
        );

        store.record_test_run(record);
        let stats = store.test_run_stats();

        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.passed_runs, 1);
        assert_eq!(stats.failed_runs, 0);
        assert_eq!(stats.build_error_runs, 0);
        assert!(stats.avg_duration_ms > 0);
        assert_eq!(stats.runs_by_kind.get("cargo_test"), Some(&1));
    }

    #[test]
    fn test_ingest_emits_websocket_event() {
        let event_bus = EventBus::new(16);
        let mut receiver = event_bus.subscribe();

        let store = TelemetryStore::with_event_bus(Duration::from_secs(300), None, event_bus);

        // Ingest telemetry - this should emit an event
        store.ingest(make_telemetry("w1", 42.0, 50.0), TelemetrySource::Piggyback);

        // Check that an event was emitted
        let event = receiver
            .try_recv()
            .expect("expected telemetry:update event");
        assert!(event.contains("telemetry:update"));
        assert!(event.contains("w1"));
        assert!(event.contains("42")); // CPU percent should be in the summary
    }

    #[test]
    fn test_store_without_event_bus_still_works() {
        // Ensure the store works without an event bus (no panics, etc.)
        let store = TelemetryStore::new(Duration::from_secs(300), None);

        store.ingest(make_telemetry("w1", 10.0, 20.0), TelemetrySource::SshPoll);
        store.ingest(make_telemetry("w2", 30.0, 40.0), TelemetrySource::Piggyback);

        let latest = store.latest_all();
        assert_eq!(latest.len(), 2);
    }
}
