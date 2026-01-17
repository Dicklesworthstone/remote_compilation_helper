//! Telemetry storage and polling for worker metrics.

#![allow(dead_code)] // Parts will be used by follow-up beads

use crate::workers::{WorkerPool, WorkerState};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::{SshClient, SshOptions, WorkerStatus};
use rch_telemetry::protocol::{ReceivedTelemetry, TelemetrySource, WorkerTelemetry};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, warn};

/// In-memory telemetry store with time-based eviction.
pub struct TelemetryStore {
    retention: ChronoDuration,
    recent: RwLock<HashMap<String, VecDeque<ReceivedTelemetry>>>,
}

impl TelemetryStore {
    /// Create a new telemetry store.
    pub fn new(retention: Duration) -> Self {
        let retention =
            ChronoDuration::from_std(retention).unwrap_or_else(|_| ChronoDuration::seconds(300));
        Self {
            retention,
            recent: RwLock::new(HashMap::new()),
        }
    }

    /// Ingest telemetry into the store.
    pub fn ingest(&self, telemetry: WorkerTelemetry, source: TelemetrySource) {
        let received = ReceivedTelemetry::new(telemetry, source);
        let worker_id = received.telemetry.worker_id.clone();

        let mut recent = self.recent.write().unwrap();
        let entries = recent.entry(worker_id).or_default();
        entries.push_back(received);

        self.evict_old(entries);
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

        let worker_id = worker.config.id.as_str();
        if let Some(last_received) = self.store.last_received_at(worker_id) {
            let since = Utc::now() - last_received;
            if since.to_std().unwrap_or_default() < self.config.skip_after {
                return false;
            }
        }

        true
    }
}

async fn poll_worker(
    worker: Arc<WorkerState>,
    store: Arc<TelemetryStore>,
    config: TelemetryPollerConfig,
) -> anyhow::Result<()> {
    let worker_id = worker.config.id.as_str();
    let command = format!(
        "rch-telemetry collect --format json --worker-id {}",
        worker_id
    );

    let options = SshOptions {
        connect_timeout: config.ssh_timeout,
        command_timeout: config.ssh_timeout,
        ..Default::default()
    };

    let mut client = SshClient::new(worker.config.clone(), options);
    client.connect().await?;
    let result = client.execute(&command).await;
    client.disconnect().await?;

    let result = match result {
        Ok(res) => res,
        Err(e) => {
            warn!(worker = worker_id, "Telemetry SSH error: {}", e);
            return Ok(());
        }
    };

    if !result.success() {
        warn!(
            worker = worker_id,
            exit = result.exit_code,
            stderr = %result.stderr.trim(),
            "Telemetry command failed"
        );
        return Ok(());
    }

    let payload = result.stdout.trim();
    if payload.is_empty() {
        warn!(
            worker = worker_id,
            "Telemetry command returned empty output"
        );
        return Ok(());
    }

    match WorkerTelemetry::from_json(payload) {
        Ok(telemetry) => {
            if !telemetry.is_compatible() {
                warn!(worker = worker_id, "Telemetry protocol version mismatch");
            }
            debug!(
                worker = worker_id,
                cpu = %telemetry.cpu.overall_percent,
                memory = %telemetry.memory.used_percent,
                "Telemetry collected via SSH"
            );
            store.ingest(telemetry, TelemetrySource::SshPoll);
        }
        Err(e) => {
            warn!(worker = worker_id, "Failed to parse telemetry JSON: {}", e);
        }
    }

    Ok(())
}
