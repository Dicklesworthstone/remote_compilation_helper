//! Telemetry storage and polling for worker metrics.

use crate::events::EventBus;
use crate::workers::{WorkerEndpointSnapshot, WorkerPool, WorkerState};
use anyhow::Context;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use directories::ProjectDirs;
use rch_common::timing::scale_duration;
use rch_common::{SshClient, SshOptions};
use rch_telemetry::protocol::{
    ReceivedTelemetry, TelemetrySource, TestRunRecord, TestRunStats, TestRunStatsAccumulator,
    TestRunStatsScope, WorkerTelemetry,
};
use rch_telemetry::speedscore::SpeedScore;
use rch_telemetry::storage::{SpeedScoreHistoryPage, TelemetryStorage};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::task;
use tokio::time::interval;
use tracing::{debug, info, warn};

const TEST_RUN_MEMORY_CAPACITY: usize = 200;

struct StoredTelemetry {
    received: ReceivedTelemetry,
    observed_at: tokio::time::Instant,
    endpoint: Option<WorkerEndpointSnapshot>,
}

impl StoredTelemetry {
    fn belongs_to(&self, endpoint: &WorkerEndpointSnapshot) -> bool {
        let Some(bound) = &self.endpoint else {
            // Existing push/piggyback payloads carry no endpoint identity. They
            // remain useful for the original endpoint, but cannot prove that a
            // replacement is fresh or healthy after this worker ID is retargeted.
            return endpoint.generation == 0;
        };
        bound.generation == endpoint.generation
            && bound.config.id == endpoint.config.id
            && bound.config.host == endpoint.config.host
            && bound.config.user == endpoint.config.user
            && bound.config.identity_file == endpoint.config.identity_file
            && rch_common::declared_os(&bound.config.tags)
                == rch_common::declared_os(&endpoint.config.tags)
    }
}

/// In-memory telemetry store with time-based eviction.
pub struct TelemetryStore {
    retention: ChronoDuration,
    recent: RwLock<HashMap<String, VecDeque<StoredTelemetry>>>,
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
        self.ingest_inner(telemetry, source, None);
    }

    /// Test fixtures may install endpoint-bound evidence without remote work.
    /// Production probes publish through their original collection deadline.
    #[cfg(test)]
    pub(crate) fn ingest_for_endpoint(
        &self,
        telemetry: WorkerTelemetry,
        source: TelemetrySource,
        endpoint: &WorkerEndpointSnapshot,
    ) {
        self.ingest_inner(telemetry, source, Some(endpoint.clone()));
    }

    fn ingest_inner(
        &self,
        telemetry: WorkerTelemetry,
        source: TelemetrySource,
        endpoint: Option<WorkerEndpointSnapshot>,
    ) {
        let received = ReceivedTelemetry::new(telemetry.clone(), source);
        let observed_at = tokio::time::Instant::now();
        let worker_id = received.telemetry.worker_id.clone();
        let mut recent = self.recent.write().unwrap_or_else(|e| e.into_inner());
        let entries = recent.entry(worker_id).or_default();
        entries.push_back(StoredTelemetry {
            received,
            observed_at,
            endpoint,
        });
        self.evict_old(entries);
        drop(recent);
        self.notify_ingested(&telemetry);
    }

    /// The caller already holds the worker's endpoint/network/circuit guards.
    /// Never block the runtime on the synchronous cache lock: contention is
    /// retried by the caller within the original collection deadline.
    fn try_publish_before(
        &self,
        pending: &mut Option<StoredTelemetry>,
        deadline: tokio::time::Instant,
        on_commit: impl FnOnce() -> bool,
    ) -> bool {
        let worker_id = pending
            .as_ref()
            .expect("a pending telemetry sample is committed once")
            .received
            .telemetry
            .worker_id
            .clone();
        let mut recent = match self.recent.try_write() {
            Ok(recent) => recent,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return false,
        };
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        // The callback rechecks the administrative epoch while every
        // destination lock is held, then updates command evidence.
        if !on_commit() {
            return false;
        }
        let entries = recent.entry(worker_id).or_default();
        entries.push_back(pending.take().expect("pending telemetry sample"));
        self.evict_old(entries);
        true
    }

    fn notify_ingested(&self, telemetry: &WorkerTelemetry) {
        if let Some(event_bus) = &self.event_bus {
            event_bus.emit("telemetry:update", &telemetry.summary());
        }
        if let Some(storage) = self.storage.as_ref() {
            let storage = Arc::clone(storage);
            let telemetry = telemetry.clone();
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

    /// Get the most recent telemetry for a worker.
    pub fn latest(&self, worker_id: &str) -> Option<ReceivedTelemetry> {
        let recent = self.recent.read().unwrap_or_else(|e| e.into_inner());
        recent
            .get(worker_id)
            .and_then(|entries| entries.back().map(|entry| entry.received.clone()))
    }

    /// Latest evidence that belongs to the endpoint being evaluated. Historical
    /// samples stay available to diagnostics, but never qualify a replacement.
    pub(crate) fn latest_for_endpoint(
        &self,
        endpoint: &WorkerEndpointSnapshot,
    ) -> Option<ReceivedTelemetry> {
        let recent = self.recent.read().unwrap_or_else(|e| e.into_inner());
        recent.get(endpoint.config.id.as_str()).and_then(|entries| {
            entries
                .iter()
                .rev()
                .find(|entry| entry.belongs_to(endpoint))
                .map(|entry| entry.received.clone())
        })
    }

    /// Get the most recent telemetry for all workers.
    pub fn latest_all(&self) -> Vec<ReceivedTelemetry> {
        let recent = self.recent.read().unwrap_or_else(|e| e.into_inner());
        recent
            .values()
            .filter_map(|entries| entries.back().map(|entry| entry.received.clone()))
            .collect()
    }

    /// Get the last received timestamp for a worker.
    pub fn last_received_at(&self, worker_id: &str) -> Option<DateTime<Utc>> {
        self.latest(worker_id).map(|entry| entry.received_at)
    }

    /// Record a test run for telemetry and optional persistence.
    pub fn record_test_run(&self, record: TestRunRecord) {
        let mut test_runs = self.test_runs.write().unwrap_or_else(|e| e.into_inner());
        if test_runs.len() >= TEST_RUN_MEMORY_CAPACITY {
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
    pub async fn test_run_stats(&self) -> TestRunStats {
        if let Some(storage) = self.storage.clone() {
            let result = task::spawn_blocking(move || storage.test_run_stats()).await;
            if let Ok(Ok(stats)) = result {
                return stats;
            }
        }

        let test_runs = self.test_runs.read().unwrap_or_else(|e| e.into_inner());
        let mut stats = TestRunStatsAccumulator::default();
        for record in test_runs.iter() {
            stats.record(record);
        }
        let mut stats = stats.finish();
        stats.scope = TestRunStatsScope::RecentMemory {
            max_records: TEST_RUN_MEMORY_CAPACITY,
        };
        stats
    }

    /// Persist a completed benchmark's SpeedScore.
    ///
    /// Writes synchronously (via a blocking task) so callers can observe the
    /// persisted state before acting on it — `should_benchmark` reads
    /// `latest_speedscore` on the very next scheduler pass, and a fire-and-
    /// forget write would leave a window where a freshly benchmarked worker is
    /// still classified as `NewWorker` (issue #40).
    ///
    /// Without persistent storage configured this is a no-op `Ok(())`, which
    /// matches the reader (`latest_speedscore` returns `Ok(None)`).
    pub async fn record_speedscore(
        &self,
        worker_id: &str,
        score: SpeedScore,
    ) -> anyhow::Result<()> {
        let Some(storage) = self.storage.clone() else {
            return Ok(());
        };
        let worker_id = worker_id.to_string();
        tokio::task::spawn_blocking(move || storage.insert_speedscore(&worker_id, &score)).await?
    }

    /// Fetch latest SpeedScore for a worker from persistent storage.
    pub async fn latest_speedscore(&self, worker_id: &str) -> anyhow::Result<Option<SpeedScore>> {
        let Some(storage) = self.storage.clone() else {
            return Ok(None);
        };
        let worker_id = worker_id.to_string();
        tokio::task::spawn_blocking(move || storage.latest_speedscore(&worker_id)).await?
    }

    /// Fetch SpeedScore history for a worker from persistent storage.
    pub async fn speedscore_history(
        &self,
        worker_id: &str,
        since: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<SpeedScoreHistoryPage> {
        let Some(storage) = self.storage.clone() else {
            return Ok(SpeedScoreHistoryPage {
                total: 0,
                entries: Vec::new(),
            });
        };
        let worker_id = worker_id.to_string();
        tokio::task::spawn_blocking(move || {
            storage.speedscore_history(&worker_id, since, limit, offset)
        })
        .await?
    }

    fn evict_old(&self, entries: &mut VecDeque<StoredTelemetry>) {
        let cutoff = Utc::now() - self.retention;
        while entries
            .front()
            .map(|entry| entry.received.received_at < cutoff)
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
        let mut ticker = interval(Duration::from_secs(300));
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
    /// Circuit-breaker settings used when a poll outcome is fed to the
    /// worker's authoritative circuit as command-class evidence (issue #48).
    /// Must match the health monitor's settings so both writers agree on
    /// thresholds; `rchd` wires both from `[circuit]`.
    pub circuit: rch_common::CircuitBreakerConfig,
}

impl Default for TelemetryPollerConfig {
    fn default() -> Self {
        Self {
            circuit: rch_common::CircuitBreakerConfig::default(),
            poll_interval: Duration::from_secs(30),
            // Telemetry is collected via a fresh SSH connect+auth+exec each cycle.
            // 5s was too tight for trans-continental workers (e.g. Contabo EU VPS
            // from a US controller): connect+auth alone can approach/exceed 5s under
            // load, causing intermittent "Command timed out after 5s" failures that
            // flap worker freshness → flap health → spurious "no workers passed
            // health thresholds" and offload falling back to local. 20s leaves
            // comfortable margin while staying under the 30s poll interval.
            ssh_timeout: Duration::from_secs(20),
            // Re-poll cadence must stay under the pressure layer's
            // telemetry-stale threshold (90s). With a 30s tick, a 60s skip
            // pushed the effective re-poll to ~90s (the tick after the skip
            // window expires) — equal to the stale threshold, so workers raced
            // in and out of "fresh". 30s makes a worker eligible again at the
            // *second* tick, i.e. ~60s effective re-poll: max worker age ~60s,
            // comfortably inside the 90s window, without tripling SSH load the
            // way a sub-tick skip (→30s re-poll) would.
            skip_after: Duration::from_secs(30),
        }
    }
}

/// Periodic SSH poller for worker telemetry.
/// Maximum number of worker telemetry SSH polls allowed to run concurrently.
/// This bounds the poller's footprint on pathologically large fleets, but MUST
/// stay comfortably above a normal fleet's worker count: a hung poll holds its
/// permit until the hard timeout (see `poll_worker` wrapping) fires, so a cap
/// at/below the worker count would let a few stuck workers starve the rest of
/// the fleet of poll permits — observed as telemetry freshness collapsing to a
/// handful of workers. 16 keeps every realistic fleet fully concurrent.
const MAX_CONCURRENT_TELEMETRY_POLLS: usize = 16;

/// Hard wall-clock bound for a single worker poll. The SSH layer is *supposed*
/// to honor `ssh_timeout` for connect/command, but in practice a stuck
/// connection can hang past it; without an outer timeout the spawned task (and
/// its concurrency permit) leaks indefinitely, silently starving future polls.
/// Sized just above `ssh_timeout` so a healthy-but-slow worker still completes.
fn poll_hard_timeout(ssh_timeout: Duration) -> Duration {
    ssh_timeout.saturating_add(Duration::from_secs(5))
}

/// Preserve the old two full attempts plus backoff as one elapsed-time budget.
/// Fast transient failures may retry within it, but a retry never resets it.
fn poll_retry_budget(ssh_timeout: Duration) -> Duration {
    poll_hard_timeout(ssh_timeout)
        .saturating_mul(2)
        .saturating_add(TELEMETRY_RETRY_BACKOFF)
}

pub struct TelemetryPoller {
    pool: WorkerPool,
    store: Arc<TelemetryStore>,
    config: TelemetryPollerConfig,
    poll_limit: Arc<tokio::sync::Semaphore>,
    ssh_pool: Option<Arc<rch_common::SshPool>>,
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
            poll_limit: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TELEMETRY_POLLS)),
            ssh_pool: None,
        }
    }

    /// Attach a shared SSH connection pool for warm ControlMaster reuse. The
    /// pooled vs. throwaway branch lives in
    /// [`collect_telemetry_from_worker_pooled`] (the poller's SSH logic is a free
    /// function, shared with the on-demand API path), so there is no per-struct
    /// `run_remote` helper here.
    #[must_use]
    pub fn with_ssh_pool(mut self, pool: Option<Arc<rch_common::SshPool>>) -> Self {
        self.ssh_pool = pool;
        self
    }

    /// Start the polling loop in the background.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(self.config.poll_interval);
            // A cycle can occasionally exhaust a worker's retry budget.
            // Skip missed ticks rather than firing a burst of
            // back-to-back cycles, which would only add SSH contention.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
        let total = workers.len();

        // Spawn one bounded poll task per eligible worker and collect handles so
        // we can report a per-cycle outcome summary at INFO. The summary is the
        // single source of truth for "is telemetry actually refreshing?" in
        // production (the daemon log is INFO-level), and avoids needing debug logs.
        let mut handles = Vec::new();
        for worker in workers {
            if !self.should_poll_worker(&worker).await {
                continue;
            }

            let store = self.store.clone();
            let config = self.config.clone();
            let poll_limit = self.poll_limit.clone();
            let ssh_pool = self.ssh_pool.clone();
            handles.push(tokio::spawn(async move {
                // Bound concurrent SSH polls (see MAX_CONCURRENT_TELEMETRY_POLLS).
                // The semaphore is never closed, so acquire_owned cannot fail.
                let _permit = poll_limit.acquire_owned().await;
                poll_worker(worker, store, config, ssh_pool).await
            }));
        }

        let attempted = handles.len();
        let mut refreshed = 0usize;
        for handle in handles {
            if matches!(handle.await, Ok(true)) {
                refreshed += 1;
            }
        }
        if attempted > 0 {
            info!(
                "telemetry poll cycle: refreshed {}/{} polled workers ({} configured)",
                refreshed, attempted, total
            );
        }

        Ok(())
    }

    async fn should_poll_worker(&self, worker: &WorkerState) -> bool {
        // The health monitor owns transport recovery. An offline worker must
        // not acquire a second reconnect loop through telemetry, even if its
        // last sample is stale. Keep polling other eligibility quarantines:
        // their recovery criteria require fresh telemetry, and gating on the
        // legacy Unreachable status stranded otherwise reachable workers.
        if !worker.background_network_allowed().await {
            return false;
        }

        let endpoint = worker.endpoint_snapshot().await;
        if let Some(latest) = self.store.latest_for_endpoint(&endpoint) {
            let since = Utc::now() - latest.received_at;
            if since.to_std().unwrap_or_default() < self.config.skip_after {
                return false;
            }
        }

        true
    }
}

/// Completed telemetry retains its original endpoint, administrative generation
/// and deadline until the on-demand API commits it to the cache.
pub(crate) struct CollectedTelemetry {
    endpoint: WorkerEndpointSnapshot,
    telemetry: WorkerTelemetry,
    received_at: DateTime<Utc>,
    observed_at: tokio::time::Instant,
    admission: crate::workers::BackgroundProbe,
    deadline: tokio::time::Instant,
}

/// Collect telemetry from a worker via SSH. The existing separate connection
/// and command allowances share one bounded lifetime through publication.
pub(crate) async fn collect_telemetry_from_worker(
    worker: &WorkerState,
    ssh_timeout: Duration,
) -> anyhow::Result<CollectedTelemetry> {
    collect_telemetry_from_worker_pooled(worker, ssh_timeout, None).await
}

/// Collect telemetry using the optional shared warm connection pool.
pub(crate) async fn collect_telemetry_from_worker_pooled(
    worker: &WorkerState,
    ssh_timeout: Duration,
    ssh_pool: Option<Arc<rch_common::SshPool>>,
) -> anyhow::Result<CollectedTelemetry> {
    collect_telemetry_from_worker_with(worker, ssh_timeout, move |endpoint, timeout, deadline| {
        collect_telemetry_for_endpoint(endpoint, timeout, ssh_pool, deadline)
    })
    .await
}

async fn collect_telemetry_from_worker_with<F, Fut>(
    worker: &WorkerState,
    ssh_timeout: Duration,
    collect: F,
) -> anyhow::Result<CollectedTelemetry>
where
    F: FnOnce(rch_common::WorkerConfig, Duration, tokio::time::Instant) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<WorkerTelemetry>>,
{
    let ssh_timeout = scale_duration(ssh_timeout);
    anyhow::ensure!(!ssh_timeout.is_zero(), "Telemetry collection timed out before admission");
    // Disconnect retains its fixed local cleanup allowance. Remote durations
    // arrive already scaled, and an extreme caller cannot exceed the control cap.
    let budget = ssh_timeout
        .saturating_mul(2)
        .saturating_add(Duration::from_secs(1))
        .min(rch_common::timing::MAX_CONTROL_TIMEOUT);
    let deadline = tokio::time::Instant::now()
        .checked_add(budget)
        .context("Telemetry deadline exceeds the supported clock range")?;
    let collection = async {
        let mut admission = worker
            .background_probe()
            .await
            .context("worker background connections are suspended")?;
        // Release configuration before SSH so a slow poll never holds up
        // worker selection or endpoint reconfiguration.
        let endpoint = worker.endpoint_snapshot().await;
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "Telemetry collection timed out before connection"
        );
        let telemetry = admission
            .run(collect(endpoint.config.clone(), ssh_timeout, deadline))
            .await
            .context("telemetry collection cancelled by worker state change")??;
        let received_at = Utc::now();
        let observed_at = tokio::time::Instant::now();
        anyhow::ensure!(
            admission.is_current() && tokio::time::Instant::now() < deadline,
            "Telemetry collection expired or its worker changed"
        );
        Ok::<_, anyhow::Error>(CollectedTelemetry {
            endpoint,
            telemetry,
            received_at,
            observed_at,
            admission,
            deadline,
        })
    };
    let result = tokio::time::timeout_at(deadline, collection)
        .await
        .context("Telemetry collection timed out")??;
    anyhow::ensure!(
        tokio::time::Instant::now() < deadline,
        "Telemetry collection timed out"
    );
    Ok(result)
}

/// Commit on-demand evidence using the collection's original budget.
pub(crate) async fn publish_collected_telemetry(
    worker: &WorkerState,
    store: &TelemetryStore,
    collected: CollectedTelemetry,
) -> anyhow::Result<WorkerTelemetry> {
    publish_telemetry_before(worker, store, &collected, TelemetrySource::OnDemand, None)
    .await?;
    Ok(collected.telemetry)
}

/// Acquire all publication destinations before changing either telemetry or
/// command-failure evidence. Expiry/cancellation while queued changes neither.
async fn publish_telemetry_before(
    worker: &WorkerState,
    store: &TelemetryStore,
    collected: &CollectedTelemetry,
    source: TelemetrySource,
    circuit_config: Option<&rch_common::CircuitBreakerConfig>,
) -> anyhow::Result<()> {
    let CollectedTelemetry {
        endpoint,
        telemetry,
        received_at,
        observed_at,
        admission,
        deadline,
    } = collected;
    let deadline = *deadline;
    anyhow::ensure!(
        tokio::time::Instant::now() < deadline,
        "Telemetry publication timed out"
    );
    let mut received = ReceivedTelemetry::new(telemetry.clone(), source);
    received.received_at = *received_at;
    let mut pending = Some(StoredTelemetry {
        received,
        observed_at: *observed_at,
        endpoint: Some(endpoint.clone()),
    });
    let publication = async {
        loop {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "Telemetry publication timed out"
            );
            anyhow::ensure!(
                admission.is_current(),
                "worker lifecycle changed during telemetry publication"
            );
            let published = {
                let _endpoint = worker
                    .lock_current_endpoint(endpoint)
                    .await
                    .context("worker endpoint changed during telemetry collection")?;
                let _publication = worker
                    .lock_network_publication(admission)
                    .await
                    .context("worker lifecycle changed during telemetry collection")?;
                let mut circuit = if circuit_config.is_some() {
                    Some(
                        worker
                            .lock_command_outcome_before(deadline)
                            .await
                            .context("Telemetry circuit publication timed out")?,
                    )
                } else {
                    None
                };
                let mut transition = None;
                store
                    .try_publish_before(&mut pending, deadline, || {
                        if !admission.is_current() {
                            return false;
                        }
                        if let (Some(circuit), Some(config)) =
                            (circuit.as_deref_mut(), circuit_config)
                        {
                            let previous = circuit.state();
                            let new = circuit.apply_command_outcome(true, config);
                            transition = Some((previous, new));
                        }
                        true
                    })
                    .then_some(transition)
            };
            if let Some(transition) = published {
                return Ok::<_, anyhow::Error>(transition);
            }
            // Cache contention must not pin the configuration, administrative
            // transition, or circuit guards while this task backs off.
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(Duration::from_millis(5).min(remaining)).await;
        }
    };
    let transition = tokio::time::timeout_at(deadline, publication)
        .await
        .context("Telemetry publication timed out")??;
    // The cache/circuit commit above contains no await. Notifications and
    // asynchronous persistence happen only after every worker guard is released.
    if let Some((previous, new)) = transition
        && previous != new
    {
        info!(
            worker = endpoint.config.id.as_str(),
            "Worker circuit state: {:?} -> {:?} (telemetry poll succeeded)",
            previous,
            new,
        );
    }
    store.notify_ingested(telemetry);
    Ok(())
}

async fn collect_telemetry_for_endpoint(
    worker_config: rch_common::WorkerConfig,
    ssh_timeout: Duration,
    ssh_pool: Option<Arc<rch_common::SshPool>>,
    deadline: tokio::time::Instant,
) -> anyhow::Result<WorkerTelemetry> {
    let worker_id = worker_config.id.clone();
    // Worker IDs come from operator-supplied config (workers.toml), not from
    // a trusted source — a stray quote, semicolon, or `$()` would otherwise
    // be evaluated by the remote shell. Always shell-escape before splicing
    // into the remote command. The companion path in rch/src/hook.rs already
    // uses `shell_escape::escape` for exactly this reason.
    let escaped_worker = shell_escape::escape(worker_config.id.as_str().into());
    // Use rch-wkr from PATH if available, otherwise fallback to ~/.local/bin/rch-wkr
    // This handles non-interactive SSH sessions where ~/.local/bin might not be in PATH
    let command = format!(
        "if command -v rch-wkr >/dev/null 2>&1; then rch-wkr telemetry --format json --worker-id {worker}; else ~/.local/bin/rch-wkr telemetry --format json --worker-id {worker}; fi",
        worker = escaped_worker,
    );

    let options = SshOptions {
        connect_timeout: ssh_timeout,
        command_timeout: ssh_timeout,
        ..Default::default()
    };

    // Reuse a warm ControlMaster via the shared pool when available; otherwise
    // fall back to a throwaway connect+exec+disconnect (mirrors the pattern in
    // TelemetryPoller::run_remote for the on-demand / no-pool paths).
    let result = if let Some(pool) = &ssh_pool {
        pool.run_with_timeout_until(
            &worker_config,
            &command,
            options.command_timeout,
            deadline,
        )
        .await
    } else {
        let mut client = SshClient::new(worker_config, options);
        client.connect_until(deadline).await?;
        let result = client
            .execute_with_timeout_until(&command, ssh_timeout, deadline)
            .await;
        let _ = client.disconnect().await;
        result
    };

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
        warn!(
            worker = worker_id.as_str(),
            "Telemetry protocol version mismatch"
        );
    }

    Ok(telemetry)
}

/// Bound retained diagnostics even when fast failures allow many retries.
const MAX_TELEMETRY_FAILURE_DETAILS: usize = 4;
/// Backoff between poll attempts. Short, so a transient SSH connect failure
/// under contention is retried after the burst clears, without dropping the
/// worker past the stale threshold until the next cycle.
const TELEMETRY_RETRY_BACKOFF: Duration = Duration::from_millis(1500);
/// Local evidence finalization may follow an exhausted remote deadline. This
/// fixed allowance never starts SSH or renews the remote retry budget.
const TELEMETRY_FAILURE_PUBLICATION_ALLOWANCE: Duration = Duration::from_secs(1);

/// Poll one worker and ingest its telemetry. Returns `true` iff telemetry was
/// collected and ingested this call.
///
/// Each attempt is bounded by a hard timeout (the SSH layer's own timeout is not
/// always honored); transient failures retry within one elapsed-time budget.
/// This lets brief SSH contention clear without starting a new deadline on
/// every retry or waiting for the next fleet poll cycle.
/// One failed poll attempt's evidence (bead pn1xb: a worker used to be
/// able to sit telemetry-dark indefinitely with ZERO log lines while a
/// no-fresh-telemetry verdict gated scheduling — the failure log must
/// carry enough to diagnose from journalctl alone).
struct PollAttemptFailure {
    attempt: u32,
    transport: &'static str,
    elapsed: Duration,
    error: String,
}

/// Render the retained recent attempts into one bounded warn line.
fn render_poll_failures(failures: &[PollAttemptFailure]) -> String {
    failures
        .iter()
        .map(|f| {
            format!(
                "attempt {} [{} {:.1}s]: {}",
                f.attempt,
                f.transport,
                f.elapsed.as_secs_f64(),
                // First bytes only: SSH/stderr noise can be huge.
                f.error.chars().take(200).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

async fn poll_worker(
    worker: Arc<WorkerState>,
    store: Arc<TelemetryStore>,
    config: TelemetryPollerConfig,
    ssh_pool: Option<Arc<rch_common::SshPool>>,
) -> bool {
    let transport: &'static str = if ssh_pool.is_some() {
        "pooled-ssh"
    } else {
        "throwaway-ssh"
    };
    let ssh_timeout = scale_duration(config.ssh_timeout);
    poll_worker_with_deadline(worker, store, config, transport, move |endpoint, deadline| {
        collect_telemetry_for_endpoint(endpoint, ssh_timeout, ssh_pool.clone(), deadline)
    })
    .await
}

#[cfg(test)]
async fn poll_worker_with<F, Fut>(
    worker: Arc<WorkerState>,
    store: Arc<TelemetryStore>,
    config: TelemetryPollerConfig,
    transport: &'static str,
    mut collect: F,
) -> bool
where
    F: FnMut(rch_common::WorkerConfig) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<WorkerTelemetry>>,
{
    poll_worker_with_deadline(worker, store, config, transport, move |endpoint, _deadline| {
        collect(endpoint)
    })
    .await
}

async fn poll_worker_with_deadline<F, Fut>(
    worker: Arc<WorkerState>,
    store: Arc<TelemetryStore>,
    config: TelemetryPollerConfig,
    transport: &'static str,
    mut collect: F,
) -> bool
where
    F: FnMut(rch_common::WorkerConfig, tokio::time::Instant) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<WorkerTelemetry>>,
{
    let per_attempt = scale_duration(poll_hard_timeout(config.ssh_timeout));
    let retry_budget = scale_duration(poll_retry_budget(config.ssh_timeout));
    let poll_started = tokio::time::Instant::now();
    let Some(poll_deadline) = poll_started.checked_add(retry_budget) else {
        return false;
    };
    // Acquire after the fleet concurrency permit, under the original budget.
    // Disabling a queued worker must never start SSH or reset its deadline.
    let preparation = async {
        let admission = worker.background_probe().await?;
        let endpoint = worker.endpoint_snapshot().await;
        Some((admission, endpoint))
    };
    let Some((mut admission, endpoint)) =
        tokio::time::timeout_at(poll_deadline, preparation).await.ok().flatten()
    else {
        return false;
    };
    if tokio::time::Instant::now() >= poll_deadline {
        return false;
    }
    // Every retry belongs to this exact endpoint generation. A reload must
    // neither mix old failures with a new host nor admit late old telemetry.
    let worker_id = &endpoint.config.id;
    let mut attempts = 0_u32;
    let mut failures: Vec<PollAttemptFailure> = Vec::new();

    loop {
        if tokio::time::Instant::now() >= poll_deadline {
            break;
        }
        if tokio::time::timeout_at(poll_deadline, worker.lock_current_endpoint(&endpoint))
            .await
            .ok()
            .flatten()
            .is_none()
        {
            return false;
        }
        let remaining = retry_budget.saturating_sub(poll_started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let attempt_timeout = per_attempt.min(remaining);
        let started = tokio::time::Instant::now();
        let Some(attempt_deadline) = started.checked_add(attempt_timeout) else {
            return false;
        };
        let attempt_deadline = attempt_deadline.min(poll_deadline);
        if !admission.is_current() {
            return false;
        }
        if tokio::time::Instant::now() >= attempt_deadline {
            break;
        }
        attempts = attempts.saturating_add(1);
        let Some(outcome) = admission
            .run(tokio::time::timeout_at(
                attempt_deadline,
                collect(endpoint.config.clone(), attempt_deadline),
            ))
            .await
        else {
            return false;
        };
        let failure = match outcome {
            Ok(Ok(telemetry)) => {
                let collected = CollectedTelemetry {
                    endpoint: endpoint.clone(),
                    telemetry,
                    received_at: Utc::now(),
                    observed_at: tokio::time::Instant::now(),
                    admission: admission.clone(),
                    deadline: attempt_deadline,
                };
                match publish_telemetry_before(
                    &worker,
                    &store,
                    &collected,
                    TelemetrySource::SshPoll,
                    Some(&config.circuit),
                )
                .await
                {
                    Ok(()) => {
                        debug!(
                            worker = worker_id.as_str(),
                            attempt = attempts,
                            "Telemetry collected and published via SSH"
                        );
                        return true;
                    }
                    Err(error) => {
                        if !admission.is_current() {
                            return false;
                        }
                        if collected.observed_at < attempt_deadline {
                            // A timely valid command result is not a worker
                            // failure when local publication cannot complete.
                            // Retain the previous cache/circuit evidence and
                            // let the next poll retry with its own admission.
                            warn!(
                                worker = worker_id.as_str(),
                                attempt = attempts,
                                error = %error,
                                "Telemetry collected on time but local publication failed"
                            );
                            return false;
                        }
                        PollAttemptFailure {
                            attempt: attempts,
                            transport,
                            elapsed: started.elapsed(),
                            error: format!("{error:#}"),
                        }
                    }
                }
            }
            Ok(Err(e)) => PollAttemptFailure {
                attempt: attempts,
                transport,
                elapsed: started.elapsed(),
                // The collector's errors carry exit code + stderr for
                // command failures (see collect_telemetry_from_worker_pooled).
                error: format!("{e:#}"),
            },
            Err(_) => PollAttemptFailure {
                attempt: attempts,
                transport,
                elapsed: started.elapsed(),
                error: format!("hard timeout after {attempt_timeout:?}"),
            },
        };
        if failures.len() == MAX_TELEMETRY_FAILURE_DETAILS {
            failures.remove(0);
        }
        failures.push(failure);
        let remaining = retry_budget.saturating_sub(poll_started.elapsed());
        if remaining.is_zero() {
            break;
        }
        if admission
            .run(tokio::time::sleep(TELEMETRY_RETRY_BACKOFF.min(remaining)))
            .await
            .is_none()
        {
            return false;
        }
    }

    warn!(
        worker = worker_id.as_str(),
        attempts,
        budget_s = retry_budget.as_secs_f64(),
        "Telemetry poll failed: {}",
        render_poll_failures(&failures)
    );
    if attempts != 0
        && let Some(deadline) =
            poll_deadline.checked_add(TELEMETRY_FAILURE_PUBLICATION_ALLOWANCE)
    {
        record_poll_failure_before(
            &worker,
            &store,
            &endpoint,
            &admission,
            poll_started,
            deadline,
            &config.circuit,
        )
        .await;
    }
    false
}

/// Feed a telemetry poll outcome to the worker's authoritative circuit as
/// command-class evidence (issue #48).
///
/// The poll runs a real binary on the worker, so it is the same shape as
/// dispatched work; the liveness probe (`echo` over a warm session) is not. A
/// host under fork exhaustion keeps answering the liveness probe while every
/// poll hard-times-out, and on liveness evidence alone the breaker closed and
/// re-admitted it. Exhausting every poll attempt is therefore recorded as a
/// command failure (blocks a half-open close; opens the circuit on its own
/// threshold), and a successful poll clears that evidence.
async fn record_poll_failure_before(
    worker: &WorkerState,
    store: &TelemetryStore,
    endpoint: &WorkerEndpointSnapshot,
    admission: &crate::workers::BackgroundProbe,
    poll_started: tokio::time::Instant,
    deadline: tokio::time::Instant,
    circuit_config: &rch_common::CircuitBreakerConfig,
) -> bool {
    if tokio::time::Instant::now() >= deadline {
        return false;
    }
    let publication = async {
        loop {
            if tokio::time::Instant::now() >= deadline || !admission.is_current() {
                return None;
            }
            let transition = {
                let _endpoint = worker.lock_current_endpoint(endpoint).await?;
                let _network = worker.lock_network_publication(admission).await?;
                let mut circuit = worker.lock_command_outcome_before(deadline).await?;
                let recent = match store.recent.try_read() {
                    Ok(recent) => Some(recent),
                    Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
                    Err(std::sync::TryLockError::WouldBlock) => None,
                };
                if let Some(recent) = recent {
                    if tokio::time::Instant::now() >= deadline || !admission.is_current() {
                        return None;
                    }
                    // A successful sample observed during this poll supersedes
                    // its failure. The monotonic receipt time is preserved
                    // through handoff and cache contention.
                    let superseded = recent
                        .get(endpoint.config.id.as_str())
                        .is_some_and(|entries| {
                            entries.iter().any(|entry| {
                                entry.belongs_to(endpoint) && entry.observed_at >= poll_started
                            })
                        });
                    if superseded
                        || tokio::time::Instant::now() >= deadline
                        || !admission.is_current()
                    {
                        return None;
                    }
                    let previous = circuit.state();
                    let new = circuit.apply_command_outcome(false, circuit_config);
                    Some((previous, new))
                } else {
                    None
                }
            };
            if transition.is_some() {
                return transition;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(Duration::from_millis(5).min(remaining)).await;
        }
    };
    let Some((previous, new)) =
        tokio::time::timeout_at(deadline, publication).await.ok().flatten()
    else {
        return false;
    };
    if previous != new {
        info!(
            worker = endpoint.config.id.as_str(),
            "Worker circuit state: {:?} -> {:?} (telemetry poll exhausted)",
            previous,
            new,
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::CompilationKind;
    use rch_common::WorkerStatus;
    use rch_common::test_guard;
    use rch_telemetry::collect::cpu::{CpuTelemetry, LoadAverage};
    use rch_telemetry::collect::memory::MemoryTelemetry;

    #[test]
    fn poll_failure_rendering_carries_transport_elapsed_and_bounded_error() {
        // pn1xb: the warn line must be diagnosable from journalctl
        // alone — every attempt, its transport, elapsed seconds, and
        // the (bounded) error including exit/stderr detail.
        let failures = vec![
            PollAttemptFailure {
                attempt: 1,
                transport: "pooled-ssh",
                elapsed: Duration::from_millis(24_900),
                error: "hard timeout after 25s".to_owned(),
            },
            PollAttemptFailure {
                attempt: 2,
                transport: "pooled-ssh",
                elapsed: Duration::from_millis(1_200),
                error: format!("Telemetry command failed (exit 1): {}", "x".repeat(500)),
            },
        ];
        let rendered = render_poll_failures(&failures);
        assert!(rendered.contains("attempt 1 [pooled-ssh 24.9s]: hard timeout"));
        assert!(
            rendered.contains("attempt 2 [pooled-ssh 1.2s]: Telemetry command failed (exit 1)")
        );
        // Bounded: a 500-char stderr is clipped to the first 200 chars
        // per attempt, so one noisy worker cannot flood the journal.
        assert!(
            rendered.len() < 500,
            "unbounded error leaked: {} chars",
            rendered.len()
        );
    }

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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(1), None);

        store.ingest(make_telemetry("w1", 10.0, 20.0), TelemetrySource::SshPoll);

        {
            let mut recent = store.recent.write().unwrap();
            let entries = recent.get_mut("w1").expect("missing worker entry");
            entries[0].received.received_at = Utc::now() - ChronoDuration::seconds(120);
        }

        store.ingest(make_telemetry("w1", 30.0, 40.0), TelemetrySource::SshPoll);

        let recent = store.recent.read().unwrap();
        let entries = recent.get("w1").expect("missing worker entry");
        assert_eq!(entries.len(), 1);
        assert!((entries[0].received.telemetry.cpu.overall_percent - 30.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_record_test_run_stats() {
        let _guard = test_guard!();
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
        let stats = store.test_run_stats().await;

        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.passed_runs, 1);
        assert_eq!(stats.failed_runs, 0);
        assert!(stats.avg_duration_ms > 0);
        assert_eq!(stats.runs_by_kind.get("cargo_test"), Some(&1));
    }

    #[test]
    fn test_ingest_emits_websocket_event() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        // Ensure the store works without an event bus (no panics, etc.)
        let store = TelemetryStore::new(Duration::from_secs(300), None);

        store.ingest(make_telemetry("w1", 10.0, 20.0), TelemetrySource::SshPoll);
        store.ingest(make_telemetry("w2", 30.0, 40.0), TelemetrySource::Piggyback);

        let latest = store.latest_all();
        assert_eq!(latest.len(), 2);
    }

    #[test]
    fn test_telemetry_poller_config_default() {
        let _guard = test_guard!();
        let config = TelemetryPollerConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(30));
        assert_eq!(config.ssh_timeout, Duration::from_secs(20));
        assert_eq!(config.skip_after, Duration::from_secs(30));
    }

    #[test]
    fn test_telemetry_poller_config_custom() {
        let _guard = test_guard!();
        let config = TelemetryPollerConfig {
            poll_interval: Duration::from_secs(60),
            ssh_timeout: Duration::from_secs(10),
            skip_after: Duration::from_secs(120),
            ..TelemetryPollerConfig::default()
        };
        assert_eq!(config.poll_interval, Duration::from_secs(60));
        assert_eq!(config.ssh_timeout, Duration::from_secs(10));
        assert_eq!(config.skip_after, Duration::from_secs(120));
    }

    #[test]
    fn test_telemetry_poller_config_clone() {
        let _guard = test_guard!();
        let config = TelemetryPollerConfig::default();
        let cloned = config.clone();
        assert_eq!(config.poll_interval, cloned.poll_interval);
        assert_eq!(config.ssh_timeout, cloned.ssh_timeout);
        assert_eq!(config.skip_after, cloned.skip_after);
    }

    #[test]
    fn test_telemetry_poller_config_debug() {
        let _guard = test_guard!();
        let config = TelemetryPollerConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("TelemetryPollerConfig"));
        assert!(debug_str.contains("poll_interval"));
        assert!(debug_str.contains("ssh_timeout"));
    }

    #[test]
    fn test_store_latest_nonexistent_worker() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        assert!(store.latest("nonexistent").is_none());
    }

    #[test]
    fn test_store_last_received_at_nonexistent_worker() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        assert!(store.last_received_at("nonexistent").is_none());
    }

    #[test]
    fn test_store_latest_all_empty() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        let latest = store.latest_all();
        assert!(latest.is_empty());
    }

    #[tokio::test]
    async fn test_store_latest_speedscore_no_storage() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        let result = store.latest_speedscore("w1").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_store_speedscore_history_no_storage() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        let result = store
            .speedscore_history("w1", Utc::now() - ChronoDuration::hours(1), 10, 0)
            .await;
        assert!(result.is_ok());
        let page = result.unwrap();
        assert_eq!(page.total, 0);
        assert!(page.entries.is_empty());
    }

    #[tokio::test]
    async fn test_store_test_run_stats_empty() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        let stats = store.test_run_stats().await;
        assert_eq!(stats.total_runs, 0);
        assert_eq!(stats.passed_runs, 0);
        assert_eq!(stats.failed_runs, 0);
        assert_eq!(
            stats.scope,
            TestRunStatsScope::RecentMemory { max_records: 200 }
        );
    }

    #[tokio::test]
    async fn test_test_run_scope_tracks_storage_read_failure() {
        let _guard = test_guard!();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.db");
        let storage = Arc::new(TelemetryStorage::new(&path, 30, 24, 365, 0).unwrap());
        let mut store = TelemetryStore::new(Duration::from_secs(300), None);
        let record = TestRunRecord::new(
            "proj".to_string(),
            "worker".to_string(),
            "cargo test".to_string(),
            CompilationKind::CargoTest,
            101,
            5,
        );
        // Populate memory before attaching storage to avoid an asynchronous
        // persistence race. An empty database still has a known stored scope.
        store.record_test_run(record.clone());
        store.storage = Some(Arc::clone(&storage));
        let empty = store.test_run_stats().await;
        assert_eq!(empty.total_runs, 0);
        assert_eq!(empty.scope, TestRunStatsScope::StoredHistory);

        storage.insert_test_run(&record).unwrap();
        let stored = store.test_run_stats().await;
        assert_eq!(stored.total_runs, 1);
        assert_eq!(stored.scope, TestRunStatsScope::StoredHistory);

        // Corrupt an actual row through a separate SQLite connection. The
        // production storage reader rejects its negative duration.
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute("UPDATE test_runs SET duration_ms = -1", [])
            .unwrap();
        assert!(storage.test_run_stats().is_err());
        let fallback = store.test_run_stats().await;
        assert_eq!(fallback.total_runs, 1);
        assert_eq!(fallback.failed_runs, 1);
        assert_eq!(fallback.avg_duration_ms, 5);
        assert_eq!(
            fallback.scope,
            TestRunStatsScope::RecentMemory { max_records: 200 }
        );
    }

    #[tokio::test]
    async fn test_test_run_stats_multiple_runs() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);

        // Successful run (exit code 0)
        let success_run = TestRunRecord::new(
            "proj".to_string(),
            "worker-1".to_string(),
            "cargo test".to_string(),
            CompilationKind::CargoTest,
            0,
            1000,
        );
        store.record_test_run(success_run);

        // Failed command; exit 101 alone does not identify its failed phase.
        let failed_run = TestRunRecord::new(
            "proj".to_string(),
            "worker-2".to_string(),
            "cargo test".to_string(),
            CompilationKind::CargoTest,
            101,
            1001,
        );
        store.record_test_run(failed_run);

        let stats = store.test_run_stats().await;
        assert_eq!(stats.total_runs, 2);
        assert_eq!(stats.passed_runs, 1);
        assert_eq!(stats.failed_runs, 1);
        assert_eq!(stats.avg_duration_ms, 1001);
    }

    #[tokio::test]
    async fn test_test_run_stats_max_capacity() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);

        // Add more than 200 runs (the capacity limit)
        for i in 0..205 {
            let record = TestRunRecord::new(
                format!("proj{}", i),
                "worker-1".to_string(),
                "cargo test".to_string(),
                CompilationKind::CargoTest,
                if i < 5 { 101 } else { 0 },
                100,
            );
            store.record_test_run(record);
        }

        // Should only retain the latest 200
        assert_eq!(store.test_runs.read().unwrap().len(), 200);
        let stats = store.test_run_stats().await;
        assert_eq!(stats.total_runs, 200);
        assert_eq!(stats.passed_runs, 200);
        assert_eq!(stats.failed_runs, 0);
        assert_eq!(
            stats.scope,
            TestRunStatsScope::RecentMemory { max_records: 200 }
        );
    }

    #[test]
    fn test_store_with_short_retention_duration() {
        let _guard = test_guard!();
        // Test that very short retention still works (immediate eviction)
        let store = TelemetryStore::new(Duration::from_millis(1), None);

        // Ingest one entry
        store.ingest(make_telemetry("w1", 10.0, 20.0), TelemetrySource::SshPoll);

        // The entry should exist immediately after insertion
        assert!(store.latest("w1").is_some());

        // Make the entry old
        {
            let mut recent = store.recent.write().unwrap();
            let entries = recent.get_mut("w1").unwrap();
            entries[0].received.received_at = Utc::now() - ChronoDuration::seconds(60);
        }

        // Ingest another entry - should trigger eviction
        store.ingest(make_telemetry("w1", 20.0, 30.0), TelemetrySource::SshPoll);

        // Only the new entry should remain
        let latest = store.latest("w1").unwrap();
        assert!((latest.telemetry.cpu.overall_percent - 20.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_telemetry_poller_creation() {
        use crate::workers::WorkerPool;

        let pool = WorkerPool::new();
        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let config = TelemetryPollerConfig::default();

        let poller = TelemetryPoller::new(pool, store, config);
        // Verify poller was created (can't easily test start without running)
        assert_eq!(poller.config.poll_interval, Duration::from_secs(30));
    }

    fn create_worker_config(id: &str) -> rch_common::WorkerConfig {
        rch_common::WorkerConfig {
            id: rch_common::WorkerId::new(id),
            host: "localhost".to_string(),
            user: "test".to_string(),
            identity_file: "/tmp/key".to_string(),
            total_slots: 8,
            priority: 50,
            tags: vec![],
            tools: Vec::new(),
        }
    }

    async fn assert_telemetry_pending<F: std::future::Future>(mut future: std::pin::Pin<&mut F>) {
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(future.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
    }

    struct HeldTelemetryCache {
        release: Option<std::sync::mpsc::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl HeldTelemetryCache {
        fn new(store: Arc<TelemetryStore>) -> Self {
            let (ready, acquired) = std::sync::mpsc::sync_channel(1);
            let (release, released) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let _cache = store.recent.write().unwrap_or_else(|e| e.into_inner());
                ready.send(()).expect("cache lock receiver");
                released
                    .recv_timeout(Duration::from_secs(10))
                    .expect("test must release the cache lock");
            });
            acquired
                .recv_timeout(Duration::from_secs(10))
                .expect("cache lock acquisition");
            Self {
                release: Some(release),
                thread: Some(thread),
            }
        }
    }

    impl Drop for HeldTelemetryCache {
        fn drop(&mut self) {
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    async fn test_collected_telemetry(
        worker: &WorkerState,
        cpu: f64,
        allowance: Duration,
    ) -> CollectedTelemetry {
        let endpoint = worker.endpoint_snapshot().await;
        let admission = worker.background_probe().await.unwrap();
        CollectedTelemetry {
            telemetry: make_telemetry(endpoint.config.id.as_str(), cpu, 20.0),
            received_at: Utc::now(),
            observed_at: tokio::time::Instant::now(),
            endpoint,
            admission,
            deadline: tokio::time::Instant::now() + allowance,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn on_demand_telemetry_bounds_admission_and_never_starts_after_expiry() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let worker = WorkerState::new(create_worker_config("queued-on-demand"));
        let invoked = AtomicBool::new(false);
        assert!(
            collect_telemetry_from_worker_with(&worker, Duration::ZERO, |_, _, _| {
                invoked.store(true, Ordering::SeqCst);
                std::future::ready(Ok(make_telemetry("queued-on-demand", 10.0, 20.0)))
            })
            .await
            .is_err()
        );
        assert!(!invoked.load(Ordering::SeqCst));

        for timeout in [Duration::from_secs(1), Duration::MAX] {
            let blocked = worker.config.write().await;
            let budget = scale_duration(timeout)
                .saturating_mul(2)
                .saturating_add(Duration::from_secs(1))
                .min(rch_common::timing::MAX_CONTROL_TIMEOUT);
            let mut collection = Box::pin(collect_telemetry_from_worker_with(
                &worker,
                timeout,
                |_, _, _| {
                    invoked.store(true, Ordering::SeqCst);
                    std::future::ready(Ok(make_telemetry("queued-on-demand", 10.0, 20.0)))
                },
            ));
            assert_telemetry_pending(collection.as_mut()).await;
            tokio::time::advance(budget).await;
            drop(blocked);
            assert!(collection.await.is_err());
            assert!(!invoked.load(Ordering::SeqCst));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn on_demand_telemetry_preserves_receipt_time_across_handoff() {
        let worker = WorkerState::new(create_worker_config("receipt-time"));
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        let circuit = rch_common::CircuitBreakerConfig::default();
        worker.record_command_outcome(false, &circuit).await;
        let began = tokio::time::Instant::now();
        let phase = scale_duration(Duration::from_secs(10));
        let budget = phase
            .saturating_mul(2)
            .saturating_add(Duration::from_secs(1))
            .min(rch_common::timing::MAX_CONTROL_TIMEOUT);
        let collected = collect_telemetry_from_worker_with(
            &worker,
            Duration::from_secs(10),
            |endpoint, timeout, deadline| async move {
                assert_eq!(timeout, phase, "the phase must be scaled exactly once");
                assert_eq!(deadline, began + budget);
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(make_telemetry(endpoint.id.as_str(), 42.0, 20.0))
            },
        )
        .await
        .unwrap();
        let received_at = collected.received_at;
        let observed_at = collected.observed_at;
        assert_eq!(observed_at, began + Duration::from_secs(1));
        tokio::time::advance(Duration::from_secs(5)).await;
        let telemetry = publish_collected_telemetry(&worker, &store, collected)
            .await
            .unwrap();
        assert_eq!(telemetry.cpu.overall_percent, 42.0);
        assert_eq!(store.latest("receipt-time").unwrap().received_at, received_at);
        assert_eq!(
            store.recent.read().unwrap()["receipt-time"].back().unwrap().observed_at,
            observed_at
        );
        assert_eq!(
            worker.circuit_stats().await.consecutive_command_failures(),
            1,
            "on-demand collection does not rewrite periodic command evidence"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn telemetry_publication_rejects_expired_circuit_wait_and_recovers() {
        for lateness in [Duration::ZERO, Duration::from_millis(1)] {
            let worker = WorkerState::new(create_worker_config("queued-publication"));
            let store = TelemetryStore::new(Duration::from_secs(300), None);
            let circuit = rch_common::CircuitBreakerConfig::default();
            worker.record_command_outcome(false, &circuit).await;
            let endpoint = worker.endpoint_snapshot().await;
            store.ingest_for_endpoint(
                make_telemetry("queued-publication", 10.0, 20.0),
                TelemetrySource::SshPoll,
                &endpoint,
            );
            let allowance = Duration::from_secs(2);
            let collected = test_collected_telemetry(&worker, 90.0, allowance).await;
            let blocked = worker
                .lock_command_outcome_before(
                    tokio::time::Instant::now() + Duration::from_secs(30),
                )
                .await
                .unwrap();
            let mut publication = Box::pin(publish_telemetry_before(
                &worker,
                &store,
                &collected,
                TelemetrySource::SshPoll,
                Some(&circuit),
            ));
            assert_telemetry_pending(publication.as_mut()).await;
            tokio::time::advance(allowance + lateness).await;
            drop(blocked);
            assert!(publication.await.is_err());
            assert_eq!(
                store.latest("queued-publication").unwrap().telemetry.cpu.overall_percent,
                10.0
            );
            assert_eq!(
                worker.circuit_stats().await.consecutive_command_failures(),
                1
            );

            let fresh = test_collected_telemetry(&worker, 20.0, allowance).await;
            publish_telemetry_before(
                &worker,
                &store,
                &fresh,
                TelemetrySource::SshPoll,
                Some(&circuit),
            )
            .await
            .unwrap();
            assert_eq!(
                store.latest("queued-publication").unwrap().telemetry.cpu.overall_percent,
                20.0
            );
            assert_eq!(
                worker.circuit_stats().await.consecutive_command_failures(),
                0
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timely_telemetry_with_blocked_publication_retains_evidence_and_recovers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for destination in ["cache", "circuit"] {
            for lateness in [Duration::ZERO, Duration::from_millis(1)] {
                let worker = Arc::new(WorkerState::new(create_worker_config("local-contention")));
                let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
                let config = TelemetryPollerConfig {
                    ssh_timeout: Duration::from_secs(1),
                    ..TelemetryPollerConfig::default()
                };
                worker.record_command_outcome(false, &config.circuit).await;
                let endpoint = worker.endpoint_snapshot().await;
                store.ingest_for_endpoint(
                    make_telemetry("local-contention", 10.0, 20.0),
                    TelemetrySource::SshPoll,
                    &endpoint,
                );
                let previous = store.latest("local-contention").unwrap();
                // Ensure the previous sample cannot supersede this poll's
                // failure merely because paused receipt times are equal.
                tokio::time::advance(Duration::from_millis(1)).await;
                let blocked_circuit = if destination == "circuit" {
                    Some(
                        worker
                            .lock_command_outcome_before(
                                tokio::time::Instant::now() + Duration::from_secs(1),
                            )
                            .await
                            .unwrap(),
                    )
                } else {
                    None
                };
                let blocked_cache = (destination == "cache")
                    .then(|| HeldTelemetryCache::new(store.clone()));
                let attempts = AtomicUsize::new(0);
                let per_attempt = scale_duration(poll_hard_timeout(config.ssh_timeout));
                let started = tokio::time::Instant::now();
                let mut poll = Box::pin(poll_worker_with(
                    worker.clone(),
                    store.clone(),
                    config.clone(),
                    "local-publication-test",
                    |endpoint| {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(make_telemetry(endpoint.id.as_str(), 90.0, 20.0)))
                    },
                ));
                assert_telemetry_pending(poll.as_mut()).await;
                assert_eq!(attempts.load(Ordering::SeqCst), 1);
                tokio::time::advance(per_attempt + lateness).await;
                drop(blocked_circuit);
                drop(blocked_cache);
                assert!(!poll.await, "{destination}: expired local publication");
                assert_eq!(attempts.load(Ordering::SeqCst), 1);
                assert_eq!(started.elapsed(), per_attempt + lateness);
                let retained = store.latest("local-contention").unwrap();
                assert_eq!(retained.received_at, previous.received_at);
                assert_eq!(retained.telemetry.cpu.overall_percent, 10.0);
                assert_eq!(
                    worker.circuit_stats().await.consecutive_command_failures(),
                    1,
                    "{destination}: local contention must not penalize the worker",
                );

                assert!(
                    poll_worker_with(
                        worker.clone(),
                        store.clone(),
                        config,
                        "fresh-publication-test",
                        |endpoint| {
                            attempts.fetch_add(1, Ordering::SeqCst);
                            std::future::ready(Ok(make_telemetry(
                                endpoint.id.as_str(),
                                20.0,
                                20.0,
                            )))
                        },
                    )
                    .await
                );
                assert_eq!(attempts.load(Ordering::SeqCst), 2);
                assert_eq!(
                    store.latest("local-contention").unwrap().telemetry.cpu.overall_percent,
                    20.0
                );
                assert_eq!(
                    worker.circuit_stats().await.consecutive_command_failures(),
                    0
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn on_demand_cache_contention_expires_or_cancels_without_partial_publication() {
        for action in ["expire", "disable", "drop"] {
            let worker = WorkerState::new(create_worker_config("busy-cache"));
            let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
            let circuit = rch_common::CircuitBreakerConfig::default();
            worker.record_command_outcome(false, &circuit).await;
            store.ingest(
                make_telemetry("busy-cache", 10.0, 20.0),
                TelemetrySource::SshPoll,
            );
            let allowance = Duration::from_secs(2);
            let collected = test_collected_telemetry(&worker, 90.0, allowance).await;
            let blocked = HeldTelemetryCache::new(store.clone());
            let mut publication = Box::pin(publish_collected_telemetry(
                &worker,
                &store,
                collected,
            ));
            assert_telemetry_pending(publication.as_mut()).await;
            match action {
                "expire" => {
                    tokio::time::advance(allowance).await;
                    assert!(publication.await.is_err());
                }
                "disable" => {
                    tokio::time::timeout(
                        Duration::from_millis(10),
                        worker.disable(Some("maintenance".into())),
                    )
                    .await
                    .expect("cache backoff must release administrative guards");
                    assert!(publication.await.is_err());
                }
                "drop" => drop(publication),
                _ => unreachable!(),
            }
            drop(blocked);
            assert_eq!(store.latest("busy-cache").unwrap().telemetry.cpu.overall_percent, 10.0);
            assert_eq!(
                worker.circuit_stats().await.consecutive_command_failures(),
                1
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expired_poll_failure_has_only_a_bounded_local_publication_window() {
        for lateness in [Duration::ZERO, Duration::from_millis(1)] {
            let worker = WorkerState::new(create_worker_config("queued-failure"));
            let store = TelemetryStore::new(Duration::from_secs(300), None);
            let circuit = rch_common::CircuitBreakerConfig::default();
            let endpoint = worker.endpoint_snapshot().await;
            let admission = worker.background_probe().await.unwrap();
            let poll_started = tokio::time::Instant::now();
            let blocked = worker
                .lock_command_outcome_before(poll_started + Duration::from_secs(30))
                .await
                .unwrap();
            let deadline = poll_started + TELEMETRY_FAILURE_PUBLICATION_ALLOWANCE;
            let mut publication = Box::pin(record_poll_failure_before(
                &worker,
                &store,
                &endpoint,
                &admission,
                poll_started,
                deadline,
                &circuit,
            ));
            assert_telemetry_pending(publication.as_mut()).await;
            tokio::time::advance(TELEMETRY_FAILURE_PUBLICATION_ALLOWANCE + lateness).await;
            drop(blocked);
            assert!(!publication.await);
            assert_eq!(worker.circuit_stats().await.consecutive_command_failures(), 0);
            assert!(
                record_poll_failure_before(
                    &worker,
                    &store,
                    &endpoint,
                    &admission,
                    poll_started,
                    tokio::time::Instant::now() + TELEMETRY_FAILURE_PUBLICATION_ALLOWANCE,
                    &circuit,
                )
                .await
            );
            assert_eq!(worker.circuit_stats().await.consecutive_command_failures(), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_older_failed_poll_cannot_replace_newer_success_evidence() {
        let worker = WorkerState::new(create_worker_config("superseded-failure"));
        let store = TelemetryStore::new(Duration::from_secs(300), None);
        let circuit = rch_common::CircuitBreakerConfig::default();
        let endpoint = worker.endpoint_snapshot().await;
        let admission = worker.background_probe().await.unwrap();
        let poll_started = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1)).await;
        let collected =
            test_collected_telemetry(&worker, 42.0, Duration::from_secs(2)).await;
        publish_telemetry_before(
            &worker,
            &store,
            &collected,
            TelemetrySource::SshPoll,
            Some(&circuit),
        )
        .await
        .unwrap();
        assert!(
            !record_poll_failure_before(
                &worker,
                &store,
                &endpoint,
                &admission,
                poll_started,
                tokio::time::Instant::now() + TELEMETRY_FAILURE_PUBLICATION_ALLOWANCE,
                &circuit,
            )
            .await
        );
        assert_eq!(worker.circuit_stats().await.consecutive_command_failures(), 0);
        assert_eq!(
            store.latest("superseded-failure").unwrap().telemetry.cpu.overall_percent,
            42.0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failed_poll_cache_backoff_does_not_block_administrative_cancellation() {
        let worker = WorkerState::new(create_worker_config("cancel-failure"));
        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let circuit = rch_common::CircuitBreakerConfig::default();
        let endpoint = worker.endpoint_snapshot().await;
        let admission = worker.background_probe().await.unwrap();
        let poll_started = tokio::time::Instant::now();
        let blocked = HeldTelemetryCache::new(store.clone());
        let mut publication = Box::pin(record_poll_failure_before(
            &worker,
            &store,
            &endpoint,
            &admission,
            poll_started,
            poll_started + TELEMETRY_FAILURE_PUBLICATION_ALLOWANCE,
            &circuit,
        ));
        assert_telemetry_pending(publication.as_mut()).await;
        tokio::time::timeout(
            Duration::from_millis(10),
            worker.disable(Some("maintenance".into())),
        )
        .await
        .expect("failure cache backoff must release administrative guards");
        assert!(!publication.await);
        drop(blocked);
        assert!(store.latest("cancel-failure").is_none());
        assert_eq!(worker.circuit_stats().await.consecutive_command_failures(), 0);
    }

    #[test]
    fn telemetry_retry_budget_preserves_full_attempt_allowance_without_overflow() {
        assert_eq!(
            poll_retry_budget(Duration::from_secs(20)),
            Duration::from_millis(51_500)
        );
        assert_eq!(poll_hard_timeout(Duration::MAX), Duration::MAX);
        assert_eq!(poll_retry_budget(Duration::MAX), Duration::MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn telemetry_at_deadline_never_refreshes_or_clears_failure_evidence() {
        for ssh_timeout in [Duration::from_secs(20), Duration::MAX] {
            let worker = Arc::new(WorkerState::new(create_worker_config("late-poll")));
            let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
            let config = TelemetryPollerConfig {
                ssh_timeout,
                ..TelemetryPollerConfig::default()
            };
            let per_attempt = scale_duration(poll_hard_timeout(ssh_timeout));
            let budget = scale_duration(poll_retry_budget(ssh_timeout));
            let started = tokio::time::Instant::now();
            let success = poll_worker_with(
                worker.clone(),
                store.clone(),
                config,
                "late-test-transport",
                |endpoint| async move {
                    tokio::time::sleep(per_attempt).await;
                    Ok(make_telemetry(endpoint.id.as_str(), 90.0, 90.0))
                },
            )
            .await;
            assert!(!success, "a deadline-boundary result was published");
            assert_eq!(started.elapsed(), budget);
            assert!(store.latest("late-poll").is_none());
            assert!(store.last_received_at("late-poll").is_none());
            assert_eq!(
                worker.circuit_stats().await.consecutive_command_failures(),
                1,
                "the exhausted poll must retain command-failure evidence"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn telemetry_can_recover_with_timely_evidence_after_a_late_attempt() {
        let worker = Arc::new(WorkerState::new(create_worker_config("late-then-ready")));
        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let config = TelemetryPollerConfig::default();
        let per_attempt = scale_duration(poll_hard_timeout(config.ssh_timeout));
        let budget = scale_duration(poll_retry_budget(config.ssh_timeout));
        let started = tokio::time::Instant::now();
        let mut attempts = 0;
        let success = poll_worker_with(
            worker.clone(),
            store.clone(),
            config,
            "recovered-test-transport",
            |endpoint| {
                attempts += 1;
                let attempt = attempts;
                async move {
                    if attempt == 1 {
                        tokio::time::sleep(per_attempt).await;
                    }
                    Ok(make_telemetry(
                        endpoint.id.as_str(),
                        if attempt == 1 { 90.0 } else { 10.0 },
                        20.0,
                    ))
                }
            },
        )
        .await;
        assert!(success);
        assert_eq!(attempts, 2, "late data must not end the poll successfully");
        assert!(started.elapsed() < budget);
        let received = store.latest("late-then-ready").unwrap();
        assert!((received.telemetry.cpu.overall_percent - 10.0).abs() < f64::EPSILON);
        assert_eq!(
            worker.circuit_stats().await.consecutive_command_failures(),
            0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn telemetry_recovers_after_more_than_two_transient_failures() {
        let worker = Arc::new(WorkerState::new(create_worker_config("busy-poll")));
        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let mut attempts = 0;
        let started = tokio::time::Instant::now();
        assert!(
            poll_worker_with(
                worker.clone(),
                store.clone(),
                TelemetryPollerConfig::default(),
                "busy-test-transport",
                |endpoint| {
                    attempts += 1;
                    std::future::ready(if attempts <= 2 {
                        Err(anyhow::anyhow!("SSH temporarily busy"))
                    } else {
                        Ok(make_telemetry(endpoint.id.as_str(), 10.0, 20.0))
                    })
                },
            )
            .await
        );
        assert_eq!(attempts, 3);
        assert_eq!(started.elapsed(), TELEMETRY_RETRY_BACKOFF * 2);
        assert!(store.latest("busy-poll").is_some());
        assert_eq!(
            worker.circuit_stats().await.consecutive_command_failures(),
            0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn telemetry_hung_and_fast_failures_share_one_elapsed_budget() {
        for hung in [false, true] {
            let worker = Arc::new(WorkerState::new(create_worker_config("exhausted-poll")));
            let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
            let config = TelemetryPollerConfig::default();
            let budget = scale_duration(poll_retry_budget(config.ssh_timeout));
            let started = tokio::time::Instant::now();
            let mut attempts = 0;
            assert!(
                !poll_worker_with(
                    worker.clone(),
                    store.clone(),
                    config,
                    "failing-test-transport",
                    |_| {
                        attempts += 1;
                        async move {
                            if hung {
                                std::future::pending().await
                            } else {
                                Err(anyhow::anyhow!("SSH remains unavailable"))
                            }
                        }
                    },
                )
                .await
            );
            assert!(attempts >= 2);
            if !hung {
                assert!(attempts > 2, "fast failures must use the remaining budget");
            }
            assert!(started.elapsed() >= budget);
            assert!(started.elapsed() <= budget + Duration::from_millis(1));
            assert!(store.latest("exhausted-poll").is_none());
            assert_eq!(
                worker.circuit_stats().await.consecutive_command_failures(),
                1,
                "a whole exhausted poll contributes one command failure"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn disabling_during_telemetry_backoff_cancels_future_attempts() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let worker = Arc::new(WorkerState::new(create_worker_config("backoff-poll")));
        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let started = Arc::new(tokio::sync::Notify::new());
        let attempts = Arc::new(AtomicUsize::new(0));
        let task = {
            let worker = worker.clone();
            let store = store.clone();
            let started = started.clone();
            let attempts = attempts.clone();
            tokio::spawn(async move {
                poll_worker_with(
                    worker,
                    store,
                    TelemetryPollerConfig::default(),
                    "retry-test-transport",
                    move |_| {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        std::future::ready(Err(anyhow::anyhow!("retryable SSH failure")))
                    },
                )
                .await
            })
        };
        started.notified().await;
        worker.disable(Some("maintenance".into())).await;
        assert!(!task.await.unwrap());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(store.latest("backoff-poll").is_none());
        assert_eq!(
            worker.circuit_stats().await.consecutive_command_failures(),
            0,
            "administrative cancellation must not publish failure evidence"
        );
    }

    #[tokio::test]
    async fn disabled_worker_never_enters_telemetry_transport() {
        let worker = Arc::new(WorkerState::new(create_worker_config("disabled-poll")));
        worker
            .disable(Some("powered off for the night".into()))
            .await;
        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        assert!(
            !poll_worker_with(
                worker,
                store,
                TelemetryPollerConfig::default(),
                "must-not-connect",
                |_| async { panic!("disabled telemetry must never dial") },
            )
            .await
        );
    }

    #[tokio::test]
    async fn administrative_change_cancels_telemetry_without_retry_or_publication() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for reenable_immediately in [false, true] {
            let worker = Arc::new(WorkerState::new(create_worker_config("active-poll")));
            let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
            let started = Arc::new(tokio::sync::Notify::new());
            let attempts = Arc::new(AtomicUsize::new(0));
            let task = {
                let worker = worker.clone();
                let store = store.clone();
                let started = started.clone();
                let attempts = attempts.clone();
                tokio::spawn(async move {
                    poll_worker_with(
                        worker,
                        store,
                        TelemetryPollerConfig::default(),
                        "vpn-blackhole",
                        move |_| {
                            attempts.fetch_add(1, Ordering::SeqCst);
                            started.notify_one();
                            std::future::pending()
                        },
                    )
                    .await
                })
            };
            tokio::time::timeout(Duration::from_secs(1), started.notified())
                .await
                .expect("poll must start");
            worker.disable(Some("maintenance".into())).await;
            if reenable_immediately {
                worker.enable().await;
            }
            assert!(
                !tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .expect("disable must cancel a hung poll immediately")
                    .unwrap()
            );
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            assert!(store.latest("active-poll").is_none());
            assert_eq!(
                worker.circuit_stats().await.consecutive_command_failures(),
                0
            );
        }
    }

    #[tokio::test]
    async fn late_poll_results_cannot_replace_new_endpoint_telemetry_or_circuit_evidence() {
        for success in [false, true] {
            for return_to_original in [false, true] {
                let original = create_worker_config("retargeted-telemetry");
                let worker = Arc::new(WorkerState::new(original.clone()));
                let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
                let started = Arc::new(tokio::sync::Notify::new());
                let release = Arc::new(tokio::sync::Notify::new());
                let task = {
                    let worker = worker.clone();
                    let store = store.clone();
                    let started = started.clone();
                    let release = release.clone();
                    tokio::spawn(async move {
                        poll_worker_with(
                            worker,
                            store,
                            TelemetryPollerConfig::default(),
                            "suspended-test-transport",
                            move |endpoint| {
                                let started = started.clone();
                                let release = release.clone();
                                async move {
                                    assert_eq!(endpoint.host, "localhost");
                                    started.notify_one();
                                    release.notified().await;
                                    if success {
                                        Ok(make_telemetry(endpoint.id.as_str(), 99.0, 99.0))
                                    } else {
                                        Err(anyhow::anyhow!("old endpoint failed"))
                                    }
                                }
                            },
                        )
                        .await
                    })
                };
                tokio::time::timeout(Duration::from_secs(1), started.notified())
                    .await
                    .expect("poll must enter transport");
                let mut replacement = original.clone();
                replacement.host = "replacement.host".to_string();
                tokio::time::timeout(Duration::from_secs(1), async {
                    assert!(worker.update_config(replacement).await);
                    if return_to_original {
                        assert!(worker.update_config(original).await);
                    }
                })
                .await
                .expect("telemetry I/O must not hold the configuration lock");

                assert!(!worker.background_network_allowed().await);
                let circuit = rch_common::CircuitBreakerConfig::default();
                worker
                    .record_transport_result(true, Duration::from_secs(30), &circuit)
                    .await;
                // Evidence produced by the replacement must survive a late
                // old success just as it survives a late old failure.
                worker.record_command_outcome(false, &circuit).await;
                store.ingest(
                    make_telemetry("retargeted-telemetry", 42.0, 42.0),
                    TelemetrySource::SshPoll,
                );
                release.notify_one();
                assert!(
                    !tokio::time::timeout(Duration::from_secs(1), task)
                        .await
                        .expect("stale poll must stop without retrying the old endpoint")
                        .unwrap()
                );
                assert_eq!(
                    worker.circuit_stats().await.consecutive_command_failures(),
                    1
                );
                assert_eq!(
                    store
                        .latest("retargeted-telemetry")
                        .unwrap()
                        .telemetry
                        .cpu
                        .overall_percent,
                    42.0
                );

                assert!(
                    poll_worker_with(
                        worker.clone(),
                        store.clone(),
                        TelemetryPollerConfig::default(),
                        "fresh-test-transport",
                        |endpoint| std::future::ready(Ok(make_telemetry(
                            endpoint.id.as_str(),
                            10.0,
                            10.0
                        ))),
                    )
                    .await
                );
                assert_eq!(
                    worker.circuit_stats().await.consecutive_command_failures(),
                    0
                );
                assert_eq!(
                    store
                        .latest("retargeted-telemetry")
                        .unwrap()
                        .telemetry
                        .cpu
                        .overall_percent,
                    10.0
                );
            }
        }
    }

    #[tokio::test]
    async fn test_should_poll_worker_healthy() {
        use crate::workers::WorkerPool;
        use rch_common::WorkerId;

        let pool = WorkerPool::new();
        pool.add_worker(create_worker_config("test-worker")).await;

        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let poller_config = TelemetryPollerConfig::default();
        let poller = TelemetryPoller::new(pool.clone(), store, poller_config);

        let worker = pool.get(&WorkerId::new("test-worker")).await.unwrap();
        // Worker is healthy and no recent telemetry, should poll
        let should_poll = poller.should_poll_worker(&worker).await;
        assert!(should_poll);
    }

    #[tokio::test]
    async fn test_should_poll_worker_unreachable_is_still_polled() {
        use crate::workers::WorkerPool;
        use rch_common::WorkerId;

        let pool = WorkerPool::new();
        pool.add_worker(create_worker_config("unreachable-worker"))
            .await;

        let worker = pool
            .get(&WorkerId::new("unreachable-worker"))
            .await
            .unwrap();
        worker.set_status(WorkerStatus::Unreachable).await;

        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let poller_config = TelemetryPollerConfig::default();
        let poller = TelemetryPoller::new(pool, store, poller_config);

        // A health-excluded (Unreachable, admin=Active) worker MUST still be
        // polled: fresh telemetry is its path back to healthy. Skipping it was
        // the stranding deadlock (2026-07-16 offload meltdown).
        let should_poll = poller.should_poll_worker(&worker).await;
        assert!(should_poll);
    }

    #[tokio::test]
    async fn test_should_poll_worker_quarantined_bypass_is_still_polled() {
        use crate::workers::WorkerPool;
        use rch_common::BypassFailureClass;
        use rch_common::WorkerId;

        let pool = WorkerPool::new();
        pool.add_worker(create_worker_config("bypassed-worker"))
            .await;

        let worker = pool.get(&WorkerId::new("bypassed-worker")).await.unwrap();
        // Quarantine it exactly as the bypass-recovery service does. Its legacy
        // status() collapses to Unreachable, but its admin intent is still
        // Active — the recovery gate needs telemetry_ok, so the poller MUST
        // keep polling it. This is the specific state the old skip stranded.
        worker.enter_bypass(BypassFailureClass::Ssh).await;
        assert_eq!(worker.status().await, WorkerStatus::Unreachable);

        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let poller_config = TelemetryPollerConfig::default();
        let poller = TelemetryPoller::new(pool, store, poller_config);

        let should_poll = poller.should_poll_worker(&worker).await;
        assert!(
            should_poll,
            "a TemporaryBypass worker must be polled so it can recover"
        );
    }

    #[tokio::test]
    async fn transport_outage_suppresses_telemetry_until_health_recovers_without_stranding_bypass()
    {
        let pool = WorkerPool::new();
        let config = create_worker_config("offline-quarantine");
        pool.add_worker(config.clone()).await;
        let worker = pool.get(&config.id).await.unwrap();
        worker
            .enter_bypass(rch_common::BypassFailureClass::DiskInodePressure)
            .await;
        let circuit = rch_common::CircuitBreakerConfig::default();
        for _ in 0..circuit.failure_threshold {
            worker
                .record_transport_result(false, Duration::from_secs(30), &circuit)
                .await;
        }
        assert!(worker.transport_is_down().await);
        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let poller = TelemetryPoller::new(pool, store.clone(), TelemetryPollerConfig::default());
        assert!(!poller.should_poll_worker(&worker).await);
        assert!(
            !poll_worker_with(
                worker.clone(),
                store,
                TelemetryPollerConfig::default(),
                "must-not-bypass-recovery-cadence",
                |_| async { panic!("telemetry may not probe an offline transport") },
            )
            .await
        );

        worker
            .record_transport_result(true, Duration::from_secs(30), &circuit)
            .await;
        assert!(poller.should_poll_worker(&worker).await);
        assert_eq!(
            worker.lifecycle().await.bypass_cause,
            Some(rch_common::BypassFailureClass::DiskInodePressure),
            "transport recovery must preserve independent disk quarantine"
        );
    }

    #[tokio::test]
    async fn test_should_poll_worker_disabled() {
        use crate::workers::WorkerPool;
        use rch_common::WorkerId;

        let pool = WorkerPool::new();
        pool.add_worker(create_worker_config("disabled-worker"))
            .await;

        let worker = pool.get(&WorkerId::new("disabled-worker")).await.unwrap();
        worker.set_status(WorkerStatus::Disabled).await;

        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let poller_config = TelemetryPollerConfig::default();
        let poller = TelemetryPoller::new(pool, store, poller_config);

        // Disabled workers should not be polled
        let should_poll = poller.should_poll_worker(&worker).await;
        assert!(!should_poll);
    }

    #[tokio::test]
    async fn test_should_poll_worker_recent_telemetry() {
        use crate::workers::WorkerPool;
        use rch_common::WorkerId;

        let pool = WorkerPool::new();
        pool.add_worker(create_worker_config("recent-telemetry-worker"))
            .await;

        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));

        // Ingest recent telemetry for this worker
        store.ingest(
            make_telemetry("recent-telemetry-worker", 50.0, 60.0),
            TelemetrySource::SshPoll,
        );

        let poller_config = TelemetryPollerConfig {
            skip_after: Duration::from_secs(60), // Skip if telemetry < 60s old
            ..Default::default()
        };
        let poller = TelemetryPoller::new(pool.clone(), store, poller_config);

        let worker = pool
            .get(&WorkerId::new("recent-telemetry-worker"))
            .await
            .unwrap();

        // Should skip polling because we just received telemetry
        let should_poll = poller.should_poll_worker(&worker).await;
        assert!(!should_poll);
    }

    #[tokio::test]
    async fn cached_telemetry_cannot_suppress_replacement_polling_or_rebind_after_aba() {
        for originally_bound in [false, true] {
            for return_to_original in [false, true] {
                let pool = WorkerPool::new();
                let original = create_worker_config("cached-before-retarget");
                pool.add_worker(original.clone()).await;
                let worker = pool.get(&original.id).await.unwrap();
                let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
                let poller =
                    TelemetryPoller::new(pool, store.clone(), TelemetryPollerConfig::default());
                let before = worker.endpoint_snapshot().await;
                let old_sample = make_telemetry(original.id.as_str(), 99.0, 99.0);
                if originally_bound {
                    store.ingest_for_endpoint(old_sample, TelemetrySource::SshPoll, &before);
                } else {
                    store.ingest(old_sample, TelemetrySource::Piggyback);
                }
                assert!(!poller.should_poll_worker(&worker).await);

                let mut replacement = original.clone();
                replacement.host = "replacement.host".to_string();
                assert!(worker.update_config(replacement).await);
                if return_to_original {
                    assert!(worker.update_config(original.clone()).await);
                }
                let current = worker.endpoint_snapshot().await;
                assert!(!poller.should_poll_worker(&worker).await);
                worker
                    .record_transport_result(
                        true,
                        Duration::from_secs(30),
                        &rch_common::CircuitBreakerConfig::default(),
                    )
                    .await;
                assert!(
                    store.latest(original.id.as_str()).is_some(),
                    "history is retained"
                );
                assert!(store.latest_for_endpoint(&current).is_none());
                assert!(poller.should_poll_worker(&worker).await);

                // An ID-only push arriving after the reload cannot manufacture
                // evidence for the replacement, even if its receipt is recent.
                store.ingest(
                    make_telemetry(original.id.as_str(), 98.0, 98.0),
                    TelemetrySource::Piggyback,
                );
                assert!(store.latest_for_endpoint(&current).is_none());
                assert!(poller.should_poll_worker(&worker).await);

                assert!(
                    poll_worker_with(
                        worker.clone(),
                        store.clone(),
                        TelemetryPollerConfig::default(),
                        "fresh-bound-transport",
                        |endpoint| {
                            std::future::ready(Ok(make_telemetry(endpoint.id.as_str(), 10.0, 10.0)))
                        },
                    )
                    .await
                );
                assert!(!poller.should_poll_worker(&worker).await);
                store.ingest(
                    make_telemetry(original.id.as_str(), 97.0, 97.0),
                    TelemetrySource::Piggyback,
                );
                assert_eq!(
                    store
                        .latest_for_endpoint(&current)
                        .unwrap()
                        .telemetry
                        .cpu
                        .overall_percent,
                    10.0,
                    "unbound pushes must not mask the valid bound observation"
                );

                let mut capacity_only = current.config.clone();
                capacity_only.total_slots += 1;
                assert!(!worker.update_config(capacity_only).await);
                assert!(!poller.should_poll_worker(&worker).await);
            }
        }
    }

    #[tokio::test]
    async fn test_poll_once_empty_pool() {
        use crate::workers::WorkerPool;

        let pool = WorkerPool::new();
        let store = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let config = TelemetryPollerConfig::default();
        let poller = TelemetryPoller::new(pool, store, config);

        // Poll with empty pool should succeed
        let result = poller.poll_once().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_telemetry_source_variants() {
        let _guard = test_guard!();
        // Verify all telemetry source variants can be used
        let _ssh_poll = TelemetrySource::SshPoll;
        let _piggyback = TelemetrySource::Piggyback;

        // Test that they can be compared
        assert_ne!(TelemetrySource::SshPoll, TelemetrySource::Piggyback);
    }

    #[test]
    fn test_received_telemetry_creation() {
        let _guard = test_guard!();
        let telemetry = make_telemetry("test-worker", 25.0, 35.0);
        let received = ReceivedTelemetry::new(telemetry.clone(), TelemetrySource::SshPoll);

        assert_eq!(received.telemetry.worker_id, "test-worker");
        assert_eq!(received.source, TelemetrySource::SshPoll);
        // received_at should be close to now
        let elapsed = (Utc::now() - received.received_at).num_seconds();
        assert!(elapsed.abs() < 2); // Within 2 seconds
    }

    #[test]
    fn test_evict_old_removes_multiple() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(1), None);

        // Add multiple entries
        store.ingest(make_telemetry("w1", 10.0, 20.0), TelemetrySource::SshPoll);
        store.ingest(make_telemetry("w1", 20.0, 30.0), TelemetrySource::SshPoll);
        store.ingest(make_telemetry("w1", 30.0, 40.0), TelemetrySource::SshPoll);

        // Make all entries old
        {
            let mut recent = store.recent.write().unwrap();
            let entries = recent.get_mut("w1").unwrap();
            for entry in entries.iter_mut() {
                entry.received.received_at = Utc::now() - ChronoDuration::seconds(120);
            }
        }

        // Ingest a new one to trigger eviction
        store.ingest(make_telemetry("w1", 50.0, 60.0), TelemetrySource::SshPoll);

        let recent = store.recent.read().unwrap();
        let entries = recent.get("w1").unwrap();
        // Only the newest should remain
        assert_eq!(entries.len(), 1);
        assert!((entries[0].received.telemetry.cpu.overall_percent - 50.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_test_run_different_kinds() {
        let _guard = test_guard!();
        let store = TelemetryStore::new(Duration::from_secs(300), None);

        // Different compilation kinds
        store.record_test_run(TestRunRecord::new(
            "proj".to_string(),
            "w1".to_string(),
            "cargo build".to_string(),
            CompilationKind::CargoBuild,
            0,
            1000,
        ));

        store.record_test_run(TestRunRecord::new(
            "proj".to_string(),
            "w1".to_string(),
            "cargo check".to_string(),
            CompilationKind::CargoCheck,
            0,
            500,
        ));

        store.record_test_run(TestRunRecord::new(
            "proj".to_string(),
            "w1".to_string(),
            "cargo clippy".to_string(),
            CompilationKind::CargoClippy,
            0,
            800,
        ));

        let stats = store.test_run_stats().await;
        assert_eq!(stats.total_runs, 3);
        assert_eq!(stats.passed_runs, 3);
        assert!(stats.runs_by_kind.contains_key("cargo_build"));
        assert!(stats.runs_by_kind.contains_key("cargo_check"));
        assert!(stats.runs_by_kind.contains_key("cargo_clippy"));
    }
}
