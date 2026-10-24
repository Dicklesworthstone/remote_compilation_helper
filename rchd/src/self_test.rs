//! Scheduled self-test runner and history tracking.
//!
//! Executes periodic remote compilation verification tests and stores
//! run history for CLI/dashboard reporting.

use crate::workers::WorkerPool;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rch_common::remote_compilation::RemoteCompilationTest;
use rch_common::{SelfTestConfig, SelfTestFailureAction, WorkerConfig, WorkerId};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{info, warn};

pub const DEFAULT_RUN_CAPACITY: usize = 100;
pub const DEFAULT_RESULT_CAPACITY: usize = 500;
const DEFAULT_SELF_TEST_TIMEOUT_SECS: u64 = 300;

/// Type of self-test run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfTestRunType {
    Manual,
    Scheduled,
}

/// Summary of a self-test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestRunRecord {
    pub id: u64,
    pub run_type: SelfTestRunType,
    pub started_at: String,
    pub completed_at: String,
    pub workers_tested: usize,
    pub workers_passed: usize,
    pub workers_failed: usize,
    pub duration_ms: u64,
}

/// Result for a single worker in a self-test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestResultRecord {
    pub run_id: u64,
    pub worker_id: String,
    pub passed: bool,
    pub local_hash: Option<String>,
    pub remote_hash: Option<String>,
    pub local_time_ms: Option<u64>,
    pub remote_time_ms: Option<u64>,
    pub error: Option<String>,
}

/// Run response with per-worker results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestRunReport {
    pub run: SelfTestRunRecord,
    pub results: Vec<SelfTestResultRecord>,
}

/// Status response for scheduled self-tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestStatus {
    pub enabled: bool,
    pub schedule: Option<String>,
    pub interval: Option<String>,
    pub last_run: Option<SelfTestRunRecord>,
    pub next_run: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SelfTestHistoryEntry {
    Run(SelfTestRunRecord),
    Result(SelfTestResultRecord),
}

/// Persistent history for self-tests (JSONL append-only).
pub struct SelfTestHistory {
    runs: RwLock<VecDeque<SelfTestRunRecord>>,
    results: RwLock<VecDeque<SelfTestResultRecord>>,
    capacity: usize,
    result_capacity: usize,
    next_id: AtomicU64,
    persistence_path: Option<PathBuf>,
}

impl SelfTestHistory {
    pub fn new(capacity: usize, result_capacity: usize) -> Self {
        Self {
            runs: RwLock::new(VecDeque::with_capacity(capacity)),
            results: RwLock::new(VecDeque::with_capacity(result_capacity)),
            capacity,
            result_capacity,
            next_id: AtomicU64::new(1),
            persistence_path: None,
        }
    }

    pub fn with_persistence(mut self, path: PathBuf) -> Self {
        self.persistence_path = Some(path);
        self
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn record_run(&self, record: SelfTestRunRecord) {
        let persistence = self
            .persistence_path
            .as_ref()
            .map(|path| (path.clone(), SelfTestHistoryEntry::Run(record.clone())));

        self.push_run(record);

        if let Some((path, entry)) = persistence {
            tokio::spawn(async move {
                if let Err(err) = persist_entry_async(&path, &entry).await {
                    warn!("Failed to persist self-test run: {}", err);
                }
            });
        }
    }

    pub fn record_result(&self, record: SelfTestResultRecord) {
        let persistence = self
            .persistence_path
            .as_ref()
            .map(|path| (path.clone(), SelfTestHistoryEntry::Result(record.clone())));

        self.push_result(record);

        if let Some((path, entry)) = persistence {
            tokio::spawn(async move {
                if let Err(err) = persist_entry_async(&path, &entry).await {
                    warn!("Failed to persist self-test result: {}", err);
                }
            });
        }
    }

    pub fn latest_run(&self) -> Option<SelfTestRunRecord> {
        let runs = self.runs.read().unwrap();
        runs.back().cloned()
    }

    pub fn recent_runs(&self, limit: usize) -> Vec<SelfTestRunRecord> {
        let runs = self.runs.read().unwrap();
        runs.iter().rev().take(limit).cloned().collect()
    }

    pub fn results_for_runs(&self, run_ids: &[u64]) -> Vec<SelfTestResultRecord> {
        let results = self.results.read().unwrap();
        results
            .iter()
            .filter(|r| run_ids.contains(&r.run_id))
            .cloned()
            .collect()
    }

    pub fn load_from_file(
        path: &Path,
        capacity: usize,
        result_capacity: usize,
    ) -> std::io::Result<Self> {
        let history =
            SelfTestHistory::new(capacity, result_capacity).with_persistence(path.to_path_buf());
        if !path.exists() {
            return Ok(history);
        }

        let content = std::fs::read_to_string(path)?;
        let mut max_id = 0u64;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: SelfTestHistoryEntry = match serde_json::from_str(line) {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("Skipping invalid self-test history line: {}", err);
                    continue;
                }
            };
            match entry {
                SelfTestHistoryEntry::Run(run) => {
                    max_id = max_id.max(run.id);
                    history.push_run(run);
                }
                SelfTestHistoryEntry::Result(result) => {
                    history.push_result(result);
                }
            }
        }

        history
            .next_id
            .store(max_id.saturating_add(1), Ordering::SeqCst);
        Ok(history)
    }

    fn push_run(&self, record: SelfTestRunRecord) {
        let mut runs = self.runs.write().unwrap();
        if runs.len() >= self.capacity {
            runs.pop_front();
        }
        runs.push_back(record);
    }

    fn push_result(&self, record: SelfTestResultRecord) {
        let mut results = self.results.write().unwrap();
        if results.len() >= self.result_capacity {
            results.pop_front();
        }
        results.push_back(record);
    }
}

async fn persist_entry_async(path: &Path, entry: &SelfTestHistoryEntry) -> std::io::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    // Concatenate JSON + newline into a single buffer so one `write_all`
    // can land atomically on the tail of an O_APPEND file. Two writes
    // (json, then `\n`) from concurrent callers can interleave and
    // produce `{a}{b}\n\n` — a corrupt JSONL stream that breaks the
    // history replay on the next daemon start.
    let mut line = serde_json::to_vec(entry)?;
    line.push(b'\n');
    file.write_all(&line).await?;
    file.flush().await?;
    Ok(())
}

/// Self-test execution options.
#[derive(Debug, Clone)]
pub struct SelfTestRunOptions {
    pub run_type: SelfTestRunType,
    pub worker_ids: Option<Vec<WorkerId>>,
    pub project_path: Option<PathBuf>,
    pub timeout: Duration,
    pub release_mode: bool,
    /// Override the configured retry count for THIS run. `None` uses the service
    /// config. A bounded smoke canary sets `Some(0)` (one attempt) so a failure
    /// surfaces immediately instead of being masked by the long retry delay
    /// blowing the run's own timeout budget.
    pub retry_count_override: Option<u32>,
}

impl Default for SelfTestRunOptions {
    fn default() -> Self {
        Self {
            run_type: SelfTestRunType::Manual,
            worker_ids: None,
            project_path: None,
            timeout: Duration::from_secs(DEFAULT_SELF_TEST_TIMEOUT_SECS),
            release_mode: true,
            retry_count_override: None,
        }
    }
}

/// Self-test service coordinating scheduled runs.
pub struct SelfTestService {
    pool: WorkerPool,
    config: SelfTestConfig,
    history: Arc<SelfTestHistory>,
    run_lock: Arc<Mutex<()>>,
    scheduler: Mutex<Option<JobScheduler>>,
}

impl SelfTestService {
    pub fn new(pool: WorkerPool, config: SelfTestConfig, history: Arc<SelfTestHistory>) -> Self {
        Self {
            pool,
            config,
            history,
            run_lock: Arc::new(Mutex::new(())),
            scheduler: Mutex::new(None),
        }
    }

    pub fn history(&self) -> Arc<SelfTestHistory> {
        self.history.clone()
    }

    pub fn status(&self) -> SelfTestStatus {
        let last_run = self.history.latest_run();
        let next_run = self.compute_next_run(&last_run, Utc::now());
        SelfTestStatus {
            enabled: self.config.enabled,
            schedule: self.config.schedule.clone(),
            interval: self.config.interval.clone(),
            last_run,
            next_run,
        }
    }

    pub async fn start(self: Arc<SelfTestService>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if let Some(schedule) = self.config.schedule.clone() {
            let scheduler = JobScheduler::new().await?;
            let service = self.clone();
            let job = Job::new_async(schedule.as_str(), move |_uuid, _lock| {
                let service = service.clone();
                Box::pin(async move {
                    if let Err(err) = service.run_scheduled().await {
                        warn!("Scheduled self-test failed: {}", err);
                    }
                })
            })?;
            scheduler.add(job).await?;
            scheduler.start().await?;
            *self.scheduler.lock().await = Some(scheduler);
            info!("Self-test scheduler started (cron)");
        }

        if let Some(interval) = self.config.interval.clone() {
            let service = self.clone();
            let duration =
                parse_duration(&interval).unwrap_or_else(|| Duration::from_secs(24 * 60 * 60));
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(duration);
                ticker.tick().await; // skip immediate tick
                loop {
                    ticker.tick().await;
                    if let Err(err) = service.run_scheduled().await {
                        warn!("Interval self-test failed: {}", err);
                    }
                }
            });
            info!("Self-test scheduler started (interval {})", interval);
        }

        Ok(())
    }

    pub async fn run_manual(&self, options: SelfTestRunOptions) -> Result<SelfTestRunReport> {
        self.run_internal(options).await
    }

    pub async fn run_scheduled_now(&self) -> Result<SelfTestRunReport> {
        self.run_scheduled().await
    }

    async fn run_scheduled(&self) -> Result<SelfTestRunReport> {
        let options = SelfTestRunOptions {
            run_type: SelfTestRunType::Scheduled,
            worker_ids: self.config.workers.resolve(),
            project_path: None,
            timeout: Duration::from_secs(DEFAULT_SELF_TEST_TIMEOUT_SECS),
            release_mode: true,
            retry_count_override: None,
        };
        self.run_internal(options).await
    }

    async fn run_internal(&self, options: SelfTestRunOptions) -> Result<SelfTestRunReport> {
        let _guard = self.run_lock.lock().await;
        let run_id = self.history.next_id();
        let started_at = Utc::now();

        let workers = self.resolve_workers(options.worker_ids.clone()).await?;
        // Each test writes a unique marker into the project's main.rs, builds
        // it locally and restores the file. Concurrent tests on ONE tree
        // overwrite and restore each other's marker and queue on one build
        // directory, so `--all` reported every worker timed out while each
        // passed alone (bd-57nk9). The daemon's own canary is tiny: give each
        // worker a private copy. An operator-supplied tree cannot be copied
        // blindly, so those tests run one at a time instead.
        let isolate = options.project_path.is_none() && workers.len() > 1;
        let sequential = options.project_path.is_some() && workers.len() > 1;
        let shared_project_path = match &options.project_path {
            Some(path) => Some(path.clone()),
            None if isolate => None,
            None => Some(ensure_self_test_project()?),
        };

        // Run all workers in PARALLEL to avoid sequential timeout accumulation
        // Each worker test runs concurrently with its own timeout
        let mut handles = Vec::new();
        let mut results = Vec::new();
        for worker in workers {
            let worker_clone = worker.clone();
            let project_path_clone = match &shared_project_path {
                Some(path) => path.clone(),
                None => ensure_self_test_project_for_worker(worker.id.as_str())?,
            };
            let options_clone = options.clone();
            let config_clone = self.config.clone();
            let pool_clone = self.pool.clone();

            let handle = tokio::spawn(async move {
                run_single_worker_test(
                    run_id,
                    &worker_clone,
                    &project_path_clone,
                    &options_clone,
                    &config_clone,
                    &pool_clone,
                )
                .await
            });
            if sequential {
                // Let this worker's marker cycle finish before the next starts.
                results.push(self_test_task_result(run_id, handle.await));
            } else {
                handles.push(handle);
            }
        }

        // Collect all results (parallel execution means total time ≈ slowest worker)
        for handle in handles {
            results.push(self_test_task_result(run_id, handle.await));
        }

        let workers_tested = results.len();
        let workers_passed = results.iter().filter(|r| r.passed).count();
        let workers_failed = workers_tested.saturating_sub(workers_passed);

        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at)
            .to_std()
            .unwrap_or_default()
            .as_millis() as u64;

        let run = SelfTestRunRecord {
            id: run_id,
            run_type: options.run_type,
            started_at: started_at.to_rfc3339(),
            completed_at: completed_at.to_rfc3339(),
            workers_tested,
            workers_passed,
            workers_failed,
            duration_ms,
        };

        self.history.record_run(run.clone());
        for result in &results {
            self.history.record_result(result.clone());
        }

        self.apply_failure_actions(&results).await;

        Ok(SelfTestRunReport { run, results })
    }

    async fn resolve_workers(
        &self,
        override_ids: Option<Vec<WorkerId>>,
    ) -> Result<Vec<WorkerConfig>> {
        let workers = self.pool.all_workers().await;
        if workers.is_empty() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();

        if let Some(ids) = override_ids {
            for worker in workers {
                let config = worker.config.read().await;
                if ids.contains(&config.id) {
                    result.push(config.clone());
                }
            }
        } else {
            // "All" means every worker that takes builds. One an operator
            // disabled or is draining is out of rotation on purpose; testing
            // it only reports a timeout. Name it explicitly to test it anyway.
            // The canary cannot run on Windows (see `canary_unsupported`), so
            // those workers are left out rather than counted as failures.
            for worker in workers {
                if matches!(
                    worker.status().await,
                    rch_common::WorkerStatus::Disabled
                        | rch_common::WorkerStatus::Draining
                        | rch_common::WorkerStatus::Drained
                ) {
                    continue;
                }
                let config = worker.config.read().await;
                if canary_unsupported(&config).is_some() {
                    continue;
                }
                result.push(config.clone());
            }
        }

        Ok(result)
    }

    async fn apply_failure_actions(&self, results: &[SelfTestResultRecord]) {
        if results.is_empty() {
            return;
        }

        for result in results.iter().filter(|r| !r.passed) {
            match self.config.on_failure {
                SelfTestFailureAction::Alert => {
                    warn!(
                        "Self-test failed for worker {}: {:?}",
                        result.worker_id, result.error
                    );
                }
                SelfTestFailureAction::DisableWorker => {
                    warn!(
                        "Self-test failed for worker {}: disabling worker",
                        result.worker_id
                    );
                    let id = WorkerId::new(result.worker_id.clone());
                    self.pool
                        .set_status(&id, rch_common::WorkerStatus::Disabled)
                        .await;
                }
                SelfTestFailureAction::AlertAndDisable => {
                    warn!(
                        "Self-test failed for worker {}: alert + disable",
                        result.worker_id
                    );
                    let id = WorkerId::new(result.worker_id.clone());
                    self.pool
                        .set_status(&id, rch_common::WorkerStatus::Disabled)
                        .await;
                }
            }
        }
    }

    fn compute_next_run(
        &self,
        last_run: &Option<SelfTestRunRecord>,
        now: DateTime<Utc>,
    ) -> Option<String> {
        if let Some(schedule) = self.config.schedule.as_ref()
            && let Ok(expr) = cron::Schedule::from_str(schedule)
            && let Some(next) = expr.after(&now).next()
        {
            return Some(next.to_rfc3339());
        }

        if let Some(interval) = self.config.interval.as_ref() {
            let duration = parse_duration(interval)?;
            let base = last_run
                .as_ref()
                .and_then(|run| DateTime::parse_from_rfc3339(&run.completed_at).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now);
            let next = base + chrono::Duration::from_std(duration).ok()?;
            return Some(next.to_rfc3339());
        }

        None
    }
}

fn parse_duration(value: &str) -> Option<Duration> {
    humantime::parse_duration(value).ok()
}

/// Run a single worker self-test with retries, each bounded by the per-worker
/// `options.timeout`, and with a fleet-safe total budget so a wedged worker
/// can never starve `--all` mode of attention (bd-nuuqt).
///
/// The `options.timeout` value is enforced in two places:
///
/// 1. **Per attempt**: each call to the remote compilation test is wrapped in
///    `tokio::time::timeout(options.timeout, ...)`.
/// 2. **Per worker total**: the retry loop itself is wrapped in
///    `tokio::time::timeout(options.timeout, ...)`. This guarantees the total
///    wall clock time a single worker can consume is strictly bounded,
///    regardless of retry count.
///
/// On timeout, `RCH-E203` (`WorkerSelfTestFailed`) is prefixed to the error
/// message so downstream automation can branch on a stable code.
async fn run_single_worker_test(
    run_id: u64,
    worker: &WorkerConfig,
    project_path: &Path,
    options: &SelfTestRunOptions,
    config: &SelfTestConfig,
    _pool: &WorkerPool, // Reserved for future use (e.g., status updates)
) -> SelfTestResultRecord {
    let worker_id = worker.id.to_string();
    let timeout_total = options.timeout;

    if let Some(reason) = canary_unsupported(worker) {
        return SelfTestResultRecord {
            run_id,
            worker_id,
            passed: false,
            local_hash: None,
            remote_hash: None,
            local_time_ms: None,
            remote_time_ms: None,
            error: Some(reason),
        };
    }

    let retry_loop = async {
        let retry_delay =
            parse_duration(&config.retry_delay).unwrap_or_else(|| Duration::from_secs(300));

        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let test = RemoteCompilationTest::new(worker.clone(), project_path.to_path_buf())
                .with_timeout(options.timeout)
                .with_release_mode(options.release_mode);

            let result = tokio::time::timeout(options.timeout, test.run()).await;

            let record = match result {
                Ok(Ok(outcome)) => SelfTestResultRecord {
                    run_id,
                    worker_id: worker_id.clone(),
                    passed: outcome.success,
                    local_hash: Some(outcome.local_hash.code_hash),
                    remote_hash: Some(outcome.remote_hash.code_hash),
                    local_time_ms: Some(outcome.local_build_ms),
                    remote_time_ms: Some(outcome.compilation_ms),
                    error: outcome.error,
                },
                Ok(Err(err)) => failed_worker_result(run_id, &worker_id, &err),
                Err(_elapsed) => SelfTestResultRecord {
                    run_id,
                    worker_id: worker_id.clone(),
                    passed: false,
                    local_hash: None,
                    remote_hash: None,
                    local_time_ms: None,
                    remote_time_ms: None,
                    error: Some(format!(
                        "[RCH-E203] Self-test attempt timed out after {:?}",
                        options.timeout
                    )),
                },
            };

            let retry_count = options.retry_count_override.unwrap_or(config.retry_count);
            if record.passed || attempt > retry_count {
                return record;
            }

            warn!(
                "Self-test failed for worker {} (attempt {}/{}), retrying in {:?}: {}",
                worker_id,
                attempt,
                retry_count,
                retry_delay,
                record.error.as_deref().unwrap_or("no error recorded")
            );
            sleep(retry_delay).await;
        }
    };

    match tokio::time::timeout(timeout_total, retry_loop).await {
        Ok(record) => record,
        Err(_elapsed) => SelfTestResultRecord {
            run_id,
            worker_id,
            passed: false,
            local_hash: None,
            remote_hash: None,
            local_time_ms: None,
            remote_time_ms: None,
            error: Some(format!(
                "[RCH-E203] Self-test hit per-worker deadline {:?} (including retries)",
                timeout_total
            )),
        },
    }
}

/// A panicked worker task becomes a failure record instead of losing the run.
fn self_test_task_result(
    run_id: u64,
    joined: std::result::Result<SelfTestResultRecord, tokio::task::JoinError>,
) -> SelfTestResultRecord {
    joined.unwrap_or_else(|join_err| {
        warn!("Self-test task panicked: {}", join_err);
        SelfTestResultRecord {
            run_id,
            worker_id: "unknown".to_string(),
            passed: false,
            local_hash: None,
            remote_hash: None,
            local_time_ms: None,
            remote_time_ms: None,
            error: Some(format!("Task panicked: {}", join_err)),
        }
    })
}

/// Keep the complete failure chain in persisted and returned self-test results.
/// Unknown hashes/timings stay absent; diagnostics do not establish execution.
fn failed_worker_result(
    run_id: u64,
    worker_id: &str,
    error: &anyhow::Error,
) -> SelfTestResultRecord {
    SelfTestResultRecord {
        run_id,
        worker_id: worker_id.to_owned(),
        passed: false,
        local_hash: None,
        remote_hash: None,
        local_time_ms: None,
        remote_time_ms: None,
        error: Some(format!("{error:#}")),
    }
}

/// Why the canary cannot run on `worker`, if it cannot.
///
/// `RemoteCompilationTest` syncs with rsync and builds through a POSIX shell,
/// and it compares against a reference built on this host. A Windows worker
/// has neither, so each attempt failed at the sync step and the run only
/// ended at the per-worker deadline (600 s by default), reported as a
/// timeout. Real builds reach Windows workers through the hook's
/// Windows-aware transport; their health shows in probes and benchmarks.
fn canary_unsupported(worker: &WorkerConfig) -> Option<String> {
    let os = rch_common::declared_os(&worker.tags)?;
    (os == "windows").then(|| {
        format!(
            "self-test canary is POSIX-only (rsync + sh) and cannot run on Windows worker {id}; \
             check it with `rch workers probe {id}` and `rch workers benchmark {id}`",
            id = worker.id
        )
    })
}

/// Canonical source of the self-test canary's `src/main.rs`. Kept as a constant
/// so [`ensure_self_test_project`] can both create AND heal the fixture.
const SELF_TEST_MAIN_RS: &str = "fn main() {\n    println!(\"rch self-test\");\n}\n";

/// Whether the on-disk canary `main.rs` is still buildable as-is — i.e. it
/// declares a `fn main`. The verification pipeline applies a test marker to
/// `main.rs`, builds, then reverts; if a run is interrupted between apply and
/// revert (or the revert is partial), the file can be left WITHOUT a `main`,
/// which makes every future local reference build fail with E0601 and wedges the
/// canary permanently. Detect that so we can heal it.
fn self_test_main_rs_is_healthy(contents: &str) -> bool {
    contents.contains("fn main(")
}

fn ensure_self_test_project() -> Result<PathBuf> {
    ensure_self_test_project_at(&default_self_test_dir()?.join("project"))
}

/// A private copy of the canary for one worker, so concurrent tests share no
/// file and no build directory. Reused across runs to keep its local build warm.
fn ensure_self_test_project_for_worker(worker_id: &str) -> Result<PathBuf> {
    ensure_self_test_project_at(&self_test_worker_project_dir(
        &default_self_test_dir()?,
        worker_id,
    ))
}

fn self_test_worker_project_dir(cache_dir: &Path, worker_id: &str) -> PathBuf {
    let name: String = worker_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let name = if name.is_empty() {
        "worker".to_owned()
    } else {
        name
    };
    cache_dir.join("workers").join(name).join("project")
}

fn ensure_self_test_project_at(project_dir: &Path) -> Result<PathBuf> {
    let src_dir = project_dir.join("src");

    fs::create_dir_all(&src_dir)
        .with_context(|| format!("Failed to create self-test project dir {:?}", src_dir))?;

    let project_name = "rch_self_test";
    let cargo_toml = project_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        let contents = format!(
            "[package]\nname = \"{project_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\n",
        );
        fs::write(&cargo_toml, contents)
            .with_context(|| format!("Failed to write {:?}", cargo_toml))?;
    }

    // Write `main.rs` when missing, and HEAL it when a previous interrupted
    // marker apply/revert left it without a `fn main` (which would fail every
    // local reference build and silently wedge the canary forever). Healing to
    // the canonical baseline is safe: the file is a daemon-owned ephemeral
    // fixture the marker cycle overwrites on each run anyway.
    let main_rs = src_dir.join("main.rs");
    let needs_main_rs = match fs::read_to_string(&main_rs) {
        Ok(existing) => !self_test_main_rs_is_healthy(&existing),
        Err(_) => true,
    };
    if needs_main_rs {
        fs::write(&main_rs, SELF_TEST_MAIN_RS)
            .with_context(|| format!("Failed to write {:?}", main_rs))?;
    }

    Ok(project_dir.to_path_buf())
}

fn default_self_test_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "rch", "rch")
        .context("Failed to resolve cache directory")?;
    let cache = dirs.cache_dir().join("self_test");
    fs::create_dir_all(&cache)
        .with_context(|| format!("Failed to create cache dir {:?}", cache))?;
    Ok(cache)
}

pub fn default_history_path() -> Result<PathBuf> {
    let base = default_self_test_dir()?;
    Ok(base.join("self_test_history.jsonl"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    #[test]
    fn each_worker_gets_a_private_canary_project() {
        let cache = tempfile::tempdir().unwrap();
        let a = self_test_worker_project_dir(cache.path(), "vmi1264463");
        let b = self_test_worker_project_dir(cache.path(), "hz3");
        let odd = self_test_worker_project_dir(cache.path(), "../we ird/id");
        assert_ne!(a, b);
        for dir in [&a, &b, &odd] {
            assert!(dir.starts_with(cache.path().join("workers")), "{dir:?}");
            assert_eq!(dir.components().count(), a.components().count());
            let project = ensure_self_test_project_at(dir).unwrap();
            assert_eq!(
                fs::read_to_string(project.join("src/main.rs")).unwrap(),
                SELF_TEST_MAIN_RS
            );
            assert!(project.join("Cargo.toml").is_file());
        }
        // A marker left in one worker's tree never reaches another's.
        fs::write(a.join("src/main.rs"), "// RCH_TEST_1\nfn main() {}\n").unwrap();
        assert_eq!(
            fs::read_to_string(b.join("src/main.rs")).unwrap(),
            SELF_TEST_MAIN_RS
        );
    }

    #[tokio::test]
    async fn all_skips_workers_taken_out_of_rotation_unless_named() {
        let pool = WorkerPool::new();
        for id in ["up", "disabled", "draining"] {
            pool.add_worker(WorkerConfig {
                id: WorkerId::new(id),
                host: format!("{id}.invalid"),
                user: "u".to_string(),
                identity_file: "/dev/null".to_string(),
                total_slots: 2,
                priority: 100,
                tags: vec![],
                tools: Vec::new(),
            })
            .await;
        }
        pool.get(&WorkerId::new("disabled"))
            .await
            .unwrap()
            .disable(Some("maintenance".into()))
            .await;
        pool.get(&WorkerId::new("draining"))
            .await
            .unwrap()
            .set_status(rch_common::WorkerStatus::Draining)
            .await;
        let service = SelfTestService::new(
            pool,
            SelfTestConfig::default(),
            Arc::new(SelfTestHistory::new(4, 4)),
        );
        let ids = |workers: Vec<WorkerConfig>| -> Vec<String> {
            let mut ids: Vec<String> = workers.iter().map(|w| w.id.to_string()).collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(service.resolve_workers(None).await.unwrap()), ["up"]);
        let named = Some(vec![WorkerId::new("disabled"), WorkerId::new("up")]);
        assert_eq!(
            ids(service.resolve_workers(named).await.unwrap()),
            ["disabled", "up"]
        );
    }

    #[tokio::test]
    async fn windows_workers_are_left_out_of_all_and_refused_at_once_when_named() {
        let pool = WorkerPool::new();
        for (id, tags) in [
            ("linux", vec![]),
            (
                "win",
                vec!["rust".to_string(), rch_common::os_tag("Windows")],
            ),
        ] {
            pool.add_worker(WorkerConfig {
                id: WorkerId::new(id),
                host: format!("{id}.invalid"),
                user: "u".to_string(),
                identity_file: "/dev/null".to_string(),
                total_slots: 2,
                priority: 100,
                tags,
                tools: Vec::new(),
            })
            .await;
        }
        let service = SelfTestService::new(
            pool.clone(),
            SelfTestConfig::default(),
            Arc::new(SelfTestHistory::new(4, 4)),
        );
        let all = service.resolve_workers(None).await.unwrap();
        assert_eq!(
            all.iter().map(|w| w.id.to_string()).collect::<Vec<_>>(),
            ["linux"]
        );
        assert!(canary_unsupported(&all[0]).is_none());

        let named = service
            .resolve_workers(Some(vec![WorkerId::new("win")]))
            .await
            .unwrap();
        assert_eq!(named.len(), 1);
        let options = SelfTestRunOptions {
            run_type: SelfTestRunType::Manual,
            worker_ids: None,
            project_path: None,
            timeout: Duration::from_secs(600),
            release_mode: true,
            retry_count_override: None,
        };
        // An unreachable host and a missing project: only the early refusal
        // can answer before the 600 s deadline.
        let record = tokio::time::timeout(
            Duration::from_secs(5),
            run_single_worker_test(
                9,
                &named[0],
                Path::new("/nonexistent/self-test-project"),
                &options,
                &SelfTestConfig::default(),
                &pool,
            ),
        )
        .await
        .expect("a Windows worker is refused without attempting the canary");
        assert!(!record.passed);
        assert_eq!((record.run_id, record.worker_id.as_str()), (9, "win"));
        let error = record.error.unwrap();
        assert!(error.contains("POSIX-only"), "{error}");
        assert!(error.contains("`rch workers probe win`"), "{error}");
    }

    #[test]
    fn failed_worker_result_retains_real_io_cause_through_serialization() {
        let retained = tempfile::tempdir().unwrap().keep();
        let missing = retained.join("never-created-artifact");
        let cause = fs::read(&missing).unwrap_err();
        assert_eq!(cause.kind(), std::io::ErrorKind::NotFound);
        let cause_message = cause.to_string();
        let error = anyhow::Error::new(cause)
            .context("Returned artifact could not be read")
            .context("Canary identity was not verified");
        let expected = format!(
            "Canary identity was not verified: Returned artifact could not be read: {cause_message}"
        );
        let record = failed_worker_result(47, "reader-case", &error);
        assert_eq!(record.error.as_deref(), Some(expected.as_str()));
        assert_eq!(record.run_id, 47);
        assert_eq!(record.worker_id, "reader-case");
        assert!(!record.passed);
        assert!(record.local_hash.is_none() && record.remote_hash.is_none());
        assert!(record.local_time_ms.is_none() && record.remote_time_ms.is_none());

        let document = serde_json::to_vec(&record).unwrap();
        let restored: SelfTestResultRecord = serde_json::from_slice(&document).unwrap();
        assert_eq!(restored.error.as_deref(), Some(expected.as_str()));
        assert_eq!(restored.run_id, 47);
        assert_eq!(restored.worker_id, "reader-case");
        assert!(!restored.passed);
        assert!(restored.local_hash.is_none() && restored.remote_hash.is_none());
        assert!(restored.local_time_ms.is_none() && restored.remote_time_ms.is_none());
        assert!(!missing.exists());
        assert_eq!(fs::read_dir(retained).unwrap().count(), 0);
    }

    // ==================== parse_duration tests ====================

    #[test]
    fn test_parse_duration_minutes() {
        let _guard = test_guard!();
        let duration = parse_duration("5m").expect("parse duration");
        assert_eq!(duration, Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_hours() {
        let _guard = test_guard!();
        let duration = parse_duration("2h").expect("parse duration");
        assert_eq!(duration, Duration::from_secs(7200));
    }

    #[test]
    fn test_parse_duration_days() {
        let _guard = test_guard!();
        let duration = parse_duration("1d").expect("parse duration");
        assert_eq!(duration, Duration::from_secs(86400));
    }

    #[test]
    fn test_parse_duration_seconds() {
        let _guard = test_guard!();
        let duration = parse_duration("30s").expect("parse duration");
        assert_eq!(duration, Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_combined() {
        let _guard = test_guard!();
        let duration = parse_duration("1h 30m").expect("parse duration");
        assert_eq!(duration, Duration::from_secs(5400));
    }

    #[test]
    fn test_parse_duration_invalid() {
        let _guard = test_guard!();
        assert!(parse_duration("invalid").is_none());
        assert!(parse_duration("").is_none());
    }

    // ==================== SelfTestRunOptions tests ====================

    #[test]
    fn test_self_test_run_options_default() {
        let _guard = test_guard!();
        let options = SelfTestRunOptions::default();
        assert_eq!(options.run_type, SelfTestRunType::Manual);
        assert!(options.worker_ids.is_none());
        assert!(options.project_path.is_none());
        assert_eq!(
            options.timeout,
            Duration::from_secs(DEFAULT_SELF_TEST_TIMEOUT_SECS)
        );
        assert!(options.release_mode);
    }

    #[test]
    fn test_self_test_run_options_custom() {
        let _guard = test_guard!();
        let options = SelfTestRunOptions {
            run_type: SelfTestRunType::Scheduled,
            worker_ids: Some(vec![WorkerId::new("w1")]),
            project_path: Some(PathBuf::from("/tmp/project")),
            timeout: Duration::from_secs(60),
            release_mode: false,
            retry_count_override: Some(0),
        };
        assert_eq!(options.run_type, SelfTestRunType::Scheduled);
        assert!(options.worker_ids.is_some());
        assert!(options.project_path.is_some());
        assert!(!options.release_mode);
        assert_eq!(options.retry_count_override, Some(0));
    }

    // ==================== SelfTestHistory tests ====================

    #[test]
    fn test_self_test_history_new() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(10, 50);
        assert_eq!(history.capacity, 10);
        assert_eq!(history.result_capacity, 50);
        assert!(history.persistence_path.is_none());
    }

    #[test]
    fn test_self_test_history_with_persistence() {
        let _guard = test_guard!();
        let history =
            SelfTestHistory::new(10, 50).with_persistence(PathBuf::from("/tmp/history.jsonl"));
        assert!(history.persistence_path.is_some());
        assert_eq!(
            history.persistence_path.as_ref().unwrap().to_str().unwrap(),
            "/tmp/history.jsonl"
        );
    }

    #[test]
    fn test_self_test_history_next_id() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(10, 50);
        assert_eq!(history.next_id(), 1);
        assert_eq!(history.next_id(), 2);
        assert_eq!(history.next_id(), 3);
    }

    #[test]
    fn test_self_test_history_push_and_latest_run() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(10, 50);
        assert!(history.latest_run().is_none());

        let run = SelfTestRunRecord {
            id: 1,
            run_type: SelfTestRunType::Manual,
            started_at: "2024-01-01T00:00:00Z".to_string(),
            completed_at: "2024-01-01T00:01:00Z".to_string(),
            workers_tested: 2,
            workers_passed: 2,
            workers_failed: 0,
            duration_ms: 60000,
        };
        history.push_run(run.clone());

        let latest = history.latest_run();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().id, 1);
    }

    #[test]
    fn test_self_test_history_recent_runs() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(10, 50);

        for i in 1..=5 {
            history.push_run(SelfTestRunRecord {
                id: i,
                run_type: SelfTestRunType::Manual,
                started_at: format!("2024-01-0{}T00:00:00Z", i),
                completed_at: format!("2024-01-0{}T00:01:00Z", i),
                workers_tested: 1,
                workers_passed: 1,
                workers_failed: 0,
                duration_ms: 1000,
            });
        }

        let recent = history.recent_runs(3);
        assert_eq!(recent.len(), 3);
        // Recent returns in reverse order (newest first)
        assert_eq!(recent[0].id, 5);
        assert_eq!(recent[1].id, 4);
        assert_eq!(recent[2].id, 3);
    }

    #[test]
    fn test_self_test_history_capacity_eviction() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(3, 50);

        for i in 1..=5 {
            history.push_run(SelfTestRunRecord {
                id: i,
                run_type: SelfTestRunType::Manual,
                started_at: "2024-01-01T00:00:00Z".to_string(),
                completed_at: "2024-01-01T00:01:00Z".to_string(),
                workers_tested: 1,
                workers_passed: 1,
                workers_failed: 0,
                duration_ms: 1000,
            });
        }

        let recent = history.recent_runs(10);
        // Should only keep 3 most recent
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].id, 5);
        assert_eq!(recent[2].id, 3);
    }

    #[test]
    fn test_self_test_history_results_for_runs() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(10, 50);

        history.push_result(SelfTestResultRecord {
            run_id: 1,
            worker_id: "w1".to_string(),
            passed: true,
            local_hash: Some("abc".to_string()),
            remote_hash: Some("abc".to_string()),
            local_time_ms: Some(100),
            remote_time_ms: Some(200),
            error: None,
        });

        history.push_result(SelfTestResultRecord {
            run_id: 2,
            worker_id: "w2".to_string(),
            passed: false,
            local_hash: None,
            remote_hash: None,
            local_time_ms: None,
            remote_time_ms: None,
            error: Some("connection failed".to_string()),
        });

        history.push_result(SelfTestResultRecord {
            run_id: 1,
            worker_id: "w3".to_string(),
            passed: true,
            local_hash: Some("def".to_string()),
            remote_hash: Some("def".to_string()),
            local_time_ms: Some(150),
            remote_time_ms: Some(250),
            error: None,
        });

        let results = history.results_for_runs(&[1]);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.run_id == 1));

        let results = history.results_for_runs(&[2]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].worker_id, "w2");

        let results = history.results_for_runs(&[1, 2]);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_self_test_history_result_capacity_eviction() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(10, 3);

        for i in 1..=5 {
            history.push_result(SelfTestResultRecord {
                run_id: i,
                worker_id: format!("w{}", i),
                passed: true,
                local_hash: None,
                remote_hash: None,
                local_time_ms: None,
                remote_time_ms: None,
                error: None,
            });
        }

        let results = history.results_for_runs(&[1, 2, 3, 4, 5]);
        // Should only keep 3 most recent results
        assert_eq!(results.len(), 3);
    }

    // ==================== SelfTestRunType tests ====================

    #[test]
    fn test_self_test_run_type_equality() {
        let _guard = test_guard!();
        assert_eq!(SelfTestRunType::Manual, SelfTestRunType::Manual);
        assert_eq!(SelfTestRunType::Scheduled, SelfTestRunType::Scheduled);
        assert_ne!(SelfTestRunType::Manual, SelfTestRunType::Scheduled);
    }

    #[test]
    fn test_self_test_run_type_serialization() {
        let _guard = test_guard!();
        let manual = serde_json::to_string(&SelfTestRunType::Manual).unwrap();
        assert_eq!(manual, "\"manual\"");

        let scheduled = serde_json::to_string(&SelfTestRunType::Scheduled).unwrap();
        assert_eq!(scheduled, "\"scheduled\"");
    }

    #[test]
    fn test_self_test_run_type_deserialization() {
        let _guard = test_guard!();
        let manual: SelfTestRunType = serde_json::from_str("\"manual\"").unwrap();
        assert_eq!(manual, SelfTestRunType::Manual);

        let scheduled: SelfTestRunType = serde_json::from_str("\"scheduled\"").unwrap();
        assert_eq!(scheduled, SelfTestRunType::Scheduled);
    }

    // ==================== Record serialization tests ====================

    #[test]
    fn test_self_test_run_record_serialization() {
        let _guard = test_guard!();
        let record = SelfTestRunRecord {
            id: 42,
            run_type: SelfTestRunType::Scheduled,
            started_at: "2024-01-01T00:00:00Z".to_string(),
            completed_at: "2024-01-01T00:01:00Z".to_string(),
            workers_tested: 3,
            workers_passed: 2,
            workers_failed: 1,
            duration_ms: 60000,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"scheduled\""));
        assert!(json.contains("\"workers_passed\":2"));

        let deserialized: SelfTestRunRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, 42);
        assert_eq!(deserialized.workers_failed, 1);
    }

    #[test]
    fn test_self_test_result_record_serialization() {
        let _guard = test_guard!();
        let record = SelfTestResultRecord {
            run_id: 1,
            worker_id: "test-worker".to_string(),
            passed: true,
            local_hash: Some("abc123".to_string()),
            remote_hash: Some("abc123".to_string()),
            local_time_ms: Some(100),
            remote_time_ms: Some(200),
            error: None,
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: SelfTestResultRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.worker_id, "test-worker");
        assert!(deserialized.passed);
        assert!(deserialized.error.is_none());
    }

    // ==================== SelfTestService tests ====================

    #[test]
    fn self_test_main_rs_health_detects_wedged_fixture() {
        // The canonical baseline is healthy.
        assert!(self_test_main_rs_is_healthy(SELF_TEST_MAIN_RS));
        // A file still carrying a marker alongside main is healthy.
        assert!(self_test_main_rs_is_healthy(
            "fn main() {}\n#[allow(dead_code)] pub fn RCH_TEST_1() {}\n"
        ));
        // The real wedged shape observed in the field: only a leftover marker,
        // no `fn main` -> E0601 on every build -> must be detected as unhealthy.
        assert!(!self_test_main_rs_is_healthy(
            "\n\n// RCH Self-Test Marker\n#[unsafe(no_mangle)]\n#[allow(dead_code)]\npub fn RCH_TEST_123() -> &'static str { \"RCH_TEST_123\" }\n"
        ));
        assert!(!self_test_main_rs_is_healthy(""));
    }

    #[test]
    fn test_status_next_run_interval() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let history = Arc::new(SelfTestHistory::new(5, 5));
        let config = SelfTestConfig {
            enabled: true,
            interval: Some("1h".to_string()),
            ..Default::default()
        };

        let service = SelfTestService::new(pool, config, history);
        let status = service.status();
        assert!(status.next_run.is_some());
    }

    #[test]
    fn test_status_disabled() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let history = Arc::new(SelfTestHistory::new(5, 5));
        let config = SelfTestConfig {
            enabled: false,
            ..Default::default()
        };

        let service = SelfTestService::new(pool, config, history);
        let status = service.status();
        assert!(!status.enabled);
    }

    #[test]
    fn test_service_history_clone() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let history = Arc::new(SelfTestHistory::new(5, 5));
        let config = SelfTestConfig::default();

        let service = SelfTestService::new(pool, config, history.clone());
        let service_history = service.history();

        // Should be the same Arc
        assert!(Arc::ptr_eq(&history, &service_history));
    }

    // ==================== SelfTestStatus tests ====================

    #[test]
    fn test_self_test_status_serialization() {
        let _guard = test_guard!();
        let status = SelfTestStatus {
            enabled: true,
            schedule: Some("0 0 * * *".to_string()),
            interval: None,
            last_run: None,
            next_run: Some("2024-01-02T00:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&status).unwrap();
        let deserialized: SelfTestStatus = serde_json::from_str(&json).unwrap();
        assert!(deserialized.enabled);
        assert_eq!(deserialized.schedule.unwrap(), "0 0 * * *");
    }

    // ==================== Constants tests ====================

    #[test]
    fn test_default_constants() {
        let _guard = test_guard!();
        assert_eq!(DEFAULT_RUN_CAPACITY, 100);
        assert_eq!(DEFAULT_RESULT_CAPACITY, 500);
        assert_eq!(DEFAULT_SELF_TEST_TIMEOUT_SECS, 300);
    }

    // ==================== Additional SelfTestHistory tests ====================

    #[test]
    fn test_self_test_history_capacity_limit_runs() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(3, 50); // Small capacity for testing

        // Add more runs than capacity
        for i in 1..=5 {
            let run = SelfTestRunRecord {
                id: i,
                run_type: SelfTestRunType::Manual,
                started_at: format!("2024-01-0{}T00:00:00Z", i),
                completed_at: format!("2024-01-0{}T00:01:00Z", i),
                workers_tested: 1,
                workers_passed: 1,
                workers_failed: 0,
                duration_ms: 60000,
            };
            history.push_run(run);
        }

        // Should only have the last 3 runs (capacity limit)
        let recent = history.recent_runs(10);
        assert_eq!(recent.len(), 3);
        // Most recent first
        assert_eq!(recent[0].id, 5);
        assert_eq!(recent[1].id, 4);
        assert_eq!(recent[2].id, 3);
    }

    #[test]
    fn test_self_test_history_load_from_file_nonexistent() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("nonexistent.jsonl");

        // Loading from non-existent file should succeed with empty history
        let history = SelfTestHistory::load_from_file(&path, 10, 50).unwrap();
        assert!(history.latest_run().is_none());
        assert!(history.persistence_path.is_some());
    }

    #[test]
    fn test_self_test_history_load_from_file_with_data() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("history.jsonl");

        // Write some test data
        let run_entry = SelfTestHistoryEntry::Run(SelfTestRunRecord {
            id: 42,
            run_type: SelfTestRunType::Scheduled,
            started_at: "2024-01-01T00:00:00Z".to_string(),
            completed_at: "2024-01-01T00:01:00Z".to_string(),
            workers_tested: 2,
            workers_passed: 2,
            workers_failed: 0,
            duration_ms: 60000,
        });
        let result_entry = SelfTestHistoryEntry::Result(SelfTestResultRecord {
            run_id: 42,
            worker_id: "worker1".to_string(),
            passed: true,
            local_hash: Some("abc123".to_string()),
            remote_hash: Some("abc123".to_string()),
            local_time_ms: Some(100),
            remote_time_ms: Some(150),
            error: None,
        });

        let mut content = serde_json::to_string(&run_entry).unwrap();
        content.push('\n');
        content.push_str(&serde_json::to_string(&result_entry).unwrap());
        content.push('\n');
        fs::write(&path, &content).unwrap();

        // Load and verify
        let history = SelfTestHistory::load_from_file(&path, 10, 50).unwrap();
        let latest = history.latest_run();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().id, 42);

        // Next ID should be 43 (max_id + 1)
        assert_eq!(history.next_id(), 43);

        let results = history.results_for_runs(&[42]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].worker_id, "worker1");
    }

    #[test]
    fn test_self_test_history_load_from_file_with_invalid_lines() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("history_invalid.jsonl");

        // Write mix of valid and invalid data
        let run_entry = SelfTestHistoryEntry::Run(SelfTestRunRecord {
            id: 1,
            run_type: SelfTestRunType::Manual,
            started_at: "2024-01-01T00:00:00Z".to_string(),
            completed_at: "2024-01-01T00:01:00Z".to_string(),
            workers_tested: 1,
            workers_passed: 1,
            workers_failed: 0,
            duration_ms: 1000,
        });

        let mut content = serde_json::to_string(&run_entry).unwrap();
        content.push_str("\ninvalid json line\n");
        content.push_str("{\"not_a_valid_entry\": true}\n");
        content.push('\n'); // Empty line
        fs::write(&path, &content).unwrap();

        // Should still load valid entries and skip invalid ones
        let history = SelfTestHistory::load_from_file(&path, 10, 50).unwrap();
        let latest = history.latest_run();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().id, 1);
    }

    #[test]
    fn test_self_test_history_record_run_without_persistence() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(10, 50);

        let run = SelfTestRunRecord {
            id: 1,
            run_type: SelfTestRunType::Manual,
            started_at: "2024-01-01T00:00:00Z".to_string(),
            completed_at: "2024-01-01T00:01:00Z".to_string(),
            workers_tested: 1,
            workers_passed: 1,
            workers_failed: 0,
            duration_ms: 1000,
        };

        history.record_run(run.clone());
        let latest = history.latest_run();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().id, 1);
    }

    #[test]
    fn test_self_test_history_record_result_without_persistence() {
        let _guard = test_guard!();
        let history = SelfTestHistory::new(10, 50);

        let result = SelfTestResultRecord {
            run_id: 1,
            worker_id: "worker1".to_string(),
            passed: true,
            local_hash: Some("hash".to_string()),
            remote_hash: Some("hash".to_string()),
            local_time_ms: Some(100),
            remote_time_ms: Some(150),
            error: None,
        };

        history.record_result(result);
        let results = history.results_for_runs(&[1]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].worker_id, "worker1");
    }

    #[test]
    fn test_self_test_run_report_serialization() {
        let _guard = test_guard!();
        let report = SelfTestRunReport {
            run: SelfTestRunRecord {
                id: 1,
                run_type: SelfTestRunType::Manual,
                started_at: "2024-01-01T00:00:00Z".to_string(),
                completed_at: "2024-01-01T00:01:00Z".to_string(),
                workers_tested: 2,
                workers_passed: 1,
                workers_failed: 1,
                duration_ms: 60000,
            },
            results: vec![
                SelfTestResultRecord {
                    run_id: 1,
                    worker_id: "worker1".to_string(),
                    passed: true,
                    local_hash: None,
                    remote_hash: None,
                    local_time_ms: None,
                    remote_time_ms: None,
                    error: None,
                },
                SelfTestResultRecord {
                    run_id: 1,
                    worker_id: "worker2".to_string(),
                    passed: false,
                    local_hash: None,
                    remote_hash: None,
                    local_time_ms: None,
                    remote_time_ms: None,
                    error: Some("timeout".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: SelfTestRunReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.run.id, 1);
        assert_eq!(deserialized.results.len(), 2);
        assert!(deserialized.results[0].passed);
        assert!(!deserialized.results[1].passed);
    }

    #[test]
    fn test_status_with_cron_schedule() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let history = Arc::new(SelfTestHistory::new(5, 5));
        let config = SelfTestConfig {
            enabled: true,
            schedule: Some("0 0 9 * * MON-FRI".to_string()),
            ..Default::default()
        };

        let service = SelfTestService::new(pool, config, history);
        let status = service.status();
        assert!(status.enabled);
        assert_eq!(status.schedule, Some("0 0 9 * * MON-FRI".to_string()));
        assert!(status.next_run.is_some());
    }

    #[test]
    fn test_next_run_cron_weekday_rollover() {
        let _guard = test_guard!();
        let now = DateTime::parse_from_rfc3339("2026-09-11T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for schedule in ["0 0 9 * * MON-FRI", "0 0 9 * * MON-FRI 2026"] {
            let service = SelfTestService::new(
                WorkerPool::new(),
                SelfTestConfig {
                    schedule: Some(schedule.to_string()),
                    ..Default::default()
                },
                Arc::new(SelfTestHistory::new(5, 5)),
            );
            assert_eq!(
                service.compute_next_run(&None, now).as_deref(),
                Some("2026-09-14T09:00:00+00:00"),
                "schedule {schedule} must advance past Friday's occurrence"
            );
        }
    }

    #[test]
    fn test_next_run_invalid_cron_falls_back_to_interval() {
        let _guard = test_guard!();
        let now = DateTime::parse_from_rfc3339("2026-09-11T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for (interval, expected) in [
            (Some("1h"), Some("2026-09-11T10:00:00+00:00")),
            (None, None),
            (Some("invalid"), None),
        ] {
            let service = SelfTestService::new(
                WorkerPool::new(),
                SelfTestConfig {
                    schedule: Some("invalid".to_string()),
                    interval: interval.map(str::to_string),
                    ..Default::default()
                },
                Arc::new(SelfTestHistory::new(5, 5)),
            );
            assert_eq!(service.compute_next_run(&None, now).as_deref(), expected);
        }
    }

    #[test]
    fn test_status_with_last_run() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let history = Arc::new(SelfTestHistory::new(5, 5));

        // Add a run to history
        let run = SelfTestRunRecord {
            id: 1,
            run_type: SelfTestRunType::Scheduled,
            started_at: "2024-01-01T00:00:00Z".to_string(),
            completed_at: "2024-01-01T00:01:00Z".to_string(),
            workers_tested: 3,
            workers_passed: 3,
            workers_failed: 0,
            duration_ms: 60000,
        };
        history.record_run(run);

        let config = SelfTestConfig {
            enabled: true,
            interval: Some("1h".to_string()),
            ..Default::default()
        };

        let service = SelfTestService::new(pool, config, history);
        let status = service.status();
        assert!(status.last_run.is_some());
        assert_eq!(status.last_run.unwrap().id, 1);
    }
}
