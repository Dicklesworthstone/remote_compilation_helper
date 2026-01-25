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
    let json = serde_json::to_string(entry)?;
    file.write_all(json.as_bytes()).await?;
    file.write_all(b"\n").await?;
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
}

impl Default for SelfTestRunOptions {
    fn default() -> Self {
        Self {
            run_type: SelfTestRunType::Manual,
            worker_ids: None,
            project_path: None,
            timeout: Duration::from_secs(DEFAULT_SELF_TEST_TIMEOUT_SECS),
            release_mode: true,
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
        let next_run = self.compute_next_run(&last_run);
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
        };
        self.run_internal(options).await
    }

    async fn run_internal(&self, options: SelfTestRunOptions) -> Result<SelfTestRunReport> {
        let _guard = self.run_lock.lock().await;
        let run_id = self.history.next_id();
        let started_at = Utc::now();

        let workers = self.resolve_workers(options.worker_ids.clone()).await?;
        let project_path = match &options.project_path {
            Some(path) => path.clone(),
            None => ensure_self_test_project()?,
        };

        let mut results = Vec::new();

        for worker in workers {
            let result = self
                .run_worker_with_retries(run_id, &worker, &project_path, &options)
                .await;
            results.push(result);
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
            for worker in workers {
                let config = worker.config.read().await;
                result.push(config.clone());
            }
        }

        Ok(result)
    }

    async fn run_worker_with_retries(
        &self,
        run_id: u64,
        worker: &WorkerConfig,
        project_path: &Path,
        options: &SelfTestRunOptions,
    ) -> SelfTestResultRecord {
        let retry_delay =
            parse_duration(&self.config.retry_delay).unwrap_or_else(|| Duration::from_secs(300));

        let mut attempt = 0;
        loop {
            attempt += 1;
            let test = RemoteCompilationTest::new(worker.clone(), project_path.to_path_buf())
                .with_timeout(options.timeout)
                .with_release_mode(options.release_mode);

            let result = test.run().await;
            let record = match result {
                Ok(outcome) => SelfTestResultRecord {
                    run_id,
                    worker_id: worker.id.to_string(),
                    passed: outcome.success,
                    local_hash: Some(outcome.local_hash.code_hash),
                    remote_hash: Some(outcome.remote_hash.code_hash),
                    local_time_ms: Some(outcome.local_build_ms),
                    remote_time_ms: Some(outcome.compilation_ms),
                    error: outcome.error,
                },
                Err(err) => SelfTestResultRecord {
                    run_id,
                    worker_id: worker.id.to_string(),
                    passed: false,
                    local_hash: None,
                    remote_hash: None,
                    local_time_ms: None,
                    remote_time_ms: None,
                    error: Some(err.to_string()),
                },
            };

            if record.passed || attempt > self.config.retry_count {
                return record;
            }

            warn!(
                "Self-test failed for worker {} (attempt {}/{}), retrying in {:?}",
                worker.id, attempt, self.config.retry_count, retry_delay
            );
            sleep(retry_delay).await;
        }
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

    fn compute_next_run(&self, last_run: &Option<SelfTestRunRecord>) -> Option<String> {
        if let Some(schedule) = self.config.schedule.as_ref()
            && let Ok(expr) = cron::Schedule::from_str(schedule)
            && let Some(next) = expr.upcoming(Utc).next()
        {
            return Some(next.to_rfc3339());
        }

        if let Some(interval) = self.config.interval.as_ref() {
            let duration = parse_duration(interval)?;
            let base = last_run
                .as_ref()
                .and_then(|run| DateTime::parse_from_rfc3339(&run.completed_at).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            let next = base + chrono::Duration::from_std(duration).ok()?;
            return Some(next.to_rfc3339());
        }

        None
    }
}

fn parse_duration(value: &str) -> Option<Duration> {
    humantime::parse_duration(value).ok()
}

fn ensure_self_test_project() -> Result<PathBuf> {
    let cache_dir = default_self_test_dir()?;
    let project_dir = cache_dir.join("project");
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

    let main_rs = src_dir.join("main.rs");
    if !main_rs.exists() {
        let contents = "fn main() {\n    println!(\"rch self-test\");\n}\n";
        fs::write(&main_rs, contents).with_context(|| format!("Failed to write {:?}", main_rs))?;
    }

    Ok(project_dir)
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

    #[test]
    fn test_parse_duration_minutes() {
        let duration = parse_duration("5m").expect("parse duration");
        assert_eq!(duration, Duration::from_secs(300));
    }

    #[test]
    fn test_status_next_run_interval() {
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
}
