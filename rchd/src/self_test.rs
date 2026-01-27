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
        use rch_common::test_guard;

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
        };
        assert_eq!(options.run_type, SelfTestRunType::Scheduled);
        assert!(options.worker_ids.is_some());
        assert!(options.project_path.is_some());
        assert!(!options.release_mode);
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
}
