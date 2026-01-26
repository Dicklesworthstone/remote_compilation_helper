//! Hot-reload support for daemon configuration.
//!
//! Provides file watching and config reload functionality for workers.toml
//! and config.toml without requiring a daemon restart.

use crate::config::{self, WorkersConfig};
use crate::workers::WorkerPool;
use anyhow::{Context, Result};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use rch_common::{WorkerConfig, WorkerId};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Configuration for the hot-reload watcher.
#[derive(Debug, Clone)]
pub struct ReloadConfig {
    /// Path to workers.toml (if provided via CLI).
    pub workers_config_path: Option<PathBuf>,
    /// Debounce interval for file changes.
    pub debounce_ms: u64,
    /// Whether to validate config before applying.
    pub validate_before_apply: bool,
}

impl Default for ReloadConfig {
    fn default() -> Self {
        Self {
            workers_config_path: None,
            debounce_ms: 500,
            validate_before_apply: true,
        }
    }
}

/// Result of a configuration reload operation.
#[derive(Debug)]
pub struct ReloadResult {
    /// Number of workers added.
    pub added: usize,
    /// Number of workers updated.
    pub updated: usize,
    /// Number of workers removed.
    pub removed: usize,
    /// Any warnings generated during reload.
    pub warnings: Vec<String>,
}

impl ReloadResult {
    pub fn new() -> Self {
        Self {
            added: 0,
            updated: 0,
            removed: 0,
            warnings: Vec::new(),
        }
    }

    pub fn has_changes(&self) -> bool {
        self.added > 0 || self.updated > 0 || self.removed > 0
    }
}

impl Default for ReloadResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Diff between old and new worker configurations.
#[derive(Debug)]
pub struct ConfigDiff {
    /// Workers to add (new in config).
    pub to_add: Vec<WorkerConfig>,
    /// Workers to update (exist but changed).
    pub to_update: Vec<WorkerConfig>,
    /// Worker IDs to remove (no longer in config).
    pub to_remove: Vec<WorkerId>,
}

impl ConfigDiff {
    pub fn is_empty(&self) -> bool {
        self.to_add.is_empty() && self.to_update.is_empty() && self.to_remove.is_empty()
    }
}

/// Compute the diff between current worker pool state and new config.
pub async fn compute_worker_diff(
    pool: &WorkerPool,
    new_workers: &[WorkerConfig],
) -> Result<ConfigDiff> {
    let current_workers = pool.all_workers().await;
    let mut current_ids: HashSet<WorkerId> = HashSet::new();

    // Build map of current workers
    let mut current_configs: std::collections::HashMap<WorkerId, WorkerConfig> =
        std::collections::HashMap::new();
    for worker in &current_workers {
        let config = worker.config.read().await.clone();
        current_ids.insert(config.id.clone());
        current_configs.insert(config.id.clone(), config);
    }

    // Build set of new worker IDs
    let new_ids: HashSet<WorkerId> = new_workers.iter().map(|w| w.id.clone()).collect();

    let mut to_add = Vec::new();
    let mut to_update = Vec::new();
    let mut to_remove = Vec::new();

    // Find workers to add or update
    for new_config in new_workers {
        if let Some(current_config) = current_configs.get(&new_config.id) {
            // Worker exists - check if it changed
            if worker_config_changed(current_config, new_config) {
                to_update.push(new_config.clone());
            }
        } else {
            // New worker
            to_add.push(new_config.clone());
        }
    }

    // Find workers to remove
    for current_id in &current_ids {
        if !new_ids.contains(current_id) {
            to_remove.push(current_id.clone());
        }
    }

    Ok(ConfigDiff {
        to_add,
        to_update,
        to_remove,
    })
}

/// Check if a worker configuration has changed.
fn worker_config_changed(old: &WorkerConfig, new: &WorkerConfig) -> bool {
    old.host != new.host
        || old.user != new.user
        || old.identity_file != new.identity_file
        || old.total_slots != new.total_slots
        || old.priority != new.priority
        || old.tags != new.tags
}

/// Validate a new workers configuration.
pub fn validate_workers_config(config: &WorkersConfig) -> Result<Vec<String>> {
    let mut warnings = Vec::new();

    // Check for duplicate IDs
    let mut seen_ids = HashSet::new();
    for worker in &config.workers {
        if !seen_ids.insert(&worker.id) {
            return Err(anyhow::anyhow!("Duplicate worker ID: {}", worker.id));
        }
    }

    // Warn about workers with 0 slots
    for worker in &config.workers {
        if worker.total_slots == 0 && worker.enabled {
            warnings.push(format!("Worker {} has 0 slots", worker.id));
        }
    }

    // Warn if no workers are enabled
    let enabled_count = config.workers.iter().filter(|w| w.enabled).count();
    if enabled_count == 0 && !config.workers.is_empty() {
        warnings.push("No workers are enabled".to_string());
    }

    Ok(warnings)
}

/// Apply a configuration diff to the worker pool.
pub async fn apply_worker_diff(pool: &WorkerPool, diff: &ConfigDiff) -> Result<ReloadResult> {
    let mut result = ReloadResult::new();

    // Add new workers
    for config in &diff.to_add {
        info!(
            "Adding worker: {} ({}@{}, {} slots)",
            config.id, config.user, config.host, config.total_slots
        );
        pool.add_worker(config.clone()).await;
        result.added += 1;
    }

    // Update existing workers
    for config in &diff.to_update {
        info!(
            "Updating worker: {} ({}@{}, {} slots)",
            config.id, config.user, config.host, config.total_slots
        );
        pool.add_worker(config.clone()).await; // add_worker handles updates
        result.updated += 1;
    }

    // Note: We don't remove workers immediately to avoid disrupting active jobs.
    // Instead, we mark them for draining. A separate process should handle removal
    // once jobs complete.
    for id in &diff.to_remove {
        if let Some(worker) = pool.get(id).await {
            let used_slots = worker.used_slots();
            if used_slots > 0 {
                info!(
                    "Worker {} has {} active slots, marking for drain instead of removal",
                    id, used_slots
                );
                worker.drain().await;
                result.warnings.push(format!(
                    "Worker {} has active jobs, draining instead of removing",
                    id
                ));
            } else {
                info!("Worker {} removed (no active jobs)", id);
                worker
                    .disable(Some("Removed from configuration".to_string()))
                    .await;
            }
            result.removed += 1;
        }
    }

    Ok(result)
}

/// Reload workers configuration from disk and apply changes.
pub async fn reload_workers(
    pool: &WorkerPool,
    config_path: Option<&Path>,
    validate: bool,
) -> Result<ReloadResult> {
    info!("Reloading workers configuration...");

    // Load new configuration
    let new_config =
        config::load_workers_config(config_path).context("Failed to load workers configuration")?;

    // Validate if requested
    let mut warnings = Vec::new();
    if validate {
        warnings =
            validate_workers_config(&new_config).context("Configuration validation failed")?;
        for warning in &warnings {
            warn!("Config warning: {}", warning);
        }
    }

    // Convert to WorkerConfig and filter enabled
    let new_workers: Vec<WorkerConfig> = new_config
        .workers
        .into_iter()
        .filter(|w| w.enabled)
        .map(WorkerConfig::from)
        .collect();

    // Compute diff
    let diff = compute_worker_diff(pool, &new_workers).await?;

    if diff.is_empty() {
        info!("No configuration changes detected");
        return Ok(ReloadResult {
            warnings,
            ..ReloadResult::new()
        });
    }

    // Apply changes
    let mut result = apply_worker_diff(pool, &diff).await?;
    result.warnings.extend(warnings);

    info!(
        "Reload complete: {} added, {} updated, {} removed",
        result.added, result.updated, result.removed
    );

    Ok(result)
}

/// Messages sent by the file watcher.
#[derive(Debug)]
pub enum ReloadMessage {
    /// Configuration file changed, reload required.
    ConfigChanged(PathBuf),
    /// Manual reload requested (e.g., via SIGHUP or CLI).
    ManualReload,
    /// Shutdown the watcher.
    Shutdown,
}

/// File watcher for configuration hot-reload.
pub struct ConfigWatcher {
    config: ReloadConfig,
    pool: WorkerPool,
    rx: mpsc::Receiver<ReloadMessage>,
    _watcher: Option<RecommendedWatcher>,
}

impl ConfigWatcher {
    /// Create a new config watcher.
    pub fn new(
        config: ReloadConfig,
        pool: WorkerPool,
    ) -> Result<(Self, mpsc::Sender<ReloadMessage>)> {
        let (tx, rx) = mpsc::channel(16);

        Ok((
            Self {
                config,
                pool,
                rx,
                _watcher: None,
            },
            tx,
        ))
    }

    /// Start watching configuration files.
    pub async fn start(
        mut self,
        tx: mpsc::Sender<ReloadMessage>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        // Determine paths to watch
        let workers_path = self.config.workers_config_path.clone();
        let config_dir = config::config_dir();

        // Set up file watcher
        let watcher_tx = tx.clone();
        let debounce = Duration::from_millis(self.config.debounce_ms);

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    // Only handle modify/create events
                    if event.kind.is_modify() || event.kind.is_create() {
                        for path in event.paths {
                            if let Some(filename) = path.file_name() {
                                let name = filename.to_string_lossy();
                                if name == "workers.toml" || name == "config.toml" {
                                    debug!("Config file changed: {:?}", path);
                                    if let Err(e) = watcher_tx
                                        .blocking_send(ReloadMessage::ConfigChanged(path.clone()))
                                    {
                                        error!("Failed to send reload message: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("File watcher error: {}", e);
                }
            }
        })?;

        // Watch the workers config path if provided
        if let Some(ref path) = workers_path {
            if let Some(parent) = path.parent() {
                watcher.watch(parent, RecursiveMode::NonRecursive)?;
                info!("Watching for config changes in {:?}", parent);
            }
        }

        // Watch the default config directory
        if let Some(dir) = config_dir {
            if dir.exists() {
                watcher.watch(&dir, RecursiveMode::NonRecursive)?;
                info!("Watching for config changes in {:?}", dir);
            }
        }

        self._watcher = Some(watcher);

        // Start the reload loop
        let handle = tokio::spawn(async move {
            self.run_reload_loop().await;
        });

        // Give the watcher time to settle
        tokio::time::sleep(debounce).await;

        Ok(handle)
    }

    /// Run the main reload loop.
    async fn run_reload_loop(mut self) {
        let debounce = Duration::from_millis(self.config.debounce_ms);
        let mut pending_reload = false;
        let mut last_reload = std::time::Instant::now();

        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    match msg {
                        Some(ReloadMessage::ConfigChanged(path)) => {
                            debug!("Config change detected: {:?}", path);
                            pending_reload = true;
                        }
                        Some(ReloadMessage::ManualReload) => {
                            info!("Manual reload requested");
                            self.perform_reload().await;
                            last_reload = std::time::Instant::now();
                            pending_reload = false;
                        }
                        Some(ReloadMessage::Shutdown) | None => {
                            info!("Config watcher shutting down");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(debounce), if pending_reload => {
                    // Debounce: only reload if enough time has passed since last reload
                    if last_reload.elapsed() >= debounce {
                        self.perform_reload().await;
                        last_reload = std::time::Instant::now();
                        pending_reload = false;
                    }
                }
            }
        }
    }

    /// Perform the actual reload.
    async fn perform_reload(&self) {
        match reload_workers(
            &self.pool,
            self.config.workers_config_path.as_deref(),
            self.config.validate_before_apply,
        )
        .await
        {
            Ok(result) => {
                if result.has_changes() {
                    info!(
                        "Configuration reloaded: {} added, {} updated, {} removed",
                        result.added, result.updated, result.removed
                    );
                } else {
                    debug!("Configuration reload: no changes");
                }
            }
            Err(e) => {
                error!("Configuration reload failed: {}", e);
                // Fail-open: keep running with existing config
            }
        }
    }
}

/// Start the configuration watcher in the background.
pub async fn start_config_watcher(
    pool: WorkerPool,
    workers_config_path: Option<PathBuf>,
) -> Result<(tokio::task::JoinHandle<()>, mpsc::Sender<ReloadMessage>)> {
    let config = ReloadConfig {
        workers_config_path,
        ..Default::default()
    };

    let (watcher, tx) = ConfigWatcher::new(config, pool)?;
    let handle = watcher.start(tx.clone()).await?;

    Ok((handle, tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    #[tokio::test]
    async fn test_compute_worker_diff_empty() {
        init_test_logging();

        let pool = WorkerPool::new();
        let new_workers: Vec<WorkerConfig> = vec![];

        let diff = compute_worker_diff(&pool, &new_workers).await.unwrap();
        assert!(diff.is_empty());
    }

    #[tokio::test]
    async fn test_compute_worker_diff_add() {
        init_test_logging();

        let pool = WorkerPool::new();
        let new_workers = vec![WorkerConfig {
            id: WorkerId::new("new-worker"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        }];

        let diff = compute_worker_diff(&pool, &new_workers).await.unwrap();
        assert_eq!(diff.to_add.len(), 1);
        assert!(diff.to_update.is_empty());
        assert!(diff.to_remove.is_empty());
    }

    #[tokio::test]
    async fn test_compute_worker_diff_update() {
        init_test_logging();

        let pool = WorkerPool::new();
        let initial_config = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(initial_config).await;

        // Change slots
        let updated_config = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 16, // Changed
            priority: 100,
            tags: vec![],
        };

        let diff = compute_worker_diff(&pool, &[updated_config]).await.unwrap();
        assert!(diff.to_add.is_empty());
        assert_eq!(diff.to_update.len(), 1);
        assert!(diff.to_remove.is_empty());
    }

    #[tokio::test]
    async fn test_compute_worker_diff_remove() {
        init_test_logging();

        let pool = WorkerPool::new();
        let config = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(config).await;

        // Empty new config = remove all
        let diff = compute_worker_diff(&pool, &[]).await.unwrap();
        assert!(diff.to_add.is_empty());
        assert!(diff.to_update.is_empty());
        assert_eq!(diff.to_remove.len(), 1);
    }

    #[test]
    fn test_validate_workers_config_duplicate_ids() {
        init_test_logging();

        let config = WorkersConfig {
            workers: vec![
                config::WorkerEntry {
                    id: "worker1".to_string(),
                    host: "host1".to_string(),
                    user: "ubuntu".to_string(),
                    identity_file: "~/.ssh/id_rsa".to_string(),
                    total_slots: 8,
                    priority: 100,
                    tags: vec![],
                    enabled: true,
                },
                config::WorkerEntry {
                    id: "worker1".to_string(), // Duplicate
                    host: "host2".to_string(),
                    user: "ubuntu".to_string(),
                    identity_file: "~/.ssh/id_rsa".to_string(),
                    total_slots: 4,
                    priority: 50,
                    tags: vec![],
                    enabled: true,
                },
            ],
        };

        let result = validate_workers_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_workers_config_zero_slots_warning() {
        init_test_logging();

        let config = WorkersConfig {
            workers: vec![config::WorkerEntry {
                id: "worker1".to_string(),
                host: "host1".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 0,
                priority: 100,
                tags: vec![],
                enabled: true,
            }],
        };

        let warnings = validate_workers_config(&config).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("0 slots"));
    }

    #[tokio::test]
    async fn test_apply_worker_diff_add() {
        init_test_logging();

        let pool = WorkerPool::new();
        let diff = ConfigDiff {
            to_add: vec![WorkerConfig {
                id: WorkerId::new("new-worker"),
                host: "192.168.1.100".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
            }],
            to_update: vec![],
            to_remove: vec![],
        };

        let result = apply_worker_diff(&pool, &diff).await.unwrap();
        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 0);
        assert_eq!(result.removed, 0);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn test_reload_workers_no_changes() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = r#"
[[workers]]
id = "worker1"
host = "192.168.1.100"
user = "ubuntu"
total_slots = 8
enabled = true
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let pool = WorkerPool::new();
        let initial = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(initial).await;

        let result = reload_workers(&pool, Some(&workers_path), true)
            .await
            .unwrap();
        assert!(!result.has_changes());
    }

    #[tokio::test]
    async fn test_reload_workers_with_changes() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        let config_content = r#"
[[workers]]
id = "worker1"
host = "192.168.1.100"
user = "ubuntu"
total_slots = 16
enabled = true

[[workers]]
id = "worker2"
host = "192.168.1.101"
user = "admin"
total_slots = 4
enabled = true
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let pool = WorkerPool::new();
        let initial = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8, // Will be updated to 16
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(initial).await;

        let result = reload_workers(&pool, Some(&workers_path), true)
            .await
            .unwrap();
        assert!(result.has_changes());
        assert_eq!(result.added, 1); // worker2
        assert_eq!(result.updated, 1); // worker1
        assert_eq!(pool.len(), 2);
    }
}
