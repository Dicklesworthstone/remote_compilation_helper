//! Hot-reload support for the daemon's worker configuration.
//!
//! Watch the selected workers file (including custom filenames) without a
//! daemon restart. Invalid or unavailable snapshots retain the current fleet;
//! only an explicit `workers = []` requests an empty fleet.

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
    /// Path to the workers configuration (if provided via CLI).
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
    /// Workers to update or reconcile after a drain.
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
    let mut draining_ids: HashSet<WorkerId> = HashSet::new();

    // Build map of current workers
    let mut current_configs: std::collections::HashMap<WorkerId, WorkerConfig> =
        std::collections::HashMap::new();
    for worker in &current_workers {
        let config = worker.config.read().await.clone();
        current_ids.insert(config.id.clone());
        if worker.is_draining().await || worker.is_drained().await {
            draining_ids.insert(config.id.clone());
        }
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
            // Reintroduced inventory can be byte-identical while the old state
            // is still draining for removal. update_config cancels only that
            // removal intent; manual drains/disables and health remain intact.
            if worker_config_changed(current_config, new_config)
                || draining_ids.contains(&new_config.id)
            {
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

    // Reject IDs that would unsafely splice into shell commands, paths, or
    // HTTP request lines. The daemon embeds worker IDs into remote shell
    // invocations (telemetry collection, hook installation), into local
    // filesystem paths (caches, control sockets), and into HTTP URLs
    // (`POST /workers/{id}/drain`). A worker ID like `; rm -rf /` would
    // turn an operator-supplied config into arbitrary code execution on
    // the worker the next time the daemon polled telemetry. We require a
    // conservative, predictable character set up-front so every downstream
    // consumer can rely on it without re-validating.
    for worker in &config.workers {
        if !is_safe_worker_id(&worker.id) {
            return Err(anyhow::anyhow!(
                "Invalid worker ID '{}': must be 1-64 chars and contain only \
                 letters, digits, '_', '-', or '.'",
                worker.id
            ));
        }
    }

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

/// Worker IDs must be safe for shell, filesystem, and URL contexts.
///
/// Allowed: ASCII letters, digits, `_`, `-`, `.`. Empty, leading-dot
/// (hidden-file confusion), and over-length IDs are rejected. We
/// deliberately disallow `/` and `:` even though they would survive most
/// shells, because they would silently re-interpret cache paths and HTTP
/// route segments respectively.
fn is_safe_worker_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    if id.starts_with('.') {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
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

    // Close admission even for an apparently idle worker before removing it.
    // Selectors retain Arc<WorkerState> snapshots: removing only the map entry
    // leaves those handles able to reserve slots outside the authoritative pool.
    // A reservation admitted before the drain must remain tracked until release.
    for id in &diff.to_remove {
        if let Some(worker) = pool.get(id).await {
            worker.drain_for_removal().await;
            let used_slots = worker.used_slots();
            if used_slots > 0 {
                info!(
                    "Worker {} has {} active slots, marking for drain instead of removal",
                    id, used_slots
                );
                result.warnings.push(format!(
                    "Worker {} has active jobs, draining instead of removing",
                    id
                ));
            }
        }
    }
    if !diff.to_remove.is_empty() {
        // This rechecks identity, lifecycle, removal intent and reservations
        // under the pool lock. Count only entries actually removed, including
        // earlier config-removal drains that completed during this reload.
        result.removed = pool.prune_drained().await;
    }

    Ok(result)
}

fn workers_reload_path(config_path: Option<&Path>) -> Result<PathBuf> {
    let path = match config_path {
        Some(path) => path.to_path_buf(),
        None => config::config_dir()
            .context("Could not determine workers configuration directory")?
            .join("workers.toml"),
    };
    anyhow::ensure!(
        path.file_name().is_some(),
        "Workers configuration must name a file: {}",
        path.display()
    );
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("Could not resolve relative workers configuration path")?
            .join(path))
    }
}

/// Reload is not first-run startup: absence is not an instruction to remove
/// the fleet. Read exactly one snapshot, without an exists-then-read race, and
/// require the workers field so an editor's empty/truncated file cannot pass
/// serde's startup defaults. Explicit `workers = []` still drains the fleet.
fn load_workers_reload_snapshot(config_path: Option<&Path>) -> Result<WorkersConfig> {
    #[derive(serde::Deserialize)]
    struct Snapshot {
        workers: Vec<config::WorkerEntry>,
    }

    let path = workers_reload_path(config_path)?;
    let contents = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "Failed to read workers reload snapshot {}; retaining current fleet",
            path.display()
        )
    })?;
    let snapshot: Snapshot = toml::from_str(&contents).with_context(|| {
        format!(
            "Invalid workers reload snapshot {}; retaining current fleet (use workers = [] to explicitly empty it)",
            path.display()
        )
    })?;
    Ok(WorkersConfig {
        workers: snapshot.workers,
    })
}

/// Reload workers configuration from disk and apply changes.
pub async fn reload_workers(
    pool: &WorkerPool,
    config_path: Option<&Path>,
    validate: bool,
) -> Result<ReloadResult> {
    info!("Reloading workers configuration...");

    // Never turn a missing or incomplete snapshot into an empty desired fleet.
    let new_config = load_workers_reload_snapshot(config_path)?;

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
    #[allow(dead_code)]
    Shutdown,
}

/// A rename can carry both the old and new path. Remove events trigger a
/// read-only reconciliation too; the strict loader retains the previous fleet.
/// Rescan notifications may have no paths, and must not be silently discarded.
fn event_requires_workers_reload(event: &Event, workers_path: &Path) -> bool {
    event.need_rescan()
        || (!event.kind.is_access() && event.paths.iter().any(|path| path == workers_path))
}

fn queue_workers_reload(tx: &mpsc::Sender<ReloadMessage>, workers_path: &Path) {
    match tx.try_send(ReloadMessage::ConfigChanged(workers_path.to_path_buf())) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {
            // A queued notification already requests a fresh snapshot. Coalesce
            // bursts instead of blocking notify's thread (including on drop).
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            debug!("Config watcher receiver has shut down");
        }
    }
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
        let selected = workers_reload_path(self.config.workers_config_path.as_deref())?;
        // Watch the parent, not the file inode, so atomic replacements keep
        // working. Resolve only the directory: the file need not exist yet and
        // its leaf may itself be an operator-managed symlink.
        let parent = selected
            .parent()
            .context("Workers configuration has no parent directory")?
            .canonicalize()
            .with_context(|| format!("Failed to resolve workers config parent for {selected:?}"))?;
        let workers_path = parent.join(
            selected
                .file_name()
                .context("Workers configuration must name a file")?,
        );
        // Freeze the same path for automatic and manual reloads. Do not watch
        // a custom basename but then reread the default workers.toml instead.
        self.config.workers_config_path = Some(workers_path.clone());

        let watcher_tx = tx.clone();
        let watched_path = workers_path.clone();
        let debounce = Duration::from_millis(self.config.debounce_ms);
        let mut watcher =
            notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
                Ok(event) if event_requires_workers_reload(&event, &watched_path) => {
                    debug!("Workers config changed: {:?}", watched_path);
                    queue_workers_reload(&watcher_tx, &watched_path);
                }
                Ok(_) => {}
                Err(e) => {
                    error!("File watcher error: {}; reconciling workers snapshot", e);
                    queue_workers_reload(&watcher_tx, &watched_path);
                }
            })?;
        watcher.watch(&parent, RecursiveMode::NonRecursive)?;
        info!("Watching workers configuration {:?}", workers_path);
        self._watcher = Some(watcher);

        // Close the gap between the daemon's initial read and watch registration.
        // The callback and this reconciliation use the same bounded queue.
        queue_workers_reload(&tx, &workers_path);
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
                // Keep serving the last successfully loaded worker configuration.
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
    use rch_common::test_guard;
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
        let _guard = test_guard!();
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
                    os: None,
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
                    os: None,
                    enabled: true,
                },
            ],
        };

        let result = validate_workers_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_workers_config_zero_slots_warning() {
        let _guard = test_guard!();
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
                os: None,
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

    #[test]
    fn test_reload_result_default() {
        let _guard = test_guard!();
        let result = ReloadResult::default();
        assert_eq!(result.added, 0);
        assert_eq!(result.updated, 0);
        assert_eq!(result.removed, 0);
        assert!(result.warnings.is_empty());
        assert!(!result.has_changes());
    }

    #[test]
    fn test_reload_result_has_changes_added_only() {
        let _guard = test_guard!();
        let mut result = ReloadResult::new();
        result.added = 1;
        assert!(result.has_changes());
    }

    #[test]
    fn test_reload_result_has_changes_updated_only() {
        let _guard = test_guard!();
        let mut result = ReloadResult::new();
        result.updated = 1;
        assert!(result.has_changes());
    }

    #[test]
    fn test_reload_result_has_changes_removed_only() {
        let _guard = test_guard!();
        let mut result = ReloadResult::new();
        result.removed = 1;
        assert!(result.has_changes());
    }

    #[test]
    fn test_reload_config_default() {
        let _guard = test_guard!();
        let config = ReloadConfig::default();
        assert!(config.workers_config_path.is_none());
        assert_eq!(config.debounce_ms, 500);
        assert!(config.validate_before_apply);
    }

    #[test]
    fn test_config_diff_is_empty_true() {
        let _guard = test_guard!();
        let diff = ConfigDiff {
            to_add: vec![],
            to_update: vec![],
            to_remove: vec![],
        };
        assert!(diff.is_empty());
    }

    #[test]
    fn test_config_diff_not_empty_with_add() {
        let _guard = test_guard!();
        let diff = ConfigDiff {
            to_add: vec![WorkerConfig {
                id: WorkerId::new("worker1"),
                host: "host".to_string(),
                user: "user".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
            }],
            to_update: vec![],
            to_remove: vec![],
        };
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_config_diff_not_empty_with_update() {
        let _guard = test_guard!();
        let diff = ConfigDiff {
            to_add: vec![],
            to_update: vec![WorkerConfig {
                id: WorkerId::new("worker1"),
                host: "host".to_string(),
                user: "user".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
            }],
            to_remove: vec![],
        };
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_config_diff_not_empty_with_remove() {
        let _guard = test_guard!();
        let diff = ConfigDiff {
            to_add: vec![],
            to_update: vec![],
            to_remove: vec![WorkerId::new("worker1")],
        };
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_validate_workers_config_no_enabled_workers() {
        let _guard = test_guard!();
        init_test_logging();

        let config = WorkersConfig {
            workers: vec![config::WorkerEntry {
                id: "worker1".to_string(),
                host: "host1".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
                os: None,
                enabled: false,
            }],
        };

        let warnings = validate_workers_config(&config).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("No workers are enabled"));
    }

    #[test]
    fn test_validate_workers_config_valid_no_warnings() {
        let _guard = test_guard!();
        init_test_logging();

        let config = WorkersConfig {
            workers: vec![config::WorkerEntry {
                id: "worker1".to_string(),
                host: "host1".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
                os: None,
                enabled: true,
            }],
        };

        let warnings = validate_workers_config(&config).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_workers_config_empty() {
        let _guard = test_guard!();
        init_test_logging();

        let config = WorkersConfig { workers: vec![] };

        // Empty config should be valid (no duplicates, no "no workers enabled" warning because workers is empty)
        let warnings = validate_workers_config(&config).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_is_safe_worker_id_accepts_normal_names() {
        assert!(is_safe_worker_id("worker1"));
        assert!(is_safe_worker_id("css"));
        assert!(is_safe_worker_id("worker-1"));
        assert!(is_safe_worker_id("worker_1"));
        assert!(is_safe_worker_id("rch.prod.01"));
        assert!(is_safe_worker_id("a"));
        assert!(is_safe_worker_id(&"a".repeat(64)));
    }

    #[test]
    fn test_is_safe_worker_id_rejects_shell_metacharacters() {
        // Defense-in-depth: even with telemetry.rs shell-escaping the ID, we
        // refuse to load configs that would smuggle metacharacters into the
        // many other places the ID is interpolated (cache paths, HTTP routes,
        // remote shell commands).
        for bad in [
            "",                  // empty
            ".hidden",           // leading dot
            "worker;rm -rf /",   // command separator
            "worker$(id)",       // command substitution
            "worker`id`",        // backticks
            "worker|cat",        // pipe
            "worker&background", // background
            "worker with space", // whitespace
            "worker\nrm",        // newline
            "worker/etc/passwd", // path separator
            "worker:443",        // url separator
            "worker'",           // single quote
            "worker\"",          // double quote
            "worker\\esc",       // backslash
            &"a".repeat(65),     // too long
        ] {
            assert!(
                !is_safe_worker_id(bad),
                "expected {bad:?} to be rejected as unsafe worker ID"
            );
        }
    }

    #[test]
    fn test_validate_workers_config_rejects_unsafe_id() {
        let _guard = test_guard!();
        init_test_logging();

        let config = WorkersConfig {
            workers: vec![crate::config::WorkerEntry {
                id: "worker;rm -rf /".to_string(),
                os: None,
                enabled: true,
                host: "1.2.3.4".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 4,
                priority: 100,
                tags: vec![],
            }],
        };

        let err = validate_workers_config(&config).unwrap_err();
        assert!(
            err.to_string().contains("Invalid worker ID"),
            "expected validation error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_compute_worker_diff_host_change() {
        init_test_logging();

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

        let updated = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.200".to_string(), // Changed host
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let diff = compute_worker_diff(&pool, &[updated]).await.unwrap();
        assert!(diff.to_add.is_empty());
        assert_eq!(diff.to_update.len(), 1);
        assert!(diff.to_remove.is_empty());
    }

    #[tokio::test]
    async fn test_compute_worker_diff_user_change() {
        init_test_logging();

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

        let updated = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "admin".to_string(), // Changed user
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let diff = compute_worker_diff(&pool, &[updated]).await.unwrap();
        assert_eq!(diff.to_update.len(), 1);
    }

    #[tokio::test]
    async fn test_compute_worker_diff_identity_file_change() {
        init_test_logging();

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

        let updated = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_ed25519".to_string(), // Changed identity file
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let diff = compute_worker_diff(&pool, &[updated]).await.unwrap();
        assert_eq!(diff.to_update.len(), 1);
    }

    #[tokio::test]
    async fn test_compute_worker_diff_priority_change() {
        init_test_logging();

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

        let updated = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 50, // Changed priority
            tags: vec![],
        };

        let diff = compute_worker_diff(&pool, &[updated]).await.unwrap();
        assert_eq!(diff.to_update.len(), 1);
    }

    #[tokio::test]
    async fn test_compute_worker_diff_tags_change() {
        init_test_logging();

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

        let updated = WorkerConfig {
            id: WorkerId::new("worker1"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec!["gpu".to_string()], // Changed tags
        };

        let diff = compute_worker_diff(&pool, &[updated]).await.unwrap();
        assert_eq!(diff.to_update.len(), 1);
    }

    #[tokio::test]
    async fn test_compute_worker_diff_no_change() {
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
        pool.add_worker(config.clone()).await;

        let diff = compute_worker_diff(&pool, &[config]).await.unwrap();
        assert!(diff.is_empty());
    }

    #[tokio::test]
    async fn test_apply_worker_diff_update() {
        init_test_logging();

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

        let diff = ConfigDiff {
            to_add: vec![],
            to_update: vec![WorkerConfig {
                id: WorkerId::new("worker1"),
                host: "192.168.1.100".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 16, // Updated slots
                priority: 100,
                tags: vec![],
            }],
            to_remove: vec![],
        };

        let result = apply_worker_diff(&pool, &diff).await.unwrap();
        assert_eq!(result.added, 0);
        assert_eq!(result.updated, 1);
        assert_eq!(result.removed, 0);
    }

    #[tokio::test]
    async fn test_apply_worker_diff_remove_idle() {
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

        let diff = ConfigDiff {
            to_add: vec![],
            to_update: vec![],
            to_remove: vec![WorkerId::new("worker1")],
        };

        let result = apply_worker_diff(&pool, &diff).await.unwrap();
        assert_eq!(result.added, 0);
        assert_eq!(result.updated, 0);
        assert_eq!(result.removed, 1);
        assert!(result.warnings.is_empty()); // No active jobs, so no warning
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn test_apply_worker_diff_drained_worker_not_counted_as_removed() {
        // Regression: previously `result.removed` incremented for every
        // `to_remove` entry, including workers that had active builds and
        // were only drained. The reload summary then claimed workers were
        // removed while they were still in the pool draining — confusing
        // both operators and any automation reading the count.
        init_test_logging();

        let pool = WorkerPool::new();
        let config = WorkerConfig {
            id: WorkerId::new("busy-worker"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            ..WorkerConfig::default()
        };
        pool.add_worker(config).await;
        // Reserve a slot so used_slots > 0 — this forces the drain path.
        let worker = pool.get(&WorkerId::new("busy-worker")).await.unwrap();
        assert!(worker.reserve_slots(1).await);

        let diff = ConfigDiff {
            to_add: vec![],
            to_update: vec![],
            to_remove: vec![WorkerId::new("busy-worker")],
        };

        let result = apply_worker_diff(&pool, &diff).await.unwrap();
        assert_eq!(
            result.removed, 0,
            "drained (not removed) workers must not count as removed"
        );
        assert_eq!(result.warnings.len(), 1, "drain path must emit a warning");
        assert_eq!(
            pool.len(),
            1,
            "worker must still be in the pool after drain"
        );
    }

    #[tokio::test]
    async fn test_apply_worker_diff_remove_nonexistent() {
        init_test_logging();

        let pool = WorkerPool::new();

        let diff = ConfigDiff {
            to_add: vec![],
            to_update: vec![],
            to_remove: vec![WorkerId::new("nonexistent")],
        };

        let result = apply_worker_diff(&pool, &diff).await.unwrap();
        // Worker doesn't exist, so nothing removed
        assert_eq!(result.removed, 0);
    }

    #[tokio::test]
    async fn test_reload_workers_validation_disabled() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        // Config with a warning condition (0 slots)
        let config_content = r#"
[[workers]]
id = "worker1"
host = "192.168.1.100"
user = "ubuntu"
total_slots = 0
enabled = true
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let pool = WorkerPool::new();

        // Reload with validation disabled
        let result = reload_workers(&pool, Some(&workers_path), false)
            .await
            .unwrap();
        // Should succeed without warnings since validation is disabled
        assert!(result.warnings.is_empty());
    }

    #[tokio::test]
    async fn test_config_watcher_new() {
        init_test_logging();

        let pool = WorkerPool::new();
        let config = ReloadConfig::default();

        let (watcher, tx) = ConfigWatcher::new(config, pool).unwrap();
        assert!(watcher._watcher.is_none()); // Watcher not started yet
        drop(tx); // Clean up
    }

    #[test]
    fn test_reload_message_debug() {
        let _guard = test_guard!();
        let msg = ReloadMessage::ManualReload;
        assert!(format!("{:?}", msg).contains("ManualReload"));

        let msg = ReloadMessage::Shutdown;
        assert!(format!("{:?}", msg).contains("Shutdown"));

        let msg = ReloadMessage::ConfigChanged(PathBuf::from("/test/path"));
        assert!(format!("{:?}", msg).contains("ConfigChanged"));
    }

    #[tokio::test]
    async fn test_compute_worker_diff_complex() {
        init_test_logging();

        let pool = WorkerPool::new();

        // Add 3 workers
        for i in 1..=3 {
            let config = WorkerConfig {
                id: WorkerId::new(format!("worker{}", i)),
                host: format!("192.168.1.{}", 100 + i),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
            };
            pool.add_worker(config).await;
        }

        // New config: remove worker1, update worker2, keep worker3, add worker4
        let new_workers = vec![
            WorkerConfig {
                id: WorkerId::new("worker2"),
                host: "192.168.1.102".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 16, // Updated
                priority: 100,
                tags: vec![],
            },
            WorkerConfig {
                id: WorkerId::new("worker3"),
                host: "192.168.1.103".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
            },
            WorkerConfig {
                id: WorkerId::new("worker4"),
                host: "192.168.1.104".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 4,
                priority: 50,
                tags: vec!["gpu".to_string()],
            },
        ];

        let diff = compute_worker_diff(&pool, &new_workers).await.unwrap();
        assert_eq!(diff.to_add.len(), 1); // worker4
        assert_eq!(diff.to_update.len(), 1); // worker2
        assert_eq!(diff.to_remove.len(), 1); // worker1
    }

    #[tokio::test]
    async fn test_reload_workers_invalid_config() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        // Invalid TOML
        std::fs::write(&workers_path, "invalid toml [[[").unwrap();

        let pool = WorkerPool::new();

        let result = reload_workers(&pool, Some(&workers_path), true).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reload_workers_duplicate_ids() {
        init_test_logging();

        let temp_dir = TempDir::new().unwrap();
        let workers_path = temp_dir.path().join("workers.toml");

        // Config with duplicate IDs
        let config_content = r#"
[[workers]]
id = "worker1"
host = "host1"
user = "ubuntu"
total_slots = 8
enabled = true

[[workers]]
id = "worker1"
host = "host2"
user = "ubuntu"
total_slots = 4
enabled = true
"#;
        std::fs::write(&workers_path, config_content).unwrap();

        let pool = WorkerPool::new();

        let result = reload_workers(&pool, Some(&workers_path), true).await;
        assert!(result.is_err());
    }

    async fn reload_safety_pool() -> WorkerPool {
        let pool = WorkerPool::new();
        for id in ["busy", "idle"] {
            pool.add_worker(WorkerConfig {
                id: WorkerId::new(id),
                total_slots: 8,
                ..WorkerConfig::default()
            })
            .await;
        }
        let busy = pool.get(&WorkerId::new("busy")).await.unwrap();
        assert!(busy.reserve_slots(1).await);
        busy.add_cached_project("retained-project".to_owned()).await;
        pool
    }

    #[tokio::test]
    async fn reload_safety_missing_and_incomplete_snapshots_preserve_the_fleet() {
        let root = tempfile::tempdir().unwrap().keep();
        let pool = reload_safety_pool().await;
        let cases = [
            ("missing", None),
            ("empty", Some("")),
            (
                "comments",
                Some("# editor has not written the workers yet\n"),
            ),
            ("wrong-table", Some("[general]\nenabled = true\n")),
            ("malformed", Some("[[workers]\n")),
            ("incomplete-entry", Some("[[workers]]\nid = 'busy'\n")),
        ];
        for (name, contents) in cases {
            let path = root.join(name);
            if let Some(contents) = contents {
                std::fs::write(&path, contents).unwrap();
            }
            for validate in [false, true] {
                assert!(
                    reload_workers(&pool, Some(&path), validate).await.is_err(),
                    "accepted {name} with validation={validate}"
                );
                assert_eq!(pool.len(), 2);
                let busy = pool.get(&WorkerId::new("busy")).await.unwrap();
                let idle = pool.get(&WorkerId::new("idle")).await.unwrap();
                assert_eq!(busy.used_slots(), 1);
                assert!(busy.has_cached_project("retained-project").await);
                assert!(!busy.is_draining().await);
                assert!(!idle.is_draining().await);
            }
        }
        assert!(reload_workers(&pool, Some(&root), true).await.is_err());
        assert_eq!(pool.len(), 2);
    }

    #[tokio::test]
    async fn reload_safety_explicit_empty_snapshot_still_drains_without_losing_reservations() {
        let root = tempfile::tempdir().unwrap().keep();
        let path = root.join("workers.toml");
        std::fs::write(&path, "workers = []\n").unwrap();
        for validate in [false, true] {
            let pool = reload_safety_pool().await;
            let result = reload_workers(&pool, Some(&path), validate).await.unwrap();
            assert_eq!(result.removed, 1);
            assert_eq!(result.warnings.len(), 1);
            assert!(pool.get(&WorkerId::new("idle")).await.is_none());
            let busy = pool.get(&WorkerId::new("busy")).await.unwrap();
            assert!(busy.is_draining().await);
            assert_eq!(busy.used_slots(), 1);
        }
    }

    #[test]
    fn reload_safety_event_filter_uses_the_selected_path_and_rescan_flag() {
        use notify::EventKind;
        use notify::event::{AccessKind, CreateKind, Flag, ModifyKind, RemoveKind, RenameMode};

        let selected = PathBuf::from("/config/fleet-primary.toml");
        let sibling = PathBuf::from("/config/workers.toml");
        for kind in [
            EventKind::Any,
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Any),
            EventKind::Remove(RemoveKind::File),
        ] {
            assert!(event_requires_workers_reload(
                &Event::new(kind).add_path(selected.clone()),
                &selected
            ));
            assert!(!event_requires_workers_reload(
                &Event::new(kind).add_path(sibling.clone()),
                &selected
            ));
        }
        let rename = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(sibling)
            .add_path(selected.clone());
        assert!(event_requires_workers_reload(&rename, &selected));
        let read = Event::new(EventKind::Access(AccessKind::Any)).add_path(selected.clone());
        assert!(!event_requires_workers_reload(&read, &selected));
        let rescan = Event::new(EventKind::Other).set_flag(Flag::Rescan);
        assert!(event_requires_workers_reload(&rescan, &selected));
    }

    #[tokio::test]
    async fn reload_safety_notification_bursts_coalesce_without_blocking() {
        let (tx, mut rx) = mpsc::channel(1);
        let path = Path::new("/config/fleet-primary.toml");
        for _ in 0..10_000 {
            queue_workers_reload(&tx, path);
        }
        assert!(matches!(
            rx.try_recv(),
            Ok(ReloadMessage::ConfigChanged(received)) if received == path
        ));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        queue_workers_reload(&tx, path);
        assert!(
            rx.try_recv().is_ok(),
            "later changes must still be delivered"
        );
        drop(rx);
        queue_workers_reload(&tx, path);
    }

    #[tokio::test]
    async fn reload_safety_native_watcher_tracks_custom_file_replacements_and_recovers() {
        struct WatcherTask(tokio::task::JoinHandle<()>);
        impl Drop for WatcherTask {
            fn drop(&mut self) {
                self.0.abort();
            }
        }

        fn write_snapshot(path: &Path, slots: u32) {
            std::fs::write(
                path,
                format!("[[workers]]\nid = 'watched'\nhost = 'localhost'\ntotal_slots = {slots}\n"),
            )
            .unwrap();
        }

        async fn wait_for_slots(pool: &WorkerPool, slots: u32) {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(worker) = pool.get(&WorkerId::new("watched")).await
                        && worker.config.read().await.total_slots == slots
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("native watcher did not apply the selected snapshot");
        }

        let root = tempfile::tempdir().unwrap().keep();
        let selected = root.join("fleet-primary.toml");
        write_snapshot(&selected, 8);
        // No initial pool load: registration must reconcile an edit that could
        // have happened between daemon startup's read and installing the watch.
        let pool = WorkerPool::new();
        let (watcher, tx) = ConfigWatcher::new(
            ReloadConfig {
                workers_config_path: Some(selected.clone()),
                debounce_ms: 20,
                validate_before_apply: true,
            },
            pool.clone(),
        )
        .unwrap();
        let mut task = WatcherTask(watcher.start(tx.clone()).await.unwrap());
        wait_for_slots(&pool, 8).await;
        let busy = pool.get(&WorkerId::new("watched")).await.unwrap();
        assert!(busy.reserve_slots(1).await);

        // Watch the directory so replacing the inode does not lose the watch.
        let replacement = root.join("replacement.toml");
        write_snapshot(&replacement, 16);
        std::fs::rename(&replacement, &selected).unwrap();
        wait_for_slots(&pool, 16).await;
        assert_eq!(busy.used_slots(), 1);

        let retained = root.join("previous-snapshot.retained");
        std::fs::rename(&selected, &retained).unwrap();
        assert!(reload_workers(&pool, Some(&selected), true).await.is_err());
        assert!(!busy.is_draining().await);
        assert_eq!(busy.used_slots(), 1);
        write_snapshot(&selected, 32);
        wait_for_slots(&pool, 32).await;

        // This is an intentional empty snapshot, not a failed read.
        std::fs::write(&replacement, "workers = []\n").unwrap();
        std::fs::rename(&replacement, &selected).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !busy.is_draining().await {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("explicit empty snapshot must drain the busy worker");
        assert_eq!(busy.used_slots(), 1);
        tx.send(ReloadMessage::Shutdown).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), &mut task.0)
            .await
            .expect("watcher shutdown blocked")
            .unwrap();
    }

    #[tokio::test]
    async fn reload_retirement_invalidates_idle_selector_handles() {
        let pool = WorkerPool::new();
        let config = WorkerConfig::default();
        let id = config.id.clone();
        pool.add_worker(config.clone()).await;
        // A selector can keep this Arc after its pool snapshot has gone stale.
        let selected = pool.get(&id).await.unwrap();
        let diff = compute_worker_diff(&pool, &[]).await.unwrap();
        let result = apply_worker_diff(&pool, &diff).await.unwrap();
        assert_eq!(result.removed, 1);
        assert!(pool.get(&id).await.is_none());
        assert!(!selected.reserve_slots(1).await);
        assert_eq!(selected.used_slots(), 0);

        pool.add_worker(config).await;
        let replacement = pool.get(&id).await.unwrap();
        assert!(!std::sync::Arc::ptr_eq(&selected, &replacement));
        assert!(!selected.reserve_slots(1).await);
        assert!(replacement.reserve_slots(1).await);
        assert_eq!(replacement.used_slots(), 1);
        replacement.release_slots(1).await;
    }

    #[tokio::test]
    async fn reload_retirement_identical_reintroduction_cancels_pending_removal() {
        use rch_common::{CircuitState, WorkerStatus};

        for complete_before_restore in [false, true] {
            let root = tempfile::tempdir().unwrap().keep();
            let path = root.join("workers.toml");
            let snapshot = "[[workers]]\nid = 'restored'\nhost = 'localhost'\ntotal_slots = 8\n";
            std::fs::write(&path, snapshot).unwrap();
            let pool = WorkerPool::new();
            reload_workers(&pool, Some(&path), true).await.unwrap();
            let id = WorkerId::new("restored");
            let original = pool.get(&id).await.unwrap();
            assert!(original.reserve_slots(1).await);
            original
                .add_cached_project("retained-project".to_owned())
                .await;
            original.set_speed_score(73.0);
            original.apply_health_status(WorkerStatus::Degraded).await;
            original.open_circuit().await;

            std::fs::write(&path, "workers = []\n").unwrap();
            let removed = reload_workers(&pool, Some(&path), true).await.unwrap();
            assert_eq!(removed.removed, 0);
            assert!(original.is_draining().await);
            if complete_before_restore {
                original.release_slots(1).await;
                assert!(original.is_drained().await);
            }

            // Restore exactly the original bytes, not a changed slot count.
            std::fs::write(&path, snapshot).unwrap();
            let result = reload_workers(&pool, Some(&path), true).await.unwrap();
            assert_eq!(result.updated, 1);
            assert_eq!(result.added, 0);
            let restored = pool.get(&id).await.unwrap();
            assert!(std::sync::Arc::ptr_eq(&original, &restored));
            assert!(!restored.is_draining().await);
            assert!(!restored.is_drained().await);
            assert_eq!(restored.status().await, WorkerStatus::Degraded);
            assert_eq!(restored.circuit_state().await, Some(CircuitState::Open));
            assert_eq!(restored.get_speed_score(), 73.0);
            assert!(restored.has_cached_project("retained-project").await);
            assert_eq!(
                restored.used_slots(),
                if complete_before_restore { 0 } else { 1 }
            );
            if !complete_before_restore {
                restored.release_slots(1).await;
            }
            assert_eq!(pool.prune_drained().await, 0);
            assert!(pool.get(&id).await.is_some());
            let desired = restored.config.read().await.clone();
            assert!(
                compute_worker_diff(&pool, &[desired])
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn reload_retirement_reconciliation_preserves_operator_drains_and_disables() {
        use rch_common::{CircuitState, WorkerStatus};

        for intent in ["draining", "drained", "disabled", "disable-after-drain"] {
            let root = tempfile::tempdir().unwrap().keep();
            let path = root.join("workers.toml");
            let snapshot = "[[workers]]\nid = 'operator'\nhost = 'localhost'\ntotal_slots = 8\n";
            std::fs::write(&path, snapshot).unwrap();
            let pool = WorkerPool::new();
            reload_workers(&pool, Some(&path), true).await.unwrap();
            let id = WorkerId::new("operator");
            let worker = pool.get(&id).await.unwrap();
            assert!(worker.reserve_slots(1).await);
            worker.apply_health_status(WorkerStatus::Unreachable).await;
            worker.open_circuit().await;
            match intent {
                "disabled" => worker.disable(Some("maintenance".to_owned())).await,
                "disable-after-drain" => {
                    worker
                        .drain_then_disable(Some("maintenance".to_owned()))
                        .await;
                }
                _ => worker.drain().await,
            }
            if intent == "drained" {
                worker.release_slots(1).await;
            }
            let status = worker.status().await;
            let slots = worker.used_slots();
            reload_workers(&pool, Some(&path), true).await.unwrap();
            assert_eq!(worker.status().await, status, "{intent}");
            assert_eq!(worker.used_slots(), slots, "{intent}");
            assert_eq!(worker.circuit_state().await, Some(CircuitState::Open));
            assert!(!worker.reserve_slots(1).await, "{intent}");
            if slots != 0 {
                worker.release_slots(slots).await;
            }
            if matches!(intent, "disabled" | "disable-after-drain") {
                assert!(worker.is_disabled().await);
                assert_eq!(
                    worker.disabled_reason().await.as_deref(),
                    Some("maintenance")
                );
            } else {
                assert!(worker.is_drained().await);
            }
            assert_eq!(pool.prune_drained().await, 0);
            let retained = pool.get(&id).await.unwrap();
            assert!(std::sync::Arc::ptr_eq(&worker, &retained));
        }
    }
}
