//! Lock file management for preventing concurrent configuration modifications.
//!
//! This module provides a `ConfigLock` that uses file-based locking with
//! timeout support and stale lock detection.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static LOCK_OWNER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Lock file contents for debugging stale locks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    /// Process ID of the lock holder.
    pub pid: u32,
    /// Hostname where the lock was acquired.
    pub hostname: String,
    /// ISO 8601 timestamp when lock was acquired.
    pub created_at: String,
    /// Description of the operation being performed.
    pub operation: String,
    /// Acquisition-unique owner id used to avoid removing another process's lock.
    #[serde(default)]
    pub owner_id: String,
}

/// A file-based configuration lock.
///
/// This lock provides mutual exclusion for configuration operations.
/// It uses a file-based approach that works across processes and
/// includes timeout support and stale lock detection.
///
/// The lock is automatically released when dropped.
///
/// # Example
///
/// ```no_run
/// use rch::state::lock::ConfigLock;
/// use std::time::Duration;
///
/// // Acquire lock with default timeout
/// let lock = ConfigLock::acquire("config")?;
///
/// // Or with custom timeout
/// let lock = ConfigLock::acquire_with_timeout(
///     "workers",
///     Duration::from_secs(10),
///     "updating worker config"
/// )?;
///
/// // Lock is released when `lock` goes out of scope
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Debug)]
pub struct ConfigLock {
    #[allow(dead_code)]
    file: File,
    path: PathBuf,
    body: String,
}

impl ConfigLock {
    /// Acquire a lock with the default timeout (30 seconds).
    ///
    /// # Arguments
    ///
    /// * `lock_name` - Name for the lock file (e.g., "config", "workers")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The lock cannot be acquired within the timeout
    /// - The lock directory cannot be created
    pub fn acquire(lock_name: &str) -> Result<Self> {
        Self::acquire_with_timeout(lock_name, Duration::from_secs(30), "unknown")
    }

    /// Acquire a lock with a custom timeout and operation description.
    ///
    /// # Arguments
    ///
    /// * `lock_name` - Name for the lock file
    /// * `timeout` - Maximum time to wait for lock acquisition
    /// * `operation` - Description of the operation (for debugging stale locks)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The lock cannot be acquired within the timeout
    /// - The lock directory cannot be created
    pub fn acquire_with_timeout(
        lock_name: &str,
        timeout: Duration,
        operation: &str,
    ) -> Result<Self> {
        let lock_dir = Self::lock_directory()?;

        fs::create_dir_all(&lock_dir)
            .with_context(|| format!("Failed to create lock directory: {:?}", lock_dir))?;

        let path = lock_dir.join(format!("{}.lock", lock_name));

        let start = Instant::now();
        let poll_interval = Duration::from_millis(100);

        loop {
            // Try to create lock file exclusively
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    let body = new_lock_body(operation)?;
                    write_lock_body(&mut file, &path, &body)?;
                    tracing::debug!("Acquired lock: {:?}", path);
                    return Ok(ConfigLock { file, path, body });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Lock exists, check if stale
                    if Self::try_remove_stale_lock(&path)? {
                        tracing::warn!("Removing stale lock: {:?}", path);
                        continue;
                    }

                    // Check timeout
                    if start.elapsed() >= timeout {
                        let holder = Self::read_lock_info(&path).ok();
                        return Err(anyhow!(
                            "Lock acquisition timeout after {:?}. Lock held by: {:?}",
                            timeout,
                            holder
                        ));
                    }

                    std::thread::sleep(poll_interval);
                }
                Err(e) => {
                    return Err(anyhow!("Failed to create lock file: {}", e));
                }
            }
        }
    }

    /// Try to acquire a lock without blocking.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(lock))` - Lock was acquired
    /// * `Ok(None)` - Lock is held by another process
    /// * `Err(e)` - An error occurred
    pub fn try_acquire(lock_name: &str, operation: &str) -> Result<Option<Self>> {
        let lock_dir = Self::lock_directory()?;

        fs::create_dir_all(&lock_dir)
            .with_context(|| format!("Failed to create lock directory: {:?}", lock_dir))?;

        let path = lock_dir.join(format!("{}.lock", lock_name));

        // Check for stale lock first
        if path.exists() && Self::try_remove_stale_lock(&path)? {
            tracing::warn!("Removing stale lock: {:?}", path);
        }

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let body = new_lock_body(operation)?;
                write_lock_body(&mut file, &path, &body)?;

                tracing::debug!("Acquired lock: {:?}", path);
                Ok(Some(ConfigLock { file, path, body }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(anyhow!("Failed to create lock file: {}", e)),
        }
    }

    /// Get the path to the lock directory.
    fn lock_directory() -> Result<PathBuf> {
        // Try runtime directory first (usually /run/user/<uid>/)
        // Fall back to data directory (~/.local/share/)
        dirs::runtime_dir()
            .or_else(dirs::data_dir)
            .map(|p| p.join("rch/locks"))
            .ok_or_else(|| anyhow!("Cannot determine lock directory"))
    }

    /// Check if a lock is stale (holder process dead or lock too old).
    #[cfg(test)]
    fn is_stale_lock(path: &Path) -> Result<bool> {
        Ok(Self::stale_lock_body(path)?.is_some())
    }

    /// Remove a stale lock only if the file still contains the stale body read
    /// by this process.
    fn try_remove_stale_lock(path: &Path) -> Result<bool> {
        let Some(body) = Self::stale_lock_body(path)? else {
            return Ok(false);
        };

        remove_lock_if_unchanged(path, &body)
            .with_context(|| format!("Failed to remove stale lock: {:?}", path))
    }

    fn stale_lock_body(path: &Path) -> Result<Option<String>> {
        let body = match fs::read_to_string(path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("Failed to read lock file: {path:?}")),
        };

        let stale = match serde_json::from_str::<LockInfo>(&body) {
            Ok(info) => lock_info_is_stale(&info),
            Err(_) => lock_file_is_too_old(path),
        };

        if stale { Ok(Some(body)) } else { Ok(None) }
    }

    /// Read lock info from a lock file.
    fn read_lock_info(path: &Path) -> Result<LockInfo> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read lock file: {:?}", path))?;
        serde_json::from_str(&content).with_context(|| "Failed to parse lock info")
    }

    /// Get information about who holds a lock.
    pub fn lock_holder(lock_name: &str) -> Result<Option<LockInfo>> {
        let lock_dir = Self::lock_directory()?;
        let path = lock_dir.join(format!("{}.lock", lock_name));

        if !path.exists() {
            return Ok(None);
        }

        Self::read_lock_info(&path).map(Some)
    }

    /// Acquire a lock in a specific directory (for testing).
    #[cfg(test)]
    fn acquire_in_dir(lock_dir: &Path, lock_name: &str, operation: &str) -> Result<Self> {
        fs::create_dir_all(lock_dir)
            .with_context(|| format!("Failed to create lock directory: {:?}", lock_dir))?;

        let path = lock_dir.join(format!("{}.lock", lock_name));

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let body = new_lock_body(operation)?;
                write_lock_body(&mut file, &path, &body)?;
                Ok(ConfigLock { file, path, body })
            }
            Err(e) => Err(anyhow!("Failed to create lock file: {}", e)),
        }
    }

    /// Try to acquire a lock in a specific directory (for testing).
    #[cfg(test)]
    fn try_acquire_in_dir(
        lock_dir: &Path,
        lock_name: &str,
        operation: &str,
    ) -> Result<Option<Self>> {
        fs::create_dir_all(lock_dir)
            .with_context(|| format!("Failed to create lock directory: {:?}", lock_dir))?;

        let path = lock_dir.join(format!("{}.lock", lock_name));

        if path.exists() {
            let _ = Self::try_remove_stale_lock(&path)?;
        }

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let body = new_lock_body(operation)?;
                write_lock_body(&mut file, &path, &body)?;
                Ok(Some(ConfigLock { file, path, body }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(anyhow!("Failed to create lock file: {}", e)),
        }
    }

    /// Get lock holder info from a specific directory (for testing).
    #[cfg(test)]
    fn lock_holder_in_dir(lock_dir: &Path, lock_name: &str) -> Result<Option<LockInfo>> {
        let path = lock_dir.join(format!("{}.lock", lock_name));

        if !path.exists() {
            return Ok(None);
        }

        Self::read_lock_info(&path).map(Some)
    }

    /// Acquire a lock in a specific directory with timeout (for testing).
    #[cfg(test)]
    fn acquire_in_dir_with_timeout(
        lock_dir: &Path,
        lock_name: &str,
        timeout: Duration,
        operation: &str,
    ) -> Result<Self> {
        fs::create_dir_all(lock_dir)
            .with_context(|| format!("Failed to create lock directory: {:?}", lock_dir))?;

        let path = lock_dir.join(format!("{}.lock", lock_name));
        let start = Instant::now();
        let poll_interval = Duration::from_millis(10); // Faster polling for tests

        loop {
            if path.exists() {
                let _ = Self::try_remove_stale_lock(&path)?;
            }

            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    let body = new_lock_body(operation)?;
                    write_lock_body(&mut file, &path, &body)?;
                    return Ok(ConfigLock { file, path, body });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if start.elapsed() >= timeout {
                        let holder = Self::read_lock_info(&path).ok();
                        return Err(anyhow!(
                            "Lock acquisition timeout after {:?}. Lock held by: {:?}",
                            timeout,
                            holder
                        ));
                    }
                    std::thread::sleep(poll_interval);
                }
                Err(e) => {
                    return Err(anyhow!("Failed to create lock file: {}", e));
                }
            }
        }
    }
}

fn new_lock_body(operation: &str) -> Result<String> {
    let info = LockInfo {
        pid: std::process::id(),
        hostname: hostname(),
        created_at: chrono::Utc::now().to_rfc3339(),
        operation: operation.to_string(),
        owner_id: new_lock_owner_id(),
    };
    serde_json::to_string(&info).context("Failed to serialize lock info")
}

fn new_lock_owner_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let sequence = LOCK_OWNER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", now.as_nanos(), sequence)
}

fn write_lock_body(file: &mut File, path: &Path, body: &str) -> Result<()> {
    if let Err(e) = std::io::Write::write_all(file, body.as_bytes()) {
        let _ = remove_lock_file_if_same_handle(file, path);
        return Err(anyhow!("Failed to write lock info: {}", e));
    }

    if let Err(e) = file.sync_all() {
        let _ = remove_lock_if_unchanged(path, body);
        return Err(anyhow!("Failed to sync lock file: {}", e));
    }

    Ok(())
}

fn remove_lock_file_if_same_handle(file: &File, path: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let file_metadata = file.metadata()?;
        let path_metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };

        if file_metadata.dev() == path_metadata.dev() && file_metadata.ino() == path_metadata.ino()
        {
            fs::remove_file(path)?;
            return Ok(true);
        }

        Ok(false)
    }

    #[cfg(not(unix))]
    {
        let _ = file;
        let _ = path;
        Ok(false)
    }
}

fn remove_lock_if_unchanged(path: &Path, expected_body: &str) -> std::io::Result<bool> {
    match fs::read_to_string(path) {
        Ok(current) if current == expected_body => {
            fs::remove_file(path)?;
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn lock_info_is_stale(info: &LockInfo) -> bool {
    // Check if process is still alive (Linux only - uses /proc)
    #[cfg(target_os = "linux")]
    {
        let proc_path = format!("/proc/{}", info.pid);
        if !std::path::Path::new(&proc_path).exists() {
            // Process doesn't exist
            return true;
        }
    }

    // On non-Linux Unix systems, we rely solely on lock age
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        // Can't safely check process existence without unsafe code.
        let _ = &info;
    }

    lock_timestamp_is_too_old(&info.created_at)
}

fn lock_timestamp_is_too_old(created_at: &str) -> bool {
    if let Ok(created) = chrono::DateTime::parse_from_rfc3339(created_at) {
        let age = chrono::Utc::now().signed_duration_since(created);
        return age > chrono::Duration::hours(1);
    }
    false
}

fn lock_file_is_too_old(path: &Path) -> bool {
    if let Ok(metadata) = fs::metadata(path)
        && let Ok(modified) = metadata.modified()
        && let Ok(age) = modified.elapsed()
    {
        return age > Duration::from_secs(60 * 60);
    }
    false
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        match remove_lock_if_unchanged(&self.path, &self.body) {
            Ok(true) => tracing::debug!("Released lock: {:?}", self.path),
            Ok(false) => {}
            Err(e) => tracing::warn!("Failed to remove lock file {:?}: {}", self.path, e),
        }
    }
}

/// Get the hostname, with fallback.
fn hostname() -> String {
    #[cfg(unix)]
    {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tracing::info;

    fn log_test_start(name: &str) {
        info!("TEST START: {}", name);
    }

    fn log_test_pass(name: &str) {
        info!("TEST PASS: {}", name);
    }

    #[test]
    fn test_lock_acquisition_and_release() {
        log_test_start("test_lock_acquisition_and_release");
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        let lock = ConfigLock::acquire_in_dir(&lock_dir, "test_lock", "testing").unwrap();
        drop(lock);
        // Should be able to acquire again after release
        let _lock2 = ConfigLock::acquire_in_dir(&lock_dir, "test_lock", "testing").unwrap();
        log_test_pass("test_lock_acquisition_and_release");
    }

    #[test]
    fn test_try_acquire_success() {
        log_test_start("test_try_acquire_success");
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        let lock = ConfigLock::try_acquire_in_dir(&lock_dir, "try_test", "testing").unwrap();
        assert!(lock.is_some());
        log_test_pass("test_try_acquire_success");
    }

    #[test]
    fn test_try_acquire_contended() {
        log_test_start("test_try_acquire_contended");
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        let _lock1 = ConfigLock::try_acquire_in_dir(&lock_dir, "contended", "first")
            .unwrap()
            .unwrap();

        // Second attempt should return None
        let lock2 = ConfigLock::try_acquire_in_dir(&lock_dir, "contended", "second").unwrap();
        assert!(lock2.is_none());
        log_test_pass("test_try_acquire_contended");
    }

    #[test]
    fn test_lock_holder() {
        log_test_start("test_lock_holder");
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        let _lock = ConfigLock::acquire_in_dir(&lock_dir, "holder_test", "test operation").unwrap();

        let holder = ConfigLock::lock_holder_in_dir(&lock_dir, "holder_test").unwrap();
        assert!(holder.is_some());
        let info = holder.unwrap();
        assert_eq!(info.pid, std::process::id());
        assert_eq!(info.operation, "test operation");
        assert!(!info.owner_id.is_empty());
        log_test_pass("test_lock_holder");
    }

    #[test]
    fn test_lock_drop_preserves_replaced_lock_body() -> Result<()> {
        log_test_start("test_lock_drop_preserves_replaced_lock_body");
        let tmp = TempDir::new()?;
        let lock_dir = tmp.path().join("locks");
        let lock = ConfigLock::acquire_in_dir(&lock_dir, "replace_test", "holder")?;
        let path = lock.path.clone();
        let replacement = new_lock_body("replacement")?;
        fs::write(&path, &replacement)?;

        drop(lock);

        assert_eq!(fs::read_to_string(&path)?, replacement);
        log_test_pass("test_lock_drop_preserves_replaced_lock_body");
        Ok(())
    }

    #[test]
    fn test_stale_cleanup_preserves_replaced_lock_body() -> Result<()> {
        log_test_start("test_stale_cleanup_preserves_replaced_lock_body");
        let tmp = TempDir::new()?;
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir)?;
        let path = lock_dir.join("stale_replace.lock");

        let stale_info = LockInfo {
            pid: 9_999_999,
            hostname: "testhost".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            operation: "stale".to_string(),
            owner_id: "stale-owner".to_string(),
        };
        fs::write(&path, serde_json::to_string(&stale_info)?)?;
        let stale_body =
            ConfigLock::stale_lock_body(&path)?.ok_or_else(|| anyhow!("expected stale body"))?;
        let replacement = new_lock_body("replacement")?;
        fs::write(&path, &replacement)?;

        let removed = remove_lock_if_unchanged(&path, &stale_body)?;

        assert!(!removed);
        assert_eq!(fs::read_to_string(&path)?, replacement);
        log_test_pass("test_stale_cleanup_preserves_replaced_lock_body");
        Ok(())
    }

    #[test]
    fn test_write_failure_cleanup_preserves_replaced_path() -> Result<()> {
        log_test_start("test_write_failure_cleanup_preserves_replaced_path");
        let tmp = TempDir::new()?;
        let path = tmp.path().join("write-cleanup.lock");
        let replacement_path = tmp.path().join("replacement.lock");

        let file = File::create(&path)?;
        fs::write(&replacement_path, "replacement")?;
        fs::rename(&replacement_path, &path)?;

        let removed = remove_lock_file_if_same_handle(&file, &path)?;

        assert!(!removed);
        assert_eq!(fs::read_to_string(&path)?, "replacement");
        log_test_pass("test_write_failure_cleanup_preserves_replaced_path");
        Ok(())
    }

    #[test]
    fn test_new_lock_body_uses_unique_owner_ids() -> Result<()> {
        let body1 = new_lock_body("same-operation")?;
        let body2 = new_lock_body("same-operation")?;
        let info1: LockInfo = serde_json::from_str(&body1)?;
        let info2: LockInfo = serde_json::from_str(&body2)?;

        assert_ne!(body1, body2);
        assert_ne!(info1.owner_id, info2.owner_id);
        Ok(())
    }

    #[test]
    fn test_no_lock_holder_when_unlocked() {
        log_test_start("test_no_lock_holder_when_unlocked");
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir).unwrap();

        let holder = ConfigLock::lock_holder_in_dir(&lock_dir, "nonexistent").unwrap();
        assert!(holder.is_none());
        log_test_pass("test_no_lock_holder_when_unlocked");
    }

    #[test]
    fn test_lock_info_serialization() {
        log_test_start("test_lock_info_serialization");
        let info = LockInfo {
            pid: 12345,
            hostname: "testhost".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            operation: "test".to_string(),
            owner_id: "owner".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        let parsed: LockInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.pid, 12345);
        assert_eq!(parsed.hostname, "testhost");
        assert_eq!(parsed.operation, "test");
        assert_eq!(parsed.owner_id, "owner");
        log_test_pass("test_lock_info_serialization");
    }

    #[test]
    fn test_lock_info_deserializes_legacy_without_owner_id() -> Result<()> {
        let parsed: LockInfo = serde_json::from_str(
            r#"{"pid":12345,"hostname":"testhost","created_at":"2025-01-01T00:00:00Z","operation":"test"}"#,
        )?;

        assert_eq!(parsed.pid, 12345);
        assert_eq!(parsed.owner_id, "");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_stale_lock_detects_missing_process() {
        use std::fs::File;

        log_test_start("test_is_stale_lock_detects_missing_process");
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir).unwrap();
        let path = lock_dir.join("stale_proc.lock");

        let info = LockInfo {
            pid: 9_999_999,
            hostname: "testhost".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            operation: "stale-proc".to_string(),
            owner_id: "stale-proc".to_string(),
        };

        let mut file = File::create(&path).unwrap();
        serde_json::to_writer(&mut file, &info).unwrap();
        file.sync_all().unwrap();

        let stale = ConfigLock::is_stale_lock(&path).unwrap();
        assert!(stale, "Missing process should mark lock as stale");
        log_test_pass("test_is_stale_lock_detects_missing_process");
    }

    #[test]
    fn test_is_stale_lock_detects_old_timestamp() {
        use std::fs::File;

        log_test_start("test_is_stale_lock_detects_old_timestamp");
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir).unwrap();
        let path = lock_dir.join("stale_age.lock");

        let old_time = chrono::Utc::now() - chrono::Duration::hours(2);
        let info = LockInfo {
            pid: std::process::id(),
            hostname: "testhost".to_string(),
            created_at: old_time.to_rfc3339(),
            operation: "stale-age".to_string(),
            owner_id: "stale-age".to_string(),
        };

        let mut file = File::create(&path).unwrap();
        serde_json::to_writer(&mut file, &info).unwrap();
        file.sync_all().unwrap();

        let stale = ConfigLock::is_stale_lock(&path).unwrap();
        assert!(stale, "Old timestamp should mark lock as stale");
        log_test_pass("test_is_stale_lock_detects_old_timestamp");
    }

    /// Helper that uses create_new without stale lock check (avoids race in is_stale_lock)
    fn try_acquire_in_dir_raw(
        lock_dir: &Path,
        lock_name: &str,
        operation: &str,
    ) -> Result<Option<ConfigLock>> {
        fs::create_dir_all(lock_dir)?;
        let path = lock_dir.join(format!("{}.lock", lock_name));

        // Pure atomic create without stale lock check
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let body = new_lock_body(operation)?;
                write_lock_body(&mut file, &path, &body)?;
                Ok(Some(ConfigLock { file, path, body }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(anyhow!("Failed to create lock file: {}", e)),
        }
    }

    #[test]
    fn test_concurrent_contention_real_threads() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;

        log_test_start("test_concurrent_contention_real_threads");

        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir).unwrap();

        let lock_dir = Arc::new(lock_dir);
        let acquired_count = Arc::new(AtomicUsize::new(0));
        let failed_count = Arc::new(AtomicUsize::new(0));

        let num_threads = 8;
        // Barrier to start all threads at the same time
        let start_barrier = Arc::new(Barrier::new(num_threads));
        // Barrier to keep lock held until all threads complete their attempt
        let done_barrier = Arc::new(Barrier::new(num_threads));
        let mut handles = vec![];

        for i in 0..num_threads {
            let lock_dir = Arc::clone(&lock_dir);
            let acquired = Arc::clone(&acquired_count);
            let failed = Arc::clone(&failed_count);
            let start = Arc::clone(&start_barrier);
            let done = Arc::clone(&done_barrier);

            handles.push(thread::spawn(move || -> Result<()> {
                // Wait for all threads to be ready
                start.wait();

                // Use raw helper to avoid stale lock detection race
                match try_acquire_in_dir_raw(&lock_dir, "race_lock", &format!("thread-{}", i)) {
                    Ok(Some(lock)) => {
                        acquired.fetch_add(1, Ordering::SeqCst);
                        // Wait for all threads to complete their attempt before releasing
                        done.wait();
                        drop(lock);
                    }
                    Ok(None) => {
                        failed.fetch_add(1, Ordering::SeqCst);
                        done.wait();
                    }
                    Err(e) => {
                        done.wait();
                        return Err(anyhow!("Unexpected error in thread {}: {}", i, e));
                    }
                }

                Ok(())
            }));
        }

        // Wait for all threads to finish
        for handle in handles {
            handle.join().map_err(|_| anyhow!("Thread panicked"))??;
        }

        let total_acquired = acquired_count.load(Ordering::SeqCst);
        let total_failed = failed_count.load(Ordering::SeqCst);

        info!(
            "TEST PASS: test_concurrent_contention_real_threads - acquired={}, failed={}",
            total_acquired, total_failed
        );

        // Exactly one thread should have acquired the lock
        assert_eq!(
            total_acquired, 1,
            "Exactly one thread should acquire the lock"
        );
        assert_eq!(
            total_failed,
            num_threads - 1,
            "Other threads should fail to acquire"
        );
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn test_concurrent_sequential_acquisition() -> Result<()> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        log_test_start("test_concurrent_sequential_acquisition");

        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir).unwrap();

        let lock_dir = Arc::new(lock_dir);
        let successful_acquisitions = Arc::new(AtomicUsize::new(0));

        let num_threads = 4;
        let mut handles = vec![];

        for i in 0..num_threads {
            let lock_dir = Arc::clone(&lock_dir);
            let success_count = Arc::clone(&successful_acquisitions);

            handles.push(thread::spawn(move || -> Result<()> {
                // Each thread tries to acquire with timeout
                match ConfigLock::acquire_in_dir_with_timeout(
                    &lock_dir,
                    "sequential_lock",
                    Duration::from_secs(30),
                    &format!("thread-{}", i),
                ) {
                    Ok(_lock) => {
                        success_count.fetch_add(1, Ordering::SeqCst);
                        // Hold the lock briefly
                        thread::sleep(Duration::from_millis(50));
                        // Lock released on drop, allowing next thread to acquire
                    }
                    Err(e) => {
                        return Err(anyhow!("Thread {} failed to acquire lock: {}", i, e));
                    }
                }

                Ok(())
            }));
        }

        for handle in handles {
            handle.join().map_err(|_| anyhow!("Thread panicked"))??;
        }

        let total = successful_acquisitions.load(Ordering::SeqCst);
        info!(
            "TEST PASS: test_concurrent_sequential_acquisition - all {} threads acquired lock sequentially",
            total
        );

        // All threads should eventually acquire the lock
        assert_eq!(
            total, num_threads,
            "All threads should eventually acquire the lock"
        );
        Ok(())
    }

    #[test]
    fn test_timeout_on_held_lock() {
        log_test_start("test_timeout_on_held_lock");

        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");

        // Acquire a lock and hold it
        let _lock = ConfigLock::acquire_in_dir(&lock_dir, "held_lock", "holding").unwrap();

        // Try to acquire with very short timeout - should fail
        let start = std::time::Instant::now();
        let result = ConfigLock::acquire_in_dir_with_timeout(
            &lock_dir,
            "held_lock",
            Duration::from_millis(100),
            "waiting",
        );

        let elapsed = start.elapsed();

        assert!(result.is_err(), "Should timeout when lock is held");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("timeout"),
            "Error should mention timeout: {}",
            err_msg
        );

        // Verify timeout was respected (with some tolerance)
        assert!(
            elapsed >= Duration::from_millis(90),
            "Should have waited at least ~100ms, got {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "Should not wait much longer than timeout, got {:?}",
            elapsed
        );

        info!(
            "TEST PASS: test_timeout_on_held_lock - timed out correctly in {:?}",
            elapsed
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_lock_released_during_wait() {
        use std::sync::mpsc;
        use std::thread;

        log_test_start("test_lock_released_during_wait");

        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir).unwrap();

        let lock_dir_clone = lock_dir.clone();
        let (ready_tx, ready_rx) = mpsc::channel();

        // Thread 1: Acquire lock, hold briefly, then release
        let holder = thread::spawn(move || {
            let lock = ConfigLock::acquire_in_dir(&lock_dir_clone, "release_test", "holder")
                .expect("holder should acquire lock");
            ready_tx.send(()).expect("signal holder ready");
            thread::sleep(Duration::from_millis(100));
            drop(lock);
        });

        // Ensure the lock is held before we start waiting (avoid racy sleeps).
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("holder did not acquire lock in time");

        // Thread 2 (main): Try to acquire with timeout longer than hold time
        let start = std::time::Instant::now();
        let result = ConfigLock::acquire_in_dir_with_timeout(
            &lock_dir,
            "release_test",
            Duration::from_secs(10),
            "waiter",
        );

        let elapsed = start.elapsed();
        holder.join().expect("Holder thread panicked");

        assert!(result.is_ok(), "Should acquire lock after holder releases");

        // Should have acquired within reasonable time (not full timeout)
        assert!(
            elapsed < Duration::from_secs(10),
            "Should acquire soon after release, got {:?}",
            elapsed
        );

        info!(
            "TEST PASS: test_lock_released_during_wait - acquired after {:?}",
            elapsed
        );
    }

    #[test]
    fn test_backoff_polling_interval() {
        log_test_start("test_backoff_polling_interval");

        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");

        // Hold a lock
        let _lock = ConfigLock::acquire_in_dir(&lock_dir, "backoff_test", "holder").unwrap();

        // Try to acquire with short timeout
        let start = std::time::Instant::now();
        let _ = ConfigLock::acquire_in_dir_with_timeout(
            &lock_dir,
            "backoff_test",
            Duration::from_millis(50),
            "waiter",
        );
        let elapsed = start.elapsed();

        // With 10ms polling interval and 50ms timeout, we should have ~5 retries
        // The elapsed time should be roughly 50ms (not much more due to busy waiting)
        assert!(
            elapsed >= Duration::from_millis(45),
            "Should wait at least close to timeout, got {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(150),
            "Should not wait excessively, got {:?}",
            elapsed
        );

        info!(
            "TEST PASS: test_backoff_polling_interval - waited {:?} for 50ms timeout",
            elapsed
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_lock_prevents_deadlock_with_timeout() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::thread;

        log_test_start("test_lock_prevents_deadlock_with_timeout");

        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir).unwrap();

        let lock_dir = Arc::new(lock_dir);
        let deadlock_avoided = Arc::new(AtomicBool::new(false));

        let lock_dir_clone = Arc::clone(&lock_dir);
        let deadlock_flag = Arc::clone(&deadlock_avoided);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        // Thread holds lock forever (simulating a hung process scenario)
        let holder = thread::spawn(move || {
            let _lock = ConfigLock::acquire_in_dir(&lock_dir_clone, "deadlock_test", "forever")
                .expect("holder should acquire lock");
            ready_tx.send(()).expect("signal holder ready");
            // Hold lock until the waiter has proved it times out.
            release_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("waiter did not release holder in time");
        });

        // Ensure the lock is held before we start waiting (avoid racy sleeps).
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("holder did not acquire lock in time");

        // Waiter should timeout rather than deadlock
        let start = std::time::Instant::now();
        let result = ConfigLock::acquire_in_dir_with_timeout(
            &lock_dir,
            "deadlock_test",
            Duration::from_secs(2),
            "waiter",
        );

        if result.is_err() {
            deadlock_avoided.store(true, Ordering::SeqCst);
        }

        let elapsed = start.elapsed();

        release_tx.send(()).expect("release holder");
        holder.join().expect("holder thread panicked");

        assert!(
            deadlock_flag.load(Ordering::SeqCst),
            "Should timeout instead of deadlocking"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "Should return within timeout period, got {:?}",
            elapsed
        );

        info!(
            "TEST PASS: test_lock_prevents_deadlock_with_timeout - avoided deadlock in {:?}",
            elapsed
        );
    }
}
