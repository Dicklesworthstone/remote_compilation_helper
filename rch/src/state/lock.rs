//! Lock file management for preventing concurrent configuration modifications.
//!
//! This module provides a `ConfigLock` that uses file-based locking with
//! timeout support and stale lock detection.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
pub struct ConfigLock {
    #[allow(dead_code)]
    file: File,
    path: PathBuf,
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
                    // Write lock info for debugging
                    let info = LockInfo {
                        pid: std::process::id(),
                        hostname: hostname(),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        operation: operation.to_string(),
                    };

                    if let Err(e) = serde_json::to_writer(&mut file, &info) {
                        // Clean up lock file if we can't write info
                        let _ = fs::remove_file(&path);
                        return Err(anyhow!("Failed to write lock info: {}", e));
                    }

                    if let Err(e) = file.sync_all() {
                        let _ = fs::remove_file(&path);
                        return Err(anyhow!("Failed to sync lock file: {}", e));
                    }

                    tracing::debug!("Acquired lock: {:?}", path);
                    return Ok(ConfigLock { file, path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Lock exists, check if stale
                    if Self::is_stale_lock(&path)? {
                        tracing::warn!("Removing stale lock: {:?}", path);
                        if let Err(e) = fs::remove_file(&path) {
                            tracing::warn!("Failed to remove stale lock: {}", e);
                        }
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
        if path.exists() && Self::is_stale_lock(&path)? {
            tracing::warn!("Removing stale lock: {:?}", path);
            let _ = fs::remove_file(&path);
        }

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let info = LockInfo {
                    pid: std::process::id(),
                    hostname: hostname(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                    operation: operation.to_string(),
                };

                serde_json::to_writer(&mut file, &info)?;
                file.sync_all()?;

                tracing::debug!("Acquired lock: {:?}", path);
                Ok(Some(ConfigLock { file, path }))
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
    fn is_stale_lock(path: &Path) -> Result<bool> {
        let info = match Self::read_lock_info(path) {
            Ok(info) => info,
            Err(_) => {
                // If we can't read the lock info, assume it's stale
                return Ok(true);
            }
        };

        // Check if process is still alive (Linux only - uses /proc)
        #[cfg(target_os = "linux")]
        {
            let proc_path = format!("/proc/{}", info.pid);
            if !std::path::Path::new(&proc_path).exists() {
                // Process doesn't exist
                return Ok(true);
            }
        }

        // On non-Linux Unix systems, we rely solely on lock age
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            // Can't safely check process existence without unsafe code
            // Fall through to age-based staleness check
            let _ = &info; // suppress unused warning
        }

        // Check if lock is too old (> 1 hour)
        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&info.created_at) {
            let age = chrono::Utc::now().signed_duration_since(created);
            if age > chrono::Duration::hours(1) {
                return Ok(true);
            }
        }

        Ok(false)
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
                let info = LockInfo {
                    pid: std::process::id(),
                    hostname: hostname(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                    operation: operation.to_string(),
                };

                serde_json::to_writer(&mut file, &info)?;
                file.sync_all()?;
                Ok(ConfigLock { file, path })
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

        if path.exists() && Self::is_stale_lock(&path)? {
            let _ = fs::remove_file(&path);
        }

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let info = LockInfo {
                    pid: std::process::id(),
                    hostname: hostname(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                    operation: operation.to_string(),
                };

                serde_json::to_writer(&mut file, &info)?;
                file.sync_all()?;
                Ok(Some(ConfigLock { file, path }))
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
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        // Remove lock file
        if let Err(e) = fs::remove_file(&self.path) {
            tracing::warn!("Failed to remove lock file {:?}: {}", self.path, e);
        } else {
            tracing::debug!("Released lock: {:?}", self.path);
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

    #[test]
    fn test_lock_acquisition_and_release() {
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        let lock = ConfigLock::acquire_in_dir(&lock_dir, "test_lock", "testing").unwrap();
        drop(lock);
        // Should be able to acquire again after release
        let _lock2 = ConfigLock::acquire_in_dir(&lock_dir, "test_lock", "testing").unwrap();
    }

    #[test]
    fn test_try_acquire_success() {
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        let lock = ConfigLock::try_acquire_in_dir(&lock_dir, "try_test", "testing").unwrap();
        assert!(lock.is_some());
    }

    #[test]
    fn test_try_acquire_contended() {
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        let _lock1 = ConfigLock::try_acquire_in_dir(&lock_dir, "contended", "first")
            .unwrap()
            .unwrap();

        // Second attempt should return None
        let lock2 = ConfigLock::try_acquire_in_dir(&lock_dir, "contended", "second").unwrap();
        assert!(lock2.is_none());
    }

    #[test]
    fn test_lock_holder() {
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        let _lock =
            ConfigLock::acquire_in_dir(&lock_dir, "holder_test", "test operation").unwrap();

        let holder = ConfigLock::lock_holder_in_dir(&lock_dir, "holder_test").unwrap();
        assert!(holder.is_some());
        let info = holder.unwrap();
        assert_eq!(info.pid, std::process::id());
        assert_eq!(info.operation, "test operation");
    }

    #[test]
    fn test_no_lock_holder_when_unlocked() {
        let tmp = TempDir::new().unwrap();
        let lock_dir = tmp.path().join("locks");
        fs::create_dir_all(&lock_dir).unwrap();

        let holder = ConfigLock::lock_holder_in_dir(&lock_dir, "nonexistent").unwrap();
        assert!(holder.is_none());
    }

    #[test]
    fn test_lock_info_serialization() {
        let info = LockInfo {
            pid: 12345,
            hostname: "testhost".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            operation: "test".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        let parsed: LockInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.pid, 12345);
        assert_eq!(parsed.hostname, "testhost");
        assert_eq!(parsed.operation, "test");
    }
}
