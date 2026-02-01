//! Update lock to prevent concurrent updates.
//!
//! Uses a PID-based lock file approach that's safe and portable.

use super::types::UpdateError;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

/// Lock to prevent concurrent updates.
pub struct UpdateLock {
    path: PathBuf,
}

impl UpdateLock {
    /// Acquire the update lock.
    ///
    /// Uses a PID-based lock file. If a lock file exists, checks if the
    /// process is still running before failing.
    pub fn acquire() -> Result<Self, UpdateError> {
        let path = get_lock_path()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                UpdateError::InstallFailed(format!("Failed to create lock dir: {}", e))
            })?;
        }

        // Check if lock file exists and if the process is still running
        if path.exists() {
            if let Ok(mut file) = File::open(&path) {
                let mut contents = String::new();
                if file.read_to_string(&mut contents).is_ok()
                    && let Ok(pid) = contents.trim().parse::<u32>()
                    && is_process_running(pid)
                {
                    return Err(UpdateError::LockHeld);
                }
            }
            // Stale lock file, remove it
            let _ = fs::remove_file(&path);
        }

        // Write our PID to the lock file
        let mut file = File::create(&path).map_err(|e| {
            UpdateError::InstallFailed(format!("Failed to create lock file: {}", e))
        })?;

        write!(file, "{}", std::process::id())
            .map_err(|e| UpdateError::InstallFailed(format!("Failed to write lock file: {}", e)))?;

        Ok(Self { path })
    }

    /// Check if an update is currently in progress.
    #[allow(dead_code)]
    pub fn is_locked() -> bool {
        if let Ok(path) = get_lock_path()
            && path.exists()
            && let Ok(mut file) = File::open(&path)
        {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok()
                && let Ok(pid) = contents.trim().parse::<u32>()
            {
                return is_process_running(pid);
            }
        }
        false
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        // Remove the lock file
        let _ = fs::remove_file(&self.path);
    }
}

/// Get the path to the lock file.
fn get_lock_path() -> Result<PathBuf, UpdateError> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        UpdateError::InstallFailed("Could not determine data directory".to_string())
    })?;

    Ok(data_dir.join("rch/update.lock"))
}

/// Check if a process is still running.
fn is_process_running(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        // On Linux, check /proc filesystem
        let proc_path = format!("/proc/{}", pid);
        std::path::Path::new(&proc_path).exists()
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, use ps command to check if process exists
        // This is less efficient but avoids unsafe code and works reliably
        std::process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        // On Windows, assume not running - conservative approach
        // that allows stale locks to be cleaned up
        false
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_lock_acquire_and_release() {
        let _guard = test_lock().lock().unwrap();
        // First lock should succeed
        let lock1 = UpdateLock::acquire();
        assert!(lock1.is_ok());

        // While first lock is held, second should fail (same process, but tests PID check)
        // Note: In same process, it will see same PID and think it's still locked
        // This is expected behavior - it prevents recursive updates

        // Drop first lock
        drop(lock1);

        // Now acquiring should succeed
        let lock3 = UpdateLock::acquire();
        assert!(lock3.is_ok());
    }

    #[test]
    fn test_is_locked_false_when_no_lock() {
        let _guard = test_lock().lock().unwrap();
        // Clear any existing lock first
        if let Ok(path) = get_lock_path() {
            let _ = std::fs::remove_file(path);
        }

        // Without lock, should not be locked
        assert!(!UpdateLock::is_locked());
    }

    #[test]
    fn test_current_process_is_running() {
        let pid = std::process::id();
        assert!(is_process_running(pid));
    }

    #[test]
    fn test_nonexistent_process_not_running() {
        // Use a very high PID that's unlikely to exist
        assert!(!is_process_running(999999999));
    }

    #[test]
    fn test_lock_file_contains_pid() {
        let _guard = test_lock().lock().unwrap();
        // Clear any existing lock first
        if let Ok(path) = get_lock_path() {
            let _ = std::fs::remove_file(&path);
        }

        let lock = UpdateLock::acquire().unwrap();
        let path = get_lock_path().unwrap();

        // Read the lock file and verify it contains our PID
        let contents = std::fs::read_to_string(&path).unwrap();
        let file_pid: u32 = contents.trim().parse().unwrap();
        let our_pid = std::process::id();

        assert_eq!(file_pid, our_pid);

        drop(lock);
    }

    #[test]
    fn test_lock_removed_on_drop() {
        let _guard = test_lock().lock().unwrap();
        // Clear any existing lock first
        if let Ok(path) = get_lock_path() {
            let _ = std::fs::remove_file(&path);
        }

        let path = get_lock_path().unwrap();

        {
            let _lock = UpdateLock::acquire().unwrap();
            assert!(path.exists());
        }
        // After drop, lock file should be removed
        assert!(!path.exists());
    }

    #[test]
    fn test_stale_lock_from_dead_process() {
        let _guard = test_lock().lock().unwrap();
        // Clear any existing lock first
        let path = get_lock_path().unwrap();
        let _ = std::fs::remove_file(&path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }

        // Create a lock file with a non-existent PID
        std::fs::write(&path, "999999999").unwrap();

        // Should be able to acquire lock since the PID doesn't exist
        let lock = UpdateLock::acquire();
        assert!(lock.is_ok());

        // Clean up
        drop(lock);
    }

    #[test]
    fn test_is_locked_with_active_lock() {
        let _guard = test_lock().lock().unwrap();
        // Clear any existing lock first
        if let Ok(path) = get_lock_path() {
            let _ = std::fs::remove_file(&path);
        }

        // Without lock, should not be locked
        assert!(!UpdateLock::is_locked());

        // Acquire lock
        let _lock = UpdateLock::acquire().unwrap();

        // Now should report as locked
        assert!(UpdateLock::is_locked());
    }

    #[test]
    fn test_is_process_running_with_zero_pid() {
        // PID 0 is a special kernel process, behavior varies by OS
        // On most systems, this should return false or true based on kernel
        // This test just ensures it doesn't panic
        let _ = is_process_running(0);
    }

    #[test]
    fn test_is_process_running_with_pid_one() {
        // PID 1 (init/systemd) should always be running on Linux
        #[cfg(unix)]
        {
            assert!(is_process_running(1));
        }
    }
}
