//! Update lock to prevent concurrent updates.
//!
//! Uses a PID-based lock file approach that's safe and portable.

use super::types::UpdateError;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Lock to prevent concurrent updates.
pub struct UpdateLock {
    path: PathBuf,
}

impl UpdateLock {
    /// Acquire the update lock.
    ///
    /// Uses a PID-based lock file. If a lock file exists, checks if the
    /// process is still running before failing.
    ///
    /// The create step uses `O_CREAT|O_EXCL` (via `OpenOptions::create_new`)
    /// so two concurrent acquirers can't both succeed. A previous revision
    /// used `File::create`, which truncates an existing file — two
    /// processes racing past a stale-lock sweep could each overwrite the
    /// other's PID and both believe they held the lock.
    pub fn acquire() -> Result<Self, UpdateError> {
        let path = get_lock_path()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                UpdateError::InstallFailed(format!("Failed to create lock dir: {}", e))
            })?;
        }

        // One-shot stale sweep: if an existing lock points at a dead PID,
        // reclaim it by comparing the contents we just read and removing
        // only if they still match.
        let mut attempted_sweep = false;
        loop {
            match exclusive_create(&path) {
                Ok(mut file) => {
                    write!(file, "{}", std::process::id()).map_err(|e| {
                        // Clean up our half-written file so a later sweep
                        // doesn't see a malformed PID and choke.
                        let _ = fs::remove_file(&path);
                        UpdateError::InstallFailed(format!("Failed to write lock file: {}", e))
                    })?;
                    file.sync_all().map_err(|e| {
                        let _ = fs::remove_file(&path);
                        UpdateError::InstallFailed(format!("Failed to sync lock file: {}", e))
                    })?;
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing_pid = read_pid(&path);
                    let holder_alive = existing_pid.is_some_and(is_process_running);
                    if holder_alive {
                        return Err(UpdateError::LockHeld);
                    }
                    if attempted_sweep {
                        // We already tried to sweep once; if the lock is
                        // still blocking us, another process just grabbed
                        // it — treat as held.
                        return Err(UpdateError::LockHeld);
                    }
                    attempted_sweep = true;
                    if !try_sweep_stale(&path, existing_pid) {
                        // Someone else reclaimed or removed it; loop and
                        // let the exclusive create race decide.
                        continue;
                    }
                    // Sweep succeeded; loop to retry create.
                }
                Err(e) => {
                    return Err(UpdateError::InstallFailed(format!(
                        "Failed to create lock file: {}",
                        e
                    )));
                }
            }
        }
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

/// Open a file with `O_CREAT|O_EXCL` semantics — succeeds only if the file
/// does not already exist. This is the primitive that makes the acquire
/// loop race-safe.
fn exclusive_create(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Read the PID recorded in the lock file, if any.
fn read_pid(path: &Path) -> Option<u32> {
    let mut file = File::open(path).ok()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;
    contents.trim().parse().ok()
}

/// Remove the lock file ONLY if the PID it contains still matches what we
/// previously observed. This avoids swiping a lock that a fresh process
/// just grabbed between our read and our remove.
fn try_sweep_stale(path: &Path, observed_pid: Option<u32>) -> bool {
    let current = read_pid(path);
    if current != observed_pid {
        return false;
    }
    match fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
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

    #[test]
    fn test_second_acquire_without_drop_is_rejected() {
        // Regression: the previous implementation used `File::create`,
        // which truncates-and-opens rather than create-exclusively. A
        // subsequent `acquire()` while a lock was still held (identified
        // by matching PID and `is_process_running(pid) = true`) would
        // still fail at the read step, but any code path that reached
        // the `File::create` call would silently overwrite the existing
        // lock. The current implementation uses `O_CREAT|O_EXCL` so the
        // second acquire is rejected unambiguously.
        let _guard = test_lock().lock().unwrap();
        let path = get_lock_path().unwrap();
        let _ = std::fs::remove_file(&path);

        let first = UpdateLock::acquire().expect("first acquire");
        // Our own PID is running, so a second attempt must see
        // `LockHeld` rather than sweeping and overwriting.
        match UpdateLock::acquire() {
            Err(UpdateError::LockHeld) => {}
            Err(other) => panic!("expected LockHeld, got {:?}", other),
            Ok(_) => panic!("expected LockHeld, second acquire unexpectedly succeeded"),
        }
        drop(first);

        // After drop, a fresh acquire should succeed again.
        let third = UpdateLock::acquire().expect("re-acquire after drop");
        drop(third);
    }

    #[test]
    fn test_acquire_is_atomic_across_threads() {
        // Regression: only one of N concurrent acquirers may succeed.
        // With `File::create`, two threads could both race past a stale
        // sweep and both overwrite the lock file with their own PID.
        use std::sync::{Arc, Barrier};
        let _guard = test_lock().lock().unwrap();
        let path = get_lock_path().unwrap();
        let _ = std::fs::remove_file(&path);

        let thread_count = 8usize;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            let b = barrier.clone();
            handles.push(std::thread::spawn(move || {
                b.wait();
                UpdateLock::acquire()
            }));
        }

        let mut successes = Vec::new();
        let mut lock_held = 0usize;
        for h in handles {
            match h.join().expect("join") {
                Ok(lock) => successes.push(lock),
                Err(UpdateError::LockHeld) => lock_held += 1,
                Err(other) => panic!("unexpected error: {:?}", other),
            }
        }
        assert_eq!(
            successes.len(),
            1,
            "exactly one thread must acquire the lock"
        );
        assert_eq!(
            successes.len() + lock_held,
            thread_count,
            "all acquires must resolve to either success or LockHeld"
        );
    }
}
