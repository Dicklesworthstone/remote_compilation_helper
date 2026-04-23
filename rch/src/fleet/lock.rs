//! Per-fleet cooperative lock for state-mutating operations.
//!
//! Prevents two concurrent `rch fleet {deploy,rollback,drain}` invocations
//! (e.g. from two NTM agent panes) from racing on worker state.
//!
//! # Mechanism
//!
//! - Lock file: `$XDG_RUNTIME_DIR/rch/fleet_op.lock`, falling back to
//!   `${TMPDIR:-/tmp}/rch-<uid>/fleet_op.lock`.
//! - Acquisition is an atomic `O_CREAT|O_EXCL` create. The file contents are
//!   a single line: `<pid> <operation> <start-unix-seconds>`.
//! - Release removes the file (RAII via [`FleetLockGuard::drop`]).
//! - Staleness: if the file exists but its recorded PID is no longer running
//!   (checked via `/proc/<pid>` on Linux), the file is removed and the
//!   acquisition retried once.
//!
//! # Waiting
//!
//! Callers can opt into waiting for the holder to release by setting
//! `RCH_FLEET_WAIT_SECS=<n>` in the environment. The default is to fail fast
//! so automation (including repeated NTM pane marches) gets a clear signal
//! rather than quietly queueing.

use anyhow::{Context, Result, anyhow};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Environment variable controlling how long to wait for a conflicting
/// fleet operation to release its lock before giving up. Values are
/// interpreted in seconds. Default: `0` (fail fast).
pub const RCH_FLEET_WAIT_SECS_ENV: &str = "RCH_FLEET_WAIT_SECS";

/// Filename for the cooperative fleet lock. Kept together with
/// other RCH runtime state.
const LOCK_FILENAME: &str = "fleet_op.lock";

/// RAII guard that removes the lock file when dropped.
///
/// Drop is best-effort: if removal fails (e.g. the file was already deleted
/// externally), a warning is logged but the drop does not panic.
#[derive(Debug)]
pub struct FleetLockGuard {
    path: PathBuf,
}

impl Drop for FleetLockGuard {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            // Missing file is fine — someone else cleaned it up. Anything
            // else we want to hear about but not panic over.
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %err,
                    "failed to remove fleet lock on drop"
                );
            }
        }
    }
}

/// Information about the holder of an existing lock.
#[derive(Debug, Clone)]
pub struct LockHolder {
    pub pid: u32,
    pub operation: String,
    pub started_at_unix: u64,
}

impl LockHolder {
    /// Human-readable description suitable for error messages.
    pub fn describe(&self) -> String {
        let age = unix_now().saturating_sub(self.started_at_unix);
        format!("pid={} op={} age={}s", self.pid, self.operation, age)
    }
}

/// Acquire the per-fleet cooperative lock.
///
/// `operation` is a short label (e.g. `"fleet-deploy"`) that is recorded in
/// the lock file so a contender can see what is holding the lock.
///
/// On contention, returns `Err` with a diagnostic that names the holder
/// (PID + operation + age) and points at [`RCH_FLEET_WAIT_SECS_ENV`]
/// so operators can choose to block.
pub fn acquire(operation: &str) -> Result<FleetLockGuard> {
    let dir = lock_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create fleet lock directory {:?}", dir))?;
    let path = dir.join(LOCK_FILENAME);

    let wait_total = read_wait_secs();
    let deadline = Instant::now() + wait_total;
    let mut attempted_stale_sweep = false;

    loop {
        match try_create_lock(&path, operation) {
            Ok(()) => return Ok(FleetLockGuard { path }),
            Err(LockError::AlreadyHeld(holder)) => {
                // One-shot sweep: if the recorded holder is no longer running,
                // reclaim the file and retry. We only do this once per call so
                // a legitimate holder can't be raced over.
                if !attempted_stale_sweep
                    && !pid_is_alive(holder.pid)
                    && try_sweep_stale(&path, &holder)?
                {
                    attempted_stale_sweep = true;
                    continue;
                }

                if Instant::now() >= deadline {
                    return Err(anyhow!(
                        "Another fleet operation is in progress ({}). \
                        Lock file: {}. Wait for it to finish or set \
                        {}=<seconds> to block for longer.",
                        holder.describe(),
                        path.display(),
                        RCH_FLEET_WAIT_SECS_ENV
                    ));
                }

                // Poll every 500ms; cheap enough and keeps contention messages
                // reasonably fresh for human-facing output.
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(LockError::Io(err)) => {
                return Err(anyhow!(err).context(format!(
                    "failed to acquire fleet lock at {}",
                    path.display()
                )));
            }
        }
    }
}

#[derive(Debug)]
enum LockError {
    AlreadyHeld(LockHolder),
    Io(std::io::Error),
}

fn try_create_lock(path: &Path, operation: &str) -> Result<(), LockError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            let payload = format!(
                "{} {} {}\n",
                std::process::id(),
                sanitize_operation(operation),
                unix_now()
            );
            file.write_all(payload.as_bytes()).map_err(LockError::Io)?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            match read_holder(path) {
                Ok(holder) => Err(LockError::AlreadyHeld(holder)),
                Err(_) => {
                    // Existing file is unreadable or malformed: treat as held
                    // by an unknown caller so we don't stomp on state we
                    // can't reason about.
                    Err(LockError::AlreadyHeld(LockHolder {
                        pid: 0,
                        operation: "unknown".to_string(),
                        started_at_unix: 0,
                    }))
                }
            }
        }
        Err(err) => Err(LockError::Io(err)),
    }
}

fn try_sweep_stale(path: &Path, holder: &LockHolder) -> Result<bool> {
    // Best-effort: remove only if the contents still match the stale holder
    // we just read, so we don't race with a legitimate new holder who
    // acquired the lock in between.
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let current = parse_holder(&contents);
            match current {
                Some(now)
                    if now.pid == holder.pid && now.started_at_unix == holder.started_at_unix =>
                {
                    std::fs::remove_file(path)
                        .with_context(|| format!("failed to remove stale fleet lock {:?}", path))?;
                    tracing::warn!(
                        stale_pid = holder.pid,
                        lock = %path.display(),
                        "removed stale fleet lock owned by non-running pid"
                    );
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err).with_context(|| format!("failed to read fleet lock {:?}", path)),
    }
}

fn read_holder(path: &Path) -> Result<LockHolder> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    parse_holder(&contents).ok_or_else(|| anyhow!("malformed lock file: {:?}", contents))
}

fn parse_holder(contents: &str) -> Option<LockHolder> {
    let line = contents.lines().next()?;
    let mut parts = line.split_whitespace();
    let pid: u32 = parts.next()?.parse().ok()?;
    let operation = parts.next()?.to_string();
    let started: u64 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some(LockHolder {
        pid,
        operation,
        started_at_unix: started,
    })
}

fn lock_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        let xdg = PathBuf::from(xdg);
        if !xdg.as_os_str().is_empty() {
            return Ok(xdg.join("rch"));
        }
    }
    // Fall back to $TMPDIR or /tmp, namespaced by uid so two users on the
    // same machine don't collide. We don't have a direct uid API without
    // unsafe; use `USER` as a proxy (good enough: two different user logins
    // on the same host have different $USER values).
    let base = std::env::var_os("TMPDIR").unwrap_or_else(|| "/tmp".into());
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    Ok(PathBuf::from(base).join(format!("rch-{}", user)))
}

fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // `/proc/<pid>` exists on Linux for any live process and disappears
    // immediately on exit. Good enough for staleness detection on the RCH
    // target fleet (Linux workstations + Linux VPS workers).
    //
    // On non-Linux, fail safe: assume alive so we never prematurely break
    // someone else's lock.
    if cfg!(target_os = "linux") {
        Path::new(&format!("/proc/{}", pid)).exists()
    } else {
        true
    }
}

fn sanitize_operation(op: &str) -> String {
    op.chars()
        .map(|c| if c.is_ascii_whitespace() { '_' } else { c })
        .collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_wait_secs() -> Duration {
    std::env::var(RCH_FLEET_WAIT_SECS_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_runtime<F: FnOnce(&Path)>(f: F) {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Point both XDG_RUNTIME_DIR and TMPDIR at the tempdir so tests are
        // isolated from the developer's actual runtime state.
        //
        // `set_var`/`remove_var` are unsafe in Rust 2024; this crate forbids
        // unsafe, so tests share the process env. We scope side effects to a
        // unique subdirectory and pass the path directly where possible.
        let lock_path = tmp.path().join("rch").join(LOCK_FILENAME);
        std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        f(&lock_path);
    }

    #[test]
    fn try_create_lock_succeeds_when_unheld() {
        with_temp_runtime(|path| {
            try_create_lock(path, "fleet-deploy").expect("acquire");
            assert!(path.exists());
            let holder = read_holder(path).expect("holder");
            assert_eq!(holder.pid, std::process::id());
            assert_eq!(holder.operation, "fleet-deploy");
        });
    }

    #[test]
    fn try_create_lock_fails_when_held() {
        with_temp_runtime(|path| {
            try_create_lock(path, "fleet-deploy").expect("first");
            match try_create_lock(path, "fleet-deploy") {
                Err(LockError::AlreadyHeld(h)) => {
                    assert_eq!(h.pid, std::process::id());
                    assert_eq!(h.operation, "fleet-deploy");
                }
                other => panic!("expected AlreadyHeld, got {:?}", other),
            }
        });
    }

    #[test]
    fn stale_lock_is_swept_when_pid_is_dead() {
        with_temp_runtime(|path| {
            // Fake holder with a definitely-dead pid (0 sentinel)
            std::fs::write(path, "0 fleet-deploy 1700000000\n").unwrap();
            let holder = read_holder(path).unwrap();
            assert!(!pid_is_alive(holder.pid));
            let swept = try_sweep_stale(path, &holder).unwrap();
            assert!(swept);
            assert!(!path.exists());
        });
    }

    #[test]
    fn parse_holder_roundtrips() {
        let h = parse_holder("12345 fleet-deploy 1700000000\n").unwrap();
        assert_eq!(h.pid, 12345);
        assert_eq!(h.operation, "fleet-deploy");
        assert_eq!(h.started_at_unix, 1700000000);
    }

    #[test]
    fn parse_holder_rejects_garbage() {
        assert!(parse_holder("").is_none());
        assert!(parse_holder("not-a-pid fleet-deploy 0").is_none());
    }

    #[test]
    fn sanitize_operation_strips_whitespace() {
        assert_eq!(sanitize_operation("fleet deploy"), "fleet_deploy");
        assert_eq!(sanitize_operation("a\tb\nc"), "a_b_c");
    }
}
