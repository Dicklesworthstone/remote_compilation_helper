//! Bounded daemon auto-start (self-healing) for the PreToolUse hook.
//!
//! When the hook discovers that `rchd` is unreachable, it performs a single
//! bounded attempt to bring the daemon back up before falling back to local
//! compilation. This module owns every moving part of that recovery: the
//! per-host state directory, kernel-backed startup ownership with staleness /
//! PID-reuse / cross-host defenses, the cooldown timestamp that prevents
//! spawn storms, locating and spawning the `rchd` binary, the health probe
//! over the Unix socket, and the bounded wait for the socket to come back.
//!
//! The principal entry point is [`try_auto_start_daemon`], called from the
//! hook's `run_exec` path; every other item here is private to this module.

use super::*;

#[derive(Debug, thiserror::Error)]
pub(super) enum AutoStartError {
    #[error("Another process is starting the daemon (lock held)")]
    LockHeld,
    #[error("Auto-start on cooldown (last attempt {0}s ago, need {1}s)")]
    CooldownActive(u64, u64),
    #[error("Failed to spawn rchd: {0}")]
    SpawnFailed(#[source] std::io::Error),
    #[error("rchd launch wrapper exited unsuccessfully: {0}")]
    WrapperFailed(std::process::ExitStatus),
    #[error("Daemon did not become healthy within the {0}s startup budget")]
    Timeout(u64),
    #[error("rchd binary not found in PATH")]
    BinaryNotFound,
    #[error("Socket exists but daemon not responding (stale socket)")]
    StaleSocket,
    #[error("Socket accepts connections but daemon health check failed")]
    UnhealthySocket,
    #[error("Configuration disabled auto-start")]
    Disabled,
    #[error("Auto-start I/O error: {0}")]
    Io(#[source] std::io::Error),
}

#[derive(Debug)]
struct AutoStartLock {
    path: PathBuf,
    body: String,
    // Held until after Drop removes our legacy sentinel. Never unlink the
    // gate itself: every contender must lock the same persistent inode.
    _gate: std::fs::File,
}

impl Drop for AutoStartLock {
    fn drop(&mut self) {
        let _ = remove_autostart_lock_if_unchanged(&self.path, &self.body);
    }
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
}

fn autostart_state_dir() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime_dir.trim().is_empty()
    {
        return PathBuf::from(runtime_dir).join("rch");
    }
    PathBuf::from("/tmp").join("rch")
}

fn autostart_lock_path() -> PathBuf {
    autostart_state_dir().join("hook_autostart.lock")
}

fn autostart_cooldown_path() -> PathBuf {
    autostart_state_dir().join("hook_autostart.cooldown")
}

fn read_cooldown_timestamp(path: &Path) -> Option<SystemTime> {
    let contents = std::fs::read_to_string(path).ok()?;
    let secs: u64 = contents.trim().parse().ok()?;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

fn write_cooldown_timestamp(path: &Path) -> Result<(), AutoStartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AutoStartError::Io)?;
    }
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    std::fs::write(path, format!("{now_secs}")).map_err(AutoStartError::Io)
}

/// Maximum age (in seconds) of a lockfile before it's eligible for
/// stale takeover regardless of the recorded PID. Belt-and-suspenders
/// against PID reuse: even if the recorded PID happens to be alive
/// (a different process that reused the ID after the original was
/// killed), a >60s-old lockfile is treated as stale.
const AUTOSTART_LOCK_STALE_TTL_SECS: u64 = 60;

/// Render the lockfile body. Format: newline-separated
/// `pid\nunix_secs\nhostname\nnonce\n`. Hand-rolled to avoid bringing in a
/// serializer for a small file the OS owns.
fn render_autostart_lock_body() -> String {
    let pid = std::process::id();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let now_secs = now.as_secs();
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let sequence = AUTOSTART_LOCK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nonce = now.as_nanos();
    format!("{pid}\n{now_secs}\n{hostname}\n{nonce:x}-{sequence:x}\n")
}

/// Parsed contents of an autostart lockfile.
#[derive(Debug)]
struct ParsedLock {
    pid: u32,
    created_at_secs: u64,
    hostname: String,
}

fn parse_autostart_lock_body(s: &str) -> Option<ParsedLock> {
    let mut lines = s.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    let created_at_secs: u64 = lines.next()?.trim().parse().ok()?;
    let hostname = lines.next()?.trim().to_string();
    if hostname.is_empty() {
        return None;
    }
    Some(ParsedLock {
        pid,
        created_at_secs,
        hostname,
    })
}

fn remove_autostart_lock_if_unchanged(path: &Path, expected_body: &str) -> bool {
    match std::fs::read_to_string(path) {
        Ok(current_body) if current_body == expected_body => match std::fs::remove_file(path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        },
        _ => false,
    }
}

/// Check whether a PID is alive. On Unix: send signal 0 (no-op) — if
/// it succeeds the process exists; ESRCH means it's gone; EPERM also
/// means it's alive (we just can't signal it). On non-Unix platforms:
/// conservative `true` since we can't check cheaply — combined with
/// the TTL fallback, a wedged lockfile still recovers within 60s.
fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // /proc/<pid> probe — cheap and unambiguous on Linux. We do
        // NOT use kill(0) directly because rch is #![forbid(unsafe_code)]
        // and the kill(2) wrapper would require nix/libc raw syscalls.
        let proc_path = std::path::PathBuf::from(format!("/proc/{pid}"));
        if proc_path.exists() {
            return true;
        }
        if !std::path::Path::new("/proc").exists() {
            // No /proc (macOS/BSD): probe via the external `kill -0`
            // binary — no unsafe, and this path only runs on the rare
            // daemon-autostart lane, never per hook decision (qqa0y: the
            // old conservative `true` meant a dead-pid lock could only
            // recover via the 60s TTL on macOS). `kill -0` exits 0 when
            // the process exists and is signalable; autostart locks live
            // in the per-user state dir, so same-user EPERM is not a
            // practical concern. A spawn failure falls back to
            // conservative alive (TTL still recovers).
            return std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(true);
        }
        // /proc exists but /proc/<pid> doesn't — PID is definitively gone.
        false
    }
    #[cfg(not(unix))]
    {
        // Conservative on non-Unix; TTL handles the stale case.
        let _ = pid;
        true
    }
}

/// Decide whether an existing lockfile is stale and may be replaced.
/// A lockfile is stale when:
///   * its PID is not alive (process exited / SIGKILLed / power-cycled), OR
///   * its body is unparseable (corruption), OR
///   * its hostname matches this host AND it's older than the TTL (PID-reuse defense).
///
/// Lockfiles from a DIFFERENT host (NFS shared lock scenario) are NEVER
/// considered stale here — only the holder's own host can prove liveness.
fn autostart_lock_is_stale(parsed: &ParsedLock) -> bool {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let age = now_secs.saturating_sub(parsed.created_at_secs);

    let our_hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    if parsed.hostname != our_hostname {
        // Different host — don't touch the lock; trust the holder.
        // The cooldown mechanism upstream still prevents storm-spawning.
        return false;
    }

    if !pid_is_alive(parsed.pid) {
        return true;
    }

    // PID is alive, same host: TTL fallback for PID-reuse case.
    age > AUTOSTART_LOCK_STALE_TTL_SECS
}

/// Serialize the entire sentinel create/read/reap/drop lifecycle. A
/// create_new sentinel alone has a publication race: another client can see
/// the still-empty file and reclaim it as corrupt. Read/compare/unlink also
/// races with another stale reaper. A persistent kernel lock closes both
/// windows for clients using this protocol, and releases on process exit.
/// Keep the legacy sentinel for compatibility with older clients; those
/// clients do not participate in the gate and retain their old guarantees.
fn acquire_autostart_gate(path: &Path) -> Result<std::fs::File, AutoStartError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut gate_path = path.as_os_str().to_os_string();
    gate_path.push(".gate");
    let gate = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(PathBuf::from(gate_path))
        .map_err(AutoStartError::Io)?;
    match gate.try_lock() {
        Ok(()) => Ok(gate),
        Err(std::fs::TryLockError::WouldBlock) => Err(AutoStartError::LockHeld),
        Err(std::fs::TryLockError::Error(error)) => Err(AutoStartError::Io(error)),
    }
}

fn acquire_autostart_lock(path: &Path) -> Result<AutoStartLock, AutoStartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AutoStartError::Io)?;
    }
    let gate = acquire_autostart_gate(path)?;
    // Retain the sentinel's stale/PID/host checks for older clients, while
    // the gate prevents upgraded clients from racing its publication/reap.
    let body = render_autostart_lock_body();
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            // Write the lockfile body so subsequent contenders can decide
            // whether to wait or take over. We deliberately don't fail the
            // acquire if the write itself fails: the kernel gate still
            // protects ownership among upgraded clients. The body is also
            // used for diagnostic and legacy stale-detection metadata.
            let _ = std::io::Write::write_all(&mut f, body.as_bytes());
            let _ = f.sync_all();
            tracing::info!(
                target: "rch::hook::auto_start_lock",
                path = %path.display(),
                pid = %std::process::id(),
                "doctor.autostart_lock.acquired",
            );
            Ok(AutoStartLock {
                path: path.to_path_buf(),
                body,
                _gate: gate,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale-detection branch: read the existing body, decide
            // whether the holder is gone, and take over if so.
            match std::fs::read_to_string(path) {
                Ok(existing) => {
                    let parsed = parse_autostart_lock_body(&existing);
                    let stale = match &parsed {
                        Some(p) => autostart_lock_is_stale(p),
                        None => {
                            // Unparseable / corrupted body — treat as stale.
                            tracing::warn!(
                                target: "rch::hook::auto_start_lock",
                                path = %path.display(),
                                bytes = existing.len(),
                                "doctor.autostart_lock.body_corrupt_treated_as_stale",
                            );
                            true
                        }
                    };
                    if stale {
                        if !remove_autostart_lock_if_unchanged(path, &existing) {
                            return Err(AutoStartError::LockHeld);
                        }
                        match OpenOptions::new().write(true).create_new(true).open(path) {
                            Ok(mut f) => {
                                let _ = std::io::Write::write_all(&mut f, body.as_bytes());
                                let _ = f.sync_all();
                                tracing::warn!(
                                    target: "rch::hook::auto_start_lock",
                                    path = %path.display(),
                                    holder_pid = ?parsed.as_ref().map(|p| p.pid),
                                    holder_host = ?parsed.as_ref().map(|p| p.hostname.clone()),
                                    holder_age_secs = ?parsed.as_ref().map(|p| {
                                        SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or(Duration::from_secs(0))
                                            .as_secs()
                                            .saturating_sub(p.created_at_secs)
                                    }),
                                    "doctor.autostart_lock.stale_replaced",
                                );
                                Ok(AutoStartLock {
                                    path: path.to_path_buf(),
                                    body,
                                    _gate: gate,
                                })
                            }
                            // Lost the race to recreate — another contender won.
                            Err(_) => Err(AutoStartError::LockHeld),
                        }
                    } else {
                        Err(AutoStartError::LockHeld)
                    }
                }
                // Couldn't even read the file — treat as held to be safe.
                Err(_) => Err(AutoStartError::LockHeld),
            }
        }
        Err(e) => Err(AutoStartError::Io(e)),
    }
}

fn which_rchd_path() -> Option<PathBuf> {
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let candidate = dir.join("rchd");
        if candidate.exists() {
            return Some(candidate);
        }
    }

    which("rchd").ok()
}

fn spawn_rchd(path: &Path, socket_path: &Path) -> Result<(), AutoStartError> {
    let mut cmd = std::process::Command::new("nohup");
    cmd.arg(path)
        .arg("--socket")
        .arg(socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    let mut child = cmd.spawn().map_err(AutoStartError::SpawnFailed)?;
    // Immediate-death detection: DEADLINE-based polling instead of one 100ms
    // sleep + single try_wait (qqa0y: under load a child that died at
    // 100-200ms slipped past the one-shot check on macOS). A fixed
    // iteration count would amplify scheduler jitter (N stretched sleeps);
    // the deadline bounds the live-child wall time at ~150ms + one slice,
    // safely under the <250ms latency contract pinned by
    // test_spawn_rchd_returns_quickly_for_live_child even on a loaded box.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(150);
    loop {
        if let Some(status) = child.try_wait().map_err(AutoStartError::SpawnFailed)? {
            return if status.success() {
                Ok(())
            } else {
                Err(AutoStartError::WrapperFailed(status))
            };
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // `nohup` does not daemonize by itself; it execs/wraps rchd as our
    // direct child. Keep a detached waiter while rch remains alive so a
    // later daemon exit is reaped instead of becoming a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// A health exchange has one deadline, not a fresh deadline for each line.
/// In particular, a peer streaming headers must not keep dispatch blocked or
/// allocate an unbounded response while holding the autostart lock.
async fn probe_daemon_health(socket_path: &Path) -> bool {
    let budget = Duration::from_millis(300);
    let probe = async {
        let stream = UnixStream::connect(socket_path).await?;
        let (reader, mut writer) = stream.into_split();
        writer.write_all(b"GET /health\n").await?;
        writer.flush().await?;

        // Use the same bounded HTTP/status parser as selection. An HTTP error
        // carrying a misleading {"status":"healthy"} body is not readiness.
        let body = daemon_ipc::read_daemon_body(reader, budget, false).await?;
        let response: HealthResponse = serde_json::from_str(&body)?;
        Ok::<bool, anyhow::Error>(response.status == "healthy")
    };
    matches!(timeout(budget, probe).await, Ok(Ok(true)))
}

async fn socket_is_confirmed_stale(socket_path: &Path) -> bool {
    match timeout(Duration::from_millis(300), UnixStream::connect(socket_path)).await {
        Ok(Ok(_stream)) => false,
        Ok(Err(error)) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
        ),
        Err(_) => false,
    }
}

/// Bound all readiness probes and sleeps together. Checking elapsed time only
/// between probes allows a slow peer to exceed the caller's startup budget.
async fn wait_for_socket(socket_path: &Path, budget: Duration) -> bool {
    if budget.is_zero() {
        return false;
    }
    timeout(budget, async {
        loop {
            if probe_daemon_health(socket_path).await {
                return true;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or(false)
}

pub(super) async fn try_auto_start_daemon(
    config: &SelfHealingConfig,
    socket_path: &Path,
) -> Result<(), AutoStartError> {
    recover_daemon_with_paths(
        config,
        socket_path,
        &autostart_lock_path(),
        &autostart_cooldown_path(),
        |socket| {
            let rchd_path = which_rchd_path().ok_or(AutoStartError::BinaryNotFound)?;
            info!(
                target: "rch::hook::auto_start",
                binary = %rchd_path.display(),
                socket = %socket.display(),
                "Spawning rchd"
            );
            spawn_rchd(&rchd_path, socket)
        },
    )
    .await
}

/// The production recovery flow, with paths and the single launch operation
/// supplied explicitly so concurrent-client tests never mutate process-global
/// environment variables or accidentally start a real daemon.
async fn recover_daemon_with_paths(
    config: &SelfHealingConfig,
    socket_path: &Path,
    lock_path: &Path,
    cooldown_path: &Path,
    launch: impl FnOnce(&Path) -> Result<(), AutoStartError>,
) -> Result<(), AutoStartError> {
    use std::os::unix::fs::FileTypeExt;

    if !config.hook_starts_daemon {
        return Err(AutoStartError::Disabled);
    }
    let budget = Duration::from_secs(config.auto_start_timeout_secs);
    if budget.is_zero() {
        return Err(AutoStartError::Timeout(config.auto_start_timeout_secs));
    }
    let started = Instant::now();
    let remaining = || budget.saturating_sub(started.elapsed());

    info!(
        target: "rch::hook::auto_start",
        "Daemon unavailable, attempting recovery"
    );
    let recovery = async {
        // Readiness is useful even when another process still owns the lock
        // or a previous launch is on cooldown. Neither is proof of no workers.
        if probe_daemon_health(socket_path).await {
            return Ok(());
        }
        let _lock = match acquire_autostart_lock(lock_path) {
            Ok(lock) => lock,
            Err(AutoStartError::LockHeld) => {
                debug!(
                    target: "rch::hook::auto_start",
                    "Waiting for another client's daemon startup"
                );
                return if wait_for_socket(socket_path, remaining()).await {
                    Ok(())
                } else {
                    Err(AutoStartError::Timeout(config.auto_start_timeout_secs))
                };
            }
            Err(error) => return Err(error),
        };

        // Another starter may have finished between the probe and acquisition.
        // Keep all socket mutation and launching under the ownership guard.
        if probe_daemon_health(socket_path).await {
            return Ok(());
        }

        // Check cooldown BEFORE touching the socket. A daemon from an earlier
        // timed-out call may still be starting; observe it without spawning.
        // A clock rollback/future timestamp cannot disable recovery forever.
        if let Some(last_attempt) = read_cooldown_timestamp(cooldown_path)
            && let Ok(elapsed) = last_attempt.elapsed()
            && elapsed.as_secs() < config.auto_start_cooldown_secs
        {
            return if wait_for_socket(socket_path, remaining()).await {
                Ok(())
            } else {
                Err(AutoStartError::CooldownActive(
                    elapsed.as_secs(),
                    config.auto_start_cooldown_secs,
                ))
            };
        }

        match std::fs::symlink_metadata(socket_path) {
            Ok(metadata) => {
                // A typo or a symlink in the configured endpoint is not a
                // stale socket. In particular, never delete a regular file.
                if !metadata.file_type().is_socket() {
                    return Err(AutoStartError::StaleSocket);
                }
                if !socket_is_confirmed_stale(socket_path).await {
                    // A live listener may be overloaded or still initializing.
                    // Never unlink it or launch a competing daemon.
                    return if wait_for_socket(socket_path, remaining()).await {
                        Ok(())
                    } else {
                        Err(AutoStartError::UnhealthySocket)
                    };
                }
                match std::fs::remove_file(socket_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return Err(AutoStartError::StaleSocket),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(AutoStartError::Io(error)),
        }

        if remaining().is_zero() {
            return Err(AutoStartError::Timeout(config.auto_start_timeout_secs));
        }
        write_cooldown_timestamp(cooldown_path)?;
        launch(socket_path)?;
        if !wait_for_socket(socket_path, remaining()).await {
            return Err(AutoStartError::Timeout(config.auto_start_timeout_secs));
        }
        info!(
            target: "rch::hook::auto_start",
            "Daemon recovery succeeded"
        );
        Ok(())
    };

    // Connect, health checks, contention, cooldown observation and readiness
    // share one asynchronous budget, rather than each restarting the clock.
    timeout(budget, recovery)
        .await
        .unwrap_or(Err(AutoStartError::Timeout(config.auto_start_timeout_secs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    /// Test helper to create a unique temp directory for auto-start tests.
    /// (Local copy of the shared hook test helper, which a sibling module
    /// cannot see.)
    fn create_test_state_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("Failed to create temp dir")
    }

    #[test]
    fn test_read_cooldown_timestamp_valid() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");

        // Write a known timestamp (100 seconds ago)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(&cooldown_path, format!("{}", now - 100)).unwrap();

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_some(), "Should read valid timestamp");

        let elapsed = timestamp.unwrap().elapsed().unwrap().as_secs();
        assert!(
            (99..=102).contains(&elapsed),
            "Elapsed time should be ~100s, got {}",
            elapsed
        );
    }

    #[test]
    fn test_read_cooldown_timestamp_missing() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("nonexistent");

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_none(), "Missing file should return None");
    }

    #[test]
    fn test_read_cooldown_timestamp_invalid_content() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");

        std::fs::write(&cooldown_path, "not a number").unwrap();

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_none(), "Invalid content should return None");
    }

    #[test]
    fn test_write_cooldown_timestamp_creates_file() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("subdir/cooldown");

        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "Should create file and parent directories");
        assert!(cooldown_path.exists(), "Cooldown file should exist");

        let contents = std::fs::read_to_string(&cooldown_path).unwrap();
        let secs: u64 = contents.trim().parse().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(secs <= now && secs >= now - 2, "Timestamp should be recent");
    }

    #[test]
    fn test_acquire_autostart_lock_success() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(lock.is_ok(), "Should acquire lock on first attempt");
        assert!(lock_path.exists(), "Lock file should exist");
    }

    #[test]
    fn test_acquire_autostart_lock_contention() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // First acquisition should succeed
        let lock1 = super::acquire_autostart_lock(&lock_path);
        assert!(lock1.is_ok(), "First lock should succeed");

        // Second acquisition should fail with LockHeld
        let lock2 = super::acquire_autostart_lock(&lock_path);
        assert!(lock2.is_err(), "Second lock should fail");
        assert!(
            matches!(lock2.unwrap_err(), super::AutoStartError::LockHeld),
            "Error should be LockHeld"
        );
    }

    #[test]
    fn test_autostart_lock_released_on_drop() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // Acquire and drop the lock
        {
            let lock = super::acquire_autostart_lock(&lock_path);
            assert!(lock.is_ok(), "First lock should succeed");
            assert!(lock_path.exists(), "Lock file should exist while held");
            // lock is dropped here
        }

        // Lock file should be removed
        assert!(
            !lock_path.exists(),
            "Lock file should be removed after drop"
        );

        // Should be able to acquire lock again
        let lock2 = super::acquire_autostart_lock(&lock_path);
        assert!(lock2.is_ok(), "Should be able to reacquire lock after drop");
    }

    #[test]
    fn test_autostart_lock_drop_preserves_replaced_lock_body() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        let lock = super::acquire_autostart_lock(&lock_path).expect("fresh acquire");
        let replacement_body = format!(
            "{}\n{}\n{}-replacement\n",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            our_hostname()
        );
        std::fs::write(&lock_path, &replacement_body).expect("replace lock body");

        drop(lock);

        let body = std::fs::read_to_string(&lock_path).expect("replacement should remain");
        assert_eq!(body, replacement_body);
    }

    // ========================================================================
    // t17 — stale-PID detection on autostart lockfile
    // ========================================================================

    fn write_lockfile(path: &std::path::Path, pid: u32, age_secs: u64, hostname: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let created_at = now.saturating_sub(age_secs);
        std::fs::write(path, format!("{pid}\n{created_at}\n{hostname}\n")).unwrap();
    }

    fn our_hostname() -> String {
        std::env::var("HOSTNAME")
            .ok()
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[test]
    fn test_acquire_autostart_lock_writes_body() {
        // Fresh acquire writes pid/timestamp/hostname so subsequent
        // contenders can decide whether to wait or take over.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        let _lock = super::acquire_autostart_lock(&lock_path).expect("fresh acquire");
        let body = std::fs::read_to_string(&lock_path).expect("read body");
        let parsed = super::parse_autostart_lock_body(&body).expect("body parses");
        assert_eq!(parsed.pid, std::process::id());
        assert!(!parsed.hostname.is_empty());
    }

    #[test]
    fn test_render_autostart_lock_body_is_unique_owner_token() {
        let _guard = test_guard!();

        let body1 = super::render_autostart_lock_body();
        let body2 = super::render_autostart_lock_body();

        assert_ne!(
            body1, body2,
            "lock cleanup token must be acquisition-unique"
        );
        assert!(super::parse_autostart_lock_body(&body1).is_some());
        assert!(super::parse_autostart_lock_body(&body2).is_some());
    }

    #[test]
    fn test_autostart_lock_detects_dead_pid() {
        // PID 99999 is virtually guaranteed not to exist (kernel PID
        // max is typically 4194304, but the actual running set is sparse;
        // we pick a value high enough to almost never collide).
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        write_lockfile(&lock_path, 99999, 5, &our_hostname());
        // Acquire — should detect stale and take over.
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_ok(),
            "Stale PID should be detected and replaced; got {:?}",
            lock.err()
        );
        // The new body should record our own PID.
        let body = std::fs::read_to_string(&lock_path).expect("read body");
        let parsed = super::parse_autostart_lock_body(&body).expect("body parses");
        assert_eq!(parsed.pid, std::process::id());
    }

    #[test]
    fn test_autostart_lock_respects_live_pid_recent() {
        // Our own PID, age 5s, same host: definitely alive AND fresh.
        // Must return LockHeld.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        write_lockfile(&lock_path, std::process::id(), 5, &our_hostname());
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(lock.is_err(), "Live recent holder must hold the lock");
        assert!(matches!(lock.unwrap_err(), super::AutoStartError::LockHeld));
    }

    #[test]
    fn test_autostart_lock_corrupt_body_treated_as_stale() {
        // Garbage body (couldn't parse) → take over.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        std::fs::write(
            &lock_path,
            "this is not\nthe expected\nlock format with extra junk",
        )
        .unwrap();
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_ok(),
            "Corrupted lockfile should be treated as stale; got {:?}",
            lock.err()
        );
    }

    #[test]
    fn test_autostart_lock_empty_body_treated_as_stale() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        std::fs::write(&lock_path, "").unwrap();
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_ok(),
            "Empty lockfile body should be treated as stale; got {:?}",
            lock.err()
        );
    }

    #[test]
    fn test_autostart_lock_different_hostname_blocks() {
        // NFS-shared scenario: a different host holds the lock. Even if
        // the PID isn't alive on our host, we can't tell — so we trust
        // the holder and return LockHeld.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // Use a PID that's almost certainly NOT alive on our host AND
        // a hostname that's almost certainly not ours.
        write_lockfile(&lock_path, 99999, 5, "definitely-not-our-host-xyz");
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_err(),
            "Lock from a different host must not be taken over"
        );
    }

    #[test]
    fn test_autostart_lock_ttl_fallback_for_same_host() {
        // PID-reuse defense: our own PID, but the lockfile is very old.
        // Should be treated as stale (TTL exceeded) and replaced.
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // Age > TTL (60s) with our own PID + hostname.
        write_lockfile(&lock_path, std::process::id(), 120, &our_hostname());
        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(
            lock.is_ok(),
            "Old lockfile (TTL exceeded) should be stale-replaced even when PID is alive; got {:?}",
            lock.err()
        );
    }

    #[test]
    fn test_autostart_stale_sweep_preserves_changed_lock_body() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        write_lockfile(&lock_path, std::process::id(), 120, &our_hostname());
        let observed_stale_body = std::fs::read_to_string(&lock_path).expect("read stale body");
        let replacement_body = super::render_autostart_lock_body();
        std::fs::write(&lock_path, &replacement_body).expect("replace lock body");

        assert!(
            !super::remove_autostart_lock_if_unchanged(&lock_path, &observed_stale_body),
            "changed lock body must not be removed"
        );
        let body = std::fs::read_to_string(&lock_path).expect("replacement should remain");
        assert_eq!(body, replacement_body);
    }

    #[test]
    fn test_parse_autostart_lock_body_valid() {
        let body = "12345\n1778000000\nmybox\n";
        let p = super::parse_autostart_lock_body(body).expect("valid body parses");
        assert_eq!(p.pid, 12345);
        assert_eq!(p.created_at_secs, 1_778_000_000);
        assert_eq!(p.hostname, "mybox");
    }

    #[test]
    fn test_parse_autostart_lock_body_invalid() {
        // Various invalid shapes.
        assert!(super::parse_autostart_lock_body("").is_none());
        assert!(super::parse_autostart_lock_body("abc\n123\nhost\n").is_none());
        assert!(super::parse_autostart_lock_body("123\nabc\nhost\n").is_none());
        assert!(super::parse_autostart_lock_body("123\n456\n").is_none());
        assert!(super::parse_autostart_lock_body("123\n456\n\n").is_none()); // empty hostname
    }

    #[test]
    fn test_acquire_autostart_lock_creates_parent_dirs() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("deep/nested/dir/autostart.lock");

        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(lock.is_ok(), "Should create parent directories");
        assert!(lock_path.exists(), "Lock file should exist");
    }

    // ========================================================================
    // t13 follow-up — rchd launch should return quickly for a live daemon,
    // but immediate launch failures should still surface.
    // ========================================================================

    #[cfg(unix)]
    #[test]
    fn test_spawn_rchd_returns_quickly_for_live_child() {
        let _guard = test_guard!();
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = create_test_state_dir();
        let fake_rchd = temp_dir.path().join("rchd");
        std::fs::write(&fake_rchd, "#!/usr/bin/env sh\nsleep 3.0\n").expect("write fake rchd");
        let mut perms = std::fs::metadata(&fake_rchd)
            .expect("fake rchd metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_rchd, perms).expect("chmod fake rchd");

        let started = std::time::Instant::now();
        super::spawn_rchd(&fake_rchd, &temp_dir.path().join("test.sock")).expect("spawn fake rchd");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(1500),
            "spawn_rchd should not wait for the daemon body to finish; elapsed={elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_spawn_rchd_reports_immediate_child_failure() {
        let _guard = test_guard!();
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = create_test_state_dir();
        let fake_rchd = temp_dir.path().join("rchd");
        std::fs::write(&fake_rchd, "#!/usr/bin/env sh\nexit 42\n").expect("write fake rchd");
        let mut perms = std::fs::metadata(&fake_rchd)
            .expect("fake rchd metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_rchd, perms).expect("chmod fake rchd");

        // The detection window is deliberately bounded (~150ms) by the
        // live-child latency contract, so under parallel-test scheduler load
        // a single attempt can miss a child that took >150ms to start+exit.
        // Retry a few times: if detection is BROKEN every attempt returns Ok
        // and the test still fails; if it works, an attempt catches the exit.
        let mut caught = None;
        for _ in 0..5 {
            if let Err(err) = super::spawn_rchd(&fake_rchd, &temp_dir.path().join("test.sock")) {
                caught = Some(err);
                break;
            }
        }
        let err = caught.expect("child failure should surface within 5 attempts");
        assert!(
            matches!(err, super::AutoStartError::WrapperFailed(status) if status.code() == Some(42)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_auto_start_config_disabled() {
        let temp_dir = create_test_state_dir();
        let socket_path = temp_dir.path().join("test.sock");

        let config = rch_common::SelfHealingConfig {
            hook_starts_daemon: false,
            ..Default::default()
        };

        let result = super::try_auto_start_daemon(&config, &socket_path).await;

        assert!(result.is_err(), "Should return error when disabled");
        assert!(
            matches!(result.unwrap_err(), super::AutoStartError::Disabled),
            "Error should be Disabled"
        );
    }

    #[tokio::test]
    async fn test_socket_is_confirmed_stale_false_for_live_listener() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let socket_path = temp_dir.path().join("test.sock");
        let _listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        assert!(
            !super::socket_is_confirmed_stale(&socket_path).await,
            "live listener must not be treated as stale"
        );
    }

    #[tokio::test]
    async fn test_socket_is_confirmed_stale_true_for_dropped_listener() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let socket_path = temp_dir.path().join("test.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        drop(listener);

        for _ in 0..20 {
            if super::socket_is_confirmed_stale(&socket_path).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            super::socket_is_confirmed_stale(&socket_path).await,
            "dropped listener should leave a stale socket path"
        );
    }

    // Note: Tests that require env var manipulation are marked with #[ignore] for safety.
    // Env var manipulation in tests can cause data races and is unsafe in Rust 2024 edition.
    // The core functionality is tested via the helper functions that don't depend on env vars.

    #[test]
    fn test_autostart_state_dir_returns_path() {
        let _guard = test_guard!();
        // Basic test that autostart_state_dir returns a valid path
        // (without manipulating env vars which is unsafe)
        let dir = super::autostart_state_dir();
        assert!(!dir.as_os_str().is_empty(), "Path should not be empty");
        assert!(
            dir.to_string_lossy().contains("rch"),
            "Path should contain 'rch'"
        );
    }

    #[test]
    fn test_autostart_lock_path_ends_with_expected_name() {
        let _guard = test_guard!();
        let path = super::autostart_lock_path();
        assert!(
            path.file_name()
                .map(|n| n == "hook_autostart.lock")
                .unwrap_or(false),
            "Lock path should end with hook_autostart.lock"
        );
    }

    #[test]
    fn test_autostart_cooldown_path_ends_with_expected_name() {
        let _guard = test_guard!();
        let path = super::autostart_cooldown_path();
        assert!(
            path.file_name()
                .map(|n| n == "hook_autostart.cooldown")
                .unwrap_or(false),
            "Cooldown path should end with hook_autostart.cooldown"
        );
    }

    // =========================================================================
    // Cooldown Integration Tests (bd-59kg)
    // =========================================================================
    //
    // Note: Full integration tests for cooldown behavior in try_auto_start_daemon
    // would require manipulating the state directory via env vars, which is unsafe
    // in Rust 2024 (data races in parallel tests). The cooldown logic is tested via:
    //
    // 1. test_read_cooldown_timestamp_valid - validates reading timestamps works
    // 2. test_read_cooldown_timestamp_missing - validates missing file returns None
    // 3. test_write_cooldown_timestamp_creates_file - validates writing timestamps
    // 4. test_auto_start_config_disabled - validates early exit when disabled
    //
    // The integration flow in try_auto_start_daemon is:
    //   cooldown_path = autostart_cooldown_path()
    //   if read_cooldown_timestamp(path).elapsed() < config.cooldown_secs:
    //       return Err(CooldownActive)
    //   ... proceed with daemon start ...
    //   write_cooldown_timestamp(path)

    #[test]
    fn test_autostart_error_cooldown_active_variant() {
        let _guard = test_guard!();
        // TEST START: AutoStartError::CooldownActive has expected structure
        let error = super::AutoStartError::CooldownActive(15, 30);

        // Verify debug formatting includes timing info
        let debug = format!("{:?}", error);
        assert!(
            debug.contains("CooldownActive"),
            "Debug should contain variant name"
        );
        assert!(debug.contains("15"), "Debug should contain elapsed seconds");
        assert!(
            debug.contains("30"),
            "Debug should contain cooldown threshold"
        );

        // Verify it's a distinct error variant
        assert!(
            !matches!(error, super::AutoStartError::Disabled),
            "Should not be Disabled"
        );
        assert!(
            !matches!(error, super::AutoStartError::LockHeld),
            "Should not be LockHeld"
        );
        // TEST PASS: CooldownActive error variant
    }

    #[test]
    fn test_cooldown_logic_simulation() {
        let _guard = test_guard!();
        // TEST START: Simulate cooldown logic without touching real state files
        // This mirrors the logic in try_auto_start_daemon lines 628-640

        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");
        let cooldown_secs: u64 = 30;

        // Case 1: No cooldown file -> should proceed
        let last_attempt = super::read_cooldown_timestamp(&cooldown_path);
        assert!(
            last_attempt.is_none(),
            "No file means no cooldown active - should proceed"
        );

        // Case 2: Recent cooldown file -> should block
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Write timestamp from 10 seconds ago (within 30s cooldown)
        std::fs::write(&cooldown_path, format!("{}", now - 10)).unwrap();

        let last_attempt = super::read_cooldown_timestamp(&cooldown_path).unwrap();
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        assert!(
            elapsed < cooldown_secs,
            "Elapsed {} should be < cooldown {} - should block",
            elapsed,
            cooldown_secs
        );

        // Case 3: Old cooldown file -> should proceed
        // Write timestamp from 60 seconds ago (outside 30s cooldown)
        std::fs::write(&cooldown_path, format!("{}", now - 60)).unwrap();

        let last_attempt = super::read_cooldown_timestamp(&cooldown_path).unwrap();
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        assert!(
            elapsed >= cooldown_secs,
            "Elapsed {} should be >= cooldown {} - should proceed",
            elapsed,
            cooldown_secs
        );
        // TEST PASS: Cooldown logic simulation
    }

    #[test]
    fn test_cooldown_file_update_after_attempt() {
        let _guard = test_guard!();
        // TEST START: Verify cooldown timestamp is updated after write
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("subdir/cooldown");

        // Write initial cooldown
        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "First write should succeed");

        let timestamp1 = std::fs::read_to_string(&cooldown_path).unwrap();
        let ts1: u64 = timestamp1
            .trim()
            .parse()
            .expect("cooldown timestamp must be a unix seconds integer");

        // Sleep briefly and write again
        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "Second write should succeed");

        let timestamp2 = std::fs::read_to_string(&cooldown_path).unwrap();
        let ts2: u64 = timestamp2
            .trim()
            .parse()
            .expect("cooldown timestamp must be a unix seconds integer");

        assert!(
            ts2 >= ts1,
            "Second write should be >= first write (ts2={ts2} >= ts1={ts1})"
        );
        // TEST PASS: Cooldown file update
    }

    /// Single-response server with no environment mutation or real daemon.
    async fn probe_test_response(response: &[u8]) -> bool {
        let dir = create_test_state_dir();
        let socket = dir.path().join("health.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let response = response.to_vec();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 12];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"GET /health\n");
            // Oversize rejection may close the connection before all bytes fit.
            let _ = stream.write_all(&response).await;
        });
        let healthy = probe_daemon_health(&socket).await;
        server.await.unwrap();
        healthy
    }

    #[tokio::test]
    async fn health_probe_accepts_valid_http_responses() {
        for response in [
            &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"healthy\"}"[..],
            &b"HTTP/1.0 200 OK\n\n{\"status\":\"healthy\"}\n"[..],
        ] {
            assert!(probe_test_response(response).await);
        }
    }

    #[tokio::test]
    async fn health_probe_rejects_invalid_status_or_body() {
        for response in [
            &b"HTTP/1.1 503 Unavailable\n\n{\"status\":\"healthy\"}"[..],
            &b"not-http 200 OK\n\n{\"status\":\"healthy\"}"[..],
            &b"{\"status\":\"healthy\"}"[..],
            &b"HTTP/1.1 200 OK\n\n{\"status\":\"degraded\"}"[..],
            &b"HTTP/1.1 200 OK\n\n{\"status\":"[..],
            &b"HTTP/1.1 200 OK\n\n\xff"[..],
        ] {
            assert!(!probe_test_response(response).await, "response: {response:?}");
        }
    }

    #[tokio::test]
    async fn health_probe_rejects_oversize_responses() {
        let mut response = b"HTTP/1.1 200 OK\n\n{\"status\":\"healthy\",\"padding\":\"".to_vec();
        response.extend(std::iter::repeat_n(b'x', 100 * 1024));
        response.extend_from_slice(b"\"}");
        assert!(!probe_test_response(&response).await);
    }

    #[tokio::test]
    async fn health_probe_trickle_cannot_extend_the_deadline() {
        let dir = create_test_state_dir();
        let socket = dir.path().join("trickle.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            loop {
                if stream.write_all(b"X-Progress: still starting\n").await.is_err() {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        });
        let result = timeout(Duration::from_secs(2), probe_daemon_health(&socket)).await;
        server.abort();
        let _ = server.await;
        assert!(!result.expect("per-line traffic must not renew the deadline"));
    }

    #[tokio::test]
    async fn readiness_wait_bounds_a_stalled_probe() {
        let dir = create_test_state_dir();
        let socket = dir.path().join("stalled.sock");
        // A listener that never handles requests still accepts connections.
        let _listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let result = timeout(
            Duration::from_millis(200),
            wait_for_socket(&socket, Duration::from_millis(30)),
        )
        .await;
        assert!(!result.expect("the 300ms probe must obey the shorter wait budget"));
    }

    #[tokio::test]
    async fn readiness_wait_observes_a_delayed_daemon() {
        let dir = create_test_state_dir();
        let socket = dir.path().join("delayed.sock");
        let server_socket = socket.clone();
        let server = tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            let listener = tokio::net::UnixListener::bind(&server_socket).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 12];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\n\n{\"status\":\"healthy\"}").await.unwrap();
        });
        assert!(wait_for_socket(&socket, Duration::from_secs(2)).await);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn readiness_zero_budget_does_not_connect() {
        let dir = create_test_state_dir();
        let socket = dir.path().join("zero.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        assert!(!wait_for_socket(&socket, Duration::ZERO).await);
        assert!(timeout(Duration::from_millis(20), listener.accept()).await.is_err());
    }

    fn recovery_config() -> SelfHealingConfig {
        SelfHealingConfig {
            hook_starts_daemon: true,
            auto_start_timeout_secs: 1,
            auto_start_cooldown_secs: 30,
            ..Default::default()
        }
    }

    fn healthy_daemon_after(socket: PathBuf, delay: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            sleep(delay).await;
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 12];
                if stream.read_exact(&mut request).await.is_ok() {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\n\n{\"status\":\"healthy\"}")
                        .await;
                }
            }
        })
    }

    #[tokio::test]
    async fn recovery_observes_another_starter_without_stealing_its_lock() {
        let dir = create_test_state_dir();
        let socket = dir.path().join("daemon.sock");
        let lock_path = dir.path().join("start.lock");
        let cooldown = dir.path().join("cooldown");
        let lock = acquire_autostart_lock(&lock_path).unwrap();
        let body = std::fs::read(&lock_path).unwrap();
        let server = healthy_daemon_after(socket.clone(), Duration::from_millis(20));
        let result = recover_daemon_with_paths(
            &recovery_config(),
            &socket,
            &lock_path,
            &cooldown,
            |_| panic!("a lock follower must never spawn"),
        )
        .await;
        server.abort();
        let _ = server.await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(std::fs::read(&lock_path).unwrap(), body);
        assert!(!cooldown.exists());
        drop(lock);
    }

    #[tokio::test]
    async fn recovery_coalesces_simultaneous_clients_into_one_launch() {
        let dir = create_test_state_dir();
        let socket = dir.path().join("daemon.sock");
        let lock_path = dir.path().join("start.lock");
        let cooldown = dir.path().join("cooldown");
        let starts = std::sync::atomic::AtomicUsize::new(0);
        let mut first_server = None;
        let mut second_server = None;
        let config = recovery_config();
        let (first, second) = tokio::join!(
            recover_daemon_with_paths(&config, &socket, &lock_path, &cooldown, |path| {
                starts.fetch_add(1, Ordering::SeqCst);
                first_server = Some(healthy_daemon_after(path.into(), Duration::from_millis(20)));
                Ok(())
            }),
            recover_daemon_with_paths(&config, &socket, &lock_path, &cooldown, |path| {
                starts.fetch_add(1, Ordering::SeqCst);
                second_server = Some(healthy_daemon_after(path.into(), Duration::from_millis(20)));
                Ok(())
            }),
        );
        for server in first_server.into_iter().chain(second_server) {
            server.abort();
            let _ = server.await;
        }
        assert!(first.is_ok(), "{first:?}");
        assert!(second.is_ok(), "{second:?}");
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert!(!lock_path.exists());
        assert!(cooldown.exists());
    }

    #[tokio::test]
    async fn recovery_observes_a_previous_launch_during_cooldown() {
        let dir = create_test_state_dir();
        let socket = dir.path().join("daemon.sock");
        let lock_path = dir.path().join("start.lock");
        let cooldown = dir.path().join("cooldown");
        write_cooldown_timestamp(&cooldown).unwrap();
        let original = std::fs::read(&cooldown).unwrap();
        let server = healthy_daemon_after(socket.clone(), Duration::from_millis(20));
        let result = recover_daemon_with_paths(
            &recovery_config(),
            &socket,
            &lock_path,
            &cooldown,
            |_| panic!("cooldown must prevent a second launch"),
        )
        .await;
        server.abort();
        let _ = server.await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(std::fs::read(&cooldown).unwrap(), original);
        assert!(!lock_path.exists());
    }

    #[tokio::test]
    async fn recovery_preserves_live_unhealthy_listeners_within_one_budget() {
        use std::os::unix::fs::MetadataExt;
        let dir = create_test_state_dir();
        let socket = dir.path().join("daemon.sock");
        let lock_path = dir.path().join("start.lock");
        let cooldown = dir.path().join("cooldown");
        let _listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let inode = std::fs::metadata(&socket).unwrap().ino();
        let result = timeout(
            Duration::from_millis(1500),
            recover_daemon_with_paths(
                &recovery_config(),
                &socket,
                &lock_path,
                &cooldown,
                |_| panic!("never replace a possible live daemon"),
            ),
        )
        .await
        .expect("all probes must share the one-second recovery budget");
        assert!(result.is_err());
        assert_eq!(std::fs::metadata(&socket).unwrap().ino(), inode);
        assert!(!cooldown.exists());
        assert!(!lock_path.exists());
    }

    #[tokio::test]
    async fn recovery_does_not_unlink_a_stale_socket_during_cooldown() {
        use std::os::unix::fs::MetadataExt;
        let dir = create_test_state_dir();
        let socket = dir.path().join("daemon.sock");
        let lock_path = dir.path().join("start.lock");
        let cooldown = dir.path().join("cooldown");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        drop(listener);
        let inode = std::fs::metadata(&socket).unwrap().ino();
        write_cooldown_timestamp(&cooldown).unwrap();
        let result = recover_daemon_with_paths(
            &recovery_config(),
            &socket,
            &lock_path,
            &cooldown,
            |_| panic!("cooldown must prevent launch"),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(std::fs::metadata(&socket).unwrap().ino(), inode);
        assert!(!lock_path.exists());
    }

    #[tokio::test]
    async fn recovery_never_deletes_regular_files_or_symlinks() {
        let dir = create_test_state_dir();
        let regular = dir.path().join("not-a-socket");
        let link = dir.path().join("socket-link");
        std::fs::write(&regular, b"keep me").unwrap();
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        for socket in [&regular, &link] {
            let result = recover_daemon_with_paths(
                &recovery_config(),
                socket,
                &dir.path().join("start.lock"),
                &dir.path().join("cooldown"),
                |_| panic!("invalid endpoint must not launch"),
            )
            .await;
            assert!(matches!(result, Err(AutoStartError::StaleSocket)));
        }
        assert_eq!(std::fs::read(&regular).unwrap(), b"keep me");
        assert_eq!(std::fs::read_link(&link).unwrap(), regular);
    }

    #[tokio::test]
    async fn recovery_zero_budget_has_no_side_effects() {
        let dir = create_test_state_dir();
        let lock_path = dir.path().join("state/start.lock");
        let cooldown = dir.path().join("state/cooldown");
        let mut config = recovery_config();
        config.auto_start_timeout_secs = 0;
        let result = recover_daemon_with_paths(
            &config,
            &dir.path().join("daemon.sock"),
            &lock_path,
            &cooldown,
            |_| panic!("zero budget must not launch"),
        )
        .await;
        assert!(matches!(result, Err(AutoStartError::Timeout(0))));
        assert!(!dir.path().join("state").exists());
    }

    #[tokio::test]
    async fn recovery_future_cooldown_does_not_permanently_disable_startup() {
        let dir = create_test_state_dir();
        let socket = dir.path().join("daemon.sock");
        let lock_path = dir.path().join("start.lock");
        let cooldown = dir.path().join("cooldown");
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        std::fs::write(&cooldown, future.to_string()).unwrap();
        let mut server = None;
        let result = recover_daemon_with_paths(
            &recovery_config(),
            &socket,
            &lock_path,
            &cooldown,
            |path| {
                server = Some(healthy_daemon_after(path.into(), Duration::ZERO));
                Ok(())
            },
        )
        .await;
        let server = server.expect("future cooldown must permit repair");
        server.abort();
        let _ = server.await;
        assert!(result.is_ok(), "{result:?}");
        assert!(
            read_cooldown_timestamp(&cooldown)
                .unwrap()
                .elapsed()
                .is_ok()
        );
    }

    #[test]
    fn recovery_corrupt_extreme_timestamp_cannot_panic() {
        let dir = create_test_state_dir();
        let cooldown = dir.path().join("cooldown");
        std::fs::write(&cooldown, u64::MAX.to_string()).unwrap();
        assert!(read_cooldown_timestamp(&cooldown).is_none());
    }

    #[tokio::test]
    async fn recovery_preserves_launch_failure_and_releases_ownership() {
        let dir = create_test_state_dir();
        let lock_path = dir.path().join("start.lock");
        let cooldown = dir.path().join("cooldown");
        let result = recover_daemon_with_paths(
            &recovery_config(),
            &dir.path().join("daemon.sock"),
            &lock_path,
            &cooldown,
            |_| Err(AutoStartError::BinaryNotFound),
        )
        .await;
        assert!(matches!(result, Err(AutoStartError::BinaryNotFound)));
        assert!(!lock_path.exists());
        assert!(
            cooldown.exists(),
            "failed launches must still be rate limited"
        );
    }

    #[test]
    fn spawn_rchd_pins_the_requested_socket_without_shell_splitting() {
        let dir = create_test_state_dir();
        let binary = dir.path().join("rchd with spaces");
        let socket = dir.path().join("daemon with spaces.sock");
        std::fs::write(
            &binary,
            concat!(
                "#!/bin/sh\n",
                "[ \"$#\" -eq 2 ] || exit 41\n",
                "[ \"$1\" = --socket ] || exit 42\n",
                "printf '%s' \"$2\" > \"$2.received\"\n",
            ),
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        spawn_rchd(&binary, &socket).unwrap();
        let receipt = dir.path().join("daemon with spaces.sock.received");
        // The bounded launcher may return before a heavily loaded child runs.
        let deadline = Instant::now() + Duration::from_secs(2);
        while !receipt.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read(receipt).unwrap(),
            socket.as_os_str().as_encoded_bytes()
        );
    }

    #[test]
    fn startup_gate_protects_unpublished_sentinel() {
        let dir = create_test_state_dir();
        let path = dir.path().join("start.lock");
        let gate = acquire_autostart_gate(&path).unwrap();
        // Simulate a pause between create_new and the first body write.
        std::fs::write(&path, "").unwrap();
        assert!(matches!(
            acquire_autostart_lock(&path),
            Err(AutoStartError::LockHeld)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        drop(gate);
        assert!(acquire_autostart_lock(&path).is_ok());
    }

    #[test]
    fn startup_gate_prevents_ttl_takeover_of_a_live_owner() {
        let dir = create_test_state_dir();
        let path = dir.path().join("start.lock");
        let owner = acquire_autostart_lock(&path).unwrap();
        write_lockfile(&path, std::process::id(), 120, &our_hostname());
        assert!(matches!(
            acquire_autostart_lock(&path),
            Err(AutoStartError::LockHeld)
        ));
        drop(owner);
        assert!(acquire_autostart_lock(&path).is_ok());
    }

    #[test]
    fn startup_gate_inode_survives_owner_release() {
        use std::os::unix::fs::MetadataExt;

        let dir = create_test_state_dir();
        let path = dir.path().join("start.lock");
        let gate_path = dir.path().join("start.lock.gate");
        let owner = acquire_autostart_lock(&path).unwrap();
        let inode = std::fs::metadata(&gate_path).unwrap().ino();
        drop(owner);
        assert!(!path.exists());
        let next_owner = acquire_autostart_lock(&path).unwrap();
        assert_eq!(std::fs::metadata(&gate_path).unwrap().ino(), inode);
        drop(next_owner);
        assert_eq!(std::fs::metadata(&gate_path).unwrap().ino(), inode);
    }

    #[test]
    fn startup_gate_is_released_after_sentinel_refusal() {
        let dir = create_test_state_dir();
        let path = dir.path().join("start.lock");
        write_lockfile(&path, std::process::id(), 0, &our_hostname());
        assert!(matches!(
            acquire_autostart_lock(&path),
            Err(AutoStartError::LockHeld)
        ));
        // Refusing a legacy owner must not leave our kernel gate locked.
        std::fs::write(&path, "invalid legacy body").unwrap();
        assert!(acquire_autostart_lock(&path).is_ok());
    }
}
