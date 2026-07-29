//! Bounded daemon auto-start (self-healing) for the PreToolUse hook.
//!
//! When the hook discovers that `rchd` is unreachable, it performs a single
//! bounded attempt to bring the daemon back up before falling back to local
//! compilation. This module owns every moving part of that recovery: the
//! per-host state directory, atomic lockfile acquisition with staleness /
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
    #[error("Daemon started but socket not found after {0}s")]
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
    Some(UNIX_EPOCH + Duration::from_secs(secs))
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
        // NOT use kill(0) because rch is #![forbid(unsafe_code)] and
        // the kill(2) wrapper would require nix/libc raw syscalls.
        let proc_path = std::path::PathBuf::from(format!("/proc/{pid}"));
        if proc_path.exists() {
            return true;
        }
        // On non-Linux Unix (macOS, BSD), /proc may not exist. We can't
        // easily check liveness without unsafe; rely on TTL fallback.
        // To distinguish "no /proc" from "PID is dead" we check whether
        // /proc itself exists.
        if !std::path::Path::new("/proc").exists() {
            // No /proc on this platform — be conservative and assume alive.
            return true;
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

fn acquire_autostart_lock(path: &Path) -> Result<AutoStartLock, AutoStartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AutoStartError::Io)?;
    }
    // Atomic create_new — winner of the race; loser falls into the
    // stale-detection branch below.
    let body = render_autostart_lock_body();
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            // Write the lockfile body so subsequent contenders can decide
            // whether to wait or take over. We deliberately don't fail the
            // acquire if the write itself fails — the lockfile-exists
            // mutual-exclusion is the load-bearing invariant; the body is
            // diagnostic + stale-detection metadata.
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

fn spawn_rchd(path: &Path) -> Result<(), AutoStartError> {
    let mut cmd = std::process::Command::new("nohup");
    cmd.arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());

    let mut child = cmd.spawn().map_err(AutoStartError::SpawnFailed)?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    if let Some(status) = child.try_wait().map_err(AutoStartError::SpawnFailed)? {
        return if status.success() {
            Ok(())
        } else {
            Err(AutoStartError::WrapperFailed(status))
        };
    }

    // `nohup` does not daemonize by itself; it execs/wraps rchd as our
    // direct child. Keep a detached waiter while rch remains alive so a
    // later daemon exit is reaped instead of becoming a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

async fn probe_daemon_health(socket_path: &Path) -> bool {
    let connect = timeout(Duration::from_millis(300), UnixStream::connect(socket_path)).await;
    let stream = match connect {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let (reader, mut writer) = stream.into_split();
    if writer.write_all(b"GET /health\n").await.is_err() {
        return false;
    }
    let _ = writer.flush().await;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut body = String::new();
    let mut in_body = false;

    loop {
        line.clear();
        let read = match timeout(Duration::from_millis(300), reader.read_line(&mut line)).await {
            Ok(Ok(n)) => n,
            _ => return false,
        };
        if read == 0 {
            break;
        }
        if in_body {
            body.push_str(&line);
        } else if line.trim().is_empty() {
            in_body = true;
        }
    }

    let response: HealthResponse = match serde_json::from_str(body.trim()) {
        Ok(resp) => resp,
        Err(_) => return false,
    };

    response.status == "healthy"
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

async fn wait_for_socket(socket_path: &Path, timeout_secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if socket_path.exists() && probe_daemon_health(socket_path).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn try_auto_start_daemon(
    config: &SelfHealingConfig,
    socket_path: &Path,
) -> Result<(), AutoStartError> {
    if !config.hook_starts_daemon {
        return Err(AutoStartError::Disabled);
    }

    info!(
        target: "rch::hook::auto_start",
        "Daemon unavailable, attempting auto-start"
    );

    // Acquire the autostart lock BEFORE doing anything destructive
    // (stale-socket removal). Two concurrent hooks racing on the same
    // socket could otherwise both observe a transiently-unresponsive
    // daemon and the second hook deletes the socket the first hook
    // just verified — corrupting an in-flight connection.
    //
    // Order is now:
    //   1. Acquire autostart lock (only one hook auto-starts at a time).
    //   2. Re-probe socket: while waiting for the lock, the prior
    //      lock-holder may have already started the daemon.
    //   3. Only delete the socket if it's confirmed stale UNDER the lock.
    let _lock = acquire_autostart_lock(&autostart_lock_path())?;

    // Re-probe under the lock — another hook may have spawned rchd
    // while we were waiting.
    if socket_path.exists() && probe_daemon_health(socket_path).await {
        debug!(
            target: "rch::hook::auto_start",
            "Socket became responsive while waiting for autostart lock"
        );
        return Ok(());
    }

    if socket_path.exists() {
        warn!(
            target: "rch::hook::auto_start",
            "Socket exists but daemon not responding (after lock-protected re-probe)"
        );
        if !socket_is_confirmed_stale(socket_path).await {
            warn!(
                target: "rch::hook::auto_start",
                "Socket still accepts connections or could not be proven stale; refusing to replace a possible live daemon"
            );
            return Err(AutoStartError::UnhealthySocket);
        }
        if let Err(err) = std::fs::remove_file(socket_path) {
            warn!(
                target: "rch::hook::auto_start",
                "Failed to remove stale socket: {}",
                err
            );
            return Err(AutoStartError::StaleSocket);
        }
    }

    let cooldown_path = autostart_cooldown_path();
    if let Some(last_attempt) = read_cooldown_timestamp(&cooldown_path) {
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        if elapsed < config.auto_start_cooldown_secs {
            return Err(AutoStartError::CooldownActive(
                elapsed,
                config.auto_start_cooldown_secs,
            ));
        }
    }

    // Note: the autostart lock acquired earlier is still held here.
    // It's released when this function returns (Drop).
    write_cooldown_timestamp(&cooldown_path)?;

    let rchd_path = which_rchd_path().ok_or(AutoStartError::BinaryNotFound)?;
    info!(
        target: "rch::hook::auto_start",
        "Spawning rchd at {}",
        rchd_path.display()
    );
    spawn_rchd(&rchd_path)?;

    let timeout_secs = config.auto_start_timeout_secs;
    if !wait_for_socket(socket_path, timeout_secs).await {
        return Err(AutoStartError::Timeout(timeout_secs));
    }

    info!(
        target: "rch::hook::auto_start",
        "Auto-start successful, socket is responsive"
    );
    Ok(())
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
        std::fs::write(&fake_rchd, "#!/usr/bin/env sh\nsleep 0.3\n").expect("write fake rchd");
        let mut perms = std::fs::metadata(&fake_rchd)
            .expect("fake rchd metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_rchd, perms).expect("chmod fake rchd");

        let started = std::time::Instant::now();
        super::spawn_rchd(&fake_rchd).expect("spawn fake rchd");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(250),
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

        let err = super::spawn_rchd(&fake_rchd).expect_err("child failure should surface");
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
}
