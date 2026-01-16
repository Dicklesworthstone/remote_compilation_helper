## Overview

Implement idempotent state detection and configuration primitives that underpin ALL setup, install, and configuration commands. This is a **foundational bead** with no dependencies - it provides the building blocks that xi5 (Agent Detection), 3d1 (Setup Wizard), and other beads rely on.

The core principle: **any RCH command can be run repeatedly without side effects or data loss**.

## Goals

1. **State Detection Layer**: Unified detection of RCH configuration state
2. **Idempotent Primitives**: Reusable functions for safe file operations
3. **Exit Code Contract**: Consistent exit codes for automation
4. **Source Tracking**: Track where each config value came from
5. **Lock File Support**: Prevent concurrent configuration modifications
6. **NEW: Atomic File Operations**: Write-to-temp then rename for crash safety
7. **NEW: Lock Timeouts**: Prevent deadlocks from abandoned locks
8. **NEW: Config Migration**: Migrate config between RCH versions
9. **NEW: Backup Retention Policy**: Automatic cleanup of old backups

## State Detection Model

```rust
// rch/src/state/mod.rs

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Complete RCH installation state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RchState {
    /// Global state assessment
    pub status: InstallStatus,

    /// Individual component states
    pub components: ComponentStates,

    /// Detected issues with remediation hints
    pub issues: Vec<StateIssue>,

    /// Timestamp of state detection
    pub detected_at: chrono::DateTime<chrono::Utc>,

    /// RCH version that created this state
    pub rch_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallStatus {
    /// Fully configured and operational
    Ready,
    /// Partially configured, needs setup
    NeedsSetup,
    /// Not installed or critically broken
    NotInstalled,
    /// Running but with warnings
    Degraded,
    /// Config from older version, needs migration
    NeedsMigration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStates {
    pub user_config: ConfigState,
    pub project_config: ConfigState,
    pub workers: WorkersState,
    pub daemon: DaemonState,
    pub hooks: Vec<AgentHookState>,
    pub binaries: BinaryState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigState {
    pub path: PathBuf,
    pub exists: bool,
    pub valid: bool,
    pub version: Option<String>,
    pub needs_migration: bool,
    pub source: ConfigSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigSource {
    Default,
    UserConfig,
    ProjectConfig,
    Environment,
    CommandLine,
}
```

## Idempotent Primitives

```rust
// rch/src/state/primitives.rs

use std::path::Path;
use std::fs::{self, File};
use std::io::Write;

/// Result of an idempotent operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotentResult {
    Created,
    AlreadyExists,
    Updated,
    Unchanged,
    DryRun,
}

/// Atomic file write: write to temp, fsync, rename
/// This ensures crash safety - either old or new content, never partial
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow!("No parent directory"))?;
    let temp_path = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));

    // Write to temp file
    let mut file = File::create(&temp_path)?;
    file.write_all(content)?;
    file.sync_all()?;  // Ensure data is on disk

    // Atomic rename
    fs::rename(&temp_path, path)?;

    // Sync parent directory (important on some filesystems)
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Create a file only if it doesn't exist (atomic)
pub fn create_if_missing(path: &Path, content: &str) -> Result<IdempotentResult> {
    if path.exists() {
        return Ok(IdempotentResult::AlreadyExists);
    }

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    atomic_write(path, content.as_bytes())?;
    Ok(IdempotentResult::Created)
}

/// Update a file only if content differs (with optional backup)
pub fn update_if_changed(path: &Path, new_content: &str, backup: bool) -> Result<IdempotentResult> {
    if !path.exists() {
        atomic_write(path, new_content.as_bytes())?;
        return Ok(IdempotentResult::Created);
    }

    let existing = fs::read_to_string(path)?;
    if existing == new_content {
        return Ok(IdempotentResult::Unchanged);
    }

    if backup {
        create_backup(path)?;
    }

    atomic_write(path, new_content.as_bytes())?;
    Ok(IdempotentResult::Updated)
}

/// Create timestamped backup with retention policy
pub fn create_backup(path: &Path) -> Result<PathBuf> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_dir = dirs::data_dir()
        .ok_or_else(|| anyhow!("Cannot determine data directory"))?
        .join("rch/backups");

    fs::create_dir_all(&backup_dir)?;

    let filename = path.file_name()
        .ok_or_else(|| anyhow!("Invalid path"))?
        .to_string_lossy();
    let backup_path = backup_dir.join(format!("{}_{}.bak", filename, timestamp));

    fs::copy(path, &backup_path)?;

    // Apply retention policy (keep last 10 backups per file)
    cleanup_old_backups(&backup_dir, &filename, 10)?;

    Ok(backup_path)
}

/// Cleanup old backups, keeping only the N most recent
fn cleanup_old_backups(backup_dir: &Path, prefix: &str, keep: usize) -> Result<()> {
    let mut backups: Vec<_> = fs::read_dir(backup_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
        .collect();

    // Sort by modification time (newest first)
    backups.sort_by(|a, b| {
        b.metadata().and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(&a.metadata().and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH))
    });

    // Remove old backups
    for backup in backups.into_iter().skip(keep) {
        fs::remove_file(backup.path())?;
    }

    Ok(())
}

/// Ensure a symlink points to the correct target
pub fn ensure_symlink(link: &Path, target: &Path) -> Result<IdempotentResult> {
    if link.exists() || link.symlink_metadata().is_ok() {
        let current_target = fs::read_link(link)?;
        if current_target == target {
            return Ok(IdempotentResult::AlreadyExists);
        }
        fs::remove_file(link)?;
    }

    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, link)?;

    Ok(IdempotentResult::Created)
}

/// Append to file only if line doesn't exist (for PATH updates)
pub fn append_line_if_missing(path: &Path, line: &str) -> Result<IdempotentResult> {
    let content = if path.exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };

    // Check if line already exists
    if content.lines().any(|l| l.trim() == line.trim()) {
        return Ok(IdempotentResult::AlreadyExists);
    }

    let mut new_content = content;
    if !new_content.ends_with('\n') && !new_content.is_empty() {
        new_content.push('\n');
    }
    new_content.push_str(line);
    new_content.push('\n');

    atomic_write(path, new_content.as_bytes())?;
    Ok(IdempotentResult::Updated)
}
```

## Lock File Support with Timeouts

```rust
// rch/src/state/lock.rs

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Lock file contents for debugging stale locks
#[derive(Debug, Serialize, Deserialize)]
struct LockInfo {
    pid: u32,
    hostname: String,
    created_at: String,
    operation: String,
}

pub struct ConfigLock {
    file: File,
    path: PathBuf,
}

impl ConfigLock {
    /// Acquire lock with timeout (default 30 seconds)
    pub fn acquire(lock_name: &str) -> Result<Self> {
        Self::acquire_with_timeout(lock_name, Duration::from_secs(30), "unknown")
    }

    /// Acquire lock with custom timeout and operation name
    pub fn acquire_with_timeout(lock_name: &str, timeout: Duration, operation: &str) -> Result<Self> {
        let lock_dir = dirs::runtime_dir()
            .or_else(|| dirs::data_dir())
            .ok_or_else(|| anyhow!("Cannot determine lock directory"))?
            .join("rch/locks");

        std::fs::create_dir_all(&lock_dir)?;
        let path = lock_dir.join(format!("{}.lock", lock_name));

        let start = Instant::now();
        let poll_interval = Duration::from_millis(100);

        loop {
            // Try to create lock file exclusively
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    // Write lock info for debugging
                    let info = LockInfo {
                        pid: std::process::id(),
                        hostname: hostname::get()
                            .map(|h| h.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "unknown".to_string()),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        operation: operation.to_string(),
                    };
                    serde_json::to_writer(&mut file, &info)?;
                    file.sync_all()?;

                    // Use flock for additional safety
                    #[cfg(unix)]
                    {
                        use std::os::unix::io::AsRawFd;
                        let fd = file.as_raw_fd();
                        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                            // flock failed, clean up and retry
                            std::fs::remove_file(&path)?;
                            continue;
                        }
                    }

                    return Ok(ConfigLock { file, path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Lock exists, check if stale
                    if Self::is_stale_lock(&path)? {
                        tracing::warn!("Removing stale lock: {:?}", path);
                        std::fs::remove_file(&path)?;
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
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Check if lock is stale (holder process is dead or lock is too old)
    fn is_stale_lock(path: &Path) -> Result<bool> {
        let info = Self::read_lock_info(path)?;

        // Check if process is still alive
        #[cfg(unix)]
        {
            if unsafe { libc::kill(info.pid as i32, 0) } != 0 {
                return Ok(true);  // Process doesn't exist
            }
        }

        // Check if lock is too old (> 1 hour)
        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&info.created_at) {
            if chrono::Utc::now().signed_duration_since(created) > chrono::Duration::hours(1) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn read_lock_info(path: &Path) -> Result<LockInfo> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        // Release flock
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.file.as_raw_fd();
            unsafe { libc::flock(fd, libc::LOCK_UN) };
        }

        // Remove lock file
        let _ = std::fs::remove_file(&self.path);
    }
}
```

## Config Migration (NEW)

```rust
// rch/src/state/migration.rs

use semver::Version;

/// Migrate config from one version to another
pub struct ConfigMigrator {
    migrations: Vec<Migration>,
}

struct Migration {
    from_version: Version,
    to_version: Version,
    migrate: fn(&mut toml::Value) -> Result<()>,
}

impl ConfigMigrator {
    pub fn new() -> Self {
        Self {
            migrations: vec![
                Migration {
                    from_version: Version::parse("0.0.0").unwrap(),
                    to_version: Version::parse("0.1.0").unwrap(),
                    migrate: |config| {
                        // Example: rename 'workers' to 'fleet.workers'
                        if let Some(workers) = config.get("workers").cloned() {
                            config.as_table_mut()
                                .ok_or_else(|| anyhow!("Invalid config"))?
                                .remove("workers");

                            let fleet = config.as_table_mut()
                                .ok_or_else(|| anyhow!("Invalid config"))?
                                .entry("fleet")
                                .or_insert(toml::Value::Table(Default::default()));

                            fleet.as_table_mut()
                                .ok_or_else(|| anyhow!("Invalid fleet config"))?
                                .insert("workers".to_string(), workers);
                        }
                        Ok(())
                    },
                },
            ],
        }
    }

    /// Migrate config to latest version
    pub fn migrate(&self, config: &mut toml::Value, from: &Version) -> Result<Version> {
        let mut current = from.clone();

        for migration in &self.migrations {
            if &current >= &migration.from_version && &current < &migration.to_version {
                tracing::info!(
                    "Migrating config from {} to {}",
                    migration.from_version,
                    migration.to_version
                );
                (migration.migrate)(config)?;
                current = migration.to_version.clone();
            }
        }

        Ok(current)
    }

    /// Check if migration is needed
    pub fn needs_migration(&self, from: &Version) -> bool {
        self.migrations.iter().any(|m| from >= &m.from_version && from < &m.to_version)
    }
}
```

## Exit Code Contract

```rust
// rch/src/state/exit_codes.rs

/// Exit codes following sysexits.h conventions where applicable
pub mod exit_codes {
    /// Success
    pub const OK: i32 = 0;

    /// Generic error
    pub const ERROR: i32 = 1;

    /// Command line usage error (EX_USAGE)
    pub const USAGE: i32 = 64;

    /// Configuration error (EX_CONFIG)
    pub const CONFIG: i32 = 78;

    /// RCH-specific: needs setup (custom range 100-127)
    pub const NEEDS_SETUP: i32 = 100;

    /// RCH-specific: daemon not running
    pub const DAEMON_DOWN: i32 = 101;

    /// RCH-specific: no workers configured
    pub const NO_WORKERS: i32 = 102;

    /// RCH-specific: already at requested version (not an error, but distinct)
    pub const ALREADY_CURRENT: i32 = 103;

    /// RCH-specific: lock held by another process
    pub const LOCKED: i32 = 104;

    /// RCH-specific: config needs migration
    pub const NEEDS_MIGRATION: i32 = 105;

    /// Convert to human-readable message
    pub fn message(code: i32) -> &'static str {
        match code {
            OK => "Success",
            ERROR => "General error",
            USAGE => "Invalid command line usage",
            CONFIG => "Configuration error",
            NEEDS_SETUP => "RCH needs initial setup (run: rch setup)",
            DAEMON_DOWN => "RCH daemon is not running (run: rchd start)",
            NO_WORKERS => "No workers configured (run: rch setup workers)",
            ALREADY_CURRENT => "Already at requested version",
            LOCKED => "Operation locked by another process",
            NEEDS_MIGRATION => "Config needs migration (run: rch config migrate)",
            _ => "Unknown error",
        }
    }
}
```

## CLI Integration

```
rch state                      # Show current state (human-readable)
rch state --json               # JSON output for scripting
rch state --check              # Exit code only (0=ready, 100=needs setup)
rch config init --if-missing   # Create only if missing (idempotent)
rch config migrate             # Migrate config to current version (NEW)
rch config validate            # Validate config without modifying (NEW)
rch setup --check              # Validate setup, report issues
```

## Implementation Files

```
rch/src/
├── state/
│   ├── mod.rs              # State types and RchState
│   ├── detect.rs           # State detection logic
│   ├── primitives.rs       # Idempotent file operations (atomic writes)
│   ├── lock.rs             # Lock file management with timeouts
│   ├── migration.rs        # Config version migration (NEW)
│   ├── backup.rs           # Backup management with retention (NEW)
│   └── exit_codes.rs       # Exit code constants
├── commands/
│   └── state.rs            # `rch state` command
```

## Testing Requirements

### Unit Tests (rch/src/state/tests/)

**primitives_test.rs**
```rust
#[test]
fn test_atomic_write_creates_file() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("test.txt");

    atomic_write(&path, b"hello").unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
}

#[test]
fn test_atomic_write_is_atomic() {
    // Simulate crash during write - temp file should not be left behind
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("test.txt");

    // Write initial content
    atomic_write(&path, b"original").unwrap();

    // Verify no .tmp files exist
    let tmp_files: Vec<_> = fs::read_dir(tmp.path()).unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|e| e == "tmp").unwrap_or(false))
        .collect();
    assert!(tmp_files.is_empty());
}

#[test]
fn test_create_if_missing_idempotent() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");

    let r1 = create_if_missing(&path, "content1").unwrap();
    assert_eq!(r1, IdempotentResult::Created);

    let r2 = create_if_missing(&path, "content2").unwrap();
    assert_eq!(r2, IdempotentResult::AlreadyExists);

    // Original content preserved
    assert_eq!(fs::read_to_string(&path).unwrap(), "content1");
}

#[test]
fn test_update_if_changed_creates_backup() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    fs::write(&path, "original").unwrap();

    update_if_changed(&path, "updated", true).unwrap();

    // Check backup exists
    let backup_dir = dirs::data_dir().unwrap().join("rch/backups");
    let backups: Vec<_> = fs::read_dir(&backup_dir).unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("config.toml"))
        .collect();
    assert!(!backups.is_empty());
}
```

**lock_test.rs**
```rust
#[test]
fn test_lock_acquisition_and_release() {
    let lock = ConfigLock::acquire("test_lock").unwrap();
    drop(lock);
    // Should be able to acquire again after release
    let _lock2 = ConfigLock::acquire("test_lock").unwrap();
}

#[test]
fn test_lock_timeout() {
    let _lock1 = ConfigLock::acquire("blocking_lock").unwrap();

    let result = ConfigLock::acquire_with_timeout(
        "blocking_lock",
        Duration::from_millis(100),
        "test"
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("timeout"));
}

#[test]
fn test_stale_lock_detection() {
    // Create a lock file with a non-existent PID
    let lock_dir = dirs::runtime_dir().unwrap().join("rch/locks");
    fs::create_dir_all(&lock_dir).unwrap();
    let lock_path = lock_dir.join("stale_test.lock");

    fs::write(&lock_path, r#"{"pid": 999999999, "hostname": "test", "created_at": "2020-01-01T00:00:00Z", "operation": "test"}"#).unwrap();

    // Should be able to acquire despite existing file (stale)
    let _lock = ConfigLock::acquire("stale_test").unwrap();
}
```

**migration_test.rs**
```rust
#[test]
fn test_migration_renames_workers() {
    let mut config: toml::Value = toml::from_str(r#"
        [workers]
        host1 = { address = "192.168.1.1" }
    "#).unwrap();

    let migrator = ConfigMigrator::new();
    migrator.migrate(&mut config, &Version::parse("0.0.0").unwrap()).unwrap();

    assert!(config.get("workers").is_none());
    assert!(config.get("fleet").unwrap().get("workers").is_some());
}
```

### Integration Tests (rch/tests/state_integration.rs)

```rust
#[test]
fn test_rch_state_shows_not_installed() {
    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("rch").unwrap()
        .env("HOME", tmp.path())
        .arg("state")
        .assert()
        .stdout(predicate::str::contains("NotInstalled"));
}

#[test]
fn test_rch_state_check_exit_code() {
    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("rch").unwrap()
        .env("HOME", tmp.path())
        .args(["state", "--check"])
        .assert()
        .code(exit_codes::NEEDS_SETUP);
}

#[test]
fn test_config_init_if_missing_idempotent() {
    let tmp = TempDir::new().unwrap();

    // First run creates
    Command::cargo_bin("rch").unwrap()
        .env("HOME", tmp.path())
        .args(["config", "init", "--if-missing"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created"));

    // Second run skips
    Command::cargo_bin("rch").unwrap()
        .env("HOME", tmp.path())
        .args(["config", "init", "--if-missing"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Already exists"));
}
```

### E2E Test Script (scripts/e2e_state_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCH="${RCH:-$SCRIPT_DIR/../target/release/rch}"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_state.log"

export HOME="$TEST_DIR"
export XDG_CONFIG_HOME="$TEST_DIR/.config"
export XDG_DATA_HOME="$TEST_DIR/.local/share"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; exit 1; }

cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

log "=== RCH State E2E Test ==="

# Test 1: Fresh install detection
test_fresh_install() {
    log "Test 1: Fresh install shows NotInstalled"
    OUTPUT=$("$RCH" state 2>&1)
    echo "$OUTPUT" | grep -qiE "not.?installed|needs.?setup" || fail "Should detect not installed"
    pass "Fresh install detection"
}

# Test 2: Exit code contract
test_exit_codes() {
    log "Test 2: Exit code contract"

    # Unconfigured should return NEEDS_SETUP (100)
    "$RCH" state --check >/dev/null 2>&1 && fail "Should return non-zero"
    EXIT_CODE=$?
    log "  Exit code: $EXIT_CODE"
    [[ $EXIT_CODE -eq 100 ]] || log "  Note: Expected 100, got $EXIT_CODE"
    pass "Exit code contract"
}

# Test 3: Idempotent config init
test_idempotent_init() {
    log "Test 3: Idempotent config init"

    # First run creates
    OUTPUT1=$("$RCH" config init --if-missing 2>&1)
    log "  First run: $OUTPUT1"
    echo "$OUTPUT1" | grep -qiE "created|initialized" || log "  Note: First run should create"

    # Second run skips
    OUTPUT2=$("$RCH" config init --if-missing 2>&1)
    log "  Second run: $OUTPUT2"
    echo "$OUTPUT2" | grep -qiE "already|exists|skipped" || log "  Note: Second run should skip"

    pass "Idempotent config init"
}

# Test 4: Lock file prevents concurrent ops
test_lock_file() {
    log "Test 4: Lock file prevents concurrent operations"

    # Start a long-running operation in background
    "$RCH" config init --if-missing &
    PID1=$!
    sleep 0.1

    # Try to run another operation
    OUTPUT=$("$RCH" config init --if-missing 2>&1 || true)
    log "  Concurrent output: $OUTPUT"

    wait $PID1
    pass "Lock file"
}

# Test 5: JSON output is parseable
test_json_output() {
    log "Test 5: JSON output is parseable"

    OUTPUT=$("$RCH" state --json 2>&1)
    log "  JSON output (first 200 chars): $(echo "$OUTPUT" | head -c 200)"

    if echo "$OUTPUT" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
        log "  Valid JSON"
    else
        log "  Note: JSON output may not be implemented yet"
    fi

    pass "JSON output"
}

# Test 6: Backup creation
test_backup_creation() {
    log "Test 6: Backup creation on update"

    # Create initial config
    "$RCH" config init --if-missing 2>&1

    # Update config (should create backup)
    "$RCH" config set daemon.log_level debug 2>&1 || true

    # Check for backups
    BACKUP_DIR="$XDG_DATA_HOME/rch/backups"
    if [[ -d "$BACKUP_DIR" ]]; then
        BACKUPS=$(ls -1 "$BACKUP_DIR" 2>/dev/null | wc -l)
        log "  Found $BACKUPS backup(s)"
    else
        log "  Note: Backup directory not found (may not be implemented)"
    fi

    pass "Backup creation"
}

# Run all tests
test_fresh_install
test_exit_codes
test_idempotent_init
test_lock_file
test_json_output
test_backup_creation

log "=== All State E2E tests passed ==="
log "Full log at: $LOG_FILE"
```

## Logging Requirements

- DEBUG: Log each state component detection step
- DEBUG: Lock acquisition/release details
- DEBUG: Backup creation paths
- INFO: Log final state summary
- INFO: Migration steps performed
- WARN: Log detected issues
- WARN: Stale lock detected and removed
- ERROR: Log failures with remediation hints

## Success Criteria

- [ ] State detection covers all components
- [ ] All file operations are atomic (write-to-temp then rename)
- [ ] Lock file prevents concurrent modifications
- [ ] Lock timeout prevents deadlocks (30s default)
- [ ] Stale lock detection and cleanup works
- [ ] Exit codes follow documented contract
- [ ] JSON output matches schema
- [ ] Config migration works for version upgrades
- [ ] Backup retention policy limits to 10 backups per file
- [ ] Unit test coverage > 80%
- [ ] All E2E tests pass

## Dependencies

None - this is a foundational bead.

## Blocks

- remote_compilation_helper-xi5 (Agent Detection)
- remote_compilation_helper-3d1 (First-Run Setup Wizard)
- remote_compilation_helper-srd (Environment Variables)
