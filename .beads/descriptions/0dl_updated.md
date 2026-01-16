## Overview

Implement idempotent state detection and configuration primitives that underpin ALL setup, install, and configuration commands. This is a **foundational bead** with no dependencies - it provides the building blocks that xi5 (Agent Detection), 3d1 (Setup Wizard), and other beads rely on.

The core principle: **any RCH command can be run repeatedly without side effects or data loss**.

## Goals

1. **State Detection Layer**: Unified detection of RCH configuration state
2. **Idempotent Primitives**: Reusable functions for safe file operations
3. **Exit Code Contract**: Consistent exit codes for automation
4. **Source Tracking**: Track where each config value came from
5. **Lock File Support**: Prevent concurrent configuration modifications

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
```

## Idempotent Primitives

```rust
// rch/src/state/primitives.rs

/// Result of an idempotent operation
#[derive(Debug, Clone)]
pub enum IdempotentResult {
    Created,
    AlreadyExists,
    Updated,
    DryRun,
}

/// Create a file only if it doesn't exist
pub fn create_if_missing(path: &Path, content: &str) -> Result<IdempotentResult>;

/// Update a file only if content differs (with backup)
pub fn update_if_changed(path: &Path, new_content: &str, backup: bool) -> Result<IdempotentResult>;

/// Ensure a symlink points to the correct target
pub fn ensure_symlink(link: &Path, target: &Path) -> Result<IdempotentResult>;

/// Append to file only if line doesn't exist (for PATH updates)
pub fn append_line_if_missing(path: &Path, line: &str) -> Result<IdempotentResult>;
```

## Lock File Support

```rust
// rch/src/state/lock.rs
pub struct ConfigLock { /* file handle + path */ }

impl ConfigLock {
    pub fn acquire(lock_path: &Path) -> Result<Self>;
}

impl Drop for ConfigLock {
    fn drop(&mut self) { /* release lock, remove file */ }
}
```

## Exit Code Contract

```rust
pub mod exit_codes {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const USAGE: i32 = 64;
    pub const CONFIG: i32 = 78;
    pub const NEEDS_SETUP: i32 = 100;
    pub const DAEMON_DOWN: i32 = 101;
    pub const NO_WORKERS: i32 = 102;
    pub const ALREADY_CURRENT: i32 = 103;
    pub const LOCKED: i32 = 104;
}
```

## CLI Integration

```
rch state                      # Show current state (human-readable)
rch state --json               # JSON output for scripting
rch state --check              # Exit code only (0=ready, 100=needs setup)
rch config init --if-missing   # Create only if missing (idempotent)
rch setup --check              # Validate setup, report issues
```

## Implementation Files

```
rch/src/
├── state/
│   ├── mod.rs              # State types and RchState
│   ├── detect.rs           # State detection logic
│   ├── primitives.rs       # Idempotent file operations
│   ├── lock.rs             # Lock file management
│   └── exit_codes.rs       # Exit code constants
├── commands/
│   └── state.rs            # `rch state` command
```

## Testing Requirements

### Unit Tests (rch/src/state/tests/)

**primitives_test.rs**: Test create_if_missing, update_if_changed, ensure_symlink, append_line_if_missing with tempfile
**detect_test.rs**: Test state detection with mock environments
**lock_test.rs**: Test lock acquisition, release, and concurrent access prevention

### Integration Tests (rch/tests/state_integration.rs)

- test_rch_state_shows_not_installed
- test_rch_state_check_exit_code
- test_rch_state_json_output
- test_config_init_if_missing_idempotent

### E2E Test Script (scripts/e2e_state_test.sh)

1. Fresh install detection (expects NotInstalled)
2. Exit code contract (expects 100 for unconfigured)
3. Idempotent config init (first creates, second skips)
4. Lock file prevents concurrent operations
5. JSON output is parseable

## Logging Requirements

- DEBUG: Log each state component detection step
- INFO: Log final state summary
- WARN: Log detected issues
- ERROR: Log failures with remediation hints

## Success Criteria

- [ ] State detection covers all components
- [ ] All file operations are atomic and idempotent
- [ ] Lock file prevents concurrent modifications
- [ ] Exit codes follow documented contract
- [ ] JSON output matches schema
- [ ] Unit test coverage > 80%
- [ ] All E2E tests pass

## Dependencies

None - this is a foundational bead.

## Blocks

- remote_compilation_helper-xi5 (Agent Detection)
- remote_compilation_helper-3d1 (First-Run Setup Wizard)
