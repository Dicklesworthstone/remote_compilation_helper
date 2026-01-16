## Overview

Implement a complete self-update pipeline (`rch update`) that downloads verified release artifacts, safely updates local binaries with daemon coordination, optionally updates all workers, and supports rollback. The update must be cryptographically verified, fully idempotent, and handle in-progress builds gracefully.

## Goals

1. `rch update` for local binaries (rch, rchd, rch-wkr)
2. SHA256 checksum verification on every download
3. Optional signature verification (minisign/Sigstore)
4. Version pinning and release channels (stable/beta/nightly)
5. Fleet update with parallel SSH distribution
6. Rollback to previous version
7. Graceful daemon restart with build drain
8. Update locking to prevent concurrent updates
9. Changelog/release notes display

## Release Artifact Contract

Release assets MUST include:
- Platform-specific tarballs: `rch-v{version}-{target}.tar.gz`
- Per-asset checksums: `rch-v{version}-{target}.tar.gz.sha256`
- Aggregated checksums: `checksums.txt`
- Optional signatures: `checksums.txt.sig` (minisign) or `.sigstore` attestation
- Release notes: `RELEASE_NOTES.md`

## CLI Interface

```
rch update [OPTIONS]

OPTIONS:
  --check                Check for updates without installing
  --version <VER>        Install specific version (e.g., v0.2.0)
  --channel <CHANNEL>    Release channel: stable (default), beta, nightly
  --fleet                Update all configured workers
  --rollback             Restore previous version from backup
  --verify               Verify current installation integrity
  --yes                  Skip confirmation prompts
  --dry-run              Show planned actions without executing
  --no-restart           Update binaries but don't restart daemon
  --drain-timeout <SEC>  Wait up to N seconds for builds to complete (default: 60)
  --force                Skip version check, reinstall current version
  --json                 Output results as JSON
```

## Update Flow

### Phase 1: Discovery
```rust
pub struct UpdateCheck {
    pub current_version: Version,
    pub latest_version: Version,
    pub update_available: bool,
    pub release_url: String,
    pub release_notes: Option<String>,
    pub assets: Vec<ReleaseAsset>,
}

async fn check_for_updates(channel: Channel) -> Result<UpdateCheck> {
    // 1. Fetch release list from GitHub API
    // 2. Filter by channel (stable = no prerelease, beta = prerelease, nightly = latest)
    // 3. Compare versions
    // 4. Return update info
}
```

### Phase 2: Download and Verify
```rust
pub struct VerifiedDownload {
    pub path: PathBuf,
    pub checksum: String,
    pub signature_status: SignatureStatus,
}

async fn download_and_verify(asset: &ReleaseAsset) -> Result<VerifiedDownload> {
    // 1. Download asset to temp file
    // 2. Download checksum file
    // 3. Verify SHA256
    // 4. If signature available, verify with minisign/sigstore
    // 5. Return verified download
}
```

### Phase 3: Daemon Coordination
```rust
pub enum DaemonState {
    NotRunning,
    Running { pid: u32, active_builds: u32 },
    Draining { pid: u32, remaining: u32, deadline: Instant },
}

async fn coordinate_daemon_update(drain_timeout: Duration) -> Result<DaemonState> {
    // 1. Check if daemon is running
    // 2. If running, signal drain mode (stop accepting new builds)
    // 3. Wait for active builds to complete (up to timeout)
    // 4. If builds still running after timeout, warn user
    // 5. Return state for update decision
}
```

### Phase 4: Installation
```rust
async fn install_update(download: &VerifiedDownload, backup: bool) -> Result<InstallResult> {
    // 1. Acquire update lock
    // 2. Stop daemon gracefully
    // 3. Backup current binaries to ~/.rch/backups/v{version}/
    // 4. Extract new binaries to temp location
    // 5. Atomic replace: rename temp -> target
    // 6. Verify new binaries work (--version check)
    // 7. Restart daemon
    // 8. Release lock
}
```

### Phase 5: Fleet Update
```rust
pub struct FleetUpdateResult {
    pub workers: Vec<WorkerUpdateResult>,
    pub success_count: u32,
    pub failure_count: u32,
    pub skipped_count: u32,
}

async fn update_fleet(workers: &[WorkerConfig], parallel: usize) -> Result<FleetUpdateResult> {
    // 1. Check versions on all workers in parallel
    // 2. Filter to workers needing update
    // 3. Upload new binaries via rsync
    // 4. Restart worker agents
    // 5. Verify health
    // 6. Collect results
}
```

## Rollback Strategy

```rust
pub struct Backup {
    pub version: Version,
    pub path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub binaries: Vec<String>,
}

async fn rollback() -> Result<()> {
    // 1. List available backups
    // 2. Select most recent (or let user choose)
    // 3. Stop daemon
    // 4. Restore binaries from backup
    // 5. Verify restored binaries
    // 6. Restart daemon
}
```

## Update Lock

```rust
// Prevent concurrent updates
pub struct UpdateLock {
    file: File,
    path: PathBuf,
}

impl UpdateLock {
    pub fn acquire() -> Result<Self> {
        let path = dirs::data_dir()?.join("rch/update.lock");
        // Use flock for cross-process locking
    }
}
```

## Implementation Files

```
rch/src/
├── update/
│   ├── mod.rs           # Public API
│   ├── check.rs         # Version checking
│   ├── download.rs      # Download and verification
│   ├── verify.rs        # Checksum and signature verification
│   ├── install.rs       # Binary installation
│   ├── daemon.rs        # Daemon coordination
│   ├── fleet.rs         # Fleet update logic
│   ├── rollback.rs      # Rollback functionality
│   └── lock.rs          # Update locking
├── commands/
│   └── update.rs        # CLI command
```

## Testing Requirements

### Unit Tests (rch/src/update/tests/)

**check_test.rs**
```rust
#[test]
fn test_version_comparison() {
    assert!(Version::parse("0.2.0") > Version::parse("0.1.0"));
    assert!(Version::parse("0.2.0-beta.1") < Version::parse("0.2.0"));
}

#[test]
fn test_channel_filtering() {
    let releases = vec![
        Release { version: "0.2.0", prerelease: false },
        Release { version: "0.3.0-beta.1", prerelease: true },
    ];
    assert_eq!(filter_by_channel(&releases, Channel::Stable).version, "0.2.0");
    assert_eq!(filter_by_channel(&releases, Channel::Beta).version, "0.3.0-beta.1");
}
```

**verify_test.rs**
```rust
#[test]
fn test_checksum_verification_success() {
    let content = b"test content";
    let expected = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72";
    assert!(verify_sha256(content, expected).is_ok());
}

#[test]
fn test_checksum_verification_failure() {
    let content = b"test content";
    let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
    assert!(verify_sha256(content, wrong).is_err());
}

#[test]
fn test_checksum_file_parsing() {
    let checksums = "abc123  rch-v0.1.0-linux.tar.gz\ndef456  rch-v0.1.0-darwin.tar.gz";
    let parsed = parse_checksums(checksums);
    assert_eq!(parsed.get("rch-v0.1.0-linux.tar.gz"), Some(&"abc123"));
}
```

**daemon_test.rs**
```rust
#[tokio::test]
async fn test_drain_waits_for_builds() {
    let mock_daemon = MockDaemon::with_active_builds(2);
    let result = coordinate_daemon_update(&mock_daemon, Duration::from_secs(5)).await;
    assert!(result.is_ok());
    assert_eq!(mock_daemon.drain_called(), true);
}
```

### Integration Tests (rch/tests/update_integration.rs)

```rust
#[tokio::test]
async fn test_update_check_with_mock_github() {
    let server = MockGitHubServer::new();
    server.add_release("v0.2.0", false);

    let result = check_for_updates_with_url(server.url(), Channel::Stable).await;
    assert!(result.unwrap().update_available);
}

#[tokio::test]
async fn test_download_and_verify() {
    let server = MockServer::new();
    server.serve_file("rch.tar.gz", include_bytes!("fixtures/rch.tar.gz"));
    server.serve_file("rch.tar.gz.sha256", b"<correct checksum>");

    let result = download_and_verify(&server.url()).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_rollback_restores_previous() {
    let tmp = TempDir::new().unwrap();
    setup_fake_installation(&tmp, "0.1.0");
    setup_backup(&tmp, "0.0.9");

    let result = rollback_with_base(&tmp).await;
    assert!(result.is_ok());
    assert_eq!(get_installed_version(&tmp), "0.0.9");
}
```

### E2E Test Script (scripts/e2e_update_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

# Test update functionality with mock releases
log() { echo "[$(date -Iseconds)] $*" >&2; }

# Setup mock release server
start_mock_server() {
    python3 -c "
import http.server
import os
os.chdir('$MOCK_RELEASE_DIR')
http.server.test(HandlerClass=http.server.SimpleHTTPRequestHandler, port=8765)
" &
    MOCK_PID=$!
    sleep 1
}

# Test 1: Update check detects new version
test_update_check() {
    log "Test: update --check detects new version"
    OUTPUT=$("$RCH" update --check 2>&1)
    echo "$OUTPUT" | grep -q "available" || fail "Should detect update"
    pass "Update check"
}

# Test 2: Dry run shows planned actions
test_dry_run() {
    log "Test: update --dry-run shows plan"
    OUTPUT=$("$RCH" update --dry-run 2>&1)
    echo "$OUTPUT" | grep -q "Would download" || fail "Should show download plan"
    pass "Dry run"
}

# Test 3: Update with verification
test_update_with_verify() {
    log "Test: update downloads and verifies"
    "$RCH" update --yes 2>&1
    "$RCH" --version | grep -q "0.2.0" || fail "Should be updated"
    pass "Update with verification"
}

# Test 4: Rollback restores previous
test_rollback() {
    log "Test: rollback restores previous version"
    "$RCH" update --rollback --yes 2>&1
    "$RCH" --version | grep -q "0.1.0" || fail "Should be rolled back"
    pass "Rollback"
}

# Run tests
start_mock_server
trap "kill $MOCK_PID 2>/dev/null" EXIT

test_update_check
test_dry_run
test_update_with_verify
test_rollback

log "All update E2E tests passed!"
```

## Logging Requirements

- INFO: Update check result (current version, latest version)
- INFO: Download progress (bytes/total, speed)
- INFO: Verification status (checksum match, signature status)
- INFO: Daemon coordination (drain started, builds remaining)
- INFO: Installation steps (backup created, binaries replaced)
- WARN: Signature not available (continue with checksum only)
- WARN: Drain timeout reached (builds still in progress)
- ERROR: Checksum mismatch (with expected vs actual)
- ERROR: Installation failed (with rollback instructions)

## Success Criteria

- [ ] `rch update --check` reports update availability
- [ ] `rch update` downloads and verifies checksum
- [ ] `rch update` creates backup before installing
- [ ] `rch update` coordinates with daemon (drain builds)
- [ ] `rch update --fleet` updates workers in parallel
- [ ] `rch update --rollback` restores previous version
- [ ] Update lock prevents concurrent updates
- [ ] JSON output for automation
- [ ] Unit test coverage > 80%
- [ ] E2E tests pass with mock server

## Dependencies

- remote_compilation_helper-bcl: CI workflow for release artifacts
- remote_compilation_helper-gao: cargo-dist for automated releases

## Blocks

- remote_compilation_helper-eke: install.sh uses update infrastructure
- remote_compilation_helper-brr: Fleet deployment uses update distribution
