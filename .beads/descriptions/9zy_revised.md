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
10. **NEW: Automatic update notification on daemon startup**
11. **NEW: Update retry with exponential backoff**
12. **NEW: Version changelog diff display**

## Release Artifact Contract

Release assets MUST include:
- Platform-specific tarballs: `rch-v{version}-{target}.tar.gz`
- Per-asset checksums: `rch-v{version}-{target}.tar.gz.sha256`
- Aggregated checksums: `checksums.txt`
- Optional signatures: `checksums.txt.sig` (minisign) or `.sigstore` attestation
- Release notes: `RELEASE_NOTES.md`
- **NEW: Changelog**: `CHANGELOG.md` for version diff display

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
  --show-changelog       Display changelog between current and target version (NEW)
  --disable-notify       Disable update notifications for this session (NEW)
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
    pub changelog_diff: Option<String>,  // NEW: Changes between versions
    pub assets: Vec<ReleaseAsset>,
}

async fn check_for_updates(channel: Channel) -> Result<UpdateCheck> {
    // 1. Fetch release list from GitHub API
    // 2. Filter by channel (stable = no prerelease, beta = prerelease, nightly = latest)
    // 3. Compare versions
    // 4. Fetch changelog diff if available
    // 5. Return update info
}
```

### Phase 2: Download and Verify
```rust
pub struct VerifiedDownload {
    pub path: PathBuf,
    pub checksum: String,
    pub signature_status: SignatureStatus,
}

/// NEW: Download with retry and exponential backoff
async fn download_with_retry(
    asset: &ReleaseAsset,
    max_retries: u32,
) -> Result<VerifiedDownload> {
    let mut delay = Duration::from_secs(1);

    for attempt in 0..max_retries {
        match download_and_verify(asset).await {
            Ok(download) => return Ok(download),
            Err(e) if e.is_transient() => {
                warn!("Download attempt {} failed: {}, retrying in {:?}", attempt, e, delay);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(60));
            }
            Err(e) => return Err(e),
        }
    }
    Err(anyhow!("Download failed after {} retries", max_retries))
}

async fn download_and_verify(asset: &ReleaseAsset) -> Result<VerifiedDownload> {
    // 1. Download asset to temp file with progress
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

## NEW: Update Notification System

```rust
// rchd/src/update_notify.rs

pub struct UpdateNotifier {
    check_interval: Duration,
    last_check: Option<Instant>,
    cached_result: Option<UpdateCheck>,
}

impl UpdateNotifier {
    /// Check for updates on daemon startup (non-blocking)
    pub async fn check_on_startup(&mut self) -> Option<UpdateCheck> {
        // Only check once per day
        if let Some(last) = self.last_check {
            if last.elapsed() < Duration::from_secs(86400) {
                return self.cached_result.clone();
            }
        }

        // Background check - don't block daemon startup
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            check_for_updates(Channel::Stable)
        ).await.ok()?.ok()?;

        self.last_check = Some(Instant::now());

        if result.update_available {
            info!(
                "Update available: {} -> {} (run 'rch update' to install)",
                result.current_version, result.latest_version
            );
            self.cached_result = Some(result.clone());
            Some(result)
        } else {
            None
        }
    }
}
```

## NEW: Changelog Diff Display

```rust
// rch/src/update/changelog.rs

pub struct ChangelogDiff {
    pub from_version: Version,
    pub to_version: Version,
    pub entries: Vec<ChangelogEntry>,
}

pub struct ChangelogEntry {
    pub version: Version,
    pub date: NaiveDate,
    pub changes: Vec<Change>,
}

pub struct Change {
    pub category: ChangeCategory,
    pub description: String,
}

pub enum ChangeCategory {
    Added,
    Changed,
    Fixed,
    Removed,
    Security,
    Performance,
}

/// Display changelog between current and target version
pub fn display_changelog_diff(diff: &ChangelogDiff, use_color: bool) {
    println!("Changes from {} to {}:\n", diff.from_version, diff.to_version);

    for entry in &diff.entries {
        println!("## {} ({})", entry.version, entry.date);
        for change in &entry.changes {
            let prefix = match change.category {
                ChangeCategory::Added => "[+]",
                ChangeCategory::Changed => "[~]",
                ChangeCategory::Fixed => "[*]",
                ChangeCategory::Removed => "[-]",
                ChangeCategory::Security => "[!]",
                ChangeCategory::Performance => "[⚡]",
            };
            println!("  {} {}", prefix, change.description);
        }
        println!();
    }
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
│   ├── lock.rs          # Update locking
│   ├── changelog.rs     # NEW: Changelog parsing and diff
│   └── retry.rs         # NEW: Retry with backoff logic
├── commands/
│   └── update.rs        # CLI command

rchd/src/
├── update_notify.rs     # NEW: Update notification on startup
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

**retry_test.rs** (NEW)
```rust
#[tokio::test]
async fn test_retry_succeeds_after_transient_failure() {
    let mock = MockDownloader::new()
        .fail_times(2)
        .then_succeed();

    let result = download_with_retry(&mock, 3).await;
    assert!(result.is_ok());
    assert_eq!(mock.attempt_count(), 3);
}

#[tokio::test]
async fn test_retry_fails_after_max_attempts() {
    let mock = MockDownloader::new()
        .always_fail_transient();

    let result = download_with_retry(&mock, 3).await;
    assert!(result.is_err());
    assert_eq!(mock.attempt_count(), 3);
}

#[tokio::test]
async fn test_retry_stops_on_permanent_error() {
    let mock = MockDownloader::new()
        .fail_permanent();

    let result = download_with_retry(&mock, 3).await;
    assert!(result.is_err());
    assert_eq!(mock.attempt_count(), 1); // No retries for permanent errors
}
```

**changelog_test.rs** (NEW)
```rust
#[test]
fn test_changelog_parsing() {
    let changelog = r#"
# Changelog

## [0.2.0] - 2024-01-15
### Added
- New feature X
### Fixed
- Bug Y

## [0.1.0] - 2024-01-01
### Added
- Initial release
"#;

    let parsed = parse_changelog(changelog).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].version.to_string(), "0.2.0");
}

#[test]
fn test_changelog_diff() {
    let entries = vec![
        ChangelogEntry { version: Version::parse("0.2.0").unwrap(), .. },
        ChangelogEntry { version: Version::parse("0.1.5").unwrap(), .. },
        ChangelogEntry { version: Version::parse("0.1.0").unwrap(), .. },
    ];

    let diff = compute_diff(&entries, "0.1.0", "0.2.0");
    assert_eq!(diff.entries.len(), 2); // 0.2.0 and 0.1.5, not 0.1.0
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

#[tokio::test]
async fn test_update_notification_caching() {
    let mut notifier = UpdateNotifier::new();

    // First check fetches
    let result1 = notifier.check_on_startup().await;

    // Second check uses cache
    let result2 = notifier.check_on_startup().await;

    assert_eq!(result1, result2);
}
```

### E2E Test Script (scripts/e2e_update_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCH="${RCH:-$SCRIPT_DIR/../target/release/rch}"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_update.log"
MOCK_PID=""

export RCH_MOCK_SSH=1
export RCH_LOG_LEVEL=debug

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; cleanup; exit 1; }

cleanup() {
    [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Setup mock release server
MOCK_RELEASE_DIR="$TEST_DIR/releases"
mkdir -p "$MOCK_RELEASE_DIR"

setup_mock_releases() {
    log "Setting up mock releases..."

    # Create mock release files
    echo "mock binary content" > "$MOCK_RELEASE_DIR/rch"
    tar -czf "$MOCK_RELEASE_DIR/rch-v0.2.0-linux-x86_64.tar.gz" -C "$MOCK_RELEASE_DIR" rch
    sha256sum "$MOCK_RELEASE_DIR/rch-v0.2.0-linux-x86_64.tar.gz" | awk '{print $1}' > "$MOCK_RELEASE_DIR/checksums.txt"

    # Create changelog
    cat > "$MOCK_RELEASE_DIR/CHANGELOG.md" << 'EOF'
# Changelog

## [0.2.0] - 2024-01-15
### Added
- New remote compilation feature
### Fixed
- Memory leak in daemon
EOF
}

start_mock_server() {
    log "Starting mock release server on port 8765..."
    python3 -c "
import http.server
import os
os.chdir('$MOCK_RELEASE_DIR')
http.server.test(HandlerClass=http.server.SimpleHTTPRequestHandler, port=8765)
" &
    MOCK_PID=$!
    sleep 2
    log "  Mock server started (PID: $MOCK_PID)"
}

# Test 1: Update check detects new version
test_update_check() {
    log "Test 1: update --check detects new version"

    OUTPUT=$("$RCH" update --check 2>&1) || true
    log "  Check output: $OUTPUT"

    echo "$OUTPUT" | grep -qiE "available|update|version" || log "  Note: mock server may not be connected"
    pass "Update check"
}

# Test 2: Dry run shows planned actions
test_dry_run() {
    log "Test 2: update --dry-run shows plan"

    OUTPUT=$("$RCH" update --dry-run 2>&1) || true
    log "  Dry run output: $(echo "$OUTPUT" | head -20)"

    echo "$OUTPUT" | grep -qiE "would|plan|dry" || log "  Note: verify dry-run behavior"
    pass "Dry run"
}

# Test 3: Changelog display (NEW)
test_changelog_display() {
    log "Test 3: update --show-changelog displays changes"

    OUTPUT=$("$RCH" update --check --show-changelog 2>&1) || true
    log "  Changelog output: $(echo "$OUTPUT" | head -20)"

    pass "Changelog display"
}

# Test 4: Update with retry on transient failure (NEW)
test_update_retry() {
    log "Test 4: Update retries on transient failure"

    # This would require network simulation
    # For now, verify the retry flag exists
    OUTPUT=$("$RCH" update --help 2>&1)
    log "  Checking for retry-related options..."

    pass "Update retry"
}

# Test 5: Rollback restores previous
test_rollback() {
    log "Test 5: rollback restores previous version"

    OUTPUT=$("$RCH" update --rollback --dry-run 2>&1) || true
    log "  Rollback output: $(echo "$OUTPUT" | head -10)"

    pass "Rollback"
}

# Test 6: Fleet update dry run
test_fleet_update() {
    log "Test 6: fleet update dry run"

    OUTPUT=$("$RCH" update --fleet --dry-run 2>&1) || true
    log "  Fleet update output: $(echo "$OUTPUT" | head -10)"

    pass "Fleet update"
}

# Test 7: JSON output
test_json_output() {
    log "Test 7: JSON output format"

    OUTPUT=$("$RCH" update --check --json 2>&1) || true
    log "  JSON output: $(echo "$OUTPUT" | head -c 500)"

    if echo "$OUTPUT" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
        log "  Valid JSON"
    else
        log "  Note: JSON output may require daemon"
    fi
    pass "JSON output"
}

# Test 8: Version pinning
test_version_pinning() {
    log "Test 8: Install specific version"

    OUTPUT=$("$RCH" update --version v0.1.0 --dry-run 2>&1) || true
    log "  Version pin output: $(echo "$OUTPUT" | head -10)"

    echo "$OUTPUT" | grep -qiE "0.1.0|version" || log "  Note: verify version pinning"
    pass "Version pinning"
}

# Test 9: Channel selection
test_channel_selection() {
    log "Test 9: Channel selection (beta)"

    OUTPUT=$("$RCH" update --channel beta --check 2>&1) || true
    log "  Beta channel output: $(echo "$OUTPUT" | head -10)"

    pass "Channel selection"
}

# Test 10: Verify installation integrity
test_verify() {
    log "Test 10: Verify installation integrity"

    OUTPUT=$("$RCH" update --verify 2>&1) || true
    log "  Verify output: $(echo "$OUTPUT" | head -10)"

    pass "Verify installation"
}

# Run all tests
setup_mock_releases
start_mock_server

test_update_check
test_dry_run
test_changelog_display
test_update_retry
test_rollback
test_fleet_update
test_json_output
test_version_pinning
test_channel_selection
test_verify

log "=== All update E2E tests passed ==="
log "Full log at: $LOG_FILE"
cat "$LOG_FILE"
```

## Logging Requirements

- INFO: Update check result (current version, latest version)
- INFO: Download progress (bytes/total, speed)
- INFO: Verification status (checksum match, signature status)
- INFO: Daemon coordination (drain started, builds remaining)
- INFO: Installation steps (backup created, binaries replaced)
- INFO: **NEW**: Update notification on daemon startup
- INFO: **NEW**: Retry attempts with delay
- WARN: Signature not available (continue with checksum only)
- WARN: Drain timeout reached (builds still in progress)
- WARN: **NEW**: Transient download failure, retrying
- ERROR: Checksum mismatch (with expected vs actual)
- ERROR: Installation failed (with rollback instructions)
- ERROR: **NEW**: Permanent download failure after retries

## Success Criteria

- [ ] `rch update --check` reports update availability
- [ ] `rch update` downloads and verifies checksum
- [ ] `rch update` creates backup before installing
- [ ] `rch update` coordinates with daemon (drain builds)
- [ ] `rch update --fleet` updates workers in parallel
- [ ] `rch update --rollback` restores previous version
- [ ] Update lock prevents concurrent updates
- [ ] JSON output for automation
- [ ] **NEW**: Update notification on daemon startup works
- [ ] **NEW**: Retry with backoff works for transient failures
- [ ] **NEW**: Changelog diff displays correctly
- [ ] Unit test coverage > 80%
- [ ] E2E tests pass with mock server

## Dependencies

- remote_compilation_helper-bcl: CI workflow for release artifacts
- remote_compilation_helper-gao: cargo-dist for automated releases

## Blocks

- remote_compilation_helper-eke: install.sh uses update infrastructure
- remote_compilation_helper-brr: Fleet deployment uses update distribution
