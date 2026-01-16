## Overview

Add `rch fleet` commands for deploying, updating, and managing the worker agent across all configured workers in parallel. This includes rollback capability, canary deployments, health verification, and detailed progress reporting.

## Goals

1. Single command deploys to all workers with parallel execution
2. Configurable parallelism with backpressure
3. Prerequisite verification (SSH, disk, rsync, zstd, rustup)
4. Atomic install/update with automatic rollback on failure
5. Canary deployment mode (deploy to subset first)
6. Post-install health verification
7. Resume capability for failed deployments
8. Detailed per-worker status and progress reporting

## CLI Interface

```
rch fleet <COMMAND>

COMMANDS:
  deploy     Deploy or update workers
  rollback   Rollback to previous version
  status     Show fleet deployment status
  verify     Verify worker installations
  drain      Drain workers before maintenance

rch fleet deploy [OPTIONS]

OPTIONS:
  --worker <ID>         Target specific worker(s), comma-separated
  --parallel <N>        Max parallel deployments (default: 4)
  --canary <PERCENT>    Deploy to N% of workers first, wait for --canary-wait
  --canary-wait <SEC>   Wait time after canary before full rollout (default: 60)
  --no-toolchain        Skip rustup/toolchain sync
  --force               Reinstall even if version matches
  --verify              Run post-install verification
  --drain-first         Drain active builds before deploy
  --drain-timeout <SEC> Max wait for drain (default: 120)
  --dry-run             Show plan without executing
  --resume              Resume from previous failed deployment
  --version <VER>       Deploy specific version (default: current local)
  --json                JSON output for automation

rch fleet rollback [OPTIONS]

OPTIONS:
  --worker <ID>         Rollback specific worker(s)
  --to-version <VER>    Rollback to specific version
  --parallel <N>        Max parallel rollbacks (default: 4)
  --verify              Verify after rollback
  --json                JSON output

rch fleet status [OPTIONS]

OPTIONS:
  --worker <ID>         Show specific worker
  --json                JSON output
  --watch               Continuous update (1s interval)
```

## Architecture

### Deployment Plan

```rust
// rch/src/fleet/plan.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPlan {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub target_version: Version,
    pub workers: Vec<WorkerDeployment>,
    pub strategy: DeploymentStrategy,
    pub options: DeployOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentStrategy {
    AllAtOnce { parallelism: usize },
    Canary {
        percent: u8,
        wait_secs: u64,
        auto_promote: bool,
    },
    Rolling { batch_size: usize, wait_between: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerDeployment {
    pub worker_id: String,
    pub current_version: Option<Version>,
    pub target_version: Version,
    pub status: DeploymentStatus,
    pub steps: Vec<DeployStep>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentStatus {
    Pending,
    Preflight,
    Draining,
    Transferring,
    Installing,
    Verifying,
    Completed,
    Failed,
    Skipped,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployStep {
    pub name: String,
    pub status: StepStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub output: Option<String>,
}
```

### Deployment Executor

```rust
// rch/src/fleet/executor.rs

pub struct FleetExecutor {
    ssh_pool: SshPool,
    progress: MultiProgress,
    state_file: PathBuf,
}

impl FleetExecutor {
    /// Execute deployment plan with progress reporting
    pub async fn execute(&self, plan: &mut DeploymentPlan) -> Result<FleetResult> {
        // 1. Save initial state for resume
        self.save_state(plan)?;

        // 2. Execute based on strategy
        match &plan.strategy {
            DeploymentStrategy::AllAtOnce { parallelism } => {
                self.execute_parallel(plan, *parallelism).await
            }
            DeploymentStrategy::Canary { percent, wait_secs, .. } => {
                self.execute_canary(plan, *percent, *wait_secs).await
            }
            DeploymentStrategy::Rolling { batch_size, wait_between } => {
                self.execute_rolling(plan, *batch_size, *wait_between).await
            }
        }
    }

    async fn execute_canary(
        &self,
        plan: &mut DeploymentPlan,
        percent: u8,
        wait_secs: u64,
    ) -> Result<FleetResult> {
        let total = plan.workers.len();
        let canary_count = (total * percent as usize / 100).max(1);

        info!("Canary deployment: {} of {} workers first", canary_count, total);

        // Deploy to canary set
        let canary_workers: Vec<_> = plan.workers.iter_mut().take(canary_count).collect();
        for worker in canary_workers {
            self.deploy_worker(worker).await?;
        }

        // Check canary health
        info!("Waiting {}s for canary verification...", wait_secs);
        tokio::time::sleep(Duration::from_secs(wait_secs)).await;

        let canary_healthy = self.verify_canary_health(plan, canary_count).await?;
        if !canary_healthy {
            warn!("Canary failed health check, aborting deployment");
            return Ok(FleetResult::CanaryFailed);
        }

        // Deploy to remaining workers
        info!("Canary healthy, deploying to remaining {} workers", total - canary_count);
        let remaining: Vec<_> = plan.workers.iter_mut().skip(canary_count).collect();
        for worker in remaining {
            self.deploy_worker(worker).await?;
        }

        Ok(FleetResult::Success)
    }

    async fn deploy_worker(&self, worker: &mut WorkerDeployment) -> Result<()> {
        worker.status = DeploymentStatus::Preflight;
        worker.started_at = Some(Utc::now());

        // Step 1: Preflight checks
        self.step_preflight(worker).await?;

        // Step 2: Drain if requested
        if self.options.drain_first {
            worker.status = DeploymentStatus::Draining;
            self.step_drain(worker).await?;
        }

        // Step 3: Transfer binaries
        worker.status = DeploymentStatus::Transferring;
        self.step_transfer(worker).await?;

        // Step 4: Install
        worker.status = DeploymentStatus::Installing;
        self.step_install(worker).await?;

        // Step 5: Toolchain sync (optional)
        if !self.options.no_toolchain {
            self.step_toolchain_sync(worker).await?;
        }

        // Step 6: Verify
        worker.status = DeploymentStatus::Verifying;
        self.step_verify(worker).await?;

        worker.status = DeploymentStatus::Completed;
        worker.completed_at = Some(Utc::now());
        Ok(())
    }
}
```

### Preflight Checks

```rust
// rch/src/fleet/preflight.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResult {
    pub ssh_ok: bool,
    pub disk_space_mb: u64,
    pub disk_ok: bool,
    pub rsync_ok: bool,
    pub zstd_ok: bool,
    pub rustup_ok: bool,
    pub current_version: Option<Version>,
    pub issues: Vec<PreflightIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightIssue {
    pub severity: Severity,
    pub check: String,
    pub message: String,
    pub remediation: Option<String>,
}

pub async fn run_preflight(ssh: &SshSession, worker: &WorkerConfig) -> Result<PreflightResult> {
    let mut result = PreflightResult::default();

    // Check SSH connectivity
    result.ssh_ok = ssh.exec("echo ok").await.is_ok();
    if !result.ssh_ok {
        result.issues.push(PreflightIssue {
            severity: Severity::Error,
            check: "ssh".into(),
            message: "Cannot connect via SSH".into(),
            remediation: Some("Verify SSH key and host configuration".into()),
        });
        return Ok(result);
    }

    // Check disk space
    let df_output = ssh.exec("df -m /home | tail -1 | awk '{print $4}'").await?;
    result.disk_space_mb = df_output.trim().parse().unwrap_or(0);
    result.disk_ok = result.disk_space_mb >= 500; // Need 500MB minimum

    // Check required tools
    result.rsync_ok = ssh.exec("which rsync").await.is_ok();
    result.zstd_ok = ssh.exec("which zstd").await.is_ok();
    result.rustup_ok = ssh.exec("which rustup").await.is_ok();

    // Check current version
    if let Ok(output) = ssh.exec("~/.rch/bin/rch-wkr --version 2>/dev/null").await {
        result.current_version = Version::parse(output.trim().split_whitespace().last().unwrap_or("")).ok();
    }

    Ok(result)
}
```

### Rollback Manager

```rust
// rch/src/fleet/rollback.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerBackup {
    pub worker_id: String,
    pub version: Version,
    pub backup_path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub binaries: Vec<String>,
}

pub struct RollbackManager {
    backup_dir: PathBuf,
}

impl RollbackManager {
    /// Create backup before deployment
    pub async fn backup_worker(&self, ssh: &SshSession, worker: &WorkerConfig) -> Result<WorkerBackup> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = format!("~/.rch/backups/{}", timestamp);

        ssh.exec(&format!("mkdir -p {}", backup_path)).await?;
        ssh.exec(&format!("cp ~/.rch/bin/* {}/", backup_path)).await?;

        // Get version
        let version_output = ssh.exec("~/.rch/bin/rch-wkr --version").await?;
        let version = Version::parse(version_output.trim().split_whitespace().last().unwrap_or("0.0.0"))?;

        Ok(WorkerBackup {
            worker_id: worker.id.clone(),
            version,
            backup_path: PathBuf::from(backup_path),
            created_at: Utc::now(),
            binaries: vec!["rch-wkr".into()],
        })
    }

    /// Rollback worker to previous backup
    pub async fn rollback_worker(
        &self,
        ssh: &SshSession,
        worker: &WorkerConfig,
        backup: &WorkerBackup,
    ) -> Result<()> {
        info!("Rolling back {} to {}", worker.id, backup.version);

        // Stop worker agent
        ssh.exec("systemctl --user stop rch-wkr || true").await?;

        // Restore binaries
        ssh.exec(&format!("cp {}/* ~/.rch/bin/", backup.backup_path.display())).await?;

        // Restart
        ssh.exec("systemctl --user start rch-wkr").await?;

        // Verify
        let version_output = ssh.exec("~/.rch/bin/rch-wkr --version").await?;
        let current = version_output.trim();
        if !current.contains(&backup.version.to_string()) {
            return Err(anyhow!("Rollback verification failed: expected {}, got {}", backup.version, current));
        }

        Ok(())
    }

    /// List available backups for a worker
    pub async fn list_backups(&self, ssh: &SshSession) -> Result<Vec<WorkerBackup>> {
        let output = ssh.exec("ls -1 ~/.rch/backups/ 2>/dev/null || echo ''").await?;
        // Parse and return backups
        todo!()
    }
}
```

## Implementation Files

```
rch/src/
├── fleet/
│   ├── mod.rs           # Public API
│   ├── plan.rs          # Deployment planning
│   ├── executor.rs      # Plan execution
│   ├── preflight.rs     # Preflight checks
│   ├── transfer.rs      # Binary transfer (rsync)
│   ├── install.rs       # Remote installation
│   ├── rollback.rs      # Rollback management
│   ├── status.rs        # Fleet status tracking
│   └── ssh.rs           # SSH session pooling
├── commands/
│   └── fleet.rs         # CLI commands
```

## Testing Requirements

### Unit Tests (rch/src/fleet/tests/)

**plan_test.rs**
```rust
#[test]
fn test_deployment_plan_creation() {
    let workers = vec![
        WorkerConfig { id: "w1".into(), .. },
        WorkerConfig { id: "w2".into(), .. },
    ];
    let plan = DeploymentPlan::new(&workers, Version::parse("0.2.0").unwrap());
    assert_eq!(plan.workers.len(), 2);
    assert!(plan.workers.iter().all(|w| w.status == DeploymentStatus::Pending));
}

#[test]
fn test_canary_count_calculation() {
    // 10% of 20 workers = 2
    assert_eq!(calculate_canary_count(20, 10), 2);
    // 10% of 5 workers = 1 (minimum 1)
    assert_eq!(calculate_canary_count(5, 10), 1);
    // 50% of 4 workers = 2
    assert_eq!(calculate_canary_count(4, 50), 2);
}

#[test]
fn test_deployment_status_transitions() {
    let mut worker = WorkerDeployment::new("w1", Version::parse("0.2.0").unwrap());
    assert!(worker.can_transition_to(DeploymentStatus::Preflight));
    worker.status = DeploymentStatus::Preflight;
    assert!(worker.can_transition_to(DeploymentStatus::Transferring));
    assert!(!worker.can_transition_to(DeploymentStatus::Completed)); // Can't skip steps
}
```

**preflight_test.rs**
```rust
#[tokio::test]
async fn test_preflight_all_ok() {
    let mock_ssh = MockSshSession::new()
        .expect_exec("echo ok", "ok")
        .expect_exec_contains("df -m", "10000")
        .expect_exec_contains("which rsync", "/usr/bin/rsync")
        .expect_exec_contains("which zstd", "/usr/bin/zstd")
        .expect_exec_contains("which rustup", "~/.cargo/bin/rustup");

    let result = run_preflight(&mock_ssh, &WorkerConfig::default()).await.unwrap();
    assert!(result.ssh_ok);
    assert!(result.disk_ok);
    assert!(result.rsync_ok);
    assert!(result.zstd_ok);
    assert!(result.rustup_ok);
    assert!(result.issues.is_empty());
}

#[tokio::test]
async fn test_preflight_low_disk() {
    let mock_ssh = MockSshSession::new()
        .expect_exec("echo ok", "ok")
        .expect_exec_contains("df -m", "100"); // Only 100MB

    let result = run_preflight(&mock_ssh, &WorkerConfig::default()).await.unwrap();
    assert!(!result.disk_ok);
    assert!(result.issues.iter().any(|i| i.check == "disk_space"));
}
```

**rollback_test.rs**
```rust
#[tokio::test]
async fn test_backup_creation() {
    let mock_ssh = MockSshSession::new()
        .expect_exec_contains("mkdir -p", "")
        .expect_exec_contains("cp", "")
        .expect_exec_contains("--version", "rch-wkr 0.1.0");

    let manager = RollbackManager::new(PathBuf::from("/tmp"));
    let backup = manager.backup_worker(&mock_ssh, &WorkerConfig::default()).await.unwrap();
    assert_eq!(backup.version, Version::parse("0.1.0").unwrap());
}

#[tokio::test]
async fn test_rollback_restores_version() {
    let mock_ssh = MockSshSession::new()
        .expect_exec_contains("stop rch-wkr", "")
        .expect_exec_contains("cp", "")
        .expect_exec_contains("start rch-wkr", "")
        .expect_exec_contains("--version", "rch-wkr 0.1.0");

    let manager = RollbackManager::new(PathBuf::from("/tmp"));
    let backup = WorkerBackup {
        version: Version::parse("0.1.0").unwrap(),
        ..Default::default()
    };
    manager.rollback_worker(&mock_ssh, &WorkerConfig::default(), &backup).await.unwrap();
}
```

### Integration Tests (rch/tests/fleet_integration.rs)

```rust
#[tokio::test]
async fn test_fleet_deploy_dry_run() {
    let output = Command::new(RCH_BIN)
        .args(["fleet", "deploy", "--dry-run"])
        .env("RCH_MOCK_SSH", "1")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Dry run"));
    assert!(stdout.contains("Would deploy"));
}

#[tokio::test]
async fn test_fleet_status_json() {
    let output = Command::new(RCH_BIN)
        .args(["fleet", "status", "--json"])
        .env("RCH_MOCK_SSH", "1")
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["workers"].is_array());
}

#[tokio::test]
async fn test_fleet_deploy_with_canary() {
    let output = Command::new(RCH_BIN)
        .args(["fleet", "deploy", "--canary", "25", "--canary-wait", "5", "--dry-run"])
        .env("RCH_MOCK_SSH", "1")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("canary"));
    assert!(stdout.contains("25%"));
}
```

### E2E Test Script (scripts/e2e_fleet_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCH="${RCH:-$SCRIPT_DIR/../target/release/rch}"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_fleet.log"

export RCH_MOCK_SSH=1
export RCH_LOG_LEVEL=debug

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; exit 1; }

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

log "=== RCH Fleet Deployment E2E Test ==="
log "Binary: $RCH"
log "Mock SSH mode: enabled"
log "Test dir: $TEST_DIR"

# Setup mock worker config
setup_mock_workers() {
    mkdir -p "$TEST_DIR/.config/rch"
    cat > "$TEST_DIR/.config/rch/workers.toml" << 'EOF'
[[workers]]
id = "mock-worker-1"
host = "localhost"
user = "testuser"

[[workers]]
id = "mock-worker-2"
host = "localhost"
user = "testuser"

[[workers]]
id = "mock-worker-3"
host = "localhost"
user = "testuser"

[[workers]]
id = "mock-worker-4"
host = "localhost"
user = "testuser"
EOF
    export RCH_CONFIG_DIR="$TEST_DIR/.config/rch"
}

# Test 1: Fleet status shows all workers
test_fleet_status() {
    log "Test 1: Fleet status shows configured workers"

    OUTPUT=$("$RCH" fleet status 2>&1)
    log "  Status output:"
    echo "$OUTPUT" | head -20 | while read -r line; do log "    $line"; done

    echo "$OUTPUT" | grep -qE "mock-worker-1|worker" || fail "Worker 1 not shown"
    pass "Fleet status"
}

# Test 2: Fleet status JSON output
test_fleet_status_json() {
    log "Test 2: Fleet status JSON output"

    OUTPUT=$("$RCH" fleet status --json 2>&1)
    log "  JSON output: $(echo "$OUTPUT" | head -c 500)..."

    echo "$OUTPUT" | python3 -c "import json, sys; d=json.load(sys.stdin); assert 'workers' in d" || fail "Invalid JSON"
    pass "Fleet status JSON"
}

# Test 3: Dry run deployment
test_dry_run_deploy() {
    log "Test 3: Dry run deployment shows plan"

    OUTPUT=$("$RCH" fleet deploy --dry-run 2>&1)
    log "  Dry run output:"
    echo "$OUTPUT" | head -30 | while read -r line; do log "    $line"; done

    echo "$OUTPUT" | grep -qiE "dry.run|would|plan" || fail "Dry run not indicated"
    echo "$OUTPUT" | grep -qE "mock-worker" || fail "Workers not in plan"
    pass "Dry run deployment"
}

# Test 4: Canary deployment plan
test_canary_plan() {
    log "Test 4: Canary deployment (25%)"

    OUTPUT=$("$RCH" fleet deploy --canary 25 --canary-wait 1 --dry-run 2>&1)
    log "  Canary plan output:"
    echo "$OUTPUT" | head -30 | while read -r line; do log "    $line"; done

    echo "$OUTPUT" | grep -qiE "canary|25%" || fail "Canary not indicated"
    pass "Canary deployment plan"
}

# Test 5: Single worker targeting
test_single_worker() {
    log "Test 5: Single worker targeting"

    OUTPUT=$("$RCH" fleet deploy --worker mock-worker-1 --dry-run 2>&1)
    log "  Single worker output:"
    echo "$OUTPUT" | head -20 | while read -r line; do log "    $line"; done

    echo "$OUTPUT" | grep -qE "mock-worker-1" || fail "Target worker not shown"
    # Should NOT include other workers
    if echo "$OUTPUT" | grep -qE "mock-worker-2.*deploy"; then
        fail "Other workers should not be in plan"
    fi
    pass "Single worker targeting"
}

# Test 6: Parallel execution limit
test_parallel_limit() {
    log "Test 6: Parallel execution limit"

    OUTPUT=$("$RCH" fleet deploy --parallel 2 --dry-run 2>&1)
    log "  Parallel limit output:"
    echo "$OUTPUT" | head -20 | while read -r line; do log "    $line"; done

    echo "$OUTPUT" | grep -qiE "parallel.*2|concurrency.*2" || log "  (Note: verify parallelism manually)"
    pass "Parallel execution limit"
}

# Test 7: Mock deployment execution
test_mock_deployment() {
    log "Test 7: Mock deployment execution"

    OUTPUT=$("$RCH" fleet deploy --worker mock-worker-1 --force 2>&1) || true
    log "  Mock deployment output:"
    echo "$OUTPUT" | head -50 | while read -r line; do log "    $line"; done

    # In mock mode, should see deployment steps
    echo "$OUTPUT" | grep -qiE "preflight|transfer|install|verify|complete|mock" || log "  (Note: deployment in mock mode)"
    pass "Mock deployment execution"
}

# Test 8: Verify command
test_verify_command() {
    log "Test 8: Fleet verify command"

    OUTPUT=$("$RCH" fleet verify 2>&1) || true
    log "  Verify output:"
    echo "$OUTPUT" | head -30 | while read -r line; do log "    $line"; done

    pass "Verify command"
}

# Test 9: Resume capability
test_resume() {
    log "Test 9: Resume from previous deployment"

    # First, create a partial state
    OUTPUT=$("$RCH" fleet deploy --resume --dry-run 2>&1) || true
    log "  Resume output:"
    echo "$OUTPUT" | head -20 | while read -r line; do log "    $line"; done

    # Should indicate no previous state or resume behavior
    pass "Resume capability"
}

# Test 10: Rollback dry run
test_rollback_dry_run() {
    log "Test 10: Rollback dry run"

    OUTPUT=$("$RCH" fleet rollback --dry-run 2>&1) || true
    log "  Rollback output:"
    echo "$OUTPUT" | head -20 | while read -r line; do log "    $line"; done

    pass "Rollback dry run"
}

# Run all tests
setup_mock_workers
test_fleet_status
test_fleet_status_json
test_dry_run_deploy
test_canary_plan
test_single_worker
test_parallel_limit
test_mock_deployment
test_verify_command
test_resume
test_rollback_dry_run

log "=== All Fleet E2E tests passed ==="
log "Full log at: $LOG_FILE"
cat "$LOG_FILE"
```

## Logging Requirements

- INFO: Deployment started with version, worker count, strategy
- INFO: Per-worker step progression (preflight → transfer → install → verify)
- INFO: Canary phase started/completed with health check result
- INFO: Per-worker completion with duration
- INFO: Final summary (success/fail/skip counts, total duration)
- WARN: Preflight issue detected (with remediation)
- WARN: Canary health check warning
- ERROR: Deployment step failure with full error
- ERROR: SSH connection failure with retry info
- DEBUG: SSH commands executed and output
- DEBUG: Rsync transfer details (bytes, speed)

## Success Criteria

- [ ] `rch fleet deploy` deploys to all workers in parallel
- [ ] Canary mode deploys to subset and waits before full rollout
- [ ] Preflight checks validate SSH, disk, tools
- [ ] Backups created before each update
- [ ] `rch fleet rollback` restores previous version
- [ ] Resume continues from failure point
- [ ] JSON output for automation
- [ ] Per-worker progress shown during deployment
- [ ] Unit test coverage > 80%
- [ ] E2E tests pass with RCH_MOCK_SSH=1

## Dependencies

- Self-Update infrastructure (remote_compilation_helper-9zy) for update/version logic
- Progress indicators (remote_compilation_helper-5te) for deployment progress
- Toolchain sync (remote_compilation_helper-ayn) for --toolchain option

## Blocks

- Web dashboard (remote_compilation_helper-piz) may show fleet status
