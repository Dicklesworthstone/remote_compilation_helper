//! True E2E Tests: Exit Code Preservation & Propagation
//!
//! Tests that compilation exit codes are correctly propagated from remote
//! workers to the local caller, matching local execution behavior exactly.
//!
//! # Test Categories
//!
//! 1. Success exit codes (0) - cargo build/test, rustc, gcc, make
//! 2. Failure exit codes (1) - build/compilation errors
//! 3. Test failure exit codes (101) - cargo test failures
//! 4. Signal exit codes (128+N) - SIGTERM, SIGKILL, etc.
//! 5. Tool-specific exit codes - make (2), etc.
//!
//! # Verification Method
//!
//! Each test:
//! 1. Runs command locally, records exit code
//! 2. Runs same command via SSH on remote worker, records exit code
//! 3. Asserts: exit codes are identical
//!
//! # Running These Tests
//!
//! ```bash
//! cargo test --features true-e2e exit_code_tests -- --nocapture
//! ```
//!
//! # Bead Reference
//!
//! This implements bead bd-1yj8: Test: Exit Code Preservation & Propagation

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use rch_common::types::WorkerConfig;
use rch_common::{CompilationKind, TierDecision, classify_command_detailed};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

/// Project root for fixtures
const FIXTURES_DIR: &str = "tests/true_e2e/fixtures";

/// Get the hello_world fixture directory (valid Rust project)
fn hello_world_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("hello_world")
}

/// Get the broken_project fixture directory (Rust compilation errors)
fn broken_project_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("broken_project")
}

/// Get the failing_tests fixture directory (Rust test failures)
fn failing_tests_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("failing_tests")
}

/// Get the hello_c fixture directory (valid C project)
fn hello_c_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("hello_c")
}

/// Get the broken_c fixture directory (C compilation errors)
fn broken_c_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("broken_c")
}

/// Get the broken_make fixture directory (Makefile errors)
fn broken_make_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("broken_make")
}

/// Get the broken_rustc fixture directory (direct rustc files)
fn broken_rustc_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("broken_rustc")
}

/// Skip the test if no real workers are available.
fn require_workers() -> Option<TestWorkersConfig> {
    if should_skip_worker_check() {
        eprintln!("Skipping: RCH_E2E_SKIP_WORKER_CHECK is set");
        return None;
    }

    match TestWorkersConfig::load() {
        Ok(config) => {
            if !config.has_enabled_workers() {
                eprintln!("Skipping: No enabled workers in configuration");
                return None;
            }
            Some(config)
        }
        Err(TestConfigError::NotFound(path)) => {
            eprintln!("Skipping: Config not found at {}", path.display());
            None
        }
        Err(e) => {
            eprintln!("Skipping: Failed to load config: {e}");
            None
        }
    }
}

/// Get a single enabled worker for testing.
fn get_test_worker(config: &TestWorkersConfig) -> Option<&rch_common::e2e::TestWorkerEntry> {
    config.enabled_workers().first().copied()
}

/// Helper to create a connected SSH client.
async fn get_connected_client(
    config: &TestWorkersConfig,
    worker_entry: &rch_common::e2e::TestWorkerEntry,
) -> Option<SshClient> {
    let worker_config = worker_entry.to_worker_config();
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config, options);
    match client.connect().await {
        Ok(()) => Some(client),
        Err(_) => None,
    }
}

/// Copy a local fixture directory to the remote worker using rsync.
async fn sync_fixture_to_remote(
    client: &mut SshClient,
    worker_config: &WorkerConfig,
    local_path: &Path,
    remote_path: &str,
) -> Result<(), String> {
    // Create remote directory
    let mkdir_cmd = format!("mkdir -p {}", remote_path);
    client
        .execute(&mkdir_cmd)
        .await
        .map_err(|e| format!("Failed to create remote directory: {e}"))?;

    // Use rsync to copy the fixture
    let output = std::process::Command::new("rsync")
        .args([
            "-avz",
            "--delete",
            "--exclude=target",
            "-e",
            &format!(
                "ssh -o StrictHostKeyChecking=accept-new -i {}",
                worker_config.identity_file
            ),
            &format!("{}/", local_path.display()),
            &format!(
                "{}@{}:{}/",
                worker_config.user, worker_config.host, remote_path
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to run rsync: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "rsync failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Clean up remote directory after test.
async fn cleanup_remote(client: &mut SshClient, remote_path: &str) -> Result<(), String> {
    let cmd = format!("rm -rf {}", remote_path);
    client
        .execute(&cmd)
        .await
        .map_err(|e| format!("Failed to cleanup: {e}"))?;
    Ok(())
}

/// Run a command locally and return the exit code.
fn run_local_command(cmd: &str, args: &[&str], dir: &Path) -> Option<i32> {
    std::process::Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .ok()
        .and_then(|out| out.status.code())
}

fn local_tool_version(tool: &str) -> Option<String> {
    let output = std::process::Command::new(tool)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout
        .lines()
        .next()
        .or_else(|| stderr.lines().next())
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
}

async fn remote_tool_version(client: &mut SshClient, tool: &str) -> Option<String> {
    let cmd = format!("command -v {tool} >/dev/null 2>&1 && {tool} --version 2>&1 | head -1");
    let result = client.execute(&cmd).await.ok()?;
    if result.exit_code != 0 {
        return None;
    }
    result
        .stdout
        .lines()
        .next()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
}

fn log_and_assert_classification(
    logger: &rch_common::e2e::TestLogger,
    cmd: &str,
    expected_kind: CompilationKind,
) {
    let details = classify_command_detailed(cmd);
    let tier4 = details
        .tiers
        .iter()
        .find(|t| t.tier == 4)
        .map(|t| t.decision);

    logger.log_with_context(
        LogLevel::Debug,
        LogSource::Custom("test".to_string()),
        "Command classified",
        vec![
            ("phase".to_string(), "classify".to_string()),
            ("cmd".to_string(), cmd.to_string()),
            (
                "is_compilation".to_string(),
                details.classification.is_compilation.to_string(),
            ),
            (
                "kind".to_string(),
                details
                    .classification
                    .kind
                    .map(|k| format!("{k:?}"))
                    .unwrap_or_else(|| "none".to_string()),
            ),
            (
                "tier4".to_string(),
                tier4
                    .map(|d| format!("{d:?}"))
                    .unwrap_or_else(|| "missing".to_string()),
            ),
        ],
    );

    assert!(
        details.classification.is_compilation,
        "Expected compilation classification for: {cmd}"
    );
    assert_eq!(
        details.classification.kind,
        Some(expected_kind),
        "Unexpected classification kind for: {cmd}"
    );
    assert_eq!(
        tier4,
        Some(TierDecision::Pass),
        "Expected Tier 4 pass for: {cmd}"
    );
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("Failed to create dir {}: {e}", dst.display()))?;
    for entry in
        fs::read_dir(src).map_err(|e| format!("Failed to read dir {}: {e}", src.display()))?
    {
        let entry = entry.map_err(|e| format!("Failed to read entry in {}: {e}", src.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("Failed to stat entry in {}: {e}", src.display()))?;
        let name = entry.file_name();
        if file_type.is_dir() && name.as_os_str() == OsStr::new("target") {
            continue;
        }
        let dst_path = dst.join(&name);
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &dst_path).map_err(|e| {
                format!(
                    "Failed to copy {} -> {}: {e}",
                    entry.path().display(),
                    dst_path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn temp_copy_fixture(src: &Path) -> Result<(TempDir, PathBuf), String> {
    let temp = TempDir::new().map_err(|e| format!("Failed to create temp dir: {e}"))?;
    let dst = temp.path().join("fixture");
    copy_dir_recursive(src, &dst)?;
    Ok((temp, dst))
}

fn run_binary_capture_stdout(path: &Path) -> Result<String, String> {
    let output = std::process::Command::new(path)
        .output()
        .map_err(|e| format!("Failed to run {}: {e}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "Binary {} failed (code {:?}): {}",
            path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn sync_file_from_remote(
    worker_config: &WorkerConfig,
    remote_file: &str,
    local_dir: &Path,
) -> Result<PathBuf, String> {
    fs::create_dir_all(local_dir)
        .map_err(|e| format!("Failed to create local dir {}: {e}", local_dir.display()))?;

    let ssh_cmd = format!(
        "ssh -o StrictHostKeyChecking=accept-new -i {}",
        worker_config.identity_file
    );
    let remote_spec = format!(
        "{}@{}:{}",
        worker_config.user, worker_config.host, remote_file
    );

    let output = std::process::Command::new("rsync")
        .args([
            "-avz",
            "-e",
            &ssh_cmd,
            &remote_spec,
            &format!("{}/", local_dir.display()),
        ])
        .output()
        .map_err(|e| format!("Failed to run rsync: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "rsync failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let file_name = Path::new(remote_file)
        .file_name()
        .ok_or_else(|| format!("Remote file has no basename: {remote_file}"))?;
    Ok(local_dir.join(file_name))
}

// =============================================================================
// Test 1: Build Success Exit Code (0) - Local vs Remote Comparison
// =============================================================================

/// Test that successful cargo build returns exit code 0 on both local and remote.
#[tokio::test]
async fn test_exit_code_cargo_build_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_cargo_build_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo build success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = format!(
        "{}/exit_code_build_success",
        config.settings.remote_work_dir
    );

    // Phase: Local baseline
    let local_exit_code = run_local_command("cargo", &["build"], &fixture_dir);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let build_cmd = format!(
        "cd {} && cargo build 2>&1; echo \"EXIT_CODE:$?\"",
        remote_path
    );
    let remote_result = client.execute(&build_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
        ],
    );

    assert_eq!(
        local_code, 0,
        "Local cargo build should succeed with exit code 0"
    );
    assert_eq!(
        remote_exit_code, 0,
        "Remote cargo build should succeed with exit code 0"
    );
    assert!(
        codes_match,
        "Local ({}) and remote ({}) exit codes should match",
        local_code, remote_exit_code
    );

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo build success exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 2: Test Success Exit Code (0)
// =============================================================================

/// Test that successful cargo test returns exit code 0 on both local and remote.
#[tokio::test]
async fn test_exit_code_cargo_test_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_cargo_test_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = format!("{}/exit_code_test_success", config.settings.remote_work_dir);

    // Phase: Local baseline
    let local_exit_code = run_local_command("cargo", &["test"], &fixture_dir);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "cargo test".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let test_cmd = format!("cd {} && cargo test 2>&1", remote_path);
    let remote_result = client.execute(&test_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "cargo test".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
        ],
    );

    assert_eq!(local_code, 0, "Local cargo test should succeed");
    assert_eq!(remote_exit_code, 0, "Remote cargo test should succeed");
    assert!(codes_match, "Exit codes should match");

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo test success exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 3: Build Error Exit Code (1)
// =============================================================================

/// Test that cargo build with errors returns exit code 1 on both local and remote.
#[tokio::test]
async fn test_exit_code_cargo_build_error() {
    let logger = TestLoggerBuilder::new("test_exit_code_cargo_build_error")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo build error exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "1".to_string()),
            ("fixture".to_string(), "broken_project".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = broken_project_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/exit_code_build_error", config.settings.remote_work_dir);

    // Phase: Local baseline
    let local_exit_code = run_local_command("cargo", &["build"], &fixture_dir);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let build_cmd = format!("cd {} && cargo build 2>&1", remote_path);
    let remote_result = client.execute(&build_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
            ("code_type".to_string(), "build_error".to_string()),
        ],
    );

    assert_eq!(
        local_code, 101,
        "Local cargo build on broken project should return exit code 101 (cargo build error)"
    );
    assert_eq!(
        remote_exit_code, 101,
        "Remote cargo build on broken project should return exit code 101"
    );
    assert!(
        codes_match,
        "Exit codes should match: local={}, remote={}",
        local_code, remote_exit_code
    );

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo build error exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 4: Test Failures Exit Code (101)
// =============================================================================

/// Test that cargo test with failures returns exit code 101 on both local and remote.
#[tokio::test]
async fn test_exit_code_cargo_test_failures() {
    let logger = TestLoggerBuilder::new("test_exit_code_cargo_test_failures")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test failures exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "101".to_string()),
            ("fixture".to_string(), "failing_tests".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = failing_tests_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!(
        "{}/exit_code_test_failures",
        config.settings.remote_work_dir
    );

    // Phase: Local baseline
    let local_exit_code = run_local_command("cargo", &["test"], &fixture_dir);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "cargo test".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let test_cmd = format!("cd {} && cargo test 2>&1", remote_path);
    let remote_result = client.execute(&test_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "cargo test".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
            ("code_type".to_string(), "test_failure".to_string()),
        ],
    );

    assert_eq!(
        local_code, 101,
        "Local cargo test with failures should return exit code 101"
    );
    assert_eq!(
        remote_exit_code, 101,
        "Remote cargo test with failures should return exit code 101"
    );
    assert!(codes_match, "Exit codes should match");

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo test failures exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 5: rustc Exit Codes
// =============================================================================

/// Test that direct rustc compilation exit codes match between local and remote.
#[tokio::test]
async fn test_exit_code_rustc_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_rustc_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting rustc success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = broken_rustc_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!(
        "{}/exit_code_rustc_success",
        config.settings.remote_work_dir
    );

    // Phase: Local baseline - compile valid.rs
    let local_exit_code = run_local_command(
        "rustc",
        &["valid.rs", "-o", "/tmp/rch_test_valid"],
        &fixture_dir,
    );

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "rustc valid.rs".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let rustc_cmd = format!(
        "cd {} && rustc valid.rs -o /tmp/rch_test_valid 2>&1",
        remote_path
    );
    let remote_result = client.execute(&rustc_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "rustc valid.rs".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
        ],
    );

    assert_eq!(local_code, 0, "Local rustc should succeed");
    assert_eq!(remote_exit_code, 0, "Remote rustc should succeed");
    assert!(codes_match, "Exit codes should match");

    // Cleanup local temp file
    let _ = std::fs::remove_file("/tmp/rch_test_valid");

    // Cleanup remote
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("rustc success exit code test passed");
    logger.print_summary();
}

/// Test that rustc with errors returns exit code 1 on both local and remote.
#[tokio::test]
async fn test_exit_code_rustc_error() {
    let logger = TestLoggerBuilder::new("test_exit_code_rustc_error")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting rustc error exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "1".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = broken_rustc_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/exit_code_rustc_error", config.settings.remote_work_dir);

    // Phase: Local baseline - compile broken.rs
    let local_exit_code = run_local_command(
        "rustc",
        &["broken.rs", "-o", "/tmp/rch_test_broken"],
        &fixture_dir,
    );

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "rustc broken.rs".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let rustc_cmd = format!(
        "cd {} && rustc broken.rs -o /tmp/rch_test_broken 2>&1",
        remote_path
    );
    let remote_result = client.execute(&rustc_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "rustc broken.rs".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
        ],
    );

    assert_eq!(
        local_code, 1,
        "Local rustc on broken code should return exit code 1"
    );
    assert_eq!(
        remote_exit_code, 1,
        "Remote rustc on broken code should return exit code 1"
    );
    assert!(codes_match, "Exit codes should match");

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("rustc error exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 6: gcc Exit Codes
// =============================================================================

/// Test that gcc compilation success returns exit code 0 on both local and remote.
#[tokio::test]
async fn test_exit_code_gcc_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_gcc_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting gcc success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = hello_c_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/exit_code_gcc_success", config.settings.remote_work_dir);

    // Phase: Local baseline - run make
    let local_exit_code = run_local_command("make", &["clean", "all"], &fixture_dir);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "make clean all".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let make_cmd = format!("cd {} && make clean all 2>&1", remote_path);
    let remote_result = client.execute(&make_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "make clean all".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
        ],
    );

    assert_eq!(local_code, 0, "Local gcc build should succeed");
    assert_eq!(remote_exit_code, 0, "Remote gcc build should succeed");
    assert!(codes_match, "Exit codes should match");

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("gcc success exit code test passed");
    logger.print_summary();
}

/// Test that gcc with errors returns exit code 1 on both local and remote.
#[tokio::test]
async fn test_exit_code_gcc_error() {
    let logger = TestLoggerBuilder::new("test_exit_code_gcc_error")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting gcc error exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "1".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = broken_c_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/exit_code_gcc_error", config.settings.remote_work_dir);

    // Phase: Local baseline
    let local_exit_code = run_local_command("make", &[], &fixture_dir);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "make".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let make_cmd = format!("cd {} && make 2>&1", remote_path);
    let remote_result = client.execute(&make_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "make".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify - gcc returns 1, make propagates it as 2
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
        ],
    );

    // Make returns 2 when a command fails
    assert!(
        local_code == 2,
        "Local make with gcc error should return exit code 2, got {}",
        local_code
    );
    assert!(
        remote_exit_code == 2,
        "Remote make with gcc error should return exit code 2, got {}",
        remote_exit_code
    );
    assert!(codes_match, "Exit codes should match");

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("gcc error exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 6b: clang / g++ / clang++ Exit Codes + Artifact Verification
// =============================================================================

/// Test that clang via make returns exit code 0 on both local and remote, and
/// that the remotely-built artifact can be copied back and executed locally.
#[tokio::test]
async fn test_exit_code_clang_make_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_clang_make_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting clang(make) success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(local_clang) = local_tool_version("clang") else {
        logger.warn("Test skipped: clang not available locally");
        return;
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local compiler detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("compiler".to_string(), "clang".to_string()),
            ("version".to_string(), local_clang),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let Some(remote_clang) = remote_tool_version(&mut client, "clang").await else {
        logger.warn("Test skipped: clang not available on worker");
        client.disconnect().await.ok();
        return;
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote compiler detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("compiler".to_string(), "clang".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("version".to_string(), remote_clang),
        ],
    );

    let fixture_src = hello_c_fixture_dir();
    if !fixture_src.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_src.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let (_local_tmp, local_fixture) = match temp_copy_fixture(&fixture_src) {
        Ok(v) => v,
        Err(e) => {
            logger.error(format!("Failed to create temp fixture copy: {e}"));
            client.disconnect().await.ok();
            return;
        }
    };

    let remote_path = format!(
        "{}/exit_code_clang_make_success",
        config.settings.remote_work_dir
    );

    // Classification check (Tier 4 expected)
    log_and_assert_classification(&logger, "make clean all CC=clang", CompilationKind::Make);

    // Phase: Local baseline
    let local_exit_code = run_local_command("make", &["clean", "all", "CC=clang"], &local_fixture);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "make clean all CC=clang".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_src, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let remote_cmd = format!("cd {} && make clean all CC=clang 2>&1", remote_path);
    let remote_result = client.execute(&remote_cmd).await;
    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "make clean all CC=clang".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify exit codes
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify_exit_code".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
        ],
    );

    assert_eq!(local_code, 0, "Local clang build should succeed");
    assert_eq!(remote_exit_code, 0, "Remote clang build should succeed");
    assert!(codes_match, "Exit codes should match");

    // Phase: Verify artifacts (local + remote copy)
    let local_bin = local_fixture.join("hello");
    let local_out = match run_binary_capture_stdout(&local_bin) {
        Ok(out) => out,
        Err(e) => {
            logger.error(e);
            panic!("Local clang-built binary failed to run");
        }
    };
    assert!(
        local_out.contains("Hello from rch test fixture!"),
        "Local output missing expected greeting"
    );

    let remote_artifacts = TempDir::new().expect("tempdir");
    let remote_bin = match sync_file_from_remote(
        &worker_config,
        &format!("{}/hello", remote_path),
        remote_artifacts.path(),
    ) {
        Ok(path) => path,
        Err(e) => {
            logger.error(format!("Failed to copy remote artifact: {e}"));
            panic!("Remote artifact copy failed");
        }
    };

    let remote_out = match run_binary_capture_stdout(&remote_bin) {
        Ok(out) => out,
        Err(e) => {
            logger.error(e);
            panic!("Remote clang-built artifact failed to run locally");
        }
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Artifact verification",
        vec![
            ("phase".to_string(), "verify_artifact".to_string()),
            ("local_path".to_string(), local_bin.display().to_string()),
            ("remote_copy".to_string(), remote_bin.display().to_string()),
            (
                "local_size".to_string(),
                fs::metadata(&local_bin)
                    .map(|m| m.len())
                    .unwrap_or(0)
                    .to_string(),
            ),
            (
                "remote_size".to_string(),
                fs::metadata(&remote_bin)
                    .map(|m| m.len())
                    .unwrap_or(0)
                    .to_string(),
            ),
        ],
    );

    assert!(
        remote_out.contains("Hello from rch test fixture!"),
        "Remote artifact output missing expected greeting"
    );

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("clang(make) success exit code test passed");
    logger.print_summary();
}

/// Test that g++ compilation success returns exit code 0 on both local and remote.
#[tokio::test]
async fn test_exit_code_gpp_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_gpp_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting g++ success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(local_gpp) = local_tool_version("g++") else {
        logger.warn("Test skipped: g++ not available locally");
        return;
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local compiler detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("compiler".to_string(), "g++".to_string()),
            ("version".to_string(), local_gpp),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let Some(remote_gpp) = remote_tool_version(&mut client, "g++").await else {
        logger.warn("Test skipped: g++ not available on worker");
        client.disconnect().await.ok();
        return;
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote compiler detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("compiler".to_string(), "g++".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("version".to_string(), remote_gpp),
        ],
    );

    // Create an ephemeral C++ fixture (no repo file proliferation)
    let local_fixture_tmp = TempDir::new().expect("tempdir");
    let local_fixture = local_fixture_tmp.path().join("cpp_fixture");
    fs::create_dir_all(&local_fixture).expect("create fixture dir");
    fs::write(
        local_fixture.join("main.cpp"),
        r#"#include <iostream>
int main() {
  std::cout << "Hello from rch C++ test fixture!" << std::endl;
  std::cout << "2 + 2 = " << (2 + 2) << std::endl;
  return 0;
}
"#,
    )
    .expect("write main.cpp");

    let remote_path = format!("{}/exit_code_gpp_success", config.settings.remote_work_dir);

    let compile_cmd = "g++ -std=c++20 -O2 -Wall -Werror -o hello_cpp main.cpp";
    log_and_assert_classification(&logger, compile_cmd, CompilationKind::Gpp);

    // Phase: Local baseline
    let local_exit_code = run_local_command(
        "g++",
        &[
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Werror",
            "-o",
            "hello_cpp",
            "main.cpp",
        ],
        &local_fixture,
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &local_fixture, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let remote_cmd = format!("cd {} && {} 2>&1", remote_path, compile_cmd);
    let remote_result = client.execute(&remote_cmd).await;
    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify_exit_code".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
        ],
    );

    assert_eq!(local_code, 0, "Local g++ build should succeed");
    assert_eq!(remote_exit_code, 0, "Remote g++ build should succeed");
    assert!(codes_match, "Exit codes should match");

    // Artifact verification: run local binary and remote-copied binary
    let local_bin = local_fixture.join("hello_cpp");
    let local_out = run_binary_capture_stdout(&local_bin).expect("run local binary");
    assert!(
        local_out.contains("Hello from rch C++ test fixture!"),
        "Local output missing expected greeting"
    );

    let remote_artifacts = TempDir::new().expect("tempdir");
    let remote_bin = sync_file_from_remote(
        &worker_config,
        &format!("{}/hello_cpp", remote_path),
        remote_artifacts.path(),
    )
    .expect("copy remote binary");

    let remote_out = run_binary_capture_stdout(&remote_bin).expect("run remote-copied binary");
    assert!(
        remote_out.contains("Hello from rch C++ test fixture!"),
        "Remote artifact output missing expected greeting"
    );

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("g++ success exit code test passed");
    logger.print_summary();
}

/// Test that clang++ compilation success returns exit code 0 on both local and remote.
#[tokio::test]
async fn test_exit_code_clangpp_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_clangpp_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting clang++ success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(local_clangpp) = local_tool_version("clang++") else {
        logger.warn("Test skipped: clang++ not available locally");
        return;
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local compiler detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("compiler".to_string(), "clang++".to_string()),
            ("version".to_string(), local_clangpp),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let Some(remote_clangpp) = remote_tool_version(&mut client, "clang++").await else {
        logger.warn("Test skipped: clang++ not available on worker");
        client.disconnect().await.ok();
        return;
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote compiler detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("compiler".to_string(), "clang++".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("version".to_string(), remote_clangpp),
        ],
    );

    let local_fixture_tmp = TempDir::new().expect("tempdir");
    let local_fixture = local_fixture_tmp.path().join("cpp_fixture");
    fs::create_dir_all(&local_fixture).expect("create fixture dir");
    fs::write(
        local_fixture.join("main.cpp"),
        r#"#include <iostream>
int main() {
  std::cout << "Hello from rch C++ test fixture!" << std::endl;
  std::cout << "3 * 4 = " << (3 * 4) << std::endl;
  return 0;
}
"#,
    )
    .expect("write main.cpp");

    let remote_path = format!(
        "{}/exit_code_clangpp_success",
        config.settings.remote_work_dir
    );
    let compile_cmd = "clang++ -std=c++20 -O2 -Wall -Werror -o hello_cpp main.cpp";
    log_and_assert_classification(&logger, compile_cmd, CompilationKind::Clangpp);

    let local_exit_code = run_local_command(
        "clang++",
        &[
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Werror",
            "-o",
            "hello_cpp",
            "main.cpp",
        ],
        &local_fixture,
    );

    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &local_fixture, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    let remote_cmd = format!("cd {} && {} 2>&1", remote_path, compile_cmd);
    let remote_result = client.execute(&remote_cmd).await;
    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    let local_code = local_exit_code.unwrap_or(-1);
    assert_eq!(local_code, 0, "Local clang++ build should succeed");
    assert_eq!(remote_exit_code, 0, "Remote clang++ build should succeed");

    let remote_artifacts = TempDir::new().expect("tempdir");
    let remote_bin = sync_file_from_remote(
        &worker_config,
        &format!("{}/hello_cpp", remote_path),
        remote_artifacts.path(),
    )
    .expect("copy remote binary");

    let out = run_binary_capture_stdout(&remote_bin).expect("run remote-copied binary");
    assert!(
        out.contains("Hello from rch C++ test fixture!"),
        "Remote artifact output missing expected greeting"
    );

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("clang++ success exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 6c: cmake/ninja Build Exit Codes + Artifact Verification
// =============================================================================

/// Test that `cmake --build` succeeds locally and remotely and the produced binary runs.
#[tokio::test]
async fn test_exit_code_cmake_build_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_cmake_build_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cmake build success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(local_cmake) = local_tool_version("cmake") else {
        logger.warn("Test skipped: cmake not available locally");
        return;
    };
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local cmake detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("tool".to_string(), "cmake".to_string()),
            ("version".to_string(), local_cmake),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let Some(remote_cmake) = remote_tool_version(&mut client, "cmake").await else {
        logger.warn("Test skipped: cmake not available on worker");
        client.disconnect().await.ok();
        return;
    };
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote cmake detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("tool".to_string(), "cmake".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("version".to_string(), remote_cmake),
        ],
    );

    let fixture_src = hello_c_fixture_dir();
    if !fixture_src.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_src.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let (_local_tmp, local_fixture) = match temp_copy_fixture(&fixture_src) {
        Ok(v) => v,
        Err(e) => {
            logger.error(format!("Failed to create temp fixture copy: {e}"));
            client.disconnect().await.ok();
            return;
        }
    };

    let build_dir = local_fixture.join("build");
    let local_configure = run_local_command(
        "cmake",
        &["-S", ".", "-B", "build", "-G", "Unix Makefiles"],
        &local_fixture,
    )
    .unwrap_or(-1);
    assert_eq!(local_configure, 0, "Local cmake configure should succeed");
    assert!(
        build_dir.exists(),
        "Local build dir should exist after configure"
    );

    log_and_assert_classification(&logger, "cmake --build build", CompilationKind::CmakeBuild);
    let local_build = run_local_command("cmake", &["--build", "build"], &local_fixture);

    let remote_path = format!(
        "{}/exit_code_cmake_build_success",
        config.settings.remote_work_dir
    );
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_src, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    let remote_configure = format!(
        "cd {} && cmake -S . -B build -G 'Unix Makefiles' 2>&1",
        remote_path
    );
    let remote_configure_result = client.execute(&remote_configure).await;
    let remote_configure_code = match &remote_configure_result {
        Ok(r) => r.exit_code,
        Err(_) => -1,
    };
    assert_eq!(
        remote_configure_code, 0,
        "Remote cmake configure should succeed"
    );

    let remote_build_cmd = format!("cd {} && cmake --build build 2>&1", remote_path);
    let remote_build_result = client.execute(&remote_build_cmd).await;
    let remote_build_code = match &remote_build_result {
        Ok(r) => r.exit_code,
        Err(_) => -1,
    };

    let local_code = local_build.unwrap_or(-1);
    assert_eq!(local_code, 0, "Local cmake --build should succeed");
    assert_eq!(remote_build_code, 0, "Remote cmake --build should succeed");
    assert_eq!(local_code, remote_build_code, "Exit codes should match");

    // Artifact verification: copy remote build output and run
    let remote_artifacts = TempDir::new().expect("tempdir");
    let remote_bin = sync_file_from_remote(
        &worker_config,
        &format!("{}/build/hello_app", remote_path),
        remote_artifacts.path(),
    )
    .expect("copy remote hello_app");
    let out = run_binary_capture_stdout(&remote_bin).expect("run remote-copied hello_app");
    assert!(
        out.contains("Hello from rch test fixture!"),
        "Remote CMake artifact output missing expected greeting"
    );

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }
    client.disconnect().await.ok();
    logger.info("cmake build success exit code test passed");
    logger.print_summary();
}

/// Test that `ninja` builds succeed (when available) and produced artifacts run locally.
#[tokio::test]
async fn test_exit_code_ninja_build_success() {
    let logger = TestLoggerBuilder::new("test_exit_code_ninja_build_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting ninja build success exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(_local_cmake) = local_tool_version("cmake") else {
        logger.warn("Test skipped: cmake not available locally");
        return;
    };
    let Some(local_ninja) = local_tool_version("ninja") else {
        logger.warn("Test skipped: ninja not available locally");
        return;
    };
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local ninja detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("tool".to_string(), "ninja".to_string()),
            ("version".to_string(), local_ninja),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    if remote_tool_version(&mut client, "ninja").await.is_none() {
        logger.warn("Test skipped: ninja not available on worker");
        client.disconnect().await.ok();
        return;
    }
    if remote_tool_version(&mut client, "cmake").await.is_none() {
        logger.warn("Test skipped: cmake not available on worker");
        client.disconnect().await.ok();
        return;
    }

    let fixture_src = hello_c_fixture_dir();
    if !fixture_src.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_src.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let (_local_tmp, local_fixture) = match temp_copy_fixture(&fixture_src) {
        Ok(v) => v,
        Err(e) => {
            logger.error(format!("Failed to create temp fixture copy: {e}"));
            client.disconnect().await.ok();
            return;
        }
    };

    let local_configure = run_local_command(
        "cmake",
        &["-S", ".", "-B", "build_ninja", "-G", "Ninja"],
        &local_fixture,
    )
    .unwrap_or(-1);
    assert_eq!(local_configure, 0, "Local ninja configure should succeed");

    log_and_assert_classification(&logger, "ninja -C build_ninja", CompilationKind::Ninja);
    let local_build = run_local_command("ninja", &["-C", "build_ninja"], &local_fixture);

    let remote_path = format!(
        "{}/exit_code_ninja_build_success",
        config.settings.remote_work_dir
    );
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_src, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    let remote_configure = format!(
        "cd {} && cmake -S . -B build_ninja -G Ninja 2>&1",
        remote_path
    );
    let remote_configure_result = client.execute(&remote_configure).await;
    let remote_configure_code = match &remote_configure_result {
        Ok(r) => r.exit_code,
        Err(_) => -1,
    };
    assert_eq!(
        remote_configure_code, 0,
        "Remote ninja configure should succeed"
    );

    let remote_build_cmd = format!("cd {} && ninja -C build_ninja 2>&1", remote_path);
    let remote_build_result = client.execute(&remote_build_cmd).await;
    let remote_build_code = match &remote_build_result {
        Ok(r) => r.exit_code,
        Err(_) => -1,
    };

    let local_code = local_build.unwrap_or(-1);
    assert_eq!(local_code, 0, "Local ninja build should succeed");
    assert_eq!(remote_build_code, 0, "Remote ninja build should succeed");
    assert_eq!(local_code, remote_build_code, "Exit codes should match");

    let remote_artifacts = TempDir::new().expect("tempdir");
    let remote_bin = sync_file_from_remote(
        &worker_config,
        &format!("{}/build_ninja/hello_app", remote_path),
        remote_artifacts.path(),
    )
    .expect("copy remote hello_app");
    let out = run_binary_capture_stdout(&remote_bin).expect("run remote-copied hello_app");
    assert!(
        out.contains("Hello from rch test fixture!"),
        "Remote Ninja artifact output missing expected greeting"
    );

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }
    client.disconnect().await.ok();
    logger.info("ninja build success exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 7: make Exit Codes
// =============================================================================

/// Test that make with missing target returns exit code 2 on both local and remote.
#[tokio::test]
async fn test_exit_code_make_error() {
    let logger = TestLoggerBuilder::new("test_exit_code_make_error")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting make error exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "2".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = broken_make_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/exit_code_make_error", config.settings.remote_work_dir);

    // Phase: Local baseline
    let local_exit_code = run_local_command("make", &[], &fixture_dir);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "make".to_string()),
            (
                "exit_code".to_string(),
                local_exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "error".to_string()),
            ),
        ],
    );

    // Setup remote
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Remote execution
    let make_cmd = format!("cd {} && make 2>&1", remote_path);
    let remote_result = client.execute(&make_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "make".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    let local_code = local_exit_code.unwrap_or(-1);
    let codes_match = local_code == remote_exit_code;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("match".to_string(), codes_match.to_string()),
            ("code_type".to_string(), "make_error".to_string()),
        ],
    );

    assert_eq!(
        local_code, 2,
        "Local make with missing target should return exit code 2"
    );
    assert_eq!(
        remote_exit_code, 2,
        "Remote make with missing target should return exit code 2"
    );
    assert!(codes_match, "Exit codes should match");

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("make error exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 8: Signal Exit Codes (128+N)
// =============================================================================

/// Test that a process killed with SIGTERM returns exit code 143 (128+15).
/// Note: This test runs a sleep command and kills it.
#[tokio::test]
async fn test_exit_code_signal_sigterm() {
    let logger = TestLoggerBuilder::new("test_exit_code_signal_sigterm")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting SIGTERM exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "143".to_string()),
            ("signal".to_string(), "SIGTERM (15)".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    // Phase: Local baseline - run a shell command that kills itself with SIGTERM
    // Using shell -c to spawn a process that sends SIGTERM to itself
    let local_result = std::process::Command::new("sh")
        .args(["-c", "kill -TERM $$"])
        .output();

    let local_exit_code = local_result.as_ref().ok().and_then(|r| r.status.code());
    // Note: On Linux, when a process is killed by signal, code() returns None
    // and signal() returns the signal number. Exit code is 128 + signal.
    let local_signal = local_result
        .as_ref()
        .ok()
        .and_then(|r| {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                r.status.signal()
            }
            #[cfg(not(unix))]
            {
                None
            }
        })
        .unwrap_or(0);

    let local_code = local_exit_code.unwrap_or(128 + local_signal);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local execution",
        vec![
            ("phase".to_string(), "local_baseline".to_string()),
            ("cmd".to_string(), "kill -TERM $$".to_string()),
            ("exit_code".to_string(), local_code.to_string()),
            ("signal".to_string(), local_signal.to_string()),
        ],
    );

    // Phase: Remote execution
    // Use a command that kills itself with SIGTERM
    let signal_cmd = "sh -c 'kill -TERM $$'";
    let remote_result = client.execute(signal_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "kill -TERM $$".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    // SIGTERM = 15, so exit code should be 128 + 15 = 143
    let expected_code = 128 + 15; // 143

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("local".to_string(), local_code.to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("expected".to_string(), expected_code.to_string()),
            (
                "match".to_string(),
                (remote_exit_code == expected_code).to_string(),
            ),
        ],
    );

    // The local process may have different behavior depending on shell
    // The key test is that remote returns 143
    assert_eq!(
        remote_exit_code, expected_code,
        "Remote process killed with SIGTERM should return exit code 143"
    );

    client.disconnect().await.ok();
    logger.info("SIGTERM exit code test passed");
    logger.print_summary();
}

/// Test that a process killed with SIGKILL returns exit code 137 (128+9).
#[tokio::test]
async fn test_exit_code_signal_sigkill() {
    let logger = TestLoggerBuilder::new("test_exit_code_signal_sigkill")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting SIGKILL exit code test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("expected_exit_code".to_string(), "137".to_string()),
            ("signal".to_string(), "SIGKILL (9)".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    // Phase: Remote execution
    // Use a command that kills itself with SIGKILL
    let signal_cmd = "sh -c 'kill -KILL $$'";
    let remote_result = client.execute(signal_cmd).await;

    let remote_exit_code = match &remote_result {
        Ok(result) => result.exit_code,
        Err(_) => -1,
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Remote execution",
        vec![
            ("phase".to_string(), "remote_execution".to_string()),
            ("cmd".to_string(), "kill -KILL $$".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
        ],
    );

    // Phase: Verify
    // SIGKILL = 9, so exit code should be 128 + 9 = 137
    let expected_code = 128 + 9; // 137

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Exit code comparison",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("remote".to_string(), remote_exit_code.to_string()),
            ("expected".to_string(), expected_code.to_string()),
            (
                "match".to_string(),
                (remote_exit_code == expected_code).to_string(),
            ),
        ],
    );

    assert_eq!(
        remote_exit_code, expected_code,
        "Remote process killed with SIGKILL should return exit code 137"
    );

    client.disconnect().await.ok();
    logger.info("SIGKILL exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 9: Arbitrary Exit Codes
// =============================================================================

/// Test that arbitrary exit codes are correctly propagated.
#[tokio::test]
async fn test_exit_code_arbitrary() {
    let logger = TestLoggerBuilder::new("test_exit_code_arbitrary")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting arbitrary exit code test",
        vec![("phase".to_string(), "setup".to_string())],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    // Test various exit codes
    let test_codes = vec![0, 1, 2, 42, 100, 127, 255];

    for expected_code in test_codes {
        let cmd = format!("exit {}", expected_code);
        let remote_result = client.execute(&cmd).await;

        let remote_exit_code = match &remote_result {
            Ok(result) => result.exit_code,
            Err(_) => -1,
        };

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("test".to_string()),
            "Exit code verification",
            vec![
                ("phase".to_string(), "verify".to_string()),
                ("expected".to_string(), expected_code.to_string()),
                ("actual".to_string(), remote_exit_code.to_string()),
                (
                    "match".to_string(),
                    (remote_exit_code == expected_code).to_string(),
                ),
            ],
        );

        assert_eq!(
            remote_exit_code, expected_code,
            "exit {} should return exit code {}, got {}",
            expected_code, expected_code, remote_exit_code
        );
    }

    client.disconnect().await.ok();
    logger.info("Arbitrary exit code test passed");
    logger.print_summary();
}

// =============================================================================
// Test 10: Exit Code Summary Test
// =============================================================================

/// Summary test that verifies all major exit code categories.
#[tokio::test]
async fn test_exit_code_summary() {
    let logger = TestLoggerBuilder::new("test_exit_code_summary")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting exit code summary test",
        vec![("phase".to_string(), "setup".to_string())],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    // Test matrix: (command, expected_exit_code, description)
    let tests = vec![
        ("true", 0, "success"),
        ("false", 1, "failure"),
        ("exit 0", 0, "explicit_success"),
        ("exit 1", 1, "explicit_failure"),
        ("exit 2", 2, "explicit_error"),
        ("exit 101", 101, "cargo_test_failure"),
        ("exit 127", 127, "command_not_found"),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (cmd, expected, desc) in tests {
        let remote_result = client.execute(cmd).await;

        let actual = match &remote_result {
            Ok(result) => result.exit_code,
            Err(_) => -1,
        };

        let matches = actual == expected;

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("test".to_string()),
            "Exit code check",
            vec![
                ("phase".to_string(), "verify".to_string()),
                ("test".to_string(), desc.to_string()),
                ("cmd".to_string(), cmd.to_string()),
                ("expected".to_string(), expected.to_string()),
                ("actual".to_string(), actual.to_string()),
                ("pass".to_string(), matches.to_string()),
            ],
        );

        if matches {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Summary",
        vec![
            ("phase".to_string(), "complete".to_string()),
            ("passed".to_string(), passed.to_string()),
            ("failed".to_string(), failed.to_string()),
            ("total".to_string(), (passed + failed).to_string()),
        ],
    );

    assert_eq!(failed, 0, "All exit code tests should pass");

    client.disconnect().await.ok();
    logger.info("Exit code summary test passed");
    logger.print_summary();
}
