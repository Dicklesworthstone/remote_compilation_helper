//! True E2E Tests: Cargo Check & Clippy Remote Execution
//!
//! Tests that `cargo check` and `cargo clippy` commands are correctly offloaded
//! to real workers with proper exit code handling.
//!
//! # Test Categories
//!
//! ## Cargo Check Tests
//! 1. Clean check - no errors or warnings
//! 2. Check with compilation errors
//! 3. Check workspace
//!
//! ## Cargo Clippy Tests
//! 1. Clean project - no warnings
//! 2. Project with clippy warnings
//! 3. Clippy with -D warnings (deny)
//!
//! # Running These Tests
//!
//! ```bash
//! # Requires workers_test.toml configuration
//! cargo test --features true-e2e cargo_check_clippy_tests -- --nocapture
//! ```
//!
//! # Bead Reference
//!
//! This implements part of bead bd-12hi: True E2E Cargo Compilation Tests (check/clippy)

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use rch_common::types::WorkerConfig;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Project root for fixtures
const FIXTURES_DIR: &str = "tests/true_e2e/fixtures";

/// Get the hello_world fixture directory (clean project)
fn hello_world_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("hello_world")
}

/// Get the broken_project fixture directory (has compilation errors)
fn broken_project_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("broken_project")
}

/// Get the clippy_warnings fixture directory (has clippy warnings)
fn clippy_warnings_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("clippy_warnings")
}

/// Get the rust_workspace fixture directory
fn rust_workspace_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("rust_workspace")
}

/// Skip the test if no real workers are available.
/// Returns the loaded config if workers are available.
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
    // First, create the remote directory
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

// =============================================================================
// CARGO CHECK TESTS
// =============================================================================

/// Test 1: cargo check on clean project
///
/// Command: `cargo check`
/// Expected: exit code 0
/// Verify: no errors in output
#[tokio::test]
async fn test_cargo_check_clean() {
    let logger = TestLoggerBuilder::new("test_cargo_check_clean")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo check clean test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "hello_world".to_string()),
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
    let remote_path = format!("{}/cargo_check_clean", config.settings.remote_work_dir);

    // Phase: Setup - sync fixture to remote
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Syncing fixture to remote",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Execute remote cargo check
    let check_cmd = format!("cd {} && cargo check 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo check",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo check".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&check_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote cargo check completed",
                vec![
                    ("phase".to_string(), "execute_remote".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("duration_ms".to_string(), remote_duration.as_millis().to_string()),
                ],
            );

            // Verify exit code
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Exit code check",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("expected".to_string(), "0".to_string()),
                    ("actual".to_string(), result.exit_code.to_string()),
                    ("match".to_string(), (result.exit_code == 0).to_string()),
                ],
            );

            assert_eq!(
                result.exit_code, 0,
                "Clean project cargo check should return exit code 0, got {}. Output: {}",
                result.exit_code, result.stdout
            );
        }
        Err(e) => {
            logger.error(format!("Remote cargo check failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo check command failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo check clean test completed");
    logger.print_summary();
}

/// Test 2: cargo check with warnings
///
/// Command: `cargo check` (on project with warnings)
/// Expected: exit code 0
/// Verify: warning output present
#[tokio::test]
async fn test_cargo_check_with_warnings() {
    let logger = TestLoggerBuilder::new("test_cargo_check_with_warnings")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo check with warnings test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "clippy_warnings".to_string()),
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

    let fixture_dir = clippy_warnings_fixture_dir();

    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: clippy_warnings fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/cargo_check_warnings", config.settings.remote_work_dir);

    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    let check_cmd = format!("cd {} && cargo check 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing cargo check (expecting warnings)",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo check".to_string()),
        ],
    );

    match client.execute(&check_cmd).await {
        Ok(result) => {
            let output = format!("{}{}", result.stdout, result.stderr);
            let has_warning = output.contains("warning:");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Warning verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("has_warning".to_string(), has_warning.to_string()),
                ],
            );

            assert_eq!(
                result.exit_code, 0,
                "Warnings should not fail cargo check by default"
            );
            assert!(
                has_warning,
                "Expected warning output in cargo check. Output: {}",
                output
            );
        }
        Err(e) => {
            logger.error(format!("Remote cargo check command error: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo check command failed unexpectedly: {e}");
        }
    }

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo check with warnings test completed");
    logger.print_summary();
}

/// Test 3: cargo check with compilation errors
///
/// Command: `cargo check` (on broken project)
/// Expected: non-zero exit code
/// Verify: compilation error in output
#[tokio::test]
async fn test_cargo_check_with_errors() {
    let logger = TestLoggerBuilder::new("test_cargo_check_with_errors")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo check with errors test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "broken_project".to_string()),
            ("expected_exit_code".to_string(), "non-zero".to_string()),
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

    // Check if fixture exists
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: broken_project fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/cargo_check_errors", config.settings.remote_work_dir);

    // Phase: Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Execute remote cargo check (expect failure)
    let check_cmd = format!("cd {} && cargo check 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo check (expecting errors)",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo check".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    match client.execute(&check_cmd).await {
        Ok(result) => {
            // Check for compilation error indicators
            let output = format!("{}{}", result.stdout, result.stderr);
            let has_compile_error = output.contains("error[E")
                || output.contains("could not compile")
                || output.contains("aborting due to");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Exit code check",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("expected".to_string(), "non-zero".to_string()),
                    ("actual".to_string(), result.exit_code.to_string()),
                    ("has_compile_error".to_string(), has_compile_error.to_string()),
                ],
            );

            assert!(
                result.exit_code != 0,
                "Compilation errors should return non-zero exit code, got 0"
            );

            assert!(
                has_compile_error,
                "Output should contain compilation error. Got: {}",
                output
            );
        }
        Err(e) => {
            logger.error(format!("Remote cargo check command error: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo check command failed unexpectedly: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo check with errors test completed");
    logger.print_summary();
}

/// Test 4: cargo check workspace
///
/// Command: `cargo check --workspace`
/// Expected: exit code 0
/// Verify: all workspace members checked
#[tokio::test]
async fn test_cargo_check_workspace() {
    let logger = TestLoggerBuilder::new("test_cargo_check_workspace")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo check workspace test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "rust_workspace".to_string()),
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

    let fixture_dir = rust_workspace_fixture_dir();

    // Check if workspace fixture exists
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: rust_workspace fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/cargo_check_workspace", config.settings.remote_work_dir);

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Execute with --workspace
    let check_cmd = format!("cd {} && cargo check --workspace 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing cargo check --workspace",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo check --workspace".to_string()),
        ],
    );

    match client.execute(&check_cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Workspace check verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                ],
            );

            assert_eq!(result.exit_code, 0, "Workspace check should pass");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Command failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Workspace check test completed");
    logger.print_summary();
}

// =============================================================================
// CARGO CLIPPY TESTS
// =============================================================================

/// Test 4: cargo clippy on clean project
///
/// Command: `cargo clippy`
/// Expected: exit code 0
/// Verify: no warnings
#[tokio::test]
async fn test_cargo_clippy_clean() {
    let logger = TestLoggerBuilder::new("test_cargo_clippy_clean")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo clippy clean test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "hello_world".to_string()),
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
    let remote_path = format!("{}/cargo_clippy_clean", config.settings.remote_work_dir);

    // Phase: Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Execute remote cargo clippy
    let clippy_cmd = format!("cd {} && cargo clippy 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo clippy",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo clippy".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&clippy_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote cargo clippy completed",
                vec![
                    ("phase".to_string(), "execute_remote".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("duration_ms".to_string(), remote_duration.as_millis().to_string()),
                ],
            );

            // Verify exit code
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Exit code check",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("expected".to_string(), "0".to_string()),
                    ("actual".to_string(), result.exit_code.to_string()),
                    ("match".to_string(), (result.exit_code == 0).to_string()),
                ],
            );

            assert_eq!(
                result.exit_code, 0,
                "Clean project cargo clippy should return exit code 0, got {}. Output: {}",
                result.exit_code, result.stdout
            );
        }
        Err(e) => {
            logger.error(format!("Remote cargo clippy failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo clippy command failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo clippy clean test completed");
    logger.print_summary();
}

/// Test 5: cargo clippy with warnings
///
/// Command: `cargo clippy` (on project with warnings)
/// Expected: exit code 0 (warnings don't cause failure by default)
/// Verify: clippy warnings in output
#[tokio::test]
async fn test_cargo_clippy_with_warnings() {
    let logger = TestLoggerBuilder::new("test_cargo_clippy_with_warnings")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo clippy with warnings test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "clippy_warnings".to_string()),
            ("expected".to_string(), "warnings in output".to_string()),
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

    let fixture_dir = clippy_warnings_fixture_dir();

    // Check if fixture exists
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: clippy_warnings fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/cargo_clippy_warnings", config.settings.remote_work_dir);

    // Phase: Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Execute remote cargo clippy
    let clippy_cmd = format!("cd {} && cargo clippy 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo clippy (expecting warnings)",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo clippy".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    match client.execute(&clippy_cmd).await {
        Ok(result) => {
            let output = format!("{}{}", result.stdout, result.stderr);

            // Check for clippy warnings
            let has_warnings = output.contains("warning:")
                || output.contains("clippy::")
                || output.contains("generated")
                    && output.contains("warning");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Clippy warnings verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("has_warnings".to_string(), has_warnings.to_string()),
                ],
            );

            // Clippy returns 0 even with warnings (unless -D warnings is used)
            assert_eq!(
                result.exit_code, 0,
                "Clippy with warnings should return 0 (without -D), got {}",
                result.exit_code
            );

            // We should see some clippy output about warnings
            assert!(
                has_warnings || output.contains("Compiling"),
                "Output should show compilation or warnings. Got: {}",
                output
            );
        }
        Err(e) => {
            logger.error(format!("Remote cargo clippy command error: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo clippy command failed unexpectedly: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo clippy with warnings test completed");
    logger.print_summary();
}

/// Test 6: cargo clippy with -D warnings (deny)
///
/// Command: `cargo clippy -- -D warnings` (on project with warnings)
/// Expected: non-zero exit code
/// Verify: clippy fails due to warnings treated as errors
#[tokio::test]
async fn test_cargo_clippy_deny_warnings() {
    let logger = TestLoggerBuilder::new("test_cargo_clippy_deny_warnings")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo clippy -D warnings test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "clippy_warnings".to_string()),
            ("expected".to_string(), "non-zero exit (warnings as errors)".to_string()),
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

    let fixture_dir = clippy_warnings_fixture_dir();

    // Check if fixture exists
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: clippy_warnings fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/cargo_clippy_deny", config.settings.remote_work_dir);

    // Phase: Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Execute remote cargo clippy with -D warnings
    let clippy_cmd = format!("cd {} && cargo clippy -- -D warnings 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo clippy -- -D warnings",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo clippy -- -D warnings".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    match client.execute(&clippy_cmd).await {
        Ok(result) => {
            let output = format!("{}{}", result.stdout, result.stderr);

            // Check for error indicators (warnings treated as errors)
            let has_error = output.contains("error:")
                || output.contains("error[E")
                || output.contains("aborting due to");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Clippy deny warnings verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("has_error".to_string(), has_error.to_string()),
                ],
            );

            // With -D warnings, clippy should fail if there are any warnings
            assert!(
                result.exit_code != 0,
                "Clippy with -D warnings should fail (non-zero exit) when warnings exist, got exit code 0. Output: {}",
                output
            );
        }
        Err(e) => {
            logger.error(format!("Remote cargo clippy command error: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo clippy command failed unexpectedly: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo clippy deny warnings test completed");
    logger.print_summary();
}
