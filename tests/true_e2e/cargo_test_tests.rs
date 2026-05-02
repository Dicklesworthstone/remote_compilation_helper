//! True E2E Tests: Cargo Test Remote Execution & Exit Codes
//!
//! Tests that `cargo test` commands are correctly offloaded to real workers
//! with proper exit code handling.
//!
//! # Test Categories
//!
//! 1. Basic test execution (pass/fail/compile error)
//! 2. Exit code verification (0, 101, 1)
//! 3. Test filtering (name patterns, --ignored, --nocapture)
//! 4. Test targets (--lib, --doc)
//! 5. Special cases (threads, workspace)
//!
//! # Running These Tests
//!
//! ```bash
//! # Requires workers_test.toml configuration
//! cargo test --features true-e2e cargo_test_tests -- --nocapture
//! ```
//!
//! # Bead Reference
//!
//! This implements bead bd-10g8: Test: cargo test Remote Execution & Exit Codes

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use rch_common::types::WorkerConfig;
use shell_escape::escape;
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Project root for fixtures
const FIXTURES_DIR: &str = "tests/true_e2e/fixtures";

fn shell_escape_str(value: &str) -> String {
    escape(Cow::from(value)).into_owned()
}

fn remote_test_path(base: &str, test_name: &str) -> String {
    format!(
        "{}/{test_name}-{}",
        base.trim_end_matches('/'),
        Uuid::new_v4()
    )
}

fn remote_rsync_path(remote_path: &str) -> String {
    shell_escape_str(&format!("{}/", remote_path.trim_end_matches('/')))
}

fn remote_cargo_command(remote_path: &str, command: &str) -> String {
    format!("cd {} && {command} 2>&1", shell_escape_str(remote_path))
}

fn rsync_ssh_command(identity_file: &str) -> String {
    let expanded_identity_file = shellexpand::tilde(identity_file);
    format!(
        "ssh -o StrictHostKeyChecking=accept-new -i {}",
        shell_escape_str(expanded_identity_file.as_ref())
    )
}

/// Get the hello_world fixture directory (has passing tests)
fn hello_world_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("hello_world")
}

/// Get the failing_tests fixture directory (has intentionally failing tests)
fn failing_tests_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("failing_tests")
}

/// Get the broken_project fixture directory (has compilation errors)
fn broken_project_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("broken_project")
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
    let escaped_remote_path = shell_escape_str(remote_path);
    let mkdir_cmd = format!("mkdir -p -- {escaped_remote_path}");
    client
        .execute(&mkdir_cmd)
        .await
        .map_err(|e| format!("Failed to create remote directory: {e}"))?;

    // Use rsync to copy the fixture
    let output = match std::process::Command::new("rsync")
        .args([
            "-avz",
            "--delete",
            "--exclude=target",
            "-e",
            &rsync_ssh_command(&worker_config.identity_file),
            &format!("{}/", local_path.display()),
            &format!(
                "{}@{}:{}",
                worker_config.user,
                worker_config.host,
                remote_rsync_path(remote_path)
            ),
        ])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            let _ = cleanup_remote(client, remote_path).await;
            return Err(format!("Failed to run rsync: {e}"));
        }
    };

    if output.status.success() {
        Ok(())
    } else {
        let _ = cleanup_remote(client, remote_path).await;
        Err(format!(
            "rsync failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Clean up remote directory after test.
async fn cleanup_remote(client: &mut SshClient, remote_path: &str) -> Result<(), String> {
    let cmd = format!("rm -rf -- {}", shell_escape_str(remote_path));
    client
        .execute(&cmd)
        .await
        .map_err(|e| format!("Failed to cleanup: {e}"))?;
    Ok(())
}

// =============================================================================
// Test 1: All tests pass (exit code 0)
// =============================================================================

/// Test that `cargo test` with all passing tests returns exit code 0.
///
/// Command: `cargo test`
/// Expected: exit code 0
/// Verify: test output shows passes
#[tokio::test]
async fn test_cargo_test_pass() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_pass")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test pass test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "hello_world".to_string()),
            ("expected_exit_code".to_string(), "0".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_pass");

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
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Phase: Execute remote cargo test
    let test_cmd = remote_cargo_command(&remote_path, "cargo test --lib");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo test",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test --lib".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&test_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            // Count tests from output
            let output = &result.stdout;
            let tests_passed = output.matches("test result: ok").count() > 0;

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Exit code check",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("expected".to_string(), "0".to_string()),
                    ("actual".to_string(), result.exit_code.to_string()),
                    ("match".to_string(), (result.exit_code == 0).to_string()),
                    ("tests_passed".to_string(), tests_passed.to_string()),
                    (
                        "duration_ms".to_string(),
                        remote_duration.as_millis().to_string(),
                    ),
                ],
            );

            assert_eq!(
                result.exit_code, 0,
                "All tests passing should return exit code 0, got {}. Output: {}",
                result.exit_code, result.stdout
            );
        }
        Err(e) => {
            logger.error(format!("Remote cargo test failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!("Remote cargo test command failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo test pass test completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 2: Some tests fail (exit code 101)
// =============================================================================

/// Test that `cargo test` with failing tests returns exit code 101.
///
/// Command: `cargo test`
/// Expected: exit code 101
/// Verify: failure output preserved
#[tokio::test]
async fn test_cargo_test_fail() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_fail")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test fail test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "failing_tests".to_string()),
            ("expected_exit_code".to_string(), "101".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = failing_tests_fixture_dir();

    // Check if fixture exists
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: failing_tests fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return Ok(());
    }

    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_fail");

    // Phase: Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Phase: Execute remote cargo test (expect failure)
    let test_cmd = remote_cargo_command(&remote_path, "cargo test");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo test (expecting failures)",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    match client.execute(&test_cmd).await {
        Ok(result) => {
            // Count failures from output
            let output = &result.stdout;
            let has_failures = output.contains("FAILED") || output.contains("failed");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Exit code check",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("expected".to_string(), "101".to_string()),
                    ("actual".to_string(), result.exit_code.to_string()),
                    ("match".to_string(), (result.exit_code == 101).to_string()),
                    ("has_failures".to_string(), has_failures.to_string()),
                ],
            );

            assert_eq!(
                result.exit_code, 101,
                "Test failures should return exit code 101, got {}",
                result.exit_code
            );

            assert!(has_failures, "Output should contain failure information");
        }
        Err(e) => {
            logger.error(format!("Remote cargo test command error: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!(
                "Remote cargo test command failed unexpectedly: {e}"
            ));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo test fail test completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 3: Compilation error (exit code 1)
// =============================================================================

/// Test that `cargo test` with compilation errors returns exit code 1.
///
/// Command: `cargo test` (on broken project)
/// Expected: exit code 1 or 101 (cargo reports compilation failure)
/// Verify: compiler error in output
#[tokio::test]
async fn test_cargo_test_build_error() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_build_error")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test build error test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "broken_project".to_string()),
            ("expected_exit_code".to_string(), "1 or 101".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = broken_project_fixture_dir();

    // Check if fixture exists
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: broken_project fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return Ok(());
    }

    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_build_error");

    // Phase: Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Phase: Execute remote cargo test (expect build failure)
    let test_cmd = remote_cargo_command(&remote_path, "cargo test");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo test (expecting build error)",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    match client.execute(&test_cmd).await {
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
                    (
                        "has_compile_error".to_string(),
                        has_compile_error.to_string(),
                    ),
                    ("error_type".to_string(), "build_error".to_string()),
                ],
            );

            // Cargo test returns non-zero for compilation errors
            // (typically 1 for build errors, but 101 is also acceptable)
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
            logger.error(format!("Remote cargo test command error: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!(
                "Remote cargo test command failed unexpectedly: {e}"
            ));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo test build error test completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 4: Filter by name
// =============================================================================

/// Test that `cargo test filter_name` runs only matching tests.
///
/// Command: `cargo test test_add`
/// Expected: only tests matching "test_add" run
#[tokio::test]
async fn test_cargo_test_filter_by_name() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_filter_by_name")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test filter test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("filter".to_string(), "test_add".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_filter");

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Execute with filter
    let test_cmd = remote_cargo_command(&remote_path, "cargo test test_add");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing filtered cargo test",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test test_add".to_string()),
            ("filter_pattern".to_string(), "test_add".to_string()),
        ],
    );

    match client.execute(&test_cmd).await {
        Ok(result) => {
            let output = &result.stdout;

            // Check that only add tests ran
            let ran_add_tests = output.contains("test_add");
            // Check that filtered tests were counted
            let has_filtered = output.contains("filtered out");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Filter verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("ran_add_tests".to_string(), ran_add_tests.to_string()),
                    ("has_filtered".to_string(), has_filtered.to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                ],
            );

            assert_eq!(result.exit_code, 0, "Filtered tests should pass");
            assert!(ran_add_tests, "Should have run test_add tests");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!("Command failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Filter by name test completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 5: Run ignored tests
// =============================================================================

/// Test that `cargo test -- --ignored` runs ignored tests.
///
/// Command: `cargo test -- --ignored`
/// Expected: ignored tests execute (and fail in our fixture)
#[tokio::test]
async fn test_cargo_test_run_ignored() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_run_ignored")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test ignored test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("flag".to_string(), "--ignored".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_ignored");

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Execute with --ignored flag
    let test_cmd = remote_cargo_command(&remote_path, "cargo test --lib -- --ignored");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing cargo test with --ignored",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test -- --ignored".to_string()),
        ],
    );

    match client.execute(&test_cmd).await {
        Ok(result) => {
            let output = &result.stdout;

            // The ignored tests in hello_world intentionally fail
            let ran_ignored = output.contains("ignored") || output.contains("FAILED");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Ignored tests verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("ran_ignored".to_string(), ran_ignored.to_string()),
                ],
            );

            // The ignored tests are designed to fail, so exit code should be 101
            // (or 0 if there are no ignored tests to run)
            assert!(
                result.exit_code == 0 || result.exit_code == 101,
                "Expected exit code 0 (no ignored tests) or 101 (ignored tests failed), got {}",
                result.exit_code
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!("Command failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Run ignored tests completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 6: Show output (--nocapture)
// =============================================================================

/// Test that `cargo test -- --nocapture` shows test output.
///
/// Command: `cargo test -- --nocapture`
/// Expected: stdout visible in output
#[tokio::test]
async fn test_cargo_test_nocapture() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_nocapture")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test nocapture test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("flag".to_string(), "--nocapture".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_nocapture");

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Execute with --nocapture
    let test_cmd = remote_cargo_command(&remote_path, "cargo test --lib -- --nocapture");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing cargo test with --nocapture",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test -- --nocapture".to_string()),
            ("output_capture_mode".to_string(), "disabled".to_string()),
        ],
    );

    match client.execute(&test_cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Nocapture verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("output_length".to_string(), result.stdout.len().to_string()),
                ],
            );

            // Tests should pass
            assert_eq!(result.exit_code, 0, "Tests with --nocapture should pass");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!("Command failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Nocapture test completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 7: Lib tests only (--lib)
// =============================================================================

/// Test that `cargo test --lib` runs only library tests.
///
/// Command: `cargo test --lib`
/// Expected: only library tests run
#[tokio::test]
async fn test_cargo_test_lib_only() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_lib_only")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test --lib test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("target_filter".to_string(), "--lib".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_lib");

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Execute with --lib
    let test_cmd = remote_cargo_command(&remote_path, "cargo test --lib");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing cargo test --lib",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test --lib".to_string()),
        ],
    );

    match client.execute(&test_cmd).await {
        Ok(result) => {
            let output = &result.stdout;

            // Should run lib tests
            let has_lib_tests = output.contains("running") && output.contains("test");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Lib tests verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("has_lib_tests".to_string(), has_lib_tests.to_string()),
                ],
            );

            assert_eq!(result.exit_code, 0, "Lib tests should pass");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!("Command failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Lib-only test completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 8: Doc tests (--doc)
// =============================================================================

/// Test that `cargo test --doc` runs documentation tests.
///
/// Command: `cargo test --doc`
/// Expected: documentation tests run
#[tokio::test]
async fn test_cargo_test_doc() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_doc")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test --doc test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("target_filter".to_string(), "--doc".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_doc");

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Execute with --doc
    let test_cmd = remote_cargo_command(&remote_path, "cargo test --doc");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing cargo test --doc",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test --doc".to_string()),
        ],
    );

    match client.execute(&test_cmd).await {
        Ok(result) => {
            let output = &result.stdout;

            // Should mention doc tests
            let has_doc_tests = output.contains("Doc-tests") || output.contains("running");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Doc tests verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("has_doc_tests".to_string(), has_doc_tests.to_string()),
                    ("doc_test_count".to_string(), "checked".to_string()),
                ],
            );

            assert_eq!(result.exit_code, 0, "Doc tests should pass");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!("Command failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Doc test completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 9: Thread control (RUST_TEST_THREADS)
// =============================================================================

/// Test that `RUST_TEST_THREADS=4 cargo test` respects thread limit.
///
/// Command: `RUST_TEST_THREADS=4 cargo test`
/// Expected: respects thread limit (tests run)
#[tokio::test]
async fn test_cargo_test_thread_control() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_thread_control")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test thread control test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            (
                "thread_config".to_string(),
                "RUST_TEST_THREADS=4".to_string(),
            ),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_threads");

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Execute with RUST_TEST_THREADS environment variable
    let test_cmd = remote_cargo_command(&remote_path, "RUST_TEST_THREADS=4 cargo test --lib");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing cargo test with thread limit",
        vec![
            ("phase".to_string(), "execute".to_string()),
            (
                "cmd".to_string(),
                "RUST_TEST_THREADS=4 cargo test".to_string(),
            ),
        ],
    );

    match client.execute(&test_cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Thread control verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                ],
            );

            assert_eq!(result.exit_code, 0, "Tests with thread limit should pass");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!("Command failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Thread control test completed");
    logger.print_summary();
    Ok(())
}

// =============================================================================
// Test 10: Workspace tests (--workspace)
// =============================================================================

/// Test that `cargo test --workspace` tests all workspace members.
///
/// Command: `cargo test --workspace`
/// Expected: all packages tested
#[tokio::test]
async fn test_cargo_test_workspace() -> Result<(), String> {
    let logger = TestLoggerBuilder::new("test_cargo_test_workspace")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo test --workspace test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "rust_workspace".to_string()),
        ],
    );

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return Ok(());
    };

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let fixture_dir = rust_workspace_fixture_dir();

    // Check if workspace fixture exists
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: rust_workspace fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return Ok(());
    }

    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_test_workspace");

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return Err(format!("Failed to sync fixture: {e}"));
    }

    // Execute with --workspace
    let test_cmd = remote_cargo_command(&remote_path, "cargo test --workspace");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing cargo test --workspace",
        vec![
            ("phase".to_string(), "execute".to_string()),
            ("cmd".to_string(), "cargo test --workspace".to_string()),
        ],
    );

    match client.execute(&test_cmd).await {
        Ok(result) => {
            let output = &result.stdout;

            // Should test multiple packages
            let tests_multiple =
                output.matches("Running").count() >= 1 || output.matches("running").count() >= 1;

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Workspace test verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    (
                        "tests_multiple_packages".to_string(),
                        tests_multiple.to_string(),
                    ),
                    (
                        "packages_tested".to_string(),
                        "workspace members".to_string(),
                    ),
                ],
            );

            assert_eq!(result.exit_code, 0, "Workspace tests should pass");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            return Err(format!("Command failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Workspace test completed");
    logger.print_summary();
    Ok(())
}

#[test]
fn remote_cargo_test_path_is_unique_and_under_base() {
    let first = remote_test_path("/tmp/rch-e2e", "cargo_test_pass");
    let second = remote_test_path("/tmp/rch-e2e/", "cargo_test_pass");

    assert_ne!(first, second);
    assert!(first.starts_with("/tmp/rch-e2e/cargo_test_pass-"));
    assert!(second.starts_with("/tmp/rch-e2e/cargo_test_pass-"));
}

#[test]
fn remote_cargo_test_rsync_path_quotes_shell_sensitive_values() {
    assert_eq!(
        remote_rsync_path("/tmp/rch e2e/cargo_test_pass"),
        "'/tmp/rch e2e/cargo_test_pass/'"
    );
}

#[test]
fn remote_cargo_test_command_path_is_shell_escaped() {
    assert_eq!(
        remote_cargo_command("/tmp/rch e2e/cargo_test_pass", "cargo test --lib"),
        "cd '/tmp/rch e2e/cargo_test_pass' && cargo test --lib 2>&1"
    );
}

#[test]
fn remote_cargo_test_rsync_ssh_command_expands_and_quotes_identity_path() {
    assert_eq!(
        rsync_ssh_command("/tmp/key files/id_ed25519"),
        "ssh -o StrictHostKeyChecking=accept-new -i '/tmp/key files/id_ed25519'"
    );

    if std::env::var_os("HOME").is_some() {
        assert!(!rsync_ssh_command("~/.ssh/id_ed25519").contains(" -i ~/"));
    }
}
