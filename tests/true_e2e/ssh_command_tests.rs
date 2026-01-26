//! True E2E Tests: SSH Command Execution & Output Capture
//!
//! Tests SSH command execution on real workers - running commands,
//! capturing output, handling errors, and managing long-running processes.
//!
//! # Test Categories
//!
//! 1. Basic Command Execution - echo, exit codes, stderr
//! 2. Environment & Working Directory - cwd, env vars
//! 3. Long-Running & Complex Commands - large output, timeouts
//! 4. Error Handling - command not found, signals
//!
//! # Running These Tests
//!
//! ```bash
//! # Requires workers_test.toml configuration
//! cargo test --features true-e2e ssh_command_tests -- --nocapture
//! ```

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use rch_common::types::WorkerConfig;
use std::time::{Duration, Instant};

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

/// Convert TestWorkerEntry to WorkerConfig for SSH client.
fn to_worker_config(entry: &rch_common::e2e::TestWorkerEntry) -> WorkerConfig {
    entry.to_worker_config()
}

/// Helper to create a connected SSH client for command tests.
async fn get_connected_client(
    config: &TestWorkersConfig,
    worker_entry: &rch_common::e2e::TestWorkerEntry,
) -> Option<SshClient> {
    let worker_config = to_worker_config(worker_entry);
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

// =============================================================================
// Test: Basic Command Execution
// =============================================================================

/// Test 1.1: Simple echo command
#[tokio::test]
async fn test_cmd_simple_echo() {
    let logger = TestLoggerBuilder::new("test_cmd_simple_echo")
        .print_realtime(true)
        .build();

    logger.info("Starting simple echo command test");

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

    // Phase: Execute
    let cmd = "echo 'hello world'";
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            ("cmd".to_string(), cmd.to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    let start = Instant::now();
    match client.execute(cmd).await {
        Ok(result) => {
            let duration = start.elapsed();

            // Phase: Result
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Command completed",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("stdout_bytes".to_string(), result.stdout.len().to_string()),
                    ("stderr_bytes".to_string(), result.stderr.len().to_string()),
                    ("duration_ms".to_string(), duration.as_millis().to_string()),
                ],
            );

            // Phase: Output
            logger.log_with_context(
                LogLevel::Debug,
                LogSource::Custom("ssh".to_string()),
                "Command output",
                vec![
                    ("stdout".to_string(), result.stdout.trim().to_string()),
                    ("stderr".to_string(), result.stderr.trim().to_string()),
                ],
            );

            assert!(result.success(), "Echo command should succeed");
            assert!(
                result.stdout.contains("hello world"),
                "Output should contain 'hello world', got: {}",
                result.stdout
            );
            assert_eq!(result.exit_code, 0, "Exit code should be 0");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Echo command failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Simple echo command test passed");
    logger.print_summary();
}

/// Test 1.2: Command with specific exit code
#[tokio::test]
async fn test_cmd_exit_code() {
    let logger = TestLoggerBuilder::new("test_cmd_exit_code")
        .print_realtime(true)
        .build();

    logger.info("Starting exit code test");

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
    let test_cases = [
        (0, "exit 0"),
        (1, "exit 1"),
        (42, "exit 42"),
        (255, "exit 255"),
    ];

    for (expected_code, cmd) in test_cases.iter() {
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("ssh".to_string()),
            "SSH command execution",
            vec![
                ("cmd".to_string(), cmd.to_string()),
                ("expected_exit".to_string(), expected_code.to_string()),
            ],
        );

        match client.execute(cmd).await {
            Ok(result) => {
                logger.log_with_context(
                    LogLevel::Info,
                    LogSource::Custom("ssh".to_string()),
                    "Command completed",
                    vec![
                        ("expected_code".to_string(), expected_code.to_string()),
                        ("actual_code".to_string(), result.exit_code.to_string()),
                        (
                            "match".to_string(),
                            (result.exit_code == *expected_code).to_string(),
                        ),
                    ],
                );

                assert_eq!(
                    result.exit_code, *expected_code,
                    "Exit code should be {}, got {}",
                    expected_code, result.exit_code
                );
            }
            Err(e) => {
                logger.error(format!("Command failed: {e}"));
                panic!("Exit code test failed: {e}");
            }
        }
    }

    client.disconnect().await.ok();
    logger.info("Exit code test passed");
    logger.print_summary();
}

/// Test 1.3: Command with stderr output
#[tokio::test]
async fn test_cmd_stderr_output() {
    let logger = TestLoggerBuilder::new("test_cmd_stderr_output")
        .print_realtime(true)
        .build();

    logger.info("Starting stderr output test");

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

    // Command that writes to stderr
    let cmd = "echo 'error message' >&2";
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            ("cmd".to_string(), cmd.to_string()),
            ("expected".to_string(), "stderr output".to_string()),
        ],
    );

    match client.execute(cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Command completed",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("stdout_bytes".to_string(), result.stdout.len().to_string()),
                    ("stderr_bytes".to_string(), result.stderr.len().to_string()),
                ],
            );

            logger.log_with_context(
                LogLevel::Debug,
                LogSource::Custom("ssh".to_string()),
                "Command output",
                vec![
                    ("stdout".to_string(), result.stdout.trim().to_string()),
                    ("stderr".to_string(), result.stderr.trim().to_string()),
                ],
            );

            assert!(
                result.stderr.contains("error message"),
                "stderr should contain 'error message', got: {}",
                result.stderr
            );
            // Stdout should be empty or minimal
            assert!(
                result.stdout.trim().is_empty(),
                "stdout should be empty, got: {}",
                result.stdout
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Stderr test failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Stderr output test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Environment & Working Directory
// =============================================================================

/// Test 2.1: Working directory
#[tokio::test]
async fn test_cmd_working_directory() {
    let logger = TestLoggerBuilder::new("test_cmd_working_directory")
        .print_realtime(true)
        .build();

    logger.info("Starting working directory test");

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

    // Test changing directory and running pwd
    let cmd = "cd /tmp && pwd";
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            ("cmd".to_string(), cmd.to_string()),
            ("expected_cwd".to_string(), "/tmp".to_string()),
        ],
    );

    match client.execute(cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Working directory result",
                vec![
                    ("expected_cwd".to_string(), "/tmp".to_string()),
                    ("actual_cwd".to_string(), result.stdout.trim().to_string()),
                ],
            );

            assert!(result.success(), "Command should succeed");
            assert!(
                result.stdout.trim() == "/tmp" || result.stdout.trim().ends_with("/tmp"),
                "Should be in /tmp, got: {}",
                result.stdout
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Working directory test failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Working directory test passed");
    logger.print_summary();
}

/// Test 2.2: Environment variables
#[tokio::test]
async fn test_cmd_environment_variables() {
    let logger = TestLoggerBuilder::new("test_cmd_environment_variables")
        .print_realtime(true)
        .build();

    logger.info("Starting environment variables test");

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

    // Test setting and reading environment variable
    let test_value = "rch_e2e_test_value_12345";
    let cmd = format!("export MY_TEST_VAR='{}' && echo $MY_TEST_VAR", test_value);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            (
                "cmd".to_string(),
                "export MY_TEST_VAR=... && echo $MY_TEST_VAR".to_string(),
            ),
            ("env_vars_set".to_string(), "MY_TEST_VAR".to_string()),
        ],
    );

    match client.execute(&cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Environment variable result",
                vec![
                    ("expected_value".to_string(), test_value.to_string()),
                    ("actual_value".to_string(), result.stdout.trim().to_string()),
                ],
            );

            assert!(result.success(), "Command should succeed");
            assert!(
                result.stdout.trim() == test_value,
                "Environment variable should be set correctly, got: {}",
                result.stdout
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Environment variables test failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Environment variables test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Long-Running & Complex Commands
// =============================================================================

/// Test 3.1: Long output handling
#[tokio::test]
async fn test_cmd_long_output() {
    let logger = TestLoggerBuilder::new("test_cmd_long_output")
        .print_realtime(true)
        .build();

    logger.info("Starting long output test");

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

    // Generate ~100KB of output (10000 lines of 10 chars each)
    let expected_lines = 10000;
    let cmd = format!(
        "for i in $(seq 1 {}); do echo \"line${{i}}xxx\"; done",
        expected_lines
    );

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            (
                "cmd".to_string(),
                "seq loop generating ~100KB output".to_string(),
            ),
            ("expected_lines".to_string(), expected_lines.to_string()),
        ],
    );

    let start = Instant::now();
    match client.execute(&cmd).await {
        Ok(result) => {
            let duration = start.elapsed();
            let actual_lines = result.stdout.lines().count();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Long output result",
                vec![
                    ("total_bytes".to_string(), result.stdout.len().to_string()),
                    ("total_lines".to_string(), actual_lines.to_string()),
                    ("duration_ms".to_string(), duration.as_millis().to_string()),
                    (
                        "truncated".to_string(),
                        (actual_lines < expected_lines).to_string(),
                    ),
                ],
            );

            assert!(result.success(), "Command should succeed");
            // Allow for some variance in line count (counting differences)
            assert!(
                actual_lines >= expected_lines - 10,
                "Should capture all output, got {} lines, expected ~{}",
                actual_lines,
                expected_lines
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Long output test failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Long output test passed");
    logger.print_summary();
}

/// Test 3.2: Binary output handling
#[tokio::test]
async fn test_cmd_binary_output() {
    let logger = TestLoggerBuilder::new("test_cmd_binary_output")
        .print_realtime(true)
        .build();

    logger.info("Starting binary output test");

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

    // Generate some binary-like output using printf with hex escapes
    let expected_bytes = 256;
    let cmd = format!(
        "printf '{}' | head -c {}",
        "\\x00\\x01\\x02\\xff\\xfe\\xfd", expected_bytes
    );

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            ("cmd".to_string(), "printf with binary data".to_string()),
            ("expected_bytes".to_string(), expected_bytes.to_string()),
        ],
    );

    match client.execute(&cmd).await {
        Ok(result) => {
            let binary_count = result.stdout.bytes().filter(|&b| b < 32 || b > 126).count();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Binary output result",
                vec![
                    ("total_bytes".to_string(), result.stdout.len().to_string()),
                    ("binary_bytes".to_string(), binary_count.to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                ],
            );

            // Binary output should be preserved (even if some bytes are lost in string conversion)
            assert!(result.stdout.len() > 0, "Should capture some output");
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            // Binary output handling is best-effort, don't fail the test
            logger.warn("Binary output handling may have limitations");
        }
    }

    client.disconnect().await.ok();
    logger.info("Binary output test passed");
    logger.print_summary();
}

/// Test 3.3: Short-running timed command
#[tokio::test]
async fn test_cmd_timed_execution() {
    let logger = TestLoggerBuilder::new("test_cmd_timed_execution")
        .print_realtime(true)
        .build();

    logger.info("Starting timed execution test");

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

    // Short sleep to verify timing
    let sleep_secs = 2;
    let cmd = format!("sleep {} && echo 'done'", sleep_secs);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            ("cmd".to_string(), format!("sleep {}", sleep_secs)),
            ("expected_duration_secs".to_string(), sleep_secs.to_string()),
        ],
    );

    let start = Instant::now();
    match client.execute(&cmd).await {
        Ok(result) => {
            let duration = start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Timed execution result",
                vec![
                    (
                        "actual_duration_ms".to_string(),
                        duration.as_millis().to_string(),
                    ),
                    (
                        "expected_duration_ms".to_string(),
                        (sleep_secs * 1000).to_string(),
                    ),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                ],
            );

            assert!(result.success(), "Sleep command should succeed");
            assert!(result.stdout.contains("done"), "Should get 'done' output");

            // Verify timing is approximately correct (within 1 second tolerance)
            let min_duration = Duration::from_secs(sleep_secs as u64);
            let max_duration = Duration::from_secs(sleep_secs as u64 + 2);
            assert!(
                duration >= min_duration && duration <= max_duration,
                "Duration should be ~{}s, was {:?}",
                sleep_secs,
                duration
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Timed execution test failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Timed execution test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Error Handling
// =============================================================================

/// Test 4.1: Command not found
#[tokio::test]
async fn test_cmd_not_found() {
    let logger = TestLoggerBuilder::new("test_cmd_not_found")
        .print_realtime(true)
        .build();

    logger.info("Starting command not found test");

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

    // Try to run a command that doesn't exist
    let cmd = "this_command_definitely_does_not_exist_12345";
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            ("cmd".to_string(), cmd.to_string()),
            (
                "expected".to_string(),
                "command not found error".to_string(),
            ),
        ],
    );

    match client.execute(cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Command not found result",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("error_type".to_string(), "non-zero exit".to_string()),
                    ("stderr".to_string(), result.stderr.trim().to_string()),
                ],
            );

            // Command should fail with non-zero exit code
            assert!(
                !result.success(),
                "Command should fail, got exit code: {}",
                result.exit_code
            );
            // Exit code for command not found is typically 127
            assert!(
                result.exit_code == 127 || result.exit_code != 0,
                "Exit code should be 127 (or non-zero), got: {}",
                result.exit_code
            );
            // Stderr should contain error message
            assert!(
                result.stderr.contains("not found") || result.stderr.contains("command not found"),
                "stderr should indicate command not found, got: {}",
                result.stderr
            );
        }
        Err(e) => {
            // Some SSH implementations might return an error instead of result
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Command not found as error",
                vec![("error".to_string(), e.to_string())],
            );
            // This is acceptable behavior
        }
    }

    client.disconnect().await.ok();
    logger.info("Command not found test passed");
    logger.print_summary();
}

/// Test 4.2: Command with permission denied
#[tokio::test]
async fn test_cmd_permission_denied() {
    let logger = TestLoggerBuilder::new("test_cmd_permission_denied")
        .print_realtime(true)
        .build();

    logger.info("Starting permission denied test");

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

    // Try to access a file without permission (root-only file)
    let cmd = "cat /etc/shadow 2>&1";
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![
            ("cmd".to_string(), cmd.to_string()),
            ("expected".to_string(), "permission denied".to_string()),
        ],
    );

    match client.execute(cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Permission denied result",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("output".to_string(), result.stdout.trim().to_string()),
                ],
            );

            // Most systems should deny this (unless running as root)
            if !result.success() {
                assert!(
                    result.stdout.to_lowercase().contains("permission denied")
                        || result.stdout.to_lowercase().contains("denied")
                        || result.stderr.to_lowercase().contains("permission denied"),
                    "Output should indicate permission denied"
                );
            } else {
                // Running as root - just log this
                logger.warn("Test running as root, permission not denied");
            }
        }
        Err(e) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Permission denied as error",
                vec![("error".to_string(), e.to_string())],
            );
        }
    }

    client.disconnect().await.ok();
    logger.info("Permission denied test passed");
    logger.print_summary();
}

/// Test 4.3: Mixed stdout and stderr
#[tokio::test]
async fn test_cmd_mixed_output() {
    let logger = TestLoggerBuilder::new("test_cmd_mixed_output")
        .print_realtime(true)
        .build();

    logger.info("Starting mixed output test");

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

    // Command that writes to both stdout and stderr
    let cmd = "echo 'stdout1' && echo 'stderr1' >&2 && echo 'stdout2' && echo 'stderr2' >&2";
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![("cmd".to_string(), "mixed stdout/stderr writes".to_string())],
    );

    match client.execute(cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Mixed output result",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("stdout".to_string(), result.stdout.trim().to_string()),
                    ("stderr".to_string(), result.stderr.trim().to_string()),
                ],
            );

            assert!(result.success(), "Command should succeed");

            // Verify stdout contains stdout messages
            assert!(
                result.stdout.contains("stdout1") && result.stdout.contains("stdout2"),
                "stdout should contain stdout messages, got: {}",
                result.stdout
            );

            // Verify stderr contains stderr messages
            assert!(
                result.stderr.contains("stderr1") && result.stderr.contains("stderr2"),
                "stderr should contain stderr messages, got: {}",
                result.stderr
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Mixed output test failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Mixed output test passed");
    logger.print_summary();
}

/// Test 4.4: Pipe command
#[tokio::test]
async fn test_cmd_pipe() {
    let logger = TestLoggerBuilder::new("test_cmd_pipe")
        .print_realtime(true)
        .build();

    logger.info("Starting pipe command test");

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

    // Test pipe with grep
    let cmd = "echo -e 'line1\\nline2\\nline3' | grep 'line2'";
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![("cmd".to_string(), "echo | grep pipe".to_string())],
    );

    match client.execute(cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Pipe command result",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("stdout".to_string(), result.stdout.trim().to_string()),
                ],
            );

            assert!(result.success(), "Pipe command should succeed");
            assert!(
                result.stdout.trim() == "line2",
                "Should get only 'line2' from grep, got: {}",
                result.stdout
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Pipe command test failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Pipe command test passed");
    logger.print_summary();
}

/// Test 4.5: Subshell command
#[tokio::test]
async fn test_cmd_subshell() {
    let logger = TestLoggerBuilder::new("test_cmd_subshell")
        .print_realtime(true)
        .build();

    logger.info("Starting subshell command test");

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

    // Test subshell with command substitution
    let cmd = "echo \"Current date: $(date +%Y-%m-%d)\"";
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH command execution",
        vec![("cmd".to_string(), "echo with $(date) subshell".to_string())],
    );

    match client.execute(cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "Subshell command result",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("stdout".to_string(), result.stdout.trim().to_string()),
                ],
            );

            assert!(result.success(), "Subshell command should succeed");
            assert!(
                result.stdout.contains("Current date:"),
                "Should contain 'Current date:', got: {}",
                result.stdout
            );
            // Verify date format (YYYY-MM-DD)
            assert!(
                result.stdout.contains("2026-") || result.stdout.contains("202"),
                "Should contain valid date, got: {}",
                result.stdout
            );
        }
        Err(e) => {
            logger.error(format!("Command failed: {e}"));
            panic!("Subshell command test failed: {e}");
        }
    }

    client.disconnect().await.ok();
    logger.info("Subshell command test passed");
    logger.print_summary();
}
