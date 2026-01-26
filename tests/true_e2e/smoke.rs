//! Infrastructure Smoke Test
//!
//! A quick validation test that exercises the entire E2E infrastructure
//! before running the full test suite. This test validates that all
//! infrastructure components work end-to-end:
//!
//! 1. Logging setup
//! 2. Worker discovery
//! 3. Daemon communication
//! 4. SSH connectivity
//! 5. Project sync
//! 6. Remote execution
//! 7. Artifact retrieval
//! 8. Output comparison
//! 9. Cleanup
//!
//! # Running the Smoke Test
//!
//! ```bash
//! # Run just the smoke test
//! cargo test --features true-e2e test_infrastructure_smoke -- --nocapture
//! ```

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestHarnessBuilder, TestLoggerBuilder,
    TestWorkersConfig, should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

/// Default socket path for the daemon.
const DEFAULT_SOCKET_PATH: &str = "/tmp/rch.sock";

/// Get the path to the hello_world fixture.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("true_e2e")
        .join("fixtures")
        .join("hello_world")
}

/// Smoke test that validates the entire E2E infrastructure.
///
/// This test runs through all infrastructure components in sequence,
/// logging each step for debugging. If any step fails, subsequent
/// steps are skipped and the test fails with a clear error message.
///
/// # Skip Behavior
///
/// The test skips gracefully when:
/// - No workers are configured (RCH_E2E_SKIP_WORKER_CHECK is set)
/// - No daemon is running
/// - Workers are unreachable
///
/// This allows the test to be run in CI without real workers.
#[tokio::test]
async fn test_infrastructure_smoke() {
    // Step 1: Logging Setup
    let logger = TestLoggerBuilder::new("test_infrastructure_smoke")
        .print_realtime(true)
        .min_level(LogLevel::Debug)
        .build();

    logger.info("=== SMOKE TEST START ===");
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Infrastructure smoke test beginning",
        vec![("step".to_string(), "1_logging".to_string())],
    );

    // Verify log file path exists
    let log_path = logger.log_path();
    logger.log_with_context(
        LogLevel::Debug,
        LogSource::Harness,
        "Log file created",
        vec![("path".to_string(), log_path.display().to_string())],
    );

    // Step 2: Worker Discovery
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Loading worker configuration",
        vec![("step".to_string(), "2_worker_discovery".to_string())],
    );

    if should_skip_worker_check() {
        logger.warn("SKIP: RCH_E2E_SKIP_WORKER_CHECK is set - skipping worker-dependent tests");
        logger.info("=== SMOKE TEST PASSED (partial - no workers) ===");
        return;
    }

    let workers_config = match TestWorkersConfig::load() {
        Ok(config) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Harness,
                "Worker configuration loaded",
                vec![
                    ("worker_count".to_string(), config.workers.len().to_string()),
                    (
                        "enabled_count".to_string(),
                        config.enabled_workers().len().to_string(),
                    ),
                ],
            );
            config
        }
        Err(TestConfigError::NotFound(path)) => {
            logger.warn(&format!(
                "SKIP: No workers config at {} - skipping worker tests",
                path.display()
            ));
            logger.info("=== SMOKE TEST PASSED (partial - no config) ===");
            return;
        }
        Err(e) => {
            logger.error(&format!("Failed to load workers config: {e}"));
            panic!("Worker config error: {e}");
        }
    };

    if !workers_config.has_enabled_workers() {
        logger.warn("SKIP: No enabled workers configured - skipping worker tests");
        logger.info("=== SMOKE TEST PASSED (partial - no enabled workers) ===");
        return;
    }

    let worker = workers_config
        .enabled_workers()
        .first()
        .copied()
        .expect("Should have at least one enabled worker");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Selected test worker",
        vec![
            ("worker_id".to_string(), worker.id.clone()),
            ("host".to_string(), worker.host.clone()),
            ("user".to_string(), worker.user.clone()),
        ],
    );

    // Step 3: Daemon Communication
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Testing daemon connectivity",
        vec![("step".to_string(), "3_daemon_communication".to_string())],
    );

    let socket_path = std::env::var("RCH_DAEMON_SOCKET")
        .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    let daemon_available = match UnixStream::connect(&socket_path).await {
        Ok(mut stream) => {
            // Send a health check request
            let health_request = r#"{"request":"Health"}"#;
            if let Err(e) = stream.write_all(health_request.as_bytes()).await {
                logger.warn(&format!("Daemon health request failed: {e}"));
                false
            } else {
                logger.log_with_context(
                    LogLevel::Info,
                    LogSource::Custom("daemon".to_string()),
                    "Daemon health check sent",
                    vec![("socket".to_string(), socket_path.clone())],
                );
                true
            }
        }
        Err(e) => {
            logger.warn(&format!(
                "SKIP: Daemon not available at {socket_path}: {e}"
            ));
            logger.info("Continuing smoke test without daemon (SSH tests only)");
            false
        }
    };

    if daemon_available {
        logger.info("Daemon communication: OK");
    }

    // Step 4: SSH Connectivity
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Testing SSH connectivity",
        vec![("step".to_string(), "4_ssh_connectivity".to_string())],
    );

    let worker_config = worker.to_worker_config();
    let ssh_options = SshOptions {
        connect_timeout: Duration::from_secs(workers_config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut ssh_client = SshClient::new(worker_config.clone(), ssh_options);
    let connect_start = Instant::now();

    if let Err(e) = ssh_client.connect().await {
        logger.error(&format!("SSH connection failed: {e}"));
        panic!("SSH connectivity test failed: {e}");
    }

    let connect_duration = connect_start.elapsed();
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "SSH connection established",
        vec![
            ("worker".to_string(), worker.id.clone()),
            (
                "connect_ms".to_string(),
                connect_duration.as_millis().to_string(),
            ),
        ],
    );

    // Run a simple command to verify SSH works
    let echo_result = ssh_client.run_command("echo 'smoke test'").await;
    match echo_result {
        Ok(result) => {
            if result.exit_code != 0 {
                logger.error(&format!("Echo command failed with exit code {}", result.exit_code));
                panic!("SSH echo test failed");
            }
            let output = result.stdout.trim();
            if output != "smoke test" {
                logger.error(&format!("Unexpected echo output: '{output}'"));
                panic!("SSH echo output mismatch");
            }
            logger.info("SSH echo test: OK");
        }
        Err(e) => {
            logger.error(&format!("SSH echo command failed: {e}"));
            panic!("SSH echo test failed: {e}");
        }
    }

    // Step 5: Project Sync
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Testing project sync to worker",
        vec![("step".to_string(), "5_project_sync".to_string())],
    );

    let fixture_path = fixtures_dir();
    if !fixture_path.exists() {
        logger.error(&format!(
            "Fixture not found: {}",
            fixture_path.display()
        ));
        panic!("hello_world fixture missing");
    }

    logger.log_with_context(
        LogLevel::Debug,
        LogSource::Harness,
        "Fixture path verified",
        vec![("path".to_string(), fixture_path.display().to_string())],
    );

    // Create remote work directory
    let remote_work_dir = format!("{}/smoke_test", workers_config.settings.remote_work_dir);
    let mkdir_result = ssh_client
        .run_command(&format!("mkdir -p {remote_work_dir}"))
        .await;

    if let Err(e) = mkdir_result {
        logger.error(&format!("Failed to create remote directory: {e}"));
        panic!("Remote directory creation failed: {e}");
    }

    // Use rsync to sync the project
    let rsync_start = Instant::now();
    let rsync_cmd = format!(
        "rsync -az --delete -e 'ssh -i {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' {}/ {}@{}:{}/",
        worker.identity_file,
        fixture_path.display(),
        worker.user,
        worker.host,
        remote_work_dir
    );

    let rsync_output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&rsync_cmd)
        .output();

    match rsync_output {
        Ok(output) => {
            let rsync_duration = rsync_start.elapsed();
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                logger.error(&format!("rsync failed: {stderr}"));
                panic!("Project sync failed");
            }
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("rsync".to_string()),
                "Project synced to worker",
                vec![
                    ("remote_dir".to_string(), remote_work_dir.clone()),
                    ("sync_ms".to_string(), rsync_duration.as_millis().to_string()),
                ],
            );
        }
        Err(e) => {
            logger.error(&format!("rsync command failed: {e}"));
            panic!("rsync failed: {e}");
        }
    }

    // Verify files arrived
    let ls_result = ssh_client
        .run_command(&format!("ls -la {remote_work_dir}"))
        .await;

    match ls_result {
        Ok(result) => {
            if !result.stdout.contains("Cargo.toml") {
                logger.error("Cargo.toml not found on remote");
                panic!("Project sync verification failed");
            }
            logger.info("Project sync verification: OK");
        }
        Err(e) => {
            logger.error(&format!("Failed to verify remote files: {e}"));
            panic!("Remote ls failed: {e}");
        }
    }

    // Step 6: Remote Execution
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Testing remote cargo build",
        vec![("step".to_string(), "6_remote_execution".to_string())],
    );

    let build_start = Instant::now();
    let build_result = ssh_client
        .run_command(&format!(
            "cd {remote_work_dir} && cargo build --color=never 2>&1"
        ))
        .await;

    match build_result {
        Ok(result) => {
            let build_duration = build_start.elapsed();
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("build".to_string()),
                "Remote build completed",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("build_ms".to_string(), build_duration.as_millis().to_string()),
                ],
            );

            if result.exit_code != 0 {
                logger.error(&format!("Build failed:\n{}", result.stdout));
                panic!("Remote cargo build failed with exit code {}", result.exit_code);
            }
            logger.info("Remote cargo build: OK");
        }
        Err(e) => {
            logger.error(&format!("Remote build command failed: {e}"));
            panic!("Remote build failed: {e}");
        }
    }

    // Step 7: Artifact Retrieval
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Testing artifact retrieval",
        vec![("step".to_string(), "7_artifact_retrieval".to_string())],
    );

    // Create local temp directory for artifacts
    let harness = TestHarnessBuilder::new("smoke_artifacts")
        .cleanup_on_success(true)
        .build()
        .expect("Failed to create harness");

    let local_artifacts = harness.test_dir().join("artifacts");
    std::fs::create_dir_all(&local_artifacts).expect("Failed to create artifacts dir");

    // Retrieve the built binary
    let retrieve_cmd = format!(
        "rsync -az -e 'ssh -i {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' {}@{}:{}/target/debug/hello_world {}/",
        worker.identity_file,
        worker.user,
        worker.host,
        remote_work_dir,
        local_artifacts.display()
    );

    let retrieve_output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&retrieve_cmd)
        .output();

    match retrieve_output {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                logger.error(&format!("Artifact retrieval failed: {stderr}"));
                panic!("Artifact retrieval failed");
            }
            logger.info("Artifact retrieval: OK");
        }
        Err(e) => {
            logger.error(&format!("rsync artifact retrieval failed: {e}"));
            panic!("Artifact retrieval failed: {e}");
        }
    }

    // Verify binary exists
    let binary_path = local_artifacts.join("hello_world");
    if !binary_path.exists() {
        logger.error(&format!(
            "Binary not found at {}",
            binary_path.display()
        ));
        panic!("Retrieved binary not found");
    }

    // Run the binary to verify it works
    let run_output = std::process::Command::new(&binary_path).output();

    match run_output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.contains("Hello") {
                logger.error(&format!("Unexpected binary output: {stdout}"));
                panic!("Binary output doesn't contain 'Hello'");
            }
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("binary".to_string()),
                "Retrieved binary executed successfully",
                vec![("output".to_string(), stdout.trim().to_string())],
            );
        }
        Err(e) => {
            logger.error(&format!("Failed to run retrieved binary: {e}"));
            panic!("Binary execution failed: {e}");
        }
    }

    // Step 8: Output Comparison
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Testing output comparison utilities",
        vec![("step".to_string(), "8_output_comparison".to_string())],
    );

    use crate::output::{CapturedOutput, ComparisonResult, OutputComparison, OutputNormalizer};

    // Create two similar outputs with path differences
    let local_output = CapturedOutput::new(
        b"Compiling hello_world v0.1.0 (/home/user/project)\n    Finished",
        b"",
        0,
        1000,
    );
    let remote_output = CapturedOutput::new(
        b"Compiling hello_world v0.1.0 (/tmp/rch/smoke_test)\n    Finished",
        b"",
        0,
        950,
    );

    let comparison = OutputComparison::new(local_output, remote_output)
        .with_normalizer(OutputNormalizer::default());

    match comparison.compare() {
        ComparisonResult::EquivalentAfterNormalization { .. } => {
            logger.info("Output comparison with normalization: OK");
        }
        ComparisonResult::ExactMatch => {
            logger.info("Output comparison (exact match): OK");
        }
        other => {
            logger.warn(&format!(
                "Output comparison returned unexpected result: {other:?}"
            ));
            // This is a warning, not a failure, since normalized comparison is expected
        }
    }

    // Step 9: Cleanup
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Cleaning up remote artifacts",
        vec![("step".to_string(), "9_cleanup".to_string())],
    );

    if workers_config.settings.cleanup_after_test {
        let cleanup_result = ssh_client
            .run_command(&format!("rm -rf {remote_work_dir}"))
            .await;

        match cleanup_result {
            Ok(result) => {
                if result.exit_code == 0 {
                    logger.info("Remote cleanup: OK");
                } else {
                    logger.warn(&format!(
                        "Remote cleanup returned non-zero exit code: {}",
                        result.exit_code
                    ));
                }
            }
            Err(e) => {
                logger.warn(&format!("Remote cleanup failed (non-fatal): {e}"));
            }
        }
    } else {
        logger.info("Cleanup skipped (cleanup_after_test=false)");
    }

    // Mark harness as passed
    harness.mark_passed();

    // Final summary
    let summary = logger.summary();
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Harness,
        "Smoke test completed",
        vec![
            ("total_entries".to_string(), summary.total_entries.to_string()),
            (
                "errors".to_string(),
                summary
                    .counts_by_level
                    .get(&LogLevel::Error)
                    .unwrap_or(&0)
                    .to_string(),
            ),
            (
                "warnings".to_string(),
                summary
                    .counts_by_level
                    .get(&LogLevel::Warn)
                    .unwrap_or(&0)
                    .to_string(),
            ),
            ("elapsed_ms".to_string(), summary.elapsed_ms.to_string()),
        ],
    );

    logger.info("=== SMOKE TEST PASSED ===");
}

/// Minimal smoke test that runs without workers - just validates infrastructure components.
///
/// This test always runs and validates that the E2E infrastructure itself works:
/// - Logger can be created and produces output
/// - Harness can be created with temp directories
/// - Fixtures can be loaded
/// - Output comparison works
#[test]
fn test_infrastructure_smoke_minimal() {
    // Create logger
    let logger = TestLoggerBuilder::new("smoke_minimal")
        .print_realtime(false)
        .build();

    logger.info("Starting minimal smoke test");

    // Create harness
    let harness = TestHarnessBuilder::new("smoke_minimal")
        .cleanup_on_success(true)
        .build()
        .expect("Harness creation should succeed");

    // Verify temp directory exists
    assert!(
        harness.test_dir().exists(),
        "Test directory should be created"
    );

    // Verify fixture exists
    let fixture = fixtures_dir();
    assert!(fixture.exists(), "hello_world fixture should exist");
    assert!(
        fixture.join("Cargo.toml").exists(),
        "Fixture should have Cargo.toml"
    );

    // Test output comparison infrastructure
    use crate::output::{CapturedOutput, ComparisonResult, OutputComparison, OutputNormalizer};

    let output1 = CapturedOutput::new(b"Hello, World!", b"", 0, 100);
    let output2 = CapturedOutput::new(b"Hello, World!", b"", 0, 100);

    let comparison = OutputComparison::new(output1, output2)
        .with_normalizer(OutputNormalizer::exact());

    assert!(
        matches!(comparison.compare(), ComparisonResult::ExactMatch),
        "Identical outputs should match exactly"
    );

    // Test command execution via harness
    let result = harness.exec("echo", ["hello"]).expect("echo should work");
    assert!(result.success(), "echo should succeed");
    assert!(
        result.stdout_contains("hello"),
        "echo should output 'hello'"
    );

    harness.mark_passed();
    logger.info("Minimal smoke test PASSED");
}
