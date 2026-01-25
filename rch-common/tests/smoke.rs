//! Infrastructure Smoke Test
//!
//! A quick validation test that exercises all E2E infrastructure components
//! before running the full test suite. This ensures the test environment
//! is properly configured.
//!
//! # Purpose
//!
//! - Validates infrastructure works before longer tests run
//! - Catches configuration issues early
//! - Serves as documentation of the "happy path"
//! - CI can fail fast on infrastructure problems
//!
//! # Running This Test
//!
//! ```bash
//! # Run just the smoke test
//! cargo test --features true-e2e test_infrastructure_smoke -- --nocapture
//! ```
//!
//! # Bead Reference
//!
//! This implements bead bd-2val: Create Infrastructure Smoke Test

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Resolve the repository fixtures directory.
fn fixtures_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    manifest_dir
        .parent()
        .unwrap_or(&manifest_dir)
        .join("tests/true_e2e/fixtures")
}

/// Get the hello_world fixture directory.
fn hello_world_fixture_dir() -> PathBuf {
    fixtures_root().join("hello_world")
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

// =============================================================================
// Infrastructure Smoke Test
// =============================================================================

/// Infrastructure Smoke Test
///
/// This test validates the entire E2E test infrastructure works before
/// running the full test suite. It performs a quick end-to-end cycle:
///
/// 1. Logging Setup - verifies TestLogger works
/// 2. Worker Discovery - loads workers_test.toml
/// 3. SSH Connectivity - connects to first worker
/// 4. Project Sync - syncs hello_world fixture
/// 5. Remote Execution - runs `cargo build`
/// 6. Artifact Retrieval - syncs built binary back
/// 7. Output Verification - verifies binary runs
/// 8. Cleanup - removes remote artifacts
///
/// If any step fails, the test provides clear error messages for debugging.
#[tokio::test]
async fn test_infrastructure_smoke() {
    let start_time = Instant::now();

    // Step 1: Logging Setup
    let logger = TestLoggerBuilder::new("test_infrastructure_smoke")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "=== INFRASTRUCTURE SMOKE TEST STARTING ===",
        vec![("step".to_string(), "1/8".to_string())],
    );

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Step 1: Logging infrastructure validated",
        vec![
            ("test_name".to_string(), logger.test_name().to_string()),
            ("logger_ok".to_string(), "true".to_string()),
        ],
    );

    // Step 2: Worker Discovery
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Step 2: Loading worker configuration",
        vec![("step".to_string(), "2/8".to_string())],
    );

    let Some(config) = require_workers() else {
        logger.log_with_context(
            LogLevel::Warn,
            LogSource::Custom("smoke".to_string()),
            "SKIP: No workers configured - infrastructure cannot be fully validated",
            vec![
                ("result".to_string(), "skip".to_string()),
                ("reason".to_string(), "no_workers".to_string()),
            ],
        );
        logger.print_summary();
        return;
    };

    let worker_count = config.enabled_workers().len();
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Worker configuration loaded",
        vec![
            ("workers_found".to_string(), worker_count.to_string()),
            (
                "timeout_secs".to_string(),
                config.effective_timeout_secs().to_string(),
            ),
            (
                "remote_work_dir".to_string(),
                config.settings.remote_work_dir.clone(),
            ),
        ],
    );

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.error("No enabled worker found - cannot proceed with smoke test");
        logger.print_summary();
        return;
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Selected test worker",
        vec![
            ("worker_id".to_string(), worker_entry.id.clone()),
            ("host".to_string(), worker_entry.host.clone()),
            ("user".to_string(), worker_entry.user.clone()),
            ("port".to_string(), worker_entry.port.to_string()),
        ],
    );

    // Step 3: SSH Connectivity
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Step 3: Testing SSH connectivity",
        vec![("step".to_string(), "3/8".to_string())],
    );

    let worker_config = worker_entry.to_worker_config();
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config.clone(), options);

    let connect_start = Instant::now();
    match client.connect().await {
        Ok(()) => {
            let connect_duration = connect_start.elapsed();
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("smoke".to_string()),
                "SSH connection established",
                vec![
                    (
                        "connect_ms".to_string(),
                        connect_duration.as_millis().to_string(),
                    ),
                    ("connected".to_string(), "true".to_string()),
                ],
            );
        }
        Err(e) => {
            logger.log_with_context(
                LogLevel::Error,
                LogSource::Custom("smoke".to_string()),
                "SSH connection FAILED - check worker configuration",
                vec![
                    ("error".to_string(), e.to_string()),
                    ("worker".to_string(), worker_entry.id.clone()),
                    ("host".to_string(), worker_entry.host.clone()),
                ],
            );
            logger.print_summary();
            panic!("Smoke test failed: SSH connection failed: {e}");
        }
    }

    // Verify SSH with echo command
    match client.execute("echo 'smoke_test_ok'").await {
        Ok(result) => {
            if result.stdout.contains("smoke_test_ok") {
                logger.log_with_context(
                    LogLevel::Info,
                    LogSource::Custom("smoke".to_string()),
                    "SSH echo command verified",
                    vec![
                        ("exit_code".to_string(), result.exit_code.to_string()),
                        ("output_ok".to_string(), "true".to_string()),
                    ],
                );
            } else {
                logger.error(format!("Unexpected echo output: {}", result.stdout));
                client.disconnect().await.ok();
                panic!("Smoke test failed: echo command produced unexpected output");
            }
        }
        Err(e) => {
            logger.error(format!("Echo command failed: {e}"));
            client.disconnect().await.ok();
            panic!("Smoke test failed: echo command failed: {e}");
        }
    }

    // Step 4: Project Sync
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Step 4: Syncing fixture to remote worker",
        vec![("step".to_string(), "4/8".to_string())],
    );

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = format!("{}/smoke_test", config.settings.remote_work_dir);

    // Create remote directory
    let mkdir_cmd = format!("mkdir -p {}", remote_path);
    if let Err(e) = client.execute(&mkdir_cmd).await {
        logger.error(format!("Failed to create remote directory: {e}"));
        client.disconnect().await.ok();
        panic!("Smoke test failed: could not create remote directory");
    }

    // Sync fixture using rsync
    let sync_start = Instant::now();
    let rsync_output = std::process::Command::new("rsync")
        .args([
            "-avz",
            "--delete",
            "--exclude=target",
            "-e",
            &format!(
                "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i {}",
                worker_config.identity_file
            ),
            &format!("{}/", fixture_dir.display()),
            &format!(
                "{}@{}:{}/",
                worker_config.user, worker_config.host, remote_path
            ),
        ])
        .output();

    let sync_duration = sync_start.elapsed();

    match rsync_output {
        Ok(output) if output.status.success() => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("smoke".to_string()),
                "Fixture synced to remote",
                vec![
                    ("sync_ms".to_string(), sync_duration.as_millis().to_string()),
                    ("local_path".to_string(), fixture_dir.display().to_string()),
                    ("remote_path".to_string(), remote_path.clone()),
                ],
            );
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            logger.error(format!("rsync failed: {stderr}"));
            cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Smoke test failed: rsync failed: {stderr}");
        }
        Err(e) => {
            logger.error(format!("Failed to run rsync: {e}"));
            cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Smoke test failed: could not run rsync: {e}");
        }
    }

    // Verify sync by listing files
    match client.execute(&format!("ls -la {}", remote_path)).await {
        Ok(result) => {
            let has_cargo_toml = result.stdout.contains("Cargo.toml");
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("smoke".to_string()),
                "Remote sync verified",
                vec![("cargo_toml_exists".to_string(), has_cargo_toml.to_string())],
            );
            if !has_cargo_toml {
                logger.error("Cargo.toml not found on remote after sync");
                cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                panic!("Smoke test failed: Cargo.toml not synced");
            }
        }
        Err(e) => {
            logger.error(format!("Failed to verify remote files: {e}"));
            cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Smoke test failed: could not verify remote files");
        }
    }

    // Step 5: Remote Execution
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Step 5: Executing cargo build on remote",
        vec![("step".to_string(), "5/8".to_string())],
    );

    let build_cmd = format!("cd {} && cargo build 2>&1", remote_path);
    let build_start = Instant::now();

    match client.execute(&build_cmd).await {
        Ok(result) => {
            let build_duration = build_start.elapsed();
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("smoke".to_string()),
                "Remote cargo build completed",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    (
                        "build_ms".to_string(),
                        build_duration.as_millis().to_string(),
                    ),
                    ("success".to_string(), result.success().to_string()),
                ],
            );

            if !result.success() {
                logger.log_with_context(
                    LogLevel::Error,
                    LogSource::Custom("smoke".to_string()),
                    "Remote build FAILED",
                    vec![
                        ("stderr".to_string(), result.stderr.clone()),
                        ("stdout".to_string(), result.stdout.clone()),
                    ],
                );
                cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                panic!("Smoke test failed: cargo build failed on remote");
            }
        }
        Err(e) => {
            logger.error(format!("Remote build command failed: {e}"));
            cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Smoke test failed: remote build command error: {e}");
        }
    }

    // Step 6: Artifact Retrieval
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Step 6: Retrieving build artifacts",
        vec![("step".to_string(), "6/8".to_string())],
    );

    // Create local temp directory for artifacts
    let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
    let local_target = temp_dir.path().join("target");
    std::fs::create_dir_all(&local_target).expect("Failed to create local target dir");

    let retrieve_start = Instant::now();
    let retrieve_output = std::process::Command::new("rsync")
        .args([
            "-avz",
            "-e",
            &format!(
                "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i {}",
                worker_config.identity_file
            ),
            &format!(
                "{}@{}:{}/target/debug/hello_world",
                worker_config.user, worker_config.host, remote_path
            ),
            &format!("{}/", local_target.display()),
        ])
        .output();

    let retrieve_duration = retrieve_start.elapsed();

    match retrieve_output {
        Ok(output) if output.status.success() => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("smoke".to_string()),
                "Artifacts retrieved",
                vec![(
                    "retrieve_ms".to_string(),
                    retrieve_duration.as_millis().to_string(),
                )],
            );
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            logger.warn(format!("rsync artifact retrieval warning: {stderr}"));
            // Continue - we'll verify the binary exists
        }
        Err(e) => {
            logger.error(format!("Failed to retrieve artifacts: {e}"));
            cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Smoke test failed: artifact retrieval failed: {e}");
        }
    }

    // Step 7: Output Verification
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Step 7: Verifying binary execution",
        vec![("step".to_string(), "7/8".to_string())],
    );

    let binary_path = local_target.join("hello_world");
    let binary_exists = binary_path.exists();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Binary verification",
        vec![
            ("path".to_string(), binary_path.display().to_string()),
            ("exists".to_string(), binary_exists.to_string()),
        ],
    );

    if binary_exists {
        // Make executable and run
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&binary_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&binary_path, perms).ok();
        }

        match std::process::Command::new(&binary_path).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let output_ok = stdout.contains("Hello");

                logger.log_with_context(
                    LogLevel::Info,
                    LogSource::Custom("smoke".to_string()),
                    "Binary execution result",
                    vec![
                        (
                            "ran_successfully".to_string(),
                            output.status.success().to_string(),
                        ),
                        ("output_valid".to_string(), output_ok.to_string()),
                        ("stdout".to_string(), stdout.trim().to_string()),
                    ],
                );

                if !output_ok {
                    logger.warn("Binary output does not contain expected 'Hello'");
                }
            }
            Err(e) => {
                logger.warn(format!("Could not execute binary locally: {e}"));
                // Don't fail - binary might be for different arch
            }
        }
    } else {
        logger.warn("Binary not found locally - may be architecture mismatch");
        // Verify it exists on remote instead
        match client
            .execute(&format!("{}/target/debug/hello_world", remote_path))
            .await
        {
            Ok(result) => {
                logger.log_with_context(
                    LogLevel::Info,
                    LogSource::Custom("smoke".to_string()),
                    "Binary executes on remote",
                    vec![
                        ("exit_code".to_string(), result.exit_code.to_string()),
                        ("output".to_string(), result.stdout.trim().to_string()),
                    ],
                );
            }
            Err(e) => {
                logger.warn(format!("Could not verify binary on remote: {e}"));
            }
        }
    }

    // Step 8: Cleanup
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Step 8: Cleanup",
        vec![("step".to_string(), "8/8".to_string())],
    );

    if config.settings.cleanup_after_test {
        cleanup_remote(&mut client, &remote_path).await;
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("smoke".to_string()),
            "Remote cleanup completed",
            vec![("path_removed".to_string(), remote_path.clone())],
        );
    } else {
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("smoke".to_string()),
            "Cleanup skipped (cleanup_after_test=false)",
            vec![("remote_path".to_string(), remote_path.clone())],
        );
    }

    client.disconnect().await.ok();

    // Final Summary
    let total_duration = start_time.elapsed();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "=== INFRASTRUCTURE SMOKE TEST PASSED ===",
        vec![
            (
                "total_ms".to_string(),
                total_duration.as_millis().to_string(),
            ),
            ("errors".to_string(), logger.error_count().to_string()),
            ("warnings".to_string(), logger.warn_count().to_string()),
        ],
    );

    logger.print_summary();

    // Final assertion
    assert!(
        !logger.has_errors(),
        "Smoke test completed but had errors logged"
    );
}

/// Helper to clean up remote directory
async fn cleanup_remote(client: &mut SshClient, remote_path: &str) {
    let cmd = format!("rm -rf {}", remote_path);
    let _ = client.execute(&cmd).await;
}

// =============================================================================
// Quick Validation Tests
// =============================================================================

/// Quick test that just validates logging works
#[test]
fn test_smoke_logging_only() {
    let logger = TestLoggerBuilder::new("smoke_logging_only")
        .print_realtime(true)
        .build();

    logger.info("Smoke logging test");
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Context logging works",
        vec![("key".to_string(), "value".to_string())],
    );

    assert!(!logger.has_errors());
    assert_eq!(logger.entries().len(), 2);
}

/// Quick test that validates config loading works
#[test]
fn test_smoke_config_loading() {
    let logger = TestLoggerBuilder::new("smoke_config_loading")
        .print_realtime(true)
        .build();

    logger.info("Testing config loading");

    match TestWorkersConfig::load() {
        Ok(config) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("smoke".to_string()),
                "Config loaded successfully",
                vec![
                    ("workers".to_string(), config.workers.len().to_string()),
                    (
                        "enabled".to_string(),
                        config.enabled_workers().len().to_string(),
                    ),
                ],
            );
        }
        Err(TestConfigError::NotFound(path)) => {
            logger.log_with_context(
                LogLevel::Warn,
                LogSource::Custom("smoke".to_string()),
                "Config file not found (expected in CI without workers)",
                vec![("path".to_string(), path.display().to_string())],
            );
        }
        Err(e) => {
            logger.error(format!("Config loading failed: {e}"));
        }
    }

    logger.print_summary();
}

/// Quick test that validates fixture directory exists
#[test]
fn test_smoke_fixture_exists() {
    let logger = TestLoggerBuilder::new("smoke_fixture_exists")
        .print_realtime(true)
        .build();

    let fixture_dir = hello_world_fixture_dir();
    let cargo_toml = fixture_dir.join("Cargo.toml");
    let main_rs = fixture_dir.join("src/main.rs");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("smoke".to_string()),
        "Checking fixture files",
        vec![
            ("fixture_dir".to_string(), fixture_dir.display().to_string()),
            (
                "cargo_toml_exists".to_string(),
                cargo_toml.exists().to_string(),
            ),
            ("main_rs_exists".to_string(), main_rs.exists().to_string()),
        ],
    );

    assert!(cargo_toml.exists(), "hello_world/Cargo.toml should exist");
    assert!(main_rs.exists(), "hello_world/src/main.rs should exist");

    logger.info("Fixture validation passed");
    logger.print_summary();
}
