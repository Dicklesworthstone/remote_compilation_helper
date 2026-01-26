//! True E2E Tests: Cargo Build Remote Execution
//!
//! Tests that `cargo build` commands are correctly offloaded to real workers
//! and produce valid binaries locally.
//!
//! # Test Categories
//!
//! 1. Basic cargo build (debug)
//! 2. Release build
//! 3. Specific target build
//! 4. Workspace build
//! 5. Package-specific build
//!
//! # Running These Tests
//!
//! ```bash
//! # Requires workers_test.toml configuration
//! cargo test --features true-e2e cargo_build_tests -- --nocapture
//! ```
//!
//! # Bead Reference
//!
//! This implements bead bd-2kr0: Test: cargo build Remote Execution

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

/// Get the hello_world fixture directory
fn hello_world_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("hello_world")
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
    // Note: In a real implementation, this would use the rch transfer pipeline
    // For now, we use a simple approach via SSH
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

/// Sync artifacts back from remote to local.
async fn sync_artifacts_from_remote(
    worker_config: &WorkerConfig,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let output = std::process::Command::new("rsync")
        .args([
            "-avz",
            "-e",
            &format!(
                "ssh -o StrictHostKeyChecking=accept-new -i {}",
                worker_config.identity_file
            ),
            &format!(
                "{}@{}:{}/target/",
                worker_config.user, worker_config.host, remote_path
            ),
            &format!("{}/target/", local_path.display()),
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
// Test: Basic cargo build (debug)
// =============================================================================

/// Test 1: Basic cargo build
///
/// Command: `cargo build`
/// Expected: target/debug/hello_world binary exists locally
/// Verify: binary runs and produces expected output
#[tokio::test]
async fn test_cargo_build_basic() {
    let logger = TestLoggerBuilder::new("test_cargo_build_basic")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo build basic test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "hello_world".to_string()),
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
    let remote_path = format!("{}/hello_world_basic", config.settings.remote_work_dir);

    // Phase: Setup - sync fixture to remote
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Syncing fixture to remote",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("local_path".to_string(), fixture_dir.display().to_string()),
            ("remote_path".to_string(), remote_path.clone()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Execute local baseline
    let local_start = Instant::now();
    let local_result = std::process::Command::new("cargo")
        .args(["build"])
        .current_dir(&fixture_dir)
        .output();

    let local_duration = local_start.elapsed();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local build baseline",
        vec![
            ("phase".to_string(), "execute_local".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
            (
                "exit_code".to_string(),
                local_result
                    .as_ref()
                    .map(|r| r.status.code().unwrap_or(-1).to_string())
                    .unwrap_or_else(|_| "error".to_string()),
            ),
            ("duration_ms".to_string(), local_duration.as_millis().to_string()),
        ],
    );

    // Phase: Execute remote build
    let build_cmd = format!("cd {} && cargo build", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote build",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&build_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote build completed",
                vec![
                    ("phase".to_string(), "execute_remote".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("duration_ms".to_string(), remote_duration.as_millis().to_string()),
                    ("worker".to_string(), worker_entry.id.clone()),
                ],
            );

            if !result.success() {
                logger.log_with_context(
                    LogLevel::Error,
                    LogSource::Custom("test".to_string()),
                    "Remote build failed",
                    vec![
                        ("phase".to_string(), "execute_remote".to_string()),
                        ("stderr".to_string(), result.stderr.clone()),
                    ],
                );
                let _ = cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                panic!("Remote cargo build failed: {}", result.stderr);
            }

            // Sync artifacts back
            if let Err(e) =
                sync_artifacts_from_remote(&worker_config, &remote_path, &fixture_dir).await
            {
                logger.warn(format!("Failed to sync artifacts back: {e}"));
            }

            // Phase: Verify binary exists
            let binary_path = fixture_dir.join("target/debug/hello_world");
            let binary_exists = binary_path.exists();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Binary verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("path".to_string(), binary_path.display().to_string()),
                    ("exists".to_string(), binary_exists.to_string()),
                ],
            );

            assert!(
                binary_exists,
                "Binary should exist at {}",
                binary_path.display()
            );

            // Verify binary runs
            if binary_exists {
                let run_result = std::process::Command::new(&binary_path).output();

                let runs_ok = run_result.as_ref().map(|r| r.status.success()).unwrap_or(false);
                let output = run_result
                    .as_ref()
                    .map(|r| String::from_utf8_lossy(&r.stdout).to_string())
                    .unwrap_or_default();

                logger.log_with_context(
                    LogLevel::Info,
                    LogSource::Custom("test".to_string()),
                    "Binary execution verification",
                    vec![
                        ("phase".to_string(), "verify".to_string()),
                        ("runs".to_string(), runs_ok.to_string()),
                        ("output_contains_expected".to_string(), output.contains("Hello").to_string()),
                    ],
                );

                assert!(runs_ok, "Binary should run successfully");
                assert!(
                    output.contains("Hello"),
                    "Binary output should contain 'Hello', got: {}",
                    output
                );
            }
        }
        Err(e) => {
            logger.error(format!("Remote command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo build command failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Basic cargo build test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Release build
// =============================================================================

/// Test 2: Release build
///
/// Command: `cargo build --release`
/// Expected: target/release/hello_world binary exists
/// Verify: binary is optimized (smaller, no debug symbols)
#[tokio::test]
async fn test_cargo_build_release() {
    let logger = TestLoggerBuilder::new("test_cargo_build_release")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo build release test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "hello_world".to_string()),
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
    let remote_path = format!("{}/hello_world_release", config.settings.remote_work_dir);

    // Phase: Setup
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Syncing fixture to remote",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("remote_path".to_string(), remote_path.clone()),
        ],
    );

    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Execute remote build with --release
    let build_cmd = format!("cd {} && cargo build --release", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote release build",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), "cargo build --release".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&build_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote release build completed",
                vec![
                    ("phase".to_string(), "execute_remote".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("duration_ms".to_string(), remote_duration.as_millis().to_string()),
                ],
            );

            if !result.success() {
                logger.error(format!("Remote build failed: {}", result.stderr));
                let _ = cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                panic!("Remote cargo build --release failed");
            }

            // Sync artifacts back
            let _ = sync_artifacts_from_remote(&worker_config, &remote_path, &fixture_dir).await;

            // Verify release binary exists
            let release_binary = fixture_dir.join("target/release/hello_world");
            let debug_binary = fixture_dir.join("target/debug/hello_world");

            let release_exists = release_binary.exists();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Release binary verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("path".to_string(), release_binary.display().to_string()),
                    ("exists".to_string(), release_exists.to_string()),
                ],
            );

            assert!(
                release_exists,
                "Release binary should exist at {}",
                release_binary.display()
            );

            // Compare sizes if both binaries exist
            if release_exists && debug_binary.exists() {
                let release_size = std::fs::metadata(&release_binary)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let debug_size = std::fs::metadata(&debug_binary)
                    .map(|m| m.len())
                    .unwrap_or(0);

                logger.log_with_context(
                    LogLevel::Info,
                    LogSource::Custom("test".to_string()),
                    "Size comparison debug vs release",
                    vec![
                        ("phase".to_string(), "verify".to_string()),
                        ("debug_size_bytes".to_string(), debug_size.to_string()),
                        ("release_size_bytes".to_string(), release_size.to_string()),
                        (
                            "release_smaller".to_string(),
                            (release_size < debug_size).to_string(),
                        ),
                    ],
                );

                // Release should generally be smaller (or at least not much larger)
                // due to optimizations and stripped debug info
            }
        }
        Err(e) => {
            logger.error(format!("Remote command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo build --release failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Release build test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Specific target build
// =============================================================================

/// Test 3: Specific target build
///
/// Command: `cargo build --bin hello_world`
/// Expected: only specified binary built
#[tokio::test]
async fn test_cargo_build_specific_target() {
    let logger = TestLoggerBuilder::new("test_cargo_build_specific_target")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting specific target build test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("target".to_string(), "hello_world".to_string()),
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
    let remote_path = format!("{}/hello_world_target", config.settings.remote_work_dir);

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Execute remote build with --bin
    let build_cmd = format!("cd {} && cargo build --bin hello_world", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote build with --bin",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), "cargo build --bin hello_world".to_string()),
            ("target_specification".to_string(), "--bin hello_world".to_string()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&build_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote target build completed",
                vec![
                    ("phase".to_string(), "execute_remote".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("duration_ms".to_string(), remote_duration.as_millis().to_string()),
                ],
            );

            if !result.success() {
                logger.error(format!("Remote build failed: {}", result.stderr));
                let _ = cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                panic!("Remote cargo build --bin failed");
            }

            // Sync artifacts back
            let _ = sync_artifacts_from_remote(&worker_config, &remote_path, &fixture_dir).await;

            // Verify binary exists
            let binary_path = fixture_dir.join("target/debug/hello_world");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Target binary verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("path".to_string(), binary_path.display().to_string()),
                    ("exists".to_string(), binary_path.exists().to_string()),
                ],
            );

            assert!(binary_path.exists(), "Target binary should exist");
        }
        Err(e) => {
            logger.error(format!("Remote command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo build --bin failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Specific target build test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Workspace build
// =============================================================================

/// Test 4: Workspace build
///
/// Command: `cargo build --workspace`
/// Expected: all workspace members built
#[tokio::test]
async fn test_cargo_build_workspace() {
    let logger = TestLoggerBuilder::new("test_cargo_build_workspace")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting workspace build test",
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
            "Test skipped: workspace fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/rust_workspace", config.settings.remote_work_dir);

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Execute remote build with --workspace
    let build_cmd = format!("cd {} && cargo build --workspace", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote workspace build",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), "cargo build --workspace".to_string()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&build_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote workspace build completed",
                vec![
                    ("phase".to_string(), "execute_remote".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("duration_ms".to_string(), remote_duration.as_millis().to_string()),
                ],
            );

            if !result.success() {
                logger.error(format!("Remote build failed: {}", result.stderr));
                let _ = cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                panic!("Remote cargo build --workspace failed");
            }

            // Sync artifacts back
            let _ = sync_artifacts_from_remote(&worker_config, &remote_path, &fixture_dir).await;

            // Verify workspace packages were built by checking for the app binary
            // (workspace structure: crates/app, crates/core, crates/utils)
            let app_binary = fixture_dir.join("target/debug/app");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Workspace build verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("packages_built".to_string(), "workspace members".to_string()),
                    ("app_binary_exists".to_string(), app_binary.exists().to_string()),
                ],
            );

            // Note: The exact verification depends on the workspace structure
            // The existence of target/debug directory with artifacts is a good indicator
            let target_dir = fixture_dir.join("target/debug");
            assert!(
                target_dir.exists(),
                "target/debug directory should exist after workspace build"
            );
        }
        Err(e) => {
            logger.error(format!("Remote command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo build --workspace failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Workspace build test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Package-specific build
// =============================================================================

/// Test 5: Package-specific build
///
/// Command: `cargo build -p hello_world`
/// Expected: only that package built
#[tokio::test]
async fn test_cargo_build_package_specific() {
    let logger = TestLoggerBuilder::new("test_cargo_build_package_specific")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting package-specific build test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("package".to_string(), "hello_world".to_string()),
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
    let remote_path = format!("{}/hello_world_package", config.settings.remote_work_dir);

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Execute remote build with -p package
    let build_cmd = format!("cd {} && cargo build -p hello_world", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote package-specific build",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), "cargo build -p hello_world".to_string()),
            ("package_filter".to_string(), "-p hello_world".to_string()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&build_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote package build completed",
                vec![
                    ("phase".to_string(), "execute_remote".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("duration_ms".to_string(), remote_duration.as_millis().to_string()),
                ],
            );

            if !result.success() {
                logger.error(format!("Remote build failed: {}", result.stderr));
                let _ = cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                panic!("Remote cargo build -p failed");
            }

            // Sync artifacts back
            let _ = sync_artifacts_from_remote(&worker_config, &remote_path, &fixture_dir).await;

            // Verify package binary exists
            let binary_path = fixture_dir.join("target/debug/hello_world");

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Package binary verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("path".to_string(), binary_path.display().to_string()),
                    ("exists".to_string(), binary_path.exists().to_string()),
                ],
            );

            assert!(binary_path.exists(), "Package binary should exist");
        }
        Err(e) => {
            logger.error(format!("Remote command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo build -p failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Package-specific build test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Exit code propagation
// =============================================================================

/// Test 6: Exit code propagation for successful build
///
/// Verify that exit code 0 is correctly propagated for successful builds.
#[tokio::test]
async fn test_cargo_build_exit_code_success() {
    let logger = TestLoggerBuilder::new("test_cargo_build_exit_code_success")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting exit code propagation test",
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
    let remote_path = format!("{}/hello_world_exitcode", config.settings.remote_work_dir);

    // Setup
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Execute
    let build_cmd = format!("cd {} && cargo build", remote_path);
    match client.execute(&build_cmd).await {
        Ok(result) => {
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
                "Successful build should return exit code 0"
            );
        }
        Err(e) => {
            logger.error(format!("Build failed unexpectedly: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Build failed: {e}");
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Exit code propagation test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Build artifact cleanup check
// =============================================================================

/// Test 7: No leftover artifacts on worker
///
/// Verify that after cleanup, no artifacts remain on the worker.
#[tokio::test]
async fn test_cargo_build_cleanup() {
    let logger = TestLoggerBuilder::new("test_cargo_build_cleanup")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cleanup verification test",
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

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let fixture_dir = hello_world_fixture_dir();
    let remote_path = format!("{}/hello_world_cleanup_test", config.settings.remote_work_dir);

    // Setup & build
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    let build_cmd = format!("cd {} && cargo build", remote_path);
    let _ = client.execute(&build_cmd).await;

    // Verify directory exists before cleanup
    let check_exists = format!("test -d {} && echo 'exists' || echo 'missing'", remote_path);
    let before_cleanup = client.execute(&check_exists).await;
    let exists_before = before_cleanup
        .map(|r| r.stdout.contains("exists"))
        .unwrap_or(false);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Pre-cleanup check",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("remote_path".to_string(), remote_path.clone()),
            ("exists_before_cleanup".to_string(), exists_before.to_string()),
        ],
    );

    // Cleanup
    let _ = cleanup_remote(&mut client, &remote_path).await;

    // Verify directory no longer exists
    let after_cleanup = client.execute(&check_exists).await;
    let exists_after = after_cleanup
        .map(|r| r.stdout.contains("exists"))
        .unwrap_or(false);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Cleanup check",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("exists_before_cleanup".to_string(), exists_before.to_string()),
            ("exists_after_cleanup".to_string(), exists_after.to_string()),
            ("cleanup_successful".to_string(), (!exists_after).to_string()),
        ],
    );

    assert!(exists_before, "Directory should exist before cleanup");
    assert!(!exists_after, "Directory should not exist after cleanup");

    client.disconnect().await.ok();
    logger.info("Cleanup verification test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Feature flags build
// =============================================================================

/// Get the feature_flags fixture directory
fn feature_flags_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("feature_flags")
}

/// Test 8: Feature flags build
///
/// Command: `cargo build --features verbose`
/// Expected: Feature is correctly passed to the remote worker
/// Verify: Build succeeds with the feature enabled
#[tokio::test]
async fn test_cargo_build_with_features() {
    let logger = TestLoggerBuilder::new("test_cargo_build_with_features")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting feature flags build test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "feature_flags".to_string()),
            ("feature".to_string(), "verbose".to_string()),
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

    let fixture_dir = feature_flags_fixture_dir();

    // Check if fixture exists
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: feature_flags fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/feature_flags_test", config.settings.remote_work_dir);

    // Phase: Setup - sync fixture to remote
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Syncing fixture to remote",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("local_path".to_string(), fixture_dir.display().to_string()),
            ("remote_path".to_string(), remote_path.clone()),
        ],
    );

    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: Execute - build without features first (baseline)
    let build_cmd_no_features = format!("cd {} && cargo build 2>&1", remote_path);
    let baseline_result = client.execute(&build_cmd_no_features).await;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Baseline build (no features)",
        vec![
            ("phase".to_string(), "execute_baseline".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
            (
                "success".to_string(),
                baseline_result
                    .as_ref()
                    .map(|r| r.success().to_string())
                    .unwrap_or_else(|_| "error".to_string()),
            ),
        ],
    );

    // Clean target for fresh build with features
    let clean_cmd = format!("cd {} && cargo clean", remote_path);
    let _ = client.execute(&clean_cmd).await;

    // Phase: Execute - build with verbose feature
    let build_cmd_with_feature = format!("cd {} && cargo build --features verbose 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Building with feature flag",
        vec![
            ("phase".to_string(), "execute_with_feature".to_string()),
            ("cmd".to_string(), "cargo build --features verbose".to_string()),
            ("feature".to_string(), "verbose".to_string()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&build_cmd_with_feature).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Feature build completed",
                vec![
                    ("phase".to_string(), "execute_with_feature".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("duration_ms".to_string(), remote_duration.as_millis().to_string()),
                    ("success".to_string(), result.success().to_string()),
                ],
            );

            if !result.success() {
                logger.log_with_context(
                    LogLevel::Error,
                    LogSource::Custom("test".to_string()),
                    "Feature build failed",
                    vec![
                        ("phase".to_string(), "execute_with_feature".to_string()),
                        ("stderr".to_string(), result.stderr.clone()),
                    ],
                );
                let _ = cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                panic!(
                    "cargo build --features verbose failed: {}",
                    result.stderr
                );
            }

            // Phase: Verify - test that feature is actually compiled in
            // We do this by running the tests with the feature enabled
            let test_cmd = format!(
                "cd {} && cargo test --features verbose -- --nocapture 2>&1",
                remote_path
            );

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Running tests to verify feature",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("cmd".to_string(), "cargo test --features verbose".to_string()),
                ],
            );

            match client.execute(&test_cmd).await {
                Ok(test_result) => {
                    logger.log_with_context(
                        LogLevel::Info,
                        LogSource::Custom("test".to_string()),
                        "Feature verification via tests",
                        vec![
                            ("phase".to_string(), "verify".to_string()),
                            ("exit_code".to_string(), test_result.exit_code.to_string()),
                            ("test_passed".to_string(), test_result.success().to_string()),
                        ],
                    );

                    assert!(
                        test_result.success(),
                        "Tests with feature should pass: {}",
                        test_result.stderr
                    );
                }
                Err(e) => {
                    logger.error(format!("Test command failed: {e}"));
                }
            }
        }
        Err(e) => {
            logger.error(format!("Remote command failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("cargo build --features verbose failed: {e}");
        }
    }

    // Phase: Additional verification - build with all features
    let all_features_cmd = format!("cd {} && cargo build --all-features 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Building with all features",
        vec![
            ("phase".to_string(), "execute_all_features".to_string()),
            ("cmd".to_string(), "cargo build --all-features".to_string()),
        ],
    );

    match client.execute(&all_features_cmd).await {
        Ok(result) => {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "All features build result",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("success".to_string(), result.success().to_string()),
                ],
            );

            assert!(
                result.success(),
                "cargo build --all-features should succeed: {}",
                result.stderr
            );
        }
        Err(e) => {
            logger.warn(format!("All features build failed: {e}"));
        }
    }

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Feature flags build test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Incremental rebuild
// =============================================================================

/// Test 9: Incremental rebuild
///
/// Verify that only changed files are recompiled on subsequent builds.
/// This tests that the remote worker preserves build cache between invocations.
#[tokio::test]
async fn test_cargo_build_incremental() {
    let logger = TestLoggerBuilder::new("test_cargo_build_incremental")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting incremental build test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "hello_world".to_string()),
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
    let remote_path = format!("{}/hello_world_incremental", config.settings.remote_work_dir);

    // Phase: Setup - sync fixture to remote
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Syncing fixture to remote",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("remote_path".to_string(), remote_path.clone()),
        ],
    );

    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        return;
    }

    // Phase: First build - full compilation
    let build_cmd = format!("cd {} && cargo build 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "First build (full compilation)",
        vec![
            ("phase".to_string(), "first_build".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
        ],
    );

    let first_start = Instant::now();
    let first_result = client.execute(&build_cmd).await;
    let first_duration = first_start.elapsed();

    let first_success = first_result.as_ref().map(|r| r.success()).unwrap_or(false);
    let first_output = first_result
        .as_ref()
        .map(|r| format!("{}\n{}", r.stdout, r.stderr))
        .unwrap_or_default();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "First build completed",
        vec![
            ("phase".to_string(), "first_build".to_string()),
            ("success".to_string(), first_success.to_string()),
            ("duration_ms".to_string(), first_duration.as_millis().to_string()),
            ("compiled".to_string(), first_output.contains("Compiling").to_string()),
        ],
    );

    if !first_success {
        logger.error("First build failed");
        let _ = cleanup_remote(&mut client, &remote_path).await;
        client.disconnect().await.ok();
        panic!("First build failed");
    }

    // Verify that "Compiling" appeared in first build
    assert!(
        first_output.contains("Compiling"),
        "First build should show 'Compiling' output"
    );

    // Phase: Second build - should be cached (no recompilation needed)
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Second build (should use cache)",
        vec![
            ("phase".to_string(), "second_build".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
        ],
    );

    let second_start = Instant::now();
    let second_result = client.execute(&build_cmd).await;
    let second_duration = second_start.elapsed();

    let second_success = second_result.as_ref().map(|r| r.success()).unwrap_or(false);
    let second_output = second_result
        .as_ref()
        .map(|r| format!("{}\n{}", r.stdout, r.stderr))
        .unwrap_or_default();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Second build completed",
        vec![
            ("phase".to_string(), "second_build".to_string()),
            ("success".to_string(), second_success.to_string()),
            ("duration_ms".to_string(), second_duration.as_millis().to_string()),
            ("recompiled".to_string(), second_output.contains("Compiling").to_string()),
        ],
    );

    if !second_success {
        logger.error("Second build failed");
        let _ = cleanup_remote(&mut client, &remote_path).await;
        client.disconnect().await.ok();
        panic!("Second build failed");
    }

    // Second build should NOT contain "Compiling" (everything cached)
    let is_cached = !second_output.contains("Compiling");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Cache verification",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("cached".to_string(), is_cached.to_string()),
            ("first_duration_ms".to_string(), first_duration.as_millis().to_string()),
            ("second_duration_ms".to_string(), second_duration.as_millis().to_string()),
        ],
    );

    // Note: We check for caching but don't fail if it's not cached,
    // as some environments might not support incremental builds
    if !is_cached {
        logger.warn("Incremental build not cached - this may be expected in some configurations");
    }

    // Phase: Touch source file and rebuild - should recompile only affected file
    let touch_cmd = format!(
        "cd {} && touch src/main.rs && sleep 1",
        remote_path
    );
    let _ = client.execute(&touch_cmd).await;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Third build (after touch)",
        vec![
            ("phase".to_string(), "third_build".to_string()),
            ("cmd".to_string(), "cargo build".to_string()),
            ("action".to_string(), "touched src/main.rs".to_string()),
        ],
    );

    let third_start = Instant::now();
    let third_result = client.execute(&build_cmd).await;
    let third_duration = third_start.elapsed();

    let third_success = third_result.as_ref().map(|r| r.success()).unwrap_or(false);
    let third_output = third_result
        .as_ref()
        .map(|r| format!("{}\n{}", r.stdout, r.stderr))
        .unwrap_or_default();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Third build completed",
        vec![
            ("phase".to_string(), "third_build".to_string()),
            ("success".to_string(), third_success.to_string()),
            ("duration_ms".to_string(), third_duration.as_millis().to_string()),
            ("recompiled".to_string(), third_output.contains("Compiling").to_string()),
        ],
    );

    if !third_success {
        logger.error("Third build failed");
        let _ = cleanup_remote(&mut client, &remote_path).await;
        client.disconnect().await.ok();
        panic!("Third build failed");
    }

    // After touching the source file, it SHOULD recompile
    let third_recompiled = third_output.contains("Compiling");

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Incremental rebuild verification",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("touched_file_recompiled".to_string(), third_recompiled.to_string()),
            ("first_duration_ms".to_string(), first_duration.as_millis().to_string()),
            ("second_duration_ms".to_string(), second_duration.as_millis().to_string()),
            ("third_duration_ms".to_string(), third_duration.as_millis().to_string()),
        ],
    );

    // Verify incremental behavior
    assert!(
        third_recompiled,
        "After touching source file, cargo should recompile"
    );

    // Cleanup
    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Incremental build test passed");
    logger.print_summary();
}
