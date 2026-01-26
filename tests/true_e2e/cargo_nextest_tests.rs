//! True E2E Tests: Cargo Nextest Remote Execution
//!
//! Tests that `cargo nextest run` is executed correctly on real workers
//! and exit codes match local execution.
//!
//! # Running These Tests
//!
//! ```bash
//! cargo test --features true-e2e cargo_nextest_tests -- --nocapture
//! ```
//!
//! # Bead Reference
//!
//! This implements part of bead bd-12hi: True E2E Cargo Compilation Tests (nextest component)

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

/// Get the hello_world fixture directory (has passing tests)
fn hello_world_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("hello_world")
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
    let mkdir_cmd = format!("mkdir -p {}", remote_path);
    client
        .execute(&mkdir_cmd)
        .await
        .map_err(|e| format!("Failed to create remote directory: {e}"))?;

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

fn nextest_available_local() -> bool {
    std::process::Command::new("cargo")
        .args(["nextest", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn nextest_available_remote(client: &mut SshClient) -> bool {
    match client.execute("cargo nextest --version").await {
        Ok(result) => result.success(),
        Err(_) => false,
    }
}

// =============================================================================
// Test: cargo nextest run (passing tests)
// =============================================================================

/// Test: cargo nextest run on hello_world fixture
#[tokio::test]
async fn test_cargo_nextest_run() {
    let logger = TestLoggerBuilder::new("test_cargo_nextest_run")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo nextest run test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "hello_world".to_string()),
        ],
    );

    if !nextest_available_local() {
        logger.warn("Test skipped: cargo nextest not installed locally");
        return;
    }

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let fixture_dir = hello_world_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: hello_world fixture not found at {}",
            fixture_dir.display()
        ));
        return;
    }

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    if !nextest_available_remote(&mut client).await {
        logger.warn("Test skipped: cargo nextest not installed on worker");
        client.disconnect().await.ok();
        return;
    }

    let remote_path = format!("{}/cargo_nextest_run", config.settings.remote_work_dir);

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

    // Local baseline
    let local_start = Instant::now();
    let local_result = std::process::Command::new("cargo")
        .args(["nextest", "run"])
        .current_dir(&fixture_dir)
        .output();
    let local_duration = local_start.elapsed();

    let local_exit = local_result
        .as_ref()
        .and_then(|r| r.status.code())
        .unwrap_or(-1);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local cargo nextest baseline",
        vec![
            ("phase".to_string(), "execute_local".to_string()),
            ("cmd".to_string(), "cargo nextest run".to_string()),
            ("exit_code".to_string(), local_exit.to_string()),
            (
                "duration_ms".to_string(),
                local_duration.as_millis().to_string(),
            ),
        ],
    );

    // Remote nextest
    let nextest_cmd = format!("cd {} && cargo nextest run 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo nextest run",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), "cargo nextest run".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&nextest_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote cargo nextest completed",
                vec![
                    ("phase".to_string(), "execute_remote".to_string()),
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    (
                        "duration_ms".to_string(),
                        remote_duration.as_millis().to_string(),
                    ),
                    ("worker".to_string(), worker_entry.id.clone()),
                ],
            );

            assert_eq!(
                local_exit,
                result.exit_code,
                "Exit code mismatch: local {} vs remote {}",
                local_exit,
                result.exit_code
            );
        }
        Err(e) => {
            logger.error(format!("Remote cargo nextest failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo nextest command failed: {e}");
        }
    }

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo nextest run test completed");
    logger.print_summary();
}
