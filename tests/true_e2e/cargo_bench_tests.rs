//! True E2E Tests: Cargo Bench Remote Execution
//!
//! Tests that `cargo bench` commands are correctly executed on real workers
//! and produce benchmark artifacts and output.
//!
//! # Running These Tests
//!
//! ```bash
//! cargo test --features true-e2e cargo_bench_tests -- --nocapture
//! ```
//!
//! # Bead Reference
//!
//! This implements part of bead bd-12hi: True E2E Cargo Compilation Tests (bench component)

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use rch_common::types::WorkerConfig;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Project root for fixtures
const FIXTURES_DIR: &str = "tests/true_e2e/fixtures";

/// Get the bench_project fixture directory
fn bench_project_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("bench_project")
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

fn find_bench_binary(root: &Path) -> Option<PathBuf> {
    let candidates = [
        root.join("target/release/deps"),
        root.join("target/debug/deps"),
    ];

    for dir in &candidates {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("bench-") || name.starts_with("bench_project-") {
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}

// =============================================================================
// Test: cargo bench basic
// =============================================================================

/// Test: cargo bench on a minimal benchmark project
///
/// Command: `cargo bench`
/// Expected: exit code 0 and bench artifact present
#[tokio::test]
async fn test_cargo_bench_basic() {
    let logger = TestLoggerBuilder::new("test_cargo_bench_basic")
        .print_realtime(true)
        .build();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Starting cargo bench basic test",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("fixture".to_string(), "bench_project".to_string()),
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

    let fixture_dir = bench_project_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: bench_project fixture not found at {}",
            fixture_dir.display()
        ));
        return;
    }

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.error("Failed to connect to worker");
        return;
    };

    let remote_path = format!("{}/cargo_bench_basic", config.settings.remote_work_dir);

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
        .args(["bench", "--bench", "bench"])
        .current_dir(&fixture_dir)
        .output();
    let local_duration = local_start.elapsed();

    let local_exit = local_result
        .ok()
        .and_then(|r| r.status.code())
        .unwrap_or(-1);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Local cargo bench baseline",
        vec![
            ("phase".to_string(), "execute_local".to_string()),
            ("cmd".to_string(), "cargo bench --bench bench".to_string()),
            ("exit_code".to_string(), local_exit.to_string()),
            (
                "duration_ms".to_string(),
                local_duration.as_millis().to_string(),
            ),
        ],
    );

    // Remote bench
    let bench_cmd = format!("cd {} && cargo bench --bench bench 2>&1", remote_path);

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("test".to_string()),
        "Executing remote cargo bench",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), "cargo bench --bench bench".to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    let remote_start = Instant::now();
    match client.execute(&bench_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Remote cargo bench completed",
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
                local_exit, result.exit_code,
                "Exit code mismatch: local {} vs remote {}",
                local_exit, result.exit_code
            );

            // Sync artifacts back
            if let Err(e) =
                sync_artifacts_from_remote(&worker_config, &remote_path, &fixture_dir).await
            {
                logger.warn(format!("Failed to sync artifacts back: {e}"));
            }

            // Verify bench artifact exists
            let bench_binary = find_bench_binary(&fixture_dir);
            let exists = bench_binary.is_some();
            let size = bench_binary
                .as_ref()
                .and_then(|p| fs::metadata(p).ok())
                .map(|m| m.len().to_string())
                .unwrap_or_else(|| "0".to_string());
            let path_str = bench_binary
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<missing>".to_string());

            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("test".to_string()),
                "Bench artifact verification",
                vec![
                    ("phase".to_string(), "verify".to_string()),
                    ("path".to_string(), path_str.clone()),
                    ("exists".to_string(), exists.to_string()),
                    ("size".to_string(), size),
                ],
            );

            assert!(exists, "Bench binary should exist at {}", path_str);
        }
        Err(e) => {
            logger.error(format!("Remote cargo bench failed: {e}"));
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            panic!("Remote cargo bench command failed: {e}");
        }
    }

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.info("Cargo bench basic test completed");
    logger.print_summary();
}
