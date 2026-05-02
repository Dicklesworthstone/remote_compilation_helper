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

use rch_common::e2e::{TestConfigError, TestWorkersConfig, should_skip_worker_check};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use rch_common::testing::{TestLogger, TestPhase};
use rch_common::types::WorkerConfig;
use shell_escape::escape;
use std::borrow::Cow;
use std::fs;
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

fn remote_target_rsync_path(remote_path: &str) -> String {
    shell_escape_str(&format!("{}/target/", remote_path.trim_end_matches('/')))
}

fn rsync_ssh_command(identity_file: &str) -> String {
    let expanded_identity_file = shellexpand::tilde(identity_file);
    format!(
        "ssh -o StrictHostKeyChecking=accept-new -i {}",
        shell_escape_str(expanded_identity_file.as_ref())
    )
}

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
    let escaped_remote_path = shell_escape_str(remote_path);
    let mkdir_cmd = format!("mkdir -p -- {escaped_remote_path}");
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
            &rsync_ssh_command(&worker_config.identity_file),
            &format!(
                "{}@{}:{}",
                worker_config.user,
                worker_config.host,
                remote_target_rsync_path(remote_path)
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
    let cmd = format!("rm -rf -- {}", shell_escape_str(remote_path));
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
                if let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && (name.starts_with("bench-") || name.starts_with("bench_project-"))
                {
                    return Some(path);
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
async fn test_cargo_bench_basic() -> Result<(), String> {
    let logger = TestLogger::for_test("test_cargo_bench_basic");

    logger.log_with_data(
        TestPhase::Setup,
        "Starting cargo bench basic test",
        serde_json::json!({"fixture": "bench_project"}),
    );

    let Some(config) = require_workers() else {
        logger.log(TestPhase::Setup, "Test skipped: no workers available");
        return Ok(());
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.log(TestPhase::Setup, "Test skipped: no enabled worker found");
        return Ok(());
    };

    let fixture_dir = bench_project_fixture_dir();
    if !fixture_dir.exists() {
        logger.log(
            TestPhase::Setup,
            format!(
                "Test skipped: bench_project fixture not found at {}",
                fixture_dir.display()
            ),
        );
        return Ok(());
    }

    let local_baseline_target = tempfile::Builder::new()
        .prefix("rch-cargo-bench-local-target-")
        .tempdir()
        .map_err(|e| format!("Failed to create local baseline target dir: {e}"))?;
    let artifact_root = tempfile::Builder::new()
        .prefix("rch-cargo-bench-artifacts-")
        .tempdir()
        .map_err(|e| format!("Failed to create artifact temp dir: {e}"))?;
    fs::create_dir_all(artifact_root.path().join("target"))
        .map_err(|e| format!("Failed to create artifact target dir: {e}"))?;

    let worker_config = worker_entry.to_worker_config();
    let Some(mut client) = get_connected_client(&config, worker_entry).await else {
        logger.fail("Failed to connect to worker");
        return Err("Failed to connect to worker".to_string());
    };

    let remote_path = remote_test_path(&config.settings.remote_work_dir, "cargo_bench_basic");

    logger.log_with_data(
        TestPhase::Setup,
        "Syncing fixture to remote",
        serde_json::json!({"worker": &worker_entry.id}),
    );

    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, &fixture_dir, &remote_path).await
    {
        let _ = cleanup_remote(&mut client, &remote_path).await;
        client.disconnect().await.ok();
        let message = format!("Failed to sync fixture: {e}");
        logger.fail(message.as_str());
        return Err(message);
    }

    // Local baseline
    logger.log(TestPhase::Execute, "Running local cargo bench baseline");
    let local_start = Instant::now();
    let local_result = std::process::Command::new("cargo")
        .args(["bench", "--bench", "bench"])
        .env("CARGO_TARGET_DIR", local_baseline_target.path())
        .current_dir(&fixture_dir)
        .output();
    let local_duration = local_start.elapsed();

    let local_exit = local_result
        .ok()
        .and_then(|r| r.status.code())
        .unwrap_or(-1);

    logger.log_with_data(
        TestPhase::Execute,
        "Local cargo bench completed",
        serde_json::json!({
            "cmd": "cargo bench --bench bench",
            "exit_code": local_exit,
            "duration_ms": local_duration.as_millis() as u64
        }),
    );

    // Remote bench
    let bench_cmd = format!(
        "cd {} && cargo bench --bench bench 2>&1",
        shell_escape_str(&remote_path)
    );

    logger.log_with_data(
        TestPhase::Execute,
        "Executing remote cargo bench",
        serde_json::json!({"cmd": "cargo bench --bench bench", "worker": &worker_entry.id}),
    );

    let remote_start = Instant::now();
    match client.execute(&bench_cmd).await {
        Ok(result) => {
            let remote_duration = remote_start.elapsed();

            logger.log_with_data(
                TestPhase::Execute,
                "Remote cargo bench completed",
                serde_json::json!({
                    "exit_code": result.exit_code,
                    "duration_ms": remote_duration.as_millis() as u64,
                    "worker": &worker_entry.id
                }),
            );

            assert_eq!(
                local_exit, result.exit_code,
                "Exit code mismatch: local {} vs remote {}",
                local_exit, result.exit_code
            );

            // Sync artifacts back
            logger.log(TestPhase::Verify, "Syncing artifacts back from remote");
            if let Err(e) =
                sync_artifacts_from_remote(&worker_config, &remote_path, artifact_root.path()).await
            {
                let _ = cleanup_remote(&mut client, &remote_path).await;
                client.disconnect().await.ok();
                let message = format!("Failed to sync artifacts back: {e}");
                logger.fail(message.as_str());
                return Err(message);
            }

            // Verify bench artifact exists
            let bench_binary = find_bench_binary(artifact_root.path());
            let exists = bench_binary.is_some();
            let size = bench_binary
                .as_ref()
                .and_then(|p| fs::metadata(p).ok())
                .map(|m| m.len())
                .unwrap_or(0);
            let path_str = bench_binary
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<missing>".to_string());

            logger.log_with_data(
                TestPhase::Verify,
                "Bench artifact verification",
                serde_json::json!({
                    "path": path_str.clone(),
                    "exists": exists,
                    "size": size
                }),
            );

            assert!(exists, "Bench binary should exist at {}", path_str);
        }
        Err(e) => {
            let _ = cleanup_remote(&mut client, &remote_path).await;
            client.disconnect().await.ok();
            let message = format!("Remote cargo bench command failed: {e}");
            logger.fail(message.as_str());
            return Err(message);
        }
    }

    // Teardown
    if config.settings.cleanup_after_test {
        logger.log(TestPhase::Teardown, "Cleaning up remote directory");
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }

    client.disconnect().await.ok();
    logger.log(TestPhase::Verify, "All verifications passed");
    logger.pass();
    Ok(())
}

#[test]
fn remote_bench_path_is_unique_and_under_base() {
    let first = remote_test_path("/tmp/rch-e2e", "cargo_bench_basic");
    let second = remote_test_path("/tmp/rch-e2e/", "cargo_bench_basic");

    assert_ne!(first, second);
    assert!(first.starts_with("/tmp/rch-e2e/cargo_bench_basic-"));
    assert!(second.starts_with("/tmp/rch-e2e/cargo_bench_basic-"));
}

#[test]
fn remote_bench_rsync_paths_quote_shell_sensitive_values() {
    assert_eq!(
        remote_rsync_path("/tmp/rch e2e/cargo_bench_basic"),
        "'/tmp/rch e2e/cargo_bench_basic/'"
    );
    assert_eq!(
        remote_target_rsync_path("/tmp/rch e2e/cargo_bench_basic"),
        "'/tmp/rch e2e/cargo_bench_basic/target/'"
    );
}

#[test]
fn remote_bench_command_path_is_shell_escaped() {
    let remote_path = "/tmp/rch e2e/cargo_bench_basic";

    assert_eq!(
        format!(
            "cd {} && cargo bench --bench bench 2>&1",
            shell_escape_str(remote_path)
        ),
        "cd '/tmp/rch e2e/cargo_bench_basic' && cargo bench --bench bench 2>&1"
    );
}

#[test]
fn remote_bench_rsync_ssh_command_expands_and_quotes_identity_path() {
    assert_eq!(
        rsync_ssh_command("/tmp/key files/id_ed25519"),
        "ssh -o StrictHostKeyChecking=accept-new -i '/tmp/key files/id_ed25519'"
    );

    if std::env::var_os("HOME").is_some() {
        assert!(!rsync_ssh_command("~/.ssh/id_ed25519").contains(" -i ~/"));
    }
}
