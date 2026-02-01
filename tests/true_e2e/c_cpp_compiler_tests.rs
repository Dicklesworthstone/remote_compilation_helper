//! True E2E Tests: C/C++ Compilation + Build Systems
//!
//! Implements bead bd-v9pq: ensure that common C/C++ compilation commands and
//! build systems execute correctly on real workers, and that artifacts can be
//! pulled back and verified locally.
//!
//! Notes:
//! - These tests are gated behind the `true-e2e` feature flag.
//! - Tests skip gracefully if no workers are configured or required tools are missing.
//! - All phases emit structured JSON logs via TestLogger.

use rch_common::classify_command_detailed;
use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions};
use rch_common::types::WorkerConfig;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Project root for fixtures.
const FIXTURES_DIR: &str = "tests/true_e2e/fixtures";

fn hello_c_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("hello_c")
}

fn broken_c_fixture_dir() -> PathBuf {
    PathBuf::from(FIXTURES_DIR).join("broken_c")
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

fn get_test_worker(config: &TestWorkersConfig) -> Option<&rch_common::e2e::TestWorkerEntry> {
    config.enabled_workers().first().copied()
}

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

fn expand_identity_file(worker_config: &WorkerConfig) -> String {
    shellexpand::tilde(&worker_config.identity_file).into_owned()
}

/// Copy a local fixture directory into a temporary directory for isolation.
fn copy_fixture_to_temp(fixture_dir: &Path) -> Result<TempDir, String> {
    let temp_dir = TempDir::new().map_err(|e| format!("Failed to create temp dir: {e}"))?;
    let output = std::process::Command::new("rsync")
        .args([
            "-a",
            "--delete",
            &format!("{}/", fixture_dir.display()),
            &format!("{}/", temp_dir.path().display()),
        ])
        .output()
        .map_err(|e| format!("Failed to run rsync (local copy): {e}"))?;

    if output.status.success() {
        Ok(temp_dir)
    } else {
        Err(format!(
            "Local rsync copy failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Run a command locally and capture (exit_code, stdout, stderr, duration).
fn run_local_capture(
    cmd: &str,
    args: &[&str],
    dir: &Path,
) -> Result<(i32, String, String, Duration), String> {
    let start = Instant::now();
    let output = std::process::Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("Failed to run local command {cmd}: {e}"))?;
    let duration = start.elapsed();
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        duration,
    ))
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

    let identity_file = expand_identity_file(worker_config);
    let output = std::process::Command::new("rsync")
        .args([
            "-avz",
            "--delete",
            "-e",
            &format!(
                "ssh -o StrictHostKeyChecking=accept-new -i {}",
                identity_file
            ),
            &format!("{}/", local_path.display()),
            &format!(
                "{}@{}:{}/",
                worker_config.user, worker_config.host, remote_path
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to run rsync (remote sync up): {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "rsync failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[derive(Debug, Clone, Copy)]
struct TransferStats {
    bytes_transferred: u64,
    files_transferred: u64,
    duration: Duration,
}

fn parse_rsync_bytes(output: &str) -> u64 {
    for line in output.lines() {
        if line.contains("Total transferred file size:")
            && let Some(num_str) = line.split(':').nth(1)
        {
            let clean = num_str.trim().replace(',', "").replace(" bytes", "");
            if let Ok(bytes) = clean.parse::<u64>() {
                return bytes;
            }
        }
    }
    0
}

fn parse_rsync_files(output: &str) -> u64 {
    for line in output.lines() {
        if line.contains("Number of regular files transferred:")
            && let Some(num_str) = line.split(':').nth(1)
            && let Ok(count) = num_str.trim().replace(',', "").parse::<u64>()
        {
            return count;
        }
    }
    0
}

/// Sync a single remote file back to the local directory.
fn sync_remote_file_to_local(
    worker_config: &WorkerConfig,
    remote_file: &str,
    local_dir: &Path,
) -> Result<TransferStats, String> {
    let start = Instant::now();
    let identity_file = expand_identity_file(worker_config);
    let output = std::process::Command::new("rsync")
        .args([
            "-avz",
            "--stats",
            "-e",
            &format!(
                "ssh -o StrictHostKeyChecking=accept-new -i {}",
                identity_file
            ),
            &format!(
                "{}@{}:{}",
                worker_config.user, worker_config.host, remote_file
            ),
            &format!("{}/", local_dir.display()),
        ])
        .output()
        .map_err(|e| format!("Failed to run rsync (artifact sync down): {e}"))?;
    let duration = start.elapsed();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(TransferStats {
            bytes_transferred: parse_rsync_bytes(&stdout),
            files_transferred: parse_rsync_files(&stdout),
            duration,
        })
    } else {
        Err(format!(
            "rsync failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

async fn cleanup_remote(client: &mut SshClient, remote_path: &str) -> Result<(), String> {
    let cmd = format!("rm -rf {}", remote_path);
    client
        .execute(&cmd)
        .await
        .map_err(|e| format!("Failed to cleanup: {e}"))?;
    Ok(())
}

async fn probe_remote_tool_version(
    client: &mut SshClient,
    tool: &str,
    version_cmd: &str,
) -> (bool, String) {
    let cmd = format!("command -v {tool} >/dev/null 2>&1 && {version_cmd}");
    match client.execute(&cmd).await {
        Ok(result) if result.exit_code == 0 => {
            let version = result
                .stdout
                .lines()
                .last()
                .unwrap_or("unknown")
                .trim()
                .to_string();
            (true, version)
        }
        _ => (false, "not found".to_string()),
    }
}

fn probe_local_tool_version(tool: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(tool).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(
        stdout
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string(),
    )
}

fn log_classification(logger: &rch_common::e2e::TestLogger, cmd: &str) {
    let started = Instant::now();
    let detailed = classify_command_detailed(cmd);
    let elapsed = started.elapsed();
    let kind = detailed
        .classification
        .kind
        .map(|k| format!("{k:?}"))
        .unwrap_or_else(|| "none".to_string());
    logger.log_with_context(
        LogLevel::Debug,
        LogSource::Custom("classify".to_string()),
        "Command classified",
        vec![
            ("phase".to_string(), "classify".to_string()),
            ("cmd".to_string(), cmd.to_string()),
            (
                "is_compilation".to_string(),
                detailed.classification.is_compilation.to_string(),
            ),
            (
                "confidence".to_string(),
                format!("{:.3}", detailed.classification.confidence),
            ),
            ("kind".to_string(), kind),
            ("duration_us".to_string(), elapsed.as_micros().to_string()),
            (
                "reason".to_string(),
                detailed.classification.reason.to_string(),
            ),
        ],
    );
}

fn assert_binary_runs(logger: &rch_common::e2e::TestLogger, binary_path: &Path) {
    let meta = std::fs::metadata(binary_path).expect("binary should exist");
    let size = meta.len();

    let output = std::process::Command::new(binary_path)
        .output()
        .expect("binary should run");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("verify".to_string()),
        "Binary verified",
        vec![
            ("phase".to_string(), "verify".to_string()),
            ("path".to_string(), binary_path.display().to_string()),
            ("size".to_string(), size.to_string()),
            (
                "exit_code".to_string(),
                output.status.code().unwrap_or(-1).to_string(),
            ),
            ("runs".to_string(), output.status.success().to_string()),
        ],
    );

    assert!(output.status.success(), "binary should exit 0");
    assert!(
        stdout.contains("Hello from rch test fixture!"),
        "stdout should include greeting, got: {}",
        stdout
    );
}

// =============================================================================
// Direct compiler tests (gcc/clang/g++/clang++)
// =============================================================================

#[tokio::test]
async fn test_true_e2e_gcc_direct_compile_and_sync() {
    let logger = TestLoggerBuilder::new("test_true_e2e_gcc_direct_compile_and_sync")
        .print_realtime(true)
        .build();
    logger.info("TEST START: test_true_e2e_gcc_direct_compile_and_sync");

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

    let (has_gcc, gcc_version) =
        probe_remote_tool_version(&mut client, "gcc", "gcc --version | head -1").await;
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("setup".to_string()),
        "Compiler detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("compiler".to_string(), "gcc".to_string()),
            ("version".to_string(), gcc_version.clone()),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );
    if !has_gcc {
        logger.warn("Test skipped: gcc not available on worker");
        client.disconnect().await.ok();
        return;
    }

    let fixture_dir = hello_c_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let temp = match copy_fixture_to_temp(&fixture_dir) {
        Ok(dir) => dir,
        Err(e) => {
            logger.error(format!("Failed to copy fixture: {e}"));
            client.disconnect().await.ok();
            return;
        }
    };

    let command = "gcc -Wall -Wextra -O2 -o hello_gcc main.c hello.c";
    log_classification(&logger, command);

    // Local baseline (best-effort)
    if probe_local_tool_version("gcc", &["--version"]).is_some() {
        let (code, _stdout, stderr, duration) =
            run_local_capture("sh", &["-c", command], temp.path()).unwrap_or((
                -1,
                String::new(),
                "local command failed".to_string(),
                Duration::from_secs(0),
            ));
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("execute_local".to_string()),
            "Local compilation",
            vec![
                ("phase".to_string(), "execute_local".to_string()),
                ("cmd".to_string(), command.to_string()),
                ("exit_code".to_string(), code.to_string()),
                ("duration_ms".to_string(), duration.as_millis().to_string()),
                (
                    "stderr_tail".to_string(),
                    stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
                ),
            ],
        );
    } else {
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("execute_local".to_string()),
            "Local compiler missing, skipping baseline",
            vec![
                ("phase".to_string(), "execute_local".to_string()),
                ("cmd".to_string(), command.to_string()),
                ("compiler".to_string(), "gcc".to_string()),
            ],
        );
    }

    let remote_path = format!("{}/c_cpp_gcc_direct", config.settings.remote_work_dir);
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, temp.path(), &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return;
    }

    let remote_cmd = format!("cd {} && {}", remote_path, command);
    let remote_started = Instant::now();
    let remote_result = client.execute(&remote_cmd).await;
    let remote_duration = remote_started.elapsed();
    let (remote_exit_code, remote_stdout, remote_stderr) = match remote_result {
        Ok(result) => (result.exit_code, result.stdout, result.stderr),
        Err(err) => {
            logger.error(format!("Remote execution failed: {err}"));
            client.disconnect().await.ok();
            return;
        }
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("execute_remote".to_string()),
        "Remote compilation",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), command.to_string()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            (
                "duration_ms".to_string(),
                remote_duration.as_millis().to_string(),
            ),
            (
                "stdout_tail".to_string(),
                remote_stdout
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
            (
                "stderr_tail".to_string(),
                remote_stderr
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
        ],
    );

    assert_eq!(remote_exit_code, 0, "remote gcc should succeed");

    // Artifact sync down + verification
    let stats = sync_remote_file_to_local(
        &worker_config,
        &format!("{}/hello_gcc", remote_path),
        temp.path(),
    )
    .map_err(|e| logger.error(format!("Failed to sync artifact: {e}")))
    .ok();

    if let Some(stats) = stats {
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("sync_down".to_string()),
            "Artifact synced",
            vec![
                ("phase".to_string(), "sync_down".to_string()),
                (
                    "bytes_transferred".to_string(),
                    stats.bytes_transferred.to_string(),
                ),
                (
                    "files_transferred".to_string(),
                    stats.files_transferred.to_string(),
                ),
                (
                    "duration_ms".to_string(),
                    stats.duration.as_millis().to_string(),
                ),
            ],
        );
    }

    let binary_path = temp.path().join("hello_gcc");
    assert_binary_runs(&logger, &binary_path);

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }
    client.disconnect().await.ok();

    logger.info("TEST PASS: test_true_e2e_gcc_direct_compile_and_sync");
    logger.print_summary();
}

#[tokio::test]
async fn test_true_e2e_gcc_error_propagation() {
    let logger = TestLoggerBuilder::new("test_true_e2e_gcc_error_propagation")
        .print_realtime(true)
        .build();
    logger.info("TEST START: test_true_e2e_gcc_error_propagation");

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

    let temp = match copy_fixture_to_temp(&fixture_dir) {
        Ok(dir) => dir,
        Err(e) => {
            logger.error(format!("Failed to copy fixture: {e}"));
            client.disconnect().await.ok();
            return;
        }
    };

    let command = "gcc -Wall -Wextra -Werror -pedantic -std=c11 -o broken broken.c";
    log_classification(&logger, command);

    // Local baseline (best-effort)
    if probe_local_tool_version("gcc", &["--version"]).is_some() {
        let (code, _stdout, stderr, duration) =
            run_local_capture("sh", &["-c", command], temp.path()).unwrap_or((
                -1,
                String::new(),
                "local command failed".to_string(),
                Duration::from_secs(0),
            ));
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("execute_local".to_string()),
            "Local compilation (expected failure)",
            vec![
                ("phase".to_string(), "execute_local".to_string()),
                ("cmd".to_string(), command.to_string()),
                ("exit_code".to_string(), code.to_string()),
                ("duration_ms".to_string(), duration.as_millis().to_string()),
                (
                    "stderr_tail".to_string(),
                    stderr.lines().rev().take(5).collect::<Vec<_>>().join(" | "),
                ),
            ],
        );
    }

    let remote_path = format!("{}/c_cpp_gcc_error", config.settings.remote_work_dir);
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, temp.path(), &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return;
    }

    let remote_cmd = format!("cd {} && {}", remote_path, command);
    let remote_result = client.execute(&remote_cmd).await;
    let (remote_exit_code, remote_stdout, remote_stderr) = match remote_result {
        Ok(result) => (result.exit_code, result.stdout, result.stderr),
        Err(err) => {
            logger.error(format!("Remote execution failed: {err}"));
            client.disconnect().await.ok();
            return;
        }
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("execute_remote".to_string()),
        "Remote compilation (expected failure)",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), command.to_string()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            (
                "stderr_tail".to_string(),
                remote_stderr
                    .lines()
                    .rev()
                    .take(8)
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
        ],
    );

    assert_ne!(remote_exit_code, 0, "remote gcc error should be non-zero");
    assert!(
        remote_stdout.contains("undefined_function")
            || remote_stderr.contains("undefined_function"),
        "error output should mention undefined_function"
    );

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }
    client.disconnect().await.ok();

    logger.info("TEST PASS: test_true_e2e_gcc_error_propagation");
    logger.print_summary();
}

// =============================================================================
// Build system tests (make/cmake/ninja)
// =============================================================================

#[tokio::test]
async fn test_true_e2e_make_build_and_sync() {
    let logger = TestLoggerBuilder::new("test_true_e2e_make_build_and_sync")
        .print_realtime(true)
        .build();
    logger.info("TEST START: test_true_e2e_make_build_and_sync");

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

    let (has_make, make_version) =
        probe_remote_tool_version(&mut client, "make", "make --version | head -1").await;
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("setup".to_string()),
        "Build tool detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("tool".to_string(), "make".to_string()),
            ("version".to_string(), make_version),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );
    if !has_make {
        logger.warn("Test skipped: make not available on worker");
        client.disconnect().await.ok();
        return;
    }

    let fixture_dir = hello_c_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let temp = match copy_fixture_to_temp(&fixture_dir) {
        Ok(dir) => dir,
        Err(e) => {
            logger.error(format!("Failed to copy fixture: {e}"));
            client.disconnect().await.ok();
            return;
        }
    };

    let command = "make";
    log_classification(&logger, command);

    let (local_code, _stdout, stderr, duration) = run_local_capture("make", &[], temp.path())
        .unwrap_or((
            -1,
            String::new(),
            "local make failed".to_string(),
            Duration::from_secs(0),
        ));
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("execute_local".to_string()),
        "Local build",
        vec![
            ("phase".to_string(), "execute_local".to_string()),
            ("cmd".to_string(), command.to_string()),
            ("exit_code".to_string(), local_code.to_string()),
            ("duration_ms".to_string(), duration.as_millis().to_string()),
            (
                "stderr_tail".to_string(),
                stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
            ),
        ],
    );

    let remote_path = format!("{}/c_cpp_make_build", config.settings.remote_work_dir);
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, temp.path(), &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return;
    }

    let remote_cmd = format!("cd {} && {}", remote_path, command);
    let remote_started = Instant::now();
    let remote_result = client.execute(&remote_cmd).await;
    let remote_duration = remote_started.elapsed();
    let (remote_exit_code, remote_stdout, remote_stderr) = match remote_result {
        Ok(result) => (result.exit_code, result.stdout, result.stderr),
        Err(err) => {
            logger.error(format!("Remote execution failed: {err}"));
            client.disconnect().await.ok();
            return;
        }
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("execute_remote".to_string()),
        "Remote build",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), command.to_string()),
            ("exit_code".to_string(), remote_exit_code.to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            (
                "duration_ms".to_string(),
                remote_duration.as_millis().to_string(),
            ),
            (
                "stdout_tail".to_string(),
                remote_stdout
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
            (
                "stderr_tail".to_string(),
                remote_stderr
                    .lines()
                    .rev()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
        ],
    );

    assert_eq!(remote_exit_code, 0, "remote make should succeed");

    let stats = sync_remote_file_to_local(
        &worker_config,
        &format!("{}/hello", remote_path),
        temp.path(),
    )
    .map_err(|e| logger.error(format!("Failed to sync artifact: {e}")))
    .ok();

    if let Some(stats) = stats {
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("sync_down".to_string()),
            "Artifact synced",
            vec![
                ("phase".to_string(), "sync_down".to_string()),
                (
                    "bytes_transferred".to_string(),
                    stats.bytes_transferred.to_string(),
                ),
                (
                    "files_transferred".to_string(),
                    stats.files_transferred.to_string(),
                ),
                (
                    "duration_ms".to_string(),
                    stats.duration.as_millis().to_string(),
                ),
            ],
        );
    }

    let binary_path = temp.path().join("hello");
    assert_binary_runs(&logger, &binary_path);

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }
    client.disconnect().await.ok();

    logger.info("TEST PASS: test_true_e2e_make_build_and_sync");
    logger.print_summary();
}

#[tokio::test]
async fn test_true_e2e_cmake_build_and_sync() {
    let logger = TestLoggerBuilder::new("test_true_e2e_cmake_build_and_sync")
        .print_realtime(true)
        .build();
    logger.info("TEST START: test_true_e2e_cmake_build_and_sync");

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

    let (has_cmake, cmake_version) =
        probe_remote_tool_version(&mut client, "cmake", "cmake --version | head -1").await;
    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("setup".to_string()),
        "Build tool detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("tool".to_string(), "cmake".to_string()),
            ("version".to_string(), cmake_version),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );
    if !has_cmake {
        logger.warn("Test skipped: cmake not available on worker");
        client.disconnect().await.ok();
        return;
    }

    let fixture_dir = hello_c_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let temp = match copy_fixture_to_temp(&fixture_dir) {
        Ok(dir) => dir,
        Err(e) => {
            logger.error(format!("Failed to copy fixture: {e}"));
            client.disconnect().await.ok();
            return;
        }
    };

    // Local baseline: configure + build
    let _ = run_local_capture("cmake", &["-S", ".", "-B", "build"], temp.path()).map(
        |(code, _o, e, d)| {
            logger.log_with_context(
                LogLevel::Info,
                LogSource::Custom("execute_local".to_string()),
                "Local cmake configure",
                vec![
                    ("phase".to_string(), "execute_local".to_string()),
                    ("cmd".to_string(), "cmake -S . -B build".to_string()),
                    ("exit_code".to_string(), code.to_string()),
                    ("duration_ms".to_string(), d.as_millis().to_string()),
                    (
                        "stderr_tail".to_string(),
                        e.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
                    ),
                ],
            );
        },
    );

    let build_cmd = "cmake --build build";
    log_classification(&logger, build_cmd);

    let remote_path = format!("{}/c_cpp_cmake_build", config.settings.remote_work_dir);
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, temp.path(), &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return;
    }

    // Configure on remote (not intercepted by classifier; still part of workflow)
    let configure_cmd = format!("cd {} && cmake -S . -B build", remote_path);
    let configure_result = client.execute(&configure_cmd).await;
    if let Ok(result) = &configure_result {
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("execute_remote".to_string()),
            "Remote cmake configure",
            vec![
                ("phase".to_string(), "execute_remote".to_string()),
                ("cmd".to_string(), "cmake -S . -B build".to_string()),
                ("exit_code".to_string(), result.exit_code.to_string()),
                ("worker".to_string(), worker_entry.id.clone()),
            ],
        );
    }
    if configure_result.as_ref().map(|r| r.exit_code).unwrap_or(-1) != 0 {
        logger.warn("Remote cmake configure failed; skipping build");
        client.disconnect().await.ok();
        return;
    }

    let remote_build_cmd = format!("cd {} && {}", remote_path, build_cmd);
    let build_started = Instant::now();
    let build_result = client.execute(&remote_build_cmd).await;
    let build_duration = build_started.elapsed();
    let (exit_code, stdout, stderr) = match build_result {
        Ok(result) => (result.exit_code, result.stdout, result.stderr),
        Err(err) => {
            logger.error(format!("Remote build failed: {err}"));
            client.disconnect().await.ok();
            return;
        }
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("execute_remote".to_string()),
        "Remote cmake build",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), build_cmd.to_string()),
            ("exit_code".to_string(), exit_code.to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            (
                "duration_ms".to_string(),
                build_duration.as_millis().to_string(),
            ),
            (
                "stdout_tail".to_string(),
                stdout.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
            ),
            (
                "stderr_tail".to_string(),
                stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
            ),
        ],
    );

    assert_eq!(exit_code, 0, "remote cmake --build should succeed");

    // Pull back the built executable (hello_app)
    let stats = sync_remote_file_to_local(
        &worker_config,
        &format!("{}/build/hello_app", remote_path),
        temp.path(),
    )
    .map_err(|e| logger.error(format!("Failed to sync artifact: {e}")))
    .ok();

    if let Some(stats) = stats {
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("sync_down".to_string()),
            "Artifact synced",
            vec![
                ("phase".to_string(), "sync_down".to_string()),
                (
                    "bytes_transferred".to_string(),
                    stats.bytes_transferred.to_string(),
                ),
                (
                    "files_transferred".to_string(),
                    stats.files_transferred.to_string(),
                ),
                (
                    "duration_ms".to_string(),
                    stats.duration.as_millis().to_string(),
                ),
            ],
        );
    }

    let binary_path = temp.path().join("hello_app");
    assert_binary_runs(&logger, &binary_path);

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }
    client.disconnect().await.ok();

    logger.info("TEST PASS: test_true_e2e_cmake_build_and_sync");
    logger.print_summary();
}

#[tokio::test]
async fn test_true_e2e_ninja_build_and_sync() {
    let logger = TestLoggerBuilder::new("test_true_e2e_ninja_build_and_sync")
        .print_realtime(true)
        .build();
    logger.info("TEST START: test_true_e2e_ninja_build_and_sync");

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

    let (has_cmake, _cmake_version) =
        probe_remote_tool_version(&mut client, "cmake", "cmake --version | head -1").await;
    let (has_ninja, ninja_version) =
        probe_remote_tool_version(&mut client, "ninja", "ninja --version").await;

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("setup".to_string()),
        "Build tools detected",
        vec![
            ("phase".to_string(), "setup".to_string()),
            ("tool".to_string(), "ninja".to_string()),
            ("version".to_string(), ninja_version),
            ("worker".to_string(), worker_entry.id.clone()),
        ],
    );

    if !has_cmake || !has_ninja {
        logger.warn("Test skipped: cmake or ninja not available on worker");
        client.disconnect().await.ok();
        return;
    }

    let fixture_dir = hello_c_fixture_dir();
    if !fixture_dir.exists() {
        logger.warn(format!(
            "Test skipped: fixture not found at {}",
            fixture_dir.display()
        ));
        client.disconnect().await.ok();
        return;
    }

    let temp = match copy_fixture_to_temp(&fixture_dir) {
        Ok(dir) => dir,
        Err(e) => {
            logger.error(format!("Failed to copy fixture: {e}"));
            client.disconnect().await.ok();
            return;
        }
    };

    let remote_path = format!("{}/c_cpp_ninja_build", config.settings.remote_work_dir);
    if let Err(e) =
        sync_fixture_to_remote(&mut client, &worker_config, temp.path(), &remote_path).await
    {
        logger.error(format!("Failed to sync fixture: {e}"));
        client.disconnect().await.ok();
        return;
    }

    // Configure with Ninja generator
    let configure_cmd = format!("cd {} && cmake -S . -B build -G Ninja", remote_path);
    let configure_result = client.execute(&configure_cmd).await;
    if configure_result.as_ref().map(|r| r.exit_code).unwrap_or(-1) != 0 {
        logger.warn("Remote cmake -G Ninja configure failed; skipping build");
        client.disconnect().await.ok();
        return;
    }

    let build_cmd = "ninja -C build";
    log_classification(&logger, build_cmd);

    let remote_build_cmd = format!("cd {} && {}", remote_path, build_cmd);
    let build_started = Instant::now();
    let build_result = client.execute(&remote_build_cmd).await;
    let build_duration = build_started.elapsed();
    let (exit_code, stdout, stderr) = match build_result {
        Ok(result) => (result.exit_code, result.stdout, result.stderr),
        Err(err) => {
            logger.error(format!("Remote ninja build failed: {err}"));
            client.disconnect().await.ok();
            return;
        }
    };

    logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("execute_remote".to_string()),
        "Remote ninja build",
        vec![
            ("phase".to_string(), "execute_remote".to_string()),
            ("cmd".to_string(), build_cmd.to_string()),
            ("exit_code".to_string(), exit_code.to_string()),
            ("worker".to_string(), worker_entry.id.clone()),
            (
                "duration_ms".to_string(),
                build_duration.as_millis().to_string(),
            ),
            (
                "stdout_tail".to_string(),
                stdout.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
            ),
            (
                "stderr_tail".to_string(),
                stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
            ),
        ],
    );

    assert_eq!(exit_code, 0, "remote ninja build should succeed");

    let stats = sync_remote_file_to_local(
        &worker_config,
        &format!("{}/build/hello_app", remote_path),
        temp.path(),
    )
    .map_err(|e| logger.error(format!("Failed to sync artifact: {e}")))
    .ok();

    if let Some(stats) = stats {
        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("sync_down".to_string()),
            "Artifact synced",
            vec![
                ("phase".to_string(), "sync_down".to_string()),
                (
                    "bytes_transferred".to_string(),
                    stats.bytes_transferred.to_string(),
                ),
                (
                    "files_transferred".to_string(),
                    stats.files_transferred.to_string(),
                ),
                (
                    "duration_ms".to_string(),
                    stats.duration.as_millis().to_string(),
                ),
            ],
        );
    }

    let binary_path = temp.path().join("hello_app");
    assert_binary_runs(&logger, &binary_path);

    if config.settings.cleanup_after_test {
        let _ = cleanup_remote(&mut client, &remote_path).await;
    }
    client.disconnect().await.ok();

    logger.info("TEST PASS: test_true_e2e_ninja_build_and_sync");
    logger.print_summary();
}
