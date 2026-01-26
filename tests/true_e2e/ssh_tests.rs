//! True E2E Tests: SSH Connection & Authentication
//!
//! Tests SSH connections to real workers without mocking, verifying
//! authentication, connection pooling, and timeout handling.
//!
//! # Test Categories
//!
//! 1. Basic SSH Connectivity - connect, authenticate, close
//! 2. Connection Timeout - handling invalid hosts, budget verification
//! 3. Connection Pooling - reuse, cleanup, leak prevention
//! 4. Key Authentication - default and custom key paths
//! 5. Reconnection - recovery after disconnect
//! 6. Multiple Workers - simultaneous connections
//!
//! # Running These Tests
//!
//! ```bash
//! # Requires workers_test.toml configuration
//! cargo test --features true-e2e ssh_tests -- --nocapture
//! ```

use rch_common::e2e::{
    LogLevel, LogSource, TestConfigError, TestLoggerBuilder, TestWorkersConfig,
    should_skip_worker_check,
};
use rch_common::ssh::{KnownHostsPolicy, SshClient, SshOptions, SshPool};
use rch_common::types::{WorkerConfig, WorkerId};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
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

// =============================================================================
// SSH Key Helpers
// =============================================================================

const ENV_INVALID_KEY_PATH: &str = "RCH_E2E_INVALID_KEY_PATH";
const ENV_FORCE_AGENT_AUTH: &str = "RCH_E2E_FORCE_AGENT_AUTH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyType {
    Ed25519,
    Rsa,
    Ecdsa,
    Unknown,
}

impl KeyType {
    fn as_str(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::Rsa => "rsa",
            KeyType::Ecdsa => "ecdsa",
            KeyType::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct KeyMetadata {
    key_type: KeyType,
    bits: Option<u32>,
    fingerprint: Option<String>,
    path: PathBuf,
}

fn parse_key_type_label(label: &str) -> Option<KeyType> {
    match label.trim().to_lowercase().as_str() {
        "ed25519" => Some(KeyType::Ed25519),
        "rsa" => Some(KeyType::Rsa),
        "ecdsa" => Some(KeyType::Ecdsa),
        _ => None,
    }
}

fn infer_key_type_from_path(path: &Path) -> KeyType {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if name.contains("ed25519") {
        KeyType::Ed25519
    } else if name.contains("ecdsa") {
        KeyType::Ecdsa
    } else if name.contains("rsa") {
        KeyType::Rsa
    } else {
        KeyType::Unknown
    }
}

fn detect_key_metadata(path: &Path) -> Option<KeyMetadata> {
    if !path.exists() {
        return None;
    }

    let mut key_type = infer_key_type_from_path(path);
    let mut bits = None;
    let mut fingerprint = None;

    if let Ok(output) = Command::new("ssh-keygen").arg("-lf").arg(path).output()
        && output.status.success()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            if let Some(line) = stdout.lines().next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(bits_str) = parts.get(0) {
                    bits = bits_str.parse::<u32>().ok();
                }
                if let Some(fp) = parts.get(1) {
                    fingerprint = Some(fp.to_string());
                }
                if let Some(last) = parts.last() {
                    if let Some(inner) = last.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
                        if let Some(parsed) = parse_key_type_label(inner) {
                            key_type = parsed;
                        }
                    }
                }
            }
        }
    }

    Some(KeyMetadata {
        key_type,
        bits,
        fingerprint,
        path: path.to_path_buf(),
    })
}

fn find_worker_with_key_type(
    config: &TestWorkersConfig,
    desired: KeyType,
) -> Option<(&rch_common::e2e::TestWorkerEntry, KeyMetadata)> {
    for worker in config.enabled_workers() {
        if let Ok(path) = worker.expanded_identity_file()
            && let Some(meta) = detect_key_metadata(&path)
            && meta.key_type == desired
        {
            return Some((worker, meta));
        }
    }
    None
}

fn mask_path(path: &str) -> String {
    let path = Path::new(path);
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();

    if parts.len() <= 2 {
        return path.display().to_string();
    }

    format!(".../{}/{}", parts[parts.len() - 2], parts[parts.len() - 1])
}

fn ssh_agent_key_count() -> Option<usize> {
    let output = Command::new("ssh-add").arg("-L").output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("The agent has no identities") {
        return Some(0);
    }

    Some(stdout.lines().filter(|line| !line.trim().is_empty()).count())
}

fn log_phase(
    logger: &rch_common::e2e::TestLogger,
    level: LogLevel,
    source: LogSource,
    phase: &str,
    message: &str,
    mut context: Vec<(String, String)>,
) {
    context.push(("phase".to_string(), phase.to_string()));
    logger.log_with_context(level, source, message, context);
}

// =============================================================================
// Test: Basic SSH Connectivity
// =============================================================================

/// Test 1.1: Basic SSH connection to worker
#[tokio::test]
async fn test_ssh_basic_connect() {
    let logger = TestLoggerBuilder::new("test_ssh_basic_connect")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH basic connectivity test");

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Harness,
        "setup",
        "Testing connection to worker",
        vec![
            ("worker_id".to_string(), worker_entry.id.clone()),
            ("host".to_string(), worker_entry.host.clone()),
            ("user".to_string(), worker_entry.user.clone()),
        ],
    );

    let worker_config = to_worker_config(worker_entry);
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config.clone(), options);

    // Phase: Connect
    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "connect",
        "SSH connection attempt",
        vec![
            ("worker".to_string(), worker_entry.id.clone()),
            ("port".to_string(), worker_entry.port.to_string()),
        ],
    );

    let connect_start = Instant::now();
    match client.connect().await {
        Ok(()) => {
            let connect_duration = connect_start.elapsed();
            log_phase(
                &logger,
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "connect",
                "SSH connection established",
                vec![
                    ("worker".to_string(), worker_entry.id.clone()),
                    ("success".to_string(), "true".to_string()),
                    (
                        "connect_duration_ms".to_string(),
                        connect_duration.as_millis().to_string(),
                    ),
                ],
            );

            assert!(client.is_connected(), "Client should report connected");
        }
        Err(e) => {
            log_phase(
                &logger,
                LogLevel::Error,
                LogSource::Custom("ssh".to_string()),
                "connect",
                "SSH connection failed",
                vec![
                    ("worker".to_string(), worker_entry.id.clone()),
                    ("error".to_string(), e.to_string()),
                ],
            );
            panic!("SSH connection failed: {e}");
        }
    }

    // Phase: Verify with echo
    logger.info("Verifying connection with echo command");
    match client.execute("echo 'ssh_test_ok'").await {
        Ok(result) => {
            log_phase(
                &logger,
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "execute",
                "Command execution result",
                vec![
                    ("exit_code".to_string(), result.exit_code.to_string()),
                    ("stdout_len".to_string(), result.stdout.len().to_string()),
                    ("duration_ms".to_string(), result.duration_ms.to_string()),
                ],
            );
            assert!(result.success(), "Echo command should succeed");
            assert!(
                result.stdout.contains("ssh_test_ok"),
                "Output should contain test string"
            );
        }
        Err(e) => {
            logger.error(format!("Echo command failed: {e}"));
            panic!("Echo command failed: {e}");
        }
    }

    // Phase: Disconnect
    logger.info("Disconnecting from worker");
    match client.disconnect().await {
        Ok(()) => {
            log_phase(
                &logger,
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "disconnect",
                "SSH connection closed",
                vec![
                    ("worker".to_string(), worker_entry.id.clone()),
                    ("clean_close".to_string(), "true".to_string()),
                ],
            );
            assert!(!client.is_connected(), "Client should report disconnected");
        }
        Err(e) => {
            logger.warn(format!("Disconnect warning: {e}"));
        }
    }

    logger.info("SSH basic connectivity test passed");
    logger.print_summary();
}

async fn run_key_auth_test(test_name: &str, key_type: KeyType) {
    let logger = TestLoggerBuilder::new(test_name)
        .print_realtime(true)
        .build();

    logger.info(format!(
        "Starting SSH {} key authentication test",
        key_type.as_str()
    ));

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some((worker_entry, meta)) = find_worker_with_key_type(&config, key_type) else {
        log_phase(
            &logger,
            LogLevel::Warn,
            LogSource::Custom("ssh".to_string()),
            "skip",
            "No worker with requested key type",
            vec![("key_type".to_string(), key_type.as_str().to_string())],
        );
        logger.print_summary();
        return;
    };

    let mut context = vec![
        ("worker".to_string(), worker_entry.id.clone()),
        ("key_type".to_string(), meta.key_type.as_str().to_string()),
        ("key_path".to_string(), meta.path.display().to_string()),
    ];
    if let Some(bits) = meta.bits {
        context.push(("key_bits".to_string(), bits.to_string()));
    }
    if let Some(fp) = &meta.fingerprint {
        context.push(("fingerprint".to_string(), fp.clone()));
    }

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "connect",
        "SSH connection attempt",
        context,
    );

    let worker_config = to_worker_config(worker_entry);
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config, options);

    let auth_start = Instant::now();
    match client.connect().await {
        Ok(()) => {
            let auth_duration = auth_start.elapsed();
            log_phase(
                &logger,
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "auth",
                "SSH authentication succeeded",
                vec![
                    ("worker".to_string(), worker_entry.id.clone()),
                    ("key_type".to_string(), key_type.as_str().to_string()),
                    ("auth_duration_ms".to_string(), auth_duration.as_millis().to_string()),
                ],
            );
        }
        Err(e) => {
            log_phase(
                &logger,
                LogLevel::Error,
                LogSource::Custom("ssh".to_string()),
                "auth",
                "SSH authentication failed",
                vec![
                    ("worker".to_string(), worker_entry.id.clone()),
                    ("key_type".to_string(), key_type.as_str().to_string()),
                    ("error".to_string(), e.to_string()),
                ],
            );
            panic!("Key authentication failed: {e}");
        }
    }

    let result = client.execute("whoami").await.expect("whoami should work");
    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "execute",
        "Identity verification",
        vec![
            ("remote_user".to_string(), result.stdout.trim().to_string()),
            ("expected_user".to_string(), worker_entry.user.clone()),
        ],
    );

    assert!(
        result.stdout.trim() == worker_entry.user,
        "whoami should return configured user"
    );

    client.disconnect().await.ok();
    logger.info(format!(
        "SSH {} key authentication test passed",
        key_type.as_str()
    ));
    logger.print_summary();
}

/// Test 1.2: Ed25519 key authentication
#[tokio::test]
async fn test_ssh_ed25519_auth() {
    run_key_auth_test("test_ssh_ed25519_auth", KeyType::Ed25519).await;
}

/// Test 1.3: RSA key authentication (if available)
#[tokio::test]
async fn test_ssh_rsa_auth() {
    run_key_auth_test("test_ssh_rsa_auth", KeyType::Rsa).await;
}

/// Test 1.4: ECDSA key authentication (if available)
#[tokio::test]
async fn test_ssh_ecdsa_auth() {
    run_key_auth_test("test_ssh_ecdsa_auth", KeyType::Ecdsa).await;
}

/// Test 1.5: SSH agent authentication (if available)
#[tokio::test]
async fn test_ssh_agent_authentication() {
    let logger = TestLoggerBuilder::new("test_ssh_agent_authentication")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH agent authentication test");

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let agent_sock = match env::var("SSH_AUTH_SOCK") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            log_phase(
                &logger,
                LogLevel::Warn,
                LogSource::Custom("ssh".to_string()),
                "skip",
                "SSH_AUTH_SOCK not set; skipping agent auth test",
                vec![],
            );
            logger.print_summary();
            return;
        }
    };

    let agent_key_count = ssh_agent_key_count().unwrap_or(0);
    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "agent",
        "SSH agent detected",
        vec![
            ("agent_sock".to_string(), mask_path(&agent_sock)),
            ("loaded_keys".to_string(), agent_key_count.to_string()),
        ],
    );

    if agent_key_count == 0 && env::var(ENV_FORCE_AGENT_AUTH).is_err() {
        log_phase(
            &logger,
            LogLevel::Warn,
            LogSource::Custom("ssh".to_string()),
            "skip",
            "SSH agent has no keys; skipping auth test",
            vec![],
        );
        logger.print_summary();
        return;
    }

    let mut worker_config = to_worker_config(worker_entry);
    worker_config.identity_file = "/tmp/rch_no_such_key".to_string();

    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config, options);

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "connect",
        "SSH connection attempt (agent auth)",
        vec![
            ("worker".to_string(), worker_entry.id.clone()),
            ("agent_sock".to_string(), mask_path(&agent_sock)),
        ],
    );

    let auth_start = Instant::now();
    match client.connect().await {
        Ok(()) => {
            let auth_duration = auth_start.elapsed();
            log_phase(
                &logger,
                LogLevel::Info,
                LogSource::Custom("ssh".to_string()),
                "auth",
                "SSH agent authentication succeeded",
                vec![
                    ("worker".to_string(), worker_entry.id.clone()),
                    ("auth_duration_ms".to_string(), auth_duration.as_millis().to_string()),
                ],
            );
        }
        Err(e) => {
            log_phase(
                &logger,
                LogLevel::Warn,
                LogSource::Custom("ssh".to_string()),
                "auth",
                "SSH agent authentication failed",
                vec![
                    ("worker".to_string(), worker_entry.id.clone()),
                    ("error".to_string(), e.to_string()),
                ],
            );
            logger.print_summary();
            return;
        }
    }

    client.disconnect().await.ok();
    logger.info("SSH agent authentication test passed");
    logger.print_summary();
}

/// Test 1.6: Wrong key rejection (optional)
#[tokio::test]
async fn test_ssh_wrong_key_rejection() {
    let logger = TestLoggerBuilder::new("test_ssh_wrong_key_rejection")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH wrong key rejection test");

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let invalid_key_path = match env::var(ENV_INVALID_KEY_PATH) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            log_phase(
                &logger,
                LogLevel::Warn,
                LogSource::Custom("ssh".to_string()),
                "skip",
                "RCH_E2E_INVALID_KEY_PATH not set; skipping wrong-key test",
                vec![],
            );
            logger.print_summary();
            return;
        }
    };

    if !Path::new(&invalid_key_path).exists() {
        log_phase(
            &logger,
            LogLevel::Warn,
            LogSource::Custom("ssh".to_string()),
            "skip",
            "Invalid key path does not exist",
            vec![("key_path".to_string(), invalid_key_path.clone())],
        );
        logger.print_summary();
        return;
    }

    let mut worker_config = to_worker_config(worker_entry);
    worker_config.identity_file = invalid_key_path.clone();

    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config, options);

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "auth",
        "SSH authentication expected to fail",
        vec![
            ("worker".to_string(), worker_entry.id.clone()),
            ("key_path".to_string(), invalid_key_path),
        ],
    );

    let result = client.connect().await;
    if result.is_ok() {
        log_phase(
            &logger,
            LogLevel::Warn,
            LogSource::Custom("ssh".to_string()),
            "auth",
            "Unexpected SSH authentication success with wrong key",
            vec![("worker".to_string(), worker_entry.id.clone())],
        );
        logger.print_summary();
        panic!("Wrong-key test unexpectedly succeeded");
    }

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "auth",
        "SSH authentication failed as expected",
        vec![
            ("worker".to_string(), worker_entry.id.clone()),
            ("error".to_string(), result.err().map(|e| e.to_string()).unwrap_or_default()),
        ],
    );

    logger.info("SSH wrong key rejection test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Connection Timeout
// =============================================================================

/// Test 2.1: Connection timeout with invalid host
#[tokio::test]
async fn test_ssh_connection_timeout() {
    let logger = TestLoggerBuilder::new("test_ssh_connection_timeout")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH connection timeout test");

    // Create config for non-existent host with short timeout
    let timeout_secs = 2;
    let worker_config = WorkerConfig {
        id: WorkerId::new("timeout-test"),
        host: "192.0.2.1".to_string(), // TEST-NET-1 (RFC 5737) - guaranteed unreachable
        user: "nobody".to_string(),
        identity_file: "~/.ssh/id_rsa".to_string(),
        total_slots: 1,
        priority: 1,
        tags: vec![],
    };

    let options = SshOptions {
        connect_timeout: Duration::from_secs(timeout_secs),
        known_hosts: KnownHostsPolicy::AcceptAll,
        ..Default::default()
    };

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "connect",
        "Testing connection timeout",
        vec![
            ("host".to_string(), worker_config.host.clone()),
            ("timeout_secs".to_string(), timeout_secs.to_string()),
        ],
    );

    let mut client = SshClient::new(worker_config, options);

    let start = Instant::now();
    let result = client.connect().await;
    let elapsed = start.elapsed();

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "connect",
        "Connection attempt completed",
        vec![
            ("success".to_string(), result.is_ok().to_string()),
            ("actual_wait_ms".to_string(), elapsed.as_millis().to_string()),
            (
                "error_type".to_string(),
                result
                    .as_ref()
                    .err()
                    .map(|e| format!("{e:?}"))
                    .unwrap_or_default(),
            ),
        ],
    );

    // Should fail
    assert!(result.is_err(), "Connection to unreachable host should fail");

    // Should timeout within reasonable bounds (timeout + buffer)
    let max_expected = Duration::from_secs(timeout_secs + 5);
    assert!(
        elapsed < max_expected,
        "Timeout should occur within {} seconds, took {:?}",
        timeout_secs + 5,
        elapsed
    );

    logger.info("SSH connection timeout test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Connection Pooling
// =============================================================================

/// Test 3.1: Connection pool reuses connections
#[tokio::test]
async fn test_ssh_pool_reuse() {
    let logger = TestLoggerBuilder::new("test_ssh_pool_reuse")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH connection pool reuse test");

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = to_worker_config(worker_entry);
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        control_master: true, // Enable connection reuse
        ..Default::default()
    };

    let pool = SshPool::new(options);

    // First connection - should create new
    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "pool",
        "Connection pool stats (before first connection)",
        vec![("active".to_string(), pool.active_connections().await.to_string())],
    );

    let first_start = Instant::now();
    let client1 = pool
        .get_or_connect(&worker_config)
        .await
        .expect("First connection should succeed");
    let first_duration = first_start.elapsed();

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "pool",
        "First connection established",
        vec![
            ("duration_ms".to_string(), first_duration.as_millis().to_string()),
            ("active".to_string(), pool.active_connections().await.to_string()),
        ],
    );

    // Second connection - should reuse existing
    let second_start = Instant::now();
    let client2 = pool
        .get_or_connect(&worker_config)
        .await
        .expect("Second connection should succeed");
    let second_duration = second_start.elapsed();
    let reused_ptr = Arc::ptr_eq(&client1, &client2);

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "pool",
        "Second connection (reused)",
        vec![
            ("duration_ms".to_string(), second_duration.as_millis().to_string()),
            ("active".to_string(), pool.active_connections().await.to_string()),
            ("reused".to_string(), reused_ptr.to_string()),
            (
                "reused_fast".to_string(),
                (second_duration < first_duration / 2).to_string(),
            ),
        ],
    );

    // Pool should have only 1 active connection (reused)
    let active = pool.active_connections().await;
    assert_eq!(active, 1, "Pool should reuse connection, not create new one");
    assert!(reused_ptr, "Pool should reuse the same connection instance");

    // Second connection should be faster (reused)
    // (This may not always hold due to jitter, so we just log it)
    logger.info(format!(
        "First: {}ms, Second: {}ms (expected second to be faster if reused)",
        first_duration.as_millis(),
        second_duration.as_millis()
    ));

    // Cleanup
    pool.close_all().await.expect("Pool cleanup should succeed");

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "pool",
        "Pool closed",
        vec![("active".to_string(), pool.active_connections().await.to_string())],
    );

    assert_eq!(
        pool.active_connections().await,
        0,
        "Pool should have no connections after close_all"
    );

    logger.info("SSH connection pool reuse test passed");
    logger.print_summary();
}

/// Test 3.2: Connection pool doesn't leak connections
#[tokio::test]
async fn test_ssh_pool_no_leaks() {
    let logger = TestLoggerBuilder::new("test_ssh_pool_no_leaks")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH connection pool leak test");

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = to_worker_config(worker_entry);
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let pool = SshPool::new(options);

    // Create and use multiple connections
    for i in 0..5 {
        let client = pool
            .get_or_connect(&worker_config)
            .await
            .expect("Connection should succeed");

        // Execute a command
        let client_guard = client.read().await;
        let _ = client_guard.execute("echo test").await;
        drop(client_guard);

        log_phase(
            &logger,
            LogLevel::Debug,
            LogSource::Custom("ssh".to_string()),
            "pool",
            "Connection iteration",
            vec![
                ("iteration".to_string(), i.to_string()),
                ("active".to_string(), pool.active_connections().await.to_string()),
            ],
        );
    }

    // Should still have only 1 connection (all reused)
    let final_count = pool.active_connections().await;
    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "pool",
        "Final pool state",
        vec![("active".to_string(), final_count.to_string())],
    );

    assert_eq!(
        final_count, 1,
        "Pool should not leak connections - expected 1, got {}",
        final_count
    );

    pool.close_all().await.ok();
    logger.info("SSH connection pool leak test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Health Check
// =============================================================================

/// Test 4: SSH health check
#[tokio::test]
async fn test_ssh_health_check() {
    let logger = TestLoggerBuilder::new("test_ssh_health_check")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH health check test");

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = to_worker_config(worker_entry);
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config, options);
    client.connect().await.expect("Connection should succeed");

    // Health check should pass
    let health_start = Instant::now();
    let healthy = client.health_check().await.expect("Health check should complete");
    let health_duration = health_start.elapsed();

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "health",
        "Health check result",
        vec![
            ("worker".to_string(), worker_entry.id.clone()),
            ("healthy".to_string(), healthy.to_string()),
            ("duration_ms".to_string(), health_duration.as_millis().to_string()),
        ],
    );

    assert!(healthy, "Connected worker should report healthy");

    client.disconnect().await.ok();
    logger.info("SSH health check test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Multiple Workers (if available)
// =============================================================================

/// Test 5: Connect to multiple workers simultaneously
#[tokio::test]
async fn test_ssh_multiple_workers() {
    let logger = TestLoggerBuilder::new("test_ssh_multiple_workers")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH multiple workers test");

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let enabled = config.enabled_workers();
    if enabled.len() < 2 {
        logger.warn(format!(
            "Test skipped: need at least 2 workers, have {}",
            enabled.len()
        ));
        return;
    }

    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let pool = SshPool::new(options);

    // Connect to all enabled workers
    let mut successful = 0;
    for worker_entry in enabled.iter() {
        let worker_config = to_worker_config(worker_entry);

        match pool.get_or_connect(&worker_config).await {
            Ok(client) => {
                let guard = client.read().await;
                match guard.execute("hostname").await {
                    Ok(result) => {
                        log_phase(
                            &logger,
                            LogLevel::Info,
                            LogSource::Custom("ssh".to_string()),
                            "execute",
                            "Worker connection success",
                            vec![
                                ("worker_id".to_string(), worker_entry.id.clone()),
                                ("hostname".to_string(), result.stdout.trim().to_string()),
                            ],
                        );
                        successful += 1;
                    }
                    Err(e) => {
                        log_phase(
                            &logger,
                            LogLevel::Warn,
                            LogSource::Custom("ssh".to_string()),
                            "execute",
                            "Worker command failed",
                            vec![
                                ("worker_id".to_string(), worker_entry.id.clone()),
                                ("error".to_string(), e.to_string()),
                            ],
                        );
                    }
                }
            }
            Err(e) => {
                log_phase(
                    &logger,
                    LogLevel::Warn,
                    LogSource::Custom("ssh".to_string()),
                    "connect",
                    "Worker connection failed",
                    vec![
                        ("worker_id".to_string(), worker_entry.id.clone()),
                        ("error".to_string(), e.to_string()),
                    ],
                );
            }
        }
    }

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "summary",
        "Multiple workers test summary",
        vec![
            ("total_workers".to_string(), enabled.len().to_string()),
            ("successful".to_string(), successful.to_string()),
            ("pool_active".to_string(), pool.active_connections().await.to_string()),
        ],
    );

    assert!(
        successful >= 1,
        "At least one worker should be reachable"
    );

    pool.close_all().await.ok();
    logger.info("SSH multiple workers test passed");
    logger.print_summary();
}

// =============================================================================
// Test: Reconnection
// =============================================================================

/// Test 6: Reconnection after disconnect
#[tokio::test]
async fn test_ssh_reconnection() {
    let logger = TestLoggerBuilder::new("test_ssh_reconnection")
        .print_realtime(true)
        .build();

    logger.info("Starting SSH reconnection test");

    let Some(config) = require_workers() else {
        logger.warn("Test skipped: no workers available");
        return;
    };

    let Some(worker_entry) = get_test_worker(&config) else {
        logger.warn("Test skipped: no enabled worker found");
        return;
    };

    let worker_config = to_worker_config(worker_entry);
    let options = SshOptions {
        connect_timeout: Duration::from_secs(config.settings.ssh_connection_timeout_secs),
        known_hosts: KnownHostsPolicy::Add,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config, options);

    // First connection
    logger.info("Establishing first connection");
    client.connect().await.expect("First connect should succeed");
    assert!(client.is_connected(), "Should be connected");

    let result1 = client.execute("echo 'first'").await.expect("First command should work");
    assert!(result1.stdout.contains("first"));

    // Disconnect
    logger.info("Disconnecting");
    client.disconnect().await.expect("Disconnect should succeed");
    assert!(!client.is_connected(), "Should be disconnected");

    // Reconnect
    logger.info("Reconnecting");
    client.connect().await.expect("Reconnect should succeed");
    assert!(client.is_connected(), "Should be connected again");

    let result2 = client.execute("echo 'second'").await.expect("Second command should work");
    assert!(result2.stdout.contains("second"));

    log_phase(
        &logger,
        LogLevel::Info,
        LogSource::Custom("ssh".to_string()),
        "reconnect",
        "Reconnection test results",
        vec![
            ("first_command".to_string(), "success".to_string()),
            ("disconnect".to_string(), "success".to_string()),
            ("reconnect".to_string(), "success".to_string()),
            ("second_command".to_string(), "success".to_string()),
        ],
    );

    client.disconnect().await.ok();
    logger.info("SSH reconnection test passed");
    logger.print_summary();
}
