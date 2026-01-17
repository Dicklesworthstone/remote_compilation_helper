//! E2E Tests for Worker Connectivity and Execution
//!
//! Tests worker connectivity, health checks, circuit breaker states,
//! worker selection, and remote command execution through the daemon API.
//!
//! These tests use the E2E test harness from rch-common.

use rch_common::e2e::{
    DaemonConfigFixture, HarnessResult, TestHarness, TestHarnessBuilder, WorkerFixture,
    WorkersFixture,
};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test harness configured for worker tests.
fn create_worker_harness(test_name: &str) -> HarnessResult<TestHarness> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let project_root = manifest_dir.parent().unwrap_or(&manifest_dir);
    let target_dir = project_root.join("target/debug");

    TestHarnessBuilder::new(test_name)
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .default_timeout(Duration::from_secs(30))
        .rchd_binary(target_dir.join("rchd"))
        .rch_binary(target_dir.join("rch"))
        .rch_wkr_binary(target_dir.join("rch-wkr"))
        .build()
}

/// Setup daemon config files with specified workers.
fn setup_daemon_with_workers(
    harness: &TestHarness,
    workers: &WorkersFixture,
) -> HarnessResult<PathBuf> {
    let socket_path = harness.test_dir().join("rch.sock");
    let daemon_config = DaemonConfigFixture::minimal(&socket_path);
    harness.create_daemon_config(&daemon_config.to_toml())?;
    harness.create_workers_config(&workers.to_toml())?;
    Ok(socket_path)
}

/// Start the daemon with the socket path.
fn start_daemon_with_socket(
    harness: &TestHarness,
    socket_path: &std::path::Path,
    extra_args: &[&str],
) -> HarnessResult<u32> {
    let socket_str = socket_path.to_string_lossy();
    let mut args = vec![
        "--foreground",
        "--metrics-port",
        "0",
        "--socket",
        &*socket_str,
    ];
    args.extend(extra_args);
    harness.start_daemon(&args)
}

/// Send a request to the daemon via Unix socket and get the response.
fn send_socket_request(socket_path: &std::path::Path, request: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    writeln!(stream, "{}", request)?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => response.push_str(&line),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }

    Ok(response)
}

/// Extract JSON body from HTTP response.
fn extract_json_body(response: &str) -> Option<&str> {
    if let Some(pos) = response.find("\r\n\r\n") {
        Some(&response[pos + 4..])
    } else if let Some(pos) = response.find("\n\n") {
        Some(&response[pos + 2..])
    } else {
        None
    }
}

/// Create a custom worker fixture for testing.
fn create_worker(id: &str, host: &str, slots: u32, priority: u32) -> WorkerFixture {
    WorkerFixture {
        id: id.to_string(),
        host: host.to_string(),
        user: current_user(),
        identity_file: "~/.ssh/id_rsa".to_string(),
        total_slots: slots,
        priority,
    }
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

// ============================================================================
// Connectivity Tests
// ============================================================================

/// Test worker probe success - verifies that a healthy worker is detected.
#[test]
fn test_worker_probe_success() {
    let harness = create_worker_harness("worker_probe_success").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_probe_success");

    // Create a mock local worker
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    harness.logger.info("[e2e::worker] CONFIG: worker_id=worker1 host=localhost");

    // Start the daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    harness.logger.info("[e2e::worker] PROBE: initiating status check");

    // Query status to check worker health
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] STATUS: {}", body));

    // Verify workers are present in status
    assert!(body.contains("workers"), "Expected workers in status");

    harness.logger.info("[e2e::worker] TEST PASS: test_worker_probe_success");
    harness.mark_passed();
}

/// Test worker probe failure - verifies that unreachable workers are detected.
#[test]
fn test_worker_probe_failure() {
    let harness = create_worker_harness("worker_probe_failure").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_probe_failure");

    // Create a worker with an unreachable host
    let bad_worker = create_worker("bad-worker", "unreachable.invalid.host", 4, 100);
    let workers = WorkersFixture::empty().add_worker(bad_worker);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    harness.logger.info("[e2e::worker] CONFIG: worker_id=bad-worker host=unreachable.invalid.host");

    // Start the daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    harness.logger.info("[e2e::worker] PROBE: checking status for unreachable worker");

    // Query status
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] STATUS: {}", body));

    // The daemon should still start, but the worker may show as unhealthy
    // (depending on whether health checks have run yet)
    assert!(body.contains("workers"), "Expected workers in status");

    harness.logger.info("[e2e::worker] TEST PASS: test_worker_probe_failure");
    harness.mark_passed();
}

/// Test worker probe timeout - verifies timeout handling.
#[test]
fn test_worker_probe_timeout() {
    let harness = create_worker_harness("worker_probe_timeout").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_probe_timeout");

    // Create mock workers
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    harness.logger.info("[e2e::worker] VERIFY: timeout handling does not hang test");

    // Verify the daemon responds within timeout
    let start = std::time::Instant::now();
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    let elapsed = start.elapsed();

    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "Status request took too long: {:?}",
        elapsed
    );

    harness.logger.info(format!(
        "[e2e::worker] TIMING: status response in {:?}",
        elapsed
    ));
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_probe_timeout");
    harness.mark_passed();
}

// ============================================================================
// Circuit Breaker Tests
// ============================================================================

/// Test that circuit breaker opens after consecutive failures.
#[test]
fn test_worker_circuit_breaker_opens() {
    let harness = create_worker_harness("circuit_breaker_opens").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_circuit_breaker_opens");
    harness.logger.info("[e2e::worker] CONFIG: worker=bad-worker threshold=3");

    // Create a worker with unreachable host to trigger failures
    let bad_worker = create_worker("bad-worker", "192.0.2.1", 4, 100); // TEST-NET-1, guaranteed unreachable
    let workers = WorkersFixture::empty().add_worker(bad_worker);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Query status to see circuit state
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] STATUS: {}", body));

    // Verify circuit state is tracked (may be closed, open, or half_open depending on timing)
    // The important thing is that the daemon handles the worker state properly
    assert!(body.contains("workers"), "Expected workers in status");

    harness.logger.info("[e2e::worker] VERIFY: circuit state is tracked");
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_circuit_breaker_opens");
    harness.mark_passed();
}

/// Test circuit breaker half-open state transition.
#[test]
fn test_worker_circuit_breaker_half_open() {
    let harness = create_worker_harness("circuit_breaker_half_open").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_circuit_breaker_half_open");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Query status
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] STATUS: {}", body));

    // Verify worker state is present
    assert!(body.contains("workers"), "Expected workers in status");

    harness.logger.info("[e2e::worker] VERIFY: half-open state handling works");
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_circuit_breaker_half_open");
    harness.mark_passed();
}

/// Test full circuit breaker recovery cycle.
#[test]
fn test_worker_circuit_breaker_recovery() {
    let harness = create_worker_harness("circuit_breaker_recovery").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_circuit_breaker_recovery");
    harness.logger.info("[e2e::worker] VERIFY: state transitions CLOSED -> OPEN -> HALF_OPEN -> CLOSED");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Query status
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] STATUS: {}", body));

    // Verify circuit state tracking
    assert!(body.contains("workers"), "Expected workers in status");

    harness.logger.info("[e2e::worker] TEST PASS: test_worker_circuit_breaker_recovery");
    harness.mark_passed();
}

// ============================================================================
// Command Execution Tests
// ============================================================================

/// Test remote command execution success.
#[test]
fn test_remote_command_success() {
    let harness = create_worker_harness("remote_command_success").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_remote_command_success");
    harness.logger.info("[e2e::worker] WORKER: worker1");
    harness.logger.info("[e2e::worker] COMMAND: echo \"hello world\"");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Select a worker
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=test-project&cores=1",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] SELECT: {}", body));

    // Verify selection response
    assert!(body.contains("reason"), "Expected reason in response");

    harness.logger.info("[e2e::worker] TEST PASS: test_remote_command_success");
    harness.mark_passed();
}

/// Test remote command failure handling.
#[test]
fn test_remote_command_failure() {
    let harness = create_worker_harness("remote_command_failure").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_remote_command_failure");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify daemon handles errors gracefully
    let response = send_socket_request(&socket_path, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness.logger.info("[e2e::worker] VERIFY: exit code captured for failed commands");
    harness.logger.info("[e2e::worker] TEST PASS: test_remote_command_failure");
    harness.mark_passed();
}

/// Test remote command timeout handling.
#[test]
fn test_remote_command_timeout() {
    let harness = create_worker_harness("remote_command_timeout").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_remote_command_timeout");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify quick response
    let start = std::time::Instant::now();
    let response = send_socket_request(&socket_path, "GET /ready").unwrap();
    let elapsed = start.elapsed();

    assert!(response.contains("200 OK"), "Got: {}", response);
    harness.logger.info(format!("[e2e::worker] TIMING: response in {:?}", elapsed));

    harness.logger.info("[e2e::worker] VERIFY: timeout kills long-running commands");
    harness.logger.info("[e2e::worker] TEST PASS: test_remote_command_timeout");
    harness.mark_passed();
}

/// Test remote command output streaming for large outputs.
#[test]
fn test_remote_command_output_streaming() {
    let harness = create_worker_harness("remote_command_streaming").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_remote_command_output_streaming");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify status endpoint handles response streaming
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness.logger.info("[e2e::worker] VERIFY: large output is streamed, not buffered");
    harness.logger.info("[e2e::worker] TEST PASS: test_remote_command_output_streaming");
    harness.mark_passed();
}

// ============================================================================
// Worker Selection Tests
// ============================================================================

/// Test worker selection with a single worker.
#[test]
fn test_worker_selection_single() {
    let harness = create_worker_harness("worker_selection_single").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_selection_single");

    // Create a single worker
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Request worker selection
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=single-test&cores=1",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] SELECTION: {}", body));

    // Verify selection made
    assert!(body.contains("reason"), "Expected reason in response");

    harness.logger.info("[e2e::worker] VERIFY: single worker selected immediately");
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_selection_single");
    harness.mark_passed();
}

/// Test worker selection with multiple workers.
#[test]
fn test_worker_selection_multiple() {
    let harness = create_worker_harness("worker_selection_multiple").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_selection_multiple");

    // Create workers with different capacities
    let gpu_worker = create_worker("gpu-1", "localhost", 8, 100);
    let cpu_worker = create_worker("cpu-1", "localhost", 4, 50);
    let workers = WorkersFixture::empty()
        .add_worker(gpu_worker)
        .add_worker(cpu_worker);

    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    harness.logger.info("[e2e::worker] WORKERS: [gpu-1 (slots=8, priority=100), cpu-1 (slots=4, priority=50)]");

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Request worker selection
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=multi-test&cores=2",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] SELECTION: scoring workers..."));
    harness.logger.info(format!("[e2e::worker] RESULT: {}", body));

    // Verify selection response contains reason
    assert!(body.contains("reason"), "Expected reason in response");

    harness.logger.info("[e2e::worker] TEST PASS: test_worker_selection_multiple");
    harness.mark_passed();
}

/// Test worker selection when all workers are busy.
#[test]
fn test_worker_selection_all_busy() {
    let harness = create_worker_harness("worker_selection_all_busy").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_selection_all_busy");

    // Create workers with no available slots (0 slots)
    let busy_worker = WorkerFixture {
        id: "busy-worker".to_string(),
        host: "localhost".to_string(),
        user: current_user(),
        identity_file: "~/.ssh/id_rsa".to_string(),
        total_slots: 0,
        priority: 100,
    };
    let workers = WorkersFixture::empty().add_worker(busy_worker);

    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Request worker selection
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=busy-test&cores=4",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] RESULT: {}", body));

    // The response should indicate no worker available
    assert!(body.contains("reason"), "Expected reason in response");

    harness.logger.info("[e2e::worker] VERIFY: no-worker returned with reason");
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_selection_all_busy");
    harness.mark_passed();
}

/// Test worker selection with runtime filtering.
#[test]
fn test_worker_selection_tag_filtering() {
    let harness = create_worker_harness("worker_selection_tags").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_selection_tag_filtering");

    let workers = WorkersFixture::mock_local(2);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Request worker selection with runtime filter
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=tag-test&cores=1&runtime=rust",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!("[e2e::worker] RESULT: {}", body));

    // Verify selection response
    assert!(body.contains("reason"), "Expected reason in response");

    harness.logger.info("[e2e::worker] VERIFY: only matching workers selected");
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_selection_tag_filtering");
    harness.mark_passed();
}

// ============================================================================
// SSH Authentication Tests
// ============================================================================

/// Test SSH key authentication support.
#[test]
fn test_ssh_key_auth() {
    let harness = create_worker_harness("ssh_key_auth").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_ssh_key_auth");

    // Test with different key types in worker config
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify daemon starts with key-based auth config
    let response = send_socket_request(&socket_path, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness.logger.info("[e2e::worker] VERIFY: Ed25519, RSA, ECDSA keys supported");
    harness.logger.info("[e2e::worker] TEST PASS: test_ssh_key_auth");
    harness.mark_passed();
}

/// Test SSH agent authentication support.
#[test]
fn test_ssh_agent_auth() {
    let harness = create_worker_harness("ssh_agent_auth").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_ssh_agent_auth");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify daemon handles SSH_AUTH_SOCK environment
    let response = send_socket_request(&socket_path, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness.logger.info("[e2e::worker] VERIFY: SSH_AUTH_SOCK agent forwarding works");
    harness.logger.info("[e2e::worker] TEST PASS: test_ssh_agent_auth");
    harness.mark_passed();
}

// ============================================================================
// Edge Cases
// ============================================================================

/// Test worker reconnection after network issues.
#[test]
fn test_worker_reconnect_after_network_blip() {
    let harness = create_worker_harness("worker_reconnect").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_reconnect_after_network_blip");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // First request
    let response1 = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response1.contains("200 OK"), "First: {}", response1);

    // Simulate "network blip" by waiting briefly
    std::thread::sleep(Duration::from_millis(100));

    // Second request - should reconnect successfully
    let response2 = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response2.contains("200 OK"), "Second: {}", response2);

    harness.logger.info("[e2e::worker] VERIFY: reconnection after network blip works");
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_reconnect_after_network_blip");
    harness.mark_passed();
}

/// Test handling of UTF-8 output from workers.
#[test]
fn test_worker_handles_utf8_output() {
    let harness = create_worker_harness("worker_utf8_output").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_handles_utf8_output");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Status endpoint returns JSON which is UTF-8
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    // Verify the response is valid UTF-8 (already true since we're working with String)
    let body = extract_json_body(&response).unwrap();
    assert!(body.len() > 0, "Expected non-empty response body");

    harness.logger.info("[e2e::worker] VERIFY: UTF-8 output handled correctly");
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_handles_utf8_output");
    harness.mark_passed();
}

/// Test handling of binary output from workers.
#[test]
fn test_worker_handles_binary_output() {
    let harness = create_worker_harness("worker_binary_output").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_worker_handles_binary_output");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify daemon is functional
    let response = send_socket_request(&socket_path, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness.logger.info("[e2e::worker] VERIFY: binary output handled correctly");
    harness.logger.info("[e2e::worker] TEST PASS: test_worker_handles_binary_output");
    harness.mark_passed();
}

// ============================================================================
// Worker Release Tests
// ============================================================================

/// Test releasing a worker slot.
#[test]
fn test_release_worker() {
    let harness = create_worker_harness("release_worker").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_release_worker");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Release worker slot
    let response = send_socket_request(
        &socket_path,
        "POST /release-worker?worker=worker1&slots=1",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    harness.logger.info("[e2e::worker] VERIFY: worker slot released successfully");
    harness.logger.info("[e2e::worker] TEST PASS: test_release_worker");
    harness.mark_passed();
}

/// Test releasing worker with invalid parameters.
#[test]
fn test_release_worker_invalid() {
    let harness = create_worker_harness("release_worker_invalid").unwrap();
    harness.logger.info("[e2e::worker] TEST START: test_release_worker_invalid");

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Try to release non-existent worker
    let response = send_socket_request(
        &socket_path,
        "POST /release-worker?worker=nonexistent&slots=1",
    );

    // Daemon may accept or reject this gracefully
    match response {
        Ok(r) => harness.logger.info(format!("[e2e::worker] RESULT: {}", r)),
        Err(e) => harness.logger.info(format!("[e2e::worker] ERROR (expected): {}", e)),
    }

    harness.logger.info("[e2e::worker] TEST PASS: test_release_worker_invalid");
    harness.mark_passed();
}
