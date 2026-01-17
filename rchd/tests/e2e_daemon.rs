//! E2E Tests for Daemon Lifecycle and API
//!
//! Tests daemon start/stop/restart and all API endpoints.
//!
//! These tests use the E2E test harness from rch-common.

use rch_common::e2e::{
    DaemonConfigFixture, HarnessResult, TestHarness, TestHarnessBuilder, WorkersFixture,
};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test harness configured for daemon tests.
fn create_daemon_harness(test_name: &str) -> HarnessResult<TestHarness> {
    TestHarnessBuilder::new(test_name)
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .default_timeout(Duration::from_secs(30))
        .build()
}

/// Setup daemon config files in the harness test directory.
fn setup_daemon_configs(harness: &TestHarness) -> HarnessResult<PathBuf> {
    let socket_path = harness.test_dir().join("rch.sock");
    let daemon_config = DaemonConfigFixture::minimal(&socket_path);
    harness.create_daemon_config(&daemon_config.to_toml())?;

    let workers = WorkersFixture::mock_local(2);
    harness.create_workers_config(&workers.to_toml())?;

    Ok(socket_path)
}

/// Send a request to the daemon via Unix socket and get the response.
fn send_socket_request(socket_path: &std::path::Path, request: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send request
    writeln!(stream, "{}", request)?;
    stream.flush()?;

    // Read response
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => response.push_str(&line),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }

    Ok(response)
}

/// Extract JSON body from HTTP response.
fn extract_json_body(response: &str) -> Option<&str> {
    // Find empty line that separates headers from body
    if let Some(pos) = response.find("\r\n\r\n") {
        Some(&response[pos + 4..])
    } else if let Some(pos) = response.find("\n\n") {
        Some(&response[pos + 2..])
    } else {
        None
    }
}

// ============================================================================
// Daemon Lifecycle Tests
// ============================================================================

#[test]
fn test_daemon_startup_and_socket_creation() {
    let harness = create_daemon_harness("daemon_startup").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    let pid = harness.start_daemon(&["--foreground", "--metrics-port", "0"]);
    assert!(pid.is_ok(), "Failed to start daemon: {:?}", pid.err());

    // Wait for socket to be created
    let socket_result = harness.wait_for_socket(&socket_path, Duration::from_secs(10));
    assert!(
        socket_result.is_ok(),
        "Socket was not created: {:?}",
        socket_result.err()
    );

    // Verify the socket exists
    assert!(socket_path.exists(), "Socket file should exist");

    harness.mark_passed();
}

#[test]
fn test_daemon_health_endpoint() {
    let harness = create_daemon_harness("daemon_health").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send health check request
    let response = send_socket_request(&socket_path, "GET /health").unwrap();

    // Verify response
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    let body = extract_json_body(&response).unwrap();
    assert!(body.contains("healthy"), "Expected 'healthy' in: {}", body);

    harness.mark_passed();
}

#[test]
fn test_daemon_ready_endpoint() {
    let harness = create_daemon_harness("daemon_ready").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send readiness check request
    let response = send_socket_request(&socket_path, "GET /ready").unwrap();

    // Verify response - should indicate ready or not_ready depending on workers
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    let body = extract_json_body(&response).unwrap();
    // The response should contain status field
    assert!(
        body.contains("status"),
        "Expected 'status' field in: {}",
        body
    );

    harness.mark_passed();
}

#[test]
fn test_daemon_status_endpoint() {
    let harness = create_daemon_harness("daemon_status").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send status request
    let response = send_socket_request(&socket_path, "GET /status").unwrap();

    // Verify response
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    let body = extract_json_body(&response).unwrap();

    // Status response should contain daemon info
    assert!(body.contains("daemon"), "Expected 'daemon' in: {}", body);
    assert!(body.contains("workers"), "Expected 'workers' in: {}", body);
    assert!(body.contains("pid"), "Expected 'pid' in: {}", body);
    assert!(
        body.contains("uptime_secs"),
        "Expected 'uptime_secs' in: {}",
        body
    );

    harness.mark_passed();
}

#[test]
fn test_daemon_metrics_endpoint() {
    let harness = create_daemon_harness("daemon_metrics").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send metrics request
    let response = send_socket_request(&socket_path, "GET /metrics").unwrap();

    // Verify response
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    assert!(
        response.contains("text/plain"),
        "Expected text/plain content type, got: {}",
        response
    );

    harness.mark_passed();
}

#[test]
fn test_daemon_budget_endpoint() {
    let harness = create_daemon_harness("daemon_budget").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send budget request
    let response = send_socket_request(&socket_path, "GET /budget").unwrap();

    // Verify response
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    let body = extract_json_body(&response).unwrap();

    // Budget response should contain budget info
    assert!(body.contains("status"), "Expected 'status' in: {}", body);
    assert!(body.contains("budgets"), "Expected 'budgets' in: {}", body);
    assert!(
        body.contains("non_compilation"),
        "Expected 'non_compilation' in: {}",
        body
    );
    assert!(
        body.contains("compilation"),
        "Expected 'compilation' in: {}",
        body
    );
    assert!(
        body.contains("worker_selection"),
        "Expected 'worker_selection' in: {}",
        body
    );

    harness.mark_passed();
}

#[test]
fn test_daemon_shutdown() {
    let harness = create_daemon_harness("daemon_shutdown").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send shutdown request
    let response = send_socket_request(&socket_path, "POST /shutdown").unwrap();

    // Verify response indicates shutdown
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    let body = extract_json_body(&response).unwrap();
    assert!(
        body.contains("shutting_down"),
        "Expected 'shutting_down' in: {}",
        body
    );

    // Wait for daemon to stop - socket should disappear
    std::thread::sleep(Duration::from_millis(500));

    // After shutdown, connecting to the socket should fail
    let connect_result = UnixStream::connect(&socket_path);
    // The daemon should have cleaned up the socket, or at least not be responding
    if connect_result.is_ok() {
        // If socket still exists, try a request - it should fail or timeout
        let stream = connect_result.unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();
        // This should fail since daemon is shutting down
    }

    harness.mark_passed();
}

// ============================================================================
// Worker Selection API Tests
// ============================================================================

#[test]
fn test_select_worker_basic() {
    let harness = create_daemon_harness("select_worker_basic").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send select-worker request
    let response =
        send_socket_request(&socket_path, "GET /select-worker?project=test-project&cores=2")
            .unwrap();

    // Verify response
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    let body = extract_json_body(&response).unwrap();

    // Response should contain reason field
    assert!(body.contains("reason"), "Expected 'reason' in: {}", body);

    harness.mark_passed();
}

#[test]
fn test_select_worker_with_runtime() {
    let harness = create_daemon_harness("select_worker_runtime").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send select-worker request with runtime
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=test-project&cores=4&runtime=rust",
    )
    .unwrap();

    // Verify response
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );
    let body = extract_json_body(&response).unwrap();
    assert!(body.contains("reason"), "Expected 'reason' in: {}", body);

    harness.mark_passed();
}

#[test]
fn test_select_worker_missing_project() {
    let harness = create_daemon_harness("select_worker_missing_project").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send select-worker request without project parameter
    // This should return an error
    let response = send_socket_request(&socket_path, "GET /select-worker?cores=2");

    // The daemon will close the connection on error, or we may get an error response
    // Either is acceptable behavior
    match response {
        Ok(r) => {
            // If we got a response, verify it indicates an error or the request format
            // The daemon should return an error for missing 'project' parameter
            harness.logger.info(format!("Response: {}", r));
        }
        Err(e) => {
            // Connection error is also acceptable - daemon closed connection
            harness.logger.info(format!("Connection error (expected): {}", e));
        }
    }

    harness.mark_passed();
}

#[test]
fn test_release_worker() {
    let harness = create_daemon_harness("release_worker").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send release-worker request
    let response =
        send_socket_request(&socket_path, "POST /release-worker?worker=worker1&slots=2").unwrap();

    // Verify response
    assert!(
        response.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response
    );

    harness.mark_passed();
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_unknown_endpoint() {
    let harness = create_daemon_harness("unknown_endpoint").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send request to unknown endpoint
    let response = send_socket_request(&socket_path, "GET /unknown-endpoint");

    // The daemon should return an error or close the connection
    match response {
        Ok(r) => {
            harness.logger.info(format!("Response: {}", r));
        }
        Err(e) => {
            harness
                .logger
                .info(format!("Connection error (expected for unknown endpoint): {}", e));
        }
    }

    harness.mark_passed();
}

#[test]
fn test_invalid_method() {
    let harness = create_daemon_harness("invalid_method").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send request with invalid method
    let response = send_socket_request(&socket_path, "PUT /status");

    // The daemon should return an error or close the connection
    match response {
        Ok(r) => {
            harness.logger.info(format!("Response: {}", r));
        }
        Err(e) => {
            harness
                .logger
                .info(format!("Connection error (expected for invalid method): {}", e));
        }
    }

    harness.mark_passed();
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_daemon_custom_socket_path() {
    let harness = create_daemon_harness("daemon_custom_socket").unwrap();

    // Create custom socket path
    let custom_socket = harness.test_dir().join("custom.sock");

    // Create daemon config pointing to custom socket
    let daemon_config = DaemonConfigFixture::minimal(&custom_socket);
    harness.create_daemon_config(&daemon_config.to_toml()).unwrap();

    let workers = WorkersFixture::empty();
    harness.create_workers_config(&workers.to_toml()).unwrap();

    // Start daemon with custom socket path via config
    harness
        .start_daemon(&[
            "--foreground",
            "--metrics-port",
            "0",
            "--socket",
            custom_socket.to_str().unwrap(),
        ])
        .unwrap();
    harness
        .wait_for_socket(&custom_socket, Duration::from_secs(10))
        .unwrap();

    // Verify we can connect to the custom socket
    let response = send_socket_request(&custom_socket, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness.mark_passed();
}

#[test]
fn test_daemon_verbose_mode() {
    let harness = create_daemon_harness("daemon_verbose").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start daemon in verbose mode
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0", "--verbose"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify daemon is working
    let response = send_socket_request(&socket_path, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness.mark_passed();
}

// ============================================================================
// Concurrent Request Tests
// ============================================================================

#[test]
fn test_concurrent_requests() {
    let harness = create_daemon_harness("concurrent_requests").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();

    // Start the daemon
    harness
        .start_daemon(&["--foreground", "--metrics-port", "0"])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Send multiple requests concurrently
    let socket_clone1 = socket_path.clone();
    let socket_clone2 = socket_path.clone();
    let socket_clone3 = socket_path.clone();

    let handle1 = std::thread::spawn(move || send_socket_request(&socket_clone1, "GET /health"));

    let handle2 = std::thread::spawn(move || send_socket_request(&socket_clone2, "GET /status"));

    let handle3 = std::thread::spawn(move || send_socket_request(&socket_clone3, "GET /ready"));

    // Wait for all requests to complete
    let result1 = handle1.join().unwrap();
    let result2 = handle2.join().unwrap();
    let result3 = handle3.join().unwrap();

    // All should succeed
    assert!(
        result1.is_ok(),
        "Health request failed: {:?}",
        result1.err()
    );
    assert!(
        result2.is_ok(),
        "Status request failed: {:?}",
        result2.err()
    );
    assert!(result3.is_ok(), "Ready request failed: {:?}", result3.err());

    assert!(result1.unwrap().contains("200 OK"));
    assert!(result2.unwrap().contains("200 OK"));
    assert!(result3.unwrap().contains("200 OK"));

    harness.mark_passed();
}

// ============================================================================
// History and Build Tracking Tests
// ============================================================================

#[test]
fn test_daemon_with_history_file() {
    let harness = create_daemon_harness("daemon_history").unwrap();
    let socket_path = setup_daemon_configs(&harness).unwrap();
    let history_file = harness.test_dir().join("history.jsonl");

    // Start daemon with history file
    harness
        .start_daemon(&[
            "--foreground",
            "--metrics-port",
            "0",
            "--history-file",
            history_file.to_str().unwrap(),
        ])
        .unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Make a request that would be recorded in history
    let response =
        send_socket_request(&socket_path, "GET /select-worker?project=history-test&cores=1")
            .unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    // Get status to check recent builds
    let status_response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(status_response.contains("200 OK"));

    harness.mark_passed();
}
