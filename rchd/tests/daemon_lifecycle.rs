//! E2E Tests for Daemon Lifecycle and API
//!
//! Tests the daemon's lifecycle management including:
//! - Startup with custom socket path
//! - Health and readiness endpoints
//! - Status endpoint
//! - Graceful shutdown via /shutdown endpoint
//!
//! These tests use the rch-common e2e test infrastructure.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rch_common::e2e::{
    fixtures::DaemonConfigFixture,
    harness::{HarnessResult, TestHarnessBuilder},
};

/// Get the absolute path to the project root directory
fn project_root() -> PathBuf {
    // The test runs from the crate directory, so we need to go up to workspace root
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().unwrap().to_path_buf()
}

/// Get the path to the rchd binary
fn rchd_binary_path() -> PathBuf {
    let root = project_root();
    root.join("target").join("debug").join("rchd")
}

/// Send a request to the daemon via Unix socket and get the response body
fn send_request(socket_path: &Path, request: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send request
    writeln!(stream, "{}", request)?;
    stream.flush()?;

    // Read response
    let reader = BufReader::new(&stream);
    let mut response = String::new();
    let mut in_body = false;

    for line in reader.lines() {
        let line = line?;
        if in_body {
            response.push_str(&line);
            response.push('\n');
        } else if line.is_empty() {
            // Empty line marks end of headers
            in_body = true;
        }
    }

    Ok(response.trim().to_string())
}

/// Parse JSON response and extract a field
fn get_json_field(json: &str, field: &str) -> Option<String> {
    // Simple JSON field extraction without full parsing
    let pattern = format!("\"{}\":", field);
    if let Some(start) = json.find(&pattern) {
        let rest = &json[start + pattern.len()..];
        let rest = rest.trim_start();

        if let Some(rest) = rest.strip_prefix('"') {
            // String value
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        } else {
            // Non-string value (number, boolean, etc.)
            let end = rest.find([',', '}', ']']).unwrap_or(rest.len());
            return Some(rest[..end].trim().to_string());
        }
    }
    None
}

#[test]
fn test_daemon_startup_creates_socket() -> HarnessResult<()> {
    let harness = TestHarnessBuilder::new("daemon_startup_socket")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create minimal workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path in test directory
    let socket_path = harness.test_dir().join("rchd.sock");

    // Start daemon with custom socket
    let socket_arg = socket_path.to_string_lossy().to_string();
    let pid = harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    harness.logger.info(format!("Daemon started with PID: {}", pid));

    // Wait for socket to be created
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    harness.assert(socket_path.exists(), "Socket file should exist")?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_health_endpoint() -> HarnessResult<()> {
    let harness = TestHarnessBuilder::new("daemon_health")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create minimal workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send health check request
    let response = send_request(&socket_path, "GET /health").map_err(|e| {
        rch_common::e2e::harness::HarnessError::Io(e)
    })?;

    harness.logger.info(format!("Health response: {}", response));

    // Verify health response contains expected fields
    let status = get_json_field(&response, "status");
    harness.assert(
        status == Some("healthy".to_string()),
        &format!("Health status should be 'healthy', got: {:?}", status),
    )?;

    let version = get_json_field(&response, "version");
    harness.assert(version.is_some(), "Health response should include version")?;

    let uptime = get_json_field(&response, "uptime_seconds");
    harness.assert(uptime.is_some(), "Health response should include uptime_seconds")?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_ready_endpoint() -> HarnessResult<()> {
    let harness = TestHarnessBuilder::new("daemon_ready")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send ready check request
    let response = send_request(&socket_path, "GET /ready").map_err(|e| {
        rch_common::e2e::harness::HarnessError::Io(e)
    })?;

    harness.logger.info(format!("Ready response: {}", response));

    // Verify ready response structure
    let status = get_json_field(&response, "status");
    harness.assert(
        status.is_some(),
        "Ready response should include status field",
    )?;

    let workers_available = get_json_field(&response, "workers_available");
    harness.assert(
        workers_available.is_some(),
        "Ready response should include workers_available field",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_status_endpoint() -> HarnessResult<()> {
    let harness = TestHarnessBuilder::new("daemon_status")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker-1"
host = "localhost"
user = "test"
total_slots = 4

[[workers]]
id = "test-worker-2"
host = "remote.example.com"
user = "builder"
total_slots = 8
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send status request
    let response = send_request(&socket_path, "GET /status").map_err(|e| {
        rch_common::e2e::harness::HarnessError::Io(e)
    })?;

    harness.logger.info(format!("Status response: {}", response));

    // Verify status response contains daemon info
    harness.assert(
        response.contains("\"daemon\""),
        "Status should contain daemon section",
    )?;
    harness.assert(
        response.contains("\"workers\""),
        "Status should contain workers section",
    )?;
    harness.assert(
        response.contains("\"pid\""),
        "Status should contain daemon PID",
    )?;
    harness.assert(
        response.contains("\"version\""),
        "Status should contain daemon version",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_budget_endpoint() -> HarnessResult<()> {
    let harness = TestHarnessBuilder::new("daemon_budget")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send budget request
    let response = send_request(&socket_path, "GET /budget").map_err(|e| {
        rch_common::e2e::harness::HarnessError::Io(e)
    })?;

    harness.logger.info(format!("Budget response: {}", response));

    // Budget endpoint should return a valid JSON response
    harness.assert(
        response.starts_with('{') && response.ends_with('}'),
        "Budget response should be valid JSON object",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_graceful_shutdown() -> HarnessResult<()> {
    let harness = TestHarnessBuilder::new("daemon_shutdown")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Verify daemon is healthy first
    let health_response = send_request(&socket_path, "GET /health").map_err(|e| {
        rch_common::e2e::harness::HarnessError::Io(e)
    })?;
    harness.assert(
        health_response.contains("healthy"),
        "Daemon should be healthy before shutdown",
    )?;

    // Send shutdown request
    let shutdown_response = send_request(&socket_path, "POST /shutdown").map_err(|e| {
        rch_common::e2e::harness::HarnessError::Io(e)
    })?;

    harness.logger.info(format!("Shutdown response: {}", shutdown_response));

    // Verify shutdown response
    harness.assert(
        shutdown_response.contains("shutting_down"),
        "Shutdown response should indicate shutting_down status",
    )?;

    // Wait a bit for the daemon to shut down
    std::thread::sleep(Duration::from_millis(500));

    // Socket should eventually become unavailable
    // Try to connect - it should fail after shutdown
    harness.wait_for(
        "daemon to shut down",
        Duration::from_secs(5),
        Duration::from_millis(200),
        || {
            // Try to send a request - if it fails, daemon has shut down
            send_request(&socket_path, "GET /health").is_err()
        },
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_metrics_endpoint() -> HarnessResult<()> {
    let harness = TestHarnessBuilder::new("daemon_metrics")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send metrics request
    let response = send_request(&socket_path, "GET /metrics").map_err(|e| {
        rch_common::e2e::harness::HarnessError::Io(e)
    })?;

    harness.logger.info(format!("Metrics response (first 500 chars): {}", &response[..response.len().min(500)]));

    // Metrics should be in Prometheus format (text/plain)
    // Should contain standard metric comments or metric lines
    harness.assert(
        !response.is_empty(),
        "Metrics response should not be empty",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_unknown_endpoint_error() -> HarnessResult<()> {
    let harness = TestHarnessBuilder::new("daemon_unknown_endpoint")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send request to unknown endpoint - this may cause connection to close with error
    let result = send_request(&socket_path, "GET /nonexistent");

    // Either an error response or connection drop is acceptable
    harness.logger.info(format!("Unknown endpoint result: {:?}", result));

    // The test passes as long as the daemon doesn't crash
    // Send a follow-up health check to verify daemon is still running
    let health_result = send_request(&socket_path, "GET /health");
    harness.assert(
        health_result.is_ok(),
        "Daemon should still be running after unknown endpoint request",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_config_fixture_integration() -> HarnessResult<()> {
    use rch_common::e2e::fixtures::{WorkerFixture, WorkersFixture};

    let harness = TestHarnessBuilder::new("daemon_config_fixture")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Use fixtures to generate config
    let socket_path = harness.test_dir().join("rchd.sock");
    let _daemon_config = DaemonConfigFixture::minimal(&socket_path);

    // Create workers using WorkersFixture
    let fixture_worker = WorkerFixture {
        id: "fixture-worker".to_string(),
        host: "fixture-host".to_string(),
        user: "builder".to_string(),
        identity_file: "~/.ssh/id_rsa".to_string(),
        total_slots: 8,
        priority: 100,
    };
    let workers_fixture = WorkersFixture::empty().add_worker(fixture_worker);

    // Write the workers config using fixture
    let workers_toml = workers_fixture.to_toml();
    harness.create_workers_config(&workers_toml)?;

    // Start daemon with socket from fixture config
    let socket_arg = socket_path.to_string_lossy().to_string();

    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Verify daemon is running with our fixture config
    let status = send_request(&socket_path, "GET /status").map_err(|e| {
        rch_common::e2e::harness::HarnessError::Io(e)
    })?;

    harness.assert(
        status.contains("fixture-worker"),
        "Status should contain the fixture worker ID",
    )?;

    harness.mark_passed();
    Ok(())
}
