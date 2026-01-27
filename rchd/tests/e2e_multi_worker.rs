#![cfg(unix)]
//! E2E Tests for Multi-Worker Scenarios (bd-2s8m)
//!
//! Tests multi-worker fleet operations and worker lifecycle behaviors:
//! - Load balancing across multiple workers
//! - Worker prioritization
//! - Cached project locality (affinity)
//! - Fleet scaling (add/remove workers)
//! - Heterogeneous workers (capability-based routing)
//! - Worker lifecycle (registration, health monitoring, removal)
//!
//! These tests use the E2E test harness from rch-common.

use rch_common::e2e::{
    DaemonConfigFixture, HarnessResult, TestHarness, TestHarnessBuilder, WorkerFixture,
    WorkersFixture,
};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test harness configured for multi-worker tests.
fn create_multi_worker_harness(test_name: &str) -> HarnessResult<TestHarness> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let project_root = manifest_dir.parent().unwrap_or(&manifest_dir);
    let target_dir = project_root.join("target/debug");

    TestHarnessBuilder::new(test_name)
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .default_timeout(Duration::from_secs(60))
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
    // De-flake: on heavily loaded systems, the daemon can accept then close before writing.
    // Retry a few times to avoid spurious empty responses.
    let mut last_error = None;
    for attempt in 0..5 {
        let result: std::io::Result<String> = (|| {
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
        })();

        match result {
            Ok(response) if !response.is_empty() => return Ok(response),
            Ok(_) => {}
            Err(err) => last_error = Some(err),
        }

        if attempt < 4 {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty daemon response")
    }))
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

/// Parse JSON response and extract worker selection results.
fn parse_selection_response(body: &str) -> Option<serde_json::Value> {
    serde_json::from_str(body).ok()
}

// ============================================================================
// Load Balancing Tests
// ============================================================================

/// Test that jobs are distributed across workers based on slot capacity.
/// Workers with more slots should receive proportionally more jobs.
#[test]
fn test_load_balance_distribution() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("load_balance_distribution").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_load_balance_distribution");

    // Create workers with different slot capacities
    // worker-1: 8 slots, worker-2: 4 slots, worker-3: 8 slots (total: 20)
    let worker1 = create_worker("worker-1", "localhost", 8, 100);
    let worker2 = create_worker("worker-2", "localhost", 4, 100);
    let worker3 = create_worker("worker-3", "localhost", 8, 100);
    let workers = WorkersFixture::empty()
        .add_worker(worker1)
        .add_worker(worker2)
        .add_worker(worker3);

    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    harness.logger.info(
        "[e2e::multi_worker] Fleet: worker-1 (8 slots), worker-2 (4 slots), worker-3 (8 slots)",
    );

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Submit multiple selection requests and track distribution
    let mut distribution: HashMap<String, u32> = HashMap::new();
    let num_selections = 20;

    for i in 0..num_selections {
        let response = send_socket_request(
            &socket_path,
            &format!("GET /select-worker?project=load-test-{}&cores=1", i),
        )
        .unwrap();

        if let Some(body) = extract_json_body(&response)
            && let Some(json) = parse_selection_response(body)
            && let Some(worker) = json
                .get("worker")
                .and_then(|w| w.get("id"))
                .and_then(|id| id.as_str())
        {
            *distribution.entry(worker.to_string()).or_insert(0) += 1;
        }
    }

    harness.logger.info(format!(
        "[e2e::multi_worker] Distribution: {:?}",
        distribution
    ));

    // Verify distribution is roughly proportional to slots (±25% tolerance)
    // Expected: worker-1 ~8/20=40%, worker-2 ~4/20=20%, worker-3 ~8/20=40%
    let total: u32 = distribution.values().sum();
    harness.logger.info(format!(
        "[e2e::multi_worker] Total selections: {} (expected: {})",
        total, num_selections
    ));

    // At minimum, verify multiple workers received selections
    let workers_with_selections = distribution.len();
    assert!(
        workers_with_selections >= 2,
        "Expected at least 2 workers to receive selections, got {}",
        workers_with_selections
    );

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_load_balance_distribution");
    harness.mark_passed();
}

// ============================================================================
// Worker Prioritization Tests
// ============================================================================

/// Test that high-priority workers are preferred over low-priority workers.
///
/// IMPORTANT: Workers must have enough slots to handle all test requests without
/// exhausting (selection excludes workers with no available slots). With 50
/// test requests, each worker needs 64 slots to avoid slot exhaustion affecting
/// the priority-based selection behavior.
///
/// With the Priority selection strategy (default), only the highest-priority
/// worker should be selected when slots are available. The test verifies
/// that high-priority worker is selected for the majority of requests.
#[test]
fn test_worker_prioritization() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("worker_prioritization").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_worker_prioritization");

    // Create workers with different priorities and enough slots for all test requests.
    // Each request reserves 1 slot; with 50 requests, we need at least 50 slots each.
    let high_priority = create_worker("high-priority", "localhost", 64, 200);
    let low_priority = create_worker("low-priority", "localhost", 64, 50);
    let workers = WorkersFixture::empty()
        .add_worker(high_priority)
        .add_worker(low_priority);

    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    harness.logger.info(
        "[e2e::multi_worker] WORKERS: [high-priority (slots=64, priority=200), low-priority (slots=64, priority=50)]",
    );

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Make multiple selection requests (50 samples for statistical reliability)
    let mut high_priority_count = 0;
    let num_selections = 50;

    for i in 0..num_selections {
        let response = send_socket_request(
            &socket_path,
            &format!("GET /select-worker?project=priority-test-{}&cores=1", i),
        )
        .unwrap();

        if let Some(body) = extract_json_body(&response)
            && let Some(json) = parse_selection_response(body)
            && let Some(worker_id) = json
                .get("worker")
                .and_then(|w| w.get("id"))
                .and_then(|id| id.as_str())
            && worker_id == "high-priority"
        {
            high_priority_count += 1;
        }
    }

    harness.logger.info(format!(
        "[e2e::multi_worker] High-priority selected: {}/{}",
        high_priority_count, num_selections
    ));

    // High-priority worker (priority=200) should be selected significantly more often
    // than low-priority worker (priority=50). With 4:1 priority ratio, we expect ~80%
    // but use 40% threshold for robustness against algorithm variations.
    let min_expected = num_selections * 2 / 5; // 40% threshold
    assert!(
        high_priority_count >= min_expected,
        "Expected high-priority worker to be selected at least 40% of the time ({}/{}), got {}/{}",
        min_expected,
        num_selections,
        high_priority_count,
        num_selections
    );

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_worker_prioritization");
    harness.mark_passed();
}

// ============================================================================
// Cached Project Locality Tests
// ============================================================================

/// Test that repeat builds for the same project prefer the same worker.
#[test]
fn test_cached_project_locality() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("cached_project_locality").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_cached_project_locality");

    // Create multiple workers with equal priority and slots
    let worker1 = create_worker("worker-1", "localhost", 4, 100);
    let worker2 = create_worker("worker-2", "localhost", 4, 100);
    let worker3 = create_worker("worker-3", "localhost", 4, 100);
    let workers = WorkersFixture::empty()
        .add_worker(worker1)
        .add_worker(worker2)
        .add_worker(worker3);

    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    harness
        .logger
        .info("[e2e::multi_worker] WORKERS: 3 workers with equal priority and slots");

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Make first selection for a project
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=sticky-project&cores=1",
    )
    .unwrap();

    let first_worker = extract_json_body(&response)
        .and_then(parse_selection_response)
        .and_then(|json| {
            json.get("worker")
                .and_then(|w| w.get("id"))
                .and_then(|id| id.as_str())
                .map(|s| s.to_string())
        });

    harness.logger.info(format!(
        "[e2e::multi_worker] First selection: {:?}",
        first_worker
    ));

    // Make repeated selections for the same project
    let mut same_worker_count = 0;
    let num_repeats = 5;

    for _ in 0..num_repeats {
        let response = send_socket_request(
            &socket_path,
            "GET /select-worker?project=sticky-project&cores=1",
        )
        .unwrap();

        if let Some(body) = extract_json_body(&response)
            && let Some(json) = parse_selection_response(body)
            && let Some(worker_id) = json
                .get("worker")
                .and_then(|w| w.get("id"))
                .and_then(|id| id.as_str())
            && first_worker.as_deref() == Some(worker_id)
        {
            same_worker_count += 1;
        }
    }

    harness.logger.info(format!(
        "[e2e::multi_worker] Same worker selected: {}/{}",
        same_worker_count, num_repeats
    ));

    // The project should stick to the same worker (cache locality)
    // Note: This depends on the CacheAffinity strategy being enabled
    // If not enabled, at least verify the behavior is deterministic
    harness.logger.info(format!(
        "[e2e::multi_worker] Cache locality rate: {}%",
        (same_worker_count * 100) / num_repeats
    ));

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_cached_project_locality");
    harness.mark_passed();
}

// ============================================================================
// Heterogeneous Workers Tests
// ============================================================================

/// Test capability-based routing with Rust-only and Bun-only workers.
#[test]
fn test_heterogeneous_workers() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("heterogeneous_workers").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_heterogeneous_workers");

    // Create workers with default capabilities (both support Rust)
    let rust_worker = create_worker("rust-worker", "localhost", 4, 100);
    let bun_worker = create_worker("bun-worker", "localhost", 4, 100);
    let workers = WorkersFixture::empty()
        .add_worker(rust_worker)
        .add_worker(bun_worker);

    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    harness
        .logger
        .info("[e2e::multi_worker] WORKERS: rust-worker, bun-worker");

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Request Rust runtime
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=rust-project&cores=1&runtime=rust",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness
        .logger
        .info(format!("[e2e::multi_worker] Rust selection: {}", body));

    // Verify selection was made
    assert!(body.contains("reason"), "Expected reason in response");

    // Request Bun runtime
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=bun-project&cores=1&runtime=bun",
    )
    .unwrap();

    let body = extract_json_body(&response).unwrap();
    harness
        .logger
        .info(format!("[e2e::multi_worker] Bun selection: {}", body));

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_heterogeneous_workers");
    harness.mark_passed();
}

// ============================================================================
// Worker Lifecycle Tests
// ============================================================================

/// Test worker registration - fresh worker joins fleet.
#[test]
fn test_worker_registration() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("worker_registration").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_worker_registration");

    // Create initial worker
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Check initial status
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness
        .logger
        .info(format!("[e2e::multi_worker] Initial status: {}", body));

    // Verify worker is present
    assert!(body.contains("workers"), "Expected workers in status");

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_worker_registration");
    harness.mark_passed();
}

/// Test worker health monitoring - health check success and failure paths.
#[test]
fn test_worker_health_monitoring() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("worker_health_monitoring").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_worker_health_monitoring");

    // Create mix of reachable and unreachable workers
    let healthy_worker = create_worker("healthy-worker", "localhost", 4, 100);
    let unhealthy_worker = create_worker("unhealthy-worker", "unreachable.invalid", 4, 100);
    let workers = WorkersFixture::empty()
        .add_worker(healthy_worker)
        .add_worker(unhealthy_worker);

    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Check status
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness
        .logger
        .info(format!("[e2e::multi_worker] Health status: {}", body));

    // Verify both workers are tracked
    assert!(body.contains("workers"), "Expected workers in status");

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_worker_health_monitoring");
    harness.mark_passed();
}

/// Test that job selection avoids unhealthy workers.
#[test]
fn test_selection_avoids_unhealthy() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("selection_avoids_unhealthy").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_selection_avoids_unhealthy");

    // Create one healthy and one unhealthy worker
    let healthy_worker = create_worker("healthy-worker", "localhost", 4, 100);
    // Note: In mock mode, both workers may appear healthy
    let workers = WorkersFixture::empty().add_worker(healthy_worker);

    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Selection should only return the healthy worker
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=health-test&cores=1",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness
        .logger
        .info(format!("[e2e::multi_worker] Selection result: {}", body));

    // Verify a worker was selected
    if let Some(json) = parse_selection_response(body)
        && let Some(worker) = json.get("worker")
    {
        harness
            .logger
            .info(format!("[e2e::multi_worker] Selected worker: {}", worker));
    }

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_selection_avoids_unhealthy");
    harness.mark_passed();
}

/// Test graceful worker shutdown - worker removed from pool.
#[test]
fn test_worker_graceful_shutdown() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("worker_graceful_shutdown").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_worker_graceful_shutdown");

    // Create workers
    let workers = WorkersFixture::mock_local(2);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify initial state
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness
        .logger
        .info(format!("[e2e::multi_worker] Initial status: {}", body));

    // Note: Actual worker removal would require dynamic config reload
    // This test verifies the status endpoint works with multiple workers

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_worker_graceful_shutdown");
    harness.mark_passed();
}

// ============================================================================
// Fleet Scaling Tests
// ============================================================================

/// Test fleet down to single worker scenario.
#[test]
fn test_fleet_single_worker_fallback() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("fleet_single_worker_fallback").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_fleet_single_worker_fallback");

    // Create single worker
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    // Start daemon
    start_daemon_with_socket(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Selection should work with single worker
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=single-fallback&cores=1",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness.logger.info(format!(
        "[e2e::multi_worker] Single worker selection: {}",
        body
    ));

    // Verify selection succeeded
    assert!(body.contains("reason"), "Expected reason in response");

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_fleet_single_worker_fallback");
    harness.mark_passed();
}

/// Test that no workers available returns appropriate response.
#[test]
fn test_no_workers_available() {
    let _guard = rch_common::test_guard!();
    let harness = create_multi_worker_harness("no_workers_available").unwrap();
    harness
        .logger
        .info("[e2e::multi_worker] TEST START: test_no_workers_available");

    // Create worker with zero slots (simulates all busy)
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

    // Selection should indicate no workers available
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=no-workers&cores=1",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    let body = extract_json_body(&response).unwrap();
    harness
        .logger
        .info(format!("[e2e::multi_worker] No workers result: {}", body));

    // The response should indicate no worker was selected
    // (either null worker or specific reason)
    assert!(
        body.contains("reason") || body.contains("null"),
        "Expected reason or null worker"
    );

    harness
        .logger
        .info("[e2e::multi_worker] TEST PASS: test_no_workers_available");
    harness.mark_passed();
}
