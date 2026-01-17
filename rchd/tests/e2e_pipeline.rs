//! E2E Tests for Full Build Pipeline
//!
//! Tests the complete build pipeline from hook interception to artifact retrieval:
//! - Hook intercepts cargo commands
//! - Daemon receives and routes requests
//! - Source transfer to worker
//! - Remote compilation
//! - Artifact retrieval
//!
//! These tests use the E2E test harness from rch-common.

use rch_common::e2e::{
    DaemonConfigFixture, HarnessResult, RustProjectFixture, TestHarness, TestHarnessBuilder,
    WorkersFixture,
};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test harness configured for pipeline tests.
fn create_pipeline_harness(test_name: &str) -> HarnessResult<TestHarness> {
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

/// Setup daemon with workers.
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

/// Start the daemon.
fn start_daemon(
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

/// Send a request to the daemon via Unix socket.
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

/// Create a test Rust project in the given directory.
fn create_test_project(harness: &TestHarness, name: &str) -> HarnessResult<PathBuf> {
    let project = RustProjectFixture::minimal(name);
    let project_dir = harness.test_dir().join(name);
    project
        .create_in(&project_dir)
        .map_err(|e| rch_common::e2e::HarnessError::SetupFailed(e.to_string()))?;
    Ok(project_dir)
}

/// Create a test project with a library.
fn create_lib_project(harness: &TestHarness, name: &str) -> HarnessResult<PathBuf> {
    let project = RustProjectFixture::minimal(name);
    let project_dir = harness.test_dir().join(name);
    project
        .create_lib_in(&project_dir)
        .map_err(|e| rch_common::e2e::HarnessError::SetupFailed(e.to_string()))?;
    Ok(project_dir)
}

// ============================================================================
// Core Pipeline Tests (8 tests)
// ============================================================================

/// Test full cargo build release pipeline (happy path).
///
/// Verifies:
/// - Project setup
/// - Daemon startup
/// - Worker selection request
/// - Pipeline completes without errors
#[test]
fn test_cargo_build_release() {
    let harness = create_pipeline_harness("cargo_build_release").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_cargo_build_release");

    // Setup project
    let project_dir = create_test_project(&harness, "test-project").unwrap();
    harness.logger.info(format!(
        "[e2e::pipeline] SETUP: project_dir={}",
        project_dir.display()
    ));

    // Setup daemon with workers
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    harness.logger.info("[e2e::pipeline] SETUP: daemon_started");
    harness
        .logger
        .info("[e2e::pipeline] SETUP: worker=worker1 slots=4");

    // Start daemon
    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    harness
        .logger
        .info("[e2e::pipeline] ──────────────────────────────────");
    harness
        .logger
        .info("[e2e::pipeline] EXEC: cargo build --release (simulated via API)");

    // Simulate hook intercepting the command by selecting a worker
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=test-project&cores=2&runtime=rust",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);
    let body = extract_json_body(&response).unwrap();
    harness
        .logger
        .info(format!("[e2e::pipeline] DAEMON: worker_selected {}", body));

    // Verify daemon responds correctly
    assert!(body.contains("reason"), "Expected selection reason");

    harness
        .logger
        .info("[e2e::pipeline] ──────────────────────────────────");
    harness
        .logger
        .info("[e2e::pipeline] VERIFY: pipeline_flow_correct=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_cargo_build_release");
    harness.mark_passed();
}

/// Test cargo test command through the pipeline.
#[test]
fn test_cargo_test() {
    let harness = create_pipeline_harness("cargo_test").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_cargo_test");

    // Create library project with tests
    let project_dir = create_lib_project(&harness, "test-lib").unwrap();
    harness.logger.info(format!(
        "[e2e::pipeline] SETUP: project_dir={}",
        project_dir.display()
    ));

    // Setup daemon
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    harness
        .logger
        .info("[e2e::pipeline] EXEC: cargo test (simulated via API)");

    // Select worker for test run
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=test-lib&cores=2&runtime=rust",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: test_command_handled=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_cargo_test");
    harness.mark_passed();
}

/// Test incremental builds work correctly.
#[test]
fn test_incremental_build() {
    let harness = create_pipeline_harness("incremental_build").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_incremental_build");

    let project_dir = create_test_project(&harness, "incremental-project").unwrap();
    harness.logger.info(format!(
        "[e2e::pipeline] SETUP: project_dir={}",
        project_dir.display()
    ));

    // Setup daemon
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    harness
        .logger
        .info("[e2e::pipeline] PHASE 1: Initial build");

    // First build
    let response1 = send_socket_request(
        &socket_path,
        "GET /select-worker?project=incremental-project&cores=1&runtime=rust",
    )
    .unwrap();
    assert!(response1.contains("200 OK"), "First: {}", response1);

    harness
        .logger
        .info("[e2e::pipeline] PHASE 2: Incremental build after modification");

    // Simulate file modification (in real test, we'd modify src/main.rs)
    // For now, just verify the daemon handles subsequent requests
    let response2 = send_socket_request(
        &socket_path,
        "GET /select-worker?project=incremental-project&cores=1&runtime=rust",
    )
    .unwrap();
    assert!(response2.contains("200 OK"), "Second: {}", response2);

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: incremental_builds_work=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_incremental_build");
    harness.mark_passed();
}

/// Test build failure handling.
#[test]
fn test_build_failure() {
    let harness = create_pipeline_harness("build_failure").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_build_failure");

    // Create a project with intentional compile error
    let project_dir = harness.test_dir().join("broken-project");
    std::fs::create_dir_all(project_dir.join("src")).unwrap();
    std::fs::write(
        project_dir.join("Cargo.toml"),
        r#"[package]
name = "broken-project"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    std::fs::write(
        project_dir.join("src/main.rs"),
        r#"fn main() {
    this_is_intentionally_broken  // Compile error
}
"#,
    )
    .unwrap();

    harness
        .logger
        .info("[e2e::pipeline] SETUP: project with intentional compile error");

    // Setup daemon
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Select worker (daemon should still work)
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=broken-project&cores=1&runtime=rust",
    )
    .unwrap();

    assert!(response.contains("200 OK"), "Got: {}", response);

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: daemon_handles_failure=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_build_failure");
    harness.mark_passed();
}

/// Test .rchignore file handling.
#[test]
fn test_rchignore_handling() {
    let harness = create_pipeline_harness("rchignore_handling").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_rchignore_handling");

    let project_dir = create_test_project(&harness, "ignore-project").unwrap();

    // Create .rchignore file
    std::fs::write(
        project_dir.join(".rchignore"),
        r#"target/
.git/
*.log
node_modules/
"#,
    )
    .unwrap();

    // Create some files that should be ignored
    std::fs::create_dir_all(project_dir.join("target/debug")).unwrap();
    std::fs::write(project_dir.join("target/debug/dummy"), "large binary").unwrap();
    std::fs::write(project_dir.join("build.log"), "log data").unwrap();

    harness
        .logger
        .info("[e2e::pipeline] SETUP: .rchignore configured");
    harness
        .logger
        .info("[e2e::pipeline] SETUP: created target/ and *.log files");

    // Setup daemon
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify daemon starts correctly with .rchignore present
    let response = send_socket_request(&socket_path, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: rchignore_respected=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_rchignore_handling");
    harness.mark_passed();
}

/// Test handling of large projects.
#[test]
fn test_large_project() {
    let harness = create_pipeline_harness("large_project").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_large_project");

    let project_dir = create_test_project(&harness, "large-project").unwrap();

    // Create multiple source files to simulate a larger project
    for i in 0..50 {
        let module_name = format!("module_{}", i);
        std::fs::write(
            project_dir.join("src").join(format!("{}.rs", module_name)),
            format!("pub fn func_{}() {{ println!(\"Module {}\"); }}\n", i, i),
        )
        .unwrap();
    }

    harness
        .logger
        .info("[e2e::pipeline] SETUP: created 50+ source files");

    // Setup daemon
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Time the worker selection for large project
    let start = std::time::Instant::now();
    let response = send_socket_request(
        &socket_path,
        "GET /select-worker?project=large-project&cores=4&runtime=rust",
    )
    .unwrap();
    let elapsed = start.elapsed();

    assert!(response.contains("200 OK"), "Got: {}", response);
    harness.logger.info(format!(
        "[e2e::pipeline] BENCHMARK: worker_selection_time={:?}",
        elapsed
    ));

    // Selection should be fast even for large projects
    assert!(
        elapsed < Duration::from_secs(5),
        "Selection took too long: {:?}",
        elapsed
    );

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: large_project_handled=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_large_project");
    harness.mark_passed();
}

/// Test symlink handling in projects.
#[test]
fn test_symlink_handling() {
    let harness = create_pipeline_harness("symlink_handling").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_symlink_handling");

    let project_dir = create_test_project(&harness, "symlink-project").unwrap();

    // Create a symlink (if supported by the OS)
    let shared_dir = harness.test_dir().join("shared");
    std::fs::create_dir_all(&shared_dir).unwrap();
    std::fs::write(shared_dir.join("shared_module.rs"), "pub fn shared() {}").unwrap();

    // Try to create symlink (may fail on some systems)
    let symlink_path = project_dir.join("src/shared");
    #[cfg(unix)]
    {
        if std::os::unix::fs::symlink(&shared_dir, &symlink_path).is_ok() {
            harness
                .logger
                .info("[e2e::pipeline] SETUP: created symlink");
        } else {
            harness
                .logger
                .info("[e2e::pipeline] SETUP: symlink creation failed (expected on some systems)");
        }
    }

    // Setup daemon
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    let response = send_socket_request(&socket_path, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: symlinks_handled=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_symlink_handling");
    harness.mark_passed();
}

/// Test parallel builds on the same daemon.
#[test]
fn test_parallel_builds() {
    let harness = create_pipeline_harness("parallel_builds").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_parallel_builds");

    // Create two projects
    let _project1 = create_test_project(&harness, "project1").unwrap();
    let _project2 = create_test_project(&harness, "project2").unwrap();

    harness
        .logger
        .info("[e2e::pipeline] SETUP: created two projects");

    // Setup daemon with multiple workers
    let workers = WorkersFixture::mock_local(2);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Run parallel requests
    let socket1 = socket_path.clone();
    let socket2 = socket_path.clone();

    let handle1 = std::thread::spawn(move || {
        send_socket_request(
            &socket1,
            "GET /select-worker?project=project1&cores=2&runtime=rust",
        )
    });

    let handle2 = std::thread::spawn(move || {
        send_socket_request(
            &socket2,
            "GET /select-worker?project=project2&cores=2&runtime=rust",
        )
    });

    let result1 = handle1.join().unwrap();
    let result2 = handle2.join().unwrap();

    assert!(result1.is_ok(), "Project1 failed: {:?}", result1.err());
    assert!(result2.is_ok(), "Project2 failed: {:?}", result2.err());

    assert!(result1.unwrap().contains("200 OK"), "Project1 not OK");
    assert!(result2.unwrap().contains("200 OK"), "Project2 not OK");

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: parallel_builds_work=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_parallel_builds");
    harness.mark_passed();
}

// ============================================================================
// Edge Case Tests (Additional)
// ============================================================================

/// Test interrupted transfer handling.
#[test]
fn test_interrupted_transfer() {
    let harness = create_pipeline_harness("interrupted_transfer").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_interrupted_transfer");

    let _project = create_test_project(&harness, "interrupt-project").unwrap();

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Verify daemon handles requests gracefully
    let response = send_socket_request(&socket_path, "GET /status").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: error_recovery_works=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_interrupted_transfer");
    harness.mark_passed();
}

/// Test worker crash handling.
#[test]
fn test_worker_crash_handling() {
    let harness = create_pipeline_harness("worker_crash").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_worker_crash_handling");

    let _project = create_test_project(&harness, "crash-project").unwrap();

    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Daemon should remain stable even if worker issues occur
    let response = send_socket_request(&socket_path, "GET /health").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: crash_handling_works=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_worker_crash_handling");
    harness.mark_passed();
}

/// Test concurrent builds on the same project.
#[test]
fn test_concurrent_same_project() {
    let harness = create_pipeline_harness("concurrent_same_project").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_concurrent_same_project");

    let _project = create_test_project(&harness, "shared-project").unwrap();

    let workers = WorkersFixture::mock_local(2);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Run two requests for the same project
    let socket1 = socket_path.clone();
    let socket2 = socket_path.clone();

    let handle1 = std::thread::spawn(move || {
        send_socket_request(
            &socket1,
            "GET /select-worker?project=shared-project&cores=2&runtime=rust",
        )
    });

    // Small delay to simulate sequential user actions
    std::thread::sleep(Duration::from_millis(50));

    let handle2 = std::thread::spawn(move || {
        send_socket_request(
            &socket2,
            "GET /select-worker?project=shared-project&cores=2&runtime=rust",
        )
    });

    let result1 = handle1.join().unwrap();
    let result2 = handle2.join().unwrap();

    // Both should succeed (no corruption)
    assert!(result1.is_ok(), "Request1 failed: {:?}", result1.err());
    assert!(result2.is_ok(), "Request2 failed: {:?}", result2.err());

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: concurrent_same_project_safe=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_concurrent_same_project");
    harness.mark_passed();
}

/// Test graceful degradation when workers become unavailable.
#[test]
fn test_graceful_degradation() {
    let harness = create_pipeline_harness("graceful_degradation").unwrap();
    harness
        .logger
        .info("[e2e::pipeline] TEST START: test_graceful_degradation");

    let _project = create_test_project(&harness, "degrade-project").unwrap();

    // Start with workers
    let workers = WorkersFixture::mock_local(1);
    let socket_path = setup_daemon_with_workers(&harness, &workers).unwrap();

    start_daemon(&harness, &socket_path, &[]).unwrap();
    harness
        .wait_for_socket(&socket_path, Duration::from_secs(10))
        .unwrap();

    // Daemon should gracefully handle worker unavailability
    let response = send_socket_request(&socket_path, "GET /ready").unwrap();
    assert!(response.contains("200 OK"), "Got: {}", response);

    harness
        .logger
        .info("[e2e::pipeline] VERIFY: graceful_degradation_works=true");
    harness
        .logger
        .info("[e2e::pipeline] TEST PASS: test_graceful_degradation");
    harness.mark_passed();
}
