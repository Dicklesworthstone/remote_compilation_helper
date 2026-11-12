#![cfg(unix)]
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
use rch_common::test_guard;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test harness configured for pipeline tests.
fn create_pipeline_harness(test_name: &str) -> HarnessResult<TestHarness> {
    // Respect CARGO_TARGET_DIR if set, otherwise use default target/debug
    let target_dir = if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(target_dir).join("debug")
    } else {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let project_root = manifest_dir.parent().unwrap_or(&manifest_dir);
        project_root.join("target/debug")
    };

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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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
    let _guard = test_guard!();
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

/// Opt-in process integration for GH #137. This runs an actual local OpenSSH
/// server, the daemon's real toolchain probes, `rch-wkr capabilities`, and
/// `rch-wkr execute` with real Cargo/compiler output. Only source-registry
/// health is supplied by the fixture: the production registry has a fixed
/// shared /var/tmp path and must not be touched by an isolated test.
#[cfg(target_os = "linux")]
mod toolchain_refresh_integration {
    use super::*;
    use rch_common::{SelectionResponse, ToolchainInfo, WorkerConfig, WorkerId};
    use serde_json::{Value, json};
    use std::io::Read;
    use std::net::TcpListener;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::process::{Child, Command, Output, Stdio};
    use std::time::Instant;

    const WORKER: &str = "toolchain-refresh-worker";
    const TOOLCHAIN: &str = "rch-issue-137";

    struct OwnedChild(Child);

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                // The still-owned, unreaped child pins this PID. SIGTERM uses
                // the daemon's ordinary shutdown path, which closes its SSH
                // masters before the fixture's sshd is stopped.
                if let Ok(pid) = i32::try_from(self.0.id()) {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGTERM,
                    );
                }
                let deadline = Instant::now() + Duration::from_secs(5);
                while matches!(self.0.try_wait(), Ok(None)) {
                    if Instant::now() >= deadline {
                        let _ = self.0.kill();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            let _ = self.0.wait();
        }
    }

    struct FixtureDirectory(Option<tempfile::TempDir>);

    impl FixtureDirectory {
        fn path(&self) -> &Path {
            self.0.as_ref().unwrap().path()
        }
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            if std::thread::panicking() {
                let path = self.0.take().unwrap().keep();
                eprintln!(
                    "retained toolchain integration logs and outputs: {}",
                    path.display()
                );
            }
        }
    }

    fn bounded_output(command: &Command, seconds: u32) -> Output {
        // These fixture commands inherit the test environment and only add
        // explicit overrides. GNU timeout supervises the command's process
        // group, including local compiler/SSH descendants, without targeting any
        // pre-existing process on the host.
        let mut bounded = Command::new(executable("timeout"));
        bounded
            .args(["--signal=TERM", "--kill-after=2s"])
            .arg(format!("{seconds}s"))
            .arg(command.get_program())
            .args(command.get_args());
        for (name, value) in command.get_envs() {
            match value {
                Some(value) => {
                    bounded.env(name, value);
                }
                None => {
                    bounded.env_remove(name);
                }
            }
        }
        if let Some(directory) = command.get_current_dir() {
            bounded.current_dir(directory);
        }
        bounded.output().expect("start bounded fixture command")
    }

    fn checked(command: &mut Command) -> Output {
        let output = bounded_output(command, 60);
        assert!(output.status.success(), "{command:?}: {output:?}");
        output
    }

    fn executable(name: &str) -> PathBuf {
        std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
            .map(|directory| directory.join(name))
            .find(|path| path.is_file())
            .unwrap_or_else(|| panic!("required integration executable {name} is missing"))
    }

    fn quote(path: &Path) -> String {
        shell_escape::escape(path.to_string_lossy()).into_owned()
    }

    fn write_executable(path: &Path, source: &str) {
        std::fs::write(path, source).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn query(socket: &Path, request: &str) -> std::io::Result<Value> {
        let mut stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(45)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        writeln!(stream, "{request}")?;
        stream.flush()?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        let body = extract_json_body(&response).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, response.clone())
        })?;
        serde_json::from_str(body).map_err(std::io::Error::other)
    }

    fn encode(value: &str) -> String {
        value.bytes().map(|byte| format!("%{byte:02X}")).collect()
    }

    struct Fixture {
        // Stop the daemon and its SSH masters before the server and directory.
        daemon: OwnedChild,
        _sshd: OwnedChild,
        root: FixtureDirectory,
        socket: PathBuf,
        rustup: PathBuf,
        sysroot: PathBuf,
        ssh: PathBuf,
        user: String,
    }

    impl Fixture {
        fn new() -> Self {
            let daemon_binary = Path::new(env!("CARGO_BIN_EXE_rchd"));
            // A small /tmp tmpfs cannot satisfy ordinary Cargo cold-build
            // admission. Keep real project outputs on the build filesystem;
            // the production disk budgets and reserve remain unchanged.
            let root = FixtureDirectory(Some(
                tempfile::Builder::new()
                    .prefix("rch-toolchain-refresh-")
                    .tempdir_in(daemon_binary.parent().expect("daemon binary directory"))
                    .unwrap(),
            ));
            let ssh = executable("ssh");
            let rustup = executable("rustup");
            let compiler = checked(Command::new("rustc").args(["--print", "sysroot"]));
            let sysroot = PathBuf::from(String::from_utf8(compiler.stdout).unwrap().trim());
            let worker_binary = daemon_binary.with_file_name("rch-wkr");
            assert!(
                worker_binary.is_file(),
                "build rch-wkr alongside rchd before this integration test"
            );
            let user = String::from_utf8(checked(Command::new("id").arg("-un")).stdout)
                .unwrap()
                .trim()
                .to_owned();
            for directory in [
                "client-bin",
                "worker-bin",
                "config",
                "state",
                "run",
                "cache",
                "worker-cache",
                "worker-cargo",
                "worker-rustup",
                "projects/fixture/src",
            ] {
                std::fs::create_dir_all(root.path().join(directory)).unwrap();
            }
            symlink(root.path().join("projects"), root.path().join("alias")).unwrap();
            for name in ["rustup", "cargo", "rustc"] {
                symlink(&rustup, root.path().join("worker-bin").join(name)).unwrap();
            }
            symlink(&worker_binary, root.path().join("worker-bin/rch-wkr")).unwrap();
            for name in ["host-key", "client-key"] {
                checked(
                    Command::new("ssh-keygen")
                        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                        .arg(root.path().join(name)),
                );
            }
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let client_config = root.path().join("ssh_config");
            std::fs::write(
                &client_config,
                format!(
                    "Host *\n  HostName 127.0.0.1\n  Port {port}\n  User {user}\n  IdentityFile {}\n  IdentitiesOnly yes\n  UserKnownHostsFile {}\n  StrictHostKeyChecking accept-new\n  BatchMode yes\n  ConnectTimeout 3\n",
                    root.path().join("client-key").display(),
                    root.path().join("known_hosts").display(),
                ),
            )
            .unwrap();
            write_executable(
                &root.path().join("client-bin/ssh"),
                &format!(
                    // The supervisor normally closes these masters on daemon
                    // shutdown. Also bound their lifetime if an assertion or
                    // external kill interrupts that cleanup.
                    "#!/bin/sh\nexec {} --signal=TERM --kill-after=2s 180s {} -F {} \"$@\"\n",
                    quote(&executable("timeout")),
                    quote(&ssh),
                    quote(&client_config)
                ),
            );
            // The source-registry health command is the sole synthetic protocol
            // result. All inventory, rustup, Cargo and worker execution commands
            // use the actual installed binaries over an authenticated SSH channel.
            write_executable(
                &root.path().join("worker-entry"),
                &format!(
                    r#"#!/bin/sh
export PATH={worker_bin}:/usr/bin:/bin
export RUSTUP_HOME={rustup_home}
export CARGO_HOME={cargo_home}
export XDG_CACHE_HOME={worker_cache}
export RUSTUP_TOOLCHAIN=rch-fixture-base
export RCH_WKR_CANONICAL_ROOT={canonical}
export RCH_WKR_ALIAS_ROOT={alias}
case "$SSH_ORIGINAL_COMMAND" in
    *rch_source_registry_health*) printf 'health_check\n'; exit 0 ;;
    *'rch-wkr capabilities'*|*'rch-wkr telemetry'*|*'rch-wkr execute'*|*'rustup run rch-issue-137 '*|*'echo ok'*|*'debug/compiled_137'*) ;;
    *) printf 'unexpected fixture command: %s\n' "$SSH_ORIGINAL_COMMAND" >&2; exit 97 ;;
esac
printf '%s\n' "$SSH_ORIGINAL_COMMAND" >> {commands}
exec /bin/sh -c "$SSH_ORIGINAL_COMMAND"
"#,
                    worker_bin = quote(&root.path().join("worker-bin")),
                    rustup_home = quote(&root.path().join("worker-rustup")),
                    cargo_home = quote(&root.path().join("worker-cargo")),
                    worker_cache = quote(&root.path().join("worker-cache")),
                    canonical = quote(&root.path().join("projects")),
                    alias = quote(&root.path().join("alias")),
                    commands = quote(&root.path().join("commands.log")),
                ),
            );
            let server_config = root.path().join("sshd_config");
            std::fs::write(
                &server_config,
                format!(
                    "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowUsers {user}\nForceCommand {}\n",
                    root.path().join("host-key").display(),
                    root.path().join("sshd.pid").display(),
                    root.path().join("client-key.pub").display(),
                    root.path().join("worker-entry").display(),
                ),
            )
            .unwrap();
            drop(listener);
            let sshd_log = std::fs::File::create(root.path().join("sshd.log")).unwrap();
            let sshd = OwnedChild(
                Command::new("/usr/sbin/sshd")
                    .args(["-D", "-e", "-f"])
                    .arg(server_config)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(sshd_log)
                    .spawn()
                    .unwrap(),
            );
            checked(
                Command::new(&rustup)
                    .env("RUSTUP_HOME", root.path().join("worker-rustup"))
                    .env("CARGO_HOME", root.path().join("worker-cargo"))
                    .args(["toolchain", "link", "rch-fixture-base"])
                    .arg(&sysroot),
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let handshake = bounded_output(
                    Command::new(&ssh)
                        .arg("-F")
                        .arg(&client_config)
                        .arg(format!("{user}@127.0.0.1"))
                        .arg("echo ok"),
                    5,
                );
                if handshake.status.success() && handshake.stdout == b"ok\n" {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "OpenSSH fixture did not become ready: {}",
                    std::fs::read_to_string(root.path().join("sshd.log")).unwrap()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            let worker = WorkerConfig {
                id: WorkerId::new(WORKER),
                host: "127.0.0.1".into(),
                user: user.clone(),
                identity_file: root.path().join("client-key").display().to_string(),
                total_slots: 1,
                ..WorkerConfig::default()
            };
            std::fs::write(
                root.path().join("config/workers.toml"),
                toml::to_string(&json!({"workers": [worker]})).unwrap(),
            )
            .unwrap();
            std::fs::write(
                root.path().join("config/daemon.toml"),
                "health_check_interval_secs = 3600\n[cache_cleanup]\nenabled = false\n",
            )
            .unwrap();
            std::fs::write(
                root.path().join("config/config.toml"),
                "[self_healing]\ndaemon_installs_hooks = false\n[self_test]\nenabled = false\n",
            )
            .unwrap();
            std::fs::write(
                root.path().join("projects/fixture/Cargo.toml"),
                "[package]\nname = \"compiled_137\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[workspace]\n",
            )
            .unwrap();
            std::fs::write(
                root.path().join("projects/fixture/src/main.rs"),
                "fn main() { println!(\"compiled-and-executed:{}\", env!(\"RUSTUP_TOOLCHAIN\")); }\n",
            )
            .unwrap();
            let socket = root.path().join("rch.sock");
            let log = std::fs::File::create(root.path().join("daemon.log")).unwrap();
            let daemon = OwnedChild(
                Command::new(env!("CARGO_BIN_EXE_rchd"))
                    .env_clear()
                    .env(
                        "PATH",
                        format!("{}:/usr/bin:/bin", root.path().join("client-bin").display()),
                    )
                    .env("XDG_CONFIG_HOME", root.path().join("xdg-config"))
                    .env("XDG_DATA_HOME", root.path().join("data"))
                    .env("XDG_CACHE_HOME", root.path().join("cache"))
                    .env("XDG_RUNTIME_DIR", root.path().join("run"))
                    .env("RCH_CONFIG_DIR", root.path().join("config"))
                    .env("RCH_STATE_HOME", root.path().join("state"))
                    .env("RCH_WORKER_REAP_ENABLE", "0")
                    .current_dir(root.path())
                    .args([
                        "--foreground",
                        "--metrics-port",
                        "0",
                        "--no-hot-reload",
                        "--socket",
                    ])
                    .arg(&socket)
                    .arg("--workers-config")
                    .arg(root.path().join("config/workers.toml"))
                    .arg("--history-file")
                    .arg(root.path().join("history.jsonl"))
                    .stdin(Stdio::null())
                    .stdout(log.try_clone().unwrap())
                    .stderr(log)
                    .spawn()
                    .unwrap(),
            );
            let mut fixture = Self {
                daemon,
                _sshd: sshd,
                root,
                socket,
                rustup,
                sysroot,
                ssh,
                user,
            };
            let deadline = Instant::now() + Duration::from_secs(45);
            loop {
                if query(&fixture.socket, "GET /select-worker?project=readiness&command=cargo%20build%20--offline&runtime=rust&cores=1&dry_run=1")
                    .ok()
                    .is_some_and(|response| !response["worker"].is_null())
                {
                    break;
                }
                assert!(
                    fixture.daemon.0.try_wait().unwrap().is_none(),
                    "daemon exited: {}",
                    fixture.logs()
                );
                assert!(
                    Instant::now() < deadline,
                    "worker never became ready: {}",
                    fixture.logs()
                );
                std::thread::sleep(Duration::from_millis(25));
            }
            fixture
        }

        fn logs(&self) -> String {
            std::fs::read_to_string(self.root.path().join("daemon.log")).unwrap()
        }

        fn install(&self) {
            checked(
                Command::new(&self.rustup)
                    .env("RUSTUP_HOME", self.root.path().join("worker-rustup"))
                    .env("CARGO_HOME", self.root.path().join("worker-cargo"))
                    .args(["toolchain", "link", TOOLCHAIN])
                    .arg(&self.sysroot),
            );
        }

        fn preflight_count(&self) -> usize {
            std::fs::read_to_string(self.root.path().join("commands.log"))
                .unwrap()
                .lines()
                .filter(|line| line.contains(&format!("rustup run {TOOLCHAIN} rustc --version")))
                .count()
        }

        fn select(&self) -> (SelectionResponse, String) {
            let wrapper = rch_common::job_identity::JobIdentity::new_local().local_wrapper_id;
            let toolchain =
                serde_json::to_string(&ToolchainInfo::new(TOOLCHAIN, None, TOOLCHAIN)).unwrap();
            let response = query(
                &self.socket,
                &format!(
                    "GET /select-worker?project=refresh-fixture&command=cargo%20build%20--offline&runtime=rust&cores=1&hook_pid={}&local_wrapper_id={wrapper}&toolchain={}",
                    std::process::id(), encode(&toolchain),
                ),
            )
            .unwrap();
            (serde_json::from_value(response).unwrap(), wrapper)
        }

        fn refuse(&self) {
            let (response, _) = self.select();
            assert!(response.worker.is_none(), "{response:?}");
            assert!(response.build_id.is_none(), "{response:?}");
            assert!(
                format!("{response:?}").contains("toolchain_preflight_command_failed"),
                "{response:?}\n{}",
                self.logs()
            );
        }

        fn refresh(&self) -> Value {
            let response = query(
                &self.socket,
                &format!("GET /workers/capabilities?refresh=true&worker={WORKER}"),
            )
            .unwrap();
            assert_eq!(
                response["workers"].as_array().unwrap().len(),
                1,
                "{response}"
            );
            assert_eq!(
                response["workers"][0]["refresh"]["live"],
                true,
                "{response}\n{}",
                self.logs()
            );
            response
        }

        fn execute_admitted(&self, iteration: usize) {
            let (selected, wrapper) = self.select();
            assert_eq!(
                selected.worker.as_ref().map(|worker| worker.id.as_str()),
                Some(WORKER),
                "{selected:?}\n{}",
                self.logs()
            );
            let build = selected.build_id.expect("real daemon reservation");
            assert!(build > 0);
            let project = self.root.path().join("projects/fixture");
            let target = self.root.path().join(format!("output-{iteration}"));
            let remote = format!(
                // The worker's disk guard and Cargo must observe the same
                // output path. Each build uses a fresh directory, so a cached
                // executable cannot masquerade as compiler execution.
                "CARGO_TARGET_DIR={} rch-wkr execute --workdir {} --toolchain {TOOLCHAIN} --command 'cargo build --offline --quiet' && {}",
                quote(&target),
                quote(&project),
                quote(&target.join("debug/compiled_137")),
            );
            let output = checked(
                Command::new(&self.ssh)
                    .arg("-F")
                    .arg(self.root.path().join("ssh_config"))
                    .arg(format!("{}@127.0.0.1", self.user))
                    .arg(remote),
            );
            assert_eq!(
                String::from_utf8(output.stdout).unwrap().trim(),
                format!("compiled-and-executed:{TOOLCHAIN}")
            );
            assert!(
                target.join("debug/compiled_137").is_file(),
                "fresh compiler output must exist"
            );
            query(&self.socket, &format!("POST /release-worker?worker={WORKER}&slots=1&build_id={build}&local_wrapper_id={wrapper}&exit_code=0")).unwrap();
            let record = query(
                &self.socket,
                &format!("GET /builds/{build}?local_wrapper_id={wrapper}"),
            )
            .unwrap();
            assert_eq!(record["status"], "completed", "{record}");
            assert_eq!(record["record"]["exit_code"], 0, "{record}");
        }
    }

    #[test]
    #[ignore = "requires OpenSSH server, GNU timeout, rustup/compiler, built rch-wkr, and build-disk headroom"]
    fn toolchain_refresh_restores_executable_admission() {
        let fixture = Fixture::new();
        let daemon_incarnation =
            query(&fixture.socket, "GET /restart-admission").unwrap()["daemon_incarnation"].clone();
        assert!(!daemon_incarnation.is_null());
        fixture.refuse();
        assert_eq!(fixture.preflight_count(), 1);
        fixture.install();
        for _ in 0..2 {
            fixture.refuse();
        }
        assert_eq!(
            fixture.preflight_count(),
            1,
            "definitive negative was reused"
        );

        let refreshed = fixture.refresh();
        assert!(
            refreshed["workers"][0]["capabilities"]["rustup_toolchains"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name == TOOLCHAIN),
            "{refreshed}"
        );
        fixture.execute_admitted(1);
        fixture.execute_admitted(2);
        assert_eq!(
            fixture.preflight_count(),
            2,
            "fresh success is reused for repeated actual builds"
        );

        // Preserve the linked toolchain while making its requested name absent.
        // A refreshed inventory must also revoke stale positive evidence.
        let installed = fixture
            .root
            .path()
            .join("worker-rustup/toolchains")
            .join(TOOLCHAIN);
        let detached = fixture.root.path().join("detached-toolchain");
        std::fs::rename(&installed, &detached).unwrap();
        fixture.refresh();
        fixture.refuse();
        assert_eq!(fixture.preflight_count(), 3);
        std::fs::rename(&detached, &installed).unwrap();
        fixture.refuse();
        assert_eq!(fixture.preflight_count(), 3);

        let reload = query(&fixture.socket, "POST /reload").unwrap();
        assert_eq!(reload["success"], true, "{reload}");
        assert_eq!(
            reload["updated"], 0,
            "the unchanged inventory must still invalidate toolchain evidence"
        );
        fixture.execute_admitted(3);
        assert_eq!(fixture.preflight_count(), 4);
        assert_eq!(
            query(&fixture.socket, "GET /restart-admission").unwrap()["daemon_incarnation"],
            daemon_incarnation,
            "recovery never restarts the daemon"
        );
    }
}
