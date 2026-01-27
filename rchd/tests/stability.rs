#![cfg(unix)]
//! Daemon stability smoke tests.
//!
//! These tests exercise rchd startup/shutdown cycles and bursty request
//! handling to ensure the daemon stays responsive under light stress.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use rch_common::e2e::harness::{HarnessResult, TestHarnessBuilder};

/// Send a request to the daemon via Unix socket and return the response body.
fn send_request(socket_path: &Path, request: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    writeln!(stream, "{}", request)?;
    stream.flush()?;

    let reader = BufReader::new(&stream);
    let mut response = String::new();
    let mut in_body = false;

    for line in reader.lines() {
        let line = line?;
        if in_body {
            response.push_str(&line);
            response.push('\n');
        } else if line.is_empty() {
            in_body = true;
        }
    }

    Ok(response.trim().to_string())
}

#[test]
fn test_daemon_startup_shutdown_cycles() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_stability_cycles")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .build()?;

    // Minimal workers config (no real connections required for status/health).
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    for cycle in 1..=3 {
        harness
            .logger
            .info(format!("Starting daemon cycle {cycle}"));

        harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;
        harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

        let response = send_request(&socket_path, "GET /health")
            .map_err(rch_common::e2e::harness::HarnessError::Io)?;
        harness.assert(
            response.contains("\"status\""),
            "Health response should include status",
        )?;

        harness.stop_process("daemon")?;
        std::thread::sleep(Duration::from_millis(300));
    }

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_request_burst() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_stability_burst")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .build()?;

    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Burst of health requests to ensure responsiveness.
    for _ in 0..100 {
        let response = send_request(&socket_path, "GET /health")
            .map_err(rch_common::e2e::harness::HarnessError::Io)?;
        harness.assert(
            response.contains("\"status\""),
            "Health response should include status",
        )?;
    }

    harness.mark_passed();
    Ok(())
}
