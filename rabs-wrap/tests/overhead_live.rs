//! S2's re-scoped C010 gate: the REAL `rabs-wrap` binary consulting a
//! LIVE rabsd, measured end-to-end (process spawn + breaker read + UDS
//! connect + hello + consult + state write + exec), p95 < 10ms.
//! Enforcing under the release profile (the shipped artifact); loudly
//! measurement-only in debug — same calibration as the original C010.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SLO_MS: f64 = 10.0;

fn rabsd_bin() -> std::path::PathBuf {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_rabs-wrap")).with_file_name("rabsd");
    if !path.exists() {
        let mut build = Command::new(env!("CARGO"));
        build.args(["build", "-p", "rabsd", "--bin", "rabsd"]);
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        assert!(build.status().expect("build rabsd").success());
    }
    path
}

#[test]
fn wrapper_end_to_end_p95_under_10ms_against_live_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");
    let mut daemon = Command::new(rabsd_bin())
        .env("RABS_SOCKET_PATH", &socket)
        .env("RABS_BOOT_MARKER", &marker)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rabsd");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "socket never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }

    let fake = dir.path().join("fake-rustc");
    std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let breaker = dir.path().join("breaker");

    // Warm-up (fs caches, first-connect costs), then measure.
    for _ in 0..5 {
        let _ = Command::new(env!("CARGO_BIN_EXE_rabs-wrap"))
            .arg(&fake)
            .args(["--crate-name", "fx"])
            .env("RABS_BREAKER_FILE", &breaker)
            .env("RABS_SOCKET_PATH", &socket)
            .status();
    }
    let mut samples: Vec<u128> = (0..60)
        .map(|_| {
            let start = Instant::now();
            let status = Command::new(env!("CARGO_BIN_EXE_rabs-wrap"))
                .arg(&fake)
                .args(["--crate-name", "fx"])
                .env("RABS_BREAKER_FILE", &breaker)
                .env("RABS_SOCKET_PATH", &socket)
                .status()
                .expect("wrapper run");
            assert!(status.success());
            start.elapsed().as_micros()
        })
        .collect();
    samples.sort_unstable();
    let p95_us = samples[(samples.len() * 95) / 100];
    let p95_ms = p95_us as f64 / 1_000.0;

    Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    let _ = daemon.wait();

    let enforcing = !cfg!(debug_assertions);
    let evidence = format!(
        "{{\"v\":1,\"suite\":\"perf/wrapper\",\"test\":\"rabs_wrap_end_to_end\",\
         \"p95_us\":{p95_us},\"SLO_ms\":{SLO_MS},\"profile\":\"{}\",\"gate\":\"{}\"}}",
        if enforcing { "release" } else { "debug" },
        if enforcing { "enforcing" } else { "measurement-only" },
    );
    eprintln!("{evidence}");
    assert!(
        !enforcing || p95_ms < SLO_MS,
        "wrapper end-to-end SLO violated: {evidence}"
    );
}
