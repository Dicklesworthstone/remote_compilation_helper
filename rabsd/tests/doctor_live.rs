//! S7 acceptance: `rabsd --doctor` against a REAL daemon and against a
//! dead one. Green (no Fail) when the daemon is up and the install is
//! sane; a Warn (not Fail) when the daemon is absent — RABS is
//! fail-open, so a dead daemon is not a catastrophic misconfiguration.
#![cfg(unix)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn rabsd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rabsd"))
}

#[test]
fn doctor_is_green_against_a_live_daemon() {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");
    let state = dir.path().join("state");
    let breaker = dir.path().join("breaker"); // absent = fresh/closed

    let mut daemon = rabsd()
        .env("RABS_SOCKET_PATH", &socket)
        .env("RABS_BOOT_MARKER", &marker)
        .env("RABS_STATE_DIR", &state)
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

    let doctor = rabsd()
        .arg("--doctor")
        .env("RABS_SOCKET_PATH", &socket)
        .env("RABS_STATE_DIR", &state)
        .env("RABS_BREAKER_FILE", &breaker)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&doctor.stdout);
    assert_eq!(
        doctor.status.code(),
        Some(0),
        "doctor should not Fail: {out}"
    );
    assert!(
        out.contains("\"id\":\"daemon\",\"severity\":\"ok\""),
        "{out}"
    );
    assert!(
        out.contains("\"id\":\"socket-perms\",\"severity\":\"ok\""),
        "{out}"
    );
    // On Linux workers this is canonical:ok; on macOS edge it's a warn —
    // either way the OVERALL must not be Fail.
    assert!(
        out.contains("\"overall\":\"ok\"") || out.contains("\"overall\":\"warn\""),
        "overall must not be Fail on a healthy install: {out}"
    );

    Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    let _ = daemon.wait();
}

#[test]
fn doctor_warns_not_fails_when_daemon_is_dead() {
    let dir = tempfile::tempdir().unwrap();
    let doctor = rabsd()
        .arg("--doctor")
        .env("RABS_SOCKET_PATH", dir.path().join("absent.sock"))
        .env("RABS_STATE_DIR", dir.path().join("state"))
        .env("RABS_BREAKER_FILE", dir.path().join("absent-breaker"))
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&doctor.stdout);
    // Fail-open: a dead daemon is a WARN, exit code 0 (not a broken
    // install a CI gate should red on).
    assert_eq!(doctor.status.code(), Some(0), "{out}");
    assert!(
        out.contains("\"id\":\"daemon\",\"severity\":\"warn\""),
        "{out}"
    );
    assert!(out.contains("fail-open"), "{out}");
}

fn run_state_startup(owner: &std::path::Path, state: &std::path::Path, doctor: bool, mask: &str) {
    // Keep umask changes inside the child, independent of parallel test threads.
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            "umask \"$1\"; shift; exec \"$@\"",
            "rabs-state-startup",
        ])
        .arg(mask)
        .arg(env!("CARGO_BIN_EXE_rabsd"));
    if doctor {
        command.arg("--doctor");
    } else {
        command.args(["--run-for-ms", "250"]);
    }
    let output = command
        .env("RABS_SOCKET_PATH", owner.join("daemon.sock"))
        .env("RABS_BOOT_MARKER", owner.join("daemon.boot"))
        .env("RABS_STATE_DIR", state)
        .env("RABS_BREAKER_FILE", owner.join("absent-breaker"))
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .output()
        .expect("run daemon state startup");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "doctor={doctor}, umask={mask}: stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(if doctor {
            "\"id\":\"state-dir\",\"severity\":\"ok\""
        } else {
            "\"kind\":\"janitor-cas-mounted\""
        }),
        "{stdout}"
    );
}

#[test]
fn fresh_daemon_and_doctor_state_is_private_under_permissive_umasks() {
    use std::os::unix::fs::PermissionsExt;
    for mask in ["0000", "0002"] {
        for doctor in [false, true] {
            let owner = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let state = owner.path().join("new-parent/state");
            run_state_startup(owner.path(), &state, doctor, mask);
            for path in [&state, state.parent().unwrap()] {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
    }
}

#[test]
fn daemon_and_doctor_preserve_existing_state_permissions_and_contents() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for mode in [0o755, 0o775] {
        for doctor in [false, true] {
            let owner = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let state = owner.path().join("state");
            std::fs::create_dir(&state).unwrap();
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(mode)).unwrap();
            let inode = std::fs::metadata(&state).unwrap().ino();
            std::fs::write(state.join("existing-state"), b"keep existing evidence").unwrap();
            run_state_startup(owner.path(), &state, doctor, "0002");
            let after = std::fs::metadata(&state).unwrap();
            assert_eq!(after.ino(), inode);
            assert_eq!(after.permissions().mode() & 0o777, mode);
            assert_eq!(
                std::fs::read(state.join("existing-state")).unwrap(),
                b"keep existing evidence"
            );
        }
    }
}
