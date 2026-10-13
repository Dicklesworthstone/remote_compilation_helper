//! Native Linux thread-liveness and TERM-to-KILL ownership regressions.
//! The fixture compiles a small C pthread program, then sources the exact
//! embedded production protocol under both sh and bash. Requires python3,
//! cc with pthread support, and procps thread enumeration; never silently skips.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn live_threads_behind_zombie_leaders_never_authorize_cleanup_success() {
    let directory = tempfile::tempdir().expect("create protocol fixture directory");
    let protocol = directory.path().join("protocol.sh");
    std::fs::write(&protocol, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write exact embedded protocol");
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/remote_process_threads.py");
    let output = Command::new("python3")
        .arg("-I")
        .arg(fixture)
        .arg(protocol)
        .stdin(Stdio::null())
        .output()
        .expect("run native thread ownership regressions");
    assert!(
        output.status.success(),
        "native thread regressions failed: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS: 28 native process and snapshot cases"),
        "native suite did not complete every case",
    );
}
