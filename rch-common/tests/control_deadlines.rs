//! Execute the production control protocol, including its compiled composition.
#[cfg(target_os = "linux")]
#[test]
fn worker_control_deadlines() {
    let directory = tempfile::tempdir().expect("temporary protocol directory");
    let protocol = directory.path().join("protocol.sh");
    std::fs::write(&protocol, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write compiled control protocol");
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/control_deadlines.py"
        ))
        .env("RCH_CONTROL_TEST_PROTOCOL", &protocol)
        .status()
        .expect("run control deadline regressions (requires Python 3)");
    assert!(status.success(), "control deadline regressions failed");
}
