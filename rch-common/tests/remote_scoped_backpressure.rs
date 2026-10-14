//! Terminal diagnostics cannot retain a finished supervisor's ownership FDs.
#![cfg(target_os = "linux")]

#[test]
fn terminal_diagnostics_preserve_status_and_release_inherited_descriptors() {
    let root = tempfile::tempdir().expect("create protocol fixture").keep();
    let protocol = root.join("protocol.sh");
    std::fs::write(&protocol, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write compiled protocol");
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/remote_scoped_backpressure.py"
        ))
        .env("RCH_TEST_PROTOCOL_SCRIPT", &protocol)
        .output()
        .expect("run native supervisor backpressure suite");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
