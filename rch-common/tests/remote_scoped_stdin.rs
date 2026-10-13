//! Native stdin and cancellation checks against the compiled launch protocol.
#![cfg(target_os = "linux")]

#[test]
fn scoped_launch_preserves_workload_stdin() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = tempfile::tempdir().expect("stdin protocol fixture");
    let script = fixture.path().join("protocol.sh");
    std::fs::write(&script, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write compiled protocol");
    let output = std::process::Command::new("python3")
        .arg(root.join("tests/remote_scoped_stdin.py"))
        .env("RCH_TEST_PROTOCOL_SCRIPT", &script)
        .env("RCH_TEST_SHELL", "/bin/sh")
        .output()
        .expect("execute native stdin and cancellation tests");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
