//! Process-level tests for the exact scripts embedded by hook::ssh.
//! The Python harnesses use real kernel locks; no daemon, SSH or worker is used.
#[cfg(unix)]
#[test]
fn source_lock_holder_process_protocol() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/tests/test_source_lock_holder.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .output()
        .expect("python3 is required for source-holder process tests");
    assert!(
        output.status.success(),
        "source-holder tests failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(unix)]
#[test]
fn source_claim_registry_process_protocol() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/tests/test_source_claim_registry.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .output()
        .expect("python3 is required for source-registry process tests");
    assert!(
        output.status.success(),
        "source-registry tests failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
