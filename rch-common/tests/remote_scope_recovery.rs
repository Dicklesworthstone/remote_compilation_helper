//! Scope receipt/cleanup contract plus an opt-in real systemd lifecycle test.
//! The fast fixture doubles systemd/cgroupfs, not the production protocol.

#[cfg(target_os = "linux")]
#[test]
fn remote_scope_recovery_contract() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/remote_scope_recovery.py"
        ))
        .status()
        .expect("Linux scope-recovery integration tests require python3");
    assert!(status.success(), "remote scope recovery contract failed");
}
