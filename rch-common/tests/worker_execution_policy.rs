//! Runs the Linux shell contract against real processes, not a reimplementation
//! of the embedded protocol. The fixture uses Python's standard library only.

#[cfg(target_os = "linux")]
#[test]
fn worker_execution_policy_shell_contract() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/worker_execution_policy.py"
        ))
        .status()
        .expect("Linux execution-policy integration tests require python3");
    assert!(status.success(), "worker execution policy contract failed");
}
