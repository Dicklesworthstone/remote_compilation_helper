use std::process::Command;

use crate::common::init_test_logging;

#[test]
fn test_rchd_version_flag() {
    init_test_logging();
    crate::test_log!("TEST START: test_rchd_version_flag");

    let output = Command::new(env!("CARGO_BIN_EXE_rchd"))
        .arg("--version")
        .output()
        .expect("Failed to run rchd --version");

    assert!(output.status.success(), "rchd --version failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty(), "Expected version output");

    crate::test_log!("TEST PASS: test_rchd_version_flag");
}
