use std::process::Command;

use crate::common::init_test_logging;

#[test]
fn test_rchd_help_includes_usage() {
    init_test_logging();
    crate::test_log!("TEST START: test_rchd_help_includes_usage");

    let output = Command::new(env!("CARGO_BIN_EXE_rchd"))
        .arg("--help")
        .output()
        .expect("Failed to run rchd --help");

    assert!(output.status.success(), "rchd --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("rchd") || stdout.contains("RCH"),
        "Expected help output to mention rchd, got: {stdout}"
    );

    crate::test_log!("TEST PASS: test_rchd_help_includes_usage");
}
