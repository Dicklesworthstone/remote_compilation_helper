use std::process::Command;

use crate::common::{assert_contains, init_test_logging};

#[test]
fn test_rch_help_includes_description() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_help_includes_description");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--help")
        .output()
        .expect("Failed to run rch --help");

    assert!(output.status.success(), "rch --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "Remote Compilation Helper");
    crate::test_log!("TEST PASS: test_rch_help_includes_description");
}
