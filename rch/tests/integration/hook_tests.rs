use std::process::{Command, Stdio};

use crate::common::init_test_logging;

#[test]
fn test_hook_allows_non_compilation() {
    init_test_logging();
    crate::test_log!("TEST START: test_hook_allows_non_compilation");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rch"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start rch hook");

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}\n"#;
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(input.as_bytes()).expect("Failed to write hook input");
    }

    let output = child.wait_with_output().expect("Failed to read hook output");
    assert!(output.status.success(), "Hook exited with failure");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.trim().is_empty(), "Expected empty output, got: {stdout}");

    crate::test_log!("TEST PASS: test_hook_allows_non_compilation");
}
