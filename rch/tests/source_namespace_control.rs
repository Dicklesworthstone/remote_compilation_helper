//! Exercise the exact compiled worker control program with native processes.
#![cfg(target_os = "linux")]

#[test]
fn source_namespace_control_bounds_processes_and_complete_output() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let fixture = tempfile::tempdir().expect("control fixture");
    let control = fixture.path().join("control.sh");
    std::fs::write(
        &control,
        include_str!("../src/hook/source_namespace_control.sh"),
    )
    .expect("write compiled control program");
    for suite in [
        "scripts/tests/test_source_namespace_control.py",
        "scripts/test_namespace_group_teardown.py",
    ] {
        let output = std::process::Command::new("python3")
            .arg(root.join(suite))
            .env("RCH_TEST_SOURCE_NAMESPACE_CONTROL", &control)
            .output()
            .expect("execute native namespace control tests");
        assert!(
            output.status.success(),
            "suite={suite}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
