//! Real shell protocol checks for source-registry storage health.
#![cfg(unix)]

#[test]
fn source_registry_health_process_protocol() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/test_source_registry_health.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg("-v")
        .output()
        .expect("run source-registry health protocol tests with python3");
    assert!(
        output.status.success(),
        "source-registry health protocol failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
