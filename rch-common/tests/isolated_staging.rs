//! Real Linux receiver/filesystem/native-build integration, independent of SSH.

#[cfg(target_os = "linux")]
#[test]
fn isolated_staging_receiver_contract() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/isolated_staging.py"
        ))
        .status()
        .expect("Linux staging integration tests require python3");
    assert!(
        status.success(),
        "isolated staging receiver contract failed"
    );
}
