//! Scope supervisor integration against the compiled production shell constant.
#[cfg(target_os = "linux")]
#[test]
fn scoped_launch_lifecycle() {
    let directory = tempfile::tempdir().expect("protocol fixture directory");
    let script = directory.path().join("protocol.sh");
    std::fs::write(&script, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write compiled protocol");
    for shell in ["/bin/sh", "/bin/bash"] {
        let status = std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/remote_scoped_launch.py"
            ))
            .env("RCH_TEST_PROTOCOL_SCRIPT", &script)
            .env("RCH_TEST_SHELL", shell)
            .status()
            .expect("scope lifecycle tests require python3 and the selected shell");
        assert!(
            status.success(),
            "scope lifecycle contract failed under {shell}"
        );
    }
}
