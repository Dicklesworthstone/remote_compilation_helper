//! Previous-boot recovery against the exact compiled worker protocol.
#![cfg(target_os = "linux")]

#[test]
fn previous_boot_recovery_never_signals_current_boot_processes() {
    // Retain the private fixture, including a failed run's compiled source.
    let root = std::env::temp_dir().join(format!("rch-reboot-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).expect("create retained protocol fixture");
    let script = root.join("protocol.sh");
    std::fs::write(&script, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write compiled worker protocol");
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/remote_reboot_recovery.py"
        ))
        .env("RCH_TEST_PROTOCOL_SCRIPT", &script)
        .output()
        .expect("run native boot-bound recovery tests");
    assert!(
        output.status.success(),
        "retained fixture={}\nstdout={}\nstderr={}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
