//! Native one-shot execution tests using the compiled worker protocol.
#![cfg(target_os = "linux")]

#[test]
fn retained_execution_identity_is_never_a_new_launch_grant() {
    let root = std::env::temp_dir().join(format!("rch-launch-once-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).expect("create retained protocol fixture");
    let script = root.join("protocol.sh");
    std::fs::write(&script, rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT)
        .expect("write compiled worker protocol");
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/remote_launch_once.py"
        ))
        .env("RCH_TEST_PROTOCOL_SCRIPT", &script)
        .output()
        .expect("run native single-launch tests");
    assert!(
        output.status.success(),
        "retained fixture={}\nstdout={}\nstderr={}",
        root.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
