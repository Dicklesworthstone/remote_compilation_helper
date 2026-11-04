//! Execute the same preparation script embedded in the remote command builder.
#![cfg(unix)]

#[test]
fn prepared_tools_keep_their_directory_binding() {
    let root = tempfile::tempdir().expect("test directory").keep();
    let script = root.join("node_prepare.sh");
    std::fs::write(&script, include_str!("../src/transfer/node_prepare.sh"))
        .expect("write compiled preparation script");
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/node_prepare_paths.py"
        ))
        .env("RCH_NODE_PREPARE_SCRIPT", &script)
        .output()
        .expect("run native prepared-tool tests");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
