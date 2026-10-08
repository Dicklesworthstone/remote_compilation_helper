//! The actual CLI's Linux force-stop path, with test-owned daemon processes.
#![cfg(target_os = "linux")]

#[test]
fn linux_force_stop_binds_the_real_cli_to_its_socket_peer() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/test_daemon_force_stop.py");
    let output = std::process::Command::new("python3")
        .arg("-I")
        .arg(script)
        .arg("--rch")
        .arg(env!("CARGO_BIN_EXE_rch"))
        .output()
        .expect("Linux force-stop regression requires Python 3.9+");
    assert!(
        output.status.success(),
        "force-stop native/CLI regressions failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
