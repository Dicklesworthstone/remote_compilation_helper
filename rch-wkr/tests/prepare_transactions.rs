//! Exercise the actual worker binary, not a model of preparation or locking.
#![cfg(target_os = "linux")]

#[test]
fn prepare_transaction_process_contract() {
    for script in [
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/prepare_transactions.py"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/prepare_workspaces.py"),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/prepare_pnpm_workspaces.py"
        ),
    ] {
        let status = std::process::Command::new("python3")
            .args(["-I", script])
            .arg(env!("CARGO_BIN_EXE_rch-wkr"))
            .status()
            .expect("run real-worker preparation regressions (requires python3)");
        assert!(
            status.success(),
            "worker preparation regression failed ({script}): {status}"
        );
    }
}
