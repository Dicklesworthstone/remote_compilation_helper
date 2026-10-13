//! Exercise the actual worker binary, not a model of preparation or locking.
#![cfg(target_os = "linux")]

#[test]
fn prepare_transaction_process_contract() {
    let status = std::process::Command::new("python3")
        .args([
            "-I",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/prepare_transactions.py"),
        ])
        .arg(env!("CARGO_BIN_EXE_rch-wkr"))
        .status()
        .expect("run real-worker preparation regressions (requires python3)");
    assert!(
        status.success(),
        "worker preparation regression failed: {status}"
    );
}
