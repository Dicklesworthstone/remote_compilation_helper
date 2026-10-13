//! Actual worker execution and output-pipe lifecycle regressions.
#![cfg(unix)]

#[test]
fn worker_output_completion() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/output_completion.py"
        ))
        .arg(env!("CARGO_BIN_EXE_rch-wkr"))
        .status()
        .expect("run output completion regressions (requires Python 3)");
    assert!(
        status.success(),
        "worker output completion regressions failed: {status}"
    );
}
