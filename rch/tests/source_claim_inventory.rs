//! Run the native inventory suite with the exact compiled protocol literals.
#![cfg(target_os = "linux")]

#[test]
fn source_claim_inventory_preserves_complete_ownership_checks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let fixture = tempfile::tempdir().expect("inventory fixture").keep();
    let script = fixture.join("transaction.sh");
    let helpers = fixture.join("helpers.sh");
    std::fs::write(&script, include_str!("../src/hook/source_claim_registry.sh"))
        .expect("write compiled transaction");
    std::fs::write(
        &helpers,
        rch_common::stale_target_reap::SOURCE_CLAIM_RECORD_HELPERS,
    )
    .expect("write compiled record helpers");
    for shell in ["/bin/sh", "/bin/bash"] {
        let output = std::process::Command::new("python3")
            .args(["-I", "-S"])
            .arg(root.join("scripts/tests/test_source_claim_inventory.py"))
            .env("RCH_TEST_SOURCE_CLAIM_SCRIPT", &script)
            .env("RCH_TEST_SOURCE_CLAIM_HELPERS", &helpers)
            .env("RCH_TEST_SHELL", shell)
            .output()
            .expect("execute native source-inventory regressions");
        assert!(
            output.status.success(),
            "shell={shell}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
