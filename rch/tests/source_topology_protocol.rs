//! Native registry/topology regressions against the compiled shell constants.
//! These exercise local worker protocol transactions, not a live SSH fleet.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

#[test]
fn source_topology_acknowledgement_and_release_protocol() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let fixture = tempfile::tempdir().expect("protocol fixture");
    let registry = fixture.path().join("registry.sh");
    let helpers = fixture.path().join("helpers.sh");
    let retry = fixture.path().join("retry.sh");
    let paths = fixture.path().join("namespace-paths.sh");
    std::fs::write(
        &registry,
        include_str!("../src/hook/source_claim_registry.sh"),
    )
    .expect("write compiled registry");
    std::fs::write(
        &helpers,
        rch_common::stale_target_reap::SOURCE_CLAIM_RECORD_HELPERS,
    )
    .expect("write compiled helpers");
    std::fs::write(
        &retry,
        include_str!("../src/hook/source_claim_admission.sh"),
    )
    .expect("write compiled admission retry");

    std::fs::write(
        &paths,
        include_str!("../src/hook/source_namespace_paths.sh"),
    )
    .expect("write compiled namespace paths");

    for suite in ["test_source_topology.py", "test_source_namespace.py"] {
        let output = Command::new("python3")
            .arg(root.join("scripts/tests").join(suite))
            .env("RCH_TEST_SOURCE_TOPOLOGY_SCRIPT", &registry)
            .env("RCH_TEST_SOURCE_TOPOLOGY_HELPERS", &helpers)
            .env("RCH_TEST_SOURCE_TOPOLOGY_RETRY", &retry)
            .env("RCH_TEST_SOURCE_NAMESPACE_PATHS", &paths)
            .env("RCH_TEST_SOURCE_TOPOLOGY_SHELL", "sh")
            .output()
            .expect("Python 3 is required for the native source-topology regressions");
        assert!(
            output.status.success(),
            "source-topology protocol failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
