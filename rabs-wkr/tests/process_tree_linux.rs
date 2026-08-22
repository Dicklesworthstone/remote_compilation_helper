//! G006 acceptance fixture (worker side): the WORKER integration of the
//! shared process-group mechanism (`rabs-asupersync::process_groups`)
//! plus worker-local jobserver authority, proven against REAL processes
//! and a REAL bubblewrap namespace on Linux.
//!
//! 1. Jobserver replacement: client-supplied make-style coordination
//!    variables are stripped; exactly one worker-authored budget is
//!    installed (pure env surgery).
//! 2. End-to-end through `execute_canonical`: the action inside the
//!    canonical namespace records its own coordination env into its
//!    writable workspace — observing EXACTLY `MAKEFLAGS=-j<slots>`,
//!    nothing smuggled — while the managed group resolves with zero
//!    residual members.
//!
//! Group-membership/TERM mechanics themselves are covered by the
//! mechanism module's own tests in rabs-asupersync.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use rabs_wkr::jobserver::{replace_with_worker_local, worker_makeflags};
use rabs_wkr::session::{CanonicalExecRequest, execute_canonical};

/// The RABS fleet shape: unprivileged userns + bubblewrap. On any other
/// host SKIP loudly rather than fake a pass.
fn namespace_supported() -> bool {
    use rabs_sandbox::canonical_namespace::HostIsolationSupport;
    let support = HostIsolationSupport::probe();
    let ok = support.missing_for_canonical().is_empty();
    if !ok {
        eprintln!(
            "SKIP: host cannot run canonical namespace tests; missing {:?}",
            support.missing_for_canonical()
        );
    }
    ok
}

#[test]
fn env_surgery_replaces_client_coordination_with_worker_budget() {
    let mut env = vec![
        ("PATH".to_string(), "/bin".to_string()),
        (
            "MAKEFLAGS".to_string(),
            "-j999 --jobserver-auth=7,8".to_string(),
        ),
        ("CARGO_MAKEFLAGS".to_string(), "smuggled".to_string()),
        ("RUST_LOG".to_string(), "debug".to_string()),
    ];
    replace_with_worker_local(&mut env, 6);
    let map: BTreeMap<String, String> = env.into_iter().collect();
    assert_eq!(map.get("MAKEFLAGS").unwrap(), "-j6");
    assert!(!map.contains_key("CARGO_MAKEFLAGS"));
    assert!(!map.contains_key("MFLAGS"));
    assert_eq!(map.get("PATH").unwrap(), "/bin");
    assert_eq!(map.get("RUST_LOG").unwrap(), "debug");
}

#[test]
fn worker_budget_floors_at_one_slot() {
    assert_eq!(worker_makeflags(32), "-j32");
    assert_eq!(worker_makeflags(0), "-j1", "no -j0 may ever be authored");
}

#[test]
fn canonical_action_observes_only_worker_authored_jobserver_env() {
    if !namespace_supported() {
        return;
    }
    // Real backing directories so bwrap's binds succeed.
    let toolchain = tempfile::tempdir().expect("toolchain tempdir");
    let workspace = tempfile::tempdir().expect("workspace tempdir");

    // The action writes EVERY coordination var it can see into its own
    // writable workspace — the only honest way to assert what the
    // namespace actually presented (the wire carries digests, not bytes).
    let request = CanonicalExecRequest {
        request_id: 424_242,
        program: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "env | grep -E '^(MAKEFLAGS|MFLAGS|CARGO_MAKEFLAGS)=' \
             > /__rabs/workspace/coord.txt"
                .to_string(),
        ],
        toolchain_backing: toolchain.path().display().to_string(),
        workspace_backing: workspace.path().display().to_string(),
        jobserver_grant: None,
    };
    let result = execute_canonical(
        &request,
        toolchain.path(),
        workspace.path(),
        6,
        &workspace.path().join("spills"),
    );

    assert!(result.executed, "namespace host must execute, not refuse");
    assert_eq!(result.exit_code, 0, "grep must find the coordination var");
    assert_eq!(
        result.residual_group_members, 0,
        "the managed group must resolve with zero surviving members"
    );

    let observed = std::fs::read_to_string(workspace.path().join("coord.txt"))
        .expect("action wrote coord.txt");
    assert_eq!(
        observed, "MAKEFLAGS=-j6\n",
        "action observes exactly one worker-authored budget, nothing smuggled"
    );
}
