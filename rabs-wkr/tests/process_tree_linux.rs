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
//!    writable workspace — observing the granted budget and a reachable
//!    worker-owned fifo, nothing smuggled — while the managed group
//!    resolves with zero residual members.
//! 3. Failed bridge setup refuses execution instead of silently
//!    replacing the grant with independent make pools.
//!
//! Group-membership/TERM mechanics themselves are covered by the
//! mechanism module's own tests in rabs-asupersync.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use rabs_wkr::jobserver::{replace_with_worker_local, worker_makeflags};
use rabs_wkr::session::{CanonicalExecRequest, execute_canonical};
use rabs_sandbox::process_context::CommandContext;

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
        ("NUM_JOBS".to_string(), "999".to_string()),
        ("RUST_LOG".to_string(), "debug".to_string()),
    ];
    replace_with_worker_local(&mut env, 6);
    let map: BTreeMap<String, String> = env.into_iter().collect();
    assert_eq!(map.get("MAKEFLAGS").unwrap(), "-j6");
    assert_eq!(
        map.get("NUM_JOBS").unwrap(),
        "6",
        "canonical capacity agrees with the budget (I003)"
    );
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
    let cargo_home = tempfile::tempdir().expect("cargo-home tempdir");
    let home = tempfile::tempdir().expect("home tempdir");

    // The action writes EVERY coordination var it can see into its own
    // writable workspace — the only honest way to assert what the
    // namespace actually presented (the wire carries digests, not bytes).
    for (requested_grant, expected_grant) in
        [(Some(2), 2), (Some(u32::MAX), 6), (Some(0), 1), (None, 6)]
    {
        let request = CanonicalExecRequest {
            request_id: 424_242,
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "auth=${MAKEFLAGS##*--jobserver-auth=fifo:}; test -p \"$auth\" || exit 71; \
             env | grep -E '^(MAKEFLAGS|MFLAGS|CARGO_MAKEFLAGS|NUM_JOBS)=' \
             > /__rabs/workspace/coord.txt"
                    .to_string(),
            ],
            toolchain_backing: toolchain.path().display().to_string(),
            workspace_backing: workspace.path().display().to_string(),
            jobserver_grant: requested_grant,
            command_context: CommandContext::default(),
        };
        let result = execute_canonical(
            &request,
            cargo_home.path(),
            home.path(),
            6,
            &workspace.path().join("spills"),
        );

        assert!(result.executed, "namespace host must execute, not refuse");
        assert_eq!(
            result.exit_code, 0,
            "advertised fifo must exist inside the namespace and coordination env must be present"
        );
        assert_eq!(
            result.residual_group_members, 0,
            "the managed group must resolve with zero surviving members"
        );

        let observed = std::fs::read_to_string(workspace.path().join("coord.txt"))
            .expect("action wrote coord.txt");
        let observed: BTreeMap<_, _> = observed
            .lines()
            .map(|line| line.split_once('=').expect("coordination assignment"))
            .collect();
        assert_eq!(observed.len(), 3, "only both auth channels and the granted capacity");
        assert_eq!(observed["MAKEFLAGS"], observed["CARGO_MAKEFLAGS"]);
        assert!(!observed.contains_key("MFLAGS"));
        assert_eq!(
            observed["NUM_JOBS"],
            expected_grant.to_string(),
            "effective grant replaces host slots"
        );
        let expected_auth =
            format!("-j{expected_grant} --jobserver-auth=fifo:/__rabs/home/");
        let relative = observed["MAKEFLAGS"]
            .strip_prefix(expected_auth.as_str())
            .expect("worker auth points into the bound bridge directory");
        let (directory, fifo_name) = relative.split_once('/').expect("private directory and FIFO");
        assert!(directory.starts_with(".rabs-jobserver-"));
        assert!(fifo_name.starts_with("rabs-jobserver-"));
        assert!(fifo_name.ends_with(".fifo"));
        assert!(!fifo_name.contains('/'));
        assert!(
            !home
                .path()
                .join(relative)
                .exists(),
            "resolved attempt releases its fifo"
        );
        assert!(!home.path().join(directory).exists(), "private runtime directory is retired");
        assert!(!workspace.path().join(".rabs-jobserver").exists(), "jobserver setup does not edit source");
    }
}

#[test]
fn jobserver_setup_failure_refuses_execution() {
    if !namespace_supported() {
        return;
    }
    let toolchain = tempfile::tempdir().expect("toolchain tempdir");
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let cargo_home = tempfile::tempdir().expect("cargo-home tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    // Runtime setup now belongs to HOME, not to a reserved source name.
    // Refuse a real setup failure at that boundary, retaining the old
    // no-execution and no-overwrite assertions.
    let obstruction = home.path().join("not-a-directory");
    std::fs::write(&obstruction, b"keep this input").expect("bridge directory obstruction");
    let request = CanonicalExecRequest {
        request_id: 424_243,
        program: "sh".to_string(),
        args: vec![
            "-c".to_string(),
            "echo started > /__rabs/workspace/started.txt".to_string(),
        ],
        toolchain_backing: toolchain.path().display().to_string(),
        workspace_backing: workspace.path().display().to_string(),
        jobserver_grant: Some(2),
        command_context: CommandContext::default(),
    };
    let result = execute_canonical(
        &request,
        cargo_home.path(),
        &obstruction,
        6,
        &workspace.path().join("spills"),
    );
    assert_eq!(result.request_id, request.request_id);
    assert!(
        !result.executed,
        "missing shared jobserver must refuse the action"
    );
    assert_eq!(result.exit_code, -1);
    assert!(!workspace.path().join("started.txt").exists());
    assert_eq!(
        std::fs::read(&obstruction).expect("preserved obstruction"),
        b"keep this input"
    );
}

#[test]
fn real_rustc_and_its_output_run_with_exact_workspace_member_context() {
    use rabs_wkr::execution::ExecutionControl;
    use rabs_wkr::session::{execute_canonical_controlled, sha256_hex};
    if !namespace_supported() { return; }
    let cargo = std::fs::canonicalize(std::env::var_os("CARGO").expect("Cargo supplies its path")).unwrap();
    let toolchain = cargo.parent().and_then(std::path::Path::parent).expect("toolchain/bin/cargo");
    let workspace = tempfile::tempdir().unwrap();
    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let spills = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(workspace.path().join("member/src")).unwrap();
    // env! executes in the REAL compiler process, not a scripted result.
    // The compiled program independently checks the runtime cwd/environment.
    std::fs::write(workspace.path().join("member/src/main.rs"), r#"
fn main() {
    assert_eq!(env!("CARGO_PKG_NAME"), "context-member");
    assert_eq!(env!("CARGO_PKG_VERSION"), "9.8.7");
    assert_eq!(env!("EXACT_CONTEXT"), "spaces \"quotes\" $HOME\n雪");
    assert_eq!(env!("EXPLICIT_EMPTY"), "");
    assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new("/__rabs/workspace/member"));
    assert_eq!(std::env::var("EXACT_CONTEXT").unwrap(), env!("EXACT_CONTEXT"));
    assert_eq!(std::env::var("EXPLICIT_EMPTY").unwrap(), "");
    assert_eq!(std::env::var("NUM_JOBS").unwrap(), "1");
    assert_eq!(std::env::var("MAKEFLAGS").unwrap(), std::env::var("CARGO_MAKEFLAGS").unwrap());
    assert_eq!(std::env::var("HOME").unwrap(), "/__rabs/home");
    println!("context-ok");
}
"#).unwrap();
    let request = CanonicalExecRequest {
        request_id: 424_244,
        program: "sh".into(),
        args: vec!["-eu".into(), "-c".into(),
            "/__rabs/toolchain/bin/rustc --edition=2024 src/main.rs -o /__rabs/workspace/context-check; exec /__rabs/workspace/context-check".into()],
        toolchain_backing: toolchain.to_str().unwrap().into(),
        workspace_backing: workspace.path().to_str().unwrap().into(),
        jobserver_grant: Some(1),
        command_context: CommandContext::new("/__rabs/workspace/member", vec![
            ("CARGO_PKG_NAME".into(), "context-member".into()),
            ("CARGO_PKG_VERSION".into(), "9.8.7".into()),
            ("EXACT_CONTEXT".into(), "spaces \"quotes\" $HOME\n雪".into()),
            ("EXPLICIT_EMPTY".into(), String::new()),
        ]).unwrap(),
    };
    let original = request.clone();
    let control = ExecutionControl::new(std::time::Duration::from_secs(60)).unwrap();
    let result = execute_canonical_controlled(&request, cargo_home.path(), home.path(), 4, spills.path(), &control);
    assert!(result.executed, "{result:?}");
    assert_eq!(result.exit_code, 0, "{result:?}");
    assert_eq!(result.residual_group_members, 0);
    assert_eq!(result.stdout_sha256, sha256_hex(b"context-ok\n"));
    assert!(workspace.path().join("context-check").is_file());
    assert_eq!(request, original, "execution does not rewrite the declared context");
}
