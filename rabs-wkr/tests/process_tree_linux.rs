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

use rabs_sandbox::process_context::CommandContext;
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

fn link_or_copy(src: &std::path::Path, dst: &std::path::Path) {
    if std::fs::hard_link(src, dst).is_err() {
        std::fs::copy(src, dst).unwrap();
    }
}

fn stage_minimal_rustc(host_toolchain: &std::path::Path) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let staged = tempfile::Builder::new()
        .prefix("rabs-min-rustc-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let root = staged.path();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::create_dir_all(root.join("lib")).unwrap();
    let rustc_src = host_toolchain.join("bin/rustc");
    link_or_copy(&rustc_src, &root.join("bin/rustc"));

    let vv = std::process::Command::new(&rustc_src)
        .arg("-vV")
        .output()
        .expect("rustc -vV");
    let vv_str = String::from_utf8_lossy(&vv.stdout);
    let host_triple = vv_str
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("host triple in rustc -vV")
        .trim();

    for entry in std::fs::read_dir(host_toolchain.join("lib")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if (name_str.starts_with("librustc_driver-") || name_str.starts_with("libLLVM"))
            && entry.file_type().unwrap().is_file()
        {
            link_or_copy(&entry.path(), &root.join("lib").join(&name));
        }
    }

    let rel_target_lib = format!("lib/rustlib/{host_triple}/lib");
    std::fs::create_dir_all(root.join(&rel_target_lib)).unwrap();
    for entry in std::fs::read_dir(host_toolchain.join(&rel_target_lib)).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if (name_str.ends_with(".rlib") || name_str.ends_with(".rmeta"))
            && !name_str.starts_with("libtest-")
            && !name_str.starts_with("libproc_macro-")
            && entry.file_type().unwrap().is_file()
        {
            link_or_copy(&entry.path(), &root.join(&rel_target_lib).join(&name));
        }
    }
    let rel_target_bin = format!("lib/rustlib/{host_triple}/bin");
    for rel_tool in ["rust-lld", "gcc-ld/ld.lld"] {
        let src_tool = host_toolchain.join(&rel_target_bin).join(rel_tool);
        if src_tool.is_file() {
            let dst_tool = root.join(&rel_target_bin).join(rel_tool);
            std::fs::create_dir_all(dst_tool.parent().unwrap()).unwrap();
            link_or_copy(&src_tool, &dst_tool);
        }
    }
    staged
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
            toolchain_identity: None,
            workspace_backing: workspace.path().display().to_string(),
            dependency_context: None,
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
        assert_eq!(
            observed.len(),
            3,
            "only both auth channels and the granted capacity"
        );
        assert_eq!(observed["MAKEFLAGS"], observed["CARGO_MAKEFLAGS"]);
        assert!(!observed.contains_key("MFLAGS"));
        assert_eq!(
            observed["NUM_JOBS"],
            expected_grant.to_string(),
            "effective grant replaces host slots"
        );
        let expected_auth = format!("-j{expected_grant} --jobserver-auth=fifo:/__rabs/home/");
        let relative = observed["MAKEFLAGS"]
            .strip_prefix(expected_auth.as_str())
            .expect("worker auth points into the bound bridge directory");
        let (directory, fifo_name) = relative
            .split_once('/')
            .expect("private directory and FIFO");
        assert!(directory.starts_with(".rabs-jobserver-"));
        assert!(fifo_name.starts_with("rabs-jobserver-"));
        assert!(fifo_name.ends_with(".fifo"));
        assert!(!fifo_name.contains('/'));
        assert!(
            !home.path().join(relative).exists(),
            "resolved attempt releases its fifo"
        );
        assert!(
            !home.path().join(directory).exists(),
            "private runtime directory is retired"
        );
        assert!(
            !workspace.path().join(".rabs-jobserver").exists(),
            "jobserver setup does not edit source"
        );
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
        toolchain_identity: None,
        workspace_backing: workspace.path().display().to_string(),
        dependency_context: None,
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
    if !namespace_supported() {
        return;
    }
    let cargo =
        std::fs::canonicalize(std::env::var_os("CARGO").expect("Cargo supplies its path")).unwrap();
    let host_toolchain = cargo
        .parent()
        .and_then(std::path::Path::parent)
        .expect("toolchain/bin/cargo");
    let staged_toolchain = stage_minimal_rustc(host_toolchain);
    let toolchain = staged_toolchain.path();
    let workspace = tempfile::tempdir().unwrap();
    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let spills = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(workspace.path().join("member/src")).unwrap();
    // env! executes in the REAL compiler process, not a scripted result.
    // The compiled program independently checks the runtime cwd/environment.
    std::fs::write(
        workspace.path().join("member/src/main.rs"),
        r#"
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
"#,
    )
    .unwrap();
    let request = CanonicalExecRequest {
        request_id: 424_244,
        program: "sh".into(),
        args: vec!["-eu".into(), "-c".into(),
            "/__rabs/toolchain/bin/rustc --edition=2024 src/main.rs -o /__rabs/workspace/context-check; exec /__rabs/workspace/context-check".into()],
        toolchain_backing: toolchain.to_str().unwrap().into(),
        toolchain_identity: None,
        workspace_backing: workspace.path().to_str().unwrap().into(),
        dependency_context: None,
        jobserver_grant: Some(1),
        command_context: CommandContext::new("/__rabs/workspace/member", vec![
            ("CARGO_PKG_NAME".into(), "context-member".into()),
            ("CARGO_PKG_VERSION".into(), "9.8.7".into()),
            ("EXACT_CONTEXT".into(), "spaces \"quotes\" $HOME\n雪".into()),
            ("EXPLICIT_EMPTY".into(), String::new()),
        ]).unwrap(),
    };
    let original = request.clone();
    let control = ExecutionControl::new(std::time::Duration::from_secs(120)).unwrap();
    let result = execute_canonical_controlled(
        &request,
        cargo_home.path(),
        home.path(),
        4,
        spills.path(),
        &control,
    );
    assert!(result.executed, "{result:?}");
    assert_eq!(result.exit_code, 0, "{result:?}");
    assert_eq!(result.residual_group_members, 0);
    assert_eq!(result.stdout_sha256, sha256_hex(b"context-ok\n"));
    assert!(workspace.path().join("context-check").is_file());
    assert_eq!(
        request, original,
        "execution does not rewrite the declared context"
    );
}

fn wait_dependency_execution(
    mut task: rabs_wkr::execution::ExecutionTask,
) -> Result<rabs_wkr::execution::ExecutionCompletion, String> {
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};

    struct Signal(std::thread::Thread);
    impl Wake for Signal {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Signal(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(task.wait());
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
        assert!(
            Instant::now() < deadline,
            "dependency worker execution timed out"
        );
        std::thread::park_timeout(Duration::from_millis(10));
    }
}

/// A real rustc invocation, retained source owner, pinned toolchain lease,
/// private output capture and the dependency-exec-v4 alias namespace. The sealed
/// source bundle uses package/ while rustc retains its original source paths.
/// This exercises the worker executor; authenticated transport is covered by
/// its session tests.
#[test]
fn real_dependency_rustc_preserves_paths_env_and_stock_metadata() {
    use rabs_sandbox::dependency_context::DependencyExecContext;
    use rabs_sandbox::runtime_cohort::observe_runtime_cohort;
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use rabs_sandbox::toolchain_dataset::{ToolchainLimits, fingerprint_toolchain};
    use rabs_wkr::artifacts::ArtifactPlan;
    use rabs_wkr::execution::ExecutionTask;
    use rabs_wkr::session::execute_uploaded_canonical_controlled;
    use rabs_wkr::source_transfer::{SourceTransferState, hex};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::path::Path;
    use std::time::Duration;

    if !namespace_supported() {
        return;
    }
    let cargo =
        std::fs::canonicalize(std::env::var_os("CARGO").expect("Cargo supplies its path")).unwrap();
    let host_toolchain = cargo.parent().and_then(Path::parent).unwrap();
    let toolchain = stage_minimal_rustc(host_toolchain);
    let identity =
        fingerprint_toolchain(toolchain.path(), &ToolchainLimits::default(), || false).unwrap();
    let source = tempfile::tempdir().unwrap();
    let output_owner = tempfile::tempdir().unwrap();
    let out = output_owner.path().join("target/debug/deps");
    std::fs::create_dir_all(&out).unwrap();
    let loader_parent = out.parent().unwrap().to_path_buf();
    let empty_search = tempfile::tempdir().unwrap();
    std::fs::create_dir(source.path().join("src")).unwrap();
    let files: [(&str, &[u8]); 2] = [
        (
            "src/lib.rs",
            br#"pub const FLAVOR: &str = env!("DEPENDENCY_FLAVOR");
pub const JOBS: Option<&str> = option_env!("NUM_JOBS");
pub const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");
pub const HERE: &str = file!();
pub const INCLUDED: &str = include_str!("message.txt");
"#,
        ),
        ("src/message.txt", b"immutable included source\n"),
    ];
    for (name, bytes) in files {
        std::fs::write(source.path().join(name), bytes).unwrap();
    }
    // Only the transfer layout changes. Both compilers still observe the
    // original source directory and unchanged relative compiler arguments.
    let manifest = SourceManifest::new(
        files
            .iter()
            .map(|(path, bytes)| SourceFile {
                path: format!("package/{path}"),
                len: bytes.len() as u64,
                sha256: Sha256::digest(bytes).into(),
                executable: false,
            })
            .collect(),
    )
    .unwrap();
    let manifest_json = json!({
        "manifest_sha256":hex(&manifest.digest()),
        "files":files.iter().map(|(path, bytes)| json!({
            "path":format!("package/{path}"),"bytes":bytes.len(),
            "sha256":hex(&Sha256::digest(bytes)),"executable":false,
        })).collect::<Vec<_>>(),
    });
    let visible_toolchain = toolchain.path().to_str().unwrap().to_owned();
    let compiler = toolchain
        .path()
        .join("bin/rustc")
        .to_str()
        .unwrap()
        .to_owned();
    let visible_source = source.path().to_str().unwrap().to_owned();
    let visible_out = out.as_path().to_str().unwrap().to_owned();
    let visible_empty = empty_search.path().to_str().unwrap().to_owned();
    let loader = toolchain.path().join("lib");
    let cohort = observe_runtime_cohort(
        Path::new(&compiler),
        toolchain.path(),
        std::slice::from_ref(&loader),
        out.as_path(),
    )
    .unwrap();
    let args = vec![
        "--crate-name".to_owned(),
        "dependency_fixture".to_owned(),
        "--crate-type".to_owned(),
        "lib".to_owned(),
        "--edition=2024".to_owned(),
        "--emit=dep-info,metadata".to_owned(),
        "-L".to_owned(),
        format!("dependency={visible_out}"),
        "-L".to_owned(),
        format!("dependency={visible_empty}"),
        "--out-dir".to_owned(),
        visible_out.clone(),
        "src/lib.rs".to_owned(),
    ];
    for (iteration, number) in [None, Some(""), Some("19")].into_iter().enumerate() {
        let mut env = vec![
            ("CARGO_MANIFEST_DIR".to_owned(), visible_source.clone()),
            (
                "DEPENDENCY_FLAVOR".to_owned(),
                "spaces \"quotes\" $HOME\n雪".to_owned(),
            ),
            (
                "LD_LIBRARY_PATH".to_owned(),
                format!(
                    "{}:{}:{}",
                    out.display(),
                    loader_parent.display(),
                    loader.display()
                ),
            ),
        ];
        if let Some(number) = number {
            env.push(("NUM_JOBS".to_owned(), number.to_owned()));
        }
        let stock = std::process::Command::new(&compiler)
            .args(&args)
            .env_clear()
            .envs(env.iter().map(|(name, value)| (name, value)))
            .current_dir(source.path())
            .output()
            .unwrap();
        assert!(
            stock.status.success(),
            "{}",
            String::from_utf8_lossy(&stock.stderr)
        );
        let expected = ["dependency_fixture.d", "libdependency_fixture.rmeta"]
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    std::fs::read(out.as_path().join(name)).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let request_id = 425_000 + iteration as u64;
        let wire = json!({"kind":"canonical-exec","request_id":request_id,"source_manifest":manifest_json});
        let mut transfer = SourceTransferState::default();
        transfer
            .handle(
                &json!({"kind":"source-begin","request_id":request_id,"manifest":manifest_json}),
                true,
                false,
            )
            .unwrap();
        for (name, bytes) in files {
            transfer
                .handle(
                    &json!({"kind":"source-chunk","request_id":request_id,
                "manifest_sha256":hex(&manifest.digest()),"path":format!("package/{name}"),
                "offset":0,"data_hex":hex(bytes),
                "chunk_sha256":hex(&Sha256::digest(bytes))}),
                    true,
                    false,
                )
                .unwrap();
        }
        transfer
            .handle(
                &json!({"kind":"source-seal","request_id":request_id,
            "manifest_sha256":hex(&manifest.digest())}),
                true,
                false,
            )
            .unwrap();
        let source_owner = transfer.take_prepared(&wire).unwrap().unwrap();
        let context = DependencyExecContext::new_with_loader_dirs(
            visible_source.clone(),
            visible_source.clone(),
            visible_toolchain.clone(),
            compiler.clone(),
            visible_out.clone(),
            vec![visible_out.clone(), visible_empty.clone()],
            vec![
                visible_out.clone(),
                loader_parent.to_str().unwrap().to_owned(),
            ],
            env,
            cohort.bytes,
        )
        .unwrap();
        assert!(
            context.artifact_roots().is_empty(),
            "the leaf constructor must select an explicit empty artifact closure"
        );
        let request = CanonicalExecRequest {
            request_id,
            program: compiler.clone(),
            args: args.clone(),
            command_context: CommandContext::default(),
            dependency_context: Some(context),
            toolchain_backing: visible_toolchain.clone(),
            toolchain_identity: Some(identity),
            workspace_backing: String::new(),
            jobserver_grant: Some(3),
        };
        let cargo_home = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let spills = tempfile::tempdir().unwrap();
        let task = ExecutionTask::spawn_with_artifacts(
            request_id,
            Duration::from_secs(240),
            ArtifactPlan::new(
                "dependency-fixture".into(),
                expected.iter().map(|(name, _)| name.clone()).collect(),
            )
            .unwrap(),
            move |control| {
                control.request_output_capture();
                execute_uploaded_canonical_controlled(
                    &request,
                    cargo_home.path(),
                    home.path(),
                    4,
                    spills.path(),
                    &control,
                    &source_owner,
                )
            },
        )
        .unwrap();
        let mut completion = wait_dependency_execution(task).expect("complete worker execution");
        assert!(completion.result.executed, "{:?}", completion.result);
        assert_eq!(completion.result.exit_code, 0);
        assert_eq!(completion.result.residual_group_members, 0);
        let captured = completion
            .artifacts
            .as_mut()
            .expect("private artifact capture");
        for (name, bytes) in expected {
            assert_eq!(
                captured.read_chunk(&name, 0, bytes.len()).unwrap(),
                bytes,
                "{name} differs from stock rustc"
            );
            assert_eq!(
                std::fs::read(out.as_path().join(&name)).unwrap(),
                bytes,
                "worker must not write the subscriber output directory"
            );
        }
    }
}

/// Direct and transitive dependency bytes must remain readable when Cargo's
/// input search root is also this action's output directory. Stock and worker
/// receive identical rustc arguments; only private backing paths differ.
#[test]
fn real_dependency_rustc_reads_shared_output_metadata_dag() {
    use rabs_sandbox::dependency_context::{DependencyArtifactRoot, DependencyExecContext};
    use rabs_sandbox::runtime_cohort::observe_runtime_cohort;
    use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SourceFile, SourceManifest};
    use rabs_sandbox::toolchain_dataset::{ToolchainLimits, fingerprint_toolchain};
    use rabs_wkr::artifacts::ArtifactPlan;
    use rabs_wkr::execution::ExecutionTask;
    use rabs_wkr::output::MAX_OUTPUT_CHUNK_BYTES;
    use rabs_wkr::session::{execute_uploaded_canonical_controlled, sha256_hex};
    use rabs_wkr::source_transfer::{SourceTransferState, hex};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    if !namespace_supported() {
        return;
    }
    let cargo =
        std::fs::canonicalize(std::env::var_os("CARGO").expect("Cargo supplies its path")).unwrap();
    let host_toolchain = cargo.parent().and_then(Path::parent).unwrap();
    let toolchain = stage_minimal_rustc(host_toolchain);
    let identity =
        fingerprint_toolchain(toolchain.path(), &ToolchainLimits::default(), || false).unwrap();
    let compiler = toolchain.path().join("bin/rustc");
    let loader = toolchain.path().join("lib");
    let source = tempfile::tempdir().unwrap();
    let upstream_source = tempfile::tempdir().unwrap();
    let output_owner = tempfile::tempdir().unwrap();
    let out = output_owner.path().join("target/debug/deps");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir(source.path().join("src")).unwrap();
    std::fs::write(
        upstream_source.path().join("leaf.rs"),
        "pub struct Token(pub u32);\n",
    )
    .unwrap();
    std::fs::write(
        upstream_source.path().join("middle.rs"),
        "pub use dag_leaf::Token;\npub fn token() -> Token { Token(42) }\n",
    )
    .unwrap();
    // Top has no direct --extern for leaf. Resolving the field on Token and
    // its public return type requires the transitive crate metadata.
    let top_source = br#"pub fn answer() -> u32 { dag_middle::token().0 }
pub fn token() -> dag_middle::Token { dag_middle::token() }
pub const FLAVOR: &str = env!("SHARED_DAG_FLAVOR");
pub const SOURCE: &str = file!();
"#;
    std::fs::write(source.path().join("src/lib.rs"), top_source).unwrap();

    for (name, file) in [("dag_leaf", "leaf.rs"), ("dag_middle", "middle.rs")] {
        let mut command = Command::new(&compiler);
        command
            .arg(format!("--crate-name={name}"))
            .args([
                "--crate-type=rlib",
                "--edition=2024",
                "--emit=link,metadata",
            ])
            .arg(format!("--out-dir={}", out.display()))
            .arg(upstream_source.path().join(file))
            .env_clear()
            .env("LD_LIBRARY_PATH", &loader)
            .stdin(Stdio::null());
        if name == "dag_middle" {
            command
                .args(["-L", &format!("dependency={}", out.display())])
                .args([
                    "--extern",
                    &format!("dag_leaf={}", out.join("libdag_leaf.rmeta").display()),
                ]);
        }
        let produced = command.output().unwrap();
        assert!(
            produced.status.success(),
            "compile real {name}: {}",
            String::from_utf8_lossy(&produced.stderr)
        );
    }
    let loader_parent = out.parent().unwrap();
    let visible_out = out.to_str().unwrap().to_owned();
    let cohort = observe_runtime_cohort(
        &compiler,
        toolchain.path(),
        std::slice::from_ref(&loader),
        &out,
    )
    .unwrap();

    for (iteration, direct_kind) in ["rmeta", "rlib"].into_iter().enumerate() {
        let args = vec![
            "--crate-name=dag_top".to_owned(),
            "--crate-type=lib".to_owned(),
            "--edition=2024".to_owned(),
            "--emit=dep-info,metadata".to_owned(),
            "--error-format=json".to_owned(),
            "--json=artifacts".to_owned(),
            "--cap-lints=allow".to_owned(),
            "-L".to_owned(),
            format!("dependency={visible_out}"),
            "--extern".to_owned(),
            format!(
                "dag_middle={}",
                out.join(format!("libdag_middle.{direct_kind}")).display()
            ),
            "--out-dir".to_owned(),
            visible_out.clone(),
            "src/lib.rs".to_owned(),
        ];
        let env = vec![
            (
                "CARGO_MANIFEST_DIR".to_owned(),
                source.path().to_str().unwrap().to_owned(),
            ),
            (
                "SHARED_DAG_FLAVOR".to_owned(),
                "retained DAG inputs".to_owned(),
            ),
            (
                "LD_LIBRARY_PATH".to_owned(),
                format!(
                    "{}:{}:{}",
                    out.display(),
                    loader_parent.display(),
                    loader.display()
                ),
            ),
        ];
        let stock = Command::new(&compiler)
            .args(&args)
            .env_clear()
            .envs(env.iter().map(|(name, value)| (name, value)))
            .current_dir(source.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            stock.status.success(),
            "stock {direct_kind} consumer: {}",
            String::from_utf8_lossy(&stock.stderr)
        );
        assert!(
            !stock.stderr.is_empty(),
            "real rustc must emit artifact notifications"
        );
        let expected: BTreeMap<_, _> = ["dag_top.d", "libdag_top.rmeta"]
            .into_iter()
            .map(|name| (name.to_owned(), std::fs::read(out.join(name)).unwrap()))
            .collect();
        let retained = BTreeMap::from([
            ("package/src/lib.rs".to_owned(), top_source.to_vec()),
            (
                "dependencies/0000/libdag_leaf.rmeta".to_owned(),
                std::fs::read(out.join("libdag_leaf.rmeta")).unwrap(),
            ),
            (
                "dependencies/0000/libdag_leaf.rlib".to_owned(),
                std::fs::read(out.join("libdag_leaf.rlib")).unwrap(),
            ),
            (
                "dependencies/0000/libdag_middle.rmeta".to_owned(),
                std::fs::read(out.join("libdag_middle.rmeta")).unwrap(),
            ),
            (
                "dependencies/0000/libdag_middle.rlib".to_owned(),
                std::fs::read(out.join("libdag_middle.rlib")).unwrap(),
            ),
        ]);
        let manifest = SourceManifest::new(
            retained
                .iter()
                .map(|(path, bytes)| SourceFile {
                    path: path.clone(),
                    len: bytes.len() as u64,
                    sha256: Sha256::digest(bytes).into(),
                    executable: false,
                })
                .collect(),
        )
        .unwrap();
        let manifest_json = json!({
            "manifest_sha256":hex(&manifest.digest()),
            "files":retained.iter().map(|(path, bytes)| json!({
                "path":path,"bytes":bytes.len(),"sha256":hex(&Sha256::digest(bytes)),
                "executable":false,
            })).collect::<Vec<_>>(),
        });
        let request_id = 426_000 + iteration as u64;
        let wire = json!({"kind":"canonical-exec", "request_id":request_id,
            "source_manifest":manifest_json});
        let mut transfer = SourceTransferState::default();
        transfer
            .handle(
                &json!({"kind":"source-begin","request_id":request_id,
            "manifest":manifest_json}),
                true,
                false,
            )
            .unwrap();
        for (path, bytes) in &retained {
            for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
                transfer
                    .handle(
                        &json!({"kind":"source-chunk","request_id":request_id,
                    "manifest_sha256":hex(&manifest.digest()),"path":path,
                    "offset":index * MAX_SOURCE_CHUNK,"data_hex":hex(chunk),
                    "chunk_sha256":hex(&Sha256::digest(chunk))}),
                        true,
                        false,
                    )
                    .unwrap();
            }
        }
        transfer
            .handle(
                &json!({"kind":"source-seal","request_id":request_id,
            "manifest_sha256":hex(&manifest.digest())}),
                true,
                false,
            )
            .unwrap();
        let source_owner = transfer.take_prepared(&wire).unwrap().unwrap();
        let context = DependencyExecContext::new_with_artifacts(
            source.path().to_str().unwrap().to_owned(),
            source.path().to_str().unwrap().to_owned(),
            toolchain.path().to_str().unwrap().to_owned(),
            compiler.to_str().unwrap().to_owned(),
            visible_out.clone(),
            vec![visible_out.clone()],
            vec![
                visible_out.clone(),
                loader_parent.to_str().unwrap().to_owned(),
            ],
            vec![DependencyArtifactRoot {
                path: visible_out.clone(),
                prefix: "dependencies/0000".to_owned(),
            }],
            env,
            cohort.bytes,
        )
        .unwrap();
        let request = CanonicalExecRequest {
            request_id,
            program: compiler.to_str().unwrap().to_owned(),
            args: args.clone(),
            command_context: CommandContext::default(),
            dependency_context: Some(context),
            toolchain_backing: toolchain.path().to_str().unwrap().to_owned(),
            toolchain_identity: Some(identity),
            workspace_backing: String::new(),
            jobserver_grant: Some(2),
        };
        let cargo_home = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let spills = tempfile::tempdir().unwrap();
        let task = ExecutionTask::spawn_with_artifacts(
            request_id,
            Duration::from_secs(240),
            ArtifactPlan::new(
                "shared-dependency-dag".to_owned(),
                expected.keys().cloned().collect(),
            )
            .unwrap(),
            move |control| {
                control.request_output_capture();
                execute_uploaded_canonical_controlled(
                    &request,
                    cargo_home.path(),
                    home.path(),
                    4,
                    spills.path(),
                    &control,
                    &source_owner,
                )
            },
        )
        .unwrap();
        let mut completion =
            wait_dependency_execution(task).expect("shared dependency worker completion");
        assert!(completion.result.executed, "{:?}", completion.result);
        assert_eq!(completion.result.exit_code, 0, "{:?}", completion.result);
        assert_eq!(completion.result.residual_group_members, 0);
        assert_eq!(completion.stop_reason, None);
        assert_eq!(completion.result.stdout_sha256, sha256_hex(&stock.stdout));
        assert_eq!(completion.result.stderr_sha256, sha256_hex(&stock.stderr));
        let streams = completion
            .outputs
            .as_mut()
            .expect("captured compiler diagnostics");
        assert!(stock.stderr.len() <= MAX_OUTPUT_CHUNK_BYTES);
        assert_eq!(
            streams
                .stdout
                .read_chunk(0, MAX_OUTPUT_CHUNK_BYTES)
                .unwrap(),
            stock.stdout
        );
        assert_eq!(
            streams
                .stderr
                .read_chunk(0, MAX_OUTPUT_CHUNK_BYTES)
                .unwrap(),
            stock.stderr
        );
        let captured = completion
            .artifacts
            .as_mut()
            .expect("exact private output capture");
        let captured_manifest = captured.manifest();
        let names = captured_manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["dag_top.d", "libdag_top.rmeta"],
            "retained inputs and their mount placeholders must not be returned as outputs"
        );
        for (name, bytes) in &expected {
            assert_eq!(
                captured.read_chunk(name, 0, bytes.len()).unwrap(),
                *bytes,
                "{direct_kind} consumer {name} differs from stock"
            );
            assert_eq!(
                std::fs::read(out.join(name)).unwrap(),
                *bytes,
                "worker must not change the caller's output tree"
            );
        }
        for (path, bytes) in retained
            .iter()
            .filter(|(path, _)| path.starts_with("dependencies/"))
        {
            let name = path.rsplit('/').next().unwrap();
            assert!(
                captured.read_chunk(name, 0, 1).is_err(),
                "input {name} leaked into output capture"
            );
            assert_eq!(
                std::fs::read(out.join(name)).unwrap(),
                *bytes,
                "worker must not change original dependency {name}"
            );
        }
    }
}

mod toolchain_binding {
    use super::namespace_supported;
    use rabs_sandbox::toolchain_dataset::{
        TOOLCHAIN_DATASET_VERSION, ToolchainIdentity, ToolchainLimits, fingerprint_toolchain,
    };
    use serde_json::{Value, json};
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const ORIGINAL: &[u8] = b"#!/bin/sh\nprintf 'toolchain-v1\\n'\n";
    const REPLACEMENT: &[u8] = b"#!/bin/sh\nprintf 'toolchain-v2\\n'\n";

    struct Worker {
        child: Child,
        reader: Option<BufReader<TcpStream>>,
    }

    impl Worker {
        fn connect(root: &Path) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_rabs-wkr"));
            command.args([
                "--coordinator",
                &listener.local_addr().unwrap().to_string(),
                "--worker-id",
                "toolchain-binding-test",
                "--once",
            ]);
            for name in [
                "RABS_WORKER_TLS_CA",
                "RABS_WORKER_TLS_CERT",
                "RABS_WORKER_TLS_KEY",
                "RABS_WORKER_TLS_SERVER_NAME",
            ] {
                command.env_remove(name);
            }
            let child = command
                .env("RABS_WORKER_STATE_DIR", root.join("worker-state"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("start the production worker");
            // Install cleanup ownership before any fallible handshake work.
            let mut worker = Self {
                child,
                reader: None,
            };
            let deadline = Instant::now() + Duration::from_secs(20);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            worker.child.try_wait().unwrap().is_none(),
                            "worker exited before handshake"
                        );
                        assert!(Instant::now() < deadline, "worker connection deadline");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept production worker: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            worker.reader = Some(BufReader::new(stream));
            let hello = worker.receive();
            assert_eq!(hello["kind"], "worker-hello", "{hello}");
            assert_eq!(hello["canonical"], true, "{hello}");
            assert_eq!(
                hello["toolchain_datasets"],
                json!([TOOLCHAIN_DATASET_VERSION])
            );
            worker.send(&json!({"kind": "session-ok"}));
            worker
        }

        fn send(&mut self, frame: &Value) {
            writeln!(self.reader.as_mut().unwrap().get_mut(), "{frame}").unwrap();
        }

        fn receive(&mut self) -> Value {
            let mut line = String::new();
            assert_ne!(
                self.reader.as_mut().unwrap().read_line(&mut line).unwrap(),
                0,
                "worker closed before its result"
            );
            serde_json::from_str(&line).expect("worker JSON frame")
        }

        fn wait_for_marker(&mut self, marker: &Path) {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !marker.is_file() {
                if let Some(status) = self.child.try_wait().unwrap() {
                    panic!(
                        "worker exited before toolchain observation: {status}; {}",
                        self.receive()
                    );
                }
                assert!(
                    Instant::now() < deadline,
                    "action did not reach its toolchain observation barrier"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn finish(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "worker exit: {status}");
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "one-shot worker did not exit after result"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for Worker {
        fn drop(&mut self) {
            if let Some(reader) = &mut self.reader {
                let _ = reader.get_mut().shutdown(Shutdown::Both);
            }
            // EOF gives the execution owner an opportunity to cancel and reap
            // its group even when the test panics before releasing the barrier.
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.child.try_wait().ok().flatten().is_none() {
                if Instant::now() >= deadline {
                    let _ = self.child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = self.child.wait();
        }
    }

    fn toolchain(root: &Path) -> ToolchainIdentity {
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/probe"), ORIGINAL).unwrap();
        fs::set_permissions(root.join("bin/probe"), fs::Permissions::from_mode(0o755)).unwrap();
        fingerprint_toolchain(root, &ToolchainLimits::default(), || false).unwrap()
    }

    fn identity_value(identity: &ToolchainIdentity) -> Value {
        let sha256: String = identity
            .sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        json!({"version": TOOLCHAIN_DATASET_VERSION, "sha256": sha256,
            "files": identity.files, "bytes": identity.bytes})
    }

    fn request(toolchain: &Path, workspace: &Path, script: &str) -> Value {
        json!({"kind": "canonical-exec", "request_id": 1, "timeout_ms": 30_000,
            "program": "sh", "args": ["-eu", "-c", script], "jobserver_grant": 1,
            "toolchain_backing": toolchain, "workspace_backing": workspace})
    }

    #[test]
    fn production_worker_retains_toolchain_bytes_with_and_without_expected_identity() {
        if !namespace_supported() {
            return;
        }
        for pinned in [false, true] {
            let owner = tempfile::tempdir().unwrap();
            let source = owner.path().join("mutable-toolchain");
            let workspace = owner.path().join("workspace");
            fs::create_dir(&workspace).unwrap();
            let expected = toolchain(&source);
            let mut frame = request(
                &source,
                &workspace,
                "printf ready > /__rabs/workspace/ready; \
                 attempts=0; while [ ! -f /__rabs/workspace/continue ]; do \
                 attempts=$((attempts + 1)); [ \"$attempts\" -lt 1000 ] || exit 72; sleep 0.01; done; \
                 exec /__rabs/toolchain/bin/probe",
            );
            if pinned {
                frame["toolchain_identity"] = identity_value(&expected);
            }
            let mut worker = Worker::connect(owner.path());
            worker.send(&frame);
            // The actual namespaced action reaches this barrier only AFTER
            // toolchain admission/copy, but has not yet opened the compiler.
            worker.wait_for_marker(&workspace.join("ready"));
            let before_mode = fs::metadata(source.join("bin/probe"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(ORIGINAL.len(), REPLACEMENT.len());
            fs::write(source.join("bin/probe"), REPLACEMENT).unwrap();
            assert_eq!(
                fs::metadata(source.join("bin/probe"))
                    .unwrap()
                    .permissions()
                    .mode(),
                before_mode
            );
            assert_ne!(
                fingerprint_toolchain(&source, &ToolchainLimits::default(), || false).unwrap(),
                expected
            );
            fs::write(workspace.join("continue"), b"run retained compiler").unwrap();
            let result = worker.receive();
            assert_eq!(result["kind"], "exec-result", "pinned={pinned}: {result}");
            assert_eq!(result["request_id"], 1);
            assert_eq!(result["executed"], true, "{result}");
            assert_eq!(result["exit_code"], 0, "{result}");
            assert_eq!(result["residual_group_members"], 0, "{result}");
            assert_eq!(
                result["stdout_sha256"],
                rabs_wkr::session::sha256_hex(b"toolchain-v1\n"),
                "the production worker must execute retained bytes, pinned={pinned}"
            );
            assert_eq!(fs::read(source.join("bin/probe")).unwrap(), REPLACEMENT);
            worker.finish();
        }
    }

    #[test]
    fn production_worker_rejects_changed_toolchain_content_or_mode_before_spawn() {
        if !namespace_supported() {
            return;
        }
        for change in [
            "equal-size-content",
            "executable-mode",
            "declared-files",
            "declared-bytes",
        ] {
            let owner = tempfile::tempdir().unwrap();
            let source = owner.path().join("mutable-toolchain");
            let workspace = owner.path().join("workspace");
            fs::create_dir(&workspace).unwrap();
            let expected = toolchain(&source);
            let mut frame = request(
                &source,
                &workspace,
                "printf launched > /__rabs/workspace/launched; exec /__rabs/toolchain/bin/probe",
            );
            frame["toolchain_identity"] = identity_value(&expected);
            match change {
                "equal-size-content" => {
                    assert_eq!(ORIGINAL.len(), REPLACEMENT.len());
                    fs::write(source.join("bin/probe"), REPLACEMENT).unwrap();
                    assert_eq!(
                        fs::metadata(source.join("bin/probe"))
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                        0o755
                    );
                }
                "executable-mode" => {
                    fs::set_permissions(source.join("bin/probe"), fs::Permissions::from_mode(0o644))
                        .unwrap()
                }
                "declared-files" => {
                    frame["toolchain_identity"]["files"] = json!(expected.files + 1)
                }
                "declared-bytes" => {
                    frame["toolchain_identity"]["bytes"] = json!(expected.bytes + 1)
                }
                _ => unreachable!(),
            }
            let mut worker = Worker::connect(owner.path());
            worker.send(&frame);
            let result = worker.receive();
            assert_eq!(result["kind"], "error", "{change}: {result}");
            assert_eq!(result["request_id"], 1);
            assert_eq!(
                result["stage"], "execution-completion",
                "{change}: {result}"
            );
            assert!(
                result["reason"]
                    .as_str()
                    .unwrap()
                    .contains("toolchain identity does not match expected dataset"),
                "{change}: {result}"
            );
            assert!(
                !workspace.join("launched").exists(),
                "{change}: rejected toolchain still launched a process"
            );
            worker.finish();
        }
    }
}
