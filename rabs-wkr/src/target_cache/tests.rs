use super::*;
use crate::execution::{ExecutionCompletion, ExecutionTask, StopReason};
use crate::session::ExecResult;
use rabs_sandbox::canonical_namespace::Bind;
use rabs_sandbox::process_context::CommandContext;
use rabs_sandbox::source_transfer::SourceFile;
use rabs_sandbox::toolchain_dataset::ToolchainIdentity;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

#[path = "persistence_tests.rs"]
mod persistence_tests;

fn inputs(root: &Path, names: &[&str]) -> WorkspaceInputs {
    let files = names
        .iter()
        .map(|name| {
            let bytes = fs::read(root.join(name)).unwrap();
            SourceFile {
                path: (*name).to_owned(),
                len: bytes.len() as u64,
                sha256: Sha256::digest(&bytes).into(),
                executable: false,
            }
        })
        .collect();
    let manifest = SourceManifest::new(files).unwrap();
    WorkspaceInputs {
        root: root.to_owned(),
        full_source_digest: manifest.digest(),
        manifest,
        projection: None,
        runtime_owner: None,
    }
}

fn runtime_inputs(root: &Path, names: &[&str]) -> WorkspaceInputs {
    inputs(root, names)
        .private_runtime_clone(&|| false)
        .unwrap()
}

fn fixture_projection(inputs: &WorkspaceInputs, prefix: &str) -> Arc<CargoHomeProjection> {
    let mut files = inputs.manifest.files().to_vec();
    files.push(SourceFile {
        path: format!("{prefix}/registry/cache/example/dep-1.crate"),
        len: 7,
        sha256: Sha256::digest(b"archive").into(),
        executable: false,
    });
    Arc::new(
        CargoHomeProjection::for_version(
            rabs_sandbox::cargo_home::ISOLATED_CARGO_HOME_SOURCE_VERSION,
            prefix,
            &SourceManifest::new(files).unwrap(),
        )
        .unwrap(),
    )
}

fn fixture_request() -> CanonicalExecRequest {
    CanonicalExecRequest {
        request_id: 1,
        program: "/__rabs/toolchain/bin/cargo".to_owned(),
        args: vec![
            "build".to_owned(),
            "--frozen".to_owned(),
            "--offline".to_owned(),
        ],
        command_context: CommandContext::default(),
        dependency_context: None,
        toolchain_backing: "/private/toolchain".to_owned(),
        toolchain_identity: Some(ToolchainIdentity {
            sha256: [1; 32],
            files: 2,
            bytes: 3,
        }),
        workspace_backing: "/private/workspace".to_owned(),
        jobserver_grant: Some(1),
    }
}

fn cargo_request(command: &str, options: &[&str]) -> (CanonicalExecRequest, ArtifactPlan) {
    use rabs_sandbox::cargo_artifacts::{
        CARGO_ARTIFACTS_VERSION, CARGO_RUN_ARTIFACTS_VERSION, CARGO_TEST_ARTIFACTS_VERSION,
    };
    let mut request = fixture_request();
    if command == "clippy" {
        request.program = "/__rabs/toolchain/bin/cargo-clippy".to_owned();
        request.command_context = CommandContext::new(
            "/__rabs/workspace",
            vec![
                ("CARGO".to_owned(), "/__rabs/toolchain/bin/cargo".to_owned()),
                ("RUSTC".to_owned(), "/__rabs/toolchain/bin/rustc".to_owned()),
            ],
        )
        .unwrap();
    }
    request.args = [
        command,
        "--frozen",
        "--offline",
        "--message-format=json",
        "--target-dir=/__rabs/out/cargo",
        "--jobs=1",
    ]
    .into_iter()
    .chain(options.iter().copied())
    .map(str::to_owned)
    .collect();
    let no_run = options
        .iter()
        .take_while(|option| **option != "--")
        .any(|option| *option == "--no-run");
    let contract = if command == "test" && !no_run {
        CARGO_TEST_ARTIFACTS_VERSION
    } else if command == "run" {
        CARGO_RUN_ARTIFACTS_VERSION
    } else {
        CARGO_ARTIFACTS_VERSION
    };
    let env: BTreeMap<_, _> = request
        .command_context
        .environment()
        .iter()
        .cloned()
        .collect();
    let plan = crate::artifacts::parse_plan(&serde_json::json!({
        "program":request.program, "args":request.args,
        "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace", "env":env},
        "artifacts":{"unit":"cargo", "files":[], "tree":"tree-files-v1", "cargo":contract},
    }))
    .unwrap()
    .unwrap();
    (request, plan)
}

fn fixture_spec(label: &str) -> CanonicalNamespaceSpec {
    let mut spec = CanonicalNamespaceSpec::new();
    spec.ro_binds
        .push(Bind::new("/private/source", "/__rabs/workspace"));
    spec.rw_binds
        .push(Bind::new("/private/target", "/__rabs/out/cargo"));
    spec.env = vec![
        ("CACHE_LABEL".to_owned(), label.to_owned()),
        ("CARGO_INCREMENTAL".to_owned(), "0".to_owned()),
        ("NUM_JOBS".to_owned(), "1".to_owned()),
    ];
    spec
}

fn incremental_request(options: &[&str]) -> (CanonicalExecRequest, ArtifactPlan) {
    use rabs_sandbox::cargo_artifacts::CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION;
    let (mut request, _) = cargo_request("build", options);
    request.command_context = CommandContext::new(
        "/__rabs/workspace",
        vec![("CARGO_INCREMENTAL".into(), "1".into())],
    )
    .unwrap();
    let plan = crate::artifacts::parse_plan(&serde_json::json!({
        "program":request.program, "args":request.args,
        "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace",
            "env":{"CARGO_INCREMENTAL":"1"}},
        "artifacts":{"unit":"cargo", "files":[], "tree":"tree-files-v1",
            "cargo":CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION},
    }))
    .unwrap()
    .unwrap();
    (request, plan)
}

fn support() -> HostIsolationSupport {
    // A pure key-construction fixture, not evidence of native namespace support.
    HostIsolationSupport {
        bubblewrap: Some("key-fixture".to_owned()),
        unprivileged_userns: true,
        overlayfs: false,
        cgroup_v2: false,
        landlock: false,
    }
}

fn scope() -> TargetCacheScope {
    TargetCacheScope::new(
        "worker",
        "coordinator:123",
        &ResultRecipient::TlsSpki([7; 32]),
    )
}

fn small_fixture() -> (
    tempfile::TempDir,
    ArtifactPlan,
    PreparedArtifacts,
    CapturedArtifacts,
) {
    let source = private_directory("rabs-hot-source-test-").unwrap();
    fs::write(source.path().join("lib.rs"), "pub fn answer() {}\n").unwrap();
    fs::set_permissions(
        source.path().join("lib.rs"),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    let plan = ArtifactPlan::new_tree("cargo".to_owned(), vec!["artifact".to_owned()]).unwrap();
    let target = PreparedArtifacts::new(plan.clone()).unwrap();
    fs::write(target.backing().join("artifact"), "seed").unwrap();
    fs::create_dir(target.backing().join("empty-out-dir")).unwrap();
    fs::set_permissions(
        target.backing().join("empty-out-dir"),
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    let captured = target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    (source, plan, target, captured)
}

fn stage_small(
    cache: &Arc<TargetCache>,
    key: TargetKey,
) -> (PendingTargetSeed, ArtifactPlan, CapturedArtifacts) {
    let (source, plan, target, captured) = small_fixture();
    let (attempt, restored) = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    let pending = attempt
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap();
    (pending, plan, captured)
}

#[test]
fn target_key_binds_inputs_scope_toolchain_command_environment_and_grant() {
    let (source, plan, _, _) = small_fixture();
    let mut input = inputs(source.path(), &["lib.rs"]);
    let mut request = fixture_request();
    let mut spec = fixture_spec("first");
    let expected = target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap();
    spec.rw_binds[0].backing = "/different/private/clone".into();
    assert_eq!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 2).unwrap()
    );
    spec.env[0].1 = "second".to_owned();
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    spec.env[0].1 = "first".to_owned();
    spec.cwd = "/__rabs/workspace/member".into();
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    spec.cwd = "/__rabs/workspace".into();
    request.args.push("--release".into());
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    request.args.pop();
    request.toolchain_identity.as_mut().unwrap().sha256[0] ^= 1;
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    request.toolchain_identity.as_mut().unwrap().sha256[0] ^= 1;
    input.projection = Some(fixture_projection(&input, ".captured"));
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    input.projection = None;
    for changed in [
        TargetCacheScope::new(
            "other-worker",
            "coordinator:123",
            &ResultRecipient::TlsSpki([7; 32]),
        ),
        TargetCacheScope::new(
            "worker",
            "other-coordinator:123",
            &ResultRecipient::TlsSpki([7; 32]),
        ),
        TargetCacheScope::new(
            "worker",
            "coordinator:123",
            &ResultRecipient::TlsSpki([8; 32]),
        ),
        TargetCacheScope::new(
            "worker",
            "coordinator:123",
            &ResultRecipient::LoopbackFixture,
        ),
    ] {
        assert_ne!(
            expected,
            target_key(changed, &request, &input, &spec, &support(), &plan, 1).unwrap()
        );
    }
    input.full_source_digest[0] ^= 1;
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
}

#[test]
fn compatible_commands_preserve_compilation_settings_and_runtime_identity() {
    let (source, _, _, _) = small_fixture();
    let input = inputs(source.path(), &["lib.rs"]);
    let spec = fixture_spec("first");
    let (build, plan) = cargo_request("build", &["--workspace"]);
    let compatible = |request: &CanonicalExecRequest, plan: &ArtifactPlan| {
        target_compatibility_key(scope(), request, &input, &spec, &support(), plan, 1).unwrap()
    };
    let expected = compatible(&build, &plan);
    assert!(expected.is_some());
    let exact = target_key(scope(), &build, &input, &spec, &support(), &plan, 1).unwrap();
    for (command, options) in [
        ("check", vec!["--workspace"]),
        ("test", vec!["--workspace", "--no-run"]),
        ("test", vec!["--workspace"]),
        ("test", vec!["--workspace", "--no-fail-fast"]),
        ("test", vec!["--workspace", "one_test", "--", "--exact"]),
        (
            "test",
            vec!["--workspace", "other_test", "--", "--nocapture"],
        ),
        ("build", vec!["--workspace", "--package", "test"]),
        ("build", vec!["--workspace", "--lib"]),
        ("build", vec!["--package=other", "--bins"]),
        ("build", vec!["-p", "other", "--example", "example"]),
        (
            "build",
            vec!["--workspace", "--exclude=other", "--all-targets"],
        ),
        ("test", vec!["--package", "test", "--test=integration"]),
        ("build", vec!["--all", "--benches"]),
        ("build", vec!["--workspace", "--profile", "test"]),
        ("build", vec!["--workspace", "--profile=dev"]),
        ("build", vec!["--workspace", "--features=test"]),
        ("build", vec!["--workspace", "--features", "build"]),
        ("check", vec!["--workspace", "-F", "test"]),
        ("build", vec!["--workspace", "--no-default-features"]),
        ("test", vec!["--workspace", "--all-features"]),
    ] {
        let (request, selected) = cargo_request(command, &options);
        assert_eq!(compatible(&request, &selected), expected, "{options:?}");
        assert_ne!(
            target_key(scope(), &request, &input, &spec, &support(), &selected, 1).unwrap(),
            exact,
            "compatibility must not weaken the exact invocation key"
        );
    }
    for options in [
        vec!["--workspace", "--release"],
        vec!["--workspace", "--target", "x86_64-unknown-linux-gnu"],
        vec!["--workspace", "--profile", "custom"],
        vec!["--workspace", "--manifest-path", "member/Cargo.toml"],
    ] {
        let (request, selected) = cargo_request("build", &options);
        let changed = compatible(&request, &selected);
        assert!(changed.is_some(), "known compiler selection: {options:?}");
        assert_ne!(
            changed, expected,
            "compiler selection collapsed: {options:?}"
        );
    }
    let (mut request, selected) = cargo_request("test", &["--workspace"]);
    for unsupported in [
        "--config",
        "-Zchecksum-freshness",
        "--unknown",
        "--no-run=1",
    ] {
        request.args.push(unsupported.to_owned());
        assert!(compatible(&request, &selected).is_none(), "{unsupported}");
        request.args.pop();
    }
    for command in ["clippy", "doc", "run", "b", "+nightly"] {
        request.args[0] = command.to_owned();
        assert!(compatible(&request, &selected).is_none(), "{command}");
    }
    request.args[0] = "test".to_owned();
    request.program = "/host/bin/cargo".to_owned();
    assert!(compatible(&request, &selected).is_none());
    assert!(compatible(&build, &small_fixture().1).is_none());
    let changed_env = fixture_spec("second");
    assert_ne!(
        target_compatibility_key(scope(), &build, &input, &changed_env, &support(), &plan, 1)
            .unwrap(),
        expected
    );
    assert_ne!(
        target_compatibility_key(scope(), &build, &input, &spec, &support(), &plan, 2).unwrap(),
        expected
    );
    let mut changed = input.clone();
    changed.full_source_digest[0] ^= 1;
    assert_ne!(
        target_compatibility_key(scope(), &build, &changed, &spec, &support(), &plan, 1).unwrap(),
        expected,
        "captured Cargo-home content remains exact"
    );
    changed = input.clone();
    let mut files = changed.manifest.files().to_vec();
    files[0].sha256[0] ^= 1;
    changed.manifest = SourceManifest::new(files).unwrap();
    assert_ne!(
        target_compatibility_key(scope(), &build, &changed, &spec, &support(), &plan, 1).unwrap(),
        expected,
        "command compatibility cannot admit changed workspace bytes"
    );
    changed = input;
    changed.projection = Some(fixture_projection(&changed, "cache"));
    assert_ne!(
        target_compatibility_key(scope(), &build, &changed, &spec, &support(), &plan, 1).unwrap(),
        expected
    );
}

#[test]
fn incremental_mode_projection_profile_and_toolchain_partition_target_keys() {
    let (source, _, _, _) = small_fixture();
    let input = inputs(source.path(), &["lib.rs"]);
    let mut spec = fixture_spec("private-incremental");
    let (request, plan) = incremental_request(&["--workspace"]);
    for (name, value) in &mut spec.env {
        if name == "CARGO_INCREMENTAL" {
            *value = "1".into();
        }
    }
    let keys =
        |request: &CanonicalExecRequest, plan: &ArtifactPlan, spec: &CanonicalNamespaceSpec| {
            (
                target_key(scope(), request, &input, spec, &support(), plan, 1).unwrap(),
                target_compatibility_key(scope(), request, &input, spec, &support(), plan, 1)
                    .unwrap()
                    .unwrap(),
            )
        };
    let expected = keys(&request, &plan, &spec);
    let mut disabled = spec.clone();
    for (name, value) in &mut disabled.env {
        if name == "CARGO_INCREMENTAL" {
            *value = "0".into();
        }
    }
    let mut changed_toolchain = request.clone();
    changed_toolchain
        .toolchain_identity
        .as_mut()
        .unwrap()
        .sha256[0] ^= 1;
    let (release, release_plan) = incremental_request(&["--workspace", "--release"]);
    let (_, full_tree_plan) = cargo_request("build", &["--workspace"]);
    for changed in [
        keys(&request, &plan, &disabled),
        keys(&changed_toolchain, &plan, &spec),
        keys(&release, &release_plan, &spec),
        keys(&request, &full_tree_plan, &spec),
    ] {
        assert_ne!(expected.0, changed.0, "exact target identity collapsed");
        assert_ne!(
            expected.1, changed.1,
            "compatible target identity collapsed"
        );
    }
}

#[test]
fn private_incremental_seed_retains_and_charges_the_complete_target() {
    let source = private_directory("rabs-incremental-source-").unwrap();
    fs::write(source.path().join("lib.rs"), b"pub fn value() {}\n").unwrap();
    let (_, plan) = incremental_request(&[]);
    let target = PreparedArtifacts::new(plan.clone()).unwrap();
    fs::create_dir_all(target.backing().join("debug/deps")).unwrap();
    fs::create_dir_all(target.backing().join("debug/incremental/unit/session")).unwrap();
    fs::write(
        target.backing().join("debug/deps/libapp.rmeta"),
        b"metadata",
    )
    .unwrap();
    let private = "debug/incremental/unit/session/query-cache.bin";
    fs::write(target.backing().join(private), b"private compiler state").unwrap();
    let private_files = rabs_sandbox::artifact_tree::MAX_TREE_FILES;
    for index in 0..private_files {
        fs::write(
            target
                .backing()
                .join(format!("debug/incremental/unit/session/object{index}")),
            b"x",
        )
        .unwrap();
    }
    let report = concat!(
        "{\"reason\":\"compiler-artifact\",\"target\":{\"kind\":[\"lib\"]},",
        "\"filenames\":[\"/__rabs/out/cargo/debug/deps/libapp.rmeta\"],\"executable\":null}\n",
        "{\"reason\":\"build-finished\",\"success\":true}\n",
    );
    let captured = target
        .capture_with_cargo_output(None, report.as_bytes(), || false)
        .unwrap();
    assert_eq!(captured.total_bytes(), 8);
    assert_eq!(
        captured.file_names().collect::<Vec<_>>(),
        ["debug/deps/libapp.rmeta"]
    );
    let total = captured.total_bytes()
        + fs::metadata(target.backing().join(private)).unwrap().len()
        + private_files as u64;
    let too_small = Arc::new(TargetCache::new(total - 1).unwrap());
    let attempt = too_small
        .acquire(
            TargetKey([1; 32]),
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap()
        .0;
    assert!(
        attempt
            .stage(&target, &captured, &|| false)
            .unwrap()
            .is_none()
    );
    assert_eq!(too_small.state.lock().unwrap().reserved_bytes, 0);

    let cache = Arc::new(TargetCache::new(total).unwrap());
    let attempt = cache
        .acquire(
            TargetKey([1; 32]),
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap()
        .0;
    let pending = attempt
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, total);
    pending.publish();
    assert_eq!(cache.state.lock().unwrap().retained_bytes, total);
    let seed_path = cache.state.lock().unwrap().entries[0]
        .tree
        .directory
        .path()
        .to_path_buf();
    let restore = || {
        cache
            .acquire(
                TargetKey([1; 32]),
                None,
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                2,
                &|| false,
            )
            .unwrap()
            .1
            .unwrap()
    };
    let first = restore();
    let second = restore();
    let identity = |root: &Path| {
        let metadata = fs::metadata(root.join(private)).unwrap();
        (metadata.dev(), metadata.ino())
    };
    assert_ne!(identity(&seed_path), identity(first.backing()));
    assert_ne!(identity(&seed_path), identity(second.backing()));
    assert_ne!(identity(first.backing()), identity(second.backing()));
    fs::write(first.backing().join(private), b"changed by one compiler").unwrap();
    for root in [seed_path.as_path(), second.backing()] {
        assert_eq!(
            fs::read(root.join(private)).unwrap(),
            b"private compiler state"
        );
        assert_eq!(
            fs::read(root.join(format!(
                "debug/incremental/unit/session/object{}",
                private_files - 1
            )))
            .unwrap(),
            b"x"
        );
    }
    fs::write(
        target.backing().join("debug/late-public-output"),
        b"unexpected",
    )
    .unwrap();
    let attempt = cache
        .acquire(
            TargetKey([2; 32]),
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            3,
            &|| false,
        )
        .unwrap()
        .0;
    assert!(attempt.stage(&target, &captured, &|| false).is_err());
    let state = cache.state.lock().unwrap();
    assert_eq!(state.retained_bytes, total);
    assert_eq!(state.reserved_bytes, 0);
}

#[test]
fn custom_profiles_reuse_only_the_same_captured_compilation_family() {
    let source = private_directory("rabs-profile-family-").unwrap();
    fs::create_dir(source.path().join(".cargo")).unwrap();
    fs::write(
        source.path().join("Cargo.toml"),
        "[package]\nname='profile_fixture'\nversion='0.1.0'\n[lib]\npath='lib.rs'\n",
    )
    .unwrap();
    fs::write(
        source.path().join("lib.rs"),
        "pub fn answer() -> u32 { 1 }\n",
    )
    .unwrap();
    let config = "[profile.ci]\ninherits='release'\nopt-level=1\nincremental=false\n";
    fs::write(source.path().join(".cargo/config.toml"), config).unwrap();
    let names = ["Cargo.toml", ".cargo/config.toml", "lib.rs"];
    let input = inputs(source.path(), &names);
    let spec = fixture_spec("first");
    let (build, plan) = cargo_request("build", &["--workspace", "--profile", "ci"]);
    let key = |request: &CanonicalExecRequest, plan: &ArtifactPlan, input: &WorkspaceInputs| {
        target_compatibility_key(scope(), request, input, &spec, &support(), plan, 1).unwrap()
    };
    let expected = key(&build, &plan, &input);
    assert!(expected.is_some());
    let exact = target_key(scope(), &build, &input, &spec, &support(), &plan, 1).unwrap();
    for (command, options) in [
        ("check", vec!["--workspace", "--profile", "ci"]),
        ("test", vec!["--workspace", "--profile", "ci", "--no-run"]),
        (
            "test",
            vec!["--workspace", "--profile", "ci", "case", "--", "--exact"],
        ),
        (
            "build",
            vec!["--package=profile_fixture", "--profile", "ci"],
        ),
        ("build", vec!["--workspace", "--profile=ci"]),
    ] {
        let (request, selected) = cargo_request(command, &options);
        assert_eq!(key(&request, &selected, &input), expected);
        assert_ne!(
            target_key(scope(), &request, &input, &spec, &support(), &selected, 1).unwrap(),
            exact
        );
    }
    for options in [
        vec!["--workspace", "--profile", "other"],
        vec!["--workspace", "--release"],
        vec!["--workspace"],
    ] {
        let (request, selected) = cargo_request("build", &options);
        let changed = key(&request, &selected, &input);
        assert!(changed.is_some());
        assert_ne!(
            changed, expected,
            "distinct compilation profiles cannot share a private family: {options:?}"
        );
    }
    fs::write(
        source.path().join("lib.rs"),
        "pub fn answer() -> u32 { 2 }\n",
    )
    .unwrap();
    let edited = inputs(source.path(), &names);
    assert_eq!(
        key(&build, &plan, &edited),
        expected,
        "source edits can reuse the same custom profile"
    );
    assert_ne!(
        target_key(scope(), &build, &edited, &spec, &support(), &plan, 1).unwrap(),
        exact
    );
    fs::write(
        source.path().join(".cargo/config.toml"),
        config.replace("opt-level=1", "opt-level=2"),
    )
    .unwrap();
    let configured = inputs(source.path(), &names);
    assert_ne!(
        key(&build, &plan, &configured),
        expected,
        "unchanged profile name cannot conceal changed compiler settings"
    );

    let (clippy, clippy_plan) = cargo_request("clippy", &["--profile=ci", "--", "-Dwarnings"]);
    let mut clippy_spec = fixture_spec("first");
    clippy.command_context.apply_to(&mut clippy_spec).unwrap();
    let clippy_key = target_compatibility_key(
        scope(),
        &clippy,
        &input,
        &clippy_spec,
        &support(),
        &clippy_plan,
        1,
    )
    .unwrap();
    assert!(clippy_key.is_some());
    assert_ne!(clippy_key, expected);
    let (changed, changed_plan) = cargo_request("clippy", &["--profile=other", "--", "-Dwarnings"]);
    assert_ne!(
        target_compatibility_key(
            scope(),
            &changed,
            &input,
            &clippy_spec,
            &support(),
            &changed_plan,
            1
        )
        .unwrap(),
        clippy_key
    );
}

#[test]
fn clippy_compatibility_keeps_selections_lints_companions_and_cargo_families_separate() {
    let fixture = CargoFixture::with_dependency();
    let input = fixture.input();
    let (request, plan) = cargo_request(
        "clippy",
        &["--workspace", "--all-targets", "--", "-D", "warnings"],
    );
    let mut spec = fixture_spec("first");
    request.command_context.apply_to(&mut spec).unwrap();
    let key = |request: &CanonicalExecRequest, plan: &ArtifactPlan, input: &WorkspaceInputs| {
        target_compatibility_key(scope(), request, input, &spec, &support(), plan, 1).unwrap()
    };
    let expected = key(&request, &plan, &input);
    assert!(expected.is_some());
    let exact = target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap();
    let (selected, selection_plan) = cargo_request(
        "clippy",
        &[
            "--package",
            "hot_fixture",
            "--bin",
            "hot_fixture",
            "--",
            "-D",
            "warnings",
        ],
    );
    assert_ne!(
        key(&selected, &selection_plan, &input),
        expected,
        "Clippy selection must not reuse a previously unlinted dependency"
    );
    assert_ne!(
        target_key(
            scope(),
            &selected,
            &input,
            &spec,
            &support(),
            &selection_plan,
            1
        )
        .unwrap(),
        exact,
        "target selection remains in the exact request identity"
    );
    for options in [
        vec!["--workspace", "--", "-D", "warnings"],
        vec![
            "--workspace",
            "--all-targets",
            "--no-deps",
            "--",
            "-D",
            "warnings",
        ],
        vec!["--workspace", "--all-targets", "--", "-A", "warnings"],
        vec!["--workspace", "--all-targets", "--", "-D", "clippy::all"],
        vec![
            "--workspace",
            "--all-targets",
            "--",
            "-A",
            "warnings",
            "-D",
            "clippy::all",
        ],
        vec![
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "clippy::all",
            "-A",
            "warnings",
        ],
        vec![
            "--workspace",
            "--all-targets",
            "--features",
            "other",
            "--",
            "-D",
            "warnings",
        ],
        vec![
            "--workspace",
            "--all-targets",
            "--release",
            "--",
            "-D",
            "warnings",
        ],
    ] {
        let (different, different_plan) = cargo_request("clippy", &options);
        let changed = key(&different, &different_plan, &input);
        assert!(changed.is_some(), "known Clippy configuration: {options:?}");
        assert_ne!(changed, expected, "Clippy controls collapsed: {options:?}");
    }
    let (allow_then_deny, allow_then_deny_plan) = cargo_request(
        "clippy",
        &["--workspace", "--", "-A", "warnings", "-D", "clippy::all"],
    );
    let (deny_then_allow, deny_then_allow_plan) = cargo_request(
        "clippy",
        &["--workspace", "--", "-D", "clippy::all", "-A", "warnings"],
    );
    assert_ne!(
        key(&allow_then_deny, &allow_then_deny_plan, &input),
        key(&deny_then_allow, &deny_then_allow_plan, &input),
        "lint order changes which diagnostic level wins"
    );
    let (check, check_plan) = cargo_request("check", &["--workspace", "--all-targets"]);
    assert_ne!(key(&check, &check_plan, &input), expected);
    let (test, test_plan) = cargo_request("test", &["--workspace"]);
    assert_ne!(key(&test, &test_plan, &input), expected);
    assert!(key(&request, &test_plan, &input).is_none());
    let mut unbound = request.clone();
    unbound.program = "/__rabs/toolchain/bin/cargo".into();
    assert!(key(&unbound, &plan, &input).is_none());
    let mut unknown = request.clone();
    unknown.args.insert(1, "--fix".into());
    assert!(key(&unknown, &plan, &input).is_none());
    let mut changed_spec = spec.clone();
    changed_spec
        .env
        .iter_mut()
        .find(|(name, _)| name == "RUSTC")
        .unwrap()
        .1 = "/__rabs/toolchain/bin/other-rustc".into();
    assert_ne!(
        target_compatibility_key(
            scope(),
            &request,
            &input,
            &changed_spec,
            &support(),
            &plan,
            1
        )
        .unwrap(),
        expected,
        "captured compiler binding remains exact"
    );
    fs::write(
        fixture.workspace.join("src/main.rs"),
        "fn main() { println!(\"edited\"); }\n",
    )
    .unwrap();
    let edited = fixture.input();
    assert_eq!(key(&request, &plan, &edited), expected);
    assert_ne!(
        target_key(scope(), &request, &edited, &spec, &support(), &plan, 1).unwrap(),
        exact,
        "source edits change exact identity while remaining eligible for a private Clippy seed"
    );
}

#[test]
fn selection_normalization_refuses_missing_empty_and_option_shaped_values() {
    let (mut request, plan) = cargo_request("build", &["--workspace"]);
    for selector in [
        "--package",
        "-p",
        "--exclude",
        "--bin",
        "--example",
        "--test",
        "--bench",
        "--features",
        "-F",
    ] {
        request.args.push(selector.into());
        assert!(
            compatible_cargo_arguments(&request, &plan).is_none(),
            "{selector}"
        );
        for value in ["", "--release"] {
            request.args.push(value.into());
            assert!(
                compatible_cargo_arguments(&request, &plan).is_none(),
                "{selector} {value}"
            );
            request.args.pop();
        }
        request.args.pop();
        request.args.push(format!("{selector}="));
        assert!(compatible_cargo_arguments(&request, &plan).is_none());
        request.args.pop();
    }
    for selector in [
        "--workspace=all",
        "--lib=1",
        "--all-targets=yes",
        "--all-features=yes",
        "--no-default-features=1",
    ] {
        request.args.push(selector.into());
        assert!(
            compatible_cargo_arguments(&request, &plan).is_none(),
            "{selector}"
        );
        request.args.pop();
    }
}

#[test]
fn exact_target_precedes_a_more_recent_compatible_seed() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let compatible = Some(TargetKey([9; 32]));
    let first = TargetKey([1; 32]);
    let second = TargetKey([2; 32]);
    for (key, bytes) in [(first, "first"), (second, "second")] {
        let (source, plan, target, _) = small_fixture();
        fs::write(target.backing().join("artifact"), bytes).unwrap();
        let captured = target
            .capture_with_dependency_inputs(None, || false)
            .unwrap();
        let (attempt, _) = cache
            .acquire(
                key,
                compatible,
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                1,
                &|| false,
            )
            .unwrap();
        attempt
            .stage(&target, &captured, &|| false)
            .unwrap()
            .unwrap()
            .publish();
    }
    let (source, plan, _, _) = small_fixture();
    for (key, expected) in [(TargetKey([3; 32]), "second"), (first, "first")] {
        let (_, restored) = cache
            .acquire(
                key,
                compatible,
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                2,
                &|| false,
            )
            .unwrap();
        let restored = restored.expect("matching seed");
        assert_eq!(
            fs::read_to_string(restored.backing().join("artifact")).unwrap(),
            expected
        );
    }
    let (_, restored) = cache
        .acquire(
            TargetKey([4; 32]),
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            3,
            &|| false,
        )
        .unwrap();
    assert!(
        restored.is_none(),
        "unknown invocation must not pick a compatible seed"
    );
}

#[test]
fn clones_preserve_bytes_timestamps_empty_directories_modes_and_private_link_groups() {
    let cache = Arc::new(TargetCache::new(1024 * 1024).unwrap());
    let (source, plan, target, _) = small_fixture();
    // Exercise the production clone candidate path as well as internal aliases.
    // Hosts without reflinks must preserve the same guarantees through copying.
    let bytes = vec![0xa5; 96 * 1024 + 7];
    fs::write(target.backing().join("artifact"), &bytes).unwrap();
    fs::set_permissions(
        target.backing().join("artifact"),
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    fs::hard_link(
        target.backing().join("artifact"),
        target.backing().join("artifact-alias"),
    )
    .unwrap();
    let captured = target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    let key = TargetKey([1; 32]);
    let original = fs::metadata(target.backing().join("artifact")).unwrap();
    let (attempt, restored) = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    attempt
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let (_, restored) = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            2,
            &|| false,
        )
        .unwrap();
    let restored = restored.unwrap();
    let cloned = fs::metadata(restored.backing().join("artifact")).unwrap();
    assert_ne!(original.ino(), cloned.ino());
    assert_eq!(
        cloned.ino(),
        fs::metadata(restored.backing().join("artifact-alias"))
            .unwrap()
            .ino()
    );
    assert_eq!(cloned.nlink(), 2);
    assert_eq!(original.modified().unwrap(), cloned.modified().unwrap());
    assert_eq!(cloned.permissions().mode() & 0o777, 0o750);
    assert_eq!(
        fs::read(restored.backing().join("artifact")).unwrap(),
        bytes
    );
    assert_eq!(
        fs::metadata(restored.backing().join("empty-out-dir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
    fs::write(restored.backing().join("artifact"), "mine").unwrap();
    fs::set_permissions(
        restored.backing().join("artifact"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    File::open(restored.backing().join("artifact"))
        .unwrap()
        .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)))
        .unwrap();
    assert_eq!(
        fs::read(restored.backing().join("artifact-alias")).unwrap(),
        b"mine"
    );
    let unchanged = fs::metadata(target.backing().join("artifact")).unwrap();
    assert_eq!(fs::read(target.backing().join("artifact")).unwrap(), bytes);
    assert_eq!(unchanged.permissions().mode() & 0o777, 0o750);
    assert_eq!(unchanged.modified().unwrap(), original.modified().unwrap());
    let (_, independent) = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            3,
            &|| false,
        )
        .unwrap();
    let independent = independent.unwrap();
    assert_eq!(
        fs::read(independent.backing().join("artifact")).unwrap(),
        bytes
    );
    assert_eq!(
        fs::read(independent.backing().join("artifact-alias")).unwrap(),
        bytes
    );
    let independent_metadata = fs::metadata(independent.backing().join("artifact")).unwrap();
    assert_eq!(independent_metadata.permissions().mode() & 0o777, 0o750);
    assert_eq!(
        independent_metadata.modified().unwrap(),
        original.modified().unwrap()
    );
    assert_ne!(
        fs::metadata(independent.backing().join("artifact"))
            .unwrap()
            .ino(),
        cloned.ino()
    );
}

fn target_copy_files(bytes: &[u8]) -> (tempfile::TempDir, File, File) {
    let root = private_directory("rabs-target-copy-test-").unwrap();
    fs::write(root.path().join("source"), bytes).unwrap();
    let input = File::open(root.path().join("source")).unwrap();
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.path().join("output"))
        .unwrap();
    (root, input, output)
}

#[test]
fn small_target_copies_skip_clone_probes_and_reset_empty_or_partial_outputs() {
    use std::io::{Seek, SeekFrom};

    for length in [0, 1, 64 * 1024] {
        let bytes = vec![0x6d; length];
        let (root, mut input, mut output) = target_copy_files(&bytes);
        input.seek(SeekFrom::End(0)).unwrap();
        output.write_all(&vec![0x33; length + 17]).unwrap();
        let digest = clone_or_copy_private_with_cloner(
            &mut input,
            &mut output,
            root.path(),
            length as u64,
            &|| false,
            |_, _, _| panic!("small files must not pay for a clone isolation probe"),
        )
        .unwrap();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(digest, expected);
        assert_eq!(fs::read(root.path().join("output")).unwrap(), bytes);
        assert_eq!(output.metadata().unwrap().len(), length as u64);
    }
}

#[test]
fn failed_target_clone_rewinds_both_handles_and_discards_partial_output() {
    use std::io::{Seek, SeekFrom};

    let bytes = vec![0x5a; 96 * 1024 + 7];
    let (root, mut input, mut output) = target_copy_files(&bytes);
    let digest = clone_or_copy_private_with_cloner(
        &mut input,
        &mut output,
        root.path(),
        bytes.len() as u64,
        &|| false,
        |mut source, mut destination, _| {
            // A failed backend is allowed to disturb both cursor positions and
            // leave bytes behind. The fallback must replace the entire file.
            source.seek(SeekFrom::End(0)).unwrap();
            destination
                .write_all(&vec![0xff; bytes.len() + 29])
                .unwrap();
            false
        },
    )
    .unwrap();
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(digest, expected);
    assert_eq!(fs::read(root.path().join("output")).unwrap(), bytes);
    assert_eq!(output.metadata().unwrap().len(), bytes.len() as u64);
}

#[test]
fn target_clone_hash_and_length_validation_read_the_actual_destination() {
    let source_bytes = vec![0x17; 96 * 1024 + 7];
    for delta in [-1_isize, 0, 1] {
        let cloned_bytes = vec![0x91; source_bytes.len().checked_add_signed(delta).unwrap()];
        let (root, mut input, mut output) = target_copy_files(&source_bytes);
        let result = clone_or_copy_private_with_cloner(
            &mut input,
            &mut output,
            root.path(),
            source_bytes.len() as u64,
            &|| false,
            |_, mut destination, _| {
                // Deterministically exercise validation independently of the
                // host filesystem. This injection is not proof of real CoW.
                destination.write_all(&cloned_bytes).unwrap();
                true
            },
        );
        if delta == 0 {
            let expected: [u8; 32] = Sha256::digest(&cloned_bytes).into();
            let source_digest: [u8; 32] = Sha256::digest(&source_bytes).into();
            assert_eq!(result.unwrap(), expected);
            assert_ne!(expected, source_digest);
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(
                error
                    .to_string()
                    .contains(if delta < 0 { "shrank" } else { "grew" })
            );
        }
    }
}

#[test]
fn target_clone_cancellation_prevents_return_before_destination_validation() {
    let bytes = vec![0x6e; 96 * 1024 + 7];
    let (root, mut input, mut output) = target_copy_files(&bytes);
    let cancelled = std::cell::Cell::new(false);
    let error = clone_or_copy_private_with_cloner(
        &mut input,
        &mut output,
        root.path(),
        bytes.len() as u64,
        &|| cancelled.get(),
        |_, mut destination, _| {
            destination.write_all(&bytes).unwrap();
            cancelled.set(true);
            true
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
}

#[test]
#[ignore = "requires RABS_REFLINK_TEST_ROOT on a real reflink-capable filesystem"]
fn real_target_reflink_preserves_private_bytes_metadata_and_independent_writes() {
    let parent = std::env::var_os("RABS_REFLINK_TEST_ROOT")
        .expect("set RABS_REFLINK_TEST_ROOT to a reflink-capable filesystem");
    let root = tempfile::Builder::new()
        .prefix("rabs-real-target-reflink-")
        .tempdir_in(parent)
        .unwrap();
    let bytes = vec![0x42; 96 * 1024 + 7];
    let source_path = root.path().join("source");
    let output_path = root.path().join("output");
    fs::write(&source_path, &bytes).unwrap();
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o750)).unwrap();
    let mut input = File::open(&source_path).unwrap();
    input
        .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(123)))
        .unwrap();
    let before = input.metadata().unwrap();
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&output_path)
        .unwrap();
    let cloned = std::cell::Cell::new(false);
    let digest = clone_or_copy_private_with_cloner(
        &mut input,
        &mut output,
        root.path(),
        bytes.len() as u64,
        &|| false,
        |source, destination, directory| {
            let result =
                rabs_cas::materialization::try_verified_reflink(source, destination, directory);
            cloned.set(result);
            result
        },
    )
    .unwrap();
    assert!(
        cloned.get(),
        "a copied fallback cannot satisfy the real-reflink gate"
    );
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(digest, expected);
    assert_eq!(fs::read(&output_path).unwrap(), bytes);
    let cloned_metadata = output.metadata().unwrap();
    assert_eq!(before.dev(), cloned_metadata.dev());
    assert_ne!(before.ino(), cloned_metadata.ino());

    // Apply the same metadata steps as copy_tree, then prove that later target
    // writes, truncation and metadata changes leave the retained inode intact.
    output.set_permissions(before.permissions()).unwrap();
    output
        .set_times(FileTimes::new().set_modified(before.modified().unwrap()))
        .unwrap();
    assert_eq!(
        output.metadata().unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert_eq!(
        output.metadata().unwrap().modified().unwrap(),
        before.modified().unwrap()
    );
    fs::write(&output_path, b"private target mutation").unwrap();
    output.set_len(7).unwrap();
    output
        .set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    output
        .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(456)))
        .unwrap();
    let unchanged = input.metadata().unwrap();
    assert_eq!(fs::read(&source_path).unwrap(), bytes);
    assert_eq!(unchanged.len(), before.len());
    assert_eq!(unchanged.permissions().mode() & 0o777, 0o750);
    assert_eq!(unchanged.modified().unwrap(), before.modified().unwrap());
    fs::write(&source_path, b"source mutation").unwrap();
    assert_eq!(fs::read(&output_path).unwrap(), b"private");
}

#[test]
fn external_hard_links_cannot_become_target_seeds() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, captured) = small_fixture();
    let outside = private_directory("rabs-hot-external-link-").unwrap();
    fs::hard_link(
        target.backing().join("artifact"),
        outside.path().join("alias"),
    )
    .unwrap();
    let (attempt, _) = cache
        .acquire(
            TargetKey([1; 32]),
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(attempt.stage(&target, &captured, &|| false).is_err());
    let state = cache.state.lock().unwrap();
    assert!(state.entries.is_empty());
    assert_eq!(state.reserved_bytes, 0);
}

#[test]
fn unsafe_target_directory_modes_bypass_seeding_without_leaking_a_reservation() {
    for (name, mode, original, message) in [
        ("empty-out-dir", 0o555, 0o750, "owner-readable writable"),
        ("", 0o755, 0o700, "artifact tree root must be private"),
    ] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let (source, plan, target, captured) = small_fixture();
        let directory = target.backing().join(name);
        fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
        let (attempt, _) = cache
            .acquire(
                TargetKey([1; 32]),
                None,
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                1,
                &|| false,
            )
            .unwrap();
        let error = attempt.stage(&target, &captured, &|| false).unwrap_err();
        assert!(error.to_string().contains(message), "{name:?}: {error}");
        let state = cache.state.lock().unwrap();
        assert!(state.entries.is_empty());
        assert_eq!(state.reserved_bytes, 0);
        // The fixture owns the original execution tree independently of the pool.
        fs::set_permissions(directory, fs::Permissions::from_mode(original)).unwrap();
    }
}

#[test]
fn corruption_refuses_the_seed_and_falls_back_to_a_fresh_target() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, captured) = small_fixture();
    let key = TargetKey([2; 32]);
    let (attempt, _) = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    attempt
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let path = cache.state.lock().unwrap().entries[0]
        .tree
        .directory
        .path()
        .join("artifact");
    fs::write(path, "evil").unwrap();
    let (_, restored) = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            2,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    assert!(cache.state.lock().unwrap().entries.is_empty());
}

#[test]
fn pending_seeds_count_toward_both_bounds_and_drop_releases_reservations() {
    let cache = Arc::new(TargetCache::new(8).unwrap());
    let (first, _, _) = stage_small(&cache, TargetKey([1; 32]));
    let (second, _, _) = stage_small(&cache, TargetKey([2; 32]));
    assert!(cache.reserve(1).is_none());
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 8);
    drop(first);
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 4);
    second.publish();
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 4);
    let (third, _, _) = stage_small(&cache, TargetKey([3; 32]));
    third.publish();
    let (fourth, _, _) = stage_small(&cache, TargetKey([4; 32]));
    fourth.publish();
    let state = cache.state.lock().unwrap();
    assert_eq!(state.retained_bytes, 8);
    assert_eq!(state.entries.len(), 2);
    drop(state);
    let many = Arc::new(TargetCache::new(1024).unwrap());
    let reservations: Vec<_> = (0..MAX_TARGET_CACHE_ENTRIES)
        .map(|_| many.reserve(1).unwrap())
        .collect();
    assert!(many.reserve(1).is_none());
    drop(reservations);
    assert_eq!(many.state.lock().unwrap().reservations, 0);
}

#[test]
fn impossible_reservations_preserve_warm_bytes_and_lru_until_pending_copy_finishes() {
    let cache = Arc::new(TargetCache::new(12).unwrap());
    for tag in [1, 2] {
        stage_small(&cache, TargetKey([tag; 32])).0.publish();
    }
    let (pending, _, _) = stage_small(&cache, TargetKey([3; 32]));
    let paths: Vec<_> = cache
        .state
        .lock()
        .unwrap()
        .entries
        .iter()
        .map(|seed| seed.tree.directory.path().to_path_buf())
        .collect();
    // Four bytes are already owned by an unpublished copy. No eviction can
    // admit nine more under a twelve-byte limit. Repeated refusals must not
    // turn all subsequent builds cold or perturb the eviction order.
    for _ in 0..3 {
        assert!(cache.reserve(9).is_none());
        let state = cache.state.lock().unwrap();
        assert_eq!(state.retained_bytes, 8);
        assert_eq!(state.reserved_bytes, 4);
        assert_eq!(state.reservations, 1);
        assert_eq!(
            state
                .entries
                .iter()
                .map(|seed| seed.key)
                .collect::<Vec<_>>(),
            vec![TargetKey([1; 32]), TargetKey([2; 32])]
        );
        for path in &paths {
            assert_eq!(fs::read(path.join("artifact")).unwrap(), b"seed");
        }
    }
    drop(pending);
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 0);
    let (source, plan, _, _) = small_fixture();
    for tag in [1, 2] {
        let (_, restored) = cache
            .acquire(
                TargetKey([tag; 32]),
                None,
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                4,
                &|| false,
            )
            .unwrap();
        let restored = restored.expect("refused admission must leave the warm seed usable");
        assert_eq!(
            fs::read(restored.backing().join("artifact")).unwrap(),
            b"seed"
        );
    }
}

#[test]
fn staging_refusal_preserves_prior_seed_and_allows_later_publication() {
    let cache = Arc::new(TargetCache::new(12).unwrap());
    stage_small(&cache, TargetKey([1; 32])).0.publish();
    let held = cache.reserve(8).unwrap();
    let (source, plan, target, _) = small_fixture();
    fs::write(target.backing().join("artifact"), b"larger").unwrap();
    let captured = target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    let new_attempt = || {
        cache
            .acquire(
                TargetKey([2; 32]),
                None,
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                2,
                &|| false,
            )
            .unwrap()
            .0
    };
    assert!(
        new_attempt()
            .stage(&target, &captured, &|| false)
            .unwrap()
            .is_none()
    );
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].key, TargetKey([1; 32]));
        assert_eq!(state.retained_bytes, 4);
        assert_eq!(state.reserved_bytes, 8);
        assert_eq!(state.reservations, 1);
    }
    drop(held);
    new_attempt()
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let state = cache.state.lock().unwrap();
    assert_eq!(state.retained_bytes, 10);
    assert_eq!(state.entries.len(), 2);
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.reservations, 0);
}

#[test]
fn feasible_reservations_keep_lru_eviction_exact_boundaries_and_entry_limits() {
    let cache = Arc::new(TargetCache::new(16).unwrap());
    for tag in [1, 2, 3] {
        stage_small(&cache, TargetKey([tag; 32])).0.publish();
    }
    let held = cache.reserve(4).unwrap();
    let next = cache.reserve(4).unwrap();
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.retained_bytes, 8);
        assert_eq!(state.reserved_bytes, 8);
        assert_eq!(state.reservations, 2);
        assert_eq!(
            state
                .entries
                .iter()
                .map(|seed| seed.key)
                .collect::<Vec<_>>(),
            vec![TargetKey([2; 32]), TargetKey([3; 32])]
        );
    }
    // Exact remaining capacity is admissible, not a false >= refusal.
    let boundary = cache.reserve(8).unwrap();
    assert!(cache.state.lock().unwrap().entries.is_empty());
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 16);
    assert!(cache.reserve(1).is_none());
    drop((boundary, next, held));
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 0);
    assert_eq!(cache.state.lock().unwrap().reservations, 0);

    stage_small(&cache, TargetKey([4; 32])).0.publish();
    let mut empty: Vec<_> = (0..MAX_TARGET_CACHE_ENTRIES - 1)
        .map(|_| cache.reserve(0).unwrap())
        .collect();
    assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
    empty.push(cache.reserve(0).unwrap());
    assert!(cache.state.lock().unwrap().entries.is_empty());
    assert!(cache.reserve(0).is_none());
    drop(empty);
    assert_eq!(cache.state.lock().unwrap().reservations, 0);
}

#[test]
fn failed_output_allocation_does_not_evict_or_promote_a_valid_seed() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    for tag in [1, 2] {
        stage_small(&cache, TargetKey([tag; 32])).0.publish();
    }
    let (source, plan, _, _) = small_fixture();
    let (_, restored) = cache
        .acquire(
            TargetKey([1; 32]),
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected destination allocation failure",
                ))
            },
            3,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.retained_bytes, 8);
        assert_eq!(
            state
                .entries
                .iter()
                .map(|seed| seed.key)
                .collect::<Vec<_>>(),
            vec![TargetKey([1; 32]), TargetKey([2; 32])]
        );
    }
    let (_, restored) = cache
        .acquire(
            TargetKey([1; 32]),
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            4,
            &|| false,
        )
        .unwrap();
    assert_eq!(
        fs::read(restored.unwrap().backing().join("artifact")).unwrap(),
        b"seed"
    );
}

#[test]
fn cancelled_restore_preserves_seed_but_never_bypasses_later_verification() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([1; 32]);
    stage_small(&cache, key).0.publish();
    let (source, plan, _, _) = small_fixture();
    let stopped = std::cell::Cell::new(false);
    let error = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || {
                let output = PreparedArtifacts::new(plan.clone())?;
                stopped.set(true);
                Ok(output)
            },
            2,
            &|| stopped.get(),
        )
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
    ));
    let path = {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.retained_bytes, 4);
        state.entries[0].tree.directory.path().join("artifact")
    };
    assert_eq!(fs::read(&path).unwrap(), b"seed");
    // Retention is not trust. A corrupt retained seed must still be refused
    // and evicted by the unchanged verification on the next attempted hit.
    fs::write(path, b"evil").unwrap();
    let (_, restored) = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            3,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    let state = cache.state.lock().unwrap();
    assert!(state.entries.is_empty());
    assert_eq!(state.retained_bytes, 0);
    assert_eq!(state.reserved_bytes, 0);
}

struct ThreadWake(std::thread::Thread);
impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

fn wait_completion(task: &mut ExecutionTask) -> Result<ExecutionCompletion, String> {
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match task.poll_completion(&mut context) {
            Poll::Ready(result) => return result,
            Poll::Pending => {
                assert!(
                    Instant::now() < deadline,
                    "target-state completion timed out"
                );
                std::thread::park_timeout(Duration::from_millis(20));
            }
        }
    }
}

#[test]
fn normal_failure_seed_requires_exact_exit_clean_completion_and_diagnostics() {
    for outcome in [
        "failure",
        "different-failure",
        "foreign-request",
        "success",
        "cancel",
        "deadline",
        "session-lost",
        "lease-expired",
        "residual",
        "bad-diagnostics",
        "unexecuted",
    ] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let (source, _, _, _) = small_fixture();
        let (_, plan) = cargo_request("test", &[]);
        let target = PreparedArtifacts::new(plan.clone()).unwrap();
        fs::write(target.backing().join("dependency"), b"compiled dependency").unwrap();
        let (attempt, _) = cache
            .acquire(
                TargetKey([3; 32]),
                None,
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                if outcome == "foreign-request" { 4 } else { 3 },
                &|| false,
            )
            .unwrap();
        let pending = attempt
            .stage_failed(
                &target,
                std::process::ExitStatus::from_raw(101 << 8),
                &|| false,
            )
            .unwrap()
            .unwrap();
        let mut task =
            ExecutionTask::spawn_with_artifacts(3, Duration::from_secs(10), plan, move |control| {
                control.retain_target_seed(pending).unwrap();
                if outcome == "bad-diagnostics" {
                    control
                        .retain_outputs(Err("lost diagnostic bytes".into()))
                        .unwrap();
                }
                let stop = match outcome {
                    "cancel" => Some(StopReason::Cancelled),
                    "deadline" => Some(StopReason::DeadlineExceeded),
                    "session-lost" => Some(StopReason::SessionLost),
                    "lease-expired" => Some(StopReason::LeaseExpired),
                    _ => None,
                };
                if let Some(stop) = stop {
                    control.cancel(stop);
                }
                ExecResult {
                    request_id: 3,
                    exit_code: match outcome {
                        "success" => 0,
                        "different-failure" => 1,
                        _ => 101,
                    },
                    stdout_sha256: crate::session::sha256_hex(b""),
                    stderr_sha256: crate::session::sha256_hex(b""),
                    executed: outcome != "unexecuted",
                    residual_group_members: u32::from(outcome == "residual"),
                    stdout_spill_bytes: 0,
                    stderr_spill_bytes: 0,
                    stdout_spill_path: None,
                    stderr_spill_path: None,
                }
            })
            .unwrap();
        let completion = wait_completion(&mut task);
        assert_eq!(
            completion.is_err(),
            matches!(outcome, "success" | "residual" | "bad-diagnostics"),
            "{outcome}"
        );
        if let Ok(completion) = completion {
            assert!(completion.artifacts.is_none(), "{outcome}");
            assert_ne!(completion.result.exit_code, 0, "{outcome}");
        }
        drop(task);
        let state = cache.state.lock().unwrap();
        assert_eq!(
            state.entries.len(),
            usize::from(outcome == "failure"),
            "{outcome}"
        );
        assert_eq!(state.reservations, 0, "{outcome}");
        assert_eq!(state.reserved_bytes, 0, "{outcome}");
    }
}

#[test]
fn failed_seed_staging_refuses_signals_non_cargo_mutation_and_unsafe_targets() {
    for case in [
        "signal",
        "wrapped-signal",
        "high-status",
        "zero",
        "non-cargo",
        "source-changed",
        "symlink",
        "interrupted",
    ] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let (source, ordinary, _, _) = small_fixture();
        let (_, cargo) = cargo_request("build", &[]);
        let plan = if case == "non-cargo" { ordinary } else { cargo };
        let target = PreparedArtifacts::new(plan.clone()).unwrap();
        fs::write(target.backing().join("dependency"), b"compiled dependency").unwrap();
        let (attempt, _) = cache
            .acquire(
                TargetKey([4; 32]),
                None,
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                4,
                &|| false,
            )
            .unwrap();
        if case == "source-changed" {
            fs::set_permissions(
                attempt.inputs.root.join("lib.rs"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            fs::write(attempt.inputs.root.join("lib.rs"), b"changed source").unwrap();
        }
        if case == "symlink" {
            std::os::unix::fs::symlink("dependency", target.backing().join("alias")).unwrap();
        }
        let status = std::process::ExitStatus::from_raw(match case {
            "signal" => 9,
            "wrapped-signal" => 137 << 8,
            "high-status" => 255 << 8,
            "zero" => 0,
            _ => 101 << 8,
        });
        assert!(
            attempt
                .stage_failed(&target, status, &|| case == "interrupted")
                .is_err(),
            "{case}"
        );
        let state = cache.state.lock().unwrap();
        assert!(state.entries.is_empty(), "{case}");
        assert_eq!(state.reservations, 0, "{case}");
        assert_eq!(state.reserved_bytes, 0, "{case}");
    }
}

#[test]
fn only_frozen_success_can_publish_a_pending_seed() {
    for outcome in [
        "success",
        "cancel",
        "failure",
        "residual",
        "missing-artifacts",
        "bad-diagnostics",
    ] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let (seed, plan, captured) = stage_small(&cache, TargetKey([1; 32]));
        let mut task =
            ExecutionTask::spawn_with_artifacts(1, Duration::from_secs(10), plan, move |control| {
                control.retain_target_seed(seed).unwrap();
                if outcome != "missing-artifacts" {
                    control.retain_artifacts(Ok(captured)).unwrap();
                }
                if outcome == "cancel" {
                    control.cancel(StopReason::Cancelled);
                }
                if outcome == "bad-diagnostics" {
                    control
                        .retain_outputs(Err("fixture capture failure".to_owned()))
                        .unwrap();
                }
                ExecResult {
                    request_id: 1,
                    exit_code: if outcome == "failure" { 1 } else { 0 },
                    stdout_sha256: crate::session::sha256_hex(b""),
                    stderr_sha256: crate::session::sha256_hex(b""),
                    executed: true,
                    residual_group_members: u32::from(outcome == "residual"),
                    stdout_spill_bytes: 0,
                    stderr_spill_bytes: 0,
                    stdout_spill_path: None,
                    stderr_spill_path: None,
                }
            })
            .unwrap();
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match task.poll_completion(&mut context) {
                Poll::Ready(result) => {
                    assert_eq!(
                        result.is_ok(),
                        matches!(outcome, "success" | "cancel" | "failure"),
                        "{outcome}"
                    );
                    break;
                }
                Poll::Pending => {
                    assert!(Instant::now() < deadline);
                    std::thread::park_timeout(Duration::from_millis(20));
                }
            }
        }
        drop(task);
        let state = cache.state.lock().unwrap();
        assert_eq!(
            state.entries.len(),
            usize::from(outcome == "success"),
            "{outcome}"
        );
        assert_eq!(state.reserved_bytes, 0, "{outcome}");
        assert_eq!(state.reservations, 0, "{outcome}");
    }
}

const BUILD_SCRIPT: &str = r#"fn main() {
    let root = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let count = std::fs::read_to_string(root.join("run-count")).ok().map(|text| text.parse::<u32>().unwrap()).unwrap_or(0) + 1;
    std::fs::write(root.join("run-count"), count.to_string()).unwrap();
    std::fs::create_dir_all(root.join("empty")).unwrap();
    let value = std::fs::read_to_string("input.txt").unwrap().trim().parse::<u32>().unwrap() + OFFSET;
    std::fs::write(root.join("answer.rs"), value.to_string()).unwrap();
    println!("cargo:rustc-env=LABEL={}", std::env::var("CACHE_LABEL").unwrap());
    println!("cargo:rerun-if-changed=input.txt");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CACHE_LABEL");
}
"#;

struct CargoFixture {
    root: tempfile::TempDir,
    workspace: PathBuf,
    plan: ArtifactPlan,
    names: Vec<&'static str>,
}

impl CargoFixture {
    fn new() -> Self {
        let root = private_directory("rabs-real-hot-cargo-").unwrap();
        let workspace = root.path().join("source");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(workspace.join("src")).unwrap();
        fs::write(
            workspace.join("Cargo.toml"),
            "[package]\nname='hot_fixture'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        fs::write(
            workspace.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = 'hot_fixture'\nversion = '0.1.0'\n",
        )
        .unwrap();
        fs::write(workspace.join("src/main.rs"), "fn main() { println!(\"{}:{}\", env!(\"LABEL\"), include!(concat!(env!(\"OUT_DIR\"), \"/answer.rs\"))); }\n").unwrap();
        fs::write(
            workspace.join("build.rs"),
            BUILD_SCRIPT.replace("OFFSET", "0"),
        )
        .unwrap();
        fs::write(workspace.join("input.txt"), "40\n").unwrap();
        let plan = ArtifactPlan::new_tree("cargo".to_owned(), vec!["debug/hot_fixture".to_owned()])
            .unwrap();
        Self {
            root,
            workspace,
            plan,
            names: vec![
                "Cargo.toml",
                "Cargo.lock",
                "build.rs",
                "input.txt",
                "src/main.rs",
            ],
        }
    }

    fn input(&self) -> WorkspaceInputs {
        inputs(&self.workspace, &self.names)
    }

    fn with_dependency() -> Self {
        let mut fixture = Self::new();
        fs::write(
            fixture.workspace.join("Cargo.toml"),
            "[package]\nname='hot_fixture'\nversion='0.1.0'\nedition='2021'\n[workspace]\nmembers=['dep']\n[dependencies]\nhot_dep={path='dep'}\n",
        ).unwrap();
        fs::write(
            fixture.workspace.join("Cargo.lock"),
            "version=4\n[[package]]\nname='hot_fixture'\nversion='0.1.0'\ndependencies=['hot_dep']\n[[package]]\nname='hot_dep'\nversion='0.1.0'\n",
        ).unwrap();
        fs::create_dir_all(fixture.workspace.join("dep/src")).unwrap();
        fs::write(
            fixture.workspace.join("dep/Cargo.toml"),
            "[package]\nname='hot_dep'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        fs::write(
            fixture.workspace.join("dep/src/lib.rs"),
            "pub fn adjustment() -> u32 { 0 }\n",
        )
        .unwrap();
        fs::write(fixture.workspace.join("src/main.rs"), r#"fn answer() -> u32 {
    include!(concat!(env!("OUT_DIR"), "/answer.rs")) + hot_dep::adjustment()
}
fn main() { println!("{}:{}", env!("LABEL"), answer()); }
#[cfg(test)]
mod tests {
    #[test]
    fn actually_executes_each_time() {
        assert_eq!(super::answer(), 40);
        let counter = std::path::Path::new(env!("OUT_DIR")).join("test-runs");
        let prior = std::fs::read_to_string(&counter).ok().map(|value| value.parse::<u32>().unwrap()).unwrap_or(0);
        std::fs::write(counter, (prior + 1).to_string()).unwrap();
    }
}
"#).unwrap();
        fixture.names.extend(["dep/Cargo.toml", "dep/src/lib.rs"]);
        fixture
    }

    fn fresh_upload_timestamps(&self) {
        // Model a new private SourceReceiver materialization of identical bytes.
        // Use actual wall time, never artificial future output timestamps.
        for file in self.input().manifest.files() {
            File::open(self.workspace.join(&file.path))
                .unwrap()
                .set_times(FileTimes::new().set_modified(SystemTime::now()))
                .unwrap();
        }
        let times = SourceTimes::capture(&self.input(), &|| false).unwrap();
        for directory in times.directories.keys() {
            File::open(self.workspace.join(directory))
                .unwrap()
                .set_times(FileTimes::new().set_modified(SystemTime::now()))
                .unwrap();
        }
    }

    fn command(
        &self,
        cache: &Arc<TargetCache>,
        command: &str,
        options: &[&str],
        hit: bool,
    ) -> CargoCommandResult {
        self.command_with_status(cache, command, options, hit, 0)
    }

    fn command_with_status(
        &self,
        cache: &Arc<TargetCache>,
        command: &str,
        options: &[&str],
        hit: bool,
        expected_status: i32,
    ) -> CargoCommandResult {
        let original = self.input();
        let sealed_times = SourceTimes::capture(&original, &|| false).unwrap();
        let runtime = tempfile::Builder::new()
            .prefix("workspace")
            .rand_bytes(0)
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(self.root.path())
            .unwrap();
        let input = original.clone_into(runtime, &|| false).unwrap();
        let workspace = input.root.clone();
        let (request, plan) = cargo_request(command, options);
        let mut spec = fixture_spec("first");
        request.command_context.apply_to(&mut spec).unwrap();
        let exact = target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap();
        let compatible =
            target_compatibility_key(scope(), &request, &input, &spec, &support(), &plan, 1)
                .unwrap();
        assert!(
            compatible.is_some(),
            "fixture uses an admitted Cargo command"
        );
        let (attempt, restored) = cache
            .acquire(
                exact,
                compatible,
                input,
                || PreparedArtifacts::fixture(plan.clone(), self.root.path()),
                1,
                &|| false,
            )
            .unwrap();
        assert_eq!(
            restored.is_some(),
            hit,
            "{command} {options:?}: target reuse"
        );
        let target = restored
            .unwrap_or_else(|| PreparedArtifacts::fixture(plan.clone(), self.root.path()).unwrap());
        // Stable physical paths model canonical mounts on hosts without bwrap.
        // Actual Cargo stdout passes unchanged through production report/capture.
        let arguments = request.args.iter().map(|argument| {
            if argument == "--target-dir=/__rabs/out/cargo" {
                format!("--target-dir={}", target.backing().display())
            } else {
                argument.clone()
            }
        });
        let cargo = PathBuf::from(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        let program = if command == "clippy" {
            cargo.with_file_name("cargo-clippy")
        } else {
            cargo.clone()
        };
        let output = Command::new(program)
            .args(arguments)
            .current_dir(&workspace)
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CLIPPY_ARGS")
            .env_remove("CLIPPY_CONF_DIR")
            .env("CARGO", &cargo)
            .env("RUSTC", cargo.with_file_name("rustc"))
            .env("RUSTFLAGS", "-C debuginfo=0")
            .env("CARGO_INCREMENTAL", "0")
            .env("CACHE_LABEL", "first")
            .output()
            .expect("run the real installed Cargo and compiler");
        assert_eq!(
            output.status.code(),
            Some(expected_status),
            "{command} {options:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let artifacts = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .collect::<Vec<_>>();
        if output.status.success() {
            assert!(!artifacts.is_empty(), "actual compiler artifact report");
        }
        let inventory = rabs_sandbox::artifact_tree::TreeInventory::scan_complete(
            target.backing(),
            MAX_ARTIFACT_BYTES,
            &|| false,
        )
        .unwrap();
        let counts = inventory
            .names()
            .filter(|name| name.ends_with("/out/test-runs"))
            .map(|name| {
                fs::read_to_string(target.backing().join(name))
                    .unwrap()
                    .parse::<u32>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            counts.len() <= 1,
            "one executed fixture test counter: {counts:?}"
        );
        let test_runs = counts.first().copied().unwrap_or(0);
        let captured = output.status.success().then(|| {
            target
                .capture_fixture_cargo_output(output.stdout.as_slice(), || false)
                .unwrap()
        });
        let pending = match &captured {
            Some(captured) => attempt.stage(&target, captured, &|| false),
            None => attempt.stage_failed(&target, output.status, &|| false),
        }
        .unwrap()
        .unwrap();
        // Exercise the same final diagnostic, exit, cleanup and interruption
        // fence as production. A failed Cargo run has no artifact offer at all.
        let stdout = crate::output::CapturedStream::from_reader(
            output.stdout.as_slice(),
            output.stdout.len() as u64,
        )
        .unwrap();
        let stderr = crate::output::CapturedStream::from_reader(
            output.stderr.as_slice(),
            output.stderr.len() as u64,
        )
        .unwrap();
        let result = ExecResult {
            request_id: 1,
            exit_code: output.status.code().unwrap(),
            stdout_sha256: stdout.sha256().to_owned(),
            stderr_sha256: stderr.sha256().to_owned(),
            executed: true,
            residual_group_members: 0,
            stdout_spill_bytes: 0,
            stderr_spill_bytes: 0,
            stdout_spill_path: None,
            stderr_spill_path: None,
        };
        let mut task =
            ExecutionTask::spawn_with_artifacts(1, Duration::from_secs(10), plan, move |control| {
                control
                    .retain_outputs(Ok(crate::output::CapturedOutputs { stdout, stderr }))
                    .unwrap();
                if let Some(captured) = captured {
                    control.retain_artifacts(Ok(captured)).unwrap();
                }
                control.retain_target_seed(pending).unwrap();
                result
            })
            .unwrap();
        let mut completion = wait_completion(&mut task).unwrap();
        assert_eq!(completion.result.exit_code, expected_status);
        assert_eq!(completion.artifacts.is_some(), expected_status == 0);
        assert_eq!(completion.stop_reason, None);
        let diagnostics = completion.outputs.as_mut().unwrap();
        assert_eq!(
            diagnostics
                .stdout
                .read_chunk(0, output.stdout.len().max(1))
                .unwrap(),
            output.stdout
        );
        assert_eq!(
            diagnostics
                .stderr
                .read_chunk(0, output.stderr.len().max(1))
                .unwrap(),
            output.stderr
        );
        assert_eq!(
            SourceTimes::capture(&self.input(), &|| false).unwrap(),
            sealed_times,
            "command transition must not change the original sealed workspace"
        );
        CargoCommandResult {
            artifacts,
            test_runs,
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }

    fn build(&self, cache: &Arc<TargetCache>, label: &str, hit: bool, expected: &str) {
        let sealed_times = SourceTimes::capture(&self.input(), &|| false).unwrap();
        let runtime_directory = tempfile::Builder::new()
            .prefix("workspace")
            .rand_bytes(0)
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(self.root.path())
            .unwrap();
        let input = self
            .input()
            .clone_into(runtime_directory, &|| false)
            .unwrap();
        let workspace = input.root.clone();
        let key = target_key(
            scope(),
            &fixture_request(),
            &input,
            &fixture_spec(label),
            &support(),
            &self.plan,
            1,
        )
        .unwrap();
        let (attempt, restored) = cache
            .acquire(
                key,
                None,
                input,
                || PreparedArtifacts::fixture(self.plan.clone(), self.root.path()),
                1,
                &|| false,
            )
            .unwrap();
        assert_eq!(
            restored.is_some(),
            hit,
            "unexpected target seed disposition"
        );
        let target = restored.unwrap_or_else(|| {
            PreparedArtifacts::fixture(self.plan.clone(), self.root.path()).unwrap()
        });
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .args([
                "build",
                "--frozen",
                "--offline",
                "--message-format=json",
                "--jobs=1",
            ])
            .arg("--manifest-path")
            .arg(workspace.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(target.backing())
            .current_dir(&workspace)
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env("RUSTFLAGS", "-C debuginfo=0")
            .env("CARGO_INCREMENTAL", "0")
            .env("CACHE_LABEL", label)
            .output()
            .expect("run the real installed Cargo");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let fresh: Vec<_> = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .map(|message| message["fresh"].as_bool().unwrap())
            .collect();
        assert!(
            fresh.len() >= 2,
            "both build script and executable must be observed"
        );
        assert!(
            fresh.iter().all(|value| *value == hit),
            "Cargo freshness {fresh:?}, expected hit={hit}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let binary = Command::new(target.backing().join("debug/hot_fixture"))
            .output()
            .unwrap();
        assert!(binary.status.success());
        assert_eq!(String::from_utf8(binary.stdout).unwrap().trim(), expected);
        let captured = target
            .capture_with_dependency_inputs(None, || false)
            .unwrap();
        let counts: Vec<_> = captured
            .file_names()
            .filter(|name| name.ends_with("/out/run-count"))
            .collect();
        assert_eq!(counts.len(), 1);
        assert_eq!(
            fs::read_to_string(target.backing().join(counts[0])).unwrap(),
            "1",
            "a fresh build script must not rerun after seeding"
        );
        assert!(
            captured
                .file_names()
                .any(|name| name.ends_with("/out/answer.rs"))
        );
        attempt
            .stage(&target, &captured, &|| false)
            .unwrap()
            .unwrap()
            .publish();
        assert_eq!(
            SourceTimes::capture(&self.input(), &|| false).unwrap(),
            sealed_times,
            "the original sealed source's metadata must remain unchanged"
        );
        // Dropping this owner removes the execution target. The next run can
        // obtain its target bytes only from an independently verified seed.
    }
}

struct CargoCommandResult {
    artifacts: Vec<serde_json::Value>,
    test_runs: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl CargoCommandResult {
    fn assert_fresh(&self, name: &str, test: bool, expected: bool) {
        let selected = self
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact["target"]["name"] == name && artifact["profile"]["test"] == test
            })
            .collect::<Vec<_>>();
        assert!(
            !selected.is_empty(),
            "missing compiler artifact for {name}, test={test}"
        );
        assert!(
            selected
                .iter()
                .all(|artifact| artifact["fresh"] == expected),
            "{name} test={test}, expected fresh={expected}: {selected:?}"
        );
    }

    fn assert_all_fresh(&self) {
        assert!(
            self.artifacts
                .iter()
                .all(|artifact| artifact["fresh"] == true),
            "unexpected recompilation: {:?}",
            self.artifacts
        );
    }

    fn assert_output_contains(&self, expected: &str) {
        let stdout = String::from_utf8_lossy(&self.stdout);
        let stderr = String::from_utf8_lossy(&self.stderr);
        assert!(
            stdout.contains(expected) || stderr.contains(expected),
            "missing {expected:?} in current process output: {stdout}\n{stderr}"
        );
    }
}

#[test]
fn real_cargo_build_test_and_check_reuse_targets_and_execute_tests_again() {
    let fixture = CargoFixture::with_dependency();
    let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
    let cold = fixture.command(&cache, "build", &["--workspace"], false);
    cold.assert_fresh("hot_dep", false, false);
    assert_eq!(cold.test_runs, 0);

    fixture.fresh_upload_timestamps();
    let compile_tests = fixture.command(&cache, "test", &["--workspace", "--no-run"], true);
    compile_tests.assert_fresh("hot_dep", false, true);
    compile_tests.assert_fresh("hot_fixture", true, false);
    assert_eq!(
        compile_tests.test_runs, 0,
        "--no-run does not execute tests"
    );

    fixture.fresh_upload_timestamps();
    let first = fixture.command(&cache, "test", &["--workspace"], true);
    first.assert_all_fresh();
    assert_eq!(first.test_runs, 1, "warm test artifacts still execute");

    fixture.fresh_upload_timestamps();
    let second = fixture.command(
        &cache,
        "test",
        &[
            "--workspace",
            "tests::actually_executes_each_time",
            "--",
            "--exact",
        ],
        true,
    );
    second.assert_all_fresh();
    assert_eq!(
        second.test_runs, 2,
        "a new harness invocation must execute again"
    );

    fixture.fresh_upload_timestamps();
    let checking = fixture.command(&cache, "check", &["--workspace"], true);
    checking.assert_fresh("hot_dep", false, false);
    let checked_again = fixture.command(&cache, "check", &["--workspace"], true);
    checked_again.assert_all_fresh();

    // Prefer the exact build seed over newer compatible test/check targets.
    let built_again = fixture.command(&cache, "build", &["--workspace"], true);
    built_again.assert_all_fresh();
}

#[test]
fn real_cargo_failed_compile_retains_completed_dependencies_for_the_fixed_source() {
    let fixture = CargoFixture::with_dependency();
    let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
    let source = fixture.workspace.join("src/main.rs");
    let original = fs::read_to_string(&source).unwrap();
    fs::write(
        &source,
        format!("{original}\nfn broken() {{ missing_function(); }}\n"),
    )
    .unwrap();
    let failed = fixture.command_with_status(&cache, "build", &[], false, 101);
    failed.assert_fresh("hot_dep", false, false);
    assert!(
        failed
            .artifacts
            .iter()
            .all(|artifact| artifact["target"]["kind"] != serde_json::json!(["bin"]))
    );

    fixture.fresh_upload_timestamps();
    let repeated = fixture.command_with_status(&cache, "build", &[], true, 101);
    repeated.assert_fresh("hot_dep", false, true);

    fs::write(&source, original).unwrap();
    fixture.fresh_upload_timestamps();
    let fixed = fixture.command(&cache, "build", &[], true);
    fixed.assert_fresh("hot_dep", false, true);
    fixed.assert_fresh("hot_fixture", false, false);
    let warm = fixture.command(&cache, "build", &[], true);
    warm.assert_all_fresh();
}

#[test]
fn real_cargo_failed_tests_reuse_compilation_but_execute_and_fail_each_time() {
    let fixture = CargoFixture::with_dependency();
    let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
    let source = fixture.workspace.join("src/main.rs");
    let original = fs::read_to_string(&source).unwrap();
    fs::write(
        &source,
        format!(
            "{original}\n#[test] fn still_fails() {{ assert_eq!(hot_dep::adjustment(), 1); }}\n"
        ),
    )
    .unwrap();
    let failed = fixture.command_with_status(&cache, "test", &[], false, 101);
    failed.assert_fresh("hot_dep", false, false);
    assert_eq!(failed.test_runs, 1);

    fixture.fresh_upload_timestamps();
    let repeated = fixture.command_with_status(&cache, "test", &[], true, 101);
    repeated.assert_all_fresh();
    assert_eq!(
        repeated.test_runs, 2,
        "a compiled failing test suite must run again"
    );

    fs::write(&source, original).unwrap();
    fixture.fresh_upload_timestamps();
    let fixed = fixture.command(&cache, "test", &[], true);
    fixed.assert_fresh("hot_dep", false, true);
    fixed.assert_fresh("hot_fixture", true, false);
    assert_eq!(fixed.test_runs, 3);
    let warm = fixture.command(&cache, "test", &[], true);
    warm.assert_all_fresh();
    assert_eq!(warm.test_runs, 4);
}

#[test]
fn real_cargo_package_and_target_selections_reuse_dependencies_and_run_current_tests() {
    let mut fixture = CargoFixture::with_dependency();
    fs::create_dir(fixture.workspace.join("examples")).unwrap();
    fs::write(
        fixture.workspace.join("examples/selection_example.rs"),
        "fn main() { println!(\"{}\", hot_dep::adjustment()); }\n",
    )
    .unwrap();
    fixture.names.push("examples/selection_example.rs");
    let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());

    let dependency = fixture.command(&cache, "build", &["--package", "hot_dep", "--lib"], false);
    dependency.assert_fresh("hot_dep", false, false);
    assert!(
        dependency
            .artifacts
            .iter()
            .all(|artifact| artifact["target"]["name"] == "hot_dep"),
        "the first selection must not build the later binary or example"
    );

    fixture.fresh_upload_timestamps();
    let binary = fixture.command(
        &cache,
        "build",
        &["--package", "hot_fixture", "--bin", "hot_fixture"],
        true,
    );
    binary.assert_fresh("hot_dep", false, true);
    binary.assert_fresh("hot_fixture", false, false);

    fixture.fresh_upload_timestamps();
    let example = fixture.command(
        &cache,
        "build",
        &["--package=hot_fixture", "--example=selection_example"],
        true,
    );
    example.assert_fresh("hot_dep", false, true);
    example.assert_fresh("selection_example", false, false);

    let tests = fixture.command(
        &cache,
        "test",
        &["-p", "hot_fixture", "--bin", "hot_fixture"],
        true,
    );
    tests.assert_fresh("hot_dep", false, true);
    tests.assert_fresh("hot_fixture", true, false);
    assert_eq!(tests.test_runs, 1);

    let tested_again = fixture.command(
        &cache,
        "test",
        &[
            "--workspace",
            "--exclude",
            "hot_dep",
            "--bin",
            "hot_fixture",
        ],
        true,
    );
    tested_again.assert_all_fresh();
    assert_eq!(
        tested_again.test_runs, 2,
        "new selections still run their test harness"
    );

    fs::write(
        fixture.workspace.join("src/main.rs"),
        "fn main() {}\n#[test]\nfn selected_failure() { panic!(\"current selected test actually ran\"); }\n",
    )
    .unwrap();
    let retained = cache.state.lock().unwrap().entries.len();
    let failed = fixture.command_with_status(
        &cache,
        "test",
        &["--package", "hot_fixture", "--bin", "hot_fixture"],
        true,
        101,
    );
    failed.assert_fresh("hot_dep", false, true);
    failed.assert_fresh("hot_fixture", true, false);
    failed.assert_output_contains("current selected test actually ran");
    failed.assert_output_contains("FAILED");
    assert_eq!(cache.state.lock().unwrap().entries.len(), retained + 1);
    let repeated = fixture.command_with_status(
        &cache,
        "test",
        &["--package", "hot_fixture", "--bin", "hot_fixture"],
        true,
        101,
    );
    repeated.assert_all_fresh();
    repeated.assert_output_contains("current selected test actually ran");
    repeated.assert_output_contains("FAILED");
    assert_eq!(cache.state.lock().unwrap().entries.len(), retained + 1);
}

#[test]
fn real_cargo_feature_selections_reuse_private_dependencies_and_current_generated_outputs() {
    let fixture = CargoFixture::with_dependency();
    fs::write(
        fixture.workspace.join("Cargo.toml"),
        "[package]\nname='hot_fixture'\nversion='0.1.0'\nedition='2021'\n\
         [workspace]\nmembers=['dep']\n\
         [dependencies]\nhot_dep={path='dep'}\n\
         [features]\ndefault=['baseline']\nbaseline=[]\nextra=[]\n",
    )
    .unwrap();
    fs::write(
        fixture.workspace.join("build.rs"),
        r#"fn main() {
    let baseline = u32::from(std::env::var_os("CARGO_FEATURE_BASELINE").is_some());
    let extra = u32::from(std::env::var_os("CARGO_FEATURE_EXTRA").is_some());
    let value = std::fs::read_to_string("input.txt").unwrap().trim().parse::<u32>().unwrap();
    std::fs::write(std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("answer.rs"),
        (value + baseline * 100 + extra * 1000).to_string()).unwrap();
    println!("cargo:rerun-if-changed=input.txt");
}
"#,
    )
    .unwrap();
    fs::write(
        fixture.workspace.join("src/main.rs"),
        r#"fn main() {
    let generated: u32 = include!(concat!(env!("OUT_DIR"), "/answer.rs"));
    let compiled = 40 + u32::from(cfg!(feature = "baseline")) * 100
        + u32::from(cfg!(feature = "extra")) * 1000;
    assert_eq!(generated, compiled, "build-script and compiler features must agree");
    println!("feature-value:{}:{}", generated, hot_dep::adjustment());
}
"#,
    )
    .unwrap();
    let original = fixture.input().manifest.digest();
    let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
    for (index, (options, value, fresh)) in [
        (vec![], 140, false),
        (vec!["--no-default-features"], 40, false),
        (
            vec!["--no-default-features", "--features", "extra"],
            1040,
            false,
        ),
        (vec!["--all-features"], 1140, false),
        // Different spellings force compatible lookup rather than selecting
        // the old exact seed; that newest target retains earlier feature units.
        (vec!["-F", "baseline"], 140, true),
        (
            vec!["--features=extra", "--no-default-features"],
            1040,
            true,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        fixture.fresh_upload_timestamps();
        let result = fixture.command(&cache, "run", &options, index != 0);
        result.assert_fresh("hot_dep", false, index != 0);
        result.assert_fresh("hot_fixture", false, fresh);
        let scripts = result
            .artifacts
            .iter()
            .filter(|artifact| artifact["target"]["kind"] == serde_json::json!(["custom-build"]))
            .collect::<Vec<_>>();
        assert_eq!(
            scripts.len(),
            1,
            "one actual feature-dependent build script"
        );
        assert_eq!(scripts[0]["fresh"], fresh);
        assert!(
            result
                .stdout
                .ends_with(format!("feature-value:{value}:0\n").as_bytes()),
            "the current feature-selected executable must run: {}",
            String::from_utf8_lossy(&result.stdout),
        );
        assert_eq!(fixture.input().manifest.digest(), original);
    }
}

#[test]
fn real_clippy_source_edits_relint_without_rebuilding_dependencies_or_suppressing_failures() {
    let fixture = CargoFixture::with_dependency();
    let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
    let deny = [
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "clippy::needless_return",
    ];
    let cold = fixture.command(&cache, "clippy", &deny, false);
    cold.assert_fresh("hot_dep", false, false);
    cold.assert_fresh("hot_fixture", false, false);

    fixture.fresh_upload_timestamps();
    fixture
        .command(&cache, "clippy", &deny, true)
        .assert_all_fresh();
    fs::write(
        fixture.workspace.join("src/main.rs"),
        "fn answer() -> u32 { return hot_dep::adjustment(); }\nfn main() { println!(\"{}\", answer()); }\n",
    )
    .unwrap();
    let retained = cache.state.lock().unwrap().entries.len();
    let failed = fixture.command_with_status(&cache, "clippy", &deny, true, 101);
    failed.assert_fresh("hot_dep", false, true);
    failed.assert_output_contains("needless_return");
    assert_eq!(
        cache.state.lock().unwrap().entries.len(),
        retained + 1,
        "an ordinary lint failure can retain private state without becoming a successful result"
    );
    fixture.fresh_upload_timestamps();
    let repeated = fixture.command_with_status(&cache, "clippy", &deny, true, 101);
    repeated.assert_fresh("hot_dep", false, true);
    repeated.assert_output_contains("needless_return");
    assert_eq!(
        cache.state.lock().unwrap().entries.len(),
        retained + 1,
        "repeating the failed invocation replaces its seed and still rejects the current lint"
    );

    let allowed = fixture.command(
        &cache,
        "clippy",
        &[
            "--workspace",
            "--all-targets",
            "--",
            "-A",
            "clippy::needless_return",
        ],
        false,
    );
    allowed.assert_fresh("hot_dep", false, false);
    allowed.assert_fresh("hot_fixture", false, false);
    let denied_again = fixture.command_with_status(&cache, "clippy", &deny, true, 101);
    denied_again.assert_fresh("hot_dep", false, true);
    denied_again.assert_output_contains("needless_return");

    fs::write(
        fixture.workspace.join("src/main.rs"),
        "fn answer() -> u32 { hot_dep::adjustment() }\nfn main() { println!(\"{}\", answer()); }\n",
    )
    .unwrap();
    fixture.fresh_upload_timestamps();
    let fixed = fixture.command(&cache, "clippy", &deny, true);
    fixed.assert_fresh("hot_dep", false, true);
    fixed.assert_fresh("hot_fixture", false, false);
    fixture
        .command(&cache, "clippy", &deny, true)
        .assert_all_fresh();

    // A dependency omitted from linting by --no-deps can become the next
    // primary package. Native Clippy may leave that unit fresh and skip its
    // lints, so this selection change must start with a separate target.
    fs::write(
        fixture.workspace.join("src/main.rs"),
        "fn main() { println!(\"{}\", hot_dep::adjustment()); }\n",
    )
    .unwrap();
    fs::write(
        fixture.workspace.join("dep/src/lib.rs"),
        "pub fn adjustment() -> u32 { return 0; }\n",
    )
    .unwrap();
    fixture.command(
        &cache,
        "clippy",
        &[
            "--package",
            "hot_fixture",
            "--bin",
            "hot_fixture",
            "--no-deps",
            "--",
            "-D",
            "clippy::needless_return",
        ],
        false,
    );
    let selected_dependency = fixture.command_with_status(
        &cache,
        "clippy",
        &[
            "--package",
            "hot_dep",
            "--lib",
            "--no-deps",
            "--",
            "-D",
            "clippy::needless_return",
        ],
        false,
        101,
    );
    selected_dependency.assert_output_contains("needless_return");
    selected_dependency.assert_output_contains("dep/src/lib.rs");
}

#[test]
fn real_cargo_private_seed_is_fresh_and_source_build_script_environment_changes_miss() {
    let fixture = CargoFixture::new();
    let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
    fixture.build(&cache, "first", false, "first:40");
    fixture.fresh_upload_timestamps();
    fixture.build(&cache, "first", true, "first:40");
    fs::write(fixture.workspace.join("input.txt"), "41\n").unwrap();
    fixture.build(&cache, "first", false, "first:41");
    fs::write(
        fixture.workspace.join("build.rs"),
        BUILD_SCRIPT.replace("OFFSET", "1"),
    )
    .unwrap();
    fixture.build(&cache, "first", false, "first:42");
    fixture.build(&cache, "second", false, "second:42");
    fixture.fresh_upload_timestamps();
    fixture.build(&cache, "second", true, "second:42");
}

#[test]
fn cold_and_contended_attempts_do_not_copy_the_sealed_workspace() {
    for contended in [false, true] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let (source, plan, target, captured) = small_fixture();
        let original = inputs(source.path(), &["lib.rs"]);
        let before = SourceTimes::capture(&original, &|| false).unwrap();
        let calls = std::cell::Cell::new(0);
        let held = contended.then(|| cache.state.lock().unwrap());
        let (attempt, restored) = cache
            .acquire(
                TargetKey([31; 32]),
                None,
                original.clone(),
                || {
                    calls.set(calls.get() + 1);
                    PreparedArtifacts::new(plan.clone())
                },
                1,
                &|| false,
            )
            .unwrap();
        assert!(restored.is_none());
        assert_eq!(
            calls.get(),
            0,
            "cold acquisition must not allocate a target copy"
        );
        assert_eq!(attempt.inputs.root, source.path());
        assert!(attempt.inputs.runtime_owner.is_none());
        assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
        drop(held);
        // Read-only input observation still supports successful cold capture.
        attempt
            .stage(&target, &captured, &|| false)
            .unwrap()
            .unwrap()
            .publish();
        assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
        assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
    }
}

#[test]
fn a_warm_hit_lazily_owns_its_source_and_preserves_the_original_seal() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, captured) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let key = TargetKey([32; 32]);
    let first_time = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    File::open(source.path().join("lib.rs"))
        .unwrap()
        .set_times(FileTimes::new().set_modified(first_time))
        .unwrap();
    let retained_times = SourceTimes::capture(&original, &|| false).unwrap();
    let (cold, restored) = cache
        .acquire(
            key,
            None,
            original.clone(),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    assert!(cold.inputs.runtime_owner.is_none());
    cold.stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap()
        .publish();

    // A later upload of the same bytes has different source timestamps. Only
    // the independently owned runtime tree may receive the retained times.
    File::open(source.path().join("lib.rs"))
        .unwrap()
        .set_times(FileTimes::new().set_modified(first_time + Duration::from_secs(10)))
        .unwrap();
    let before = SourceTimes::capture(&original, &|| false).unwrap();
    assert_ne!(before, retained_times);
    let (warm, restored) = cache
        .acquire(
            key,
            None,
            original.clone(),
            || PreparedArtifacts::new(plan.clone()),
            2,
            &|| false,
        )
        .unwrap();
    let restored = restored.expect("the exact seed must remain reusable");
    assert_ne!(warm.inputs.root, original.root);
    assert_eq!(
        warm.inputs.runtime_owner.as_ref().unwrap().path(),
        warm.inputs.root
    );
    assert_eq!(
        SourceTimes::capture(&warm.inputs, &|| false).unwrap(),
        retained_times
    );
    assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
    let source_inode = fs::metadata(source.path().join("lib.rs")).unwrap();
    let runtime_inode = fs::metadata(warm.inputs.root.join("lib.rs")).unwrap();
    assert_ne!(
        (source_inode.dev(), source_inode.ino()),
        (runtime_inode.dev(), runtime_inode.ino())
    );
    assert_eq!(
        fs::read(restored.backing().join("artifact")).unwrap(),
        b"seed"
    );
    let runtime_path = warm.inputs.root.clone();
    drop(warm);
    assert!(
        !runtime_path.exists(),
        "the attempt must own the complete copy lifetime"
    );
    assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
    // The timestamp-restoration guard itself remains unchanged.
    assert!(retained_times.restore(&original, &|| false).is_err());
}

#[test]
fn refused_lazy_restore_keeps_the_original_workspace_and_fresh_target_path() {
    for corrupt in [false, true] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let key = TargetKey([33; 32]);
        stage_small(&cache, key).0.publish();
        if corrupt {
            let path = cache.state.lock().unwrap().entries[0]
                .tree
                .directory
                .path()
                .join("artifact");
            fs::write(path, b"evil").unwrap();
        }
        let (source, plan, _, _) = small_fixture();
        let original = inputs(source.path(), &["lib.rs"]);
        let before = SourceTimes::capture(&original, &|| false).unwrap();
        let (attempt, restored) = cache
            .acquire(
                key,
                None,
                original.clone(),
                || {
                    if corrupt {
                        PreparedArtifacts::new(plan.clone())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "injected allocation refusal",
                        ))
                    }
                },
                2,
                &|| false,
            )
            .unwrap();
        assert!(restored.is_none());
        assert_eq!(attempt.inputs.root, original.root);
        assert!(attempt.inputs.runtime_owner.is_none());
        assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
        assert_eq!(
            cache.state.lock().unwrap().entries.len(),
            usize::from(!corrupt)
        );
    }
}

#[test]
fn cancellation_before_lazy_source_copy_keeps_seed_and_drops_the_new_target() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([34; 32]);
    stage_small(&cache, key).0.publish();
    let (source, plan, _, _) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let before = SourceTimes::capture(&original, &|| false).unwrap();
    let stopped = std::cell::Cell::new(false);
    let new_output_path = std::cell::RefCell::new(None);
    let error = cache
        .acquire(
            key,
            None,
            original.clone(),
            || {
                let output = PreparedArtifacts::new(plan.clone())?;
                *new_output_path.borrow_mut() = Some(output.backing().to_path_buf());
                stopped.set(true);
                Ok(output)
            },
            2,
            &|| stopped.get(),
        )
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
    ));
    assert!(!new_output_path.borrow().as_ref().unwrap().exists());
    assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 0);
    assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
}

#[test]
fn a_cold_attempt_still_refuses_changed_sealed_source_before_seed_publication() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, captured) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let (attempt, restored) = cache
        .acquire(
            TargetKey([35; 32]),
            None,
            original,
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    assert!(attempt.inputs.runtime_owner.is_none());
    fs::set_permissions(
        source.path().join("lib.rs"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(source.path().join("lib.rs"), b"changed source").unwrap();
    assert!(attempt.stage(&target, &captured, &|| false).is_err());
    let state = cache.state.lock().unwrap();
    assert!(state.entries.is_empty());
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.reservations, 0);
}

#[test]
fn lazy_restoration_binds_both_owned_mounts_or_changes_neither() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([36; 32]);
    stage_small(&cache, key).0.publish();
    let (source, plan, current, _) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let (attempt, restored) = cache
        .acquire(
            key,
            None,
            original.clone(),
            || PreparedArtifacts::new(plan.clone()),
            2,
            &|| false,
        )
        .unwrap();
    let restored = restored.unwrap();
    let make_spec = || {
        let mut spec = fixture_spec("unchanged");
        spec.ro_binds[0].backing = original.root.clone();
        spec.rw_binds[0].backing = current.backing().to_path_buf();
        spec
    };
    let request = fixture_request();
    let mut spec = make_spec();
    let expected_key =
        target_key(scope(), &request, &original, &spec, &support(), &plan, 1).unwrap();
    attempt
        .bind_restored(&mut spec, &original, &current, &restored, &plan)
        .unwrap();
    assert_eq!(spec.ro_binds[0].backing, attempt.inputs.root);
    assert_eq!(spec.rw_binds[0].backing, restored.backing());
    assert_eq!(
        target_key(
            scope(),
            &request,
            &attempt.inputs,
            &spec,
            &support(),
            &plan,
            1
        )
        .unwrap(),
        expected_key,
        "private backing selection must not change the exact semantic key"
    );
    for wrong_source in [false, true] {
        let mut spec = make_spec();
        if wrong_source {
            spec.ro_binds[0].backing = "/unowned/source".into();
        } else {
            spec.rw_binds[0].backing = "/unowned/target".into();
        }
        let before_source = spec.ro_binds[0].backing.clone();
        let before_output = spec.rw_binds[0].backing.clone();
        assert!(
            attempt
                .bind_restored(&mut spec, &original, &current, &restored, &plan)
                .is_err()
        );
        assert_eq!(spec.ro_binds[0].backing, before_source);
        assert_eq!(spec.rw_binds[0].backing, before_output);
    }
    let mut changed = original.clone();
    changed.full_source_digest[0] ^= 1;
    let mut spec = make_spec();
    assert!(
        attempt
            .bind_restored(&mut spec, &changed, &current, &restored, &plan)
            .is_err()
    );
    assert_eq!(spec.ro_binds[0].backing, original.root);
    assert_eq!(spec.rw_binds[0].backing, current.backing());
    let (cold, _) = cache
        .acquire(
            TargetKey([37; 32]),
            None,
            original.clone(),
            || PreparedArtifacts::new(plan.clone()),
            3,
            &|| false,
        )
        .unwrap();
    let mut spec = make_spec();
    assert!(
        cold.bind_restored(&mut spec, &original, &current, &restored, &plan)
            .is_err()
    );
    assert_eq!(spec.ro_binds[0].backing, original.root);
    assert_eq!(spec.rw_binds[0].backing, current.backing());
}

#[test]
fn a_mismatched_runtime_owner_is_not_treated_as_a_sealed_source() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, _, _) = small_fixture();
    let mut original = inputs(source.path(), &["lib.rs"]);
    original.runtime_owner = Some(Arc::new(
        private_directory("rabs-wrong-runtime-owner-").unwrap(),
    ));
    let error = cache
        .acquire(
            TargetKey([38; 32]),
            None,
            original,
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap_err();
    assert!(error.to_string().contains("runtime owner differs"));
    assert!(cache.state.lock().unwrap().entries.is_empty());
}

#[test]
fn live_warm_attempts_own_independent_source_inodes_and_publication_checks() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([39; 32]);
    stage_small(&cache, key).0.publish();
    let (source, plan, _, _) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let before = SourceTimes::capture(&original, &|| false).unwrap();
    let acquire = || {
        let (attempt, restored) = cache
            .acquire(
                key,
                None,
                original.clone(),
                || PreparedArtifacts::new(plan.clone()),
                2,
                &|| false,
            )
            .unwrap();
        (attempt, restored.expect("matching seed must be restored"))
    };
    // Both attempts stay live together. Neither source nor target may alias
    // the other attempt, the retained seed, or the original sealed workspace.
    let (first, first_target) = acquire();
    let (second, second_target) = acquire();
    let identity = |path: &Path| {
        let metadata = fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    };
    let first_source = first.inputs.root.join("lib.rs");
    let second_source = second.inputs.root.join("lib.rs");
    assert_ne!(identity(&first_source), identity(&second_source));
    assert_ne!(
        identity(&first_source),
        identity(&original.root.join("lib.rs"))
    );
    assert_ne!(
        identity(&second_source),
        identity(&original.root.join("lib.rs"))
    );
    assert_ne!(
        identity(&first_target.backing().join("artifact")),
        identity(&second_target.backing().join("artifact"))
    );
    let original_bytes = fs::read(&second_source).unwrap();
    fs::set_permissions(&first_source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&first_source, b"changed private workspace").unwrap();
    assert_eq!(fs::read(&second_source).unwrap(), original_bytes);
    assert_eq!(
        fs::read(original.root.join("lib.rs")).unwrap(),
        original_bytes
    );
    assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
    let first_capture = first_target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    assert!(
        first
            .stage(&first_target, &first_capture, &|| false)
            .is_err()
    );
    let second_capture = second_target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    second
        .stage(&second_target, &second_capture, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let state = cache.state.lock().unwrap();
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.reservations, 0);
}
