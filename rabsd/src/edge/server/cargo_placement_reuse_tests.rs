use super::*;
use rabs_key::live_dependency::{
    LiveRustcRequest, ToolchainFacts, dep_info_closure_violation, live_dependency_key,
    plan_dependency_action,
};
use rabs_protocol::input_evidence::{
    ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::ObjectId;
use std::cell::Cell;

const PACKAGE: &str = "/home/agent/.cargo/registry/src/test-index/demo-1.0.0";
const HOST: &str = "x86_64-unknown-linux-gnu";

fn plan(target: Option<&str>) -> DependencyActionPlan {
    let output = format!(
        "{}/debug/deps",
        target
            .filter(|value| value.starts_with('/'))
            .unwrap_or("/work/target")
    );
    let argv: Vec<String> = [
        "/toolchain/bin/rustc",
        "--crate-name",
        "demo",
        "--crate-type",
        "lib",
        "--edition=2021",
        "--emit=dep-info,metadata,link",
        "--error-format=json",
        "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
        "-C",
        "metadata=0123456789abcdef",
        "-C",
        "extra-filename=-0123456789abcdef",
        "--cap-lints",
        "allow",
        "--out-dir",
        output.as_str(),
        "/home/agent/.cargo/registry/src/test-index/demo-1.0.0/src/lib.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut env: Vec<(String, String)> = [
        ("HOME", "/home/agent"),
        ("PATH", "/usr/bin:/bin"),
        ("CARGO_MANIFEST_DIR", PACKAGE),
        ("CARGO_PKG_NAME", "demo"),
        ("CARGO_PKG_VERSION", "1.0.0"),
        ("CARGO", "/toolchain/bin/cargo"),
    ]
    .into_iter()
    .map(|(name, value)| (name.into(), value.into()))
    .collect();
    if let Some(value) = target {
        env.push((VARIABLE.into(), value.into()));
    }
    plan_dependency_action(
        LiveRustcRequest {
            argv: &argv,
            cwd: PACKAGE,
            env: &env,
        },
        HOST,
    )
    .unwrap()
}

fn derive(plan: &mut DependencyActionPlan) -> Result<LiveDependencyKey, LiveRefusal> {
    derive_with(plan, 7, None)
}

fn derive_with(
    plan: &DependencyActionPlan,
    source_tag: u8,
    record: Option<&[u8]>,
) -> Result<LiveDependencyKey, LiveRefusal> {
    let digest = compute("rabs.test.toolchain.v1", b"compiler");
    let toolchain = ToolchainFacts {
        compiler_binary_digest: digest.clone(),
        verbose_version: format!("rustc test\nhost: {HOST}\n"),
        sysroot_root_digest: digest,
        runtime_libraries: Vec::new(),
    };
    let inputs = ActionInputManifest {
        schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
        inputs: ["Cargo.toml", "src/lib.rs"]
            .into_iter()
            .map(|path| PositiveInput {
                virtual_path: RawBytes::new(plan.input_virtual_path(path).into_bytes()),
                object: ObjectId(compute("rabs.test.source.v1", &[source_tag])),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            })
            .collect(),
        ..ActionInputManifest::default()
    };
    live_dependency_key(plan, &toolchain, &[], &[], record, &inputs)
}

#[test]
fn target_placement_reuses_keys_but_never_changes_execution() {
    let mut a = plan(Some("/agents/one/target"));
    let mut b = plan(Some("/agents/two/target"));
    let original_a = a.clone();
    let original_b = b.clone();
    let exact_a = derive(&mut a).unwrap();
    assert_ne!(exact_a.action_key, derive(&mut b).unwrap().action_key);
    let projected_a = key(&mut a, true, derive).unwrap();
    let projected_b = key(&mut b, true, derive).unwrap();
    assert_eq!(projected_a, projected_b);
    assert_ne!(projected_a.action_key, exact_a.action_key);
    assert_ne!(
        projected_a.descriptor.sandbox_semantic_policy,
        exact_a.descriptor.sandbox_semantic_policy
    );
    assert_eq!(
        projected_a.action_key,
        compute_action_key(&projected_a.descriptor).final_key
    );
    assert_eq!(
        projected_a.descriptor_digest,
        descriptor_digest(&descriptor_canonical_bytes(&projected_a.descriptor))
    );
    for (actual, mut original) in [(a, original_a), (b, original_b)] {
        original.keyed_env.retain(|(name, _)| name != VARIABLE);
        assert_eq!(actual, original, "only the tracked-read veto can change");
    }
}

#[test]
fn tracked_value_and_presence_reads_refuse_publication() {
    let mut candidate = plan(Some("/agents/one/target"));
    key(&mut candidate, true, derive).unwrap();
    let ordinary = format!("{}/demo.d: {PACKAGE}/src/lib.rs\n", candidate.out_dir);
    assert_eq!(
        dep_info_closure_violation(&candidate, ordinary.as_bytes(), |_| true),
        None
    );
    for suffix in [
        "# env-dep:CARGO_TARGET_DIR=/agents/one/target\n",
        "# env-dep:CARGO_TARGET_DIR\n",
        "# env-dep:CARGO_TARGET_DIR=\n",
    ] {
        let reason = dep_info_closure_violation(
            &candidate,
            (ordinary.clone() + suffix).as_bytes(),
            |_| true,
        )
        .unwrap();
        assert!(reason.contains("unkeyed variable CARGO_TARGET_DIR"));
    }
}

#[test]
fn absence_is_not_conflated_with_any_present_value() {
    let mut absent = plan(None);
    let unchanged = absent.clone();
    let absent_key = key(&mut absent, true, derive).unwrap();
    assert_eq!(absent, unchanged);
    assert_eq!(absent_key, derive(&mut absent).unwrap());
    for value in ["", "/agents/one/target", "relative-target"] {
        let mut present = plan(Some(value));
        assert_ne!(
            key(&mut present, true, derive).unwrap().action_key,
            absent_key.action_key
        );
    }
}

#[test]
fn disabled_projection_keeps_exact_values_and_identity() {
    let mut candidate = plan(Some("/agents/one/target"));
    let original = candidate.clone();
    let expected = derive(&mut candidate).unwrap();
    assert_eq!(key(&mut candidate, false, derive).unwrap(), expected);
    assert_eq!(candidate, original);
}

#[test]
fn other_environment_source_and_compiler_flags_remain_semantic() {
    let mut original = plan(Some("/agents/one/target"));
    let base = key(&mut original, true, derive).unwrap().action_key;
    let mut changed = plan(Some("/agents/two/target"));
    for env in [&mut changed.execution_env, &mut changed.keyed_env] {
        env.push(("RUSTC_BOOTSTRAP".into(), "1".into()));
    }
    assert_ne!(key(&mut changed, true, derive).unwrap().action_key, base);
    let mut source = plan(Some("/agents/two/target"));
    assert_ne!(
        key(&mut source, true, |plan| derive_with(plan, 8, None))
            .unwrap()
            .action_key,
        base
    );
    let mut cfg = plan(Some("/agents/two/target"));
    cfg.invocation.cfgs.push("semantic_change".into());
    assert_ne!(key(&mut cfg, true, derive).unwrap().action_key, base);
}

#[test]
fn captured_rustc_env_directive_keeps_exact_key_and_does_not_mutate_plan() {
    let mut candidate = plan(Some("/agents/one/target"));
    candidate.generated_root = Some("/work/generated".into());
    for env in [&mut candidate.execution_env, &mut candidate.keyed_env] {
        env.push(("OUT_DIR".into(), "/work/generated".into()));
    }
    let record = b"cargo::rustc-env=CARGO_TARGET_DIR=/agents/one/target\n";
    let original = candidate.clone();
    let expected = derive_with(&candidate, 7, Some(record)).unwrap();
    assert_eq!(
        key(&mut candidate, true, |plan| derive_with(plan, 7, Some(record))).unwrap(),
        expected
    );
    assert_eq!(candidate, original);
}

#[test]
fn invalid_original_facts_are_not_rescued_by_projection_or_leak_mutation() {
    let mut candidate = plan(Some("/agents/one/target"));
    let original = candidate.clone();
    let calls = Cell::new(0);
    let result = key(&mut candidate, true, |plan| {
        calls.set(calls.get() + 1);
        plan.keyed_env.clear();
        Err(LiveRefusal::Facts("invalid original evidence".into()))
    });
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(candidate, original);
}

#[test]
fn mismatched_or_duplicate_bindings_are_never_projected() {
    for variant in 0..3 {
        let mut candidate = plan(Some("/agents/one/target"));
        if variant == 1 {
            candidate.execution_env.push((VARIABLE.into(), "/other".into()));
        } else if variant == 2 {
            candidate.keyed_env.push((VARIABLE.into(), "/other".into()));
        } else {
            candidate
                .keyed_env
                .iter_mut()
                .find(|(name, _)| name == VARIABLE)
                .unwrap()
                .1 = "/other".into();
        }
        let original = candidate.clone();
        let calls = Cell::new(0);
        let _ = key(&mut candidate, true, |plan| {
            calls.set(calls.get() + 1);
            assert_eq!(*plan, original);
            derive(plan)
        });
        assert_eq!(calls.get(), 1);
        assert_eq!(candidate, original);
    }
}

#[test]
fn failed_projection_preserves_another_profiles_read_veto() {
    let mut candidate = plan(Some("/agents/one/target"));
    for env in [&mut candidate.execution_env, &mut candidate.keyed_env] {
        env.push(("CARGO_OTHER_PLACEMENT".into(), "present".into()));
    }
    let mut expected = candidate.clone();
    expected
        .keyed_env
        .retain(|(name, _)| name != "CARGO_OTHER_PLACEMENT");
    let baseline = derive(&mut expected).unwrap();
    let result = key(&mut candidate, true, |plan| {
        // Model a narrower placement profile followed by a projection refusal.
        plan.keyed_env.retain(|(name, _)| name != "CARGO_OTHER_PLACEMENT");
        if single_value(&plan.keyed_env).is_none() {
            return Err(LiveRefusal::Facts("requires exact target binding".into()));
        }
        derive(plan)
    })
    .unwrap();
    assert_eq!(result, baseline);
    assert_eq!(candidate, expected);
    assert!(
        dep_info_closure_violation(
            &candidate,
            b"# env-dep:CARGO_OTHER_PLACEMENT=present\n",
            |_| true,
        )
        .is_some()
    );
}
