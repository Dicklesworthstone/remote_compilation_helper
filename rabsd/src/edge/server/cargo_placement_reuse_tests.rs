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

// Keep every original single-variable regression on its original opt-in.
fn key(
    plan: &mut DependencyActionPlan,
    enabled: bool,
    derive: impl Fn(&mut DependencyActionPlan) -> Result<LiveDependencyKey, LiveRefusal>,
) -> Result<LiveDependencyKey, LiveRefusal> {
    super::key(plan, enabled, false, derive)
}

fn single_value(env: &[(String, String)]) -> Option<&str> {
    super::single_value(env, VARIABLE)
}

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
        let reason =
            dep_info_closure_violation(&candidate, (ordinary.clone() + suffix).as_bytes(), |_| {
                true
            })
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
        key(&mut candidate, true, |plan| derive_with(
            plan,
            7,
            Some(record)
        ))
        .unwrap(),
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
            candidate
                .execution_env
                .push((VARIABLE.into(), "/other".into()));
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
        plan.keyed_env
            .retain(|(name, _)| name != "CARGO_OTHER_PLACEMENT");
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

fn binding(plan: &mut DependencyActionPlan, name: &str, value: &str) {
    for env in [&mut plan.execution_env, &mut plan.keyed_env] {
        env.retain(|(key, _)| key != name);
        env.push((name.to_owned(), value.to_owned()));
        env.sort();
    }
}

fn layout_key(plan: &mut DependencyActionPlan) -> LiveDependencyKey {
    super::key(plan, false, true, derive).unwrap()
}

#[test]
fn each_layout_variable_reuses_values_without_rewriting_execution() {
    for variable in LAYOUT_VARIABLES {
        let mut a = plan(None);
        let mut b = plan(None);
        binding(&mut a, variable, "/agents/one/build");
        binding(&mut b, variable, "/agents/two/build");
        assert_ne!(derive(&mut a).unwrap(), derive(&mut b).unwrap());
        let original_a = a.clone();
        let original_b = b.clone();
        assert_eq!(layout_key(&mut a), layout_key(&mut b));
        for (actual, mut original) in [(a, original_a), (b, original_b)] {
            original.keyed_env.retain(|(name, _)| name != variable);
            assert_eq!(actual, original, "only {variable}'s read veto may change");
        }
    }
}

#[test]
fn combined_layout_converges_and_vetoes_every_tracked_read() {
    let mut a = plan(Some("/agents/one/final"));
    let mut b = plan(Some("/agents/two/final"));
    for variable in &LAYOUT_VARIABLES[1..] {
        binding(&mut a, variable, "/agents/one/intermediate");
        binding(&mut b, variable, "/agents/two/intermediate");
    }
    let original = a.clone();
    assert_eq!(layout_key(&mut a), layout_key(&mut b));
    let mut expected = original;
    expected
        .keyed_env
        .retain(|(name, _)| !LAYOUT_VARIABLES.contains(&name.as_str()));
    assert_eq!(a, expected);
    let ordinary = format!("{}/demo.d: {PACKAGE}/src/lib.rs\n", a.out_dir);
    assert_eq!(
        dep_info_closure_violation(&a, ordinary.as_bytes(), |_| true),
        None
    );
    for variable in LAYOUT_VARIABLES {
        for suffix in [
            String::new(),
            "=".into(),
            "=/agents/one/intermediate".into(),
        ] {
            let dep_info = format!("{ordinary}# env-dep:{variable}{suffix}\n");
            let refusal = dep_info_closure_violation(&a, dep_info.as_bytes(), |_| true).unwrap();
            assert!(
                refusal.contains(&format!("unkeyed variable {variable}")),
                "{refusal}"
            );
        }
    }
}

#[test]
fn every_layout_presence_set_has_a_distinct_key_even_for_empty_values() {
    let mut identities = Vec::new();
    for mask in 0..8 {
        let mut empty = plan(None);
        let mut present = plan(None);
        for (bit, variable) in LAYOUT_VARIABLES.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                binding(&mut empty, variable, "");
                binding(&mut present, variable, "/another/place");
            }
        }
        // Input order is not identity. Presence and the versioned variable
        // set are: absence must not reuse a compile that could observe it.
        present.execution_env.reverse();
        present.keyed_env.reverse();
        let identity = layout_key(&mut empty);
        assert_eq!(identity, layout_key(&mut present));
        assert!(
            !identities.contains(&identity),
            "presence mask {mask} collided"
        );
        identities.push(identity);
    }
}

#[test]
fn legacy_opt_in_keeps_its_exact_policy_and_does_not_expand_coverage() {
    let mut old = plan(Some("/agents/one/target"));
    let mut expected_plan = old.clone();
    expected_plan.keyed_env.retain(|(name, _)| name != VARIABLE);
    let mut expected = derive(&mut expected_plan).unwrap();
    let previous = &expected.descriptor.sandbox_semantic_policy;
    let mut policy = CanonicalEncoder::new();
    policy
        .str(POLICY_TAG)
        .str(previous.domain)
        .bytes(&previous.bytes)
        .str("CARGO_TARGET_DIR present; tracked reads refuse publication");
    expected.descriptor.sandbox_semantic_policy = compute(DOMAIN_LIVE_ISOLATION, &policy.finish());
    expected.action_key = compute_action_key(&expected.descriptor).final_key;
    expected.descriptor_digest =
        descriptor_digest(&descriptor_canonical_bytes(&expected.descriptor));
    assert_eq!(key(&mut old, true, derive).unwrap(), expected);
    assert_eq!(old, expected_plan);
    assert_eq!(layout_key(&mut plan(Some("/agents/two/target"))), expected);
    for variable in &LAYOUT_VARIABLES[1..] {
        let mut exact = plan(None);
        binding(&mut exact, variable, "/agents/one/build");
        let before = exact.clone();
        let identity = derive(&mut exact).unwrap();
        assert_eq!(key(&mut exact, true, derive).unwrap(), identity);
        assert_eq!(exact, before);
    }
}

#[test]
fn a_script_required_layout_binding_stays_exact_without_blocking_the_others() {
    for required in LAYOUT_VARIABLES {
        let mut candidate = plan(None);
        for variable in LAYOUT_VARIABLES {
            binding(&mut candidate, variable, "/agents/one/build");
        }
        candidate.generated_root = Some("/work/generated".into());
        binding(&mut candidate, "OUT_DIR", "/work/generated");
        let record = format!("cargo::rustc-env={required}=/agents/one/build\n");
        let original = candidate.clone();
        let projected = super::key(&mut candidate, false, true, |plan| {
            derive_with(plan, 7, Some(record.as_bytes()))
        })
        .unwrap();
        assert_eq!(candidate.execution_env, original.execution_env);
        assert_eq!(candidate.generated_root, original.generated_root);
        for variable in LAYOUT_VARIABLES {
            assert_eq!(
                super::single_value(&candidate.keyed_env, variable).is_some(),
                variable == required,
            );
        }
        let mut other = original.clone();
        for variable in LAYOUT_VARIABLES
            .into_iter()
            .filter(|name| *name != required)
        {
            binding(&mut other, variable, "/agents/two/build");
        }
        assert_eq!(
            projected,
            super::key(&mut other, false, true, |plan| {
                derive_with(plan, 7, Some(record.as_bytes()))
            })
            .unwrap()
        );
        let mut changed = original;
        binding(&mut changed, required, "/explicit/new/value");
        let changed_record = format!("cargo::rustc-env={required}=/explicit/new/value\n");
        assert_ne!(
            projected,
            super::key(&mut changed, false, true, |plan| {
                derive_with(plan, 7, Some(changed_record.as_bytes()))
            })
            .unwrap()
        );
    }
}

#[test]
fn layout_trials_reconstruct_inner_projection_policy_from_original_inputs() {
    let mut candidate = plan(None);
    for variable in LAYOUT_VARIABLES {
        binding(&mut candidate, variable, "/agents/one/build");
    }
    binding(&mut candidate, "CARGO_INNER_PLACEMENT", "/inner/value");
    let original = candidate.clone();
    let calls = Cell::new(0);
    // Model a narrower profile that requires its original keyed binding,
    // removes it, and derives a different policy. Starting the next trial
    // from the prior mutated plan would silently lose that policy or refuse.
    let inner = |plan: &mut DependencyActionPlan| {
        calls.set(calls.get() + 1);
        assert_eq!(
            super::single_value(&plan.keyed_env, "CARGO_INNER_PLACEMENT"),
            Some("/inner/value")
        );
        plan.keyed_env
            .retain(|(name, _)| name != "CARGO_INNER_PLACEMENT");
        let mut identity = derive(plan)?;
        identity.descriptor.sandbox_semantic_policy =
            compute(DOMAIN_LIVE_ISOLATION, b"inner policy");
        identity.action_key = compute_action_key(&identity.descriptor).final_key;
        identity.descriptor_digest =
            descriptor_digest(&descriptor_canonical_bytes(&identity.descriptor));
        Ok(identity)
    };
    let actual = super::key(&mut candidate, false, true, inner).unwrap();
    assert_eq!(calls.get(), 4, "one baseline plus at most three trials");
    let mut expected_plan = original;
    expected_plan
        .keyed_env
        .retain(|(name, _)| !LAYOUT_VARIABLES.contains(&name.as_str()));
    let mut expected = inner(&mut expected_plan).unwrap();
    bind_policy(&mut expected, &LAYOUT_VARIABLES);
    assert_eq!(actual, expected);
    assert_eq!(candidate, expected_plan);
}

#[test]
fn invalid_layout_baseline_is_not_rescued_and_execution_rewrites_are_refused() {
    let mut candidate = plan(None);
    binding(&mut candidate, "CARGO_BUILD_BUILD_DIR", "/agents/one/build");
    let original = candidate.clone();
    let calls = Cell::new(0);
    let invalid = super::key(&mut candidate, false, true, |plan| {
        calls.set(calls.get() + 1);
        plan.execution_env.clear();
        Err(LiveRefusal::Facts("invalid baseline".into()))
    });
    assert!(invalid.is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(candidate, original);
    let expected = derive(&mut candidate).unwrap();
    for restore_binding in [false, true] {
        let result = super::key(&mut candidate, false, true, |plan| {
            if super::single_value(&plan.keyed_env, "CARGO_BUILD_BUILD_DIR").is_none() {
                if restore_binding {
                    binding(plan, "CARGO_BUILD_BUILD_DIR", "/agents/one/build");
                } else {
                    plan.execution_env.clear();
                }
            }
            derive(plan)
        })
        .unwrap();
        assert_eq!(result, expected);
        assert_eq!(candidate, original);
    }
}

#[test]
fn full_layout_opt_in_still_keys_other_environment_source_and_flags() {
    let mut baseline = plan(None);
    binding(&mut baseline, "CARGO_BUILD_BUILD_DIR", "/agents/one/build");
    let identity = layout_key(&mut baseline);
    for variant in 0..3 {
        let mut changed = plan(None);
        binding(&mut changed, "CARGO_BUILD_BUILD_DIR", "/agents/two/build");
        if variant == 0 {
            binding(
                &mut changed,
                "CARGO_BUILD_TARGET",
                "aarch64-unknown-linux-gnu",
            );
        } else if variant == 1 {
            changed.invocation.cfgs.push("semantic_change".into());
        }
        let actual = super::key(&mut changed, false, true, |plan| {
            derive_with(plan, if variant == 2 { 8 } else { 7 }, None)
        })
        .unwrap();
        assert_ne!(actual, identity);
    }
}
