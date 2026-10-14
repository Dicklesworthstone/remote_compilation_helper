//! Opt-in cross-worktree reuse for compiles with an EMPTY build-script OUT_DIR.
//!
//! Enable in the daemon with RABS_REUSE_EMPTY_OUT_DIR=1, in addition to the
//! existing live dependency opt-in. This does not cache build-script execution.
//! Cargo still runs it; the exact captured stdout, cfgs, custom rustc-env values,
//! complete source tree and every dependency remain inputs to the compiler key.
//!
//! Only the key's generated-root spelling is projected. The compiler and all
//! filesystem guards retain the REAL paths and environment. OUT_DIR remains in
//! execution_env but not keyed_env: the existing dep_info_closure_violation
//! guard therefore forbids publication on ANY tracked read of it (env! and
//! option_env! included). Reading a generated file also refuses: the captured
//! generated manifest has no members. No source scanning or filename heuristic
//! claims that a compiler did not read OUT_DIR.
//!
//! A separate policy digest requires new comparison evidence for this class.
//! Existing exact-path entries cannot serve it, and no sampling, quarantine,
//! capture-acknowledgment or installation gate is bypassed. Nonempty trees and
//! requests without this opt-in keep their exact keys. An empty-tree compile
//! that actually reads OUT_DIR runs normally but is not cached in this class;
//! disabling the opt-in retains the existing exact-path caching behavior.

use crate::edge::live_facts::{GENERATED_ROOT, PackageFacts};
use rabs_key::action_key::compute_action_key;
use rabs_key::canonical::CanonicalEncoder;
use rabs_key::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use rabs_key::live_dependency::{
    DOMAIN_LIVE_ISOLATION, DependencyActionPlan, DependencyDirectoryFact, ExternFact,
    LiveDependencyKey, LiveRefusal, ToolchainFacts, live_dependency_key,
};
use rabs_key::typed_digest::compute;
use rabs_protocol::input_evidence::ActionInputManifest;

const EMPTY_ROOT: &str = "/__rabs/unused-build-script-out";
const POLICY_TAG: &str = "rabs.live-dependency.empty-out-dir.v1";

pub(super) fn enabled() -> bool {
    matches!(
        std::env::var("RABS_REUSE_EMPTY_OUT_DIR").as_deref(),
        Ok("1" | "true" | "on")
    )
}

fn captured_empty(
    plan: &DependencyActionPlan,
    package: &PackageFacts,
    inputs: &ActionInputManifest,
) -> bool {
    let Some(root) = &plan.generated_root else {
        return false;
    };
    // Require the actual capture, not an empty Vec or a request's assertion.
    // Empty subdirectories are deliberately NOT projected by this first class.
    if package.build_script_output.is_none()
        || !package.generated_files.is_empty()
        || !package
            .snapshot
            .manifest(GENERATED_ROOT)
            .is_some_and(|manifest| manifest.members.is_empty())
    {
        return false;
    }
    let generated_prefix = format!("{}/", plan.generated_virtual_root());
    if inputs.inputs.iter().any(|input| {
        input
            .virtual_path
            .as_bytes()
            .starts_with(generated_prefix.as_bytes())
    }) {
        return false;
    }
    // Presence is part of this profile. Do not conflate unset, duplicate or
    // custom-overridden OUT_DIR with Cargo's normal generated-root binding.
    [&plan.execution_env, &plan.keyed_env]
        .into_iter()
        .all(|env| {
            let mut values = env.iter().filter(|(name, _)| name == "OUT_DIR");
            values.next().is_some_and(|(_, value)| value == root) && values.next().is_none()
        })
}

/// Derive a key and, only on successful projection, install its read veto in
/// the actual execution plan. The returned plan must travel with the request
/// into the ordinary before-serving and post-execution closure checks.
pub(super) fn key(
    plan: &mut DependencyActionPlan,
    toolchain: &ToolchainFacts,
    externs: &[ExternFact],
    directories: &[DependencyDirectoryFact],
    package: &PackageFacts,
    inputs: &ActionInputManifest,
    enable_projection: bool,
) -> Result<LiveDependencyKey, LiveRefusal> {
    let record = package.build_script_output.as_deref();
    // Validate all original facts first, including directory-source witnesses,
    // generated inputs, environment directives and exact dependency coverage.
    let exact = live_dependency_key(plan, toolchain, externs, directories, record, inputs)?;
    if !enable_projection || !captured_empty(plan, package, inputs) {
        return Ok(exact);
    }
    let mut projected = plan.clone();
    projected.generated_root = Some(EMPTY_ROOT.to_owned());
    projected.keyed_env.retain(|(name, _)| name != "OUT_DIR");
    let Ok(mut keyed) =
        live_dependency_key(&projected, toolchain, externs, directories, record, inputs)
    else {
        // E.g. an explicit rustc-env=OUT_DIR directive requires exact keying.
        // Failed optimization must not mutate the caller's execution contract.
        return Ok(exact);
    };
    let original_policy = &keyed.descriptor.sandbox_semantic_policy;
    let mut policy = CanonicalEncoder::new();
    policy
        .str(POLICY_TAG)
        .str(original_policy.domain)
        .bytes(&original_policy.bytes)
        .str("complete empty generated tree; OUT_DIR present; tracked reads refuse publication");
    keyed.descriptor.sandbox_semantic_policy = compute(DOMAIN_LIVE_ISOLATION, &policy.finish());
    keyed.action_key = compute_action_key(&keyed.descriptor).final_key;
    keyed.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&keyed.descriptor));

    // Do NOT replace the caller's plan with `projected`: that would give the
    // compiler/guards a fictional OUT_DIR. Removing this one keyed name makes
    // the existing unkeyed-environment-read guard reject its observed reads.
    plan.keyed_env.retain(|(name, _)| name != "OUT_DIR");
    Ok(keyed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::live_facts::LiveFacts;
    use rabs_key::build_script_directives::bind_rustc_environment;
    use rabs_key::live_dependency::{
        LiveRustcRequest, dep_info_closure_violation, plan_dependency_action,
    };
    use rabs_protocol::input_evidence::{
        INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const HOST: &str = "x86_64-unknown-linux-gnu";
    const RECORD: &[u8] = b"cargo::rustc-env=BUILD_LABEL=ready\ncargo::rustc-cfg=configured\n";

    struct Fixture {
        _temporary: tempfile::TempDir,
        root: PathBuf,
        package: PathBuf,
        facts: Arc<LiveFacts>,
    }

    struct Captured {
        plan: DependencyActionPlan,
        package: Arc<PackageFacts>,
        inputs: ActionInputManifest,
    }

    fn toolchain() -> ToolchainFacts {
        let identity = compute("rabs.test.toolchain.v1", b"same compiler");
        ToolchainFacts {
            compiler_binary_digest: identity.clone(),
            verbose_version: format!("rustc test\nhost: {HOST}\n"),
            sysroot_root_digest: identity,
            runtime_libraries: Vec::new(),
        }
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().canonicalize().unwrap();
            let package = root.join("cargo/registry/src/test-index/demo-1.0.0");
            std::fs::create_dir_all(package.join("src")).unwrap();
            std::fs::write(package.join("Cargo.toml"), b"[package]\nname='demo'\n").unwrap();
            std::fs::write(package.join("build.rs"), b"fn main() {}\n").unwrap();
            std::fs::write(package.join("src/lib.rs"), b"pub const VALUE: u32 = 7;\n").unwrap();
            Self {
                _temporary: temporary,
                root,
                package,
                facts: LiveFacts::new(),
            }
        }

        fn capture(
            &self,
            label: &str,
            record: &[u8],
            members: &[(&str, Option<&[u8]>)],
        ) -> Captured {
            let output = self.root.join(label).join("deps");
            let generated = self.root.join(label).join("build/demo/out");
            std::fs::create_dir_all(&output).unwrap();
            std::fs::create_dir_all(&generated).unwrap();
            for (name, bytes) in members {
                let path = generated.join(name);
                if let Some(bytes) = bytes {
                    std::fs::write(path, bytes).unwrap();
                } else {
                    std::fs::create_dir_all(path).unwrap();
                }
            }
            let unit = generated.parent().unwrap();
            std::fs::write(unit.join("root-output"), generated.to_str().unwrap()).unwrap();
            std::fs::write(unit.join("output"), record).unwrap();
            let args = vec![
                "/toolchain/bin/rustc".into(),
                "--crate-name=demo".into(),
                "--crate-type=lib".into(),
                "--edition=2021".into(),
                "--emit=dep-info,metadata,link".into(),
                "--error-format=json".into(),
                "--cap-lints=allow".into(),
                "--cfg=configured".into(),
                "--out-dir".into(),
                output.to_str().unwrap().to_owned(),
                self.package.join("src/lib.rs").to_str().unwrap().to_owned(),
            ];
            let env = vec![
                (
                    "CARGO_HOME".into(),
                    self.root.join("cargo").to_str().unwrap().to_owned(),
                ),
                (
                    "CARGO_MANIFEST_DIR".into(),
                    self.package.to_str().unwrap().to_owned(),
                ),
                ("CARGO_PKG_NAME".into(), "demo".into()),
                ("OUT_DIR".into(), generated.to_str().unwrap().to_owned()),
                ("BUILD_LABEL".into(), "ready".into()),
                ("CARGO_MAKEFLAGS".into(), "-j --jobserver-fds=3,4".into()),
            ];
            let mut plan = plan_dependency_action(
                LiveRustcRequest {
                    argv: &args,
                    cwd: self.package.to_str().unwrap(),
                    env: &env,
                },
                HOST,
            )
            .unwrap();
            let package = self
                .facts
                .package(&self.package, plan.source_kind, Some(&generated))
                .unwrap();
            bind_rustc_environment(&mut plan, package.build_script_output.as_deref(), &env)
                .unwrap();
            let mut inputs = ActionInputManifest {
                schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
                ..ActionInputManifest::default()
            };
            for (files, generated) in [(&package.files, false), (&package.generated_files, true)] {
                inputs
                    .inputs
                    .extend(files.iter().map(|(relative, object, executable)| {
                        let path = if generated {
                            plan.generated_input_virtual_path(relative)
                        } else {
                            plan.input_virtual_path(relative)
                        };
                        PositiveInput {
                            virtual_path: RawBytes::new(path.into_bytes()),
                            object: ObjectId(object.clone()),
                            file_type: InputFileType::Regular,
                            executable: *executable,
                            symlink_resolution: Vec::new(),
                        }
                    }));
            }
            Captured {
                plan,
                package,
                inputs,
            }
        }
    }

    impl Captured {
        fn exact(&self) -> LiveDependencyKey {
            live_dependency_key(
                &self.plan,
                &toolchain(),
                &[],
                &[],
                self.package.build_script_output.as_deref(),
                &self.inputs,
            )
            .unwrap()
        }

        fn key(&mut self, enabled: bool) -> Result<LiveDependencyKey, LiveRefusal> {
            key(
                &mut self.plan,
                &toolchain(),
                &[],
                &[],
                &self.package,
                &self.inputs,
                enabled,
            )
        }

        fn closure(&self, dep_info: &str) -> Option<String> {
            dep_info_closure_violation(&self.plan, dep_info.as_bytes(), |path| {
                self.inputs
                    .inputs
                    .iter()
                    .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
            })
        }
    }

    #[test]
    fn empty_out_dir_disabled_keeps_exact_key_and_complete_execution_plan() {
        let fixture = Fixture::new();
        let mut captured = fixture.capture("one", RECORD, &[]);
        let original = captured.plan.clone();
        let expected = captured.exact();
        assert_eq!(captured.key(false).unwrap(), expected);
        assert_eq!(captured.plan, original);
    }

    #[test]
    fn empty_out_dir_reuses_across_worktrees_without_rewriting_the_compiler() {
        let fixture = Fixture::new();
        let mut a = fixture.capture("one", RECORD, &[]);
        let mut b = fixture.capture("two", RECORD, &[]);
        let original_a = a.plan.clone();
        let original_b = b.plan.clone();
        let exact_a = a.exact();
        let exact_b = b.exact();
        assert_ne!(
            exact_a.action_key, exact_b.action_key,
            "baseline must reproduce the placement miss"
        );
        let projected_a = a.key(true).unwrap();
        let projected_b = b.key(true).unwrap();
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
        for (actual, original) in [(&a.plan, original_a), (&b.plan, original_b)] {
            let mut expected = original.clone();
            expected.keyed_env.retain(|(name, _)| name != "OUT_DIR");
            assert_eq!(*actual, expected, "only the tracked-read veto may change");
            assert_eq!(actual.execution_env, original.execution_env);
            assert_eq!(actual.generated_root, original.generated_root);
            assert!(
                !actual
                    .execution_env
                    .iter()
                    .any(|(_, value)| value.contains(EMPTY_ROOT))
            );
        }
    }

    #[test]
    fn empty_out_dir_reads_and_generated_reads_cannot_publish_projected_results() {
        let fixture = Fixture::new();
        let mut captured = fixture.capture("one", RECORD, &[]);
        let root = captured.plan.generated_root.clone().unwrap();
        let good = format!(
            "{}/demo.d: {}/src/lib.rs\n",
            captured.plan.out_dir, captured.plan.source_root
        );
        captured.key(true).unwrap();
        assert_eq!(captured.closure(&good), None);
        assert_eq!(
            captured.closure(&(good.clone() + "# env-dep:BUILD_LABEL=ready\n")),
            None
        );
        for suffix in [
            format!("# env-dep:OUT_DIR={root}\n"),
            "# env-dep:OUT_DIR\n".to_owned(),
            "# env-dep:CARGO_MAKEFLAGS=-j\n".to_owned(),
        ] {
            assert!(
                captured
                    .closure(&(good.clone() + &suffix))
                    .unwrap()
                    .contains("unkeyed variable")
            );
        }
        for path in [
            format!("{root}/generated.rs"),
            format!("{root}/../outside.rs"),
        ] {
            let dep_info = format!("{}/demo.d: {path}\n", captured.plan.out_dir);
            assert!(captured.closure(&dep_info).is_some());
        }
    }

    #[test]
    fn nonempty_generated_trees_and_even_empty_subdirectories_keep_exact_keys() {
        let fixture = Fixture::new();
        for (label, members) in [
            (
                "files",
                vec![(
                    "value.rs",
                    Some(b"pub const GENERATED: u32 = 9;".as_slice()),
                )],
            ),
            ("directories", vec![("empty", None)]),
        ] {
            let mut captured = fixture.capture(label, RECORD, &members);
            let original = captured.plan.clone();
            let expected = captured.exact();
            assert_eq!(captured.key(true).unwrap(), expected);
            assert_eq!(captured.plan, original);
            let root = captured.plan.generated_root.as_ref().unwrap();
            assert_eq!(
                captured.closure(&format!("# env-dep:OUT_DIR={root}\n")),
                None
            );
        }
    }

    #[test]
    fn empty_out_dir_keeps_exact_script_stdout_source_cfg_and_other_environment() {
        let fixture = Fixture::new();
        let mut first = fixture.capture("one", RECORD, &[]);
        let key = first.key(true).unwrap().action_key;
        let mut record = fixture.capture("two", b"cargo::rustc-env=BUILD_LABEL=ready\n", &[]);
        assert_ne!(record.key(true).unwrap().action_key, key);
        let mut cfg = fixture.capture("three", RECORD, &[]);
        cfg.plan.invocation.cfgs.push("another_cfg".to_owned());
        assert_ne!(cfg.key(true).unwrap().action_key, key);
        let mut env = fixture.capture("four", RECORD, &[]);
        env.plan
            .keyed_env
            .push(("RUST_SOMETHING".into(), "semantic".into()));
        env.plan
            .execution_env
            .push(("RUST_SOMETHING".into(), "semantic".into()));
        assert_ne!(env.key(true).unwrap().action_key, key);
        std::fs::write(
            fixture.package.join("src/lib.rs"),
            b"pub const VALUE: u32 = 8;\n",
        )
        .unwrap();
        let mut source = fixture.capture("five", RECORD, &[]);
        assert_ne!(source.key(true).unwrap().action_key, key);
    }

    #[test]
    fn empty_out_dir_does_not_rewrite_paths_embedded_in_other_keyed_values() {
        let fixture = Fixture::new();
        let mut keys = Vec::new();
        for label in ["one", "two"] {
            let mut captured = fixture.capture(label, RECORD, &[]);
            let root = captured.plan.generated_root.clone().unwrap();
            for env in [
                &mut captured.plan.keyed_env,
                &mut captured.plan.execution_env,
            ] {
                env.push(("RUST_BUILD_PATH".into(), root.clone()));
            }
            keys.push(captured.key(true).unwrap().action_key);
        }
        assert_ne!(keys[0], keys[1]);
    }

    #[test]
    fn empty_out_dir_growth_and_run_record_replacement_invalidate_retained_capture() {
        let fixture = Fixture::new();
        let mut captured = fixture.capture("one", RECORD, &[]);
        let previous = captured.key(true).unwrap().action_key;
        let root = Path::new(captured.plan.generated_root.as_ref().unwrap());
        captured.package.verify_unchanged(&fixture.package).unwrap();
        std::fs::write(root.join("new.rs"), b"generated later").unwrap();
        assert!(captured.package.verify_unchanged(&fixture.package).is_err());
        let mut next = fixture.capture("one", RECORD, &[]);
        let exact = next.exact();
        assert_eq!(next.key(true).unwrap(), exact);
        assert_ne!(exact.action_key, previous);
        std::fs::write(
            root.parent().unwrap().join("output"),
            b"different script output\n",
        )
        .unwrap();
        assert!(next.package.verify_unchanged(&fixture.package).is_err());
    }

    #[test]
    fn empty_out_dir_requires_captured_run_record_and_valid_original_facts() {
        let fixture = Fixture::new();
        let missing = fixture.capture("one", RECORD, &[]);
        let root = Path::new(missing.plan.generated_root.as_ref().unwrap());
        std::fs::rename(
            root.parent().unwrap().join("output"),
            fixture.root.join("retained-output-record"),
        )
        .unwrap();
        assert!(
            fixture
                .facts
                .package(&fixture.package, missing.plan.source_kind, Some(root))
                .is_err()
        );
        assert!(missing.package.verify_unchanged(&fixture.package).is_err());
        let mut invalid = fixture.capture("two", RECORD, &[]);
        invalid.inputs.inputs.clear();
        let original = invalid.plan.clone();
        assert!(invalid.key(true).is_err());
        assert_eq!(invalid.plan, original);
    }
}
