//! Closed, complete-workspace Rust leaf-library archive cache identity.
//!
//! This first workspace serving class deliberately retains the entire sealed
//! workspace, including every directory listing. It is not an observed minimal
//! closure and unrelated workspace edits invalidate it. The canonical driver
//! must independently retain the selected ordinary library unit and a Cargo
//! graph with no project executors. Only independently supervised Rlib worker
//! executions in the existing complete-workspace namespace may supply evidence.
//! Metadata, generated/native inputs, explicit externs and implicit crate
//! candidates remain in the fresh execution-only class.

use super::remote::{self, RemoteDependencyOutputClass, RemoteDependencyRefusal};
use super::workspace_execution::workspace_layout;
use super::{
    DependencyActionPlan, DependencyDirectoryFact, DependencySourceKind, LiveDependencyKey,
    LiveRefusal, ToolchainFacts, captured_action_key,
};
use crate::action_key::compute_action_key;
use crate::canonical::CanonicalEncoder;
use crate::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use crate::typed_digest::compute;
use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::input_evidence::ActionInputManifest;
use rabs_protocol::result_identity::TypedDigest;

const KEY_EPOCH: u32 = 4;
const PROJECTION_EPOCH: u32 = 1;
const POLICY_DOMAIN: &str = "rabs.canonical-workspace-closed-rlib.isolation.v1";
const SEMANTICS_DOMAIN: &str = "rabs.canonical-workspace-closed-rlib.semantics.v1";
const SEMANTICS: &str = "completed independently supervised pure Rust leaf-library archive; complete sealed workspace and every directory listing; no project executors, externs, crate candidates, generated or native inputs; exact environment; authenticated drained receipt; existing publication, independent verification, class quarantine and private installation gates";

pub(super) const ISOLATION_PROFILE: &str = "canonical-workspace-closed-rlib-v1: \
    driver-retained Cargo-selected ordinary library build in a graph without \
    project executors; canonical-workspace-exec-v3 namespace explicitly \
    negotiated in Rlib mode; complete immutable canonical workspace with exact \
    file identities and every immediate directory listing including empty \
    directories; exact canonical argv, cwd, manifest path, output placement, \
    primary-package and lint behavior; exact complete presented environment; \
    independently retained complete toolchain and measured ELF runtime; \
    no procfs or entropy devices, only private null device, fresh private \
    output, HOME and temporary storage; no generated tree, native input, \
    explicit extern or implicit Rust artifact candidate; no project code \
    execution, proc macro, incremental state, external linker, binary or \
    harness output, control socket or local wrapper completion authority; \
    compiler dep-info and tracked-control-variable read veto required; exact \
    archive, metadata, dep-info and diagnostic transcript capture; independently \
    authenticated request and completed drained worker receipt; existing \
    publication, independent samples, release authorization, class quarantine \
    and subscriber-owned private installation gates; no provisional outputs";

/// Refine a modeled fresh workspace invocation into a closed archive candidate.
/// This is pure planning, not cache authority. The coordinator must retain the
/// selected Cargo graph, validate empty candidate inventories, and own the exact
/// enforced worker context before publication or replay can be considered.
///
/// # Errors
/// A different source class or any invocation outside the pure leaf Rlib subset.
pub fn plan_closed_workspace_rlib(
    execution: &DependencyActionPlan,
) -> Result<DependencyActionPlan, LiveRefusal> {
    if execution.source_kind != DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "closed workspace planning requires the original fresh workspace plan".into(),
        ));
    }
    let mut plan = execution.clone();
    plan.source_kind = DependencySourceKind::WorkspaceClosedRlib;
    validate_closed_workspace_rlib_plan(&plan)?;
    Ok(plan)
}

/// Validate the bounded invocation contract independently of directory I/O.
///
/// # Errors
/// A noncanonical plan, metadata or nonlibrary output, or executable/generated/
/// native/extern inputs. Directory candidates are additionally checked by
/// [`remote_closed_workspace_rlib_shape`].
pub fn validate_closed_workspace_rlib_plan(plan: &DependencyActionPlan) -> Result<(), LiveRefusal> {
    workspace_layout(plan)?;
    if plan.source_kind != DependencySourceKind::WorkspaceClosedRlib
        || !matches!(plan.invocation.crate_types.as_slice(), [kind] if matches!(kind.as_str(), "lib" | "rlib"))
        || plan
            .invocation
            .passthrough
            .iter()
            .any(|arg| arg == "--test")
        || plan.generated_root.is_some()
        || !plan.native_roots.is_empty()
        || !plan.invocation.native_libs.is_empty()
        || !plan.externs.is_empty()
        || remote::remote_dependency_output_class(&plan.invocation)
            != Ok(RemoteDependencyOutputClass::Rlib)
    {
        return Err(LiveRefusal::Facts(
            "workspace cache admits only closed pure Rust leaf-library archives without generated, native or extern inputs".into(),
        ));
    }
    Ok(())
}

/// Mechanical preparation admission for the closed leaf archive class.
/// Empty search inventories are semantic negative inputs: an implicit crate
/// candidate must not sneak a procedural macro or uncommitted producer into
/// this class merely because no `--extern` argument named it.
///
/// # Errors
/// An incomplete/reordered candidate inventory, any candidate, unsupported
/// loader/runtime layout, or an invocation outside the closed leaf subset.
pub fn remote_closed_workspace_rlib_shape(
    plan: &DependencyActionPlan,
    directories: &[DependencyDirectoryFact],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    validate_closed_workspace_rlib_plan(plan)?;
    remote::remote_execution_shape(plan, directories, toolchain_root)?;
    if directories
        .iter()
        .any(|directory| !directory.artifacts.is_empty())
    {
        return Err(LiveRefusal::Facts(
            "closed workspace leaf archives require empty Rust candidate inventories".into(),
        )
        .into());
    }
    Ok(())
}

/// The separately versioned isolation identity; a fresh workspace policy never
/// compares equal even when it happens to execute the same ordinary library.
///
/// # Errors
/// The plan does not satisfy this class's invocation contract.
pub fn remote_closed_workspace_rlib_isolation_policy(
    plan: &DependencyActionPlan,
) -> Result<TypedDigest, RemoteDependencyRefusal> {
    validate_closed_workspace_rlib_plan(plan)?;
    Ok(isolation_policy())
}

fn isolation_policy() -> TypedDigest {
    compute(POLICY_DOMAIN, ISOLATION_PROFILE.as_bytes())
}

fn execution_semantics() -> TypedDigest {
    compute(SEMANTICS_DOMAIN, SEMANTICS.as_bytes())
}

/// Recognize only this submitted descriptor profile for durable class receipts.
/// This is not execution or publication authority: independently retained graph,
/// inputs, worker context and receipt checks remain mandatory. In particular an
/// arbitrary `RustcWorkspaceCompile` descriptor remains private.
#[must_use]
pub fn is_closed_workspace_rlib_descriptor(descriptor: &ActionDescriptor) -> bool {
    descriptor.action_class == ActionClass::RustcWorkspaceCompile
        && descriptor.key_epoch == KEY_EPOCH
        && descriptor.projection_epoch == PROJECTION_EPOCH
        && descriptor.sandbox_semantic_policy == isolation_policy()
        && descriptor.execution_semantics == execution_semantics()
}

/// Bind the complete retained workspace and exact closed archive execution.
/// There is deliberately no source projection, environment exemption or
/// dependency-artifact equivalence in this first workspace cache class.
///
/// # Errors
/// An invalid class, incomplete file/directory closure, generated run record,
/// unbound toolchain/runtime, or a nonempty Rust candidate inventory.
#[allow(clippy::too_many_arguments)]
pub fn remote_closed_workspace_rlib_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    directories: &[DependencyDirectoryFact],
    inputs: &ActionInputManifest,
    build_script_output: Option<&[u8]>,
    toolchain_root: &str,
    retained_toolchain_sha256: &[u8; 32],
    runtime: &TypedDigest,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    remote_closed_workspace_rlib_shape(plan, directories, toolchain_root)?;
    if build_script_output.is_some() {
        return Err(LiveRefusal::Facts(
            "closed workspace leaf archives cannot consume a build-script run record".into(),
        )
        .into());
    }
    let mut key = captured_action_key(plan, toolchain, &[], directories, None, inputs)?;
    remote::bind_remote_execution_inputs(
        &mut key,
        plan,
        toolchain_root,
        retained_toolchain_sha256,
        runtime,
    )?;
    let mut environment = CanonicalEncoder::new();
    environment.seq(&plan.execution_env, |encoder, (name, value)| {
        encoder.str(name).str(value);
    });
    key.descriptor.environment = compute(
        "rabs.canonical-workspace-closed-rlib.environment.v1",
        &environment.finish(),
    );
    let mut invocation = CanonicalEncoder::new();
    invocation
        .bytes(&plan.invocation.canonical_bytes())
        .str(&plan.compiler)
        .str(&plan.cwd)
        .str(&plan.package_root)
        .str(&plan.source_root)
        .str(&plan.out_dir)
        .str(toolchain_root);
    invocation.seq(&plan.dependency_dirs, |encoder, directory| {
        encoder.str(directory);
    });
    invocation.seq(&plan.invocation.excluded_presentation, |encoder, flag| {
        encoder.str(flag);
    });
    key.descriptor.normalized_invocation = compute(
        "rabs.canonical-workspace-closed-rlib.invocation.v1",
        &invocation.finish(),
    );
    key.descriptor.key_epoch = KEY_EPOCH;
    key.descriptor.projection_epoch = PROJECTION_EPOCH;
    key.descriptor.action_class = ActionClass::RustcWorkspaceCompile;
    key.descriptor.sandbox_semantic_policy = isolation_policy();
    key.descriptor.execution_semantics = execution_semantics();
    key.action_key = compute_action_key(&key.descriptor).final_key;
    key.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&key.descriptor));
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_dependency::{
        ExternFact, LiveRustcRequest, canonical_cargo_dependency_key, dep_info_closure_violation,
        plan_canonical_workspace_execution, remote_workspace_execution_key,
    };
    use rabs_protocol::input_evidence::{
        DirectoryEnumeration, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;

    const HOST: &str = "x86_64-unknown-linux-gnu";
    const WORKSPACE: &str = "/__rabs/workspace";
    const TOOLCHAIN: &str = "/__rabs/toolchain";
    const OUTPUT: &str = "/__rabs/out/cargo/debug/deps";

    fn request() -> (Vec<String>, Vec<(String, String)>) {
        (
            [
                "/__rabs/toolchain/bin/rustc",
                "--crate-name=leaf",
                "--crate-type=lib",
                "--edition=2021",
                "leaf/src/lib.rs",
                "--error-format=json",
                "--json=artifacts",
                "--warn=dead_code",
                "--emit=dep-info,metadata,link",
                "--out-dir",
                OUTPUT,
                "-L",
                "dependency=/__rabs/out/cargo/debug/deps",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            [
                ("HOME", "/__rabs/home"),
                ("CARGO_HOME", "/__rabs/cargo-home"),
                ("CARGO_MANIFEST_DIR", "/__rabs/workspace/leaf"),
                ("CARGO_PKG_NAME", "leaf"),
                ("CARGO_PRIMARY_PACKAGE", "1"),
                ("USER_PAYLOAD", "exact environment"),
                ("CARGO_MAKEFLAGS", "--jobserver-auth=3,4"),
                ("LD_LIBRARY_PATH", "/__rabs/toolchain/lib"),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
        )
    }

    fn execution(argv: &[String], env: &[(String, String)]) -> DependencyActionPlan {
        plan_canonical_workspace_execution(
            LiveRustcRequest {
                argv,
                env,
                cwd: WORKSPACE,
            },
            HOST,
        )
        .unwrap()
    }

    fn plan() -> DependencyActionPlan {
        let (argv, env) = request();
        plan_closed_workspace_rlib(&execution(&argv, &env)).unwrap()
    }

    fn listing(path: String, entries: &[&str]) -> DirectoryEnumeration {
        DirectoryEnumeration {
            virtual_path: RawBytes::new(path.into_bytes()),
            entries: entries.iter().map(|name| RawBytes::from(*name)).collect(),
        }
    }

    fn inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: [
                "Cargo.toml",
                "leaf/Cargo.toml",
                "leaf/src/lib.rs",
                "sibling.txt",
            ]
            .into_iter()
            .map(|relative| PositiveInput {
                virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
                object: ObjectId(compute(
                    "rabs.test.workspace-closed-input.v1",
                    relative.as_bytes(),
                )),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            })
            .collect(),
            directory_enumerations: vec![
                listing(
                    plan.source_virtual_root(),
                    &["Cargo.toml", "empty", "leaf", "sibling.txt"],
                ),
                listing(plan.input_virtual_path("empty"), &[]),
                listing(plan.input_virtual_path("leaf"), &["Cargo.toml", "src"]),
                listing(plan.input_virtual_path("leaf/src"), &["lib.rs"]),
            ],
            ..ActionInputManifest::default()
        }
    }

    fn toolchain() -> ToolchainFacts {
        ToolchainFacts {
            compiler_binary_digest: compute("rabs.test.workspace-closed-input.v1", b"compiler"),
            verbose_version: format!("rustc 1.100.0\nhost: {HOST}\nLLVM version: 21"),
            sysroot_root_digest: compute("rabs.test.workspace-closed-input.v1", b"sysroot"),
            runtime_libraries: Vec::new(),
        }
    }

    fn directories(plan: &DependencyActionPlan) -> Vec<DependencyDirectoryFact> {
        plan.dependency_dirs
            .iter()
            .map(|path| DependencyDirectoryFact {
                path: path.clone(),
                artifacts: Vec::new(),
            })
            .collect()
    }

    fn key(
        plan: &DependencyActionPlan,
        inputs: &ActionInputManifest,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_closed_workspace_rlib_key(
            plan,
            &toolchain(),
            &directories(plan),
            inputs,
            None,
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
    }

    #[test]
    fn closed_workspace_rlib_is_distinct_from_every_existing_cache_and_fresh_profile() {
        let (argv, env) = request();
        let fresh = execution(&argv, &env);
        let plan = plan_closed_workspace_rlib(&fresh).unwrap();
        let input = inputs(&plan);
        let key = key(&plan, &input).unwrap();
        assert_eq!(plan.invocation, fresh.invocation);
        assert_eq!(plan.execution_env, fresh.execution_env);
        assert_eq!(plan.keyed_env, plan.execution_env);
        assert_eq!(plan.cwd, WORKSPACE);
        assert_eq!(plan.source_root, WORKSPACE);
        assert_eq!(
            plan.source_kind.as_str(),
            "canonical-workspace-closed-rlib-v1"
        );
        assert!(is_closed_workspace_rlib_descriptor(&key.descriptor));
        let fresh_key = remote_workspace_execution_key(
            &fresh,
            &toolchain(),
            &directories(&fresh),
            &input,
            None,
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
        .unwrap();
        assert_ne!(key.action_key, fresh_key.action_key);
        assert!(!is_closed_workspace_rlib_descriptor(&fresh_key.descriptor));
        assert!(
            remote_closed_workspace_rlib_key(
                &fresh,
                &toolchain(),
                &directories(&fresh),
                &input,
                None,
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
            )
            .is_err()
        );
        assert!(
            remote_workspace_execution_key(
                &plan,
                &toolchain(),
                &directories(&plan),
                &input,
                None,
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
            )
            .is_err()
        );
        assert!(
            canonical_cargo_dependency_key(
                &plan,
                &toolchain(),
                &[],
                &directories(&plan),
                None,
                &input
            )
            .is_err()
        );
        assert!(
            remote::remote_dependency_key(
                &plan,
                &toolchain(),
                &directories(&plan),
                &input,
                None,
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
            )
            .is_err()
        );
    }

    #[test]
    fn closed_workspace_rlib_rejects_metadata_harness_generated_native_and_extern_inputs() {
        for flags in [
            vec!["--emit=dep-info,metadata"],
            vec!["--emit=dep-info,metadata", "--crate-type=bin"],
            vec!["--emit=dep-info,metadata", "--test"],
            vec!["--extern=other=/__rabs/out/cargo/debug/deps/libother.rlib"],
        ] {
            let (mut argv, env) = request();
            if flags.iter().any(|arg| arg.starts_with("--emit=")) {
                argv.retain(|arg| !arg.starts_with("--emit="));
            }
            if flags.iter().any(|arg| arg.starts_with("--crate-type=")) {
                argv.retain(|arg| !arg.starts_with("--crate-type="));
            }
            argv.extend(flags.iter().map(|arg| (*arg).to_owned()));
            assert!(
                plan_closed_workspace_rlib(&execution(&argv, &env)).is_err(),
                "{flags:?}"
            );
        }
        let (mut argv, mut env) = request();
        let generated = "/__rabs/out/cargo/debug/build/leaf-123/out";
        env.push(("OUT_DIR".into(), generated.into()));
        assert!(plan_closed_workspace_rlib(&execution(&argv, &env)).is_err());
        argv.extend([format!("-Lnative={generated}"), "-lstatic=leaf".into()]);
        assert!(plan_closed_workspace_rlib(&execution(&argv, &env)).is_err());
        let plan = plan();
        assert!(
            remote_closed_workspace_rlib_key(
                &plan,
                &toolchain(),
                &directories(&plan),
                &inputs(&plan),
                Some(b""),
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
            )
            .is_err()
        );
    }

    #[test]
    fn closed_workspace_rlib_binds_sibling_bytes_and_complete_negative_directory_topology() {
        let plan = plan();
        let input = inputs(&plan);
        let original = key(&plan, &input).unwrap().action_key;
        let mut changed = input.clone();
        changed.inputs.last_mut().unwrap().object = ObjectId(compute(
            "rabs.test.workspace-closed-input.v1",
            b"changed sibling",
        ));
        assert_ne!(key(&plan, &changed).unwrap().action_key, original);
        changed = input.clone();
        changed.inputs.last_mut().unwrap().executable = true;
        assert_ne!(key(&plan, &changed).unwrap().action_key, original);
        changed = input.clone();
        changed.directory_enumerations[0]
            .entries
            .push(RawBytes::from("z_empty"));
        changed
            .directory_enumerations
            .push(listing(plan.input_virtual_path("z_empty"), &[]));
        assert_ne!(key(&plan, &changed).unwrap().action_key, original);
        changed.directory_enumerations.pop();
        assert!(
            key(&plan, &changed).is_err(),
            "an unbound empty directory must refuse"
        );
        changed = input.clone();
        changed.directory_enumerations.remove(1);
        assert!(key(&plan, &changed).is_err());
        changed = input;
        changed.inputs.pop();
        assert!(
            key(&plan, &changed).is_err(),
            "a named but uncaptured sibling must refuse"
        );
    }

    #[test]
    fn closed_workspace_rlib_keys_every_environment_value_but_keeps_tracked_control_read_veto() {
        let (argv, env) = request();
        let plan = plan_closed_workspace_rlib(&execution(&argv, &env)).unwrap();
        let original = key(&plan, &inputs(&plan)).unwrap().action_key;
        for name in ["USER_PAYLOAD", "CARGO_MAKEFLAGS", "CARGO_PRIMARY_PACKAGE"] {
            let mut changed = env.clone();
            changed
                .iter_mut()
                .find(|(key, _)| key == name)
                .unwrap()
                .1
                .push_str(" changed");
            let next = plan_closed_workspace_rlib(&execution(&argv, &changed)).unwrap();
            assert_ne!(
                key(&next, &inputs(&next)).unwrap().action_key,
                original,
                "{name}"
            );
        }
        let read = b"# env-dep:CARGO_MAKEFLAGS=--jobserver-auth=3,4\n";
        assert!(dep_info_closure_violation(&plan, read, |_| true).is_some());
        assert!(
            dep_info_closure_violation(
                &plan,
                b"# env-dep:USER_PAYLOAD=exact environment\n",
                |_| true
            )
            .is_none()
        );
    }

    #[test]
    fn closed_workspace_rlib_refuses_implicit_crates_and_incomplete_candidate_inventories() {
        let plan = plan();
        let mut candidates = directories(&plan);
        candidates[0].artifacts.push(ExternFact {
            path: format!("{OUTPUT}/libimplicit.rmeta"),
            content_digest: compute("rabs.test.workspace-closed-input.v1", b"implicit crate"),
        });
        assert!(remote_closed_workspace_rlib_shape(&plan, &candidates, TOOLCHAIN).is_err());
        assert!(remote_closed_workspace_rlib_shape(&plan, &[], TOOLCHAIN).is_err());
        candidates[0].artifacts.clear();
        candidates[0].path.push_str("/other");
        assert!(remote_closed_workspace_rlib_shape(&plan, &candidates, TOOLCHAIN).is_err());
    }

    #[test]
    fn closed_workspace_rlib_descriptor_receipt_requires_every_profile_discriminator() {
        let plan = plan();
        let descriptor = key(&plan, &inputs(&plan)).unwrap().descriptor;
        for change in 0..5 {
            let mut other = descriptor.clone();
            match change {
                0 => other.key_epoch += 1,
                1 => other.projection_epoch += 1,
                2 => other.action_class = ActionClass::RustcDependencyCompile,
                3 => other.sandbox_semantic_policy.bytes[0] ^= 1,
                _ => other.execution_semantics.bytes[0] ^= 1,
            }
            assert!(!is_closed_workspace_rlib_descriptor(&other));
        }
    }

    #[test]
    fn closed_workspace_rlib_requires_exact_retained_toolchain_and_measured_runtime() {
        let plan = plan();
        let input = inputs(&plan);
        let original = key(&plan, &input).unwrap().action_key;
        let compute_key = |retained: &[u8; 32], runtime: &TypedDigest| {
            remote_closed_workspace_rlib_key(
                &plan,
                &toolchain(),
                &directories(&plan),
                &input,
                None,
                TOOLCHAIN,
                retained,
                runtime,
            )
        };
        assert_ne!(
            compute_key(
                &[40; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime")
            )
            .unwrap()
            .action_key,
            original
        );
        assert_ne!(
            compute_key(
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"changed runtime")
            )
            .unwrap()
            .action_key,
            original
        );
        assert!(
            compute_key(
                &[39; 32],
                &compute("rabs.test.untrusted-runtime.v1", b"runtime")
            )
            .is_err()
        );
    }
}
