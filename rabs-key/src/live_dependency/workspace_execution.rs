//! Fresh, request-owned execution of canonical Cargo workspace libraries.
//!
//! This identity binds the complete retained workspace and generated trees,
//! compiler environment and exact Rust dependency artifacts. It is transport
//! and execution identity only: no lookup, publication, shared serving or
//! provisional metadata release is authorized by this class. The coordinator
//! must independently retain Cargo-selected unit membership and the worker's
//! completed, drained execution before installing that request's outputs.

use super::remote::{self, RemoteDependencyOutputClass, RemoteDependencyRefusal};
use super::{
    DependencyActionPlan, DependencyDirectoryFact, DependencySourceKind, LiveDependencyKey,
    LiveRefusal, LiveRustcRequest, ToolchainFacts, captured_action_key, env_value,
    normalized_generated_relative, plain_path_in_profile, plan_in_profile, within,
};
use crate::action_key::compute_action_key;
use crate::canonical::CanonicalEncoder;
use crate::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use crate::invocation::SourceInput;
use crate::typed_digest::compute;
use rabs_protocol::descriptor::ActionClass;
use rabs_protocol::input_evidence::ActionInputManifest;
use rabs_protocol::result_identity::TypedDigest;

pub(super) const WORKSPACE: &str = "/__rabs/workspace";
const COMPILER: &str = "/__rabs/toolchain/bin/rustc";
const TOOLCHAIN: &str = "/__rabs/toolchain";
const TARGET: &str = "/__rabs/out/cargo";
const POLICY_DOMAIN: &str = "rabs.canonical-workspace-execution.isolation.v1";
pub(super) const WORKSPACE_EXECUTION_PROFILE: &str = "canonical-workspace-execution-only-v1: \
    canonical-workspace-exec-v1 explicitly negotiated; one fresh independently \
    supervised worker rustc for a coordinator-retained Cargo-selected library; \
    exact canonical argv, working directory, manifest directory, complete \
    presented environment including primary-package and lint behavior; complete \
    immutable canonical workspace and generated OUT_DIR trees with exact file \
    identities and every immediate directory listing including empty directories; \
    independently retained toolchain and measured ELF runtime; exact read-only \
    Rust metadata/archive candidate inventories; fresh private output, HOME and \
    temporary storage; metadata or closed pure-Rust archive mode, no native link \
    inputs, executable externs, incremental state or coordinator control socket; \
    authenticated request-owned receipt and drained process group required; \
    installation only into this live request's exact declared output paths; no \
    dependency or workspace action-cache lookup, publication, shared result \
    serving, local completion authority or provisional metadata release";

pub(super) fn resolved_workspace_source(cwd: &str, source: &str) -> Option<String> {
    if !plain_path_in_profile(cwd, true) || !(cwd == WORKSPACE || within(cwd, WORKSPACE)) {
        return None;
    }
    let resolved = if source.starts_with('/') {
        if !plain_path_in_profile(source, true) {
            return None;
        }
        source.to_owned()
    } else {
        if !normalized_generated_relative(source) {
            return None;
        }
        format!("{cwd}/{source}")
    };
    (plain_path_in_profile(&resolved, true) && within(&resolved, WORKSPACE)).then_some(resolved)
}

/// Resolve a workspace source for matching against the retained Cargo unit
/// graph without changing the actual invocation. A normalized relative source
/// is interpreted from the original canonical cwd, which may differ from the
/// member's CARGO_MANIFEST_DIR. Traversal and alternate path spellings refuse.
///
/// # Errors
/// A nonworkspace plan, stdin, or a source outside the complete retained tree.
pub fn workspace_source_path(plan: &DependencyActionPlan) -> Result<String, LiveRefusal> {
    if !plan.canonical_cargo
        || plan.source_kind != DependencySourceKind::WorkspaceExecutionOnly
        || plan.source_root != WORKSPACE
    {
        return Err(LiveRefusal::Facts(
            "workspace source resolution requires its retained canonical execution class".into(),
        ));
    }
    let Some(SourceInput::Path(source)) = &plan.invocation.source else {
        return Err(LiveRefusal::SourceOutsidePackage("no source path".into()));
    };
    resolved_workspace_source(&plan.cwd, source)
        .ok_or_else(|| LiveRefusal::SourceOutsidePackage(source.clone()))
}

pub(super) fn workspace_layout(plan: &DependencyActionPlan) -> Result<(), LiveRefusal> {
    if !plan.canonical_cargo
        || plan.source_kind != DependencySourceKind::WorkspaceExecutionOnly
        || plan.source_root != WORKSPACE
        || plan.source_dir_name != "workspace"
        || plan.directory_source_manifest.is_some()
        || plan.compiler != COMPILER
        || plan.invocation.compiler_argv0 != COMPILER
        || env_value(&plan.execution_env, "CARGO_HOME") != Some("/__rabs/cargo-home")
        || env_value(&plan.execution_env, "HOME") != Some("/__rabs/home")
        || env_value(&plan.execution_env, "CARGO_MANIFEST_DIR") != Some(plan.package_root.as_str())
        || env_value(&plan.execution_env, "CARGO_PKG_NAME").is_none()
        || !plain_path_in_profile(&plan.package_root, true)
        || !(plan.package_root == WORKSPACE || within(&plan.package_root, WORKSPACE))
        || !plain_path_in_profile(&plan.out_dir, true)
        || !within(&plan.out_dir, TARGET)
        || plan.invocation.out_dir.as_deref() != Some(plan.out_dir.as_str())
        || plan
            .dependency_dirs
            .iter()
            .any(|directory| !plain_path_in_profile(directory, true) || !within(directory, TARGET))
        || plan.keyed_env != plan.execution_env
        || plan
            .execution_env
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
        || plan.execution_env.iter().any(|(name, _)| {
            name != "CARGO_PRIMARY_PACKAGE" && super::REFUSED_NAMES.contains(&name.as_str())
        })
        || plan.target_triple
            != plan
                .invocation
                .target
                .as_ref()
                .unwrap_or(&plan.host_triple)
                .as_str()
    {
        return Err(LiveRefusal::Facts(
            "workspace execution plan differs from the complete canonical Cargo layout".into(),
        ));
    }
    workspace_source_path(plan)?;
    if let Some(root) = &plan.generated_root {
        let overlaps = |other: &str| root == other || within(root, other) || within(other, root);
        if !plain_path_in_profile(root, true)
            || !within(root, TARGET)
            || [plan.source_root.as_str(), plan.out_dir.as_str(), TOOLCHAIN]
                .into_iter()
                .chain(plan.dependency_dirs.iter().map(String::as_str))
                .any(overlaps)
        {
            return Err(LiveRefusal::Facts(
                "workspace generated inputs must be disjoint within the Cargo target".into(),
            ));
        }
    }
    if env_value(&plan.execution_env, "OUT_DIR") != plan.generated_root.as_deref() {
        return Err(LiveRefusal::Facts(
            "workspace generated inputs must preserve the exact OUT_DIR environment".into(),
        ));
    }
    Ok(())
}

/// Plan a fresh canonical workspace library compilation. The caller must match
/// the resolved source, crate and selected mode against its driver-owned Cargo
/// graph before observing or dispatching inputs. Canonical path spelling alone
/// cannot select this entry point on the ordinary wrapper endpoint.
///
/// The complete workspace is execution input, not a minimal cache closure.
/// Primary-package environment, uncapped warnings and relative source argv are
/// preserved. No compiler output from this class may enter dependency serving.
///
/// # Errors
/// Unsupported output/native/proc-macro inputs, unsafe canonical paths or an
/// environment outside the independently retained worker execution contract.
pub fn plan_canonical_workspace_execution(
    request: LiveRustcRequest<'_>,
    host_triple: &str,
) -> Result<DependencyActionPlan, LiveRefusal> {
    let plan = plan_in_profile(request, host_triple, None, true, true)?;
    workspace_layout(&plan)?;
    remote::remote_dependency_output_class(&plan.invocation)
        .map_err(|error| LiveRefusal::Facts(error.to_string()))?;
    remote::remote_loader_search_paths(&plan, TOOLCHAIN)
        .map_err(|error| LiveRefusal::Facts(error.to_string()))?;
    Ok(plan)
}

/// Check mechanical worker execution eligibility after complete Rust candidate
/// observation. This authorizes preparation only, never result-cache access.
pub fn remote_workspace_execution_shape(
    plan: &DependencyActionPlan,
    directories: &[DependencyDirectoryFact],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    workspace_layout(plan)?;
    remote::remote_execution_shape(plan, directories, toolchain_root)
}

/// Distinct policy bound to this fresh workspace execution identity. It cannot
/// satisfy any remote dependency publication or serving policy comparison.
pub fn remote_workspace_execution_isolation_policy(
    plan: &DependencyActionPlan,
) -> Result<TypedDigest, RemoteDependencyRefusal> {
    workspace_layout(plan)?;
    let mode = match remote::remote_dependency_output_class(&plan.invocation)? {
        RemoteDependencyOutputClass::Metadata => "metadata",
        RemoteDependencyOutputClass::Rlib => "rlib-no-procfs-or-entropy",
    };
    let mut policy = CanonicalEncoder::new();
    policy.str(WORKSPACE_EXECUTION_PROFILE).str(mode);
    Ok(compute(POLICY_DOMAIN, &policy.finish()))
}

/// Bind one canonical workspace request's complete retained execution inputs.
/// The result is an execution identity, not permission to skip a compiler,
/// publish a result, join shared cache singleflight, or serve another request.
/// The original observations and selected-unit capability must remain retained
/// through verified installation of this request's freshly executed outputs.
///
/// # Errors
/// Any incomplete source/generated directory closure, unbound compiler or Rust
/// artifact input, wrong runtime observer, or inconsistent workspace profile.
#[allow(clippy::too_many_arguments)]
pub fn remote_workspace_execution_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    directories: &[DependencyDirectoryFact],
    inputs: &ActionInputManifest,
    build_script_output: Option<&[u8]>,
    toolchain_root: &str,
    retained_toolchain_sha256: &[u8; 32],
    runtime: &TypedDigest,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    remote_workspace_execution_shape(plan, directories, toolchain_root)?;
    let externs = remote::remote_extern_facts(plan, directories)?;
    let mut key = captured_action_key(
        plan,
        toolchain,
        &externs,
        directories,
        build_script_output,
        inputs,
    )?;
    remote::bind_remote_execution_inputs(
        &mut key,
        plan,
        toolchain_root,
        retained_toolchain_sha256,
        runtime,
    )?;
    key.descriptor.key_epoch = 1;
    key.descriptor.projection_epoch = 1;
    key.descriptor.action_class = ActionClass::RustcWorkspaceCompile;
    // Every presented value participates here, including wrapper/jobserver
    // controls. This execution-only identity makes no cross-request equivalence
    // claim and never borrows the dependency lane's tracked-read exemptions.
    let mut environment = CanonicalEncoder::new();
    environment.seq(&plan.execution_env, |encoder, (name, value)| {
        encoder.str(name).str(value);
    });
    key.descriptor.environment = compute(
        "rabs.canonical-workspace-execution.environment.v1",
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
        "rabs.canonical-workspace-execution.invocation.v1",
        &invocation.finish(),
    );
    key.descriptor.sandbox_semantic_policy = remote_workspace_execution_isolation_policy(plan)?;
    key.descriptor.execution_semantics = compute(
        "rabs.canonical-workspace-execution.semantics.v1",
        b"fresh supervised rustc execution; completed drained receipt; exact request-owned output installation; no result-cache lookup, publication or serving",
    );
    key.action_key = compute_action_key(&key.descriptor).final_key;
    key.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&key.descriptor));
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_dependency::{
        canonical_cargo_dependency_key, canonicalize_compiler_transcript, canonicalize_placements,
        dep_info_closure_violation, generated_input_directories, live_dependency_key,
        workspace_input_directories,
    };
    use rabs_protocol::input_evidence::{
        DirectoryEnumeration, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;

    const HOST: &str = "x86_64-unknown-linux-gnu";
    const OUTPUT: &str = "/__rabs/out/cargo/debug/deps";
    const GENERATED: &str = "/__rabs/out/cargo/debug/build/member-123/out";

    fn request() -> (Vec<String>, Vec<(String, String)>) {
        (
            [
                COMPILER,
                "--crate-name=member",
                "--crate-type=lib",
                "--edition=2021",
                "member/src/lib.rs",
                "--error-format=json",
                "--json=artifacts",
                "--warn=dead_code",
                "--emit=dep-info,metadata",
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
                ("CARGO_MANIFEST_DIR", "/__rabs/workspace/member"),
                ("CARGO_PKG_NAME", "member"),
                ("CARGO_PRIMARY_PACKAGE", "1"),
                (
                    "LD_LIBRARY_PATH",
                    "/__rabs/out/cargo/debug/deps:/__rabs/toolchain/lib",
                ),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
        )
    }

    fn from_request(argv: &[String], env: &[(String, String)], cwd: &str) -> DependencyActionPlan {
        plan_canonical_workspace_execution(LiveRustcRequest { argv, env, cwd }, HOST).unwrap()
    }

    fn plan() -> DependencyActionPlan {
        let (argv, env) = request();
        from_request(&argv, &env, WORKSPACE)
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
                "member/Cargo.toml",
                "member/src/lib.rs",
                "shared.rs",
            ]
            .into_iter()
            .map(|relative| PositiveInput {
                virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
                object: ObjectId(compute("rabs.test.workspace-input.v1", relative.as_bytes())),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            })
            .collect(),
            directory_enumerations: vec![
                listing(
                    plan.source_virtual_root(),
                    &["Cargo.toml", "empty", "member", "shared.rs"],
                ),
                listing(plan.input_virtual_path("empty"), &[]),
                listing(plan.input_virtual_path("member"), &["Cargo.toml", "src"]),
                listing(plan.input_virtual_path("member/src"), &["lib.rs"]),
            ],
            ..ActionInputManifest::default()
        }
    }

    fn toolchain() -> ToolchainFacts {
        ToolchainFacts {
            compiler_binary_digest: compute("rabs.test.workspace-input.v1", b"compiler"),
            verbose_version: format!("rustc 1.100.0\nhost: {HOST}\nLLVM version: 21"),
            sysroot_root_digest: compute("rabs.test.workspace-input.v1", b"sysroot"),
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
        remote_workspace_execution_key(
            plan,
            &toolchain(),
            &directories(plan),
            inputs,
            plan.generated_root.as_ref().map(|_| b"".as_slice()),
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
    }

    #[test]
    fn selected_member_keeps_primary_environment_lints_relative_argv_and_cwd() {
        let (argv, env) = request();
        let plan = from_request(&argv, &env, WORKSPACE);
        assert_eq!(
            plan.invocation,
            crate::invocation::parse(&argv, None).unwrap()
        );
        assert_eq!(plan.invocation.cap_lints, None);
        assert_eq!(plan.cwd, WORKSPACE);
        assert_eq!(plan.package_root, "/__rabs/workspace/member");
        assert_eq!(plan.source_root, WORKSPACE);
        assert_eq!(
            workspace_source_path(&plan).unwrap(),
            "/__rabs/workspace/member/src/lib.rs"
        );
        assert_eq!(
            env_value(&plan.execution_env, "CARGO_PRIMARY_PACKAGE"),
            Some("1")
        );
        assert_eq!(plan.keyed_env, plan.execution_env);
        assert_eq!(
            plan.source_kind.as_str(),
            "canonical-workspace-execution-only"
        );
        let mut member_argv = argv.clone();
        member_argv[4] = "src/lib.rs".into();
        let member = from_request(&member_argv, &env, "/__rabs/workspace/member");
        assert_eq!(
            workspace_source_path(&member).unwrap(),
            workspace_source_path(&plan).unwrap()
        );
        assert_ne!(
            key(&member, &inputs(&member)).unwrap().action_key,
            key(&plan, &inputs(&plan)).unwrap().action_key
        );
    }

    #[test]
    fn empty_workspace_loader_list_remains_an_exact_keyed_binding() {
        let (argv, mut env) = request();
        env.iter_mut()
            .find(|(name, _)| name == "LD_LIBRARY_PATH")
            .unwrap()
            .1
            .clear();
        let empty = from_request(&argv, &env, WORKSPACE);
        assert_eq!(env_value(&empty.execution_env, "LD_LIBRARY_PATH"), Some(""));
        assert_eq!(empty.execution_env, empty.keyed_env);
        assert!(
            remote::remote_loader_search_paths(&empty, TOOLCHAIN)
                .unwrap()
                .is_empty()
        );
        assert!(
            remote::remote_empty_loader_directories(&empty, TOOLCHAIN)
                .unwrap()
                .is_empty()
        );
        let empty_key = key(&empty, &inputs(&empty)).unwrap();
        let mut absent_env = env.clone();
        absent_env.retain(|(name, _)| name != "LD_LIBRARY_PATH");
        let absent = from_request(&argv, &absent_env, WORKSPACE);
        let absent_key = key(&absent, &inputs(&absent)).unwrap();
        assert_ne!(
            empty_key.descriptor.environment,
            absent_key.descriptor.environment
        );
        assert_ne!(empty_key.action_key, absent_key.action_key);

        for value in [
            ":",
            ":/__rabs/toolchain/lib",
            "/__rabs/toolchain/lib:",
            "/__rabs/toolchain/lib::/__rabs/toolchain/lib/rustlib",
        ] {
            let mut changed = env.clone();
            changed
                .iter_mut()
                .find(|(name, _)| name == "LD_LIBRARY_PATH")
                .unwrap()
                .1 = value.into();
            assert!(
                plan_canonical_workspace_execution(
                    LiveRustcRequest {
                        argv: &argv,
                        env: &changed,
                        cwd: WORKSPACE,
                    },
                    HOST,
                )
                .is_err(),
                "nonempty loader lists cannot contain cwd-search components: {value:?}"
            );
        }
        env.push(("LD_PRELOAD".into(), String::new()));
        assert!(
            plan_canonical_workspace_execution(
                LiveRustcRequest {
                    argv: &argv,
                    env: &env,
                    cwd: WORKSPACE
                },
                HOST,
            )
            .is_err()
        );
    }

    #[test]
    fn workspace_identity_is_distinct_and_all_dependency_cache_entrypoints_refuse_it() {
        let (mut argv, mut env) = request();
        // Even an otherwise external-looking lint/environment combination must
        // not let the explicit workspace source class inherit cache authority.
        argv.push("--cap-lints=allow".into());
        env.retain(|(name, _)| name != "CARGO_PRIMARY_PACKAGE");
        let plan = from_request(&argv, &env, WORKSPACE);
        let inputs = inputs(&plan);
        let directories = directories(&plan);
        let key = key(&plan, &inputs).unwrap();
        assert_eq!(
            key.descriptor.action_class,
            ActionClass::RustcWorkspaceCompile
        );
        assert_eq!(key.descriptor.sandbox_semantic_policy.domain, POLICY_DOMAIN);
        assert!(
            live_dependency_key(&plan, &toolchain(), &[], &directories, None, &inputs).is_err()
        );
        assert!(
            canonical_cargo_dependency_key(&plan, &toolchain(), &[], &directories, None, &inputs)
                .is_err()
        );
        assert!(
            remote::remote_dependency_key(
                &plan,
                &toolchain(),
                &directories,
                &inputs,
                None,
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime")
            )
            .is_err()
        );
        assert!(remote::remote_dependency_shape(&plan, &directories, TOOLCHAIN).is_err());
        assert!(remote::remote_dependency_isolation_policy(&plan).is_err());
        let mut forged = plan.clone();
        forged.canonical_cargo = false;
        assert!(
            live_dependency_key(&forged, &toolchain(), &[], &directories, None, &inputs).is_err()
        );
        assert!(remote_workspace_execution_shape(&forged, &directories, TOOLCHAIN).is_err());
        forged = plan;
        forged.source_kind = DependencySourceKind::DirectoryPackage;
        assert!(remote_workspace_execution_shape(&forged, &directories, TOOLCHAIN).is_err());
    }

    #[test]
    fn empty_source_directories_and_every_presented_environment_value_bind_execution_identity() {
        let plan = plan();
        let base = inputs(&plan);
        assert_eq!(
            workspace_input_directories(&plan, &base).unwrap(),
            ["empty", "member", "member/src"]
        );
        let original = key(&plan, &base).unwrap();
        let mut changed = base.clone();
        changed.directory_enumerations[0]
            .entries
            .push(RawBytes::from("unused"));
        changed.directory_enumerations[0].entries.sort();
        changed
            .directory_enumerations
            .push(listing(plan.input_virtual_path("unused"), &[]));
        assert_ne!(
            original.action_key,
            key(&plan, &changed).unwrap().action_key
        );
        let (argv, mut env) = request();
        for (name, value) in [
            ("CARGO_PRIMARY_PACKAGE", "2"),
            ("RABS_SOCKET", "/private/control"),
        ] {
            env.retain(|(existing, _)| existing != name);
            env.push((name.into(), value.into()));
            let changed = from_request(&argv, &env, WORKSPACE);
            assert_ne!(
                original.descriptor.environment,
                key(&changed, &base).unwrap().descriptor.environment
            );
        }
    }

    #[test]
    fn source_directory_evidence_refuses_missing_parents_aliases_symlinks_and_collisions() {
        let plan = plan();
        let good = inputs(&plan);
        for mutation in 0..7 {
            let mut invalid = good.clone();
            match mutation {
                0 => {
                    invalid.directory_enumerations.remove(0);
                }
                1 => {
                    invalid.directory_enumerations.remove(2);
                }
                2 => {
                    invalid
                        .directory_enumerations
                        .push(invalid.directory_enumerations[1].clone());
                }
                3 => {
                    invalid.directory_enumerations[1].virtual_path =
                        RawBytes::new(plan.input_virtual_path("empty/../alias").into_bytes());
                }
                4 => {
                    invalid.inputs[2].file_type = InputFileType::Symlink;
                }
                5 => {
                    invalid
                        .directory_enumerations
                        .push(listing(plan.input_virtual_path("shared.rs"), &[]));
                }
                _ => {
                    invalid.directory_enumerations[0]
                        .entries
                        .push(RawBytes::from("unobserved"));
                }
            }
            assert!(key(&plan, &invalid).is_err(), "mutation {mutation}");
        }
        let mut missing_source = good;
        missing_source.inputs.retain(|input| {
            input.virtual_path.as_bytes() != plan.input_virtual_path("member/src/lib.rs").as_bytes()
        });
        missing_source
            .directory_enumerations
            .last_mut()
            .unwrap()
            .entries
            .clear();
        assert!(key(&plan, &missing_source).is_err());
    }

    #[test]
    fn empty_generated_root_and_complete_source_topology_coexist_without_sentinel_files() {
        let (argv, mut env) = request();
        env.push(("OUT_DIR".into(), GENERATED.into()));
        let plan = from_request(&argv, &env, WORKSPACE);
        let mut manifest = inputs(&plan);
        manifest
            .directory_enumerations
            .push(listing(plan.generated_virtual_root(), &[]));
        let empty = key(&plan, &manifest).unwrap();
        assert!(
            generated_input_directories(&plan, &manifest)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            workspace_input_directories(&plan, &manifest).unwrap().len(),
            3
        );
        let mut populated = manifest.clone();
        populated
            .directory_enumerations
            .last_mut()
            .unwrap()
            .entries
            .push(RawBytes::from("nested"));
        populated.directory_enumerations.push(listing(
            plan.generated_input_virtual_path("nested"),
            &["empty", "value.rs"],
        ));
        populated.directory_enumerations.push(listing(
            plan.generated_input_virtual_path("nested/empty"),
            &[],
        ));
        populated.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(
                plan.generated_input_virtual_path("nested/value.rs")
                    .into_bytes(),
            ),
            object: ObjectId(compute("rabs.test.workspace-input.v1", b"generated")),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        assert_eq!(
            generated_input_directories(&plan, &populated).unwrap(),
            ["nested", "nested/empty"]
        );
        assert_ne!(empty.action_key, key(&plan, &populated).unwrap().action_key);
        let mut absent_root = manifest;
        absent_root.directory_enumerations.pop();
        assert!(key(&plan, &absent_root).is_err());
        populated
            .directory_enumerations
            .last_mut()
            .unwrap()
            .virtual_path = RawBytes::from("/__rabs/unowned");
        assert!(key(&plan, &populated).is_err());
    }

    #[test]
    fn native_executable_incremental_and_escaping_source_inputs_remain_ineligible() {
        let (argv, env) = request();
        for source in [
            "../lib.rs",
            "member/../member/src/lib.rs",
            "./member/src/lib.rs",
            "member//src/lib.rs",
            "member/src/space name.rs",
            "/tmp/lib.rs",
            "/__rabs/workspace-other/lib.rs",
        ] {
            let mut changed = argv.clone();
            changed[4] = source.into();
            assert!(
                plan_canonical_workspace_execution(
                    LiveRustcRequest {
                        argv: &changed,
                        env: &env,
                        cwd: WORKSPACE,
                    },
                    HOST
                )
                .is_err(),
                "{source}"
            );
        }
        for extra in [
            vec!["--extern=macro=/__rabs/out/cargo/debug/deps/libmacro.so"],
            vec!["-Lnative=/__rabs/workspace/native"],
            vec!["-ldylib=external"],
            vec!["-Ctarget-cpu=native"],
            vec!["-Cincremental=/__rabs/out/cargo/incremental"],
        ] {
            let mut changed = argv.clone();
            changed.extend(extra.iter().map(|flag| (*flag).to_owned()));
            assert!(
                plan_canonical_workspace_execution(
                    LiveRustcRequest {
                        argv: &changed,
                        env: &env,
                        cwd: WORKSPACE,
                    },
                    HOST
                )
                .is_err(),
                "{extra:?}"
            );
        }
    }

    #[test]
    fn archive_and_metadata_use_separate_policies_and_exact_output_declarations() {
        let (mut argv, env) = request();
        let metadata = from_request(&argv, &env, WORKSPACE);
        argv[8] = "--emit=dep-info,metadata,link".into();
        let archive = from_request(&argv, &env, WORKSPACE);
        let metadata_key = key(&metadata, &inputs(&metadata)).unwrap();
        let archive_key = key(&archive, &inputs(&archive)).unwrap();
        assert_ne!(
            metadata_key.descriptor.sandbox_semantic_policy,
            archive_key.descriptor.sandbox_semantic_policy
        );
        assert!(
            archive
                .output_names()
                .iter()
                .any(|name| name.ends_with(".rlib"))
        );
        let mut changed = archive.clone();
        changed.outputs = metadata.outputs;
        assert!(
            remote_workspace_execution_shape(&changed, &directories(&changed), TOOLCHAIN).is_err()
        );
        argv[2] = "--crate-type=bin".into();
        assert!(
            plan_canonical_workspace_execution(
                LiveRustcRequest {
                    argv: &argv,
                    env: &env,
                    cwd: WORKSPACE
                },
                HOST
            )
            .is_err()
        );
    }

    #[test]
    fn verified_workspace_transcripts_and_relative_dep_info_are_preserved_exactly() {
        let plan = plan();
        let manifest = inputs(&plan);
        let dep_info = format!(
            "{OUTPUT}/libmember.rmeta: member/src/lib.rs empty/../shared.rs\n# env-dep:CARGO_PRIMARY_PACKAGE=1\n"
        );
        assert!(
            dep_info_closure_violation(&plan, dep_info.as_bytes(), |path| {
                manifest
                    .inputs
                    .iter()
                    .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
            })
            .is_none()
        );
        assert_eq!(
            canonicalize_placements(dep_info.as_bytes(), &plan).unwrap(),
            dep_info.as_bytes()
        );
        let diagnostic =
            b"{\"message\":\"/__rabs/workspace/member unused function\",\"level\":\"warning\"}\n";
        assert_eq!(
            canonicalize_compiler_transcript(diagnostic, &plan).unwrap(),
            diagnostic
        );
        assert!(
            dep_info_closure_violation(
                &plan,
                b"# env-dep:CARGO_MAKEFLAGS=--jobserver-auth=3,4\n",
                |_| true
            )
            .is_some(),
            "worker descriptor coordination cannot preserve source-observed jobserver values"
        );
    }
}
