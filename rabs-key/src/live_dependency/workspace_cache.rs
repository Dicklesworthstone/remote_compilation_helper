//! Closed, complete-workspace Rust leaf-library cache identities.
//!
//! These workspace serving classes deliberately retain the entire sealed
//! workspace, including every directory listing. It is not an observed minimal
//! closure and unrelated workspace edits invalidate it. The canonical driver
//! must independently retain the selected ordinary library unit and a Cargo
//! graph with no project executors. Archive and metadata executions require
//! distinct, independently supervised worker profiles without procfs or entropy
//! devices. Ordinary workspace metadata execution is not this closed profile.
//! Generated/native inputs, explicit externs and implicit crate candidates
//! remain in the fresh execution-only class.

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

// Keep the archive profile and its domains/encodings byte-for-byte stable.
// Closed metadata introduces its own identity rather than widening Rlib or
// borrowing the ordinary metadata namespace's filesystem policy.
const KEY_EPOCH: u32 = 4;
const PROJECTION_EPOCH: u32 = 1;
const POLICY_DOMAIN: &str = "rabs.canonical-workspace-closed-rlib.isolation.v1";
const SEMANTICS_DOMAIN: &str = "rabs.canonical-workspace-closed-rlib.semantics.v1";
const SEMANTICS: &str = "completed independently supervised pure Rust leaf-library archive; complete sealed workspace and every directory listing; no project executors, externs, crate candidates, generated or native inputs; exact environment; authenticated drained receipt; existing publication, independent verification, class quarantine and private installation gates";
const METADATA_KEY_EPOCH: u32 = 5;
const METADATA_POLICY_DOMAIN: &str = "rabs.canonical-workspace-closed-metadata.isolation.v1";
const METADATA_SEMANTICS_DOMAIN: &str = "rabs.canonical-workspace-closed-metadata.semantics.v1";
const METADATA_SEMANTICS: &str = "completed independently supervised pure Rust leaf-library metadata check; canonical-workspace-closed-metadata-v1 explicitly negotiated in closed-metadata mode without procfs or entropy devices; complete sealed workspace and every directory listing; no project executors, externs, crate candidates, generated or native inputs; exact environment; authenticated drained receipt; existing publication, independent verification, class quarantine and private installation gates";

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

pub(super) const METADATA_ISOLATION_PROFILE: &str = "canonical-workspace-closed-metadata-v1: \
    driver-retained Cargo-selected ordinary library check in a graph without \
    project executors; canonical-workspace-closed-metadata-v1 namespace \
    explicitly negotiated in closed-metadata mode, independently measured \
    without borrowing ordinary Metadata or Rlib execution authority; complete \
    immutable canonical workspace with exact file identities and every \
    immediate directory listing including empty directories; exact canonical \
    argv, cwd, manifest path, output placement, primary-package and lint \
    behavior; exact complete presented environment; independently retained \
    complete toolchain and measured ELF runtime; no procfs or entropy devices, \
    only private null device, fresh private output, HOME and temporary storage; \
    no generated tree, native input, explicit extern or implicit Rust artifact \
    candidate; no project code execution, proc macro, incremental state, \
    external linker, archive, binary or harness output, control socket or local \
    wrapper completion authority; compiler dep-info and tracked-control-variable \
    read veto required; exact metadata, dep-info and diagnostic transcript \
    capture; independently authenticated request and completed drained worker \
    receipt; existing publication, independent samples, release authorization, \
    class quarantine and subscriber-owned private installation gates; no \
    provisional outputs";

/// Independently qualified workspace library profiles. Identifying a profile
/// never supplies the driver's graph or an authenticated worker receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedWorkspaceLibraryClass {
    /// Ordinary library archive under the existing closed Rlib namespace.
    Rlib,
    /// Ordinary library check under the separately negotiated closed metadata
    /// namespace, never the fresh metadata namespace with procfs and devices.
    Metadata,
}

impl ClosedWorkspaceLibraryClass {
    const fn source_kind(self) -> DependencySourceKind {
        match self {
            Self::Rlib => DependencySourceKind::WorkspaceClosedRlib,
            Self::Metadata => DependencySourceKind::WorkspaceClosedMetadata,
        }
    }

    const fn output_class(self) -> RemoteDependencyOutputClass {
        match self {
            Self::Rlib => RemoteDependencyOutputClass::Rlib,
            Self::Metadata => RemoteDependencyOutputClass::Metadata,
        }
    }

    const fn key_epoch(self) -> u32 {
        match self {
            Self::Rlib => KEY_EPOCH,
            Self::Metadata => METADATA_KEY_EPOCH,
        }
    }

    fn isolation_policy(self) -> TypedDigest {
        match self {
            Self::Rlib => compute(POLICY_DOMAIN, ISOLATION_PROFILE.as_bytes()),
            Self::Metadata => compute(
                METADATA_POLICY_DOMAIN,
                METADATA_ISOLATION_PROFILE.as_bytes(),
            ),
        }
    }

    fn execution_semantics(self) -> TypedDigest {
        match self {
            Self::Rlib => compute(SEMANTICS_DOMAIN, SEMANTICS.as_bytes()),
            Self::Metadata => compute(METADATA_SEMANTICS_DOMAIN, METADATA_SEMANTICS.as_bytes()),
        }
    }

    const fn environment_domain(self) -> &'static str {
        match self {
            Self::Rlib => "rabs.canonical-workspace-closed-rlib.environment.v1",
            Self::Metadata => "rabs.canonical-workspace-closed-metadata.environment.v1",
        }
    }

    const fn invocation_domain(self) -> &'static str {
        match self {
            Self::Rlib => "rabs.canonical-workspace-closed-rlib.invocation.v1",
            Self::Metadata => "rabs.canonical-workspace-closed-metadata.invocation.v1",
        }
    }
}

/// Refine a modeled fresh workspace invocation into a closed library candidate.
/// This is pure planning, not cache authority. The coordinator must retain the
/// selected Cargo graph, validate empty candidate inventories, and own the exact
/// enforced worker context before publication or replay can be considered.
///
/// # Errors
/// A different source class or an invocation outside ordinary leaf-library
/// archives or metadata checks.
pub fn plan_closed_workspace_library(
    execution: &DependencyActionPlan,
) -> Result<DependencyActionPlan, LiveRefusal> {
    if execution.source_kind != DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "closed workspace planning requires the original fresh workspace plan".into(),
        ));
    }
    let class = match remote::remote_dependency_output_class(&execution.invocation)
        .map_err(|error| LiveRefusal::Facts(error.to_string()))?
    {
        RemoteDependencyOutputClass::Rlib => ClosedWorkspaceLibraryClass::Rlib,
        RemoteDependencyOutputClass::Metadata => ClosedWorkspaceLibraryClass::Metadata,
    };
    let mut plan = execution.clone();
    plan.source_kind = class.source_kind();
    validate_closed_workspace_library_plan(&plan)?;
    Ok(plan)
}

/// Validate the bounded invocation contract independently of directory I/O.
///
/// # Errors
/// A noncanonical plan, mismatched output/profile, nonlibrary output, or
/// executable/generated/native/extern inputs. Directory candidates are
/// additionally checked by [`remote_closed_workspace_library_shape`].
pub fn validate_closed_workspace_library_plan(
    plan: &DependencyActionPlan,
) -> Result<ClosedWorkspaceLibraryClass, LiveRefusal> {
    workspace_layout(plan)?;
    let class = match plan.source_kind {
        DependencySourceKind::WorkspaceClosedRlib => ClosedWorkspaceLibraryClass::Rlib,
        DependencySourceKind::WorkspaceClosedMetadata => ClosedWorkspaceLibraryClass::Metadata,
        _ => {
            return Err(LiveRefusal::Facts(
                "closed workspace library validation requires its distinct cache profile".into(),
            ));
        }
    };
    if !matches!(plan.invocation.crate_types.as_slice(), [kind] if matches!(kind.as_str(), "lib" | "rlib"))
        || plan
            .invocation
            .passthrough
            .iter()
            .any(|arg| arg == "--test")
        || plan.generated_root.is_some()
        || !plan.native_roots.is_empty()
        || !plan.invocation.native_libs.is_empty()
        || !plan.externs.is_empty()
        || !plan.invocation.externs.is_empty()
        || remote::remote_dependency_output_class(&plan.invocation) != Ok(class.output_class())
    {
        return Err(LiveRefusal::Facts(
            "workspace cache requires a matching closed pure Rust leaf-library profile without generated, native or extern inputs".into(),
        ));
    }
    Ok(class)
}

/// Invocation boundary for dependency-bearing archives only. Callers separately
/// require their exact class, candidate closure and committed producer authority.
pub(super) fn validate_pure_workspace_rlib(plan: &DependencyActionPlan) -> Result<(), LiveRefusal> {
    workspace_layout(plan)?;
    if !matches!(plan.invocation.crate_types.as_slice(), [kind] if matches!(kind.as_str(), "lib" | "rlib"))
        || plan
            .invocation
            .passthrough
            .iter()
            .any(|arg| arg == "--test")
        || plan.generated_root.is_some()
        || !plan.native_roots.is_empty()
        || !plan.invocation.native_libs.is_empty()
        || remote::remote_dependency_output_class(&plan.invocation)
            != Ok(RemoteDependencyOutputClass::Rlib)
    {
        return Err(LiveRefusal::Facts(
            "workspace cache admits only closed pure Rust library archives without generated or native inputs".into(),
        ));
    }
    Ok(())
}

/// Mechanical preparation admission for the closed leaf-library classes.
/// Empty search inventories are semantic negative inputs: an implicit crate
/// candidate must not sneak a procedural macro or uncommitted producer into
/// this class merely because no `--extern` argument named it.
///
/// # Errors
/// An incomplete/reordered candidate inventory, any candidate, unsupported
/// loader/runtime layout, or an invocation outside the closed leaf subset.
pub fn remote_closed_workspace_library_shape(
    plan: &DependencyActionPlan,
    directories: &[DependencyDirectoryFact],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    validate_closed_workspace_library_plan(plan)?;
    remote::remote_execution_shape(plan, directories, toolchain_root)?;
    if directories
        .iter()
        .any(|directory| !directory.artifacts.is_empty())
    {
        return Err(LiveRefusal::Facts(
            "closed workspace leaf libraries require empty Rust candidate inventories".into(),
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
pub fn remote_closed_workspace_library_isolation_policy(
    plan: &DependencyActionPlan,
) -> Result<TypedDigest, RemoteDependencyRefusal> {
    Ok(validate_closed_workspace_library_plan(plan)?.isolation_policy())
}

/// Recognize only the exact submitted descriptor profile for durable class receipts.
/// This is not execution or publication authority: independently retained graph,
/// inputs, worker context and receipt checks remain mandatory. In particular an
/// arbitrary `RustcWorkspaceCompile` descriptor remains private.
#[must_use]
pub fn closed_workspace_library_descriptor_class(
    descriptor: &ActionDescriptor,
) -> Option<ClosedWorkspaceLibraryClass> {
    [
        ClosedWorkspaceLibraryClass::Rlib,
        ClosedWorkspaceLibraryClass::Metadata,
    ]
    .into_iter()
    .find(|class| {
        descriptor.action_class == ActionClass::RustcWorkspaceCompile
            && descriptor.key_epoch == class.key_epoch()
            && descriptor.projection_epoch == PROJECTION_EPOCH
            && descriptor.sandbox_semantic_policy == class.isolation_policy()
            && descriptor.execution_semantics == class.execution_semantics()
    })
}

/// Bind the complete retained workspace and exact closed library execution.
/// There is deliberately no source projection, environment exemption or
/// dependency-artifact equivalence in either closed workspace cache class.
///
/// # Errors
/// An invalid class, incomplete file/directory closure, generated run record,
/// unbound toolchain/runtime, or a nonempty Rust candidate inventory.
#[allow(clippy::too_many_arguments)]
pub fn remote_closed_workspace_library_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    directories: &[DependencyDirectoryFact],
    inputs: &ActionInputManifest,
    build_script_output: Option<&[u8]>,
    toolchain_root: &str,
    retained_toolchain_sha256: &[u8; 32],
    runtime: &TypedDigest,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    remote_closed_workspace_library_shape(plan, directories, toolchain_root)?;
    let class = validate_closed_workspace_library_plan(plan)?;
    if build_script_output.is_some() {
        return Err(LiveRefusal::Facts(
            "closed workspace leaf libraries cannot consume a build-script run record".into(),
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
    key.descriptor.environment = compute(class.environment_domain(), &environment.finish());
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
    key.descriptor.normalized_invocation = compute(class.invocation_domain(), &invocation.finish());
    key.descriptor.key_epoch = class.key_epoch();
    key.descriptor.projection_epoch = PROJECTION_EPOCH;
    key.descriptor.action_class = ActionClass::RustcWorkspaceCompile;
    key.descriptor.sandbox_semantic_policy = class.isolation_policy();
    key.descriptor.execution_semantics = class.execution_semantics();
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
    const CLASSES: [ClosedWorkspaceLibraryClass; 2] = [
        ClosedWorkspaceLibraryClass::Rlib,
        ClosedWorkspaceLibraryClass::Metadata,
    ];

    fn request(class: ClosedWorkspaceLibraryClass) -> (Vec<String>, Vec<(String, String)>) {
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
                match class {
                    ClosedWorkspaceLibraryClass::Rlib => "--emit=dep-info,metadata,link",
                    ClosedWorkspaceLibraryClass::Metadata => "--emit=dep-info,metadata",
                },
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

    fn plan(class: ClosedWorkspaceLibraryClass) -> DependencyActionPlan {
        let (argv, env) = request(class);
        plan_closed_workspace_library(&execution(&argv, &env)).unwrap()
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
        remote_closed_workspace_library_key(
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
    fn closed_workspace_library_profiles_are_distinct_from_existing_cache_and_fresh_profiles() {
        for class in CLASSES {
            let (argv, env) = request(class);
            let fresh = execution(&argv, &env);
            let plan = plan_closed_workspace_library(&fresh).unwrap();
            let input = inputs(&plan);
            let key = key(&plan, &input).unwrap();
            assert_eq!(
                validate_closed_workspace_library_plan(&plan).unwrap(),
                class
            );
            assert!(plan_closed_workspace_library(&plan).is_err());
            assert_eq!(plan.invocation, fresh.invocation);
            assert_eq!(plan.execution_env, fresh.execution_env);
            assert_eq!(plan.keyed_env, plan.execution_env);
            assert_eq!(plan.cwd, WORKSPACE);
            assert_eq!(plan.source_root, WORKSPACE);
            assert_eq!(
                plan.source_kind.as_str(),
                match class {
                    ClosedWorkspaceLibraryClass::Rlib => "canonical-workspace-closed-rlib-v1",
                    ClosedWorkspaceLibraryClass::Metadata =>
                        "canonical-workspace-closed-metadata-v1",
                }
            );
            assert_eq!(
                closed_workspace_library_descriptor_class(&key.descriptor),
                Some(class)
            );
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
            assert!(closed_workspace_library_descriptor_class(&fresh_key.descriptor).is_none());
            assert!(
                remote_closed_workspace_library_key(
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
    }

    #[test]
    fn closed_metadata_and_archive_profiles_cannot_borrow_each_others_identity() {
        let archive = plan(ClosedWorkspaceLibraryClass::Rlib);
        let metadata = plan(ClosedWorkspaceLibraryClass::Metadata);
        let archive_key = key(&archive, &inputs(&archive)).unwrap();
        let metadata_key = key(&metadata, &inputs(&metadata)).unwrap();
        assert_eq!(archive_key.descriptor.key_epoch, 4);
        assert_eq!(metadata_key.descriptor.key_epoch, 5);
        assert_ne!(archive_key.action_key, metadata_key.action_key);
        assert_ne!(
            archive_key.descriptor.sandbox_semantic_policy,
            metadata_key.descriptor.sandbox_semantic_policy
        );
        assert_ne!(
            archive_key.descriptor.execution_semantics,
            metadata_key.descriptor.execution_semantics
        );
        for (original, other) in [(&archive, &metadata), (&metadata, &archive)] {
            let mut relabeled = original.clone();
            relabeled.source_kind = other.source_kind;
            assert!(validate_closed_workspace_library_plan(&relabeled).is_err());
            assert!(key(&relabeled, &inputs(&relabeled)).is_err());
            assert!(remote_closed_workspace_library_isolation_policy(&relabeled).is_err());
        }
        // Neither the output epoch nor either policy component alone can
        // convert durable evidence from one independently qualified class.
        for change in 0..3 {
            let mut mixed = archive_key.descriptor.clone();
            match change {
                0 => mixed.key_epoch = metadata_key.descriptor.key_epoch,
                1 => {
                    mixed.sandbox_semantic_policy =
                        metadata_key.descriptor.sandbox_semantic_policy.clone();
                }
                _ => {
                    mixed.execution_semantics = metadata_key.descriptor.execution_semantics.clone();
                }
            }
            assert!(closed_workspace_library_descriptor_class(&mixed).is_none());
        }
    }

    #[test]
    fn closed_workspace_metadata_preserves_exact_lints_presentation_and_output_placement() {
        let (argv, env) = request(ClosedWorkspaceLibraryClass::Metadata);
        let original_plan = plan_closed_workspace_library(&execution(&argv, &env)).unwrap();
        let original = key(&original_plan, &inputs(&original_plan))
            .unwrap()
            .action_key;
        for change in 0..3 {
            let mut changed = argv.clone();
            match change {
                0 => {
                    let lint = changed
                        .iter_mut()
                        .find(|arg| *arg == "--warn=dead_code")
                        .unwrap();
                    *lint = "--deny=dead_code".into();
                }
                1 => changed.push("--color=always".into()),
                _ => {
                    let output = changed.iter_mut().find(|arg| *arg == OUTPUT).unwrap();
                    *output = "/__rabs/out/cargo/another-profile/deps".into();
                }
            }
            let fresh = execution(&changed, &env);
            let candidate = plan_closed_workspace_library(&fresh).unwrap();
            assert_eq!(candidate.invocation, fresh.invocation);
            assert_eq!(candidate.execution_env, fresh.execution_env);
            assert_ne!(
                key(&candidate, &inputs(&candidate)).unwrap().action_key,
                original
            );
        }
    }

    #[test]
    fn closed_workspace_libraries_refuse_incremental_and_executable_compiler_classes() {
        for class in CLASSES {
            for flag in [
                "-Cincremental=/__rabs/out/cargo/incremental",
                "--crate-type=proc-macro",
                "--crate-type=dylib",
                "--crate-type=cdylib",
                "--crate-type=staticlib",
            ] {
                let (mut argv, env) = request(class);
                if flag.starts_with("--crate-type=") {
                    argv.retain(|arg| !arg.starts_with("--crate-type="));
                }
                argv.push(flag.into());
                let candidate = plan_canonical_workspace_execution(
                    LiveRustcRequest {
                        argv: &argv,
                        env: &env,
                        cwd: WORKSPACE,
                    },
                    HOST,
                )
                .and_then(|plan| plan_closed_workspace_library(&plan));
                assert!(candidate.is_err(), "{class:?}: {flag}");
            }
        }
    }

    #[test]
    fn closed_workspace_libraries_reject_binary_harness_generated_native_and_extern_inputs() {
        for class in CLASSES {
            for flags in [
                vec!["--emit=dep-info,metadata", "--crate-type=bin"],
                vec!["--emit=dep-info,metadata", "--test"],
                vec!["--extern=other=/__rabs/out/cargo/debug/deps/libother.rlib"],
            ] {
                let (mut argv, env) = request(class);
                if flags.iter().any(|arg| arg.starts_with("--emit=")) {
                    argv.retain(|arg| !arg.starts_with("--emit="));
                }
                if flags.iter().any(|arg| arg.starts_with("--crate-type=")) {
                    argv.retain(|arg| !arg.starts_with("--crate-type="));
                }
                argv.extend(flags.iter().map(|arg| (*arg).to_owned()));
                assert!(
                    plan_closed_workspace_library(&execution(&argv, &env)).is_err(),
                    "{flags:?}"
                );
            }
            let (mut argv, mut env) = request(class);
            let generated = "/__rabs/out/cargo/debug/build/leaf-123/out";
            env.push(("OUT_DIR".into(), generated.into()));
            assert!(plan_closed_workspace_library(&execution(&argv, &env)).is_err());
            argv.extend([format!("-Lnative={generated}"), "-lstatic=leaf".into()]);
            assert!(plan_closed_workspace_library(&execution(&argv, &env)).is_err());
            let plan = plan(class);
            assert!(
                remote_closed_workspace_library_key(
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
    }

    #[test]
    fn closed_workspace_libraries_bind_sibling_bytes_and_complete_negative_directory_topology() {
        for class in CLASSES {
            let plan = plan(class);
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
    }

    #[test]
    fn closed_workspace_libraries_key_every_environment_value_but_keep_tracked_control_read_veto() {
        for class in CLASSES {
            let (argv, env) = request(class);
            let plan = plan_closed_workspace_library(&execution(&argv, &env)).unwrap();
            let original = key(&plan, &inputs(&plan)).unwrap().action_key;
            for name in ["USER_PAYLOAD", "CARGO_MAKEFLAGS", "CARGO_PRIMARY_PACKAGE"] {
                let mut changed = env.clone();
                changed
                    .iter_mut()
                    .find(|(key, _)| key == name)
                    .unwrap()
                    .1
                    .push_str(" changed");
                let next = plan_closed_workspace_library(&execution(&argv, &changed)).unwrap();
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
    }

    #[test]
    fn closed_workspace_libraries_refuse_implicit_crates_and_incomplete_candidate_inventories() {
        for class in CLASSES {
            let plan = plan(class);
            let mut candidates = directories(&plan);
            candidates[0].artifacts.push(ExternFact {
                path: format!("{OUTPUT}/libimplicit.rmeta"),
                content_digest: compute("rabs.test.workspace-closed-input.v1", b"implicit crate"),
            });
            assert!(remote_closed_workspace_library_shape(&plan, &candidates, TOOLCHAIN).is_err());
            assert!(remote_closed_workspace_library_shape(&plan, &[], TOOLCHAIN).is_err());
            candidates[0].artifacts.clear();
            candidates[0].path.push_str("/other");
            assert!(remote_closed_workspace_library_shape(&plan, &candidates, TOOLCHAIN).is_err());
        }
    }

    #[test]
    fn closed_workspace_library_descriptor_receipt_requires_every_profile_discriminator() {
        for class in CLASSES {
            let plan = plan(class);
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
                assert!(closed_workspace_library_descriptor_class(&other).is_none());
            }
        }
    }

    #[test]
    fn closed_workspace_libraries_require_exact_retained_toolchain_and_measured_runtime() {
        for class in CLASSES {
            let plan = plan(class);
            let input = inputs(&plan);
            let original = key(&plan, &input).unwrap().action_key;
            let compute_key = |retained: &[u8; 32], runtime: &TypedDigest| {
                remote_closed_workspace_library_key(
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
}
