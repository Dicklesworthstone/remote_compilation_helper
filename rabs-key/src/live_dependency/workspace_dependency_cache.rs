//! Complete-workspace archives with exact, already committed Rust producers.
//!
//! Every visible retained crate candidate, including candidates not named by an
//! explicit extern, requires a driver-owned committed-install witness. These
//! pure facts bind that witness into the key; they never grant installation or
//! publication authority. The coordinator revalidates the original file
//! generation and the current durable producer lineage at each live boundary.

use super::remote::{self, RemoteDependencyRefusal};
use super::workspace_cache::validate_pure_workspace_rlib;
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
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, OutputRole, TypedDigest};

// Epoch 5 belongs to the independently developed closed leaf-metadata class.
const KEY_EPOCH: u32 = 6;
const PROJECTION_EPOCH: u32 = 1;
const POLICY_DOMAIN: &str = "rabs.canonical-workspace-committed-rlib.isolation.v1";
const SEMANTICS_DOMAIN: &str = "rabs.canonical-workspace-committed-rlib.semantics.v1";
const SEMANTICS: &str = "completed independently supervised pure Rust archive; complete sealed workspace and exact environment; every retained Rust candidate bound to exact committed workspace producer action, descriptor, manifest and logical output; no provisional, adopted, local fallback or request-owned producer authority; transitive current producer safety at commit and replay; existing capture and independent sample gates";

pub(super) const ISOLATION_PROFILE: &str = "canonical-workspace-committed-rlib-v1: \
    driver-retained Cargo-selected ordinary library build in a graph without \
    project executors; canonical-workspace-exec-v3 namespace in Rlib mode; \
    complete immutable canonical workspace with every immediate directory \
    listing; exact argv, cwd, environment and output placement; complete retained \
    toolchain and measured ELF runtime; no procfs or entropy devices, only \
    private null device and fresh private output, HOME and temporary storage; \
    exact read-only retained Rust candidate inventories in original directory \
    order, including every transitive alternative; every retained rmeta/rlib \
    physically installed from an already committed closed-workspace producer \
    with exact action, descriptor, manifest and logical-output object identity; \
    whole explicit rlib bytes retained, existing versioned metadata shadowing \
    projection unchanged; no generated/native inputs, project executors, proc \
    macros, incremental state, final links or local wrapper completion authority; \
    no unresolved or adopted producer lineage; original file generations and \
    transitive current producer serving and class safety revalidated; exact \
    dep-info, tracked-control-variable veto and authenticated drained receipt; \
    existing publication, independent samples, release and private installation gates";

/// Stable logical identity of one retained candidate and its committed producer.
/// Physical path/generation capabilities stay outside this pure type and key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedWorkspaceDependency {
    /// Exact candidate path in the canonical worker namespace.
    pub path: String,
    /// Action whose committed result supplied these bytes.
    pub producer_action: TypedDigest,
    /// Descriptor of that exact producer publication.
    pub producer_descriptor: TypedDigest,
    /// Content identity of the immutable canonical result manifest.
    pub producer_manifest: TypedDigest,
    /// Role in the producer's single authoritative logical-output map.
    pub role: OutputRole,
    /// Logical output path in that map, never a physical backing path.
    pub virtual_path: RawBytes,
    /// Entire retained artifact's object identity.
    pub object: ObjectId,
}

/// Refine the original fresh plan; actual driver selection and every candidate
/// witness must independently qualify before this plan can be used.
///
/// # Errors
/// Any class except the original fresh class or a nonordinary Rlib invocation.
pub fn plan_committed_workspace_rlib(
    execution: &DependencyActionPlan,
) -> Result<DependencyActionPlan, LiveRefusal> {
    if execution.source_kind != DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "committed workspace planning requires the original fresh workspace plan".into(),
        ));
    }
    let mut plan = execution.clone();
    plan.source_kind = DependencySourceKind::WorkspaceCommittedRlib;
    validate_committed_workspace_rlib_plan(&plan)?;
    Ok(plan)
}

/// Validate only the pure invocation boundary, never producer authority.
///
/// # Errors
/// Wrong class, nonlibrary output, generated/native inputs or project execution.
pub fn validate_committed_workspace_rlib_plan(
    plan: &DependencyActionPlan,
) -> Result<(), LiveRefusal> {
    validate_pure_workspace_rlib(plan)?;
    if plan.source_kind != DependencySourceKind::WorkspaceCommittedRlib {
        return Err(LiveRefusal::Facts(
            "committed workspace archive requires its distinct class".into(),
        ));
    }
    Ok(())
}

/// Require an exact binding for every retained candidate in the same ordered
/// directory/member inventory used to build the worker's read-only namespace.
///
/// # Errors
/// Empty, missing, extra, reordered, wrong-role or differently keyed witnesses.
pub fn validate_committed_workspace_dependencies(
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
) -> Result<(), LiveRefusal> {
    let candidates = directories
        .iter()
        .flat_map(|directory| &directory.artifacts)
        .collect::<Vec<_>>();
    if candidates.is_empty() || candidates.len() != dependencies.len() {
        return Err(LiveRefusal::Facts(
            "committed workspace archives require a witness for every retained Rust candidate"
                .into(),
        ));
    }
    for (candidate, dependency) in candidates.into_iter().zip(dependencies) {
        let basename = candidate.path.rsplit('/').next().unwrap_or("");
        let expected_role = if basename.ends_with(".rmeta") {
            OutputRole::ProvisionalMetadata
        } else if basename.ends_with(".rlib") {
            OutputRole::Materializable
        } else {
            return Err(LiveRefusal::Facts("non-Rust committed candidate".into()));
        };
        if dependency.path != candidate.path
            || dependency.object.0 != candidate.content_digest
            || dependency.role != expected_role
            || dependency.virtual_path.as_bytes() != basename.as_bytes()
        {
            return Err(LiveRefusal::Facts(
                "committed producer witness differs from the exact retained Rust candidate".into(),
            ));
        }
    }
    Ok(())
}

/// Mechanical namespace admission and complete exact producer binding.
///
/// # Errors
/// Unsupported invocation, namespace, extern or committed candidate inventory.
pub fn remote_committed_workspace_rlib_shape(
    plan: &DependencyActionPlan,
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    validate_committed_workspace_rlib_plan(plan)?;
    remote::remote_execution_shape(plan, directories, toolchain_root)?;
    validate_committed_workspace_dependencies(directories, dependencies)?;
    Ok(())
}

fn isolation_policy() -> TypedDigest {
    compute(POLICY_DOMAIN, ISOLATION_PROFILE.as_bytes())
}
fn execution_semantics() -> TypedDigest {
    compute(SEMANTICS_DOMAIN, SEMANTICS.as_bytes())
}

/// Separately versioned policy for the committed-producer archive class.
///
/// # Errors
/// The invocation is outside the pure contract.
pub fn remote_committed_workspace_rlib_isolation_policy(
    plan: &DependencyActionPlan,
) -> Result<TypedDigest, RemoteDependencyRefusal> {
    validate_committed_workspace_rlib_plan(plan)?;
    Ok(isolation_policy())
}

/// Descriptor classification only; never a replacement for live witnesses.
#[must_use]
pub fn is_committed_workspace_rlib_descriptor(descriptor: &ActionDescriptor) -> bool {
    descriptor.action_class == ActionClass::RustcWorkspaceCompile
        && descriptor.key_epoch == KEY_EPOCH
        && descriptor.projection_epoch == PROJECTION_EPOCH
        && descriptor.sandbox_semantic_policy == isolation_policy()
        && descriptor.execution_semantics == execution_semantics()
}

fn encode_digest(encoder: &mut CanonicalEncoder, digest: &TypedDigest) {
    match digest.algorithm {
        DigestAlgorithm::Sha256V1 => {
            encoder.str("sha256-v1");
        }
    }
    encoder.str(digest.domain).bytes(&digest.bytes);
}

/// Bind exact source, candidate bytes, committed provenance and runtime. Every
/// explicit archive is hashed whole under the existing retained input contract.
///
/// # Errors
/// Incomplete evidence, unbound runtime or a candidate without exact provenance.
#[allow(clippy::too_many_arguments)]
pub fn remote_committed_workspace_rlib_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
    inputs: &ActionInputManifest,
    build_script_output: Option<&[u8]>,
    toolchain_root: &str,
    retained_toolchain_sha256: &[u8; 32],
    runtime: &TypedDigest,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    remote_committed_workspace_rlib_shape(plan, directories, dependencies, toolchain_root)?;
    if build_script_output.is_some() {
        return Err(LiveRefusal::Facts(
            "committed workspace archives cannot consume a build-script run record".into(),
        )
        .into());
    }
    let externs = remote::remote_extern_facts(plan, directories)?;
    let mut key = captured_action_key(plan, toolchain, &externs, directories, None, inputs)?;
    remote::bind_remote_execution_inputs(
        &mut key,
        plan,
        toolchain_root,
        retained_toolchain_sha256,
        runtime,
    )?;
    let mut provenance = CanonicalEncoder::new();
    encode_digest(&mut provenance, &key.descriptor.dependency_inputs);
    provenance.seq(dependencies, |encoder, dependency| {
        encoder.str(&dependency.path);
        encode_digest(encoder, &dependency.producer_action);
        encode_digest(encoder, &dependency.producer_descriptor);
        encode_digest(encoder, &dependency.producer_manifest);
        encoder.str(match dependency.role {
            OutputRole::Materializable => "materializable",
            OutputRole::ProvisionalMetadata => "provisional-metadata",
            OutputRole::DepInfo => "dep-info",
            OutputRole::BuildScriptMetadata => "build-script-metadata",
            OutputRole::TestSideEffect => "test-side-effect",
        });
        encoder.bytes(dependency.virtual_path.as_bytes());
        encode_digest(encoder, &dependency.object.0);
    });
    key.descriptor.dependency_inputs = compute(
        "rabs.canonical-workspace-committed-rlib.dependencies.v1",
        &provenance.finish(),
    );
    let mut environment = CanonicalEncoder::new();
    environment.seq(&plan.execution_env, |encoder, (name, value)| {
        encoder.str(name).str(value);
    });
    key.descriptor.environment = compute(
        "rabs.canonical-workspace-committed-rlib.environment.v1",
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
        "rabs.canonical-workspace-committed-rlib.invocation.v1",
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
        ExternFact, LiveRustcRequest, plan_canonical_workspace_execution,
        remote_workspace_execution_key,
    };
    use rabs_protocol::input_evidence::{
        DirectoryEnumeration, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };

    const HOST: &str = "x86_64-unknown-linux-gnu";
    const OUTPUT: &str = "/__rabs/out/cargo/debug/deps";
    const TOOLCHAIN: &str = "/__rabs/toolchain";

    fn digest(bytes: &[u8]) -> TypedDigest {
        compute("rabs.test.committed-workspace.v1", bytes)
    }

    fn execution(archive: bool) -> DependencyActionPlan {
        execution_with_payload(archive, "one")
    }

    fn execution_with_payload(archive: bool, payload: &str) -> DependencyActionPlan {
        let mut argv = [
            "/__rabs/toolchain/bin/rustc",
            "--crate-name=consumer",
            "--crate-type=lib",
            "--edition=2021",
            "consumer/src/lib.rs",
            "--error-format=json",
            "--json=artifacts",
            "--emit=dep-info,metadata,link",
            "--out-dir",
            OUTPUT,
            "-L",
            "dependency=/__rabs/out/cargo/debug/deps",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        argv.push(format!(
            "--extern=upstream={OUTPUT}/libupstream.{}",
            if archive { "rlib" } else { "rmeta" }
        ));
        let env = [
            ("HOME", "/__rabs/home"),
            ("CARGO_HOME", "/__rabs/cargo-home"),
            ("CARGO_MANIFEST_DIR", "/__rabs/workspace/consumer"),
            ("CARGO_PKG_NAME", "consumer"),
            ("CARGO_PRIMARY_PACKAGE", "1"),
            ("USER_PAYLOAD", payload),
            ("CARGO_MAKEFLAGS", "--jobserver-auth=3,4"),
            ("LD_LIBRARY_PATH", "/__rabs/toolchain/lib"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect::<Vec<_>>();
        plan_canonical_workspace_execution(
            LiveRustcRequest {
                argv: &argv,
                env: &env,
                cwd: "/__rabs/workspace",
            },
            HOST,
        )
        .unwrap()
    }

    fn inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let listing = |relative: &str, names: &[&str]| DirectoryEnumeration {
            virtual_path: RawBytes::new(
                if relative.is_empty() {
                    plan.source_virtual_root()
                } else {
                    plan.input_virtual_path(relative)
                }
                .into_bytes(),
            ),
            entries: names.iter().map(|name| RawBytes::from(*name)).collect(),
        };
        ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: [
                "Cargo.toml",
                "consumer/Cargo.toml",
                "consumer/src/lib.rs",
                "sibling.txt",
            ]
            .into_iter()
            .map(|relative| PositiveInput {
                virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
                object: ObjectId(digest(relative.as_bytes())),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            })
            .collect(),
            directory_enumerations: vec![
                listing("", &["Cargo.toml", "consumer", "empty", "sibling.txt"]),
                listing("consumer", &["Cargo.toml", "src"]),
                listing("consumer/src", &["lib.rs"]),
                listing("empty", &[]),
            ],
            ..ActionInputManifest::default()
        }
    }

    fn toolchain() -> ToolchainFacts {
        ToolchainFacts {
            compiler_binary_digest: digest(b"compiler"),
            verbose_version: format!("rustc 1.100.0\nhost: {HOST}\nLLVM version: 21"),
            sysroot_root_digest: digest(b"sysroot"),
            runtime_libraries: Vec::new(),
        }
    }

    fn candidate(name: &str) -> CommittedWorkspaceDependency {
        CommittedWorkspaceDependency {
            path: format!("{OUTPUT}/{name}"),
            producer_action: digest(b"producer action"),
            producer_descriptor: digest(b"producer descriptor"),
            producer_manifest: digest(b"producer manifest"),
            role: if name.ends_with(".rmeta") {
                OutputRole::ProvisionalMetadata
            } else {
                OutputRole::Materializable
            },
            virtual_path: RawBytes::from(name),
            object: ObjectId(digest(name.as_bytes())),
        }
    }

    fn directories(dependencies: &[CommittedWorkspaceDependency]) -> Vec<DependencyDirectoryFact> {
        vec![DependencyDirectoryFact {
            path: OUTPUT.into(),
            artifacts: dependencies
                .iter()
                .map(|dependency| ExternFact {
                    path: dependency.path.clone(),
                    content_digest: dependency.object.0.clone(),
                })
                .collect(),
        }]
    }

    fn key(
        plan: &DependencyActionPlan,
        dependencies: &[CommittedWorkspaceDependency],
        inputs: &ActionInputManifest,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_committed_workspace_rlib_key(
            plan,
            &toolchain(),
            &directories(dependencies),
            dependencies,
            inputs,
            None,
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
    }

    #[test]
    fn committed_producer_identity_has_its_own_key_and_receipt_profile() {
        let fresh = execution(false);
        let plan = plan_committed_workspace_rlib(&fresh).unwrap();
        let dependencies = vec![candidate("libupstream.rmeta")];
        let inputs = inputs(&plan);
        let committed = key(&plan, &dependencies, &inputs).unwrap();
        assert!(is_committed_workspace_rlib_descriptor(
            &committed.descriptor
        ));
        assert_eq!(committed.descriptor.key_epoch, 6);
        let fresh_key = remote_workspace_execution_key(
            &fresh,
            &toolchain(),
            &directories(&dependencies),
            &inputs,
            None,
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
        .unwrap();
        assert_ne!(committed.action_key, fresh_key.action_key);
        assert!(!is_committed_workspace_rlib_descriptor(
            &fresh_key.descriptor
        ));
        assert_eq!(
            super::super::workspace_cache::closed_workspace_library_descriptor_class(
                &committed.descriptor
            ),
            None
        );
        assert!(super::super::workspace_cache::plan_closed_workspace_library(&fresh).is_err());
        assert!(plan_committed_workspace_rlib(&plan).is_err());
        for field in 0..3 {
            let mut changed = dependencies.clone();
            match field {
                0 => changed[0].producer_action.bytes[0] ^= 1,
                1 => changed[0].producer_descriptor.bytes[0] ^= 1,
                _ => changed[0].producer_manifest.bytes[0] ^= 1,
            }
            assert_ne!(
                key(&plan, &changed, &inputs).unwrap().action_key,
                committed.action_key
            );
        }
    }

    #[test]
    fn every_transitive_candidate_requires_its_exact_ordered_witness() {
        let plan = plan_committed_workspace_rlib(&execution(false)).unwrap();
        let dependencies = vec![candidate("libother.rmeta"), candidate("libupstream.rmeta")];
        let directories = directories(&dependencies);
        assert!(
            remote_committed_workspace_rlib_shape(&plan, &directories, &dependencies, TOOLCHAIN)
                .is_ok()
        );
        for altered in [
            Vec::new(),
            dependencies[..1].to_vec(),
            vec![dependencies[1].clone(), dependencies[0].clone()],
            vec![dependencies[0].clone(), dependencies[0].clone()],
        ] {
            assert!(validate_committed_workspace_dependencies(&directories, &altered).is_err());
        }
        for field in 0..4 {
            let mut altered = dependencies.clone();
            match field {
                0 => altered[0].path.push('x'),
                1 => altered[0].object.0.bytes[0] ^= 1,
                2 => altered[0].role = OutputRole::Materializable,
                _ => altered[0].virtual_path = RawBytes::from("different.rmeta"),
            }
            assert!(validate_committed_workspace_dependencies(&directories, &altered).is_err());
        }
    }

    #[test]
    fn explicit_rlib_uses_the_entire_archive_beside_identical_metadata() {
        let plan = plan_committed_workspace_rlib(&execution(true)).unwrap();
        let dependencies = vec![
            candidate("libupstream.rlib"),
            candidate("libupstream.rmeta"),
        ];
        let inputs = inputs(&plan);
        let before = key(&plan, &dependencies, &inputs).unwrap();
        let mut changed = dependencies.clone();
        changed[0].object = ObjectId(digest(b"same metadata but different archive code"));
        assert_ne!(
            key(&plan, &changed, &inputs).unwrap().action_key,
            before.action_key
        );
        assert!(key(&plan, &dependencies[1..], &inputs).is_err());
        let mut changed = dependencies.clone();
        changed[1].object = ObjectId(digest(b"different non-explicit metadata candidate"));
        assert_ne!(
            key(&plan, &changed, &inputs).unwrap().action_key,
            before.action_key
        );
    }

    #[test]
    fn complete_workspace_environment_and_negative_directories_remain_keyed() {
        let plan = plan_committed_workspace_rlib(&execution(false)).unwrap();
        let dependencies = vec![candidate("libupstream.rmeta")];
        let original = inputs(&plan);
        let before = key(&plan, &dependencies, &original).unwrap();
        let mut changed = original.clone();
        changed.inputs.last_mut().unwrap().object = ObjectId(digest(b"sibling changed"));
        assert_ne!(
            key(&plan, &dependencies, &changed).unwrap().action_key,
            before.action_key
        );
        let mut missing = original.clone();
        missing.directory_enumerations.pop();
        assert!(key(&plan, &dependencies, &missing).is_err());
        let mut topology = original.clone();
        topology.directory_enumerations[0]
            .entries
            .push(RawBytes::from("z_empty"));
        topology.directory_enumerations.push(DirectoryEnumeration {
            virtual_path: RawBytes::new(plan.input_virtual_path("z_empty").into_bytes()),
            entries: Vec::new(),
        });
        assert_ne!(
            key(&plan, &dependencies, &topology).unwrap().action_key,
            before.action_key
        );
        let mut environment = plan.clone();
        environment
            .execution_env
            .iter_mut()
            .find(|(name, _)| name == "USER_PAYLOAD")
            .unwrap()
            .1 = "two".into();
        assert!(key(&environment, &dependencies, &original).is_err());
        let environment =
            plan_committed_workspace_rlib(&execution_with_payload(false, "two")).unwrap();
        assert_ne!(
            key(&environment, &dependencies, &original)
                .unwrap()
                .action_key,
            before.action_key
        );
    }

    #[test]
    fn unbound_candidate_and_project_execution_cannot_borrow_the_class() {
        let plan = plan_committed_workspace_rlib(&execution(false)).unwrap();
        let dependencies = vec![candidate("libupstream.rmeta")];
        let mut directories = directories(&dependencies);
        directories[0].artifacts.push(ExternFact {
            path: format!("{OUTPUT}/libunsafe.so"),
            content_digest: digest(b"plugin"),
        });
        assert!(
            remote_committed_workspace_rlib_shape(&plan, &directories, &dependencies, TOOLCHAIN)
                .is_err()
        );
        let mut generated = plan.clone();
        generated.generated_root = Some("/__rabs/out/cargo/debug/build/consumer/out".into());
        assert!(validate_committed_workspace_rlib_plan(&generated).is_err());
        for source_kind in [
            DependencySourceKind::WorkspaceExecutionOnly,
            DependencySourceKind::WorkspaceClosedRlib,
            DependencySourceKind::WorkspaceClosedMetadata,
        ] {
            let mut mislabeled = plan.clone();
            mislabeled.source_kind = source_kind;
            assert!(key(&mislabeled, &dependencies, &inputs(&plan)).is_err());
        }
        let mut macro_kind = plan.clone();
        macro_kind.invocation.crate_types = vec!["proc-macro".into()];
        assert!(validate_committed_workspace_rlib_plan(&macro_kind).is_err());
        let mut bare = plan.clone();
        bare.invocation.externs[0].1 = None;
        assert!(key(&bare, &dependencies, &inputs(&plan)).is_err());
    }
}
