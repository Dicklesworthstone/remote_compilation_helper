//! Complete-workspace libraries with exact, already committed Rust producers.
//!
//! Every visible retained crate candidate, including candidates not named by an
//! explicit extern, requires a driver-owned committed-install witness. These
//! pure facts bind that witness into the key; they never grant installation or
//! publication authority. The coordinator revalidates the original file
//! generation and the current durable producer lineage at each live boundary.

use super::remote::{self, RemoteDependencyOutputClass, RemoteDependencyRefusal};
use super::workspace_cache::validate_pure_workspace_rlib;
use super::workspace_execution::workspace_layout;
use super::{
    DependencyActionPlan, DependencyDirectoryFact, DependencySourceKind, LiveDependencyKey,
    LiveRefusal, ToolchainFacts, artifacts_component, captured_action_key,
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
const METADATA_KEY_EPOCH: u32 = 7;
const METADATA_POLICY_DOMAIN: &str = "rabs.canonical-workspace-committed-metadata.isolation.v1";
const METADATA_SEMANTICS_DOMAIN: &str = "rabs.canonical-workspace-committed-metadata.semantics.v1";
const METADATA_SEMANTICS: &str = "completed independently supervised pure Rust metadata check; canonical-workspace-closed-metadata-v1 explicitly negotiated in ClosedMetadata mode without procfs or entropy devices; complete sealed workspace and exact environment; every retained Rust candidate bound to exact committed workspace producer action, descriptor, manifest and logical output; no provisional, adopted, local fallback or request-owned producer authority; transitive current producer safety at commit and replay; separate metadata class, capture and independent sample gates";

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

pub(super) const METADATA_ISOLATION_PROFILE: &str = "canonical-workspace-committed-metadata-v1: \
    driver-retained Cargo-selected ordinary library check in a graph without \
    project executors; canonical-workspace-closed-metadata-v1 explicitly \
    negotiated in ClosedMetadata mode independently of ordinary Metadata or \
    Rlib execution authority; complete immutable canonical workspace with every \
    immediate directory listing; exact argv, cwd, environment and output \
    placement; complete retained toolchain and measured ELF runtime; no procfs \
    or entropy devices, only private null device and fresh private output, HOME \
    and temporary storage; exact read-only retained Rust candidate inventories \
    in original directory order, including every transitive alternative; every \
    retained rmeta/rlib physically installed from an already committed \
    closed-workspace producer with exact action, descriptor, manifest and \
    logical-output object identity; whole explicit rlib bytes retained, existing \
    versioned metadata shadowing projection unchanged; no generated/native \
    inputs, project executors, proc macros, incremental state, archive, binary \
    or harness output, final links or local wrapper completion authority; no \
    unresolved, provisional, adopted, fallback or request-owned producer lineage; \
    original file generations and transitive current producer serving and class \
    safety revalidated; exact dep-info, tracked-control-variable veto and \
    authenticated drained receipt; separate metadata publication class and \
    independent samples, release and private installation gates";

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

/// Refine a fresh workspace check into the separate committed metadata class.
/// Exact driver selection and committed producer witnesses are still required;
/// this pure planner supplies neither execution nor publication authority.
///
/// # Errors
/// A nonfresh source class or an invocation outside ordinary library metadata.
pub fn plan_committed_workspace_metadata(
    execution: &DependencyActionPlan,
) -> Result<DependencyActionPlan, LiveRefusal> {
    if execution.source_kind != DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "committed metadata planning requires the original fresh workspace plan".into(),
        ));
    }
    let mut plan = execution.clone();
    plan.source_kind = DependencySourceKind::WorkspaceCommittedMetadata;
    validate_committed_workspace_metadata_plan(&plan)?;
    Ok(plan)
}

/// Validate the strict metadata invocation independently of producer authority.
/// The archive and leaf metadata profiles remain unchanged and cannot supply
/// qualification for this separately keyed class.
///
/// # Errors
/// A different class, nonlibrary or codegen output, harness, generated/native
/// inputs, or a noncanonical workspace layout or environment.
pub fn validate_committed_workspace_metadata_plan(
    plan: &DependencyActionPlan,
) -> Result<(), LiveRefusal> {
    workspace_layout(plan)?;
    if plan.source_kind != DependencySourceKind::WorkspaceCommittedMetadata
        || !matches!(plan.invocation.crate_types.as_slice(), [kind] if matches!(kind.as_str(), "lib" | "rlib"))
        || plan
            .invocation
            .passthrough
            .iter()
            .any(|argument| argument == "--test")
        || plan.generated_root.is_some()
        || !plan.native_roots.is_empty()
        || !plan.invocation.native_libs.is_empty()
        || remote::remote_dependency_output_class(&plan.invocation)
            != Ok(RemoteDependencyOutputClass::Metadata)
    {
        return Err(LiveRefusal::Facts(
            "committed workspace metadata requires its distinct ordinary library check class without generated or native inputs".into(),
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

/// Admit the strict metadata namespace with the same exact ordered committed
/// producer bindings used by archives. Implicit candidates receive the same
/// path, type, ordering and output-alias checks as explicit extern inputs.
///
/// # Errors
/// An unsupported invocation or namespace, incomplete provenance, an invalid
/// retained candidate, or an extern outside the exact committed inventory.
pub fn remote_committed_workspace_metadata_shape(
    plan: &DependencyActionPlan,
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    validate_committed_workspace_metadata_plan(plan)?;
    remote::remote_execution_shape(plan, directories, toolchain_root)?;
    validate_committed_workspace_dependencies(directories, dependencies)?;
    let externs = remote::remote_extern_facts(plan, directories)?;
    artifacts_component(plan, &externs, directories)?;
    Ok(())
}

fn isolation_policy() -> TypedDigest {
    compute(POLICY_DOMAIN, ISOLATION_PROFILE.as_bytes())
}
fn execution_semantics() -> TypedDigest {
    compute(SEMANTICS_DOMAIN, SEMANTICS.as_bytes())
}

fn metadata_isolation_policy() -> TypedDigest {
    compute(
        METADATA_POLICY_DOMAIN,
        METADATA_ISOLATION_PROFILE.as_bytes(),
    )
}

fn metadata_execution_semantics() -> TypedDigest {
    compute(METADATA_SEMANTICS_DOMAIN, METADATA_SEMANTICS.as_bytes())
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

/// The independently versioned committed metadata policy. Its worker must
/// explicitly negotiate the closed metadata namespace; this identity never
/// authorizes reuse under the ordinary fresh metadata context.
///
/// # Errors
/// The invocation is outside the committed metadata contract.
pub fn remote_committed_workspace_metadata_isolation_policy(
    plan: &DependencyActionPlan,
) -> Result<TypedDigest, RemoteDependencyRefusal> {
    validate_committed_workspace_metadata_plan(plan)?;
    Ok(metadata_isolation_policy())
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

/// Classify only the exact committed metadata descriptor, never producer
/// completion, current lineage safety, or cache-serving authority.
#[must_use]
pub fn is_committed_workspace_metadata_descriptor(descriptor: &ActionDescriptor) -> bool {
    descriptor.action_class == ActionClass::RustcWorkspaceCompile
        && descriptor.key_epoch == METADATA_KEY_EPOCH
        && descriptor.projection_epoch == PROJECTION_EPOCH
        && descriptor.sandbox_semantic_policy == metadata_isolation_policy()
        && descriptor.execution_semantics == metadata_execution_semantics()
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
    remote_committed_workspace_key(
        plan,
        toolchain,
        directories,
        dependencies,
        inputs,
        build_script_output,
        toolchain_root,
        retained_toolchain_sha256,
        runtime,
        RemoteDependencyOutputClass::Rlib,
    )
}

/// Bind strict metadata execution to exact source, complete candidate bytes,
/// committed producer identities and runtime, using separate class domains.
/// The coordinator must retain and revalidate the same physical installation
/// witnesses and transitive durable producer safety before commit or replay.
///
/// # Errors
/// Incomplete evidence, unbound runtime, an unsupported metadata invocation,
/// or any retained candidate without exact committed provenance.
#[allow(clippy::too_many_arguments)]
pub fn remote_committed_workspace_metadata_key(
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
    remote_committed_workspace_key(
        plan,
        toolchain,
        directories,
        dependencies,
        inputs,
        build_script_output,
        toolchain_root,
        retained_toolchain_sha256,
        runtime,
        RemoteDependencyOutputClass::Metadata,
    )
}

#[allow(clippy::too_many_arguments)]
fn remote_committed_workspace_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
    inputs: &ActionInputManifest,
    build_script_output: Option<&[u8]>,
    toolchain_root: &str,
    retained_toolchain_sha256: &[u8; 32],
    runtime: &TypedDigest,
    output: RemoteDependencyOutputClass,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    match output {
        RemoteDependencyOutputClass::Rlib => {
            remote_committed_workspace_rlib_shape(plan, directories, dependencies, toolchain_root)?;
        }
        RemoteDependencyOutputClass::Metadata => {
            remote_committed_workspace_metadata_shape(
                plan,
                directories,
                dependencies,
                toolchain_root,
            )?;
        }
    }
    if build_script_output.is_some() {
        return Err(LiveRefusal::Facts(
            "committed workspace libraries cannot consume a build-script run record".into(),
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
        match output {
            RemoteDependencyOutputClass::Rlib => {
                "rabs.canonical-workspace-committed-rlib.dependencies.v1"
            }
            RemoteDependencyOutputClass::Metadata => {
                "rabs.canonical-workspace-committed-metadata.dependencies.v1"
            }
        },
        &provenance.finish(),
    );
    let mut environment = CanonicalEncoder::new();
    environment.seq(&plan.execution_env, |encoder, (name, value)| {
        encoder.str(name).str(value);
    });
    key.descriptor.environment = compute(
        match output {
            RemoteDependencyOutputClass::Rlib => {
                "rabs.canonical-workspace-committed-rlib.environment.v1"
            }
            RemoteDependencyOutputClass::Metadata => {
                "rabs.canonical-workspace-committed-metadata.environment.v1"
            }
        },
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
        match output {
            RemoteDependencyOutputClass::Rlib => {
                "rabs.canonical-workspace-committed-rlib.invocation.v1"
            }
            RemoteDependencyOutputClass::Metadata => {
                "rabs.canonical-workspace-committed-metadata.invocation.v1"
            }
        },
        &invocation.finish(),
    );
    key.descriptor.key_epoch = match output {
        RemoteDependencyOutputClass::Rlib => KEY_EPOCH,
        RemoteDependencyOutputClass::Metadata => METADATA_KEY_EPOCH,
    };
    key.descriptor.projection_epoch = PROJECTION_EPOCH;
    key.descriptor.action_class = ActionClass::RustcWorkspaceCompile;
    key.descriptor.sandbox_semantic_policy = match output {
        RemoteDependencyOutputClass::Rlib => isolation_policy(),
        RemoteDependencyOutputClass::Metadata => metadata_isolation_policy(),
    };
    key.descriptor.execution_semantics = match output {
        RemoteDependencyOutputClass::Rlib => execution_semantics(),
        RemoteDependencyOutputClass::Metadata => metadata_execution_semantics(),
    };
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
        execution_with_output(archive, payload, false)
    }

    fn execution_with_output(archive: bool, payload: &str, metadata: bool) -> DependencyActionPlan {
        let mut argv = [
            "/__rabs/toolchain/bin/rustc",
            "--crate-name=consumer",
            "--crate-type=lib",
            "--edition=2021",
            "consumer/src/lib.rs",
            "--error-format=json",
            "--json=artifacts",
            if metadata {
                "--emit=dep-info,metadata"
            } else {
                "--emit=dep-info,metadata,link"
            },
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

    fn metadata_plan(archive: bool, payload: &str) -> DependencyActionPlan {
        plan_committed_workspace_metadata(&execution_with_output(archive, payload, true)).unwrap()
    }

    fn metadata_key(
        plan: &DependencyActionPlan,
        dependencies: &[CommittedWorkspaceDependency],
        inputs: &ActionInputManifest,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_committed_workspace_metadata_key(
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

    #[test]
    fn committed_metadata_has_its_own_identity_without_widening_archive_or_leaf_authority() {
        let fresh = execution_with_output(false, "one", true);
        let metadata = plan_committed_workspace_metadata(&fresh).unwrap();
        let archive = plan_committed_workspace_rlib(&execution(false)).unwrap();
        let dependencies = vec![candidate("libupstream.rmeta")];
        let input = inputs(&metadata);
        let keyed = metadata_key(&metadata, &dependencies, &input).unwrap();
        let archive_key = key(&archive, &dependencies, &input).unwrap();
        assert_eq!(keyed.descriptor.key_epoch, 7);
        assert_eq!(archive_key.descriptor.key_epoch, 6);
        assert_eq!(
            metadata.source_kind.as_str(),
            "canonical-workspace-committed-metadata-v1"
        );
        assert!(is_committed_workspace_metadata_descriptor(
            &keyed.descriptor
        ));
        assert!(!is_committed_workspace_rlib_descriptor(&keyed.descriptor));
        assert!(!is_committed_workspace_metadata_descriptor(
            &archive_key.descriptor
        ));
        assert_ne!(keyed.action_key, archive_key.action_key);
        assert!(plan_committed_workspace_metadata(&metadata).is_err());
        assert!(key(&metadata, &dependencies, &input).is_err());
        assert!(metadata_key(&archive, &dependencies, &input).is_err());
        assert!(super::super::workspace_cache::plan_closed_workspace_library(&fresh).is_err());
        assert!(
            super::super::workspace_cache::closed_workspace_library_descriptor_class(
                &keyed.descriptor
            )
            .is_none()
        );
        let fresh_key = remote_workspace_execution_key(
            &fresh,
            &toolchain(),
            &directories(&dependencies),
            &input,
            None,
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
        .unwrap();
        assert_ne!(keyed.action_key, fresh_key.action_key);
        assert!(!is_committed_workspace_metadata_descriptor(
            &fresh_key.descriptor
        ));
        for field in 0..5 {
            let mut mixed = keyed.descriptor.clone();
            match field {
                0 => mixed.key_epoch = archive_key.descriptor.key_epoch,
                1 => mixed.projection_epoch += 1,
                2 => {
                    mixed.sandbox_semantic_policy =
                        archive_key.descriptor.sandbox_semantic_policy.clone()
                }
                3 => mixed.execution_semantics = archive_key.descriptor.execution_semantics.clone(),
                _ => mixed.action_class = ActionClass::RustcDependencyCompile,
            }
            assert!(!is_committed_workspace_metadata_descriptor(&mixed));
            assert!(!is_committed_workspace_rlib_descriptor(&mixed));
        }
    }

    #[test]
    fn committed_metadata_keys_every_exact_producer_and_whole_explicit_archive() {
        for archive in [false, true] {
            let plan = metadata_plan(archive, "one");
            let dependencies = if archive {
                vec![
                    candidate("libupstream.rlib"),
                    candidate("libupstream.rmeta"),
                ]
            } else {
                vec![
                    candidate("libtransitive.rmeta"),
                    candidate("libupstream.rmeta"),
                ]
            };
            let input = inputs(&plan);
            let original = metadata_key(&plan, &dependencies, &input)
                .unwrap()
                .action_key;
            for candidate_index in 0..dependencies.len() {
                for field in 0..4 {
                    let mut changed = dependencies.clone();
                    let dependency = &mut changed[candidate_index];
                    match field {
                        0 => dependency.object.0.bytes[0] ^= 1,
                        1 => dependency.producer_action.bytes[0] ^= 1,
                        2 => dependency.producer_descriptor.bytes[0] ^= 1,
                        _ => dependency.producer_manifest.bytes[0] ^= 1,
                    }
                    assert_ne!(
                        metadata_key(&plan, &changed, &input).unwrap().action_key,
                        original,
                        "archive={archive}, candidate={candidate_index}, field={field}"
                    );
                }
            }
            if archive {
                assert!(metadata_key(&plan, &dependencies[1..], &input).is_err());
            } else {
                assert_ne!(
                    metadata_key(&plan, &dependencies[1..], &input)
                        .unwrap()
                        .action_key,
                    original
                );
            }
        }
    }

    #[test]
    fn committed_metadata_requires_complete_ordered_provenance_and_safe_candidates() {
        let plan = metadata_plan(false, "one");
        let dependencies = vec![
            candidate("libtransitive.rmeta"),
            candidate("libupstream.rmeta"),
        ];
        let candidates = directories(&dependencies);
        for field in 0..7 {
            let mut changed = dependencies.clone();
            match field {
                0 => changed.clear(),
                1 => {
                    changed.remove(0);
                }
                2 => changed.swap(0, 1),
                3 => changed[0].object.0.bytes[0] ^= 1,
                4 => changed[0].role = OutputRole::Materializable,
                5 => changed[0].virtual_path = RawBytes::from("different.rmeta"),
                _ => changed[0].path.push('x'),
            }
            assert!(
                remote_committed_workspace_metadata_shape(&plan, &candidates, &changed, TOOLCHAIN)
                    .is_err(),
                "provenance field {field}"
            );
        }
        for name in ["libplugin.so", "../liboutside.rmeta", "libconsumer.rmeta"] {
            let changed = vec![candidate(name), candidate("libupstream.rmeta")];
            assert!(
                remote_committed_workspace_metadata_shape(
                    &plan,
                    &directories(&changed),
                    &changed,
                    TOOLCHAIN
                )
                .is_err(),
                "candidate {name}"
            );
        }
        let mut changed = dependencies.clone();
        changed.swap(0, 1);
        assert!(
            remote_committed_workspace_metadata_shape(
                &plan,
                &directories(&changed),
                &changed,
                TOOLCHAIN
            )
            .is_err()
        );
        let mut extra = candidates.clone();
        extra[0].artifacts.push(ExternFact {
            path: format!("{OUTPUT}/libunregistered.rmeta"),
            content_digest: digest(b"unregistered candidate"),
        });
        assert!(
            remote_committed_workspace_metadata_shape(&plan, &extra, &dependencies, TOOLCHAIN)
                .is_err()
        );
    }

    #[test]
    fn committed_metadata_retains_complete_workspace_environment_and_runtime_identity() {
        let plan = metadata_plan(false, "one");
        let dependencies = vec![candidate("libupstream.rmeta")];
        let input = inputs(&plan);
        let original = metadata_key(&plan, &dependencies, &input)
            .unwrap()
            .action_key;
        let mut changed = input.clone();
        changed.inputs.last_mut().unwrap().object = ObjectId(digest(b"unrelated sibling changed"));
        assert_ne!(
            metadata_key(&plan, &dependencies, &changed)
                .unwrap()
                .action_key,
            original
        );
        changed = input.clone();
        changed.directory_enumerations.pop();
        assert!(metadata_key(&plan, &dependencies, &changed).is_err());
        assert_ne!(
            metadata_key(&metadata_plan(false, "two"), &dependencies, &input)
                .unwrap()
                .action_key,
            original
        );
        for name in ["CARGO_MAKEFLAGS", "CARGO_PRIMARY_PACKAGE"] {
            let mut changed = plan.clone();
            for environment in [&mut changed.keyed_env, &mut changed.execution_env] {
                environment
                    .iter_mut()
                    .find(|(key, _)| key == name)
                    .unwrap()
                    .1
                    .push_str(" changed");
            }
            assert_ne!(
                metadata_key(&changed, &dependencies, &input)
                    .unwrap()
                    .action_key,
                original
            );
        }
        let mut changed = plan.clone();
        changed
            .invocation
            .excluded_presentation
            .push("--color=always".into());
        assert_ne!(
            metadata_key(&changed, &dependencies, &input)
                .unwrap()
                .action_key,
            original
        );
        assert_ne!(
            remote_committed_workspace_metadata_key(
                &plan,
                &toolchain(),
                &directories(&dependencies),
                &dependencies,
                &input,
                None,
                TOOLCHAIN,
                &[40; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
            )
            .unwrap()
            .action_key,
            original
        );
        assert!(
            remote_committed_workspace_metadata_key(
                &plan,
                &toolchain(),
                &directories(&dependencies),
                &dependencies,
                &input,
                None,
                TOOLCHAIN,
                &[39; 32],
                &digest(b"unmeasured runtime"),
            )
            .is_err()
        );
    }

    #[test]
    fn committed_metadata_cannot_admit_codegen_harness_native_generated_or_bare_externs() {
        let plan = metadata_plan(false, "one");
        let dependencies = vec![candidate("libupstream.rmeta")];
        for source_kind in [
            DependencySourceKind::WorkspaceExecutionOnly,
            DependencySourceKind::WorkspaceClosedRlib,
            DependencySourceKind::WorkspaceClosedMetadata,
            DependencySourceKind::WorkspaceCommittedRlib,
        ] {
            let mut changed = plan.clone();
            changed.source_kind = source_kind;
            assert!(metadata_key(&changed, &dependencies, &inputs(&changed)).is_err());
        }
        for field in 0..6 {
            let mut changed = plan.clone();
            match field {
                0 => changed.invocation.emit.push("link".into()),
                1 => changed.invocation.crate_types = vec!["bin".into()],
                2 => changed.invocation.passthrough.push("--test".into()),
                3 => {
                    changed.generated_root =
                        Some("/__rabs/out/cargo/debug/build/consumer/out".into())
                }
                4 => changed
                    .invocation
                    .native_libs
                    .push("static=unmodeled".into()),
                _ => changed.invocation.codegen.push((
                    "incremental".into(),
                    Some("/__rabs/out/cargo/incremental".into()),
                )),
            }
            if let Ok(outputs) = crate::output_derivation::derive_workspace_output_declarations(
                &changed.invocation,
                &changed.host_triple,
            ) {
                changed.outputs = outputs;
            }
            assert!(
                validate_committed_workspace_metadata_plan(&changed).is_err(),
                "field {field}"
            );
        }
        let mut bare = plan.clone();
        bare.invocation.externs[0].1 = None;
        assert!(metadata_key(&bare, &dependencies, &inputs(&bare)).is_err());
        assert!(
            remote_committed_workspace_metadata_key(
                &plan,
                &toolchain(),
                &directories(&dependencies),
                &dependencies,
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
