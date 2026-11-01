//! Rust libraries with exact, already committed artifact producers.
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
const MIXED_RLIB_KEY_EPOCH: u32 = 8;
const MIXED_METADATA_KEY_EPOCH: u32 = 9;
const MIXED_RLIB_POLICY_DOMAIN: &str = "rabs.canonical-workspace-committed-mixed-rlib.isolation.v1";
const MIXED_METADATA_POLICY_DOMAIN: &str =
    "rabs.canonical-workspace-committed-mixed-metadata.isolation.v1";
const MIXED_RLIB_SEMANTICS_DOMAIN: &str =
    "rabs.canonical-workspace-committed-mixed-rlib.semantics.v1";
const MIXED_METADATA_SEMANTICS_DOMAIN: &str =
    "rabs.canonical-workspace-committed-mixed-metadata.semantics.v1";
const MIXED_RLIB_SEMANTICS: &str = "completed independently supervised pure Rust archive; complete sealed workspace and exact environment; every retained candidate bound to exact committed archive-workspace producer or separately qualified canonical remote immutable dependency archive leaf; exact producer action, descriptor, manifest, output role and whole object identity; empty external-leaf ancestry and per-intermediate workspace producer policy; no provisional, adopted, local fallback or request-owned producer authority; current transitive producer safety, authenticated drained capture and independent mixed-class samples";
const MIXED_METADATA_SEMANTICS: &str = "completed independently supervised pure Rust metadata check; explicitly negotiated ClosedMetadata namespace without procfs or entropy devices; complete sealed workspace and exact environment; every retained candidate bound to exact committed workspace producer or separately qualified canonical remote immutable dependency leaf; metadata producers authorize only metadata outputs, archive producers may authorize metadata and whole archives; exact producer action, descriptor, manifest, output role and object identity; empty external-leaf ancestry and per-intermediate workspace producer policy; no provisional, adopted, local fallback or request-owned producer authority; current transitive producer safety, authenticated drained capture and independent mixed-class samples";

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

pub(super) const MIXED_RLIB_ISOLATION_PROFILE: &str = "canonical-workspace-committed-mixed-rlib-v1: \
    driver-retained ordinary library build in a Cargo graph without project \
    executors; canonical-workspace-exec-v3 Rlib namespace with complete immutable \
    workspace and every immediate directory listing; exact argv, cwd, environment \
    and output placement; complete retained toolchain and measured ELF runtime; \
    no procfs or entropy devices, private null device, fresh output, HOME and temp; \
    exact read-only candidate inventories in original order, including transitive \
    alternatives and whole explicit archives; every candidate physically installed \
    from an already committed closed or mixed archive-workspace producer, or a \
    separately qualified canonical remote immutable dependency archive leaf; \
    external registry, Git and checked directory-source leaves require zero \
    explicit externs, zero retained candidates, no generated/native inputs and \
    empty durable ancestry; qualification binds exact action, descriptor, manifest \
    and original remote execution mode after verified published installation; \
    metadata-only external or workspace producers cannot authorize archive \
    consumers; exact producer output roles and whole object identities; original \
    file generations, current qualification and transitive producer safety \
    rechecked at publication and delivery; each intermediate retains its own \
    ancestry policy; no project executors, generated/native inputs, proc macros, \
    incremental state, final links, provisional adoption, local completion, \
    fallback or request-owned producer authority; exact dep-info and tracked \
    environment veto, authenticated drained receipt and independent mixed-class \
    samples, release and private installation gates";

pub(super) const MIXED_METADATA_ISOLATION_PROFILE: &str = "canonical-workspace-committed-mixed-metadata-v1: \
    driver-retained ordinary library check in a Cargo graph without project \
    executors; canonical-workspace-closed-metadata-v1 explicitly negotiated in \
    ClosedMetadata mode; complete immutable workspace and every immediate \
    directory listing; exact argv, cwd, environment and output placement; complete \
    retained toolchain and measured ELF runtime; no procfs or entropy devices, \
    private null device, fresh output, HOME and temp; exact read-only candidate \
    inventories in original order, including transitive alternatives and whole \
    explicit archives; every candidate physically installed from a committed \
    closed or mixed workspace producer, or a separately qualified canonical \
    remote immutable dependency leaf; external registry, Git and checked \
    directory-source leaves require zero explicit externs, zero retained \
    candidates, no generated/native inputs and empty durable ancestry; qualification \
    binds exact action, descriptor, manifest and original remote execution mode \
    after verified published installation; metadata producers authorize only \
    ProvisionalMetadata rmeta, archive producers may authorize rmeta or whole \
    Materializable rlib; original file generations, current qualification and \
    transitive producer safety rechecked at publication and delivery; each \
    intermediate retains its own ancestry policy; no project executors, \
    generated/native inputs, proc macros, incremental state, archive or harness \
    outputs, final links, provisional adoption, local completion, fallback or \
    request-owned producer authority; exact dep-info and tracked environment veto, \
    authenticated drained receipt and independent mixed-class samples, release \
    and private installation gates";

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

/// The producer contract retained by an operation-owned committed-input proof.
/// Source origin is independent: immutable DAG policies retain the original
/// registry, Git or directory-package kind; workspace DAG policies retain the
/// existing mixed workspace source scope and use new descriptor identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommittedDependencyPolicy {
    /// Existing workspace-only archive producer contract, epoch 6.
    WorkspaceRlib,
    /// Existing workspace-only metadata producer contract, epoch 7.
    WorkspaceMetadata,
    /// Existing workspace/archive and qualified immutable-leaf contract, epoch 8.
    MixedWorkspaceRlib,
    /// Existing workspace/metadata and qualified immutable-leaf contract, epoch 9.
    MixedWorkspaceMetadata,
    /// Immutable archive with a complete committed producer inventory, epoch 10.
    ImmutableDagRlib,
    /// Immutable metadata with a complete committed producer inventory, epoch 11.
    ImmutableDagMetadata,
    /// Workspace archive admitting committed immutable dependency DAGs, epoch 12.
    WorkspaceDagRlib,
    /// Workspace metadata admitting committed immutable dependency DAGs, epoch 13.
    WorkspaceDagMetadata,
}

impl CommittedDependencyPolicy {
    /// Original policy for existing committed workspace source classes. New
    /// DAG policies require an explicit retained capability; a source kind
    /// alone never selects them.
    #[must_use]
    pub const fn from_source_kind(kind: DependencySourceKind) -> Option<Self> {
        match kind {
            DependencySourceKind::WorkspaceCommittedRlib => Some(Self::WorkspaceRlib),
            DependencySourceKind::WorkspaceCommittedMetadata => Some(Self::WorkspaceMetadata),
            DependencySourceKind::WorkspaceMixedRlib => Some(Self::MixedWorkspaceRlib),
            DependencySourceKind::WorkspaceMixedMetadata => Some(Self::MixedWorkspaceMetadata),
            _ => None,
        }
    }

    /// Exact compiler output class; workspace metadata additionally requires
    /// the separately negotiated ClosedMetadata worker namespace.
    #[must_use]
    pub const fn output_class(self) -> RemoteDependencyOutputClass {
        match self {
            Self::WorkspaceRlib
            | Self::MixedWorkspaceRlib
            | Self::ImmutableDagRlib
            | Self::WorkspaceDagRlib => RemoteDependencyOutputClass::Rlib,
            Self::WorkspaceMetadata
            | Self::MixedWorkspaceMetadata
            | Self::ImmutableDagMetadata
            | Self::WorkspaceDagMetadata => RemoteDependencyOutputClass::Metadata,
        }
    }

    /// Check source origin and invocation compatibility, independently of any
    /// installed producer, current publication or runtime authority.
    ///
    /// # Errors
    /// A different source/mode, noncanonical layout, or unsupported inputs.
    pub fn validate_plan(self, plan: &DependencyActionPlan) -> Result<(), LiveRefusal> {
        match self {
            Self::WorkspaceRlib => validate_committed_workspace_rlib_plan(plan),
            Self::WorkspaceMetadata => validate_committed_workspace_metadata_plan(plan),
            Self::MixedWorkspaceRlib
            | Self::MixedWorkspaceMetadata
            | Self::WorkspaceDagRlib
            | Self::WorkspaceDagMetadata => {
                if validate_mixed_workspace_library_plan(plan)? != self.output_class() {
                    return Err(LiveRefusal::Facts(
                        "committed policy differs from workspace output class".into(),
                    ));
                }
                Ok(())
            }
            Self::ImmutableDagRlib | Self::ImmutableDagMetadata => {
                super::canonical_cargo::canonical_layout(plan)?;
                let source_is_immutable = match plan.source_kind {
                    DependencySourceKind::RegistryPackage | DependencySourceKind::GitCheckout => {
                        plan.directory_source_manifest.is_none()
                    }
                    DependencySourceKind::DirectoryPackage => {
                        plan.directory_source_manifest.is_some()
                    }
                    _ => false,
                };
                if !source_is_immutable
                    || !matches!(plan.invocation.crate_types.as_slice(), [kind] if matches!(kind.as_str(), "lib" | "rlib"))
                    || plan.generated_root.is_some()
                    || !plan.native_roots.is_empty()
                    || !plan.invocation.native_libs.is_empty()
                    || remote::remote_dependency_output_class(&plan.invocation)
                        != Ok(self.output_class())
                {
                    return Err(LiveRefusal::Facts("committed immutable DAG requires a pure canonical immutable library without generated or native inputs".into()));
                }
                let outputs = crate::output_derivation::derive_dependency_output_declarations(
                    &plan.invocation,
                    &plan.host_triple,
                )
                .map_err(|error| {
                    LiveRefusal::Facts(format!("immutable DAG output contract: {error:?}"))
                })?;
                if outputs.canonical_bytes() != plan.outputs.canonical_bytes() {
                    return Err(LiveRefusal::Facts(
                        "immutable DAG output declarations differ from its invocation".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

struct DagContract {
    epoch: u32,
    class: ActionClass,
    isolation_domain: &'static str,
    semantics_domain: &'static str,
    dependencies_domain: &'static str,
    profile: &'static str,
}

const IMMUTABLE_DAG_RLIB: DagContract = DagContract {
    epoch: 10,
    class: ActionClass::RustcDependencyCompile,
    isolation_domain: "rabs.canonical-immutable-committed-dag-rlib.isolation.v1",
    semantics_domain: "rabs.canonical-immutable-committed-dag-rlib.semantics.v1",
    dependencies_domain: "rabs.canonical-immutable-committed-dag-rlib.dependencies.v1",
    profile: "canonical-immutable-committed-dag-rlib-v1: complete immutable canonical registry, Git or checksum-witnessed directory package; existing canonical-dependency-exec-v4 Rlib namespace with no procfs or entropy devices; exact argv, semantic environment, complete retained toolchain and matched ELF runtime; exact ordered read-only Rust candidate inventory, whole explicit archives and unchanged metadata-shadow projection; every retained candidate bound to an operation-owned installed generation and exact committed archive producer action, descriptor, manifest, role and object; qualified immutable archive leaves or committed immutable archive DAGs, no unresolved ancestors; H028 carries all exact retained candidates and current transitive serving, class and quarantine gates apply at commit and delivery; no local completion, request-owned or unregistered inputs, generated/native inputs, proc macros, incremental state or final links; authenticated drained capture, exact diagnostics, dep-info and tracked-control veto; separate class samples and existing release and installation gates",
};
const IMMUTABLE_DAG_METADATA: DagContract = DagContract {
    epoch: 11,
    class: ActionClass::RustcDependencyCompile,
    isolation_domain: "rabs.canonical-immutable-committed-dag-metadata.isolation.v1",
    semantics_domain: "rabs.canonical-immutable-committed-dag-metadata.semantics.v1",
    dependencies_domain: "rabs.canonical-immutable-committed-dag-metadata.dependencies.v1",
    profile: "canonical-immutable-committed-dag-metadata-v1: complete immutable canonical registry, Git or checksum-witnessed directory package; existing canonical-dependency-exec-v4 Metadata namespace and established dep-info read-closure contract; exact canonical argv and semantic environment, complete retained toolchain and matched ELF runtime; exact ordered read-only Rust candidate inventory and whole explicit archives; every retained candidate bound to an operation-owned installed generation and exact committed immutable producer action, descriptor, manifest, role and object; qualified immutable leaves or committed immutable DAGs; metadata producers authorize only ProvisionalMetadata rmeta, archive producers may authorize rmeta or whole Materializable rlib; H028 carries every retained candidate and current transitive serving, class and quarantine gates apply at commit and delivery; no unregistered, unresolved, adopted, local fallback or request-owned authority; no generated/native inputs, proc macros, incremental state or codegen output; authenticated drained capture, exact diagnostics and tracked-control veto, independent class samples and existing release and installation gates",
};
const WORKSPACE_DAG_RLIB: DagContract = DagContract {
    epoch: 12,
    class: ActionClass::RustcWorkspaceCompile,
    isolation_domain: "rabs.canonical-workspace-committed-dag-rlib.isolation.v1",
    semantics_domain: "rabs.canonical-workspace-committed-dag-rlib.semantics.v1",
    dependencies_domain: "rabs.canonical-workspace-committed-dag-rlib.dependencies.v1",
    profile: "canonical-workspace-committed-dag-rlib-v1: selected ordinary library in an executor-free canonical Cargo graph; complete immutable workspace files and directory topology, exact argv and environment, complete retained toolchain and matched ELF runtime; existing canonical-workspace-exec-v3 Rlib namespace with no procfs or entropy devices; complete ordered retained candidate inventory and whole explicit archive bytes; every candidate has its original operation-owned installation generation and exact committed producer action, descriptor, manifest, role and object; closed, mixed or DAG workspace archive producers plus qualified immutable archive leaves and committed immutable archive DAGs; every intermediate retains its own producer policy, metadata-only producer authority is excluded; exact H028 ancestry and current transitive serving/class safety at commit and every delivery phase; no generated/native inputs, proc macros, incremental state, final links, local or request-owned completion, unresolved or adopted lineage; authenticated drained capture, exact diagnostics and dep-info, separate class samples and existing release and installation gates",
};
const WORKSPACE_DAG_METADATA: DagContract = DagContract {
    epoch: 13,
    class: ActionClass::RustcWorkspaceCompile,
    isolation_domain: "rabs.canonical-workspace-committed-dag-metadata.isolation.v1",
    semantics_domain: "rabs.canonical-workspace-committed-dag-metadata.semantics.v1",
    dependencies_domain: "rabs.canonical-workspace-committed-dag-metadata.dependencies.v1",
    profile: "canonical-workspace-committed-dag-metadata-v1: selected ordinary check in an executor-free canonical Cargo graph; complete immutable workspace files and directory topology, exact argv and environment, complete retained toolchain and matched ELF runtime; explicitly negotiated canonical-workspace-closed-metadata-v1 ClosedMetadata namespace without procfs or entropy devices; every ordered retained Rust candidate has its original operation-owned installation generation and exact committed producer action, descriptor, manifest, role and object; closed, mixed or DAG workspace producers plus qualified immutable leaves and committed immutable DAGs; metadata producers authorize only ProvisionalMetadata rmeta, archive producers may authorize rmeta or whole Materializable rlib; every intermediate retains its own narrower producer policy; complete H028 ancestry and current transitive serving/class safety at commit and every delivery phase; no generated/native inputs, proc macros, incremental state, archive or harness outputs, local or request-owned completion, unresolved or adopted lineage; authenticated drained capture, exact diagnostics and dep-info, separate class samples and existing release and installation gates",
};

fn dag_contract(policy: CommittedDependencyPolicy) -> Option<&'static DagContract> {
    match policy {
        CommittedDependencyPolicy::ImmutableDagRlib => Some(&IMMUTABLE_DAG_RLIB),
        CommittedDependencyPolicy::ImmutableDagMetadata => Some(&IMMUTABLE_DAG_METADATA),
        CommittedDependencyPolicy::WorkspaceDagRlib => Some(&WORKSPACE_DAG_RLIB),
        CommittedDependencyPolicy::WorkspaceDagMetadata => Some(&WORKSPACE_DAG_METADATA),
        _ => None,
    }
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

/// Refine a fresh workspace plan into the separately keyed mixed-producer
/// class. The canonical driver must still retain the selected executor-free
/// graph and exact committed installation capability for every candidate.
///
/// # Errors
/// A nonfresh plan or an invocation outside ordinary closed library compilation.
pub fn plan_mixed_workspace_library(
    execution: &DependencyActionPlan,
) -> Result<DependencyActionPlan, LiveRefusal> {
    if execution.source_kind != DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "mixed workspace planning requires the original fresh workspace plan".into(),
        ));
    }
    let mut plan = execution.clone();
    plan.source_kind = match remote::remote_dependency_output_class(&plan.invocation)
        .map_err(|error| LiveRefusal::Facts(error.to_string()))?
    {
        RemoteDependencyOutputClass::Rlib => DependencySourceKind::WorkspaceMixedRlib,
        RemoteDependencyOutputClass::Metadata => DependencySourceKind::WorkspaceMixedMetadata,
    };
    validate_mixed_workspace_library_plan(&plan)?;
    Ok(plan)
}

/// Validate the pure mixed-producer invocation boundary and return its exact
/// output class. This does not qualify any producer or authorize publication.
///
/// # Errors
/// Wrong class, nonlibrary/codegen outputs, harness or generated/native inputs.
pub fn validate_mixed_workspace_library_plan(
    plan: &DependencyActionPlan,
) -> Result<RemoteDependencyOutputClass, LiveRefusal> {
    workspace_layout(plan)?;
    let output = match plan.source_kind {
        DependencySourceKind::WorkspaceMixedRlib => RemoteDependencyOutputClass::Rlib,
        DependencySourceKind::WorkspaceMixedMetadata => RemoteDependencyOutputClass::Metadata,
        _ => {
            return Err(LiveRefusal::Facts(
                "mixed workspace libraries require their distinct producer policy class".into(),
            ));
        }
    };
    if !matches!(plan.invocation.crate_types.as_slice(), [kind] if matches!(kind.as_str(), "lib" | "rlib"))
        || plan
            .invocation
            .passthrough
            .iter()
            .any(|argument| argument == "--test")
        || plan.generated_root.is_some()
        || !plan.native_roots.is_empty()
        || !plan.invocation.native_libs.is_empty()
        || remote::remote_dependency_output_class(&plan.invocation) != Ok(output)
    {
        return Err(LiveRefusal::Facts(
            "mixed workspace caching requires an ordinary closed Rust library without generated or native inputs".into(),
        ));
    }
    Ok(output)
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

/// Admit the complete mixed-producer namespace and exact ordered witnesses.
/// A candidate's actual producer class and immutable-leaf qualification remain
/// live coordinator obligations, never assertions supplied by these pure facts.
///
/// # Errors
/// Unsupported invocation, namespace, extern or incomplete candidate provenance.
pub fn remote_mixed_workspace_library_shape(
    plan: &DependencyActionPlan,
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    validate_mixed_workspace_library_plan(plan)?;
    remote::remote_execution_shape(plan, directories, toolchain_root)?;
    validate_committed_workspace_dependencies(directories, dependencies)?;
    let externs = remote::remote_extern_facts(plan, directories)?;
    artifacts_component(plan, &externs, directories)?;
    Ok(())
}

/// Validate the exact namespace and every ordered committed candidate under
/// the capability's explicit producer policy. These pure facts cannot mint a
/// physical installation witness or assert a producer's current standing.
///
/// # Errors
/// Unsupported source/mode, namespace, externs or incomplete provenance.
pub fn remote_committed_dependency_shape(
    plan: &DependencyActionPlan,
    policy: CommittedDependencyPolicy,
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    policy.validate_plan(plan)?;
    match policy {
        CommittedDependencyPolicy::WorkspaceRlib => {
            remote_committed_workspace_rlib_shape(plan, directories, dependencies, toolchain_root)
        }
        CommittedDependencyPolicy::WorkspaceMetadata => remote_committed_workspace_metadata_shape(
            plan,
            directories,
            dependencies,
            toolchain_root,
        ),
        CommittedDependencyPolicy::MixedWorkspaceRlib
        | CommittedDependencyPolicy::MixedWorkspaceMetadata
        | CommittedDependencyPolicy::WorkspaceDagRlib
        | CommittedDependencyPolicy::WorkspaceDagMetadata => {
            remote_mixed_workspace_library_shape(plan, directories, dependencies, toolchain_root)
        }
        CommittedDependencyPolicy::ImmutableDagRlib
        | CommittedDependencyPolicy::ImmutableDagMetadata => {
            remote::remote_dependency_shape(plan, directories, toolchain_root)?;
            validate_committed_workspace_dependencies(directories, dependencies)?;
            let externs = remote::remote_extern_facts(plan, directories)?;
            artifacts_component(plan, &externs, directories)?;
            Ok(())
        }
    }
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

fn mixed_isolation_policy(output: RemoteDependencyOutputClass) -> TypedDigest {
    let (domain, profile) = match output {
        RemoteDependencyOutputClass::Rlib => {
            (MIXED_RLIB_POLICY_DOMAIN, MIXED_RLIB_ISOLATION_PROFILE)
        }
        RemoteDependencyOutputClass::Metadata => (
            MIXED_METADATA_POLICY_DOMAIN,
            MIXED_METADATA_ISOLATION_PROFILE,
        ),
    };
    compute(domain, profile.as_bytes())
}

fn mixed_execution_semantics(output: RemoteDependencyOutputClass) -> TypedDigest {
    let (domain, semantics) = match output {
        RemoteDependencyOutputClass::Rlib => (MIXED_RLIB_SEMANTICS_DOMAIN, MIXED_RLIB_SEMANTICS),
        RemoteDependencyOutputClass::Metadata => {
            (MIXED_METADATA_SEMANTICS_DOMAIN, MIXED_METADATA_SEMANTICS)
        }
    };
    compute(domain, semantics.as_bytes())
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

/// Distinct mixed-producer policy, never the older workspace-only policy.
///
/// # Errors
/// The invocation is outside its mixed archive or closed metadata contract.
pub fn remote_mixed_workspace_library_isolation_policy(
    plan: &DependencyActionPlan,
) -> Result<TypedDigest, RemoteDependencyRefusal> {
    Ok(mixed_isolation_policy(
        validate_mixed_workspace_library_plan(plan)?,
    ))
}

/// Isolation identity selected by the retained producer capability, never by
/// mutable source kind alone. The four existing identities remain unchanged.
///
/// # Errors
/// Source origin or invocation mode does not match the exact policy.
pub fn remote_committed_dependency_isolation_policy(
    plan: &DependencyActionPlan,
    policy: CommittedDependencyPolicy,
) -> Result<TypedDigest, RemoteDependencyRefusal> {
    policy.validate_plan(plan)?;
    if let Some(contract) = dag_contract(policy) {
        return Ok(compute(
            contract.isolation_domain,
            contract.profile.as_bytes(),
        ));
    }
    match policy {
        CommittedDependencyPolicy::WorkspaceRlib => {
            remote_committed_workspace_rlib_isolation_policy(plan)
        }
        CommittedDependencyPolicy::WorkspaceMetadata => {
            remote_committed_workspace_metadata_isolation_policy(plan)
        }
        CommittedDependencyPolicy::MixedWorkspaceRlib
        | CommittedDependencyPolicy::MixedWorkspaceMetadata => {
            remote_mixed_workspace_library_isolation_policy(plan)
        }
        _ => unreachable!("DAG policies returned their distinct contract"),
    }
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

/// Classify only the exact mixed archive identity, never producer authority.
#[must_use]
pub fn is_mixed_workspace_rlib_descriptor(descriptor: &ActionDescriptor) -> bool {
    descriptor.action_class == ActionClass::RustcWorkspaceCompile
        && descriptor.key_epoch == MIXED_RLIB_KEY_EPOCH
        && descriptor.projection_epoch == PROJECTION_EPOCH
        && descriptor.sandbox_semantic_policy
            == mixed_isolation_policy(RemoteDependencyOutputClass::Rlib)
        && descriptor.execution_semantics
            == mixed_execution_semantics(RemoteDependencyOutputClass::Rlib)
}

/// Classify only the exact mixed metadata identity, never producer authority.
#[must_use]
pub fn is_mixed_workspace_metadata_descriptor(descriptor: &ActionDescriptor) -> bool {
    descriptor.action_class == ActionClass::RustcWorkspaceCompile
        && descriptor.key_epoch == MIXED_METADATA_KEY_EPOCH
        && descriptor.projection_epoch == PROJECTION_EPOCH
        && descriptor.sandbox_semantic_policy
            == mixed_isolation_policy(RemoteDependencyOutputClass::Metadata)
        && descriptor.execution_semantics
            == mixed_execution_semantics(RemoteDependencyOutputClass::Metadata)
}

/// Exact policy identity only, not proof of installation, retained inputs,
/// publication, current ancestry, or independent verification samples.
#[must_use]
pub fn committed_dependency_descriptor_policy(
    descriptor: &ActionDescriptor,
) -> Option<CommittedDependencyPolicy> {
    for (policy, matches) in [
        (
            CommittedDependencyPolicy::WorkspaceRlib,
            is_committed_workspace_rlib_descriptor(descriptor),
        ),
        (
            CommittedDependencyPolicy::WorkspaceMetadata,
            is_committed_workspace_metadata_descriptor(descriptor),
        ),
        (
            CommittedDependencyPolicy::MixedWorkspaceRlib,
            is_mixed_workspace_rlib_descriptor(descriptor),
        ),
        (
            CommittedDependencyPolicy::MixedWorkspaceMetadata,
            is_mixed_workspace_metadata_descriptor(descriptor),
        ),
    ] {
        if matches {
            return Some(policy);
        }
    }
    for policy in [
        CommittedDependencyPolicy::ImmutableDagRlib,
        CommittedDependencyPolicy::ImmutableDagMetadata,
        CommittedDependencyPolicy::WorkspaceDagRlib,
        CommittedDependencyPolicy::WorkspaceDagMetadata,
    ] {
        let contract = dag_contract(policy).expect("DAG policy has a contract");
        if descriptor.action_class == contract.class
            && descriptor.key_epoch == contract.epoch
            && descriptor.projection_epoch == PROJECTION_EPOCH
            && descriptor.dependency_inputs.domain == contract.dependencies_domain
            && descriptor.sandbox_semantic_policy
                == compute(contract.isolation_domain, contract.profile.as_bytes())
            && descriptor.execution_semantics
                == compute(contract.semantics_domain, contract.profile.as_bytes())
        {
            return Some(policy);
        }
    }
    None
}

/// Identify a claimed DAG namespace even when its exact descriptor is invalid.
/// Coordinators use this after exact classification to prevent an altered DAG
/// descriptor falling through to generic dependency-class authority.
#[must_use]
pub fn uses_committed_dependency_namespace(descriptor: &ActionDescriptor) -> bool {
    (10..=13).contains(&descriptor.key_epoch)
        || [
            &IMMUTABLE_DAG_RLIB,
            &IMMUTABLE_DAG_METADATA,
            &WORKSPACE_DAG_RLIB,
            &WORKSPACE_DAG_METADATA,
        ]
        .into_iter()
        .any(|contract| {
            descriptor.sandbox_semantic_policy.domain == contract.isolation_domain
                || descriptor.execution_semantics.domain == contract.semantics_domain
                || descriptor.dependency_inputs.domain == contract.dependencies_domain
        })
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
        false,
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
        false,
    )
}

/// Bind complete workspace inputs and every exact committed producer identity
/// under the separate mixed-producer contract. Live leaf qualification, current
/// lineage and physical generations remain mandatory outside this pure key.
///
/// # Errors
/// Incomplete evidence, unbound runtime, unsupported inputs or missing provenance.
#[allow(clippy::too_many_arguments)]
pub fn remote_mixed_workspace_library_key(
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
    let output = validate_mixed_workspace_library_plan(plan)?;
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
        output,
        true,
    )
}

/// Build the exact descriptor selected by an operation-owned committed-input
/// policy. New immutable DAG keys retain their immutable source origin and the
/// existing worker mode. New workspace DAG keys retain the complete workspace
/// closure and their separately negotiated archive/closed-metadata context.
/// Every retained candidate's exact bytes and producer identities are bound;
/// the four existing workspace key encodings remain byte-for-byte unchanged.
///
/// # Errors
/// Unsupported inputs, source/mode mismatch, incomplete provenance or runtime.
#[allow(clippy::too_many_arguments)]
pub fn remote_committed_dependency_key(
    plan: &DependencyActionPlan,
    policy: CommittedDependencyPolicy,
    toolchain: &ToolchainFacts,
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
    inputs: &ActionInputManifest,
    build_script_output: Option<&[u8]>,
    toolchain_root: &str,
    retained_toolchain_sha256: &[u8; 32],
    runtime: &TypedDigest,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    remote_committed_dependency_shape(plan, policy, directories, dependencies, toolchain_root)?;
    match policy {
        CommittedDependencyPolicy::WorkspaceRlib => {
            return remote_committed_workspace_rlib_key(
                plan,
                toolchain,
                directories,
                dependencies,
                inputs,
                build_script_output,
                toolchain_root,
                retained_toolchain_sha256,
                runtime,
            );
        }
        CommittedDependencyPolicy::WorkspaceMetadata => {
            return remote_committed_workspace_metadata_key(
                plan,
                toolchain,
                directories,
                dependencies,
                inputs,
                build_script_output,
                toolchain_root,
                retained_toolchain_sha256,
                runtime,
            );
        }
        CommittedDependencyPolicy::MixedWorkspaceRlib
        | CommittedDependencyPolicy::MixedWorkspaceMetadata => {
            return remote_mixed_workspace_library_key(
                plan,
                toolchain,
                directories,
                dependencies,
                inputs,
                build_script_output,
                toolchain_root,
                retained_toolchain_sha256,
                runtime,
            );
        }
        _ => {}
    }
    if build_script_output.is_some() {
        return Err(LiveRefusal::Facts(
            "committed dependency DAG cannot consume a build-script run record".into(),
        )
        .into());
    }
    let immutable = matches!(
        policy,
        CommittedDependencyPolicy::ImmutableDagRlib
            | CommittedDependencyPolicy::ImmutableDagMetadata
    );
    let mut key = if immutable {
        remote::remote_dependency_key(
            plan,
            toolchain,
            directories,
            inputs,
            None,
            toolchain_root,
            retained_toolchain_sha256,
            runtime,
        )?
    } else {
        remote_mixed_workspace_library_key(
            plan,
            toolchain,
            directories,
            dependencies,
            inputs,
            None,
            toolchain_root,
            retained_toolchain_sha256,
            runtime,
        )?
    };
    let contract = dag_contract(policy).expect("nonlegacy policy has a DAG contract");
    let mut provenance = CanonicalEncoder::new();
    encode_digest(&mut provenance, &key.descriptor.dependency_inputs);
    if immutable {
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
    }
    // Workspace base components already bind the same complete ordered
    // producer tuple; rebind that encoding without changing its source scope.
    key.descriptor.dependency_inputs = compute(contract.dependencies_domain, &provenance.finish());
    key.descriptor.key_epoch = contract.epoch;
    key.descriptor.projection_epoch = PROJECTION_EPOCH;
    key.descriptor.action_class = contract.class;
    key.descriptor.sandbox_semantic_policy =
        compute(contract.isolation_domain, contract.profile.as_bytes());
    key.descriptor.execution_semantics =
        compute(contract.semantics_domain, contract.profile.as_bytes());
    key.action_key = compute_action_key(&key.descriptor).final_key;
    key.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&key.descriptor));
    Ok(key)
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
    mixed: bool,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    match (mixed, output) {
        (true, _) => {
            remote_mixed_workspace_library_shape(plan, directories, dependencies, toolchain_root)?;
        }
        (false, RemoteDependencyOutputClass::Rlib) => {
            remote_committed_workspace_rlib_shape(plan, directories, dependencies, toolchain_root)?;
        }
        (false, RemoteDependencyOutputClass::Metadata) => {
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
        match (mixed, output) {
            (true, RemoteDependencyOutputClass::Rlib) => {
                "rabs.canonical-workspace-committed-mixed-rlib.dependencies.v1"
            }
            (true, RemoteDependencyOutputClass::Metadata) => {
                "rabs.canonical-workspace-committed-mixed-metadata.dependencies.v1"
            }
            (false, RemoteDependencyOutputClass::Rlib) => {
                "rabs.canonical-workspace-committed-rlib.dependencies.v1"
            }
            (false, RemoteDependencyOutputClass::Metadata) => {
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
        match (mixed, output) {
            (true, RemoteDependencyOutputClass::Rlib) => {
                "rabs.canonical-workspace-committed-mixed-rlib.environment.v1"
            }
            (true, RemoteDependencyOutputClass::Metadata) => {
                "rabs.canonical-workspace-committed-mixed-metadata.environment.v1"
            }
            (false, RemoteDependencyOutputClass::Rlib) => {
                "rabs.canonical-workspace-committed-rlib.environment.v1"
            }
            (false, RemoteDependencyOutputClass::Metadata) => {
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
        match (mixed, output) {
            (true, RemoteDependencyOutputClass::Rlib) => {
                "rabs.canonical-workspace-committed-mixed-rlib.invocation.v1"
            }
            (true, RemoteDependencyOutputClass::Metadata) => {
                "rabs.canonical-workspace-committed-mixed-metadata.invocation.v1"
            }
            (false, RemoteDependencyOutputClass::Rlib) => {
                "rabs.canonical-workspace-committed-rlib.invocation.v1"
            }
            (false, RemoteDependencyOutputClass::Metadata) => {
                "rabs.canonical-workspace-committed-metadata.invocation.v1"
            }
        },
        &invocation.finish(),
    );
    key.descriptor.key_epoch = match (mixed, output) {
        (false, RemoteDependencyOutputClass::Rlib) => KEY_EPOCH,
        (false, RemoteDependencyOutputClass::Metadata) => METADATA_KEY_EPOCH,
        (true, RemoteDependencyOutputClass::Rlib) => MIXED_RLIB_KEY_EPOCH,
        (true, RemoteDependencyOutputClass::Metadata) => MIXED_METADATA_KEY_EPOCH,
    };
    key.descriptor.projection_epoch = PROJECTION_EPOCH;
    key.descriptor.action_class = ActionClass::RustcWorkspaceCompile;
    key.descriptor.sandbox_semantic_policy = match (mixed, output) {
        (true, output) => mixed_isolation_policy(output),
        (false, RemoteDependencyOutputClass::Rlib) => isolation_policy(),
        (false, RemoteDependencyOutputClass::Metadata) => metadata_isolation_policy(),
    };
    key.descriptor.execution_semantics = match (mixed, output) {
        (true, output) => mixed_execution_semantics(output),
        (false, RemoteDependencyOutputClass::Rlib) => execution_semantics(),
        (false, RemoteDependencyOutputClass::Metadata) => metadata_execution_semantics(),
    };
    key.action_key = compute_action_key(&key.descriptor).final_key;
    key.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&key.descriptor));
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_dependency::{
        ExternFact, LiveRustcRequest, plan_canonical_remote_dependency_action,
        plan_canonical_workspace_execution, remote_workspace_execution_key,
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

    fn mixed_key(
        plan: &DependencyActionPlan,
        dependencies: &[CommittedWorkspaceDependency],
        inputs: &ActionInputManifest,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_mixed_workspace_library_key(
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

    fn policy_key(
        plan: &DependencyActionPlan,
        policy: CommittedDependencyPolicy,
        dependencies: &[CommittedWorkspaceDependency],
        inputs: &ActionInputManifest,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_committed_dependency_key(
            plan,
            policy,
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

    fn immutable_plan(package: &str, metadata: bool) -> DependencyActionPlan {
        let argv = [
            "/__rabs/toolchain/bin/rustc".into(),
            "--crate-name=consumer".into(),
            "--crate-type=lib".into(),
            "--edition=2021".into(),
            format!("{package}/src/lib.rs"),
            "--error-format=json".into(),
            "--json=artifacts".into(),
            if metadata {
                "--emit=dep-info,metadata"
            } else {
                "--emit=dep-info,metadata,link"
            }
            .into(),
            "--cap-lints=allow".into(),
            format!("--out-dir={OUTPUT}"),
            "-L".into(),
            format!("dependency={OUTPUT}"),
            format!("--extern=upstream={OUTPUT}/libupstream.rmeta"),
        ];
        let env = [
            ("HOME".into(), "/__rabs/home".into()),
            ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
            ("CARGO_MANIFEST_DIR".into(), package.into()),
            ("CARGO_PKG_NAME".into(), "consumer".into()),
            ("CARGO_INCREMENTAL".into(), "0".into()),
        ];
        let checksum = package
            .starts_with("/__rabs/workspace/vendor/")
            .then(|| digest(b"checked directory package manifest"));
        plan_canonical_remote_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                env: &env,
                cwd: package,
            },
            HOST,
            checksum,
        )
        .unwrap()
    }

    fn immutable_inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let crate::invocation::SourceInput::Path(source) = plan.invocation.source.as_ref().unwrap()
        else {
            panic!("fixture source must be a real path");
        };
        let source = source
            .strip_prefix(&format!("{}/", plan.source_root))
            .unwrap();
        let mut files = vec![
            ("Cargo.toml", digest(b"manifest")),
            (source, digest(b"crate source")),
        ];
        if let Some(checksum) = &plan.directory_source_manifest {
            files.push((".cargo-checksum.json", checksum.clone()));
        }
        ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: files
                .into_iter()
                .map(|(path, digest)| PositiveInput {
                    virtual_path: RawBytes::new(plan.input_virtual_path(path).into_bytes()),
                    object: ObjectId(digest),
                    file_type: InputFileType::Regular,
                    executable: false,
                    symlink_resolution: Vec::new(),
                })
                .collect(),
            ..ActionInputManifest::default()
        }
    }

    #[test]
    fn typed_committed_policy_preserves_all_four_published_workspace_identities() {
        let dependencies = vec![candidate("libupstream.rmeta")];
        for metadata in [false, true] {
            let fresh = execution_with_output(false, "one", metadata);
            let workspace = if metadata {
                plan_committed_workspace_metadata(&fresh).unwrap()
            } else {
                plan_committed_workspace_rlib(&fresh).unwrap()
            };
            let mixed = plan_mixed_workspace_library(&fresh).unwrap();
            for plan in [workspace, mixed] {
                let policy = CommittedDependencyPolicy::from_source_kind(plan.source_kind).unwrap();
                let captured = inputs(&plan);
                let original = match policy {
                    CommittedDependencyPolicy::WorkspaceRlib => {
                        key(&plan, &dependencies, &captured)
                    }
                    CommittedDependencyPolicy::WorkspaceMetadata => {
                        metadata_key(&plan, &dependencies, &captured)
                    }
                    _ => mixed_key(&plan, &dependencies, &captured),
                }
                .unwrap();
                let typed = policy_key(&plan, policy, &dependencies, &captured).unwrap();
                assert_eq!(typed, original);
                assert_eq!(
                    committed_dependency_descriptor_policy(&typed.descriptor),
                    Some(policy)
                );
                assert!(!uses_committed_dependency_namespace(&typed.descriptor));
            }
        }
        assert_eq!(
            CommittedDependencyPolicy::from_source_kind(DependencySourceKind::RegistryPackage),
            None
        );
    }

    #[test]
    fn immutable_dag_keys_keep_all_canonical_origins_and_separate_each_output_policy() {
        let dependencies = vec![candidate("libupstream.rmeta")];
        for (package, kind) in [
            (
                "/__rabs/cargo-home/registry/src/index/consumer-1.0.0",
                DependencySourceKind::RegistryPackage,
            ),
            (
                "/__rabs/cargo-home/git/checkouts/fixture-cafe1234/0123456789ab/crates/member",
                DependencySourceKind::GitCheckout,
            ),
            (
                "/__rabs/workspace/vendor/consumer-1.0.0",
                DependencySourceKind::DirectoryPackage,
            ),
        ] {
            for metadata in [false, true] {
                let plan = immutable_plan(package, metadata);
                assert_eq!(plan.source_kind, kind);
                let policy = if metadata {
                    CommittedDependencyPolicy::ImmutableDagMetadata
                } else {
                    CommittedDependencyPolicy::ImmutableDagRlib
                };
                let captured = immutable_inputs(&plan);
                let dag = policy_key(&plan, policy, &dependencies, &captured).unwrap();
                assert_eq!(dag.descriptor.key_epoch, if metadata { 11 } else { 10 });
                assert_eq!(
                    dag.descriptor.action_class,
                    ActionClass::RustcDependencyCompile
                );
                assert_eq!(
                    committed_dependency_descriptor_policy(&dag.descriptor),
                    Some(policy)
                );
                let ordinary = remote::remote_dependency_key(
                    &plan,
                    &toolchain(),
                    &directories(&dependencies),
                    &captured,
                    None,
                    TOOLCHAIN,
                    &[39; 32],
                    &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
                )
                .unwrap();
                assert_ne!(dag.action_key, ordinary.action_key);
                assert_eq!(
                    committed_dependency_descriptor_policy(&ordinary.descriptor),
                    None
                );
                assert!(
                    policy_key(
                        &plan,
                        if metadata {
                            CommittedDependencyPolicy::ImmutableDagRlib
                        } else {
                            CommittedDependencyPolicy::ImmutableDagMetadata
                        },
                        &dependencies,
                        &captured
                    )
                    .is_err()
                );
                assert!(
                    policy_key(
                        &plan,
                        CommittedDependencyPolicy::WorkspaceDagMetadata,
                        &dependencies,
                        &captured
                    )
                    .is_err()
                );
                let mut changed = captured.clone();
                changed.inputs[1].object = ObjectId(digest(b"changed immutable source"));
                assert_ne!(
                    dag.action_key,
                    policy_key(&plan, policy, &dependencies, &changed)
                        .unwrap()
                        .action_key
                );
            }
        }
    }

    #[test]
    fn dag_policies_bind_every_candidate_byte_and_exact_committed_producer() {
        let immutable = immutable_plan(
            "/__rabs/cargo-home/registry/src/index/consumer-1.0.0",
            false,
        );
        let workspace = plan_mixed_workspace_library(&execution(false)).unwrap();
        let dependencies = vec![
            candidate("libupstream.rmeta"),
            candidate("libzztransitive.rlib"),
        ];
        for (plan, policy, captured) in [
            (
                &immutable,
                CommittedDependencyPolicy::ImmutableDagRlib,
                immutable_inputs(&immutable),
            ),
            (
                &workspace,
                CommittedDependencyPolicy::WorkspaceDagRlib,
                inputs(&workspace),
            ),
        ] {
            let original = policy_key(plan, policy, &dependencies, &captured).unwrap();
            for field in 0..4 {
                let mut changed = dependencies.clone();
                let dependency = &mut changed[1];
                match field {
                    0 => dependency.producer_action = digest(b"different producer action"),
                    1 => dependency.producer_descriptor = digest(b"different producer descriptor"),
                    2 => dependency.producer_manifest = digest(b"different producer manifest"),
                    _ => {
                        dependency.object = ObjectId(digest(b"different entire transitive archive"))
                    }
                }
                assert_ne!(
                    original.action_key,
                    policy_key(plan, policy, &changed, &captured)
                        .unwrap()
                        .action_key
                );
            }
            for evidence in [
                Vec::new(),
                dependencies[..1].to_vec(),
                dependencies.iter().rev().cloned().collect(),
            ] {
                assert!(
                    remote_committed_dependency_shape(
                        plan,
                        policy,
                        &directories(&dependencies),
                        &evidence,
                        TOOLCHAIN
                    )
                    .is_err()
                );
            }
            let mut wrong = dependencies.clone();
            wrong[1].role = OutputRole::ProvisionalMetadata;
            assert!(policy_key(plan, policy, &wrong, &captured).is_err());
            let mut proc_macro = dependencies.clone();
            proc_macro.push(candidate("libhidden_proc_macro.so"));
            assert!(policy_key(plan, policy, &proc_macro, &captured).is_err());
        }
    }

    #[test]
    fn workspace_dag_keeps_full_source_topology_and_legacy_scope_separate() {
        let dependencies = vec![candidate("libupstream.rmeta")];
        for metadata in [false, true] {
            let plan = plan_mixed_workspace_library(&execution_with_output(false, "one", metadata))
                .unwrap();
            let policy = if metadata {
                CommittedDependencyPolicy::WorkspaceDagMetadata
            } else {
                CommittedDependencyPolicy::WorkspaceDagRlib
            };
            let captured = inputs(&plan);
            let dag = policy_key(&plan, policy, &dependencies, &captured).unwrap();
            assert_eq!(dag.descriptor.key_epoch, if metadata { 13 } else { 12 });
            assert_eq!(
                committed_dependency_descriptor_policy(&dag.descriptor),
                Some(policy)
            );
            assert_ne!(
                dag.action_key,
                mixed_key(&plan, &dependencies, &captured)
                    .unwrap()
                    .action_key
            );
            let mut sibling = captured.clone();
            sibling.inputs[3].object = ObjectId(digest(b"changed complete workspace sibling"));
            assert_ne!(
                dag.action_key,
                policy_key(&plan, policy, &dependencies, &sibling)
                    .unwrap()
                    .action_key
            );
            let mut topology = captured.clone();
            topology.directory_enumerations[0]
                .entries
                .push(RawBytes::from("new-empty"));
            topology.directory_enumerations[0].entries.sort();
            topology.directory_enumerations.push(DirectoryEnumeration {
                virtual_path: RawBytes::new(plan.input_virtual_path("new-empty").into_bytes()),
                entries: Vec::new(),
            });
            assert_ne!(
                dag.action_key,
                policy_key(&plan, policy, &dependencies, &topology)
                    .unwrap()
                    .action_key
            );
            let changed_env =
                plan_mixed_workspace_library(&execution_with_output(false, "two", metadata))
                    .unwrap();
            assert_ne!(
                dag.action_key,
                policy_key(&changed_env, policy, &dependencies, &captured)
                    .unwrap()
                    .action_key
            );
            assert!(
                policy_key(
                    &plan,
                    CommittedDependencyPolicy::ImmutableDagRlib,
                    &dependencies,
                    &captured
                )
                .is_err()
            );
        }
    }

    #[test]
    fn dag_namespace_claims_fail_closed_and_purity_cannot_be_inferred_from_bytes() {
        let plan = immutable_plan(
            "/__rabs/cargo-home/registry/src/index/consumer-1.0.0",
            false,
        );
        let policy = CommittedDependencyPolicy::ImmutableDagRlib;
        let dependencies = vec![candidate("libupstream.rmeta")];
        let captured = immutable_inputs(&plan);
        let key = policy_key(&plan, policy, &dependencies, &captured).unwrap();
        for field in 0..6 {
            let mut descriptor = key.descriptor.clone();
            match field {
                0 => descriptor.key_epoch = 1,
                1 => descriptor.projection_epoch = 2,
                2 => descriptor.action_class = ActionClass::RustcWorkspaceCompile,
                3 => descriptor.sandbox_semantic_policy = digest(b"wrong policy"),
                4 => descriptor.execution_semantics = digest(b"wrong semantics"),
                _ => descriptor.dependency_inputs = digest(b"unbound dependencies"),
            }
            assert_eq!(committed_dependency_descriptor_policy(&descriptor), None);
            assert!(uses_committed_dependency_namespace(&descriptor));
        }
        let mut generated = plan.clone();
        generated.generated_root = Some("/__rabs/out/cargo/debug/build/consumer/out".into());
        assert!(policy_key(&generated, policy, &dependencies, &captured).is_err());
        let mut native = plan.clone();
        native.native_roots.push("/__rabs/workspace/native".into());
        assert!(policy_key(&native, policy, &dependencies, &captured).is_err());
        let mut unchecked = plan.clone();
        unchecked.source_kind = DependencySourceKind::DirectoryPackage;
        assert!(policy_key(&unchecked, policy, &dependencies, &captured).is_err());
        assert!(
            remote_committed_dependency_key(
                &plan,
                policy,
                &toolchain(),
                &directories(&dependencies),
                &dependencies,
                &captured,
                Some(b"build-script run"),
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime")
            )
            .is_err()
        );
        assert!(policy_key(&plan, policy, &[], &captured).is_err());
    }

    #[test]
    fn mixed_workspace_profiles_cannot_borrow_prior_workspace_or_other_output_authority() {
        let dependencies = vec![candidate("libupstream.rmeta")];
        for metadata in [false, true] {
            let fresh = execution_with_output(false, "one", metadata);
            let mixed = plan_mixed_workspace_library(&fresh).unwrap();
            let prior = if metadata {
                plan_committed_workspace_metadata(&fresh).unwrap()
            } else {
                plan_committed_workspace_rlib(&fresh).unwrap()
            };
            let input = inputs(&mixed);
            let actual = mixed_key(&mixed, &dependencies, &input).unwrap();
            let previous = if metadata {
                metadata_key(&prior, &dependencies, &input).unwrap()
            } else {
                key(&prior, &dependencies, &input).unwrap()
            };
            assert_eq!(actual.descriptor.key_epoch, if metadata { 9 } else { 8 });
            assert_eq!(previous.descriptor.key_epoch, if metadata { 7 } else { 6 });
            assert_ne!(actual.action_key, previous.action_key);
            assert_ne!(
                actual.descriptor.dependency_inputs,
                previous.descriptor.dependency_inputs
            );
            assert_ne!(
                actual.descriptor.environment,
                previous.descriptor.environment
            );
            assert_ne!(
                actual.descriptor.normalized_invocation,
                previous.descriptor.normalized_invocation
            );
            assert_eq!(
                is_mixed_workspace_metadata_descriptor(&actual.descriptor),
                metadata
            );
            assert_eq!(
                is_mixed_workspace_rlib_descriptor(&actual.descriptor),
                !metadata
            );
            assert!(!is_committed_workspace_rlib_descriptor(&actual.descriptor));
            assert!(!is_committed_workspace_metadata_descriptor(
                &actual.descriptor
            ));
            assert!(!is_mixed_workspace_rlib_descriptor(&previous.descriptor));
            assert!(!is_mixed_workspace_metadata_descriptor(
                &previous.descriptor
            ));
            assert_eq!(
                remote_mixed_workspace_library_isolation_policy(&mixed).unwrap(),
                actual.descriptor.sandbox_semantic_policy
            );
            assert!(key(&mixed, &dependencies, &input).is_err());
            assert!(metadata_key(&mixed, &dependencies, &input).is_err());
            for other in [&fresh, &prior] {
                assert!(validate_mixed_workspace_library_plan(other).is_err());
                assert!(mixed_key(other, &dependencies, &input).is_err());
            }
            assert!(plan_mixed_workspace_library(&mixed).is_err());
            for field in 0..4 {
                let mut forged = actual.descriptor.clone();
                match field {
                    0 => forged.key_epoch = previous.descriptor.key_epoch,
                    1 => forged.projection_epoch += 1,
                    2 => {
                        forged.sandbox_semantic_policy =
                            previous.descriptor.sandbox_semantic_policy.clone()
                    }
                    _ => {
                        forged.execution_semantics = previous.descriptor.execution_semantics.clone()
                    }
                }
                assert!(!is_mixed_workspace_rlib_descriptor(&forged));
                assert!(!is_mixed_workspace_metadata_descriptor(&forged));
            }
        }
    }

    #[test]
    fn mixed_workspace_keys_every_candidate_whole_archive_and_exact_producer_identity() {
        let dependencies = vec![
            candidate("libupstream.rlib"),
            candidate("libupstream.rmeta"),
        ];
        for metadata in [false, true] {
            let plan = plan_mixed_workspace_library(&execution_with_output(true, "one", metadata))
                .unwrap();
            let input = inputs(&plan);
            let original = mixed_key(&plan, &dependencies, &input).unwrap();
            for field in 0..4 {
                let mut changed = dependencies.clone();
                match field {
                    0 => changed[0].producer_action = digest(b"another committed producer"),
                    1 => changed[0].producer_descriptor = digest(b"another producer descriptor"),
                    2 => changed[0].producer_manifest = digest(b"another producer publication"),
                    _ => {
                        changed[0].object =
                            ObjectId(digest(b"same metadata, different archive code"))
                    }
                }
                assert_ne!(
                    mixed_key(&plan, &changed, &input).unwrap().action_key,
                    original.action_key
                );
            }
            let retained = directories(&dependencies);
            for changed in [
                Vec::new(),
                dependencies[1..].to_vec(),
                vec![dependencies[1].clone(), dependencies[0].clone()],
            ] {
                assert!(
                    remote_mixed_workspace_library_shape(&plan, &retained, &changed, TOOLCHAIN)
                        .is_err()
                );
            }
            let mut wrong_role = dependencies.clone();
            wrong_role[1].role = OutputRole::Materializable;
            assert!(mixed_key(&plan, &wrong_role, &input).is_err());
            let mut unknown = dependencies.clone();
            unknown.push(candidate("proc_macro.so"));
            assert!(mixed_key(&plan, &unknown, &input).is_err());
            assert!(mixed_key(&plan, &dependencies[1..], &input).is_err());
        }
    }

    #[test]
    fn mixed_workspace_retains_complete_inputs_and_rejects_generated_native_and_harnesses() {
        let dependencies = vec![candidate("libupstream.rmeta")];
        for metadata in [false, true] {
            let plan = plan_mixed_workspace_library(&execution_with_output(false, "one", metadata))
                .unwrap();
            let input = inputs(&plan);
            let original = mixed_key(&plan, &dependencies, &input).unwrap().action_key;
            let mut changed = input.clone();
            changed.inputs.last_mut().unwrap().object = ObjectId(digest(b"changed sibling"));
            assert_ne!(
                mixed_key(&plan, &dependencies, &changed)
                    .unwrap()
                    .action_key,
                original
            );
            let mut missing = input.clone();
            missing.directory_enumerations.pop();
            assert!(mixed_key(&plan, &dependencies, &missing).is_err());
            let mut topology = input.clone();
            topology.directory_enumerations[0]
                .entries
                .push(RawBytes::from("z_empty"));
            topology.directory_enumerations.push(DirectoryEnumeration {
                virtual_path: RawBytes::new(plan.input_virtual_path("z_empty").into_bytes()),
                entries: Vec::new(),
            });
            assert_ne!(
                mixed_key(&plan, &dependencies, &topology)
                    .unwrap()
                    .action_key,
                original
            );
            let environment =
                plan_mixed_workspace_library(&execution_with_output(false, "two", metadata))
                    .unwrap();
            assert_ne!(
                mixed_key(&environment, &dependencies, &input)
                    .unwrap()
                    .action_key,
                original
            );
            for field in 0..5 {
                let mut unsupported = plan.clone();
                match field {
                    0 => {
                        unsupported.generated_root =
                            Some("/__rabs/out/cargo/debug/build/generated/out".into())
                    }
                    1 => unsupported
                        .native_roots
                        .push("/__rabs/out/cargo/debug/build/native/out".into()),
                    2 => unsupported
                        .invocation
                        .native_libs
                        .push("static=native".into()),
                    3 => unsupported.invocation.passthrough.push("--test".into()),
                    _ => unsupported.invocation.codegen.push((
                        "incremental".into(),
                        Some("/__rabs/out/cargo/incremental".into()),
                    )),
                }
                assert!(
                    mixed_key(&unsupported, &dependencies, &input).is_err(),
                    "field={field}"
                );
            }
            assert!(
                remote_mixed_workspace_library_key(
                    &plan,
                    &toolchain(),
                    &directories(&dependencies),
                    &dependencies,
                    &input,
                    Some(b"cargo:rustc-env=UNDECLARED=value"),
                    TOOLCHAIN,
                    &[39; 32],
                    &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
                )
                .is_err()
            );
            assert!(
                remote_mixed_workspace_library_key(
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
