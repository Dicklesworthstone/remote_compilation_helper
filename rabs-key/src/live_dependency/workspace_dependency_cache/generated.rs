//! Complete generated workspace inputs with exact committed Rust producers.
//!
//! These are additive DAG contracts, not extensions of the generated leaf or
//! pure workspace classes. The compiler sees both the complete own OUT_DIR and
//! every retained Rust candidate. Each loadable candidate requires an exact
//! committed producer witness; the build script itself receives no cache
//! authority. Live generation, lineage and worker-context checks remain with
//! the coordinator and are not supplied by these pure key facts.
//! Explicit bundled static libraries in the complete own OUT_DIR have
//! separate archive and closed metadata classes. Propagated native searches
//! have separate metadata and archive DAG classes retaining every foreign
//! OUT_DIR and its completed Cargo record, with an optional complete own
//! generated tree. Archives require archive-capable committed producers and
//! the existing output-archive native closure checks.
//! Dynamic native requests retain fresh execution without these authorities.

use super::{
    CommittedDependencyPolicy, CommittedWorkspaceDependency, DagContract, PROJECTION_EPOCH,
    encode_digest, validate_committed_workspace_dependencies,
};
use crate::action_key::compute_action_key;
use crate::canonical::CanonicalEncoder;
use crate::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use crate::live_dependency::remote::{self, RemoteDependencyOutputClass, RemoteDependencyRefusal};
use crate::live_dependency::workspace_cache::validate_native_generated_inputs;
use crate::live_dependency::workspace_execution::workspace_layout;
use crate::live_dependency::{
    DependencyActionPlan, DependencyDirectoryFact, DependencySourceKind, LiveDependencyKey,
    LiveRefusal, ToolchainFacts, artifacts_component, captured_action_key,
};
use crate::typed_digest::compute;
use rabs_protocol::descriptor::ActionClass;
use rabs_protocol::input_evidence::ActionInputManifest;
use rabs_protocol::result_identity::{OutputRole, TypedDigest};

pub(in crate::live_dependency) const GENERATED_DAG_RLIB_ISOLATION_PROFILE: &str = "canonical-workspace-generated-dag-rlib-v1: \
    driver-retained Cargo-selected ordinary library build; other units may \
    execute project code without granting local completion authority; independently \
    isolated compiler in the existing canonical-workspace-exec-v3 Rlib namespace \
    without procfs or entropy devices; complete sealed workspace and disjoint own \
    OUT_DIR, every regular file and immediate directory listing including empty \
    directories; exact logical generated root, completed Cargo build-script stdout \
    record and fully keyed presented environment, matching rustc-env directives; \
    build-script execution is not cached; exact argv, cwd, manifest directory and \
    output placement, complete retained toolchain and measured ELF runtime; every \
    ordered loadable Rust candidate has an operation-owned installed generation \
    and exact committed producer action, descriptor, manifest, role and whole \
    object identity; whole explicit rlib bytes and existing metadata-shadow \
    projection, exact empty search metadata without producer authority; explicit \
    empty externs refuse; closed, generated, mixed and DAG workspace archive \
    producers plus qualified immutable archive leaves and committed immutable \
    archive DAGs; each intermediate retains its own producer policy; complete \
    nonempty H028 ancestry and current transitive serving, class, quarantine and \
    native archive closure at commit and every delivery phase; original source, \
    generated tree, Cargo record and dependency generations revalidated; no \
    native search roots or library directives, metadata-only producer authority, \
    proc macros, incremental state, final links, local or request-owned producer \
    authority, provisional or adopted lineage; authenticated drained capture, \
    dep-info and tracked-control read veto, exact diagnostics, separate generated \
    DAG class samples and existing release and private installation gates";

pub(in crate::live_dependency) const GENERATED_DAG_METADATA_ISOLATION_PROFILE: &str = "canonical-workspace-generated-dag-metadata-v1: \
    driver-retained Cargo-selected ordinary library check; other units may \
    execute project code without granting local completion authority; independently \
    isolated compiler in explicitly negotiated canonical-workspace-closed-metadata-v1 \
    ClosedMetadata mode, never ordinary Metadata or Rlib authority, without procfs \
    or entropy devices; complete sealed workspace and disjoint own OUT_DIR, every \
    regular file and immediate directory listing including empty directories; \
    exact logical generated root, completed Cargo build-script stdout record and \
    fully keyed presented environment, matching rustc-env directives; build-script \
    execution is not cached; exact argv, cwd, manifest directory and output \
    placement, complete retained toolchain and measured ELF runtime; every \
    ordered loadable Rust candidate has an operation-owned installed generation \
    and exact committed producer action, descriptor, manifest, role and whole \
    object identity; whole explicit rlib bytes and existing metadata-shadow \
    projection, exact empty search metadata without producer authority; explicit \
    empty externs refuse; closed, generated, mixed and DAG workspace producers \
    plus qualified immutable leaves and committed immutable DAGs; metadata \
    producers authorize only ProvisionalMetadata rmeta, archive producers may \
    authorize rmeta or whole Materializable rlib; each intermediate retains its \
    own producer policy; complete nonempty H028 ancestry and current transitive \
    serving, class, quarantine and native archive closure at commit and every \
    delivery phase; original source, generated tree, Cargo record and dependency \
    generations revalidated; no native search roots or library directives, proc \
    macros, incremental state, archive or harness outputs, final links, local or \
    request-owned producer authority, provisional or adopted lineage; authenticated \
    drained capture, dep-info and tracked-control read veto, exact diagnostics, \
    separate generated DAG metadata samples and existing release and private \
    installation gates";

pub(in crate::live_dependency) const NATIVE_GENERATED_DAG_RLIB_ISOLATION_PROFILE: &str = "canonical-workspace-native-generated-dag-rlib-v1: \
    driver-retained selected ordinary library; complete immutable workspace and \
    disjoint own OUT_DIR files and directory membership; exact completed Cargo \
    stdout and matching fully keyed environment; build script executes normally \
    and grants no compiler authority; independently negotiated closed Rlib \
    canonical-workspace-exec-v3 namespace without procfs or entropy devices; \
    static native searches confined to the own OUT_DIR, every selected directory \
    and named bundled archive retained and validated; exact supported bundle, \
    whole-archive and verbatim modifiers and native search ordering; no foreign \
    generated roots, dynamic/framework/system searches or external linker; every \
    loadable Rust candidate bound to its operation-owned installed generation, \
    exact committed producer action, descriptor, manifest, role and whole object; \
    complete nonempty H028 ancestry with transitive current publication and \
    serving safety checked at every delivery phase; exact empty metadata remains \
    keyed without producer authority; no metadata-only archive producers; \
    original source, generated tree, Cargo record and dependency generations \
    revalidated; complete output rlib native closure including source link \
    attributes, thin archives and linker scripts; authenticated drained receipt, \
    dep-info and tracked-control veto; separate native-generated DAG samples, \
    class quarantine and private installation gates; no local completion, \
    provisional, adopted or request-owned producer authority";

pub(in crate::live_dependency) const NATIVE_GENERATED_DAG_METADATA_ISOLATION_PROFILE: &str = "canonical-workspace-native-generated-dag-metadata-v1: \
    driver-retained selected ordinary library check; complete immutable workspace \
    and disjoint own OUT_DIR files and every directory listing; exact completed \
    Cargo stdout and matching fully keyed environment; build script executes \
    normally and grants no compiler authority; independently negotiated \
    canonical-workspace-closed-metadata-v1 ClosedMetadata namespace without procfs \
    or entropy devices, never ordinary Metadata or Rlib authority; static native \
    searches confined to the own OUT_DIR, every selected directory and named \
    bundled archive retained and validated; exact supported bundle, whole-archive \
    and verbatim modifiers and native search ordering; no foreign generated roots, \
    dynamic/framework/system searches or external linker; every loadable Rust \
    candidate bound to its operation-owned installed generation, exact committed \
    producer action, descriptor, manifest, role and whole object; metadata producers \
    authorize only ProvisionalMetadata rmeta, archive producers may authorize rmeta \
    or whole Materializable rlib; each intermediate retains its producer policy; \
    complete nonempty H028 ancestry with transitive current publication, serving \
    and native archive safety checked at every delivery phase; exact empty metadata \
    remains keyed without producer authority; exact argv, cwd, manifest, output \
    placement, toolchain and measured ELF runtime; original source, generated tree, \
    Cargo record and dependency generations revalidated; metadata, dep-info and \
    diagnostic output only, no archive, binary, harness or terminal producer \
    authority; authenticated drained receipt, dep-info and tracked-control veto; \
    separate native-generated DAG metadata samples, class quarantine and private \
    installation gates; no local completion, provisional publication, adopted or \
    request-owned producer authority";

pub(super) const NATIVE_RLIB: DagContract = DagContract {
    epoch: 31,
    class: ActionClass::RustcWorkspaceCompile,
    isolation_domain: "rabs.canonical-workspace-native-generated-dag-rlib.isolation.v1",
    semantics_domain: "rabs.canonical-workspace-native-generated-dag-rlib.semantics.v1",
    dependencies_domain: "rabs.canonical-workspace-native-generated-dag-rlib.dependencies.v1",
    profile: NATIVE_GENERATED_DAG_RLIB_ISOLATION_PROFILE,
};

pub(super) const NATIVE_METADATA: DagContract = DagContract {
    epoch: 33,
    class: ActionClass::RustcWorkspaceCompile,
    isolation_domain: "rabs.canonical-workspace-native-generated-dag-metadata.isolation.v1",
    semantics_domain: "rabs.canonical-workspace-native-generated-dag-metadata.semantics.v1",
    dependencies_domain: "rabs.canonical-workspace-native-generated-dag-metadata.dependencies.v1",
    profile: NATIVE_GENERATED_DAG_METADATA_ISOLATION_PROFILE,
};

pub(in crate::live_dependency) const PROPAGATED_NATIVE_DAG_METADATA_ISOLATION_PROFILE: &str = "canonical-workspace-propagated-native-dag-metadata-v1: \
    driver-retained Cargo-selected ordinary library check; independently \
    negotiated canonical-workspace-closed-metadata-v1 ClosedMetadata namespace \
    without procfs or entropy devices, never ordinary Metadata or Rlib authority; \
    complete immutable workspace and every regular file and directory listing; \
    every foreign Cargo OUT_DIR selected by propagated native searches \
    independently bound to its completed root-output/stdout record and complete \
    immutable tree, including empty directories; exact logical roots, native \
    search order and supported static bundle, whole-archive and verbatim flags; \
    optional own OUT_DIR retains its complete tree and exact completed Cargo \
    stdout with matching fully keyed environment; build-script execution is not \
    cached and supplies no compiler authority; no arbitrary host, dynamic or \
    framework search, external linker, archive, binary or harness output; exact \
    argv, cwd, manifest, output placement, complete retained toolchain and \
    measured ELF runtime; every loadable Rust candidate has an operation-owned \
    installed generation and exact committed producer action, descriptor, \
    manifest, role and whole object identity; whole explicit archives and \
    existing metadata-shadow projection, exact empty search metadata remains \
    keyed without producer authority; explicit empty externs refuse; complete \
    nonempty H028 ancestry with current transitive serving, class, quarantine \
    and native archive closure rechecked at commit and every delivery phase; \
    metadata producers authorize only ProvisionalMetadata rmeta, archive \
    producers may authorize rmeta or whole Materializable rlib; each \
    intermediate retains its own producer policy; original source, generated \
    and native trees, all Cargo records and dependency generations revalidated; \
    authenticated completed drained receipt, dep-info and tracked-control read \
    veto, exact metadata and diagnostic transcript; separate propagated-native \
    metadata samples, class quarantine and private installation gates; no \
    proc macros, incremental state, local completion, provisional publication, \
    adopted or request-owned producer authority";

pub(super) const PROPAGATED_NATIVE_METADATA: DagContract = DagContract {
    epoch: 36,
    class: ActionClass::RustcWorkspaceCompile,
    isolation_domain: "rabs.canonical-workspace-propagated-native-dag-metadata.isolation.v1",
    semantics_domain: "rabs.canonical-workspace-propagated-native-dag-metadata.semantics.v1",
    dependencies_domain: "rabs.canonical-workspace-propagated-native-dag-metadata.dependencies.v1",
    profile: PROPAGATED_NATIVE_DAG_METADATA_ISOLATION_PROFILE,
};

pub(in crate::live_dependency) const PROPAGATED_NATIVE_DAG_RLIB_ISOLATION_PROFILE: &str = "canonical-workspace-propagated-native-dag-rlib-v1: \
    driver-retained Cargo-selected ordinary library build; independently \
    negotiated canonical-workspace-exec-v3 Rlib namespace without procfs or \
    entropy devices; complete immutable workspace files and directory listings; \
    every foreign Cargo OUT_DIR selected by propagated native searches bound \
    to its completed root-output/stdout record and complete immutable tree, \
    including empty directories; exact logical roots, native search order and \
    supported static bundle, whole-archive and verbatim flags; optional own \
    OUT_DIR retains its complete tree, exact completed Cargo stdout and matching \
    fully keyed environment; build scripts execute normally and supply no \
    compiler or run-cache authority; exact argv, cwd, manifest, output placement, \
    complete retained toolchain and measured ELF runtime; every loadable Rust \
    candidate bound to its operation-owned installed generation and exact \
    committed archive-capable producer action, descriptor, manifest, role and \
    whole object identity; whole explicit archives and existing metadata-shadow \
    projection, exact empty search metadata remains keyed without producer \
    authority; explicit empty externs refuse; complete nonempty H028 ancestry, \
    each intermediate's producer policy and current transitive serving, class, \
    quarantine and native archive closure rechecked at commit and delivery; \
    metadata-only producers cannot authorize any input, including rmeta; \
    original source, generated/native trees, Cargo records and dependency \
    generations revalidated; authenticated completed drained receipt, exact \
    dep-info and diagnostics, tracked-control read veto and complete output \
    rlib native closure including source link attributes, thin archives and \
    linker scripts; separate propagated-native archive samples, class quarantine \
    and private installation gates; no arbitrary host or dynamic/framework \
    search, external linker, final executable, proc macro, incremental state, \
    local completion, provisional publication, adopted or request-owned authority";

pub(super) const PROPAGATED_NATIVE_RLIB: DagContract = DagContract {
    epoch: 37,
    class: ActionClass::RustcWorkspaceCompile,
    isolation_domain: "rabs.canonical-workspace-propagated-native-dag-rlib.isolation.v1",
    semantics_domain: "rabs.canonical-workspace-propagated-native-dag-rlib.semantics.v1",
    dependencies_domain: "rabs.canonical-workspace-propagated-native-dag-rlib.dependencies.v1",
    profile: PROPAGATED_NATIVE_DAG_RLIB_ISOLATION_PROFILE,
};

pub(super) const RLIB: DagContract = DagContract {
    epoch: 28,
    class: ActionClass::RustcWorkspaceCompile,
    isolation_domain: "rabs.canonical-workspace-generated-dag-rlib.isolation.v1",
    semantics_domain: "rabs.canonical-workspace-generated-dag-rlib.semantics.v1",
    dependencies_domain: "rabs.canonical-workspace-generated-dag-rlib.dependencies.v1",
    profile: GENERATED_DAG_RLIB_ISOLATION_PROFILE,
};

pub(super) const METADATA: DagContract = DagContract {
    epoch: 29,
    class: ActionClass::RustcWorkspaceCompile,
    isolation_domain: "rabs.canonical-workspace-generated-dag-metadata.isolation.v1",
    semantics_domain: "rabs.canonical-workspace-generated-dag-metadata.semantics.v1",
    dependencies_domain: "rabs.canonical-workspace-generated-dag-metadata.dependencies.v1",
    profile: GENERATED_DAG_METADATA_ISOLATION_PROFILE,
};

/// Refine an original fresh workspace invocation into a generated DAG
/// candidate. Planning grants neither producer nor cache authority: the
/// coordinator must retain the selected Cargo unit and an exact committed
/// installation witness for every loadable Rust candidate.
///
/// # Errors
/// A nonfresh plan, missing own OUT_DIR, nonlibrary output, unclosed native
/// inputs, or unsupported executable/compiler state. Static native inputs are
/// admitted only by the independent native archive and closed metadata classes.
pub fn plan_generated_workspace_dag_library(
    execution: &DependencyActionPlan,
) -> Result<DependencyActionPlan, LiveRefusal> {
    if execution.source_kind != DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "generated workspace DAG planning requires the original fresh workspace plan".into(),
        ));
    }
    let (source_kind, policy) = match remote::remote_dependency_output_class(&execution.invocation)
        .map_err(|error| LiveRefusal::Facts(error.to_string()))?
    {
        RemoteDependencyOutputClass::Rlib
            if !remote::validate_plan_native_roots(execution)?.is_empty() =>
        {
            (
                DependencySourceKind::WorkspaceNativeGeneratedDagRlib,
                CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib,
            )
        }
        RemoteDependencyOutputClass::Rlib => (
            DependencySourceKind::WorkspaceGeneratedDagRlib,
            CommittedDependencyPolicy::GeneratedWorkspaceDagRlib,
        ),
        RemoteDependencyOutputClass::Metadata
            if !remote::validate_plan_native_roots(execution)?.is_empty() =>
        {
            (
                DependencySourceKind::WorkspaceNativeGeneratedDagMetadata,
                CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata,
            )
        }
        RemoteDependencyOutputClass::Metadata => (
            DependencySourceKind::WorkspaceGeneratedDagMetadata,
            CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata,
        ),
    };
    let mut plan = execution.clone();
    plan.source_kind = source_kind;
    validate_plan(&plan, policy)?;
    Ok(plan)
}

/// Refine an original fresh workspace library check which inherits native
/// searches from completed Cargo build scripts. Every foreign OUT_DIR is
/// retained in full; an own generated tree is optional. The coordinator must
/// independently bind the selected unit, roots, Cargo records and every
/// committed Rust producer before this candidate can receive cache authority.
///
/// # Errors
/// A nonfresh plan, no foreign native root, nonlibrary or codegen output,
/// unclosed native input, or unsupported executable/compiler state.
pub fn plan_propagated_native_workspace_dag_metadata(
    execution: &DependencyActionPlan,
) -> Result<DependencyActionPlan, LiveRefusal> {
    if execution.source_kind != DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "propagated native metadata planning requires the original fresh workspace plan".into(),
        ));
    }
    let mut plan = execution.clone();
    plan.source_kind = DependencySourceKind::WorkspacePropagatedNativeDagMetadata;
    validate_propagated_native_plan(
        &plan,
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagMetadata,
    )?;
    Ok(plan)
}

/// Refine an original fresh workspace library build with inherited native
/// searches into the separately qualified archive class. Input trees and Cargo
/// records remain complete, and every Rust producer must have archive authority.
/// The output rlib still requires the existing native closure proof before
/// publication; an unbundled link edge never acquires cache authority here.
///
/// # Errors
/// A nonfresh plan, no foreign native root, nonlibrary or nonarchive output,
/// unclosed native input, or unsupported executable/compiler state.
pub fn plan_propagated_native_workspace_dag_rlib(
    execution: &DependencyActionPlan,
) -> Result<DependencyActionPlan, LiveRefusal> {
    if execution.source_kind != DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "propagated native archive planning requires the original fresh workspace plan".into(),
        ));
    }
    let mut plan = execution.clone();
    plan.source_kind = DependencySourceKind::WorkspacePropagatedNativeDagRlib;
    validate_propagated_native_plan(
        &plan,
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagRlib,
    )?;
    Ok(plan)
}

fn validate_propagated_native_plan(
    plan: &DependencyActionPlan,
    policy: CommittedDependencyPolicy,
) -> Result<(), LiveRefusal> {
    let source_kind = match policy {
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagMetadata => {
            DependencySourceKind::WorkspacePropagatedNativeDagMetadata
        }
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagRlib => {
            DependencySourceKind::WorkspacePropagatedNativeDagRlib
        }
        _ => {
            return Err(LiveRefusal::Facts(
                "propagated native workspace caching requires its distinct committed-input policy"
                    .into(),
            ));
        }
    };
    workspace_layout(plan)?;
    if plan.source_kind != source_kind
        || !matches!(plan.invocation.crate_types.as_slice(), [kind] if matches!(kind.as_str(), "lib" | "rlib"))
        || plan
            .invocation
            .passthrough
            .iter()
            .any(|arg| arg == "--test")
        || plan.native_roots.is_empty()
        || remote::validate_plan_native_roots(plan)?.is_empty()
        || remote::remote_dependency_output_class(&plan.invocation) != Ok(policy.output_class())
    {
        return Err(LiveRefusal::Facts(
            "propagated native workspace caching requires its exact ordinary library output class, complete foreign Cargo OUT_DIR inputs and committed Rust ancestry"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_plan(
    plan: &DependencyActionPlan,
    policy: CommittedDependencyPolicy,
) -> Result<(), LiveRefusal> {
    if matches!(
        policy,
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagMetadata
            | CommittedDependencyPolicy::PropagatedNativeWorkspaceDagRlib
    ) {
        return validate_propagated_native_plan(plan, policy);
    }
    workspace_layout(plan)?;
    let source_kind = match policy {
        CommittedDependencyPolicy::GeneratedWorkspaceDagRlib => {
            DependencySourceKind::WorkspaceGeneratedDagRlib
        }
        CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata => {
            DependencySourceKind::WorkspaceGeneratedDagMetadata
        }
        CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib => {
            DependencySourceKind::WorkspaceNativeGeneratedDagRlib
        }
        CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata => {
            DependencySourceKind::WorkspaceNativeGeneratedDagMetadata
        }
        _ => {
            return Err(LiveRefusal::Facts(
                "generated workspace DAG requires its distinct committed-input policy".into(),
            ));
        }
    };
    if plan.source_kind != source_kind
        || !matches!(plan.invocation.crate_types.as_slice(), [kind] if matches!(kind.as_str(), "lib" | "rlib"))
        || plan
            .invocation
            .passthrough
            .iter()
            .any(|arg| arg == "--test")
        || plan.generated_root.is_none()
        || !plan.native_roots.is_empty()
        || (!matches!(
            policy,
            CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib
                | CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata
        ) && (!plan.invocation.native_libs.is_empty()
            || !remote::validate_plan_native_roots(plan)?.is_empty()))
        || remote::remote_dependency_output_class(&plan.invocation) != Ok(policy.output_class())
    {
        return Err(LiveRefusal::Facts(
            "generated workspace DAG requires its exact library mode and own OUT_DIR; native inputs require their separate static archive or closed metadata class".into(),
        ));
    }
    if matches!(
        policy,
        CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib
            | CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata
    ) {
        validate_native_generated_inputs(plan, policy.output_class())?;
    }
    Ok(())
}

pub(super) fn shape(
    plan: &DependencyActionPlan,
    policy: CommittedDependencyPolicy,
    directories: &[DependencyDirectoryFact],
    dependencies: &[CommittedWorkspaceDependency],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    validate_plan(plan, policy)?;
    remote::remote_execution_shape(plan, directories, toolchain_root)?;
    validate_committed_workspace_dependencies(directories, dependencies)?;
    let externs = remote::remote_extern_facts(plan, directories)?;
    artifacts_component(plan, &externs, directories)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn key(
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
    shape(plan, policy, directories, dependencies, toolchain_root)?;
    let (contract, environment_domain, invocation_domain) = match policy {
        CommittedDependencyPolicy::GeneratedWorkspaceDagRlib => (
            &RLIB,
            "rabs.canonical-workspace-generated-dag-rlib.environment.v1",
            "rabs.canonical-workspace-generated-dag-rlib.invocation.v1",
        ),
        CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata => (
            &METADATA,
            "rabs.canonical-workspace-generated-dag-metadata.environment.v1",
            "rabs.canonical-workspace-generated-dag-metadata.invocation.v1",
        ),
        CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib => (
            &NATIVE_RLIB,
            "rabs.canonical-workspace-native-generated-dag-rlib.environment.v1",
            "rabs.canonical-workspace-native-generated-dag-rlib.invocation.v1",
        ),
        CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata => (
            &NATIVE_METADATA,
            "rabs.canonical-workspace-native-generated-dag-metadata.environment.v1",
            "rabs.canonical-workspace-native-generated-dag-metadata.invocation.v1",
        ),
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagMetadata => (
            &PROPAGATED_NATIVE_METADATA,
            "rabs.canonical-workspace-propagated-native-dag-metadata.environment.v1",
            "rabs.canonical-workspace-propagated-native-dag-metadata.invocation.v1",
        ),
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagRlib => (
            &PROPAGATED_NATIVE_RLIB,
            "rabs.canonical-workspace-propagated-native-dag-rlib.environment.v1",
            "rabs.canonical-workspace-propagated-native-dag-rlib.invocation.v1",
        ),
        _ => unreachable!("generated DAG shape checked its exact policy"),
    };
    let externs = remote::remote_extern_facts(plan, directories)?;
    // Bind every complete generated/native tree and its exact completed Cargo
    // record. The propagated class may have no own OUT_DIR, but its foreign
    // records are mandatory inputs. Do not relabel a pure/leaf descriptor.
    let mut key = captured_action_key(
        plan,
        toolchain,
        &externs,
        directories,
        build_script_output,
        inputs,
    )?;
    remote::validate_generated_native_manifest(plan, inputs)?;
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
            _ => unreachable!("generated DAG input has a checked Rust artifact role"),
        });
        encoder.bytes(dependency.virtual_path.as_bytes());
        encode_digest(encoder, &dependency.object.0);
    });
    key.descriptor.dependency_inputs = compute(contract.dependencies_domain, &provenance.finish());
    let mut environment = CanonicalEncoder::new();
    environment.seq(&plan.execution_env, |encoder, (name, value)| {
        encoder.str(name).str(value);
    });
    key.descriptor.environment = compute(environment_domain, &environment.finish());
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
    key.descriptor.normalized_invocation = compute(invocation_domain, &invocation.finish());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_dependency::workspace_cache as leaf;
    use crate::live_dependency::workspace_dependency_cache as committed;
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
    const TOOLCHAIN: &str = "/__rabs/toolchain";
    const WORKSPACE: &str = "/__rabs/workspace";
    const OUTPUT: &str = "/__rabs/out/cargo/debug/deps";
    const GENERATED: &str = "/__rabs/out/cargo/debug/build/consumer-123/out";
    const FOREIGN_NATIVE_A: &str = "/__rabs/out/cargo/debug/build/provider-a/out";
    const FOREIGN_NATIVE_B: &str = "/__rabs/out/cargo/debug/build/provider-b/out";
    const PROPAGATED_POLICY: CommittedDependencyPolicy =
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagMetadata;
    const PROPAGATED_ARCHIVE_POLICY: CommittedDependencyPolicy =
        CommittedDependencyPolicy::PropagatedNativeWorkspaceDagRlib;
    const RECORD: &[u8] = b"cargo:rerun-if-changed=build.rs\ncargo:rustc-env=BUILD_TAG=generated\n";
    const NATIVE_RECORD: &[u8] = b"cargo:rerun-if-changed=build.rs\ncargo:rustc-env=BUILD_TAG=generated\ncargo:rustc-link-search=native=/__rabs/out/cargo/debug/build/consumer-123/out\ncargo:rustc-link-lib=static=generated\n";
    const POLICIES: [CommittedDependencyPolicy; 2] = [
        CommittedDependencyPolicy::GeneratedWorkspaceDagRlib,
        CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata,
    ];
    const NATIVE_POLICIES: [(CommittedDependencyPolicy, DependencySourceKind, u32); 2] = [
        (
            CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib,
            DependencySourceKind::WorkspaceNativeGeneratedDagRlib,
            31,
        ),
        (
            CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata,
            DependencySourceKind::WorkspaceNativeGeneratedDagMetadata,
            33,
        ),
    ];

    fn digest(bytes: &[u8]) -> TypedDigest {
        compute("rabs.test.generated-workspace-dag.v1", bytes)
    }

    fn request(
        policy: CommittedDependencyPolicy,
        generated: bool,
        explicit_archive: bool,
    ) -> (Vec<String>, Vec<(String, String)>) {
        let mut argv = [
            "/__rabs/toolchain/bin/rustc",
            "--crate-name=consumer",
            "--crate-type=lib",
            "--edition=2021",
            "consumer/src/lib.rs",
            "--error-format=json",
            "--json=artifacts",
            "--warn=dead_code",
            match policy.output_class() {
                RemoteDependencyOutputClass::Rlib => "--emit=dep-info,metadata,link",
                RemoteDependencyOutputClass::Metadata => "--emit=dep-info,metadata",
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
            if explicit_archive { "rlib" } else { "rmeta" }
        ));
        let mut env = [
            ("HOME", "/__rabs/home"),
            ("CARGO_HOME", "/__rabs/cargo-home"),
            ("CARGO_MANIFEST_DIR", "/__rabs/workspace/consumer"),
            ("CARGO_PKG_NAME", "consumer"),
            ("CARGO_PRIMARY_PACKAGE", "1"),
            ("USER_PAYLOAD", "exact input"),
            ("CARGO_MAKEFLAGS", "--jobserver-auth=3,4"),
            ("LD_LIBRARY_PATH", "/__rabs/toolchain/lib"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect::<Vec<_>>();
        if generated {
            env.push(("OUT_DIR".into(), GENERATED.into()));
            env.push(("BUILD_TAG".into(), "generated".into()));
        }
        if matches!(
            policy,
            CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib
                | CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata
        ) {
            argv.extend([format!("-Lnative={GENERATED}"), "-lstatic=generated".into()]);
        }
        (argv, env)
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

    fn plan(policy: CommittedDependencyPolicy, explicit_archive: bool) -> DependencyActionPlan {
        let (argv, env) = request(policy, true, explicit_archive);
        plan_generated_workspace_dag_library(&execution(&argv, &env)).unwrap()
    }

    fn listing(path: String, entries: &[&str]) -> DirectoryEnumeration {
        DirectoryEnumeration {
            virtual_path: RawBytes::new(path.into_bytes()),
            entries: entries.iter().map(|entry| RawBytes::from(*entry)).collect(),
        }
    }

    fn source_inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: [
                "Cargo.toml",
                "consumer/Cargo.toml",
                "consumer/build.rs",
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
                listing(
                    plan.source_virtual_root(),
                    &["Cargo.toml", "consumer", "empty", "sibling.txt"],
                ),
                listing(
                    plan.input_virtual_path("consumer"),
                    &["Cargo.toml", "build.rs", "src"],
                ),
                listing(plan.input_virtual_path("consumer/src"), &["lib.rs"]),
                listing(plan.input_virtual_path("empty"), &[]),
            ],
            ..ActionInputManifest::default()
        }
    }

    fn inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let mut inputs = source_inputs(plan);
        inputs
            .inputs
            .extend(
                ["value.rs", "nested/piece.rs"]
                    .into_iter()
                    .map(|relative| PositiveInput {
                        virtual_path: RawBytes::new(
                            plan.generated_input_virtual_path(relative).into_bytes(),
                        ),
                        object: ObjectId(digest(relative.as_bytes())),
                        file_type: InputFileType::Regular,
                        executable: false,
                        symlink_resolution: Vec::new(),
                    }),
            );
        inputs.directory_enumerations.extend([
            listing(
                plan.generated_virtual_root(),
                &["empty", "nested", "value.rs"],
            ),
            listing(plan.generated_input_virtual_path("empty"), &[]),
            listing(
                plan.generated_input_virtual_path("nested"),
                &["empty", "piece.rs"],
            ),
            listing(plan.generated_input_virtual_path("nested/empty"), &[]),
        ]);
        inputs
    }

    fn native_inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let mut captured = inputs(plan);
        captured.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(
                plan.generated_input_virtual_path("libgenerated.a")
                    .into_bytes(),
            ),
            object: ObjectId(digest(b"exact bundled native archive")),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        let root = captured
            .directory_enumerations
            .iter_mut()
            .find(|directory| {
                directory.virtual_path.as_bytes() == plan.generated_virtual_root().as_bytes()
            })
            .unwrap();
        root.entries.push(RawBytes::from("libgenerated.a"));
        root.entries
            .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        captured
    }

    fn propagated_request(
        own_generated: bool,
        explicit_archive: bool,
        native_library: bool,
    ) -> (Vec<String>, Vec<(String, String)>) {
        let (mut argv, env) = request(PROPAGATED_POLICY, own_generated, explicit_archive);
        argv.extend([
            format!("-Lnative={FOREIGN_NATIVE_B}/nested"),
            format!("-Lnative={FOREIGN_NATIVE_A}"),
        ]);
        if native_library {
            argv.push("-lstatic=provider".into());
        }
        (argv, env)
    }

    fn propagated_execution(
        own_generated: bool,
        explicit_archive: bool,
        native_library: bool,
    ) -> DependencyActionPlan {
        let (argv, env) = propagated_request(own_generated, explicit_archive, native_library);
        execution(&argv, &env)
    }

    fn propagated_archive_execution(
        own_generated: bool,
        explicit_archive: bool,
        native_library: bool,
    ) -> DependencyActionPlan {
        let (mut argv, env) = request(PROPAGATED_ARCHIVE_POLICY, own_generated, explicit_archive);
        argv.extend([
            format!("-Lnative={FOREIGN_NATIVE_B}/nested"),
            format!("-Lnative={FOREIGN_NATIVE_A}"),
        ]);
        if native_library {
            argv.push("-lstatic=provider".into());
        }
        execution(&argv, &env)
    }

    fn propagated_inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let mut captured = if plan.generated_root.is_some() {
            inputs(plan)
        } else {
            source_inputs(plan)
        };
        for (index, root) in plan.native_roots.iter().enumerate() {
            captured.directory_enumerations.extend([
                listing(
                    plan.native_input_virtual_root(index),
                    &["empty", "libprovider.a", "nested"],
                ),
                listing(plan.native_input_virtual_path(index, "empty"), &[]),
                listing(
                    plan.native_input_virtual_path(index, "nested"),
                    &["libprovider.a"],
                ),
            ]);
            for relative in ["libprovider.a", "nested/libprovider.a"] {
                captured.inputs.push(PositiveInput {
                    virtual_path: RawBytes::new(
                        plan.native_input_virtual_path(index, relative).into_bytes(),
                    ),
                    object: ObjectId(digest(format!("{root}/{relative}").as_bytes())),
                    file_type: InputFileType::Regular,
                    executable: false,
                    symlink_resolution: Vec::new(),
                });
            }
            captured.inputs.push(PositiveInput {
                virtual_path: RawBytes::new(plan.native_record_virtual_path(index).into_bytes()),
                object: ObjectId(digest(
                    format!("cargo::rustc-link-search=native={root}\n").as_bytes(),
                )),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            });
        }
        captured
    }

    fn candidate(name: &str) -> CommittedWorkspaceDependency {
        let producer = name.rsplit_once('.').unwrap().0;
        CommittedWorkspaceDependency {
            path: format!("{OUTPUT}/{name}"),
            producer_action: digest(format!("action {producer}").as_bytes()),
            producer_descriptor: digest(format!("descriptor {producer}").as_bytes()),
            producer_manifest: digest(format!("manifest {producer}").as_bytes()),
            role: if name.ends_with(".rmeta") {
                OutputRole::ProvisionalMetadata
            } else {
                OutputRole::Materializable
            },
            virtual_path: RawBytes::from(name),
            object: ObjectId(digest(name.as_bytes())),
        }
    }

    fn dependencies() -> Vec<CommittedWorkspaceDependency> {
        [
            "liblower.rlib",
            "liblower.rmeta",
            "libupstream.rlib",
            "libupstream.rmeta",
        ]
        .into_iter()
        .map(candidate)
        .collect()
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

    fn toolchain() -> ToolchainFacts {
        ToolchainFacts {
            compiler_binary_digest: digest(b"compiler"),
            verbose_version: format!("rustc 1.100.0\nhost: {HOST}\nLLVM version: 21"),
            sysroot_root_digest: digest(b"sysroot"),
            runtime_libraries: Vec::new(),
        }
    }

    fn build_key(
        plan: &DependencyActionPlan,
        policy: CommittedDependencyPolicy,
        dependencies: &[CommittedWorkspaceDependency],
        inputs: &ActionInputManifest,
        record: Option<&[u8]>,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        key_with_inventory(
            plan,
            policy,
            &directories(dependencies),
            dependencies,
            inputs,
            record,
        )
    }

    fn key_with_inventory(
        plan: &DependencyActionPlan,
        policy: CommittedDependencyPolicy,
        directories: &[DependencyDirectoryFact],
        dependencies: &[CommittedWorkspaceDependency],
        inputs: &ActionInputManifest,
        record: Option<&[u8]>,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        committed::remote_committed_dependency_key(
            plan,
            policy,
            &toolchain(),
            directories,
            dependencies,
            inputs,
            record,
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
    }

    #[test]
    fn propagated_native_metadata_admits_exact_foreign_trees_with_optional_own_out_dir() {
        for own_generated in [false, true] {
            for explicit_archive in [false, true] {
                for native_library in [false, true] {
                    let (argv, env) =
                        propagated_request(own_generated, explicit_archive, native_library);
                    let fresh = plan_canonical_workspace_execution(
                        LiveRustcRequest {
                            argv: &argv,
                            env: &env,
                            cwd: WORKSPACE,
                        },
                        HOST,
                    );
                    if !own_generated && native_library {
                        assert_eq!(
                            fresh.unwrap_err(),
                            LiveRefusal::MissingEnv("OUT_DIR"),
                            "direct native directives require their own Cargo build-script owner"
                        );
                        continue;
                    }
                    let fresh = fresh.unwrap();
                    let plan = plan_propagated_native_workspace_dag_metadata(&fresh).unwrap();
                    let captured = propagated_inputs(&plan);
                    let record = own_generated.then_some(RECORD);
                    let keyed =
                        build_key(&plan, PROPAGATED_POLICY, &dependencies(), &captured, record)
                            .unwrap();
                    assert_eq!(plan.invocation, fresh.invocation);
                    assert_eq!(plan.execution_env, fresh.execution_env);
                    assert_eq!(plan.native_roots, [FOREIGN_NATIVE_A, FOREIGN_NATIVE_B]);
                    assert_eq!(plan.generated_root.is_some(), own_generated);
                    assert_eq!(
                        plan.source_kind,
                        DependencySourceKind::WorkspacePropagatedNativeDagMetadata
                    );
                    assert_eq!(
                        plan.source_kind.as_str(),
                        "canonical-workspace-propagated-native-dag-metadata-v1"
                    );
                    assert_eq!(
                        CommittedDependencyPolicy::from_source_kind(plan.source_kind),
                        Some(PROPAGATED_POLICY)
                    );
                    assert_eq!(keyed.descriptor.key_epoch, 36);
                    assert_eq!(
                        committed::committed_dependency_descriptor_policy(&keyed.descriptor),
                        Some(PROPAGATED_POLICY)
                    );
                    assert_eq!(
                        committed::remote_committed_dependency_isolation_policy(
                            &plan,
                            PROPAGATED_POLICY
                        )
                        .unwrap(),
                        keyed.descriptor.sandbox_semantic_policy
                    );
                    assert_eq!(plan.output_names(), ["consumer.d", "libconsumer.rmeta"]);
                    assert_eq!(
                        build_key(&plan, PROPAGATED_POLICY, &dependencies(), &captured, record)
                            .unwrap()
                            .action_key,
                        keyed.action_key
                    );
                    assert!(plan_propagated_native_workspace_dag_metadata(&plan).is_err());
                    assert!(plan_generated_workspace_dag_library(&fresh).is_err());
                    assert!(leaf::plan_closed_workspace_library(&fresh).is_err());
                    assert!(committed::plan_mixed_workspace_library(&fresh).is_err());
                }
            }
        }
    }

    #[test]
    fn propagated_native_metadata_keys_every_tree_record_search_and_committed_producer() {
        let fresh = propagated_execution(true, false, true);
        let plan = plan_propagated_native_workspace_dag_metadata(&fresh).unwrap();
        let captured = propagated_inputs(&plan);
        let dependencies = dependencies();
        let original = build_key(
            &plan,
            PROPAGATED_POLICY,
            &dependencies,
            &captured,
            Some(RECORD),
        )
        .unwrap();
        // Includes unselected native alternatives, the optional own generated
        // tree and unrelated workspace files: this class keeps full closure.
        for input in &captured.inputs {
            let mut changed = captured.clone();
            changed
                .inputs
                .iter_mut()
                .find(|candidate| candidate.virtual_path == input.virtual_path)
                .unwrap()
                .object = ObjectId(digest(b"changed retained input"));
            assert_ne!(
                original.action_key,
                build_key(
                    &plan,
                    PROPAGATED_POLICY,
                    &dependencies,
                    &changed,
                    Some(RECORD)
                )
                .unwrap()
                .action_key,
                "input={:?}",
                input.virtual_path
            );
        }
        let mut membership = captured.clone();
        membership
            .directory_enumerations
            .iter_mut()
            .find(|directory| {
                directory.virtual_path.as_bytes() == plan.native_input_virtual_root(0).as_bytes()
            })
            .unwrap()
            .entries
            .push(RawBytes::from("new-empty"));
        for directory in &mut membership.directory_enumerations {
            directory
                .entries
                .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        }
        membership
            .directory_enumerations
            .push(listing(plan.native_input_virtual_path(0, "new-empty"), &[]));
        assert_ne!(
            original.action_key,
            build_key(
                &plan,
                PROPAGATED_POLICY,
                &dependencies,
                &membership,
                Some(RECORD)
            )
            .unwrap()
            .action_key
        );
        let mut reordered = plan.clone();
        let search_count = reordered.invocation.lib_search.len();
        reordered
            .invocation
            .lib_search
            .swap(search_count - 2, search_count - 1);
        assert_ne!(
            original.action_key,
            build_key(
                &reordered,
                PROPAGATED_POLICY,
                &dependencies,
                &captured,
                Some(RECORD)
            )
            .unwrap()
            .action_key
        );
        let mut changed_producer = dependencies.clone();
        for dependency in &mut changed_producer[..2] {
            dependency.producer_manifest = digest(b"new committed native-dependent producer");
        }
        assert_ne!(
            original.action_key,
            build_key(
                &plan,
                PROPAGATED_POLICY,
                &changed_producer,
                &captured,
                Some(RECORD)
            )
            .unwrap()
            .action_key
        );
        let mut own_record = RECORD.to_vec();
        own_record.extend_from_slice(b"cargo::rerun-if-changed=another-input.h\n");
        assert_ne!(
            original.action_key,
            build_key(
                &plan,
                PROPAGATED_POLICY,
                &dependencies,
                &captured,
                Some(&own_record)
            )
            .unwrap()
            .action_key
        );
    }

    #[test]
    fn propagated_native_metadata_requires_complete_records_trees_and_nonempty_ancestry() {
        for own_generated in [false, true] {
            let plan = plan_propagated_native_workspace_dag_metadata(&propagated_execution(
                own_generated,
                false,
                own_generated,
            ))
            .unwrap();
            let captured = propagated_inputs(&plan);
            let dependencies = dependencies();
            let record = own_generated.then_some(RECORD);
            for index in 0..plan.native_roots.len() {
                for path in [
                    plan.native_input_virtual_path(index, "libprovider.a"),
                    plan.native_input_virtual_path(index, "nested/libprovider.a"),
                    plan.native_record_virtual_path(index),
                ] {
                    let mut incomplete = captured.clone();
                    incomplete
                        .inputs
                        .retain(|input| input.virtual_path.as_bytes() != path.as_bytes());
                    assert!(
                        build_key(&plan, PROPAGATED_POLICY, &dependencies, &incomplete, record)
                            .is_err(),
                        "missing={path}"
                    );
                }
                for mutation in 0..4 {
                    let mut changed = captured.clone();
                    let position = changed
                        .inputs
                        .iter()
                        .position(|input| {
                            input.virtual_path.as_bytes()
                                == plan.native_record_virtual_path(index).as_bytes()
                        })
                        .unwrap();
                    match mutation {
                        0 => changed.inputs.push(changed.inputs[position].clone()),
                        1 => changed.inputs[position].executable = true,
                        2 => changed.inputs[position].file_type = InputFileType::Symlink,
                        _ => changed.inputs[position]
                            .symlink_resolution
                            .push(RawBytes::from("/unretained/output")),
                    }
                    assert!(
                        build_key(&plan, PROPAGATED_POLICY, &dependencies, &changed, record)
                            .is_err()
                    );
                }
                let mut no_empty_directory = captured.clone();
                no_empty_directory
                    .directory_enumerations
                    .retain(|directory| {
                        directory.virtual_path.as_bytes()
                            != plan.native_input_virtual_path(index, "empty").as_bytes()
                    });
                assert!(
                    build_key(
                        &plan,
                        PROPAGATED_POLICY,
                        &dependencies,
                        &no_empty_directory,
                        record
                    )
                    .is_err()
                );
            }
            let mut missing_producer = dependencies.clone();
            missing_producer.pop();
            assert!(
                key_with_inventory(
                    &plan,
                    PROPAGATED_POLICY,
                    &directories(&dependencies),
                    &missing_producer,
                    &captured,
                    record
                )
                .is_err()
            );
            let mut wrong_role = dependencies.clone();
            wrong_role[1].role = OutputRole::Materializable;
            assert!(build_key(&plan, PROPAGATED_POLICY, &wrong_role, &captured, record).is_err());
            assert!(build_key(&plan, PROPAGATED_POLICY, &[], &captured, record).is_err());
            if own_generated {
                assert!(
                    build_key(&plan, PROPAGATED_POLICY, &dependencies, &captured, None).is_err()
                );
            }
        }
    }

    #[test]
    fn propagated_native_metadata_refuses_other_execution_modes_and_unclosed_native_searches() {
        let fresh = propagated_execution(false, false, false);
        for mutation in 0..12 {
            let mut changed = fresh.clone();
            match mutation {
                0 => changed.native_roots.clear(),
                1 => changed.native_roots.reverse(),
                2 => changed.native_roots.push(changed.native_roots[0].clone()),
                3 => changed.native_roots[0] = "/__rabs/out/cargo/debug/build/unbound/out".into(),
                4 => changed.invocation.native_libs = vec!["dylib=provider".into()],
                5 => changed.invocation.native_libs = vec!["static:-bundle=provider".into()],
                6 => changed.invocation.native_libs = vec!["static:+verbatim=../outside.a".into()],
                7 => changed.invocation.lib_search.push("native=/usr/lib".into()),
                8 => changed
                    .invocation
                    .lib_search
                    .push("framework=/System/Library".into()),
                9 => changed.invocation.emit.push("link".into()),
                10 => changed.invocation.crate_types = vec!["bin".into()],
                _ => changed.invocation.passthrough.push("--test".into()),
            }
            assert!(
                plan_propagated_native_workspace_dag_metadata(&changed).is_err(),
                "mutation={mutation}"
            );
        }
        let (mut argv, env) = request(PROPAGATED_POLICY, false, false);
        argv.push(format!("-Lnative={FOREIGN_NATIVE_A}/absent"));
        let absent =
            plan_propagated_native_workspace_dag_metadata(&execution(&argv, &env)).unwrap();
        assert!(
            build_key(
                &absent,
                PROPAGATED_POLICY,
                &dependencies(),
                &propagated_inputs(&absent),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn propagated_native_metadata_cannot_borrow_older_leaf_dag_or_local_authority() {
        let fresh = propagated_execution(true, false, true);
        let plan = plan_propagated_native_workspace_dag_metadata(&fresh).unwrap();
        let captured = propagated_inputs(&plan);
        let dependencies = dependencies();
        let original = build_key(
            &plan,
            PROPAGATED_POLICY,
            &dependencies,
            &captured,
            Some(RECORD),
        )
        .unwrap();
        for (policy, kind) in [
            (
                CommittedDependencyPolicy::WorkspaceMetadata,
                DependencySourceKind::WorkspaceCommittedMetadata,
            ),
            (
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
                DependencySourceKind::WorkspaceMixedMetadata,
            ),
            (
                CommittedDependencyPolicy::WorkspaceDagMetadata,
                DependencySourceKind::WorkspaceMixedMetadata,
            ),
            (
                CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata,
                DependencySourceKind::WorkspaceGeneratedDagMetadata,
            ),
            (
                CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata,
                DependencySourceKind::WorkspaceNativeGeneratedDagMetadata,
            ),
            (
                CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib,
                DependencySourceKind::WorkspaceNativeGeneratedDagRlib,
            ),
        ] {
            let mut relabeled = plan.clone();
            relabeled.source_kind = kind;
            assert!(build_key(&relabeled, policy, &dependencies, &captured, Some(RECORD)).is_err());
            assert!(
                build_key(
                    &relabeled,
                    PROPAGATED_POLICY,
                    &dependencies,
                    &captured,
                    Some(RECORD)
                )
                .is_err()
            );
        }
        assert!(
            canonical_cargo_dependency_key(
                &plan,
                &toolchain(),
                &[],
                &directories(&dependencies),
                Some(RECORD),
                &captured,
            )
            .is_err()
        );
        assert!(leaf::closed_workspace_library_descriptor_class(&original.descriptor).is_none());
        for mutation in 0..4 {
            let mut forged = original.descriptor.clone();
            match mutation {
                0 => forged.key_epoch = 33,
                1 => forged.key_epoch = crate::live_dependency::LIVE_DEPENDENCY_KEY_EPOCH,
                2 => forged.action_class = ActionClass::RustcDependencyCompile,
                _ => forged.dependency_inputs = digest(b"unqualified producer inventory"),
            }
            assert!(committed::committed_dependency_descriptor_policy(&forged).is_none());
            assert!(committed::uses_committed_dependency_namespace(&forged));
        }
    }

    #[test]
    fn propagated_native_metadata_dep_info_keeps_exact_read_and_environment_vetoes() {
        let plan = plan_propagated_native_workspace_dag_metadata(&propagated_execution(
            true, false, false,
        ))
        .unwrap();
        let captured = propagated_inputs(&plan);
        let is_input = |path: &str| {
            captured
                .inputs
                .iter()
                .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
        };
        let dep_info = format!(
            "{OUTPUT}/libconsumer.rmeta: consumer/src/lib.rs {GENERATED}/value.rs {FOREIGN_NATIVE_A}/nested/libprovider.a\n"
        );
        assert!(dep_info_closure_violation(&plan, dep_info.as_bytes(), is_input).is_none());
        for extra in [
            format!("{OUTPUT}/libconsumer.rmeta: {FOREIGN_NATIVE_A}/absent.rs\n"),
            format!("{OUTPUT}/libconsumer.rmeta: /usr/include/unretained.h\n"),
            "# env-dep:CARGO_MAKEFLAGS=--jobserver-auth=3,4\n".into(),
        ] {
            assert!(dep_info_closure_violation(&plan, extra.as_bytes(), is_input).is_some());
        }
    }

    #[test]
    fn propagated_native_archives_require_their_distinct_full_input_contract() {
        for own_generated in [false, true] {
            for explicit_archive in [false, true] {
                for native_library in [false, true] {
                    if !own_generated && native_library {
                        continue; // Native directives require an own Cargo build-script owner.
                    }
                    let fresh = propagated_archive_execution(
                        own_generated,
                        explicit_archive,
                        native_library,
                    );
                    let plan = plan_propagated_native_workspace_dag_rlib(&fresh).unwrap();
                    let captured = propagated_inputs(&plan);
                    let record = own_generated.then_some(RECORD);
                    let keyed = build_key(
                        &plan,
                        PROPAGATED_ARCHIVE_POLICY,
                        &dependencies(),
                        &captured,
                        record,
                    )
                    .unwrap();
                    assert_eq!(plan.invocation, fresh.invocation);
                    assert_eq!(plan.execution_env, fresh.execution_env);
                    assert_eq!(plan.native_roots, [FOREIGN_NATIVE_A, FOREIGN_NATIVE_B]);
                    assert_eq!(plan.generated_root.is_some(), own_generated);
                    assert_eq!(
                        plan.source_kind,
                        DependencySourceKind::WorkspacePropagatedNativeDagRlib
                    );
                    assert_eq!(
                        CommittedDependencyPolicy::from_source_kind(plan.source_kind),
                        Some(PROPAGATED_ARCHIVE_POLICY)
                    );
                    assert_eq!(keyed.descriptor.key_epoch, 37);
                    assert_eq!(
                        committed::committed_dependency_descriptor_policy(&keyed.descriptor),
                        Some(PROPAGATED_ARCHIVE_POLICY)
                    );
                    assert_eq!(
                        plan.output_names(),
                        ["consumer.d", "libconsumer.rlib", "libconsumer.rmeta"]
                    );
                    assert!(plan_propagated_native_workspace_dag_rlib(&plan).is_err());
                    assert!(plan_propagated_native_workspace_dag_metadata(&fresh).is_err());
                    assert!(plan_generated_workspace_dag_library(&fresh).is_err());
                    assert!(leaf::plan_closed_workspace_library(&fresh).is_err());
                    assert!(
                        build_key(&plan, PROPAGATED_POLICY, &dependencies(), &captured, record)
                            .is_err()
                    );
                    let metadata = plan_propagated_native_workspace_dag_metadata(
                        &propagated_execution(own_generated, explicit_archive, native_library),
                    )
                    .unwrap();
                    let metadata_key = build_key(
                        &metadata,
                        PROPAGATED_POLICY,
                        &dependencies(),
                        &propagated_inputs(&metadata),
                        record,
                    )
                    .unwrap();
                    assert_ne!(keyed.action_key, metadata_key.action_key);
                    assert_ne!(
                        keyed.descriptor.sandbox_semantic_policy,
                        metadata_key.descriptor.sandbox_semantic_policy
                    );
                }
            }
        }
    }

    #[test]
    fn propagated_native_archive_keys_close_native_bytes_records_membership_and_producers() {
        let fresh = propagated_archive_execution(true, true, true);
        let plan = plan_propagated_native_workspace_dag_rlib(&fresh).unwrap();
        let captured = propagated_inputs(&plan);
        let dependencies = dependencies();
        let keyed = |plan: &DependencyActionPlan,
                     inputs: &ActionInputManifest,
                     producers: &[CommittedWorkspaceDependency]| {
            build_key(
                plan,
                PROPAGATED_ARCHIVE_POLICY,
                producers,
                inputs,
                Some(RECORD),
            )
        };
        let original = keyed(&plan, &captured, &dependencies).unwrap();
        for position in 0..captured.inputs.len() {
            let mut changed = captured.clone();
            changed.inputs[position].object.0.bytes[0] ^= 1;
            assert_ne!(
                original.action_key,
                keyed(&plan, &changed, &dependencies).unwrap().action_key,
                "input {:?}",
                captured.inputs[position].virtual_path
            );
        }
        let mut changed = captured.clone();
        changed.directory_enumerations.push(listing(
            plan.native_input_virtual_path(0, "empty/nested"),
            &[],
        ));
        changed
            .directory_enumerations
            .iter_mut()
            .find(|entry| {
                entry.virtual_path.as_bytes()
                    == plan.native_input_virtual_path(0, "empty").as_bytes()
            })
            .unwrap()
            .entries
            .push(RawBytes::from("nested"));
        assert_ne!(
            original.action_key,
            keyed(&plan, &changed, &dependencies).unwrap().action_key
        );
        let mut reordered = plan.clone();
        reordered.invocation.lib_search.reverse();
        assert_ne!(
            original.action_key,
            keyed(&reordered, &captured, &dependencies)
                .unwrap()
                .action_key
        );
        for index in 0..plan.native_roots.len() {
            for path in [
                plan.native_record_virtual_path(index),
                plan.native_input_virtual_path(index, "libprovider.a"),
            ] {
                let mut missing = captured.clone();
                missing
                    .inputs
                    .retain(|input| input.virtual_path.as_bytes() != path.as_bytes());
                assert!(keyed(&plan, &missing, &dependencies).is_err());
            }
        }
        let mut missing = dependencies.clone();
        missing.pop();
        assert!(
            key_with_inventory(
                &plan,
                PROPAGATED_ARCHIVE_POLICY,
                &directories(&dependencies),
                &missing,
                &captured,
                Some(RECORD),
            )
            .is_err()
        );
        assert!(keyed(&plan, &captured, &[]).is_err());
        for position in 0..dependencies.len() {
            let mut changed = dependencies.clone();
            changed[position].producer_manifest.bytes[0] ^= 1;
            assert_ne!(
                original.action_key,
                keyed(&plan, &captured, &changed).unwrap().action_key
            );
        }
        let is_input = |path: &str| {
            captured
                .inputs
                .iter()
                .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
        };
        assert!(
            dep_info_closure_violation(
                &plan,
                format!(
                    "{OUTPUT}/libconsumer.rlib: consumer/src/lib.rs {GENERATED}/value.rs {FOREIGN_NATIVE_A}/nested/libprovider.a\n"
                )
                .as_bytes(),
                is_input,
            )
            .is_none()
        );
        for unclosed in [
            format!("{OUTPUT}/libconsumer.rlib: /usr/include/unretained.h\n"),
            "# env-dep:CARGO_MAKEFLAGS=--jobserver-auth=3,4\n".into(),
        ] {
            assert!(dep_info_closure_violation(&plan, unclosed.as_bytes(), is_input).is_some());
        }
    }

    #[test]
    fn propagated_native_archives_refuse_nonbundled_inputs_and_mislabeled_authority() {
        let fresh = propagated_archive_execution(false, true, false);
        for mutation in 0..12 {
            let mut changed = fresh.clone();
            match mutation {
                0 => changed.native_roots.clear(),
                1 => changed.native_roots.reverse(),
                2 => changed.native_roots.push(changed.native_roots[0].clone()),
                3 => changed.native_roots[0] = "/__rabs/out/cargo/debug/build/unbound/out".into(),
                4 => changed.invocation.native_libs = vec!["dylib=provider".into()],
                5 => changed.invocation.native_libs = vec!["static:-bundle=provider".into()],
                6 => changed.invocation.native_libs = vec!["static:+verbatim=../outside.a".into()],
                7 => changed.invocation.lib_search.push("native=/usr/lib".into()),
                8 => changed
                    .invocation
                    .lib_search
                    .push("framework=/System/Library".into()),
                9 => changed.invocation.emit.retain(|kind| kind != "link"),
                10 => changed.invocation.crate_types = vec!["bin".into()],
                _ => changed.invocation.passthrough.push("--test".into()),
            }
            assert!(
                plan_propagated_native_workspace_dag_rlib(&changed).is_err(),
                "mutation={mutation}"
            );
        }
        let plan = plan_propagated_native_workspace_dag_rlib(&fresh).unwrap();
        let captured = propagated_inputs(&plan);
        let original = build_key(
            &plan,
            PROPAGATED_ARCHIVE_POLICY,
            &dependencies(),
            &captured,
            None,
        )
        .unwrap();
        for mutation in 0..5 {
            let mut forged = original.descriptor.clone();
            match mutation {
                0 => forged.key_epoch = 36,
                1 => forged.key_epoch = crate::live_dependency::LIVE_DEPENDENCY_KEY_EPOCH,
                2 => forged.action_class = ActionClass::RustcDependencyCompile,
                3 => forged.dependency_inputs = digest(b"unqualified producer inventory"),
                _ => {
                    forged.sandbox_semantic_policy = compute(
                        PROPAGATED_NATIVE_METADATA.isolation_domain,
                        PROPAGATED_NATIVE_METADATA.profile.as_bytes(),
                    );
                }
            }
            assert!(committed::committed_dependency_descriptor_policy(&forged).is_none());
            assert!(committed::uses_committed_dependency_namespace(&forged));
        }
        assert!(leaf::closed_workspace_library_descriptor_class(&original.descriptor).is_none());
    }

    #[test]
    fn native_generated_dag_binds_native_inputs_and_earns_separate_producer_authority() {
        for (policy, source_kind, epoch) in NATIVE_POLICIES {
            let plan = plan(policy, false);
            let dependencies = dependencies();
            let captured = native_inputs(&plan);
            let original =
                build_key(&plan, policy, &dependencies, &captured, Some(NATIVE_RECORD)).unwrap();
            assert_eq!(plan.source_kind, source_kind);
            assert_eq!(original.descriptor.key_epoch, epoch);
            assert_eq!(
                CommittedDependencyPolicy::from_source_kind(source_kind),
                Some(policy)
            );
            assert_eq!(
                committed::committed_dependency_descriptor_policy(&original.descriptor),
                Some(policy)
            );
            assert!(
                leaf::closed_workspace_library_descriptor_class(&original.descriptor).is_none()
            );
            for old_policy in POLICIES {
                assert!(
                    build_key(
                        &plan,
                        old_policy,
                        &dependencies,
                        &captured,
                        Some(NATIVE_RECORD)
                    )
                    .is_err()
                );
                let mut relabeled = plan.clone();
                relabeled.source_kind = if old_policy == POLICIES[0] {
                    DependencySourceKind::WorkspaceGeneratedDagRlib
                } else {
                    DependencySourceKind::WorkspaceGeneratedDagMetadata
                };
                assert!(
                    build_key(
                        &relabeled,
                        old_policy,
                        &dependencies,
                        &captured,
                        Some(NATIVE_RECORD)
                    )
                    .is_err()
                );
            }
            let mut old_epoch = original.descriptor.clone();
            old_epoch.key_epoch = 28;
            assert!(committed::committed_dependency_descriptor_policy(&old_epoch).is_none());
            let mut changed = captured.clone();
            changed.inputs.last_mut().unwrap().object = ObjectId(digest(b"rebuilt native archive"));
            assert_ne!(
                original.action_key,
                build_key(&plan, policy, &dependencies, &changed, Some(NATIVE_RECORD))
                    .unwrap()
                    .action_key
            );
            let mut changed_record = NATIVE_RECORD.to_vec();
            changed_record.extend_from_slice(b"cargo:rerun-if-changed=consumer/native.h\n");
            assert_ne!(
                original.action_key,
                build_key(
                    &plan,
                    policy,
                    &dependencies,
                    &captured,
                    Some(&changed_record)
                )
                .unwrap()
                .action_key
            );
            assert!(build_key(&plan, policy, &dependencies, &captured, None).is_err());
            assert!(
                build_key(
                    &plan,
                    policy,
                    &dependencies,
                    &inputs(&plan),
                    Some(NATIVE_RECORD)
                )
                .is_err()
            );

            // The native boundary does not weaken exact Rust producer ownership.
            let mut unowned = dependencies.clone();
            unowned.pop();
            assert!(
                key_with_inventory(
                    &plan,
                    policy,
                    &directories(&dependencies),
                    &unowned,
                    &captured,
                    Some(NATIVE_RECORD)
                )
                .is_err()
            );
            let mut changed_producer = dependencies.clone();
            for dependency in &mut changed_producer[..2] {
                dependency.producer_manifest = digest(b"new producer publication");
            }
            assert_ne!(
                original.action_key,
                build_key(
                    &plan,
                    policy,
                    &changed_producer,
                    &captured,
                    Some(NATIVE_RECORD)
                )
                .unwrap()
                .action_key
            );
        }
    }

    #[test]
    fn native_generated_dag_refuses_search_only_foreign_dynamic_and_mismatched_output_inputs() {
        for (policy, _, _) in NATIVE_POLICIES {
            let plan = plan(policy, false);
            let dependencies = dependencies();
            let captured = native_inputs(&plan);
            for mutation in 0..7 {
                let mut changed = plan.clone();
                match mutation {
                    0 => changed.invocation.native_libs.clear(),
                    1 => changed.invocation.native_libs = vec!["dylib=generated".into()],
                    2 => changed.invocation.native_libs = vec!["static:-bundle=generated".into()],
                    3 => {
                        changed.native_roots =
                            vec!["/__rabs/out/cargo/debug/build/foreign/out".into()]
                    }
                    4 => changed.generated_root = None,
                    5 => {
                        changed.invocation.emit =
                            if policy.output_class() == RemoteDependencyOutputClass::Rlib {
                                vec!["dep-info".into(), "metadata".into()]
                            } else {
                                vec!["dep-info".into(), "metadata".into(), "link".into()]
                            }
                    }
                    _ => {
                        changed.invocation.native_libs =
                            vec!["static:+verbatim=../outside.a".into()]
                    }
                }
                assert!(
                    build_key(
                        &changed,
                        policy,
                        &dependencies,
                        &captured,
                        Some(NATIVE_RECORD)
                    )
                    .is_err(),
                    "mutation={mutation}"
                );
            }
            let (mut argv, env) = request(policy, true, false);
            argv.retain(|argument| argument != &format!("-Lnative={GENERATED}"));
            argv.push(format!("-Lnative={GENERATED}/absent"));
            let absent_directory =
                plan_generated_workspace_dag_library(&execution(&argv, &env)).unwrap();
            assert!(
                build_key(
                    &absent_directory,
                    policy,
                    &dependencies,
                    &captured,
                    Some(NATIVE_RECORD)
                )
                .is_err()
            );
        }
        let (argv, env) = request(
            CommittedDependencyPolicy::GeneratedWorkspaceDagMetadata,
            true,
            false,
        );
        let mut argv = argv;
        argv.extend([format!("-Lnative={GENERATED}"), "-lstatic=generated".into()]);
        let metadata_plan = plan_generated_workspace_dag_library(&execution(&argv, &env)).unwrap();
        assert_eq!(
            metadata_plan.source_kind,
            DependencySourceKind::WorkspaceNativeGeneratedDagMetadata
        );
        assert!(
            CommittedDependencyPolicy::NativeGeneratedWorkspaceDagRlib
                .validate_plan(&metadata_plan)
                .is_err()
        );
    }

    #[test]
    fn native_generated_dag_metadata_requires_its_exact_profile_and_metadata_output_roles() {
        use crate::output_declarations::OutputClass;

        let policy = CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata;
        let plan = plan(policy, false);
        let captured = native_inputs(&plan);
        let dependencies: Vec<_> = dependencies()
            .into_iter()
            .filter(|dependency| dependency.path.ends_with(".rmeta"))
            .collect();
        let original =
            build_key(&plan, policy, &dependencies, &captured, Some(NATIVE_RECORD)).unwrap();
        assert_eq!(
            plan.source_kind.as_str(),
            "canonical-workspace-native-generated-dag-metadata-v1"
        );
        assert_eq!(policy.output_class(), RemoteDependencyOutputClass::Metadata);
        let mut outputs: Vec<_> = plan
            .outputs
            .declarations
            .iter()
            .map(|output| (output.virtual_path.as_str(), output.class))
            .collect();
        outputs.sort();
        assert_eq!(
            outputs,
            [
                ("consumer.d", OutputClass::DepInfo),
                ("libconsumer.rmeta", OutputClass::ProvisionalMetadata)
            ]
        );
        let mut relabeled = plan.clone();
        relabeled
            .outputs
            .declarations
            .iter_mut()
            .find(|output| output.virtual_path.ends_with(".rmeta"))
            .unwrap()
            .class = OutputClass::File;
        assert!(
            build_key(
                &relabeled,
                policy,
                &dependencies,
                &captured,
                Some(NATIVE_RECORD)
            )
            .is_err()
        );
        let mut wrong_role = dependencies.clone();
        wrong_role[0].role = OutputRole::Materializable;
        assert!(build_key(&plan, policy, &wrong_role, &captured, Some(NATIVE_RECORD)).is_err());
        assert!(
            NATIVE_GENERATED_DAG_METADATA_ISOLATION_PROFILE
                .contains("canonical-workspace-closed-metadata-v1 ClosedMetadata")
        );
        assert!(
            canonical_cargo_dependency_key(
                &plan,
                &toolchain(),
                &[],
                &directories(&dependencies),
                Some(NATIVE_RECORD),
                &captured
            )
            .is_err()
        );
        assert!(
            remote::remote_dependency_key(
                &plan,
                &toolchain(),
                &directories(&dependencies),
                &captured,
                Some(NATIVE_RECORD),
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime")
            )
            .is_err()
        );

        let (argv, env) = request(policy, true, false);
        let fresh = execution(&argv, &env);
        let fresh_key = remote_workspace_execution_key(
            &fresh,
            &toolchain(),
            &directories(&dependencies),
            &captured,
            Some(NATIVE_RECORD),
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
        .unwrap();
        for mutation in 0..6 {
            let mut changed = original.descriptor.clone();
            match mutation {
                0 => changed.key_epoch = 31,
                1 => changed.projection_epoch += 1,
                2 => changed.action_class = ActionClass::RustcDependencyCompile,
                3 => {
                    changed.sandbox_semantic_policy =
                        fresh_key.descriptor.sandbox_semantic_policy.clone()
                }
                4 => changed.execution_semantics = fresh_key.descriptor.execution_semantics.clone(),
                _ => changed.dependency_inputs = fresh_key.descriptor.dependency_inputs.clone(),
            }
            assert!(committed::committed_dependency_descriptor_policy(&changed).is_none());
            assert!(committed::uses_committed_dependency_namespace(&changed));
        }
        for retained_domain in 0..3 {
            let mut changed = fresh_key.descriptor.clone();
            changed.key_epoch = 6;
            changed.action_class = ActionClass::RustcDependencyCompile;
            match retained_domain {
                0 => {
                    changed.sandbox_semantic_policy =
                        original.descriptor.sandbox_semantic_policy.clone()
                }
                1 => changed.execution_semantics = original.descriptor.execution_semantics.clone(),
                _ => changed.dependency_inputs = original.descriptor.dependency_inputs.clone(),
            }
            assert!(committed::committed_dependency_descriptor_policy(&changed).is_none());
            assert!(committed::uses_committed_dependency_namespace(&changed));
        }
        for index in 0..dependencies.len() {
            for field in 0..4 {
                let mut changed = dependencies.clone();
                match field {
                    0 => changed[index].producer_action = digest(b"different action"),
                    1 => changed[index].producer_descriptor = digest(b"different descriptor"),
                    2 => changed[index].producer_manifest = digest(b"different manifest"),
                    _ => changed[index].object = ObjectId(digest(b"different whole metadata")),
                }
                assert_ne!(
                    original.action_key,
                    build_key(&plan, policy, &changed, &captured, Some(NATIVE_RECORD))
                        .unwrap()
                        .action_key
                );
            }
        }
        let mut unowned = dependencies.clone();
        unowned.remove(0);
        assert!(
            key_with_inventory(
                &plan,
                policy,
                &directories(&dependencies),
                &unowned,
                &captured,
                Some(NATIVE_RECORD)
            )
            .is_err()
        );
        assert!(build_key(&plan, policy, &[], &captured, Some(NATIVE_RECORD)).is_err());
    }

    #[test]
    fn native_generated_dag_metadata_binds_full_closure_environment_and_runtime() {
        let policy = CommittedDependencyPolicy::NativeGeneratedWorkspaceDagMetadata;
        let plan = plan(policy, true);
        let dependencies = dependencies();
        let captured = native_inputs(&plan);
        let original = build_key(&plan, policy, &dependencies, &captured, Some(NATIVE_RECORD))
            .unwrap()
            .action_key;
        for index in 0..captured.inputs.len() {
            let mut changed = captured.clone();
            changed.inputs[index].object =
                ObjectId(digest(b"changed source/generated/archive bytes"));
            assert_ne!(
                original,
                build_key(&plan, policy, &dependencies, &changed, Some(NATIVE_RECORD))
                    .unwrap()
                    .action_key
            );
        }
        for generated in [false, true] {
            let mut changed = captured.clone();
            let root = if generated {
                plan.generated_virtual_root()
            } else {
                plan.source_virtual_root()
            };
            changed
                .directory_enumerations
                .iter_mut()
                .find(|entry| entry.virtual_path.as_bytes() == root.as_bytes())
                .unwrap()
                .entries
                .push(RawBytes::from("z_empty"));
            changed
                .directory_enumerations
                .push(listing(format!("{root}/z_empty"), &[]));
            assert_ne!(
                original,
                build_key(&plan, policy, &dependencies, &changed, Some(NATIVE_RECORD))
                    .unwrap()
                    .action_key
            );
            changed.directory_enumerations.pop();
            assert!(
                build_key(&plan, policy, &dependencies, &changed, Some(NATIVE_RECORD)).is_err()
            );
        }
        for name in ["USER_PAYLOAD", "CARGO_MAKEFLAGS", "CARGO_PRIMARY_PACKAGE"] {
            let mut changed = plan.clone();
            changed
                .execution_env
                .iter_mut()
                .find(|(key, _)| key == name)
                .unwrap()
                .1
                .push_str(" changed");
            changed.keyed_env = changed.execution_env.clone();
            assert_ne!(
                original,
                build_key(
                    &changed,
                    policy,
                    &dependencies,
                    &captured,
                    Some(NATIVE_RECORD)
                )
                .unwrap()
                .action_key
            );
        }
        assert!(
            build_key(
                &plan,
                policy,
                &dependencies,
                &captured,
                Some(b"cargo:rustc-env=BUILD_TAG=other\n")
            )
            .is_err()
        );
        for field in 0..3 {
            let mut toolchain = toolchain();
            let mut retained = [39; 32];
            let mut runtime = compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime");
            match field {
                0 => toolchain.sysroot_root_digest = digest(b"changed sysroot"),
                1 => retained[0] ^= 1,
                _ => runtime = compute(remote::RUNTIME_COHORT_DOMAIN, b"changed runtime"),
            }
            assert_ne!(
                original,
                committed::remote_committed_dependency_key(
                    &plan,
                    policy,
                    &toolchain,
                    &directories(&dependencies),
                    &dependencies,
                    &captured,
                    Some(NATIVE_RECORD),
                    TOOLCHAIN,
                    &retained,
                    &runtime
                )
                .unwrap()
                .action_key
            );
        }
    }

    #[test]
    fn generated_dag_profiles_require_distinct_source_policy_record_and_complete_provenance() {
        let dependencies = dependencies();
        for (policy, kind, epoch, label) in [
            (
                POLICIES[0],
                DependencySourceKind::WorkspaceGeneratedDagRlib,
                28,
                "canonical-workspace-generated-dag-rlib-v1",
            ),
            (
                POLICIES[1],
                DependencySourceKind::WorkspaceGeneratedDagMetadata,
                29,
                "canonical-workspace-generated-dag-metadata-v1",
            ),
        ] {
            let (argv, env) = request(policy, true, false);
            let fresh = execution(&argv, &env);
            let plan = plan_generated_workspace_dag_library(&fresh).unwrap();
            let captured = inputs(&plan);
            let keyed = build_key(&plan, policy, &dependencies, &captured, Some(RECORD)).unwrap();
            assert_eq!(plan.source_kind, kind);
            assert_eq!(plan.source_kind.as_str(), label);
            assert_eq!(plan.invocation, fresh.invocation);
            assert_eq!(plan.execution_env, fresh.execution_env);
            assert_eq!(plan.generated_root.as_deref(), Some(GENERATED));
            assert_eq!(
                CommittedDependencyPolicy::from_source_kind(kind),
                Some(policy)
            );
            assert_eq!(
                keyed.descriptor.action_class,
                ActionClass::RustcWorkspaceCompile
            );
            assert_eq!(keyed.descriptor.key_epoch, epoch);
            assert_eq!(
                committed::committed_dependency_descriptor_policy(&keyed.descriptor),
                Some(policy)
            );
            assert_eq!(
                committed::remote_committed_dependency_isolation_policy(&plan, policy).unwrap(),
                keyed.descriptor.sandbox_semantic_policy
            );
            assert!(committed::uses_committed_dependency_namespace(
                &keyed.descriptor
            ));
            assert!(leaf::closed_workspace_library_descriptor_class(&keyed.descriptor).is_none());
            assert!(!leaf::uses_closed_workspace_library_namespace(
                &keyed.descriptor
            ));
            assert!(plan_generated_workspace_dag_library(&plan).is_err());
            assert!(leaf::plan_closed_workspace_library(&fresh).is_err());
            assert!(committed::plan_mixed_workspace_library(&fresh).is_err());
            assert!(build_key(&plan, policy, &dependencies, &captured, None).is_err());
            assert!(build_key(&plan, policy, &[], &captured, Some(RECORD)).is_err());
            assert!(
                canonical_cargo_dependency_key(
                    &plan,
                    &toolchain(),
                    &[],
                    &directories(&dependencies),
                    Some(RECORD),
                    &captured
                )
                .is_err()
            );
            assert!(
                remote::remote_dependency_key(
                    &plan,
                    &toolchain(),
                    &directories(&dependencies),
                    &captured,
                    Some(RECORD),
                    TOOLCHAIN,
                    &[39; 32],
                    &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime")
                )
                .is_err()
            );
            for wrong in [
                CommittedDependencyPolicy::WorkspaceRlib,
                CommittedDependencyPolicy::WorkspaceMetadata,
                CommittedDependencyPolicy::MixedWorkspaceRlib,
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
                CommittedDependencyPolicy::ImmutableDagRlib,
                CommittedDependencyPolicy::ImmutableDagMetadata,
                CommittedDependencyPolicy::WorkspaceDagRlib,
                CommittedDependencyPolicy::WorkspaceDagMetadata,
                CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata,
                CommittedDependencyPolicy::WorkspaceTerminalMetadata,
                if policy == POLICIES[0] {
                    POLICIES[1]
                } else {
                    POLICIES[0]
                },
            ] {
                assert!(
                    build_key(&plan, wrong, &dependencies, &captured, Some(RECORD)).is_err(),
                    "{wrong:?}"
                );
            }
            let fresh_key = remote_workspace_execution_key(
                &fresh,
                &toolchain(),
                &directories(&dependencies),
                &captured,
                Some(RECORD),
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
            )
            .unwrap();
            assert_ne!(keyed.action_key, fresh_key.action_key);
            assert!(
                committed::committed_dependency_descriptor_policy(&fresh_key.descriptor).is_none()
            );
            for field in 0..6 {
                let mut changed = keyed.descriptor.clone();
                match field {
                    0 => changed.key_epoch = 6,
                    1 => changed.projection_epoch += 1,
                    2 => changed.action_class = ActionClass::RustcDependencyCompile,
                    3 => {
                        changed.sandbox_semantic_policy =
                            fresh_key.descriptor.sandbox_semantic_policy.clone()
                    }
                    4 => {
                        changed.execution_semantics =
                            fresh_key.descriptor.execution_semantics.clone()
                    }
                    _ => changed.dependency_inputs = fresh_key.descriptor.dependency_inputs.clone(),
                }
                assert!(committed::committed_dependency_descriptor_policy(&changed).is_none());
                assert!(committed::uses_committed_dependency_namespace(&changed));
            }
            for retained_domain in 0..3 {
                let mut changed = fresh_key.descriptor.clone();
                changed.key_epoch = 6;
                changed.action_class = ActionClass::RustcDependencyCompile;
                match retained_domain {
                    0 => {
                        changed.sandbox_semantic_policy =
                            keyed.descriptor.sandbox_semantic_policy.clone()
                    }
                    1 => changed.execution_semantics = keyed.descriptor.execution_semantics.clone(),
                    _ => changed.dependency_inputs = keyed.descriptor.dependency_inputs.clone(),
                }
                assert!(committed::committed_dependency_descriptor_policy(&changed).is_none());
                assert!(
                    committed::uses_committed_dependency_namespace(&changed),
                    "a partial generated-DAG namespace cannot acquire generic dependency authority"
                );
            }
        }
    }

    #[test]
    fn generated_dag_keys_bind_whole_explicit_archives_and_every_implicit_producer_tuple() {
        for policy in POLICIES {
            for explicit_archive in [false, true] {
                let plan = plan(policy, explicit_archive);
                let captured = inputs(&plan);
                let dependencies = dependencies();
                let original =
                    build_key(&plan, policy, &dependencies, &captured, Some(RECORD)).unwrap();
                for index in 0..dependencies.len() {
                    for field in 0..4 {
                        let mut changed = dependencies.clone();
                        match field {
                            0 => changed[index].producer_action = digest(b"different action"),
                            1 => {
                                changed[index].producer_descriptor = digest(b"different descriptor")
                            }
                            2 => changed[index].producer_manifest = digest(b"different manifest"),
                            _ => {
                                changed[index].object =
                                    ObjectId(digest(b"different whole artifact"))
                            }
                        }
                        assert_ne!(
                            build_key(&plan, policy, &changed, &captured, Some(RECORD))
                                .unwrap()
                                .action_key,
                            original.action_key,
                            "{policy:?}, archive={explicit_archive}, candidate={index}, field={field}"
                        );
                    }
                }
                // The retained inventory is authoritative even when rustc names
                // no explicit extern. Every implicit candidate still needs its
                // committed tuple; adjacent metadata cannot erase archive bytes.
                let (mut argv, env) = request(policy, true, explicit_archive);
                argv.retain(|arg| !arg.starts_with("--extern="));
                let implicit =
                    plan_generated_workspace_dag_library(&execution(&argv, &env)).unwrap();
                build_key(
                    &implicit,
                    policy,
                    &dependencies,
                    &inputs(&implicit),
                    Some(RECORD),
                )
                .unwrap();
                assert!(
                    build_key(&implicit, policy, &[], &inputs(&implicit), Some(RECORD)).is_err()
                );
            }
        }
    }

    #[test]
    fn generated_dag_keys_bind_source_generated_topology_record_environment_and_runtime() {
        let dependencies = dependencies();
        for policy in POLICIES {
            let plan = plan(policy, true);
            let captured = inputs(&plan);
            let original = build_key(&plan, policy, &dependencies, &captured, Some(RECORD))
                .unwrap()
                .action_key;
            let keyed = |plan: &DependencyActionPlan, inputs: &ActionInputManifest, record| {
                build_key(plan, policy, &dependencies, inputs, Some(record))
                    .unwrap()
                    .action_key
            };
            for index in 0..captured.inputs.len() {
                let mut changed = captured.clone();
                changed.inputs[index].object = ObjectId(digest(b"changed source/generated bytes"));
                assert_ne!(keyed(&plan, &changed, RECORD), original);
                changed = captured.clone();
                changed.inputs[index].executable = true;
                assert_ne!(keyed(&plan, &changed, RECORD), original);
            }
            for generated in [false, true] {
                let mut changed = captured.clone();
                let root = if generated {
                    plan.generated_virtual_root()
                } else {
                    plan.source_virtual_root()
                };
                changed
                    .directory_enumerations
                    .iter_mut()
                    .find(|entry| entry.virtual_path.as_bytes() == root.as_bytes())
                    .unwrap()
                    .entries
                    .push(RawBytes::from("z_empty"));
                changed
                    .directory_enumerations
                    .push(listing(format!("{root}/z_empty"), &[]));
                assert_ne!(keyed(&plan, &changed, RECORD), original);
            }
            assert_ne!(
                keyed(
                    &plan,
                    &captured,
                    b"cargo:rerun-if-changed=another-input\ncargo:rustc-env=BUILD_TAG=generated\n"
                ),
                original
            );
            for name in ["USER_PAYLOAD", "CARGO_MAKEFLAGS", "CARGO_PRIMARY_PACKAGE"] {
                let mut changed = plan.clone();
                changed
                    .execution_env
                    .iter_mut()
                    .find(|(key, _)| key == name)
                    .unwrap()
                    .1
                    .push_str(" changed");
                changed.keyed_env = changed.execution_env.clone();
                assert_ne!(keyed(&changed, &captured, RECORD), original, "{name}");
            }
            let mut relocated = plan.clone();
            relocated.generated_root =
                Some("/__rabs/out/cargo/debug/build/consumer-other/out".into());
            relocated
                .execution_env
                .iter_mut()
                .find(|(name, _)| name == "OUT_DIR")
                .unwrap()
                .1 = relocated.generated_root.clone().unwrap();
            relocated.keyed_env = relocated.execution_env.clone();
            assert_ne!(keyed(&relocated, &captured, RECORD), original);
            for field in 0..3 {
                let mut toolchain = toolchain();
                let mut retained = [39; 32];
                let mut runtime = compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime");
                match field {
                    0 => toolchain.sysroot_root_digest = digest(b"another sysroot"),
                    1 => retained[0] ^= 1,
                    _ => runtime = compute(remote::RUNTIME_COHORT_DOMAIN, b"another runtime"),
                }
                assert_ne!(
                    committed::remote_committed_dependency_key(
                        &plan,
                        policy,
                        &toolchain,
                        &directories(&dependencies),
                        &dependencies,
                        &captured,
                        Some(RECORD),
                        TOOLCHAIN,
                        &retained,
                        &runtime
                    )
                    .unwrap()
                    .action_key,
                    original
                );
            }
            let observed = format!(
                "{OUTPUT}/libconsumer.rmeta: consumer/src/lib.rs {GENERATED}/nested/piece.rs\n# env-dep:BUILD_TAG=generated\n"
            );
            assert!(
                dep_info_closure_violation(&plan, observed.as_bytes(), |path| captured
                    .inputs
                    .iter()
                    .any(|input| input.virtual_path.as_bytes() == path.as_bytes()))
                .is_none()
            );
            assert!(
                dep_info_closure_violation(
                    &plan,
                    b"# env-dep:CARGO_MAKEFLAGS=--jobserver-auth=3,4\n",
                    |_| true
                )
                .is_some()
            );
        }
    }

    #[test]
    fn generated_dag_rejects_incomplete_trees_records_and_unbound_or_reordered_candidates() {
        let dependencies = dependencies();
        let directories = directories(&dependencies);
        for policy in POLICIES {
            let plan = plan(policy, false);
            let captured = inputs(&plan);
            build_key(&plan, policy, &dependencies, &captured, Some(RECORD)).unwrap();
            for mutation in 0..7 {
                let mut changed = captured.clone();
                match mutation {
                    0 => {
                        changed.inputs.pop();
                    }
                    1 => {
                        changed.directory_enumerations.pop();
                    }
                    2 => changed.inputs.push(changed.inputs.last().unwrap().clone()),
                    3 => changed.inputs.last_mut().unwrap().file_type = InputFileType::Symlink,
                    4 => {
                        changed.inputs.last_mut().unwrap().virtual_path =
                            RawBytes::from("/__rabs/unowned.rs")
                    }
                    5 => {
                        changed.inputs.last_mut().unwrap().virtual_path = RawBytes::new(
                            plan.generated_input_virtual_path("nested/../value.rs")
                                .into_bytes(),
                        )
                    }
                    _ => {
                        changed.directory_enumerations[0].entries.pop();
                    }
                }
                assert!(
                    build_key(&plan, policy, &dependencies, &changed, Some(RECORD)).is_err(),
                    "{policy:?}, closure mutation={mutation}"
                );
            }
            for record in [
                None,
                Some(b"cargo:rustc-env=BUILD_TAG=another\n".as_slice()),
                Some(b"cargo:rustc-env=ABSENT=value\n".as_slice()),
                Some(b"cargo:rustc-env=BUILD_TAG\n".as_slice()),
                Some(b"\xff".as_slice()),
            ] {
                assert!(build_key(&plan, policy, &dependencies, &captured, record).is_err());
            }
            for mutation in 0..8 {
                let mut changed = dependencies.clone();
                match mutation {
                    0 => changed.clear(),
                    1 => {
                        changed.pop();
                    }
                    2 => changed.swap(0, 1),
                    3 => changed[0].object = ObjectId(digest(b"different observed bytes")),
                    4 => changed[0].role = OutputRole::ProvisionalMetadata,
                    5 => changed[0].virtual_path = RawBytes::from("another.rlib"),
                    6 => changed[0].path.push('x'),
                    _ => changed.push(candidate("libunobserved.rmeta")),
                }
                assert!(
                    key_with_inventory(
                        &plan,
                        policy,
                        &directories,
                        &changed,
                        &captured,
                        Some(RECORD)
                    )
                    .is_err(),
                    "{policy:?}, witness mutation={mutation}"
                );
            }
            for mutation in 0..3 {
                let mut changed = directories.clone();
                match mutation {
                    0 => changed.clear(),
                    1 => changed[0].artifacts.swap(0, 1),
                    _ => changed[0].path = "/__rabs/out/cargo/debug/unobserved".into(),
                }
                assert!(
                    key_with_inventory(
                        &plan,
                        policy,
                        &changed,
                        &dependencies,
                        &captured,
                        Some(RECORD)
                    )
                    .is_err()
                );
            }
            for name in [
                "libhidden_proc_macro.so",
                "../libescape.rmeta",
                "libconsumer.rmeta",
            ] {
                let mut changed = vec![candidate(name)];
                changed.extend(dependencies.iter().cloned());
                changed.sort_by(|left, right| left.path.cmp(&right.path));
                assert!(
                    build_key(&plan, policy, &changed, &captured, Some(RECORD)).is_err(),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn generated_dag_planning_preserves_native_executable_and_unclosed_input_refusals() {
        let dependencies = dependencies();
        for policy in POLICIES {
            let (argv, env) = request(policy, true, false);
            for flags in [
                vec![format!("-Lnative={GENERATED}")],
                vec![format!("-Lnative={GENERATED}"), "-lstatic=generated".into()],
                vec!["-Lnative=/__rabs/out/cargo/debug/build/foreign/out".into()],
                vec!["-Cincremental=/__rabs/out/cargo/incremental".into()],
                vec!["-Ctarget-cpu=native".into()],
                vec!["--test".into()],
                vec!["--crate-type=bin".into()],
                vec!["--crate-type=proc-macro".into()],
                vec!["--crate-type=dylib".into()],
                vec!["--extern=plugin=/__rabs/out/cargo/debug/deps/libplugin.so".into()],
            ] {
                let mut changed = argv.clone();
                if flags.iter().any(|flag| flag.starts_with("--crate-type=")) {
                    changed.retain(|arg| !arg.starts_with("--crate-type="));
                }
                changed.extend(flags.iter().cloned());
                assert!(
                    plan_canonical_workspace_execution(
                        LiveRustcRequest {
                            argv: &changed,
                            env: &env,
                            cwd: WORKSPACE
                        },
                        HOST
                    )
                    .and_then(|mut fresh| {
                        fresh.source_kind = if policy == POLICIES[0] {
                            DependencySourceKind::WorkspaceGeneratedDagRlib
                        } else {
                            DependencySourceKind::WorkspaceGeneratedDagMetadata
                        };
                        validate_plan(&fresh, policy)
                    })
                    .is_err(),
                    "{policy:?}: {flags:?}"
                );
            }
            let plan = plan_generated_workspace_dag_library(&execution(&argv, &env)).unwrap();
            let captured = inputs(&plan);
            for mutation in 0..7 {
                let mut changed = plan.clone();
                match mutation {
                    0 => changed.generated_root = None,
                    1 => changed.generated_root = Some(OUTPUT.into()),
                    2 => changed.generated_root = Some("/__rabs/workspace/generated".into()),
                    3 => changed.keyed_env.retain(|(name, _)| name != "OUT_DIR"),
                    4 => changed.source_kind = DependencySourceKind::WorkspaceExecutionOnly,
                    5 => {
                        changed.source_kind = if policy == POLICIES[0] {
                            DependencySourceKind::WorkspaceGeneratedRlib
                        } else {
                            DependencySourceKind::WorkspaceGeneratedMetadata
                        }
                    }
                    _ => {
                        changed.source_kind = if policy == POLICIES[0] {
                            DependencySourceKind::WorkspaceMixedRlib
                        } else {
                            DependencySourceKind::WorkspaceMixedMetadata
                        }
                    }
                }
                assert!(
                    build_key(&changed, policy, &dependencies, &captured, Some(RECORD)).is_err(),
                    "{policy:?}, plan mutation={mutation}"
                );
            }
            let (argv, env) = request(policy, false, false);
            assert!(plan_generated_workspace_dag_library(&execution(&argv, &env)).is_err());
        }
    }

    #[test]
    fn generated_dag_keeps_empty_out_dirs_and_inert_metadata_without_inventing_producers() {
        let dependencies = dependencies();
        for policy in POLICIES {
            let plan = plan(policy, false);
            let mut empty = source_inputs(&plan);
            empty
                .directory_enumerations
                .push(listing(plan.generated_virtual_root(), &[]));
            let empty_key = build_key(&plan, policy, &dependencies, &empty, Some(RECORD)).unwrap();
            assert_ne!(
                empty_key.action_key,
                build_key(&plan, policy, &dependencies, &inputs(&plan), Some(RECORD))
                    .unwrap()
                    .action_key
            );
            assert!(build_key(&plan, policy, &dependencies, &empty, None).is_err());
            let mut missing_root = empty.clone();
            missing_root.directory_enumerations.pop();
            assert!(build_key(&plan, policy, &dependencies, &missing_root, Some(RECORD)).is_err());

            let mut candidates = directories(&dependencies);
            let inert = ExternFact {
                path: format!("{OUTPUT}/libinert.rmeta"),
                content_digest: crate::live_dependency::empty_metadata_object_digest(),
            };
            candidates[0].artifacts.insert(0, inert.clone());
            let inert_key = key_with_inventory(
                &plan,
                policy,
                &candidates,
                &dependencies,
                &empty,
                Some(RECORD),
            )
            .unwrap();
            assert_ne!(inert_key.action_key, empty_key.action_key);
            let mut invented = dependencies.clone();
            let mut witness = candidate("libinert.rmeta");
            witness.object = ObjectId(inert.content_digest);
            invented.insert(0, witness);
            assert!(
                key_with_inventory(&plan, policy, &candidates, &invented, &empty, Some(RECORD))
                    .is_err()
            );
            let (mut argv, env) = request(policy, true, false);
            argv.push(format!("--extern=inert={OUTPUT}/libinert.rmeta"));
            let explicit_empty =
                plan_generated_workspace_dag_library(&execution(&argv, &env)).unwrap();
            assert!(
                key_with_inventory(
                    &explicit_empty,
                    policy,
                    &candidates,
                    &dependencies,
                    &empty,
                    Some(RECORD)
                )
                .is_err()
            );
            candidates[0]
                .artifacts
                .retain(|artifact| artifact.path.ends_with("libinert.rmeta"));
            argv.retain(|arg| !arg.starts_with("--extern="));
            let inert_only = plan_generated_workspace_dag_library(&execution(&argv, &env)).unwrap();
            assert!(
                key_with_inventory(&inert_only, policy, &candidates, &[], &empty, Some(RECORD))
                    .is_err(),
                "an inert-only inventory remains a generated leaf, not a DAG"
            );
        }
    }

    #[test]
    fn generated_dag_preserves_every_existing_committed_and_generated_leaf_contract() {
        // Independent SHA-256 known answers taken from the committed 403acc44
        // profiles before this extension. New generated DAG classes must not
        // rewrite an existing class or invalidate its earned evidence.
        let hex = |digest: &TypedDigest| {
            digest
                .bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        for (policy, epoch, isolation, semantics) in [
            (
                CommittedDependencyPolicy::WorkspaceRlib,
                18,
                "7645dbe4c391b1201141c8ecb084877bc59ef8314af5a253fb24aa8e5838d8c4",
                "e32eb0cde05a9d2868c64afdbfd07efe066a65db35b2abb0d48058fcceacd798",
            ),
            (
                CommittedDependencyPolicy::WorkspaceMetadata,
                19,
                "e2ff1a4ce2d0559916b375474901e7ff6cb3eb4db564a7143ab331ddb6a8d0ef",
                "993c44b29aabf8633bd504503ce8aca9615ed25c27efd25fbc4c56e1934d8869",
            ),
            (
                CommittedDependencyPolicy::MixedWorkspaceRlib,
                20,
                "1685dbd7aa9ffd8e0cc511dd05472456b8d00d5599eff17fe3a1dc409a68e71b",
                "35abddd534be26bc16b1334657f1bc7c6407c4774f7effec3ee8c7ccca7825f3",
            ),
            (
                CommittedDependencyPolicy::MixedWorkspaceMetadata,
                21,
                "006c584b2b0781cd864b61ffa30408359a28c40652f7546d3e428b99f60a90cc",
                "93888e77ae8d8f586293614b4af067dfb210a73325b67066f7ff7fec019314ae",
            ),
            (
                CommittedDependencyPolicy::ImmutableDagRlib,
                10,
                "afc8f0ac4f42103f60c3611aed2b0b7db29e6b957fc96dd46ff8e21be2df6c36",
                "992d12c2e5591d9cbe82016cc19c9aa5ad3169d4550b6dabef6818b1547df5d9",
            ),
            (
                CommittedDependencyPolicy::ImmutableDagMetadata,
                11,
                "ecae566ab1d61bc925ff7bf688741482081d43e2700a7075cb1dd529df83982c",
                "99f66d82af3e77320567393a96d000b08c87e3747d38073cff17351f777a0c11",
            ),
            (
                CommittedDependencyPolicy::WorkspaceDagRlib,
                22,
                "4a377945381b25aec5f217c7d169d74f0bcd25d35f542948d0ec541679ebc72b",
                "2d7e27754af9f774737412074921b183029e1e4bc90e2343855d0618c8a9002d",
            ),
            (
                CommittedDependencyPolicy::WorkspaceDagMetadata,
                23,
                "7a91e849a723b9c31c8181726cbc69b61b385fd25a3aa5d9e9aadfc1cd3dcfdc",
                "c7be425cd75fc0e3d328badeda8a6f82958abdb7064acd66197f5b1383217ab1",
            ),
            (
                CommittedDependencyPolicy::WorkspaceTerminalLeafMetadata,
                24,
                "868799f0dacc2a0e3f0328060e50e372507ca3a394915a855aa236e71a1265bb",
                "badb038516919ecb16f5e05c5c019cc1800feefd70d262b17a10cce56977548f",
            ),
            (
                CommittedDependencyPolicy::WorkspaceTerminalMetadata,
                25,
                "7fcd18805fe434cf7de68c0ffa6daee9d45215c7a556545b817b2a31449169fb",
                "86c9e4726d18af966dec98393ca2395633d687fa50d0be1dcf2fa2abf4aff2c6",
            ),
        ] {
            let (actual_epoch, actual_isolation, actual_semantics) = match policy {
                CommittedDependencyPolicy::WorkspaceRlib => (
                    committed::KEY_EPOCH,
                    committed::isolation_policy(),
                    committed::execution_semantics(),
                ),
                CommittedDependencyPolicy::WorkspaceMetadata => (
                    committed::METADATA_KEY_EPOCH,
                    committed::metadata_isolation_policy(),
                    committed::metadata_execution_semantics(),
                ),
                CommittedDependencyPolicy::MixedWorkspaceRlib => (
                    committed::MIXED_RLIB_KEY_EPOCH,
                    committed::mixed_isolation_policy(policy.output_class()),
                    committed::mixed_execution_semantics(policy.output_class()),
                ),
                CommittedDependencyPolicy::MixedWorkspaceMetadata => (
                    committed::MIXED_METADATA_KEY_EPOCH,
                    committed::mixed_isolation_policy(policy.output_class()),
                    committed::mixed_execution_semantics(policy.output_class()),
                ),
                _ => {
                    let contract = committed::dag_contract(policy).unwrap();
                    (
                        contract.epoch,
                        compute(contract.isolation_domain, contract.profile.as_bytes()),
                        compute(contract.semantics_domain, contract.profile.as_bytes()),
                    )
                }
            };
            assert_eq!(actual_epoch, epoch, "{policy:?}");
            assert_eq!(hex(&actual_isolation), isolation, "{policy:?}");
            assert_eq!(hex(&actual_semantics), semantics, "{policy:?}");
        }
        for (policy, epoch, isolation, semantics) in [
            (
                POLICIES[0],
                26,
                "766561810f3559cc0b2f873d2ab02e49b0ec3bfbd95411f36fbbb8436df30b13",
                "a0e88ed77f1fc80fd5ee4e73fa4115fbddea0d13388979874c41e9418e1bf600",
            ),
            (
                POLICIES[1],
                27,
                "cb4f97cffe1b01a5ab5c22c1eeafe4ac576842be737eb852dee68d383947c393",
                "dc05d694ffab0b0ff5ccfc575777b121d3521278f11fefc63f6005f66676ee17",
            ),
        ] {
            let (mut argv, env) = request(policy, true, false);
            argv.retain(|arg| !arg.starts_with("--extern="));
            let fresh = execution(&argv, &env);
            let leaf = leaf::plan_closed_workspace_library(&fresh).unwrap();
            let key = leaf::remote_closed_workspace_library_key(
                &leaf,
                &toolchain(),
                &directories(&[]),
                &inputs(&leaf),
                Some(RECORD),
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
            )
            .unwrap();
            assert_eq!(key.descriptor.key_epoch, epoch);
            assert_eq!(hex(&key.descriptor.sandbox_semantic_policy), isolation);
            assert_eq!(hex(&key.descriptor.execution_semantics), semantics);
            assert!(committed::committed_dependency_descriptor_policy(&key.descriptor).is_none());
            assert!(!committed::uses_committed_dependency_namespace(
                &key.descriptor
            ));
            let dag = plan_generated_workspace_dag_library(&fresh).unwrap();
            assert!(build_key(&dag, policy, &[], &inputs(&dag), Some(RECORD)).is_err());
        }
    }
}
