//! Closed, complete-workspace Rust leaf-library cache identities.
//!
//! These workspace serving classes deliberately retain the entire sealed
//! workspace, including every directory listing. It is not an observed minimal
//! closure and unrelated workspace edits invalidate it. The canonical driver
//! must independently retain the selected ordinary library unit. Other units
//! in the Cargo operation may execute project code; local wrapper completion
//! remains untrusted. Archive and metadata executions require distinct,
//! independently supervised worker profiles without procfs or entropy devices.
//! Ordinary workspace metadata execution is not this closed profile.
//! Generated leaf libraries use separate classes that also bind the complete
//! own OUT_DIR tree and exact completed Cargo build-script record. The build
//! script itself is not cached. Native searches, explicit externs and loadable
//! implicit crate candidates remain in the fresh execution-only class. Exact
//! empty metadata is still keyed and supplied as an inert read-only input.

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

// V2 qualifies the isolated compiler action independently of other executors in
// its Cargo operation. New epochs cannot borrow the old graph-wide evidence.
// Archive and metadata policies remain independently keyed; the worker contexts
// themselves are unchanged, including the closed-metadata-v1 capability.
const KEY_EPOCH: u32 = 16;
const PROJECTION_EPOCH: u32 = 1;
const POLICY_DOMAIN: &str = "rabs.canonical-workspace-closed-rlib.isolation.v2";
const SEMANTICS_DOMAIN: &str = "rabs.canonical-workspace-closed-rlib.semantics.v2";
const SEMANTICS: &str = "completed independently supervised pure Rust leaf-library archive; selected Cargo unit may share an operation with other project executors, whose local completion claims grant no authority; the isolated compiler action cannot execute project code; complete sealed workspace and every directory listing; no externs, loadable crate candidates, generated or native inputs; exact empty search metadata remains keyed and materialized without producer authority; exact environment; authenticated drained receipt; existing publication, independent verification, class quarantine and private installation gates";
const METADATA_KEY_EPOCH: u32 = 17;
const METADATA_POLICY_DOMAIN: &str = "rabs.canonical-workspace-closed-metadata.isolation.v2";
const METADATA_SEMANTICS_DOMAIN: &str = "rabs.canonical-workspace-closed-metadata.semantics.v2";
const METADATA_SEMANTICS: &str = "completed independently supervised pure Rust leaf-library metadata check; selected Cargo unit may share an operation with other project executors, whose local completion claims grant no authority; the isolated compiler action cannot execute project code; canonical-workspace-closed-metadata-v1 explicitly negotiated in closed-metadata mode without procfs or entropy devices; complete sealed workspace and every directory listing; no externs, loadable crate candidates, generated or native inputs; exact empty search metadata remains keyed and materialized without producer authority; exact environment; authenticated drained receipt; existing publication, independent verification, class quarantine and private installation gates";

// Generated inputs extend only these new classes. The pure V2 profiles, epochs
// and component bytes above remain unchanged, including already earned evidence.
const GENERATED_KEY_EPOCH: u32 = 26;
const GENERATED_METADATA_KEY_EPOCH: u32 = 27;
const GENERATED_POLICY_DOMAIN: &str = "rabs.canonical-workspace-generated-rlib.isolation.v1";
const GENERATED_METADATA_POLICY_DOMAIN: &str =
    "rabs.canonical-workspace-generated-metadata.isolation.v1";
const GENERATED_SEMANTICS_DOMAIN: &str = "rabs.canonical-workspace-generated-rlib.semantics.v1";
const GENERATED_METADATA_SEMANTICS_DOMAIN: &str =
    "rabs.canonical-workspace-generated-metadata.semantics.v1";
const GENERATED_SEMANTICS: &str = "completed independently supervised Rust leaf-library archive with complete sealed workspace and own OUT_DIR files and directory topology; exact completed Cargo build-script stdout record and exact presented environment; build-script execution is not cached and local completion grants no authority; independently negotiated Rlib namespace without procfs or entropy devices; no externs, loadable Rust candidates, native search roots or library directives; exact empty search metadata remains an input without producer authority; exact source/generated/record generations revalidated at capture and installation; native archive output closure, authenticated drained receipt, independent generated-class samples, class quarantine and private installation gates";
const GENERATED_METADATA_SEMANTICS: &str = "completed independently supervised Rust leaf-library metadata check with complete sealed workspace and own OUT_DIR files and directory topology; exact completed Cargo build-script stdout record and exact presented environment; build-script execution is not cached and local completion grants no authority; canonical-workspace-closed-metadata-v1 explicitly negotiated in ClosedMetadata mode without procfs or entropy devices; no externs, loadable Rust candidates, native search roots or library directives; exact empty search metadata remains an input without producer authority; exact source/generated/record generations revalidated at capture and installation; authenticated drained receipt, independent generated-metadata samples, class quarantine and private installation gates";

pub(super) const ISOLATION_PROFILE: &str = "canonical-workspace-closed-rlib-v2: \
    driver-retained Cargo-selected ordinary library build; other units in the \
    operation may execute project code without granting local completion \
    authority; independently isolated compiler action; canonical-workspace-exec-v3 namespace explicitly \
    negotiated in Rlib mode; complete immutable canonical workspace with exact \
    file identities and every immediate directory listing including empty \
    directories; exact canonical argv, cwd, manifest path, output placement, \
    primary-package and lint behavior; exact complete presented environment; \
    independently retained complete toolchain and measured ELF runtime; \
    no procfs or entropy devices, only private null device, fresh private \
    output, HOME and temporary storage; no generated tree, native input, \
    explicit extern or loadable implicit Rust artifact candidate; exact empty \
    search metadata remains keyed and materialized without producer authority; no project code \
    execution, proc macro, incremental state, external linker, binary or \
    harness output, control socket or local wrapper completion authority; \
    compiler dep-info and tracked-control-variable read veto required; exact \
    archive, metadata, dep-info and diagnostic transcript capture; independently \
    authenticated request and completed drained worker receipt; existing \
    publication, independent samples, release authorization, class quarantine \
    and subscriber-owned private installation gates; no provisional outputs";

pub(super) const METADATA_ISOLATION_PROFILE: &str = "canonical-workspace-closed-metadata-v2: \
    driver-retained Cargo-selected ordinary library check; other units in the \
    operation may execute project code without granting local completion \
    authority; independently isolated compiler action; canonical-workspace-closed-metadata-v1 namespace \
    explicitly negotiated in closed-metadata mode, independently measured \
    without borrowing ordinary Metadata or Rlib execution authority; complete \
    immutable canonical workspace with exact file identities and every \
    immediate directory listing including empty directories; exact canonical \
    argv, cwd, manifest path, output placement, primary-package and lint \
    behavior; exact complete presented environment; independently retained \
    complete toolchain and measured ELF runtime; no procfs or entropy devices, \
    only private null device, fresh private output, HOME and temporary storage; \
    no generated tree, native input, explicit extern or loadable implicit Rust \
    artifact candidate; exact empty search metadata remains keyed and materialized \
    without producer authority; no project code execution, proc macro, incremental state, \
    external linker, archive, binary or harness output, control socket or local \
    wrapper completion authority; compiler dep-info and tracked-control-variable \
    read veto required; exact metadata, dep-info and diagnostic transcript \
    capture; independently authenticated request and completed drained worker \
    receipt; existing publication, independent samples, release authorization, \
    class quarantine and subscriber-owned private installation gates; no \
    provisional outputs";

pub(super) const GENERATED_ISOLATION_PROFILE: &str = "canonical-workspace-generated-rlib-v1: \
    driver-retained Cargo-selected ordinary leaf-library build; other units in \
    the operation may execute project code without granting local completion \
    authority; independently isolated compiler action; canonical-workspace-exec-v3 \
    namespace explicitly negotiated in Rlib mode; complete immutable canonical \
    workspace and complete disjoint own OUT_DIR tree, every regular file and \
    immediate directory listing including empty directories; exact logical \
    generated root and completed Cargo build-script stdout record; every \
    rustc-env directive must agree with the exact fully keyed environment; \
    build-script execution is not cached; exact argv, cwd, manifest path, output \
    placement, primary-package and lint behavior; complete retained toolchain \
    and measured ELF runtime; no procfs or entropy devices, private null device, \
    fresh private output, HOME and temporary storage; no native search roots \
    or native library directives, explicit externs or loadable implicit Rust \
    candidates; exact empty search metadata remains keyed and materialized \
    without producer authority; no project code execution, proc macros, \
    incremental state, external linker, binary or harness output, control socket \
    or local wrapper completion authority; source, generated tree and Cargo \
    record generations revalidated before capture and every installation; exact \
    dep-info and tracked-control-variable veto; exact archive, metadata, dep-info \
    and diagnostic capture, complete bundled native archive closure; authenticated \
    completed drained worker receipt; existing publication, independent generated \
    class samples, release, quarantine and private installation gates; no \
    provisional, adopted or request-owned producer authority";

pub(super) const GENERATED_METADATA_ISOLATION_PROFILE: &str = "canonical-workspace-generated-metadata-v1: \
    driver-retained Cargo-selected ordinary leaf-library check; other units in \
    the operation may execute project code without granting local completion \
    authority; independently isolated compiler action; canonical-workspace-closed-metadata-v1 \
    explicitly negotiated in ClosedMetadata mode, never ordinary Metadata or \
    Rlib authority; complete immutable canonical workspace and complete disjoint \
    own OUT_DIR tree, every regular file and immediate directory listing including \
    empty directories; exact logical generated root and completed Cargo build-script \
    stdout record; every rustc-env directive must agree with the exact fully keyed \
    environment; build-script execution is not cached; exact argv, cwd, manifest \
    path, output placement, primary-package and lint behavior; complete retained \
    toolchain and measured ELF runtime; no procfs or entropy devices, private null \
    device, fresh private output, HOME and temporary storage; no native search \
    roots or native library directives, explicit externs or loadable implicit Rust \
    candidates; exact empty search metadata remains keyed and materialized without \
    producer authority; no project code execution, proc macros, incremental state, \
    external linker, archive, binary or harness output, control socket or local \
    wrapper completion authority; source, generated tree and Cargo record \
    generations revalidated before capture and every installation; exact dep-info \
    and tracked-control-variable veto; exact metadata, dep-info and diagnostic \
    capture; authenticated completed drained worker receipt; existing publication, \
    independent generated-metadata samples, release, quarantine and private \
    installation gates; no provisional, adopted or request-owned producer authority";

/// Independently qualified workspace library profiles. Identifying a profile
/// never supplies the driver's graph or an authenticated worker receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedWorkspaceLibraryClass {
    /// Ordinary library archive under the existing closed Rlib namespace.
    Rlib,
    /// Ordinary library check under the separately negotiated closed metadata
    /// namespace, never the fresh metadata namespace with procfs and devices.
    Metadata,
    /// Closed leaf-library archive with complete generated input and Cargo
    /// run-record evidence, independently qualified from pure workspace builds.
    GeneratedRlib,
    /// Closed leaf-library check with complete generated input and Cargo
    /// run-record evidence, never ordinary metadata execution authority.
    GeneratedMetadata,
}

impl ClosedWorkspaceLibraryClass {
    const fn source_kind(self) -> DependencySourceKind {
        match self {
            Self::Rlib => DependencySourceKind::WorkspaceClosedRlib,
            Self::Metadata => DependencySourceKind::WorkspaceClosedMetadata,
            Self::GeneratedRlib => DependencySourceKind::WorkspaceGeneratedRlib,
            Self::GeneratedMetadata => DependencySourceKind::WorkspaceGeneratedMetadata,
        }
    }

    const fn output_class(self) -> RemoteDependencyOutputClass {
        match self {
            Self::Rlib | Self::GeneratedRlib => RemoteDependencyOutputClass::Rlib,
            Self::Metadata | Self::GeneratedMetadata => RemoteDependencyOutputClass::Metadata,
        }
    }

    const fn requires_generated_inputs(self) -> bool {
        matches!(self, Self::GeneratedRlib | Self::GeneratedMetadata)
    }

    const fn key_epoch(self) -> u32 {
        match self {
            Self::Rlib => KEY_EPOCH,
            Self::Metadata => METADATA_KEY_EPOCH,
            Self::GeneratedRlib => GENERATED_KEY_EPOCH,
            Self::GeneratedMetadata => GENERATED_METADATA_KEY_EPOCH,
        }
    }

    fn isolation_policy(self) -> TypedDigest {
        match self {
            Self::Rlib => compute(POLICY_DOMAIN, ISOLATION_PROFILE.as_bytes()),
            Self::Metadata => compute(
                METADATA_POLICY_DOMAIN,
                METADATA_ISOLATION_PROFILE.as_bytes(),
            ),
            Self::GeneratedRlib => compute(
                GENERATED_POLICY_DOMAIN,
                GENERATED_ISOLATION_PROFILE.as_bytes(),
            ),
            Self::GeneratedMetadata => compute(
                GENERATED_METADATA_POLICY_DOMAIN,
                GENERATED_METADATA_ISOLATION_PROFILE.as_bytes(),
            ),
        }
    }

    fn execution_semantics(self) -> TypedDigest {
        match self {
            Self::Rlib => compute(SEMANTICS_DOMAIN, SEMANTICS.as_bytes()),
            Self::Metadata => compute(METADATA_SEMANTICS_DOMAIN, METADATA_SEMANTICS.as_bytes()),
            Self::GeneratedRlib => {
                compute(GENERATED_SEMANTICS_DOMAIN, GENERATED_SEMANTICS.as_bytes())
            }
            Self::GeneratedMetadata => compute(
                GENERATED_METADATA_SEMANTICS_DOMAIN,
                GENERATED_METADATA_SEMANTICS.as_bytes(),
            ),
        }
    }

    const fn environment_domain(self) -> &'static str {
        match self {
            Self::Rlib => "rabs.canonical-workspace-closed-rlib.environment.v2",
            Self::Metadata => "rabs.canonical-workspace-closed-metadata.environment.v2",
            Self::GeneratedRlib => "rabs.canonical-workspace-generated-rlib.environment.v1",
            Self::GeneratedMetadata => "rabs.canonical-workspace-generated-metadata.environment.v1",
        }
    }

    const fn invocation_domain(self) -> &'static str {
        match self {
            Self::Rlib => "rabs.canonical-workspace-closed-rlib.invocation.v2",
            Self::Metadata => "rabs.canonical-workspace-closed-metadata.invocation.v2",
            Self::GeneratedRlib => "rabs.canonical-workspace-generated-rlib.invocation.v1",
            Self::GeneratedMetadata => "rabs.canonical-workspace-generated-metadata.invocation.v1",
        }
    }

    const fn generated_dependencies_domain(self) -> Option<&'static str> {
        match self {
            Self::Rlib | Self::Metadata => None,
            Self::GeneratedRlib => Some("rabs.canonical-workspace-generated-rlib.dependencies.v1"),
            Self::GeneratedMetadata => {
                Some("rabs.canonical-workspace-generated-metadata.dependencies.v1")
            }
        }
    }
}

/// Refine a modeled fresh workspace invocation into a closed library candidate.
/// This is pure planning, not cache authority. The coordinator must retain the
/// selected Cargo graph, exclude loadable candidates, and own the exact
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
    let output = remote::remote_dependency_output_class(&execution.invocation)
        .map_err(|error| LiveRefusal::Facts(error.to_string()))?;
    let class = match (output, execution.generated_root.is_some()) {
        (RemoteDependencyOutputClass::Rlib, false) => ClosedWorkspaceLibraryClass::Rlib,
        (RemoteDependencyOutputClass::Metadata, false) => ClosedWorkspaceLibraryClass::Metadata,
        (RemoteDependencyOutputClass::Rlib, true) => ClosedWorkspaceLibraryClass::GeneratedRlib,
        (RemoteDependencyOutputClass::Metadata, true) => {
            ClosedWorkspaceLibraryClass::GeneratedMetadata
        }
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
/// executable/native/extern inputs. Generated inputs require their distinct
/// profile; the key builder additionally requires a complete tree and matching
/// Cargo record. Directory candidates are checked by the remote shape.
pub fn validate_closed_workspace_library_plan(
    plan: &DependencyActionPlan,
) -> Result<ClosedWorkspaceLibraryClass, LiveRefusal> {
    workspace_layout(plan)?;
    let class = match plan.source_kind {
        DependencySourceKind::WorkspaceClosedRlib => ClosedWorkspaceLibraryClass::Rlib,
        DependencySourceKind::WorkspaceClosedMetadata => ClosedWorkspaceLibraryClass::Metadata,
        DependencySourceKind::WorkspaceGeneratedRlib => ClosedWorkspaceLibraryClass::GeneratedRlib,
        DependencySourceKind::WorkspaceGeneratedMetadata => {
            ClosedWorkspaceLibraryClass::GeneratedMetadata
        }
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
        || plan.generated_root.is_some() != class.requires_generated_inputs()
        || !plan.native_roots.is_empty()
        || !plan.invocation.native_libs.is_empty()
        || !remote::validate_plan_native_roots(plan)?.is_empty()
        || !plan.externs.is_empty()
        || !plan.invocation.externs.is_empty()
        || remote::remote_dependency_output_class(&plan.invocation) != Ok(class.output_class())
    {
        return Err(LiveRefusal::Facts(
            "workspace cache requires a matching closed Rust leaf-library generated-input profile without native searches, native library directives or extern inputs".into(),
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
/// Search inventories may contain only exact empty metadata, which remains
/// keyed and materialized. An implicit loadable crate must not sneak a
/// procedural macro or uncommitted producer into this class merely because no
/// `--extern` argument named it.
///
/// # Errors
/// An incomplete/reordered inventory, any loadable candidate, unsupported
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
        .flat_map(|directory| &directory.artifacts)
        .any(|artifact| {
            !super::is_empty_metadata_artifact(&artifact.path, &artifact.content_digest)
        })
    {
        return Err(LiveRefusal::Facts(
            "closed workspace leaf libraries require no loadable Rust candidates".into(),
        )
        .into());
    }
    // Empty metadata is still an exact namespace member: its path, ordering
    // and output-alias checks cannot be skipped with producer qualification.
    super::artifacts_component(plan, &[], directories)?;
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
        ClosedWorkspaceLibraryClass::GeneratedRlib,
        ClosedWorkspaceLibraryClass::GeneratedMetadata,
    ]
    .into_iter()
    .find(|class| {
        descriptor.action_class == ActionClass::RustcWorkspaceCompile
            && descriptor.key_epoch == class.key_epoch()
            && descriptor.projection_epoch == PROJECTION_EPOCH
            && descriptor.sandbox_semantic_policy == class.isolation_policy()
            && descriptor.execution_semantics == class.execution_semantics()
            && class
                .generated_dependencies_domain()
                .is_none_or(|domain| descriptor.dependency_inputs.domain == domain)
    })
}

/// Detect a claimed closed workspace leaf namespace without granting its class.
/// Retired profiles and malformed or relabeled descriptors must not acquire
/// generic immutable-dependency authority when exact leaf recognition fails.
/// The original leaf epochs 4/5 overlap other historical identities, so their
/// typed domains establish that claim; pure leaf epochs 16/17 and generated
/// leaf epochs 26/27 are reserved.
/// This does not imply committed dependency inputs or producer witnesses.
#[must_use]
pub fn uses_closed_workspace_library_namespace(descriptor: &ActionDescriptor) -> bool {
    matches!(
        descriptor.key_epoch,
        KEY_EPOCH | METADATA_KEY_EPOCH | GENERATED_KEY_EPOCH | GENERATED_METADATA_KEY_EPOCH
    ) || [
        descriptor.sandbox_semantic_policy.domain,
        descriptor.execution_semantics.domain,
        descriptor.dependency_inputs.domain,
    ]
    .into_iter()
    .any(|domain| {
        domain.starts_with("rabs.canonical-workspace-closed-rlib.")
            || domain.starts_with("rabs.canonical-workspace-closed-metadata.")
            || domain.starts_with("rabs.canonical-workspace-generated-rlib.")
            || domain.starts_with("rabs.canonical-workspace-generated-metadata.")
    })
}

/// Bind the complete retained workspace and exact closed library execution.
/// There is deliberately no source projection, environment exemption or
/// dependency-artifact equivalence in either closed workspace cache class.
///
/// # Errors
/// An invalid class, incomplete file/directory closure, missing or mismatched
/// generated run record, unbound toolchain/runtime, or loadable Rust candidates.
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
    if build_script_output.is_some() && !class.requires_generated_inputs() {
        return Err(LiveRefusal::Facts(
            "closed workspace leaf libraries cannot consume a build-script run record".into(),
        )
        .into());
    }
    let mut key = captured_action_key(
        plan,
        toolchain,
        &[],
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
    if let Some(domain) = class.generated_dependencies_domain() {
        // The base component binds the exact ordered candidate inventory and
        // completed Cargo stdout bytes. Preserve both beneath a distinct
        // generated-class domain so a pure/fresh component cannot be relabeled.
        let mut dependencies = CanonicalEncoder::new();
        dependencies
            .str(key.descriptor.dependency_inputs.domain)
            .bytes(&key.descriptor.dependency_inputs.bytes);
        key.descriptor.dependency_inputs = compute(domain, &dependencies.finish());
    }
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
    const GENERATED_CLASSES: [ClosedWorkspaceLibraryClass; 2] = [
        ClosedWorkspaceLibraryClass::GeneratedRlib,
        ClosedWorkspaceLibraryClass::GeneratedMetadata,
    ];
    const GENERATED: &str = "/__rabs/out/cargo/debug/build/leaf-123/out";
    const GENERATED_RECORD: &[u8] =
        b"cargo:rerun-if-changed=build.rs\ncargo:rustc-env=GENERATED_MARKER=retained\n";

    fn request(class: ClosedWorkspaceLibraryClass) -> (Vec<String>, Vec<(String, String)>) {
        let (argv, mut env) = (
            [
                "/__rabs/toolchain/bin/rustc",
                "--crate-name=leaf",
                "--crate-type=lib",
                "--edition=2021",
                "leaf/src/lib.rs",
                "--error-format=json",
                "--json=artifacts",
                "--warn=dead_code",
                match class.output_class() {
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
            .collect::<Vec<_>>(),
        );
        if class.requires_generated_inputs() {
            env.push(("OUT_DIR".into(), GENERATED.into()));
            env.push(("GENERATED_MARKER".into(), "retained".into()));
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

    fn generated_inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        assert!(plan.generated_root.is_some());
        let mut captured = inputs(plan);
        captured
            .inputs
            .extend(
                ["value.rs", "nested/piece.rs"]
                    .into_iter()
                    .map(|relative| PositiveInput {
                        virtual_path: RawBytes::new(
                            plan.generated_input_virtual_path(relative).into_bytes(),
                        ),
                        object: ObjectId(compute(
                            "rabs.test.workspace-generated-input.v1",
                            relative.as_bytes(),
                        )),
                        file_type: InputFileType::Regular,
                        executable: false,
                        symlink_resolution: Vec::new(),
                    }),
            );
        captured.directory_enumerations.extend([
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
        captured
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
        key_with_record(plan, inputs, None)
    }

    fn key_with_record(
        plan: &DependencyActionPlan,
        inputs: &ActionInputManifest,
        record: Option<&[u8]>,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_closed_workspace_library_key(
            plan,
            &toolchain(),
            &directories(plan),
            inputs,
            record,
            TOOLCHAIN,
            &[39; 32],
            &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
    }

    #[test]
    fn generated_leaf_classes_require_their_own_profile_record_and_enforced_output_mode() {
        for (class, source, epoch) in [
            (
                ClosedWorkspaceLibraryClass::GeneratedRlib,
                "canonical-workspace-generated-rlib-v1",
                26,
            ),
            (
                ClosedWorkspaceLibraryClass::GeneratedMetadata,
                "canonical-workspace-generated-metadata-v1",
                27,
            ),
        ] {
            let (argv, env) = request(class);
            let fresh = execution(&argv, &env);
            let plan = plan_closed_workspace_library(&fresh).unwrap();
            let captured = generated_inputs(&plan);
            let keyed = key_with_record(&plan, &captured, Some(GENERATED_RECORD)).unwrap();
            assert_eq!(
                validate_closed_workspace_library_plan(&plan).unwrap(),
                class
            );
            assert_eq!(plan.source_kind.as_str(), source);
            assert_eq!(plan.generated_root.as_deref(), Some(GENERATED));
            assert_eq!(plan.invocation, fresh.invocation);
            assert_eq!(plan.execution_env, fresh.execution_env);
            assert_eq!(plan.keyed_env, plan.execution_env);
            assert_eq!(keyed.descriptor.key_epoch, epoch);
            assert_eq!(
                closed_workspace_library_descriptor_class(&keyed.descriptor),
                Some(class)
            );
            assert!(uses_closed_workspace_library_namespace(&keyed.descriptor));
            assert!(
                !super::super::workspace_dependency_cache::uses_committed_dependency_namespace(
                    &keyed.descriptor
                )
            );
            assert!(
                super::super::workspace_dependency_cache::CommittedDependencyPolicy::from_source_kind(
                    plan.source_kind
                )
                .is_none(),
                "generated leaves do not acquire committed-input authority"
            );
            let fresh_key = remote_workspace_execution_key(
                &fresh,
                &toolchain(),
                &directories(&fresh),
                &captured,
                Some(GENERATED_RECORD),
                TOOLCHAIN,
                &[39; 32],
                &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
            )
            .unwrap();
            assert_ne!(keyed.action_key, fresh_key.action_key);
            assert!(closed_workspace_library_descriptor_class(&fresh_key.descriptor).is_none());
            assert!(
                key(&plan, &captured).is_err(),
                "Cargo run record is mandatory"
            );
            assert!(plan_closed_workspace_library(&plan).is_err());
            assert!(
                canonical_cargo_dependency_key(
                    &plan,
                    &toolchain(),
                    &[],
                    &directories(&plan),
                    Some(GENERATED_RECORD),
                    &captured
                )
                .is_err(),
                "generated workspace output cannot acquire local dependency authority"
            );
            assert!(
                remote::remote_dependency_key(
                    &plan,
                    &toolchain(),
                    &directories(&plan),
                    &captured,
                    Some(GENERATED_RECORD),
                    TOOLCHAIN,
                    &[39; 32],
                    &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
                )
                .is_err()
            );

            let pure = match class.output_class() {
                RemoteDependencyOutputClass::Rlib => ClosedWorkspaceLibraryClass::Rlib,
                RemoteDependencyOutputClass::Metadata => ClosedWorkspaceLibraryClass::Metadata,
            };
            let mut relabeled = plan.clone();
            relabeled.source_kind = pure.source_kind();
            assert!(validate_closed_workspace_library_plan(&relabeled).is_err());
            assert!(key_with_record(&relabeled, &captured, Some(GENERATED_RECORD)).is_err());
            relabeled = plan.clone();
            relabeled.source_kind = match class.output_class() {
                RemoteDependencyOutputClass::Rlib => {
                    DependencySourceKind::WorkspaceGeneratedMetadata
                }
                RemoteDependencyOutputClass::Metadata => {
                    DependencySourceKind::WorkspaceGeneratedRlib
                }
            };
            assert!(validate_closed_workspace_library_plan(&relabeled).is_err());

            for mutation in 0..6 {
                let mut changed = keyed.descriptor.clone();
                match mutation {
                    0 => changed.key_epoch = pure.key_epoch(),
                    1 => changed.sandbox_semantic_policy = pure.isolation_policy(),
                    2 => changed.execution_semantics = pure.execution_semantics(),
                    3 => changed.dependency_inputs = fresh_key.descriptor.dependency_inputs.clone(),
                    4 => changed.action_class = ActionClass::RustcDependencyCompile,
                    _ => changed.projection_epoch += 1,
                }
                assert!(closed_workspace_library_descriptor_class(&changed).is_none());
                assert!(uses_closed_workspace_library_namespace(&changed));
            }
            let mut disguised = keyed.descriptor.clone();
            disguised.key_epoch = super::super::LIVE_DEPENDENCY_KEY_EPOCH;
            disguised.action_class = ActionClass::RustcDependencyCompile;
            disguised.sandbox_semantic_policy = compute(super::super::DOMAIN_LIVE_ISOLATION, b"x");
            disguised.execution_semantics = compute(super::super::DOMAIN_LIVE_EXECUTION, b"x");
            assert!(uses_closed_workspace_library_namespace(&disguised));
            assert!(closed_workspace_library_descriptor_class(&disguised).is_none());
        }
    }

    #[test]
    fn generated_leaf_keys_bind_every_generated_byte_listing_record_and_environment_value() {
        for class in GENERATED_CLASSES {
            let plan = plan(class);
            let captured = generated_inputs(&plan);
            let original = key_with_record(&plan, &captured, Some(GENERATED_RECORD))
                .unwrap()
                .action_key;
            let compute_key =
                |plan: &DependencyActionPlan, inputs: &ActionInputManifest, record| {
                    key_with_record(plan, inputs, Some(record))
                        .unwrap()
                        .action_key
                };
            for index in 0..captured.inputs.len() {
                let mut changed = captured.clone();
                changed.inputs[index].object = ObjectId(compute(
                    "rabs.test.workspace-generated-input.v1",
                    b"changed bytes",
                ));
                assert_ne!(compute_key(&plan, &changed, GENERATED_RECORD), original);
                changed = captured.clone();
                changed.inputs[index].executable = !changed.inputs[index].executable;
                assert_ne!(compute_key(&plan, &changed, GENERATED_RECORD), original);
            }
            let mut changed = captured.clone();
            changed
                .directory_enumerations
                .iter_mut()
                .find(|entry| {
                    entry.virtual_path.as_bytes() == plan.generated_virtual_root().as_bytes()
                })
                .unwrap()
                .entries
                .push(RawBytes::from("z_empty"));
            changed
                .directory_enumerations
                .push(listing(plan.generated_input_virtual_path("z_empty"), &[]));
            assert_ne!(compute_key(&plan, &changed, GENERATED_RECORD), original);

            let changed_record = b"cargo:rerun-if-changed=another-input\ncargo:rustc-env=GENERATED_MARKER=retained\n";
            assert_ne!(compute_key(&plan, &captured, changed_record), original);
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
                    compute_key(&changed, &captured, GENERATED_RECORD),
                    original,
                    "{name}"
                );
            }
            let mut changed = plan.clone();
            changed.generated_root = Some("/__rabs/out/cargo/debug/build/leaf-other/out".into());
            changed
                .execution_env
                .iter_mut()
                .find(|(name, _)| name == "OUT_DIR")
                .unwrap()
                .1 = changed.generated_root.clone().unwrap();
            changed.keyed_env = changed.execution_env.clone();
            assert_ne!(compute_key(&changed, &captured, GENERATED_RECORD), original);

            // Build scripts that emit only cfg/env directives still have a
            // real empty OUT_DIR. Its root listing remains a required input.
            let mut empty = inputs(&plan);
            empty
                .directory_enumerations
                .push(listing(plan.generated_virtual_root(), &[]));
            let empty_key = compute_key(&plan, &empty, GENERATED_RECORD);
            assert_ne!(empty_key, original);
            empty.directory_enumerations.pop();
            assert!(key_with_record(&plan, &empty, Some(GENERATED_RECORD)).is_err());

            let observed = format!(
                "{OUTPUT}/libleaf.rmeta: leaf/src/lib.rs {GENERATED}/nested/piece.rs\n# env-dep:GENERATED_MARKER=retained\n"
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
                .is_some(),
                "generated inputs do not remove the tracked-control read veto"
            );
        }
    }

    #[test]
    fn generated_leaf_keys_refuse_incomplete_trees_and_mismatched_cargo_records() {
        for class in GENERATED_CLASSES {
            let plan = plan(class);
            let captured = generated_inputs(&plan);
            key_with_record(&plan, &captured, Some(GENERATED_RECORD)).unwrap();
            for mutation in 0..6 {
                let mut changed = captured.clone();
                match mutation {
                    0 => {
                        changed.inputs.pop();
                    }
                    1 => {
                        changed.directory_enumerations.pop();
                    }
                    2 => {
                        changed.inputs.push(changed.inputs.last().unwrap().clone());
                    }
                    3 => changed.inputs.last_mut().unwrap().file_type = InputFileType::Symlink,
                    4 => {
                        changed.inputs.last_mut().unwrap().virtual_path =
                            RawBytes::from("/__rabs/out/unowned.rs")
                    }
                    _ => {
                        changed.inputs.last_mut().unwrap().virtual_path = RawBytes::new(
                            plan.generated_input_virtual_path("nested/../value.rs")
                                .into_bytes(),
                        )
                    }
                }
                assert!(
                    key_with_record(&plan, &changed, Some(GENERATED_RECORD)).is_err(),
                    "{class:?}, mutation {mutation}"
                );
            }
            for record in [
                None,
                Some(b"cargo:rustc-env=GENERATED_MARKER=another\n".as_slice()),
                Some(b"cargo:rustc-env=NOT_PRESENT=value\n".as_slice()),
                Some(b"cargo:rustc-env=GENERATED_MARKER\n".as_slice()),
                Some(b"\xff".as_slice()),
            ] {
                assert!(key_with_record(&plan, &captured, record).is_err());
            }
            for mutation in 0..4 {
                let mut changed = plan.clone();
                match mutation {
                    0 => changed.generated_root = None,
                    1 => changed.generated_root = Some("/__rabs/workspace/generated".into()),
                    2 => changed.generated_root = Some(OUTPUT.into()),
                    _ => changed.keyed_env.retain(|(name, _)| name != "OUT_DIR"),
                }
                assert!(key_with_record(&changed, &captured, Some(GENERATED_RECORD)).is_err());
            }
        }
    }

    #[test]
    fn generated_leaf_planning_refuses_native_searches_and_all_executable_or_dependency_shapes() {
        for class in GENERATED_CLASSES {
            let (argv, env) = request(class);
            for flags in [
                vec![format!("-Lnative={GENERATED}")],
                vec![format!("-Lnative={GENERATED}"), "-lstatic=leaf".into()],
                vec!["-Lnative=/__rabs/out/cargo/debug/build/foreign/out".into()],
                vec!["--extern=other=/__rabs/out/cargo/debug/deps/libother.rlib".into()],
                vec!["-Cincremental=/__rabs/out/cargo/incremental".into()],
                vec!["--test".into()],
                vec!["--crate-type=proc-macro".into()],
            ] {
                let mut changed = argv.clone();
                if flags.iter().any(|arg| arg.starts_with("--crate-type=")) {
                    changed.retain(|arg| !arg.starts_with("--crate-type="));
                }
                changed.extend(flags.iter().cloned());
                let candidate = plan_canonical_workspace_execution(
                    LiveRustcRequest {
                        argv: &changed,
                        env: &env,
                        cwd: WORKSPACE,
                    },
                    HOST,
                )
                .and_then(|fresh| plan_closed_workspace_library(&fresh));
                assert!(candidate.is_err(), "{class:?}: {flags:?}");
            }
            let plan = plan_closed_workspace_library(&execution(&argv, &env)).unwrap();
            let captured = generated_inputs(&plan);
            for extension in ["rlib", "rmeta", "so"] {
                let mut candidates = directories(&plan);
                candidates[0].artifacts.push(ExternFact {
                    path: format!("{OUTPUT}/libimplicit.{extension}"),
                    content_digest: compute("rabs.test.workspace-generated-input.v1", b"candidate"),
                });
                assert!(
                    remote_closed_workspace_library_shape(&plan, &candidates, TOOLCHAIN).is_err()
                );
                assert!(
                    remote_closed_workspace_library_key(
                        &plan,
                        &toolchain(),
                        &candidates,
                        &captured,
                        Some(GENERATED_RECORD),
                        TOOLCHAIN,
                        &[39; 32],
                        &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn generated_classes_preserve_committed_pure_v2_policy_bytes() {
        // These known answers were taken from the existing pure profiles before
        // generated-class support. Extending the class set must not invalidate
        // pure-workspace publications or silently change their contracts.
        let hex = |digest: TypedDigest| {
            digest
                .bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        for (class, isolation, semantics) in [
            (
                ClosedWorkspaceLibraryClass::Rlib,
                "f5839bfd9d94bd8a6fe3d3b606f3d71cec7e431709203afd239fe331ceb60663",
                "50a212bc708caceb0a35f8a5ffad5f79bcb08678070b1e3d5501a332ab9b8646",
            ),
            (
                ClosedWorkspaceLibraryClass::Metadata,
                "ab9958a55d6a16a1f5f02acf5dd9c688edabab759bf0823ed1c2f08aa117da65",
                "3820100f85acc23cc06aa8818e186435ca2c92a75134feb55e19da9c47a321e9",
            ),
        ] {
            let plan = plan(class);
            let key = key(&plan, &inputs(&plan)).unwrap();
            assert_eq!(hex(key.descriptor.sandbox_semantic_policy), isolation);
            assert_eq!(hex(key.descriptor.execution_semantics), semantics);
            assert_eq!(
                key.descriptor.key_epoch,
                if class == ClosedWorkspaceLibraryClass::Rlib {
                    16
                } else {
                    17
                }
            );
            assert_eq!(
                key.descriptor.dependency_inputs.domain,
                super::super::DOMAIN_LIVE_ARTIFACTS
            );
        }
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
                    ClosedWorkspaceLibraryClass::Rlib => "canonical-workspace-closed-rlib-v2",
                    ClosedWorkspaceLibraryClass::Metadata =>
                        "canonical-workspace-closed-metadata-v2",
                    ClosedWorkspaceLibraryClass::GeneratedRlib =>
                        "canonical-workspace-generated-rlib-v1",
                    ClosedWorkspaceLibraryClass::GeneratedMetadata =>
                        "canonical-workspace-generated-metadata-v1",
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
            assert!(!uses_closed_workspace_library_namespace(
                &fresh_key.descriptor
            ));
            assert!(
                !super::super::workspace_dependency_cache::uses_committed_dependency_namespace(
                    &key.descriptor,
                )
            );
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
        assert_eq!(archive_key.descriptor.key_epoch, 16);
        assert_eq!(metadata_key.descriptor.key_epoch, 17);
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
    fn pure_workspace_libraries_refuse_generated_inputs_and_all_leaf_classes_refuse_native_inputs()
    {
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
            let mut relabeled = plan_closed_workspace_library(&execution(&argv, &env)).unwrap();
            assert_eq!(
                validate_closed_workspace_library_plan(&relabeled)
                    .unwrap()
                    .output_class(),
                class.output_class()
            );
            relabeled.source_kind = class.source_kind();
            assert!(validate_closed_workspace_library_plan(&relabeled).is_err());
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
    fn closed_workspace_libraries_keep_exact_empty_metadata_in_the_action_key() {
        for class in CLASSES {
            let plan = plan(class);
            let keyed = |directories: &[DependencyDirectoryFact]| {
                remote_closed_workspace_library_key(
                    &plan,
                    &toolchain(),
                    directories,
                    &inputs(&plan),
                    None,
                    TOOLCHAIN,
                    &[39; 32],
                    &compute(remote::RUNTIME_COHORT_DOMAIN, b"runtime"),
                )
            };
            let mut candidates = directories(&plan);
            let original = keyed(&candidates).unwrap().action_key;
            candidates[0].artifacts.push(ExternFact {
                path: format!("{OUTPUT}/libchecked_binary.rmeta"),
                content_digest: super::super::empty_metadata_object_digest(),
            });
            let with_empty = keyed(&candidates).unwrap().action_key;
            assert_ne!(with_empty, original, "empty metadata must stay keyed");
            candidates[0].artifacts[0].path = format!("{OUTPUT}/libother_binary.rmeta");
            assert_ne!(keyed(&candidates).unwrap().action_key, with_empty);
            candidates[0].artifacts[0].content_digest.bytes[0] ^= 1;
            assert!(
                keyed(&candidates).is_err(),
                "nonempty unknown metadata must refuse"
            );
            candidates[0].artifacts[0].content_digest =
                super::super::empty_metadata_object_digest();
            candidates[0].artifacts[0].path = format!("{OUTPUT}/libother_binary.rlib");
            assert!(
                keyed(&candidates).is_err(),
                "empty archives are not inert metadata"
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
            assert!(uses_closed_workspace_library_namespace(&descriptor));
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
                assert!(uses_closed_workspace_library_namespace(&other));
            }
        }
    }

    #[test]
    fn isolated_workspace_leaf_v2_requires_fresh_evidence_and_blocks_legacy_downgrades() {
        for (class, old_epoch, isolation, semantics) in [
            (
                ClosedWorkspaceLibraryClass::Rlib,
                4,
                "rabs.canonical-workspace-closed-rlib.isolation.v1",
                "rabs.canonical-workspace-closed-rlib.semantics.v1",
            ),
            (
                ClosedWorkspaceLibraryClass::Metadata,
                5,
                "rabs.canonical-workspace-closed-metadata.isolation.v1",
                "rabs.canonical-workspace-closed-metadata.semantics.v1",
            ),
        ] {
            let plan = plan(class);
            let keyed = key(&plan, &inputs(&plan)).unwrap();
            assert_eq!(keyed.descriptor.key_epoch, old_epoch + 12);
            assert!(
                keyed
                    .descriptor
                    .sandbox_semantic_policy
                    .domain
                    .ends_with(".v2")
            );
            assert!(keyed.descriptor.execution_semantics.domain.ends_with(".v2"));
            assert_eq!(
                closed_workspace_library_descriptor_class(&keyed.descriptor),
                Some(class)
            );
            // Old epoch and each old domain independently veto recognition.
            // Relabeling their action class must still trigger the namespace
            // guard before a coordinator's generic immutable fallback.
            for change in 0..4 {
                let mut old = keyed.descriptor.clone();
                match change {
                    0 => old.key_epoch = old_epoch,
                    1 => old.sandbox_semantic_policy.domain = isolation,
                    2 => old.execution_semantics.domain = semantics,
                    _ => {
                        old.key_epoch = old_epoch;
                        old.sandbox_semantic_policy.domain = isolation;
                        old.execution_semantics.domain = semantics;
                    }
                }
                assert!(closed_workspace_library_descriptor_class(&old).is_none());
                assert!(uses_closed_workspace_library_namespace(&old));
                assert_ne!(compute_action_key(&old).final_key, keyed.action_key);
                old.action_class = ActionClass::RustcDependencyCompile;
                old.key_epoch = super::super::LIVE_DEPENDENCY_KEY_EPOCH;
                assert!(closed_workspace_library_descriptor_class(&old).is_none());
                assert!(uses_closed_workspace_library_namespace(&old));
            }
            // Preserve the separately measured worker namespace. The v2
            // cache policy never invents a closed-metadata-v2 capability.
            let profile = match class {
                ClosedWorkspaceLibraryClass::Rlib => ISOLATION_PROFILE,
                ClosedWorkspaceLibraryClass::Metadata => METADATA_ISOLATION_PROFILE,
                ClosedWorkspaceLibraryClass::GeneratedRlib => GENERATED_ISOLATION_PROFILE,
                ClosedWorkspaceLibraryClass::GeneratedMetadata => {
                    GENERATED_METADATA_ISOLATION_PROFILE
                }
            };
            assert!(profile.contains("other units in the operation may execute project code"));
            assert!(profile.contains("local wrapper completion authority"));
            if class == ClosedWorkspaceLibraryClass::Metadata {
                assert!(profile.contains("canonical-workspace-closed-metadata-v1 namespace"));
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
