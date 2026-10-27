//! Dependency actions executed in a closed worker view.
//!
//! This class has distinct isolation and platform identity from unsandboxed
//! local dependency execution. The worker retains subscriber source, cwd,
//! toolchain and output spellings, mounts the complete captured package,
//! toolchain, completed build-script OUT_DIR and exact dependency candidate
//! directories read-only, and supplies private empty backings only for
//! directories with an empty inventory.
//! A remote result cannot be offered as an edge-local execution.
//!
//! The runtime digest is observed by rabs_sandbox::runtime_cohort on both hosts
//! and retained in a sparse read-only view checked before and after execution.
//! A configured cohort label
//! or target triple cannot replace that observation. This pure module checks
//! its domain and binds its bytes; authenticated delivery, observation and
//! attempt authority remain the callers' responsibilities.

use rabs_protocol::input_evidence::ActionInputManifest;
use rabs_protocol::result_identity::TypedDigest;

use super::{
    DependencyActionPlan, DependencyDirectoryFact, ExternFact, LiveDependencyKey, LiveRefusal,
    PlannedExtern, ToolchainFacts, live_dependency_key, plain_path_in_profile, within,
};
use crate::action_key::compute_action_key;
use crate::canonical::CanonicalEncoder;
use crate::extern_resolution::DependencyArtifactKind;
use crate::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use crate::invocation::NormalizedRustcInvocation;
use crate::output_derivation::derive_dependency_output_declarations;
use crate::output_platform::{CpuBaseline, OutputPlatformContract};
use crate::typed_digest::compute;

/// Required observer domain; kept in sync with the sandbox runtime observer.
pub const RUNTIME_COHORT_DOMAIN: &str = "rabs.rustc-host-runtime.v2";
/// Isolation policy domain for the remote metadata dependency class.
pub const REMOTE_DEPENDENCY_ISOLATION_DOMAIN: &str = "rabs.remote-leaf.isolation.v1";
/// Canonical Cargo planning and closed worker execution form a distinct lane.
/// Neither ordinary worker receipts nor local canonical checks supply its
/// evidence, even when source bytes and compiler options happen to match.
pub const CANONICAL_REMOTE_DEPENDENCY_ISOLATION_DOMAIN: &str =
    "rabs.canonical-cargo-remote-dependency.isolation.v1";
/// Complete retained toolchain bytes, joined with the observed compiler contract.
pub const REMOTE_TOOLCHAIN_DOMAIN: &str = "rabs.remote-leaf.toolchain.v1";
/// Versioned execution policy, deliberately separate from local-edge evidence.
pub const REMOTE_DEPENDENCY_ISOLATION_PROFILE: &str = "remote-dependency-metadata-v7: \
    Linux worker namespace; subscriber paths preserved; complete regular-file \
    dependency source, exact toolchain and complete crate-candidate inventories \
    mounted read-only; explicit rmeta and complete rlib extern bytes retained; \
    complete generated OUT_DIR tree retained read-only at its original path, \
    including every empty directory and exact keyed directory listing, with captured Cargo stdout and rustc-env \
    directives bound; build-script execution is not cached; no bare extern, \
    proc-macro or native inputs; metadata and dep-info \
    only; shared input/output roots use exact read-only file mounts above private \
    writable output backing, with owned input placeholders verified and excluded \
    from exact output capture; declared outputs cannot alias inputs; empty inventories \
    receive private empty backings; outputs private until complete authenticated \
    delivery; network denied; compiler environment preserved by dependency-env-v2 \
    except process-local jobserver descriptors; all loader paths within the exact \
    toolchain or independently observed dependency-exec-v8 directories without \
    dynamic libraries, including Cargo output parents; selected host ELF runtime \
    bytes, exact loader symlink topology and loader cache captured and mounted \
    read-only in a sparse /usr view without other host /usr or /etc/alternatives \
    contents; runtime, CPU and filesystem cohort observed and independently \
    matched before execution; retained runtime checked again after cleanup; \
    private proc and device views remain available and later dynamic loading \
    and nondeterministic runtime inputs are not a general workspace closure; \
    dep-info closure and tracked-environment checks required before coordinator-only \
    publication; full-result readiness";

/// Archive emission has a separately enforced view. In particular, LLVM's
/// integrated assembler may read `.incbin` files without listing them in
/// dep-info; it must not see procfs, randomness devices, or the host filesystem.
/// This policy is never evidence for an unsandboxed local archive compilation.
pub const REMOTE_RLIB_ISOLATION_PROFILE: &str = "remote-dependency-rlib-v2: \
    dependency-exec-v8 rlib execution mode; original subscriber paths preserved; \
    complete regular-file package, generated OUT_DIR, exact toolchain, Rust \
    dependency candidate inventories and observed selected ELF runtime retained \
    read-only; generated trees include every empty directory and exact keyed directory listing; \
    exact compiler environment except process-local jobserver descriptors; \
    network denied; no procfs or general device filesystem, only deterministic \
    /dev/null; fresh private empty home, temporary and output storage; LLVM \
    integrated archive codegen only with no proc macros, native link inputs, \
    external linker, incremental state or unmodeled output options; every \
    assembler include/incbin read resolves within retained keyed inputs or fails; \
    required dep-info and optional detached metadata accompany the complete rlib; \
    exact private output capture, runtime/input revalidation, authenticated delivery \
    and coordinator-only publication; full-result readiness";

const CANONICAL_REMOTE_DEPENDENCY_ISOLATION_PROFILE: &str = "canonical-cargo-remote-metadata-v4: canonical-dependency-exec-v4 negotiated \
    separately from dependency-exec-v8; coordinator-owned canonical Cargo \
    planning and retained logical-to-physical mappings; exact canonical rustc \
    argv, cwd, environment and replay bytes; external registry, Git or checked \
    directory-source metadata and dep-info only; closed worker package, complete \
    toolchain and candidate inventories with independently matched retained ELF \
    runtime; no outer Cargo workspace, complete Cargo home or coordinator control \
    socket mounted; existing authenticated delivery, input revalidation, closure, \
    sampling and release authorization remain required; complete generated OUT_DIR \
    retained read-only at its exact canonical spelling, including every empty directory \
    and exact keyed directory listing, \
    with exact persisted Cargo stdout and matching rustc-env directives keyed; \
    no workspace, archive, build-script execution or proc-macro authority";

const CANONICAL_REMOTE_RLIB_ISOLATION_PROFILE: &str = "canonical-cargo-remote-rlib-v3: \
    canonical-dependency-exec-v4 rlib mode negotiated independently from metadata \
    and ordinary dependency-exec-v8; coordinator-owned canonical Cargo planning \
    and retained logical-to-physical mappings; exact canonical rustc argv, cwd, \
    environment and replay bytes; complete immutable external registry, Git or \
    checked directory-source package, toolchain, exact Rust candidate inventories \
    and independently matched retained ELF runtime; existing closed archive \
    namespace with no procfs, entropy devices, outer Cargo workspace/home or \
    coordinator control socket; fresh private output, HOME and temporary storage; \
    all assembler include/incbin inputs must resolve within retained keyed bytes \
    or fail; existing exact output validation, authenticated delivery, input \
    revalidation, sampling and release authorization required; no local codegen \
    capture or workspace publication; complete generated OUT_DIR retained read-only \
    at its exact canonical spelling, including every empty directory and exact keyed \
    directory listing, with exact persisted \
    Cargo stdout and matching rustc-env directives keyed; no build-script execution, \
    proc macros or native linking";

/// Output and isolation class selected from a bounded compiler invocation.
/// This is not execution or serving authority: the caller must enforce the
/// matching worker context and retain every observed input through completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteDependencyOutputClass {
    /// Existing metadata-only execution and cache policy.
    Metadata,
    /// Pure Rust archive codegen in the stricter, closed filesystem profile.
    Rlib,
}

/// Classify exact supported remote output modes. Native linking, mixed crate
/// types, implicit output defaults and additional LLVM/assembly outputs cannot
/// borrow the archive profile. Full output naming/options are checked by the
/// ordinary dependency output adapter before dispatch.
pub fn remote_dependency_output_class(
    invocation: &NormalizedRustcInvocation,
) -> Result<RemoteDependencyOutputClass, RemoteDependencyRefusal> {
    let has = |kind| invocation.emit.iter().any(|actual| actual == kind);
    if invocation.emit.len() == 2 && has("metadata") && has("dep-info") {
        return Ok(RemoteDependencyOutputClass::Metadata);
    }
    if invocation.crate_types.len() == 1
        && matches!(invocation.crate_types[0].as_str(), "lib" | "rlib")
        && has("dep-info")
        && has("link")
        && (invocation.emit.len() == 2 || (invocation.emit.len() == 3 && has("metadata")))
    {
        return Ok(RemoteDependencyOutputClass::Rlib);
    }
    Err(RemoteDependencyRefusal::OutputClass)
}

/// Exact isolation-policy component used by the remote key builder. Daemon
/// publication and serving boundaries compare this against the descriptor,
/// together with an opaque witness of the enforced worker execution mode.
pub fn remote_dependency_isolation_policy(
    plan: &DependencyActionPlan,
) -> Result<TypedDigest, RemoteDependencyRefusal> {
    if plan.canonical_cargo {
        super::canonical_cargo::canonical_layout(plan)?;
        let (canonical_profile, execution_profile) =
            match remote_dependency_output_class(&plan.invocation)? {
                RemoteDependencyOutputClass::Metadata => (
                    CANONICAL_REMOTE_DEPENDENCY_ISOLATION_PROFILE,
                    REMOTE_DEPENDENCY_ISOLATION_PROFILE,
                ),
                RemoteDependencyOutputClass::Rlib => (
                    CANONICAL_REMOTE_RLIB_ISOLATION_PROFILE,
                    REMOTE_RLIB_ISOLATION_PROFILE,
                ),
            };
        let mut policy = CanonicalEncoder::new();
        policy
            .str(canonical_profile)
            .str(execution_profile)
            .str(plan.source_kind.as_str());
        return Ok(compute(
            CANONICAL_REMOTE_DEPENDENCY_ISOLATION_DOMAIN,
            &policy.finish(),
        ));
    }
    let profile = match remote_dependency_output_class(&plan.invocation)? {
        RemoteDependencyOutputClass::Metadata => REMOTE_DEPENDENCY_ISOLATION_PROFILE,
        RemoteDependencyOutputClass::Rlib => REMOTE_RLIB_ISOLATION_PROFILE,
    };
    let mut policy = CanonicalEncoder::new();
    policy.str(profile).str(plan.source_kind.as_str());
    Ok(compute(
        REMOTE_DEPENDENCY_ISOLATION_DOMAIN,
        &policy.finish(),
    ))
}

/// Why an otherwise admitted dependency cannot use this remote class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteDependencyRefusal {
    /// Source, toolchain, output or other local-plan facts were inconsistent.
    Local(LiveRefusal),
    /// Neither metadata-only nor the explicitly closed archive output class.
    OutputClass,
    /// Generated inputs do not have a coherent, disjoint original OUT_DIR binding.
    GeneratedInputs,
    /// An extern is unbound, executable, or lacks a complete candidate identity.
    ExternInputs,
    /// Native input or host-dependent CPU selection.
    NativeInputs,
    /// The exact observed compiler/sysroot paths are not the requested ones.
    ToolchainPath(String),
    /// Loader state cannot be reconstructed entirely from retained inputs.
    LoaderEnvironment(String),
    /// A digest did not come from the versioned host-runtime observer.
    RuntimeIdentity,
}

impl RemoteDependencyRefusal {
    /// Stable diagnostic reason, independent of paths and environment values.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Local(_) => "REMOTE_DEP_LOCAL_FACTS",
            Self::OutputClass => "REMOTE_DEP_OUTPUT_CLASS",
            Self::GeneratedInputs => "REMOTE_DEP_GENERATED_INPUTS",
            Self::ExternInputs => "REMOTE_DEP_EXTERN_INPUTS",
            Self::NativeInputs => "REMOTE_DEP_NATIVE_INPUTS",
            Self::ToolchainPath(_) => "REMOTE_DEP_TOOLCHAIN_PATH",
            Self::LoaderEnvironment(_) => "REMOTE_DEP_LOADER_ENVIRONMENT",
            Self::RuntimeIdentity => "REMOTE_DEP_RUNTIME_IDENTITY",
        }
    }
}

impl std::fmt::Display for RemoteDependencyRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(error) => write!(formatter, "{}: {error}", self.code()),
            Self::ToolchainPath(path) | Self::LoaderEnvironment(path) => {
                write!(formatter, "{}: {path}", self.code())
            }
            _ => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for RemoteDependencyRefusal {}

impl From<LiveRefusal> for RemoteDependencyRefusal {
    fn from(error: LiveRefusal) -> Self {
        Self::Local(error)
    }
}

/// Ordered loader search directories relative to the supplied toolchain root.
///
/// The empty relative string represents the toolchain root itself. Join these
/// components to the retained physical root for runtime observation. Exact
/// non-toolchain entries are returned by remote_empty_loader_directories; the
/// caller must hold a fresh LoaderDirectoryWitness for those paths before
/// remote keying, dispatch, publication and installation. The compiler retains
/// the full original LD_LIBRARY_PATH, whose omitted paths have private backings.
pub fn remote_loader_search_paths(
    plan: &DependencyActionPlan,
    toolchain_root: &str,
) -> Result<Vec<String>, RemoteDependencyRefusal> {
    loader_paths(plan, toolchain_root).map(|(toolchain, _)| toolchain)
}

/// Exact private-empty loader aliases required by the original environment.
///
/// Sorted and deduplicated for the dependency-exec-v6 worker context. This
/// includes output/dependency entries and Cargo's output parent. No directory
/// is silently assumed empty: rabs_sandbox::loader_directories must observe
/// every returned root, even if its Rust .rlib/.rmeta inventory was empty.
/// The worker must create fresh backings and may populate only declared child
/// directory mountpoints before binding the actual private output below them.
pub fn remote_empty_loader_directories(
    plan: &DependencyActionPlan,
    toolchain_root: &str,
) -> Result<Vec<String>, RemoteDependencyRefusal> {
    loader_paths(plan, toolchain_root).map(|(_, empty)| empty)
}

fn loader_paths(
    plan: &DependencyActionPlan,
    toolchain_root: &str,
) -> Result<(Vec<String>, Vec<String>), RemoteDependencyRefusal> {
    if !plain_path_in_profile(toolchain_root, plan.canonical_cargo)
        || (plan.canonical_cargo && toolchain_root != "/__rabs/toolchain")
        || plan.compiler != format!("{toolchain_root}/bin/rustc")
        || plan.invocation.compiler_argv0 != plan.compiler
    {
        return Err(RemoteDependencyRefusal::ToolchainPath(
            "compiler must be the observed sysroot's bin/rustc".to_owned(),
        ));
    }
    let mut passthrough = plan.invocation.passthrough.iter();
    while let Some(argument) = passthrough.next() {
        let root = if argument == "--sysroot" {
            passthrough.next().map(String::as_str)
        } else {
            argument.strip_prefix("--sysroot=")
        };
        if let Some(root) = root
            && root != toolchain_root
        {
            return Err(RemoteDependencyRefusal::ToolchainPath(
                "explicit sysroot differs from the retained toolchain".to_owned(),
            ));
        }
    }
    let mut search_paths = Vec::new();
    let mut empty = std::collections::BTreeSet::new();
    let overlaps =
        |left: &str, right: &str| left == right || within(left, right) || within(right, left);
    for (name, value) in &plan.execution_env {
        if (name.starts_with("LD_") && name != "LD_LIBRARY_PATH") || name == "GLIBC_TUNABLES" {
            return Err(RemoteDependencyRefusal::LoaderEnvironment(name.clone()));
        }
        if name != "LD_LIBRARY_PATH" {
            continue;
        }
        for entry in value.split(':') {
            if !plain_path_in_profile(entry, plan.canonical_cargo) {
                return Err(RemoteDependencyRefusal::LoaderEnvironment(
                    "LD_LIBRARY_PATH contains an empty, relative or unrepresentable entry".into(),
                ));
            }
            if entry == toolchain_root {
                search_paths.push(String::new());
            } else if within(entry, toolchain_root) {
                search_paths.push(entry[toolchain_root.len() + 1..].to_owned());
            } else {
                let reserved = if plan.canonical_cargo {
                    entry != "/__rabs/out/cargo" && !within(entry, "/__rabs/out/cargo")
                } else {
                    [
                        "/__rabs", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc",
                        "/dev", "/sys", "/run",
                    ]
                    .iter()
                    .any(|reserved| overlaps(entry, reserved))
                };
                if overlaps(entry, toolchain_root)
                    || overlaps(entry, &plan.source_root)
                    || reserved
                    || within(entry, &plan.out_dir)
                    || plan.dependency_dirs.iter().any(|root| within(entry, root))
                    || plan
                        .generated_root
                        .as_deref()
                        .is_some_and(|root| entry == root || within(entry, root))
                {
                    return Err(RemoteDependencyRefusal::LoaderEnvironment(
                        "private loader directory overlaps inputs, runtime or an output descendant"
                            .into(),
                    ));
                }
                empty.insert(entry.to_owned());
                if empty.len() > 64 {
                    return Err(RemoteDependencyRefusal::LoaderEnvironment(
                        "too many private loader directories".into(),
                    ));
                }
            }
        }
    }
    Ok((search_paths, empty.into_iter().collect()))
}

/// Check the remote dependency shape before expensive capture or runtime observation.
///
/// This has no filesystem access and needs neither a retained toolchain nor a
/// runtime digest. It checks the same invocation, output, loader and complete
/// dependency-inventory restrictions that remote_dependency_key enforces again.
/// A success admits preparation only; it is not dispatch or cache authority.
pub fn remote_dependency_shape(
    plan: &DependencyActionPlan,
    directories: &[DependencyDirectoryFact],
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    if plan.canonical_cargo {
        super::canonical_cargo::canonical_layout(plan)?;
    }
    if directories.len() != plan.dependency_dirs.len()
        || plan
            .dependency_dirs
            .iter()
            .zip(directories)
            .any(|(root, fact)| root != &fact.path)
    {
        return Err(LiveRefusal::Facts(
            "dependency directory inventory is incomplete or reordered".into(),
        )
        .into());
    }
    validate_generated_root(plan, toolchain_root)?;
    remote_extern_facts(plan, directories)?;
    if !plan.invocation.native_libs.is_empty()
        || plan
            .invocation
            .codegen
            .iter()
            .any(|(name, value)| name == "target-cpu" && value.as_deref() == Some("native"))
    {
        return Err(RemoteDependencyRefusal::NativeInputs);
    }
    remote_dependency_output_class(&plan.invocation)?;
    let derived = derive_dependency_output_declarations(&plan.invocation, &plan.host_triple)
        .map_err(|error| LiveRefusal::Outputs(error.to_string()))?;
    if derived != plan.outputs {
        return Err(
            LiveRefusal::Facts("declared outputs differ from the invocation".into()).into(),
        );
    }
    remote_loader_search_paths(plan, toolchain_root)?;
    Ok(())
}

/// The generated tree is an input, never an output-placement alias. Check the
/// original environment even when an independent local key projection removed
/// OUT_DIR from keyed_env: the worker must still receive its exact real path.
fn validate_generated_root(
    plan: &DependencyActionPlan,
    toolchain_root: &str,
) -> Result<(), RemoteDependencyRefusal> {
    let mut presented = plan
        .execution_env
        .iter()
        .filter(|(name, _)| name == "OUT_DIR")
        .map(|(_, value)| value.as_str());
    let observed = presented.next();
    if presented.next().is_some() || observed != plan.generated_root.as_deref() {
        return Err(RemoteDependencyRefusal::GeneratedInputs);
    }
    let Some(root) = plan.generated_root.as_deref() else {
        return Ok(());
    };
    let overlaps = |other: &str| root == other || within(root, other) || within(other, root);
    if !plain_path_in_profile(root, plan.canonical_cargo)
        || root.contains(&plan.out_dir)
        || (!plan.canonical_cargo && overlaps("/__rabs"))
        || [
            plan.source_root.as_str(),
            plan.out_dir.as_str(),
            toolchain_root,
        ]
        .into_iter()
        .chain(plan.dependency_dirs.iter().map(String::as_str))
        .chain([
            "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/dev", "/sys", "/run",
        ])
        .any(overlaps)
    {
        return Err(RemoteDependencyRefusal::GeneratedInputs);
    }
    Ok(())
}

/// Resolve every explicit extern to its exact keyed candidate. The ordinary
/// local planner labels a bare extern as toolchain-provided but does not prove
/// that resolution cannot execute a proc macro, so this remote class refuses it.
fn remote_extern_facts(
    plan: &DependencyActionPlan,
    directories: &[DependencyDirectoryFact],
) -> Result<Vec<ExternFact>, RemoteDependencyRefusal> {
    if plan.externs.len() != plan.invocation.externs.len() {
        return Err(RemoteDependencyRefusal::ExternInputs);
    }
    plan.externs
        .iter()
        .zip(&plan.invocation.externs)
        .map(|(planned, (argument_name, argument_path))| {
            let PlannedExtern::File { name, path, kind } = planned else {
                return Err(RemoteDependencyRefusal::ExternInputs);
            };
            if name != argument_name
                || argument_path.as_deref() != Some(path.as_str())
                || !matches!(
                    kind,
                    DependencyArtifactKind::Rmeta | DependencyArtifactKind::Rlib
                )
            {
                return Err(RemoteDependencyRefusal::ExternInputs);
            }
            directories
                .iter()
                .flat_map(|directory| &directory.artifacts)
                .find(|fact| &fact.path == path)
                .cloned()
                .ok_or_else(|| {
                    LiveRefusal::Facts(
                        "remote extern is missing from the complete candidate inventory".into(),
                    )
                    .into()
                })
        })
        .collect()
}

/// Key an admitted, fully observed dependency for remote execution. The rlib
/// class requires its separately enforced filesystem profile; this function
/// does not grant codegen authority to local dependency execution.
///
/// Ordinary semantic input components are retained, while worker isolation and
/// the measured platform replace the unsandboxed local components. The existing
/// capture/projection epoch remains in force; the versioned remote policy owns
/// this class's separate namespace. The mandatory retained-toolchain SHA-256
/// must come from capture_toolchain (toolchain-dataset-v1), or a coherent
/// fingerprint that the retained upload independently matches. It binds every
/// captured file and alias, including DSOs selected through loader directories
/// outside the local ToolchainFacts inventory. Retain that dataset through
/// upload and require the worker's independently verified identical identity.
///
/// Directory facts must cover every planned directory in order, even when it
/// is the output directory. Every nonempty inventory is retained byte-for-byte
/// and mounted read-only on the worker. Candidates in the output directory
/// receive individual read-only file mounts over owned placeholders; only
/// declared new outputs are captured. Empty inventories receive fresh private
/// worker directories.
/// Generated source members use the existing generated input manifest root.
/// Their complete tree and exact Cargo build-script stdout are keyed by the
/// ordinary dependency validator, including rustc-env agreement. The worker
/// sees the captured tree at the original OUT_DIR, never the mutable caller tree.
/// Revalidate all original observations through dispatch and installation.
///
/// # Errors
/// A typed refusal for unsupported invocation shape, incomplete closure facts
/// or a runtime identity with another domain.
#[allow(clippy::too_many_arguments)]
pub fn remote_dependency_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    directories: &[DependencyDirectoryFact],
    inputs: &ActionInputManifest,
    build_script_output: Option<&[u8]>,
    toolchain_root: &str,
    retained_toolchain_sha256: &[u8; 32],
    runtime: &TypedDigest,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    if runtime.domain != RUNTIME_COHORT_DOMAIN {
        return Err(RemoteDependencyRefusal::RuntimeIdentity);
    }
    remote_dependency_shape(plan, directories, toolchain_root)?;
    let externs = remote_extern_facts(plan, directories)?;
    let mut key = if plan.canonical_cargo {
        super::canonical_cargo::canonical_dependency_key(
            plan,
            toolchain,
            &externs,
            directories,
            build_script_output,
            inputs,
        )?
    } else {
        live_dependency_key(
            plan,
            toolchain,
            &externs,
            directories,
            build_script_output,
            inputs,
        )?
    };
    let output_class = remote_dependency_output_class(&plan.invocation)?;
    if output_class == RemoteDependencyOutputClass::Rlib {
        // An assembler `.incbin` can mention the original dependency/output
        // roots without appearing in dep-info. The metadata lane's placement
        // equivalence therefore is not a proof for archive codegen. Preserve
        // exact argv, cwd and semantic environment until an observed-read
        // policy can establish a narrower equivalence. Process-local controls
        // retain their existing tracked-read publication veto.
        let mut invocation = CanonicalEncoder::new();
        invocation
            .bytes(&plan.invocation.canonical_bytes())
            .str(&plan.cwd)
            .str(&plan.compiler)
            .str(toolchain_root)
            .str(&plan.source_root)
            .str(&plan.out_dir);
        invocation.seq(&plan.dependency_dirs, |encoder, directory| {
            encoder.str(directory);
        });
        invocation.seq(&plan.invocation.excluded_presentation, |encoder, flag| {
            encoder.str(flag);
        });
        key.descriptor.normalized_invocation =
            compute("rabs.remote-rlib.exact-invocation.v1", &invocation.finish());
        // Use original semantic values, not keyed_env: that set may already
        // have projected Cargo layout or empty OUT_DIR spellings. Preserve
        // the shared exclusion for jobserver/wrapper controls, whose tracked
        // reads (including absence) already veto publication.
        let semantic_env = plan
            .execution_env
            .iter()
            .filter(|(name, _)| matches!(super::env_role(name), super::EnvRole::Keyed))
            .collect::<Vec<_>>();
        let mut environment = CanonicalEncoder::new();
        environment.seq(&semantic_env, |encoder, (name, value)| {
            encoder.str(name).str(value);
        });
        key.descriptor.environment = compute(
            "rabs.remote-rlib.exact-environment.v1",
            &environment.finish(),
        );
    }
    let mut retained_toolchain = CanonicalEncoder::new();
    retained_toolchain
        .str(key.descriptor.toolchain.domain)
        .bytes(&key.descriptor.toolchain.bytes)
        .str("toolchain-dataset-v1")
        .bytes(retained_toolchain_sha256);
    key.descriptor.toolchain = compute(REMOTE_TOOLCHAIN_DOMAIN, &retained_toolchain.finish());
    key.descriptor.sandbox_semantic_policy = remote_dependency_isolation_policy(plan)?;
    let codegen = |name: &str| {
        plan.invocation
            .codegen
            .iter()
            .filter(|(flag, _)| flag == name)
            .filter_map(|(_, value)| value.clone())
            .collect::<Vec<_>>()
    };
    let runtime_hex: String = runtime
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    key.descriptor.output_platform = OutputPlatformContract {
        target_triple: plan.target_triple.clone(),
        host_abi_triple: plan.host_triple.clone(),
        cpu_baseline: CpuBaseline::Explicit {
            baseline: codegen("target-cpu")
                .pop()
                .unwrap_or_else(|| "target-default".into()),
            feature_adjustments: codegen("target-feature"),
        },
        libc_runtime: format!("{}:{runtime_hex}", runtime.domain),
        linker_format: match output_class {
            RemoteDependencyOutputClass::Metadata => "metadata-only-no-linker-v1",
            RemoteDependencyOutputClass::Rlib => "rust-rlib-no-native-linker-v1",
        }
        .to_owned(),
        sdk_identity: None,
        deployment_target: None,
        signing_policy: None,
        filesystem_semantic_class: "linux-private-regular-tree-observed-by-runtime-cohort-v1"
            .into(),
    }
    .contract_digest();
    key.action_key = compute_action_key(&key.descriptor).final_key;
    key.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&key.descriptor));
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::super::canonical_cargo_dependency_key;
    use super::*;
    use crate::live_dependency::{LiveRustcRequest, plan_dependency_action};
    use rabs_protocol::input_evidence::{
        DirectoryEnumeration, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;

    const TOOLCHAIN: &str = "/toolchain";
    const PACKAGE: &str = "/home/test/.cargo/registry/src/index/leaf-1.0.0";
    const OUTPUT: &str = "/work/target/debug/deps";

    fn plan(out_dir: &str) -> DependencyActionPlan {
        let argv = [
            format!("{TOOLCHAIN}/bin/rustc"),
            "--crate-name=leaf".into(),
            "--crate-type=lib".into(),
            "--edition=2021".into(),
            format!("{PACKAGE}/src/lib.rs"),
            "--error-format=json".into(),
            "--json=artifacts".into(),
            "--emit=dep-info,metadata".into(),
            "--cap-lints=allow".into(),
            format!("--out-dir={out_dir}"),
            "-L".into(),
            format!("dependency={out_dir}"),
        ];
        let env = [
            ("HOME".into(), "/home/test".into()),
            ("CARGO_MANIFEST_DIR".into(), PACKAGE.into()),
            ("CARGO_PKG_NAME".into(), "leaf".into()),
            (
                "LD_LIBRARY_PATH".into(),
                format!("{out_dir}:{TOOLCHAIN}/lib"),
            ),
        ];
        plan_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            },
            "x86_64-unknown-linux-gnu",
        )
        .unwrap()
    }

    fn toolchain() -> ToolchainFacts {
        ToolchainFacts {
            compiler_binary_digest: compute("rabs.test.v1", b"rustc"),
            verbose_version: "rustc 1.100.0\nhost: x86_64-unknown-linux-gnu\nLLVM version: 21"
                .into(),
            sysroot_root_digest: compute("rabs.test.v1", b"sysroot"),
            runtime_libraries: vec![compute("rabs.test.v1", b"driver")],
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

    fn inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: ["Cargo.toml", "src/lib.rs"]
                .into_iter()
                .map(|relative| PositiveInput {
                    virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
                    object: ObjectId(compute("rabs.test.v1", relative.as_bytes())),
                    file_type: InputFileType::Regular,
                    executable: false,
                    symlink_resolution: Vec::new(),
                })
                .collect(),
            directory_enumerations: plan
                .generated_root
                .as_ref()
                .map(|_| DirectoryEnumeration {
                    virtual_path: RawBytes::new(plan.generated_virtual_root().into_bytes()),
                    entries: Vec::new(),
                })
                .into_iter()
                .collect(),
            ..ActionInputManifest::default()
        }
    }

    fn key(plan: &DependencyActionPlan, runtime_bytes: &[u8]) -> LiveDependencyKey {
        remote_dependency_key(
            plan,
            &toolchain(),
            &directories(plan),
            &inputs(plan),
            None,
            TOOLCHAIN,
            &[41; 32],
            &compute(RUNTIME_COHORT_DOMAIN, runtime_bytes),
        )
        .unwrap()
    }

    fn archive_plan(out_dir: &str, separate_metadata: bool) -> DependencyActionPlan {
        let mut plan = plan(out_dir);
        plan.invocation.emit = vec!["dep-info".into(), "link".into()];
        if separate_metadata {
            plan.invocation.emit.push("metadata".into());
        }
        plan.outputs =
            derive_dependency_output_declarations(&plan.invocation, &plan.host_triple).unwrap();
        plan
    }

    fn canonical_plan(out_dir: &str) -> DependencyActionPlan {
        canonical_plan_with_emit(out_dir, "dep-info,metadata")
    }

    fn canonical_plan_with_emit(out_dir: &str, emit: &str) -> DependencyActionPlan {
        canonical_plan_with_generated(out_dir, emit, None)
    }

    fn canonical_plan_with_generated(
        out_dir: &str,
        emit: &str,
        generated: Option<&str>,
    ) -> DependencyActionPlan {
        let package = "/__rabs/cargo-home/registry/src/index/leaf-1.0.0";
        let argv = [
            "/__rabs/toolchain/bin/rustc".to_owned(),
            "--crate-name=leaf".into(),
            "--crate-type=lib".into(),
            "--edition=2021".into(),
            format!("{package}/src/lib.rs"),
            "--error-format=json".into(),
            "--json=artifacts".into(),
            format!("--emit={emit}"),
            "--cap-lints=allow".into(),
            format!("--out-dir={out_dir}"),
            "-L".into(),
            format!("dependency={out_dir}"),
        ];
        let mut env = vec![
            ("HOME".into(), "/__rabs/home".into()),
            ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
            ("CARGO_MANIFEST_DIR".into(), package.into()),
            ("CARGO_PKG_NAME".into(), "leaf".into()),
            (
                "LD_LIBRARY_PATH".into(),
                format!("{out_dir}:/__rabs/out/cargo/debug:/__rabs/toolchain/lib"),
            ),
        ];
        if let Some(root) = generated {
            env.push(("OUT_DIR".into(), root.into()));
            env.push(("BUILD_LABEL".into(), "pinned".into()));
        }
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: package,
            env: &env,
        };
        if generated.is_some() {
            assert!(
                super::super::plan_canonical_cargo_dependency_action(
                    request,
                    "x86_64-unknown-linux-gnu",
                    None,
                )
                .is_err(),
                "generated inputs cannot select local metadata capture"
            );
        } else if emit.contains("link") {
            assert!(matches!(
                super::super::plan_canonical_cargo_dependency_action(
                    request,
                    "x86_64-unknown-linux-gnu",
                    None,
                ),
                Err(LiveRefusal::UnclosedCodegenInputs)
            ));
        }
        super::super::plan_canonical_remote_dependency_action(
            request,
            "x86_64-unknown-linux-gnu",
            None,
        )
        .unwrap()
    }

    fn canonical_key(
        plan: &DependencyActionPlan,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_dependency_key(
            plan,
            &toolchain(),
            &directories(plan),
            &inputs(plan),
            None,
            "/__rabs/toolchain",
            &[41; 32],
            &compute(RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
    }

    #[test]
    fn canonical_remote_metadata_has_separate_authority_and_exact_replay_identity() {
        let plan = canonical_plan("/__rabs/out/cargo/debug/deps");
        let remote = canonical_key(&plan).unwrap();
        let local = canonical_cargo_dependency_key(
            &plan,
            &toolchain(),
            &[],
            &directories(&plan),
            None,
            &inputs(&plan),
        )
        .unwrap();
        let ordinary = key(&super::tests::plan(OUTPUT), b"runtime");
        assert_eq!(
            remote.descriptor.sandbox_semantic_policy.domain,
            CANONICAL_REMOTE_DEPENDENCY_ISOLATION_DOMAIN
        );
        assert_ne!(remote.action_key, local.action_key);
        assert_ne!(remote.action_key, ordinary.action_key);
        assert_ne!(
            remote.descriptor.sandbox_semantic_policy,
            ordinary.descriptor.sandbox_semantic_policy
        );
        assert_eq!(
            remote.action_key,
            compute_action_key(&remote.descriptor).final_key
        );
        assert_eq!(
            remote.descriptor_digest,
            descriptor_digest(&descriptor_canonical_bytes(&remote.descriptor))
        );
        let moved = canonical_plan("/__rabs/out/cargo/debug/other-deps");
        assert_ne!(remote.action_key, canonical_key(&moved).unwrap().action_key);
        assert_eq!(
            remote_loader_search_paths(&plan, "/__rabs/toolchain").unwrap(),
            ["lib"]
        );
        assert_eq!(
            remote_empty_loader_directories(&plan, "/__rabs/toolchain").unwrap(),
            ["/__rabs/out/cargo/debug", "/__rabs/out/cargo/debug/deps"]
        );
    }

    #[test]
    fn canonical_remote_context_cannot_borrow_unobserved_generated_or_host_path_authority() {
        let original = canonical_plan("/__rabs/out/cargo/debug/deps");
        let mut generated = original.clone();
        generated.generated_root = Some("/__rabs/out/cargo/debug/build/leaf/out".into());
        generated
            .execution_env
            .push(("OUT_DIR".into(), generated.generated_root.clone().unwrap()));
        assert!(canonical_key(&generated).is_err());
        let mut ordinary = original.clone();
        ordinary.canonical_cargo = false;
        assert!(canonical_key(&ordinary).is_err());
        assert!(remote_dependency_shape(&original, &directories(&original), TOOLCHAIN).is_err());
        for directory in [
            "/__rabs/home/control",
            "/__rabs/workspace",
            "/__rabs/cargo-home",
            "/__rabs/out",
            "/__rabs/out/cargo-other/debug",
            "/usr/lib",
            "/work/target/debug",
        ] {
            let mut plan = original.clone();
            plan.execution_env
                .iter_mut()
                .find(|(name, _)| name == "LD_LIBRARY_PATH")
                .unwrap()
                .1 = directory.to_owned();
            assert!(canonical_key(&plan).is_err(), "loader alias {directory}");
        }
    }

    #[test]
    fn canonical_archives_require_remote_authority_and_key_assembler_payload_bytes() {
        for emit in ["dep-info,link", "dep-info,metadata,link"] {
            let plan = canonical_plan_with_emit("/__rabs/out/cargo/debug/deps", emit);
            let archive = canonical_key(&plan).unwrap();
            assert_eq!(
                remote_dependency_output_class(&plan.invocation),
                Ok(RemoteDependencyOutputClass::Rlib)
            );
            assert!(plan.output_names().contains(&"libleaf.rlib".to_owned()));
            assert!(matches!(
                canonical_cargo_dependency_key(
                    &plan,
                    &toolchain(),
                    &[],
                    &directories(&plan),
                    None,
                    &inputs(&plan),
                ),
                Err(LiveRefusal::UnclosedCodegenInputs)
            ));
            assert!(
                live_dependency_key(
                    &plan,
                    &toolchain(),
                    &[],
                    &directories(&plan),
                    None,
                    &inputs(&plan),
                )
                .is_err()
            );
            let metadata = canonical_key(&canonical_plan(&plan.out_dir)).unwrap();
            let ordinary = key(&archive_plan(OUTPUT, emit.contains("metadata")), b"runtime");
            for other in [metadata, ordinary] {
                assert_ne!(archive.action_key, other.action_key);
                assert_ne!(
                    archive.descriptor.sandbox_semantic_policy,
                    other.descriptor.sandbox_semantic_policy
                );
            }
            assert_eq!(
                archive.descriptor.normalized_invocation.domain,
                "rabs.remote-rlib.exact-invocation.v1"
            );
            let moved = canonical_plan_with_emit("/__rabs/out/cargo/release/deps", emit);
            assert_ne!(
                archive.action_key,
                canonical_key(&moved).unwrap().action_key
            );

            // .incbin is absent from rustc dep-info. The complete retained
            // package inventory, rather than a discovered Rust read set, must
            // therefore invalidate an archive when those bytes change.
            let mut retained = inputs(&plan);
            retained.inputs.push(PositiveInput {
                virtual_path: RawBytes::new(plan.input_virtual_path("payload.bin").into_bytes()),
                object: ObjectId(compute("test.source.v1", b"assembler payload one")),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            });
            let with_inputs = |inputs: &ActionInputManifest| {
                remote_dependency_key(
                    &plan,
                    &toolchain(),
                    &directories(&plan),
                    inputs,
                    None,
                    "/__rabs/toolchain",
                    &[41; 32],
                    &compute(RUNTIME_COHORT_DOMAIN, b"runtime"),
                )
                .unwrap()
            };
            let first = with_inputs(&retained);
            retained.inputs.last_mut().unwrap().object =
                ObjectId(compute("test.source.v1", b"assembler payload two"));
            assert_ne!(first.action_key, with_inputs(&retained).action_key);
            assert_eq!(
                archive.action_key,
                compute_action_key(&archive.descriptor).final_key
            );
        }
    }

    #[test]
    fn canonical_remote_archive_policy_does_not_admit_other_codegen_or_native_linking() {
        let original = canonical_plan_with_emit("/__rabs/out/cargo/debug/deps", "dep-info,link");
        for emit in [
            vec!["link"],
            vec!["dep-info", "metadata", "link", "asm"],
            vec!["dep-info", "obj"],
            vec!["dep-info", "llvm-ir"],
        ] {
            let mut plan = original.clone();
            plan.invocation.emit = emit.into_iter().map(str::to_owned).collect();
            assert!(canonical_key(&plan).is_err());
            assert!(remote_dependency_isolation_policy(&plan).is_err());
        }
        for crate_type in ["bin", "dylib", "cdylib", "staticlib", "proc-macro"] {
            let mut plan = original.clone();
            plan.invocation.crate_types = vec![crate_type.into()];
            assert!(canonical_key(&plan).is_err());
            assert!(remote_dependency_isolation_policy(&plan).is_err());
        }
        let mut generated = original.clone();
        generated.generated_root = Some("/__rabs/out/cargo/debug/build/leaf/out".into());
        assert!(canonical_key(&generated).is_err());
    }

    #[test]
    fn archives_require_a_distinct_enforced_policy_and_exact_output_set() {
        for separate_metadata in [false, true] {
            let archive = archive_plan(OUTPUT, separate_metadata);
            assert_eq!(
                remote_dependency_output_class(&archive.invocation),
                Ok(RemoteDependencyOutputClass::Rlib)
            );
            let mut outputs = archive.output_names();
            outputs.sort();
            let mut expected = vec!["leaf.d".to_owned(), "libleaf.rlib".to_owned()];
            if separate_metadata {
                expected.push("libleaf.rmeta".to_owned());
            }
            assert_eq!(outputs, expected);
            let remote = key(&archive, b"runtime");
            let metadata = key(&plan(OUTPUT), b"runtime");
            let local = live_dependency_key(
                &archive,
                &toolchain(),
                &[],
                &directories(&archive),
                None,
                &inputs(&archive),
            )
            .unwrap();
            assert_ne!(remote.action_key, local.action_key);
            assert_ne!(remote.action_key, metadata.action_key);
            assert_ne!(
                remote.descriptor.sandbox_semantic_policy,
                local.descriptor.sandbox_semantic_policy
            );
            assert_ne!(
                remote.descriptor.sandbox_semantic_policy,
                metadata.descriptor.sandbox_semantic_policy
            );
            assert_eq!(
                super::super::check_dependency_cache_read_closure(&archive.invocation),
                Err(LiveRefusal::UnclosedCodegenInputs),
                "a remote archive policy must never authorize local codegen capture"
            );
            assert_eq!(
                remote.action_key,
                compute_action_key(&remote.descriptor).final_key
            );
        }
    }

    #[test]
    fn archive_keys_retain_paths_environment_and_complete_source_bytes() {
        let archive = archive_plan(OUTPUT, true);
        let original = key(&archive, b"runtime");
        assert_ne!(
            original.action_key,
            key(&archive_plan("/other/target/debug/deps", true), b"runtime").action_key,
            "unobserved assembler path reads do not inherit metadata placement equivalence"
        );
        let mut environment = archive_plan(OUTPUT, true);
        environment
            .execution_env
            .push(("ARCHIVE_FLAVOR".into(), "changed".into()));
        assert_ne!(
            original.action_key,
            key(&environment, b"runtime").action_key
        );
        let mut source = inputs(&archive);
        source.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(archive.input_virtual_path("embedded.bin").into_bytes()),
            object: ObjectId(compute("rabs.test.v1", b"assembler input bytes")),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        let changed = remote_dependency_key(
            &archive,
            &toolchain(),
            &directories(&archive),
            &source,
            None,
            TOOLCHAIN,
            &[41; 32],
            &compute(RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
        .unwrap();
        assert_ne!(original.action_key, changed.action_key);
        assert_ne!(
            original.action_key,
            key(&archive, b"other-runtime").action_key
        );
    }

    #[test]
    fn archive_replay_excludes_process_controls_but_refuses_their_tracked_reads() {
        let original = archive_plan(OUTPUT, true);
        let first = key(&original, b"runtime");
        let mut changed = archive_plan(OUTPUT, true);
        changed.execution_env.extend([
            (
                "CARGO_MAKEFLAGS".into(),
                "--jobserver-auth=fifo:/__rabs/home/first".into(),
            ),
            ("RABS_SOCKET_PATH".into(), "/another/edge.sock".into()),
        ]);
        assert_eq!(first.action_key, key(&changed, b"runtime").action_key);
        changed
            .execution_env
            .iter_mut()
            .find(|(name, _)| name == "CARGO_MAKEFLAGS")
            .unwrap()
            .1 = "--jobserver-auth=fifo:/__rabs/home/second".into();
        assert_eq!(first.action_key, key(&changed, b"runtime").action_key);
        for binding in [
            "CARGO_MAKEFLAGS=--jobserver-auth=4,5",
            "CARGO_MAKEFLAGS",
            "RABS_SOCKET_PATH",
        ] {
            let dep_info = format!("{OUTPUT}/leaf.d: {PACKAGE}/src/lib.rs\n# env-dep:{binding}\n");
            assert!(
                super::super::dep_info_closure_violation(&changed, dep_info.as_bytes(), |_| true)
                    .is_some()
            );
        }
        let mut projected = archive_plan(OUTPUT, true);
        projected
            .keyed_env
            .retain(|(name, _)| name != "LD_LIBRARY_PATH");
        assert_eq!(
            first.descriptor.environment,
            key(&projected, b"runtime").descriptor.environment
        );
        projected
            .execution_env
            .iter_mut()
            .find(|(name, _)| name == "LD_LIBRARY_PATH")
            .unwrap()
            .1 = format!("{OUTPUT}:/work/another-loader-parent:{TOOLCHAIN}/lib");
        assert_ne!(first.action_key, key(&projected, b"runtime").action_key);
    }

    #[test]
    fn archive_identity_retains_toolchain_mount_spelling_even_without_loader_env() {
        let mut original = archive_plan(OUTPUT, true);
        original
            .execution_env
            .retain(|(name, _)| name != "LD_LIBRARY_PATH");
        original
            .keyed_env
            .retain(|(name, _)| name != "LD_LIBRARY_PATH");
        let first = key(&original, b"runtime");
        let mut moved = original;
        moved.compiler = "/relocated/toolchain/bin/rustc".into();
        moved.invocation.compiler_argv0.clone_from(&moved.compiler);
        let relocated = remote_dependency_key(
            &moved,
            &toolchain(),
            &directories(&moved),
            &inputs(&moved),
            None,
            "/relocated/toolchain",
            &[41; 32],
            &compute(RUNTIME_COHORT_DOMAIN, b"runtime"),
        )
        .unwrap();
        assert_eq!(first.descriptor.toolchain, relocated.descriptor.toolchain);
        assert_ne!(
            first.descriptor.normalized_invocation,
            relocated.descriptor.normalized_invocation
        );
        assert_ne!(
            first.action_key, relocated.action_key,
            "an assembler read of an absolute toolchain filename cannot inherit content-only toolchain equivalence"
        );
    }

    #[test]
    fn archive_class_refuses_implicit_native_mixed_and_extra_outputs() {
        for emits in [
            vec![],
            vec!["link"],
            vec!["dep-info", "link", "obj"],
            vec!["dep-info", "metadata", "link", "asm"],
            vec!["dep-info", "link", "link"],
        ] {
            let mut invocation = archive_plan(OUTPUT, true).invocation;
            invocation.emit = emits.into_iter().map(str::to_owned).collect();
            assert_eq!(
                remote_dependency_output_class(&invocation),
                Err(RemoteDependencyRefusal::OutputClass)
            );
        }
        for types in [
            vec![],
            vec!["bin"],
            vec!["dylib"],
            vec!["proc-macro"],
            vec!["lib", "rlib"],
        ] {
            let mut invocation = archive_plan(OUTPUT, true).invocation;
            invocation.crate_types = types.into_iter().map(str::to_owned).collect();
            assert_eq!(
                remote_dependency_output_class(&invocation),
                Err(RemoteDependencyRefusal::OutputClass)
            );
        }
        let mut native = archive_plan(OUTPUT, true);
        native
            .invocation
            .native_libs
            .push("native_dependency".into());
        assert_eq!(
            remote_dependency_shape(&native, &directories(&native), TOOLCHAIN),
            Err(RemoteDependencyRefusal::NativeInputs)
        );
        let mut external_linker = archive_plan(OUTPUT, true);
        external_linker
            .invocation
            .codegen
            .push(("linker".into(), Some("/usr/bin/cc".into())));
        assert!(
            remote_dependency_shape(&external_linker, &directories(&external_linker), TOOLCHAIN)
                .is_err()
        );
    }

    #[test]
    fn remote_namespace_is_distinct_and_binds_the_observed_runtime() {
        let plan = plan(OUTPUT);
        let local = live_dependency_key(
            &plan,
            &toolchain(),
            &[],
            &directories(&plan),
            None,
            &inputs(&plan),
        )
        .unwrap();
        let remote = key(&plan, b"observed-runtime-a");
        assert_ne!(local.action_key, remote.action_key);
        assert_ne!(
            local.descriptor.sandbox_semantic_policy,
            remote.descriptor.sandbox_semantic_policy
        );
        assert_ne!(
            local.descriptor.output_platform,
            remote.descriptor.output_platform
        );
        assert_eq!(
            local.descriptor.action_inputs,
            remote.descriptor.action_inputs
        );
        assert_eq!(local.descriptor.environment, remote.descriptor.environment);
        assert_ne!(local.descriptor.toolchain, remote.descriptor.toolchain);
        assert_eq!(remote.descriptor.toolchain.domain, REMOTE_TOOLCHAIN_DOMAIN);
        assert_ne!(
            remote.action_key,
            key(&plan, b"observed-runtime-b").action_key
        );
        assert_eq!(
            remote.action_key,
            compute_action_key(&remote.descriptor).final_key
        );
        assert_eq!(
            remote.descriptor_digest,
            descriptor_digest(&descriptor_canonical_bytes(&remote.descriptor))
        );
        assert_eq!(
            local,
            live_dependency_key(
                &plan,
                &toolchain(),
                &[],
                &directories(&plan),
                None,
                &inputs(&plan)
            )
            .unwrap()
        );
    }

    #[test]
    fn retained_toolchain_bytes_outside_local_inventory_cannot_alias() {
        let plan = plan(OUTPUT);
        let runtime = compute(RUNTIME_COHORT_DOMAIN, b"same-host-runtime");
        let call = |facts: &ToolchainFacts, retained: &[u8; 32]| {
            remote_dependency_key(
                &plan,
                facts,
                &directories(&plan),
                &inputs(&plan),
                None,
                TOOLCHAIN,
                retained,
                &runtime,
            )
            .unwrap()
        };
        // A custom loader directory can contain inputs outside the local
        // selected rustlib/runtime inventory. Its complete retained dataset
        // identity must move the remote key even when local facts are equal.
        let first = call(&toolchain(), &[41; 32]);
        let changed_dataset = call(&toolchain(), &[42; 32]);
        assert_ne!(first.action_key, changed_dataset.action_key);
        assert_ne!(
            first.descriptor.toolchain,
            changed_dataset.descriptor.toolchain
        );
        assert_eq!(
            first.descriptor.output_platform,
            changed_dataset.descriptor.output_platform
        );
        assert_eq!(
            first.descriptor.action_inputs,
            changed_dataset.descriptor.action_inputs
        );
        let mut changed_probe = toolchain();
        changed_probe.compiler_binary_digest = compute("rabs.test.v1", b"other-compiler");
        assert_ne!(first.action_key, call(&changed_probe, &[41; 32]).action_key);
    }

    #[test]
    fn output_placement_does_not_split_identical_remote_leaf_actions() {
        assert_eq!(
            key(&plan(OUTPUT), b"runtime"),
            key(&plan("/other/target/debug/deps"), b"runtime")
        );
    }

    #[test]
    fn loader_output_parents_remain_exact_semantic_environment_values() {
        let with_parent = |out_dir: &str| {
            let mut plan = plan(out_dir);
            let parent = out_dir.rsplit_once('/').unwrap().0;
            let loader = format!("{out_dir}:{parent}:{TOOLCHAIN}/lib");
            for (name, value) in &mut plan.execution_env {
                if name == "LD_LIBRARY_PATH" {
                    value.clone_from(&loader);
                }
            }
            for (name, value) in &mut plan.keyed_env {
                if name == "LD_LIBRARY_PATH" {
                    value.clone_from(&loader);
                }
            }
            plan
        };
        let first = with_parent(OUTPUT);
        let other = with_parent("/other/target/debug/deps");
        assert_eq!(
            remote_empty_loader_directories(&first, TOOLCHAIN).unwrap(),
            ["/work/target/debug", OUTPUT]
        );
        let first = key(&first, b"same-runtime");
        let other = key(&other, b"same-runtime");
        // Only the out-dir itself has the existing placement normalizer.
        // Parent spellings remain keyed; this slice makes no unproved claim
        // that diagnostics or tracked reads of the parent can be relocated.
        assert_eq!(
            first.descriptor.normalized_invocation,
            other.descriptor.normalized_invocation
        );
        assert_ne!(first.descriptor.environment, other.descriptor.environment);
        assert_ne!(first.action_key, other.action_key);
    }

    #[test]
    fn every_search_inventory_is_required_and_shared_output_inputs_are_keyed() {
        let plan = plan(OUTPUT);
        let runtime = compute(RUNTIME_COHORT_DOMAIN, b"runtime");
        let call = |directories: &[DependencyDirectoryFact]| {
            remote_dependency_key(
                &plan,
                &toolchain(),
                directories,
                &inputs(&plan),
                None,
                TOOLCHAIN,
                &[41; 32],
                &runtime,
            )
        };
        assert!(call(&[]).is_err());
        let mut facts = directories(&plan);
        facts[0].path = "/wrong/deps".into();
        assert!(call(&facts).is_err());
        facts = directories(&plan);
        facts[0].artifacts.push(ExternFact {
            path: format!("{OUTPUT}/libhidden.rmeta"),
            content_digest: compute("rabs.test.v1", b"hidden"),
        });
        let populated = call(&facts).unwrap();
        assert_ne!(
            populated.action_key,
            call(&directories(&plan)).unwrap().action_key
        );
        facts[0].artifacts[0].content_digest = compute("rabs.test.v1", b"changed hidden");
        assert_ne!(populated.action_key, call(&facts).unwrap().action_key);
        facts[0].artifacts[0].path = format!("{OUTPUT}/libleaf.rmeta");
        assert!(
            call(&facts).is_err(),
            "an output cannot also be a retained input"
        );
    }

    fn dag_fixture(out_dir: &str) -> (DependencyActionPlan, Vec<DependencyDirectoryFact>) {
        let mut plan = plan(out_dir);
        for (name, root, file, kind) in [
            (
                "middle",
                "/work/inputs/z-first",
                "libmiddle.rmeta",
                DependencyArtifactKind::Rmeta,
            ),
            (
                "archive",
                "/work/inputs/a-second",
                "libarchive.rlib",
                DependencyArtifactKind::Rlib,
            ),
        ] {
            let path = format!("{root}/{file}");
            plan.dependency_dirs.push(root.into());
            plan.invocation
                .lib_search
                .push(format!("dependency={root}"));
            plan.invocation
                .externs
                .push((name.into(), Some(path.clone())));
            plan.externs.push(PlannedExtern::File {
                name: name.into(),
                path,
                kind,
            });
        }
        let mut directories = directories(&plan);
        directories[1].artifacts = vec![
            ExternFact {
                path: "/work/inputs/z-first/libmiddle.rmeta".into(),
                content_digest: compute("rabs.test.v1", b"direct metadata"),
            },
            ExternFact {
                path: "/work/inputs/z-first/libtransitive.rmeta".into(),
                content_digest: compute("rabs.test.v1", b"transitive metadata"),
            },
        ];
        directories[2].artifacts.push(ExternFact {
            path: "/work/inputs/a-second/libarchive.rlib".into(),
            content_digest: compute("rabs.test.v1", b"complete archive including object members"),
        });
        (plan, directories)
    }

    fn dag_key(
        plan: &DependencyActionPlan,
        directories: &[DependencyDirectoryFact],
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_dependency_key(
            plan,
            &toolchain(),
            directories,
            &inputs(plan),
            None,
            TOOLCHAIN,
            &[41; 32],
            &compute(RUNTIME_COHORT_DOMAIN, b"same-runtime"),
        )
    }

    #[test]
    fn remote_metadata_dag_binds_direct_artifacts_and_every_transitive_candidate() {
        let (plan, directories) = dag_fixture(OUTPUT);
        let remote = dag_key(&plan, &directories).unwrap();
        let local = live_dependency_key(
            &plan,
            &toolchain(),
            &remote_extern_facts(&plan, &directories).unwrap(),
            &directories,
            None,
            &inputs(&plan),
        )
        .unwrap();
        assert_eq!(
            remote.descriptor.dependency_inputs,
            local.descriptor.dependency_inputs
        );
        // Neither a direct metadata edit, a transitive search candidate edit,
        // nor an implementation member in an explicitly supplied full archive
        // may reuse this result. No reduced archive projection is introduced.
        for (directory, artifact) in [(1, 0), (1, 1), (2, 0)] {
            let mut changed = directories.clone();
            changed[directory].artifacts[artifact].content_digest =
                compute("rabs.test.v1", b"changed consumed bytes");
            let changed = dag_key(&plan, &changed).unwrap();
            assert_ne!(remote.action_key, changed.action_key);
            assert_ne!(
                remote.descriptor.dependency_inputs,
                changed.descriptor.dependency_inputs
            );
        }
        let (relocated, relocated_directories) = dag_fixture("/other/target/check/out");
        assert_eq!(
            remote.action_key,
            dag_key(&relocated, &relocated_directories)
                .unwrap()
                .action_key
        );
    }

    #[test]
    fn shared_cargo_output_directory_keys_full_externs_and_transitive_metadata() {
        let mut plan = plan(OUTPUT);
        for (name, filename, kind) in [
            ("archive", "libarchive.rlib", DependencyArtifactKind::Rlib),
            ("middle", "libmiddle.rmeta", DependencyArtifactKind::Rmeta),
        ] {
            let path = format!("{OUTPUT}/{filename}");
            plan.invocation
                .externs
                .push((name.into(), Some(path.clone())));
            plan.externs.push(PlannedExtern::File {
                name: name.into(),
                path,
                kind,
            });
        }
        let mut directories = directories(&plan);
        directories[0].artifacts = [
            ("libarchive.rlib", "full archive bytes"),
            ("libmiddle.rmeta", "direct metadata"),
            ("libtransitive.rmeta", "transitive metadata"),
        ]
        .into_iter()
        .map(|(filename, bytes)| ExternFact {
            path: format!("{OUTPUT}/{filename}"),
            content_digest: compute("rabs.test.v1", bytes.as_bytes()),
        })
        .collect();
        remote_dependency_shape(&plan, &directories, TOOLCHAIN).unwrap();
        let original = dag_key(&plan, &directories).unwrap();
        for index in 0..3 {
            let mut changed = directories.clone();
            changed[0].artifacts[index].content_digest =
                compute("rabs.test.v1", b"changed shared candidate bytes");
            assert_ne!(
                original.action_key,
                dag_key(&plan, &changed).unwrap().action_key
            );
        }
        let mut missing_transitive = directories.clone();
        missing_transitive[0].artifacts.pop();
        assert_ne!(
            original.action_key,
            dag_key(&plan, &missing_transitive).unwrap().action_key,
            "search-directory membership participates even without a direct extern",
        );
        let mut missing_direct = directories.clone();
        missing_direct[0].artifacts.remove(1);
        assert!(dag_key(&plan, &missing_direct).is_err());
        let mut output_collision = directories;
        output_collision[0].artifacts.push(ExternFact {
            path: format!("{OUTPUT}/libleaf.rmeta"),
            content_digest: compute("rabs.test.v1", b"stale own output"),
        });
        output_collision[0]
            .artifacts
            .sort_by(|left, right| left.path.cmp(&right.path));
        assert!(dag_key(&plan, &output_collision).is_err());
    }

    #[test]
    fn remote_dag_refuses_missing_reordered_executable_or_unbound_extern_inputs() {
        let (plan, directories) = dag_fixture(OUTPUT);
        let mut missing = directories.clone();
        missing[1].artifacts.remove(0);
        assert!(dag_key(&plan, &missing).is_err());
        let mut reordered = directories.clone();
        reordered.swap(1, 2);
        assert!(dag_key(&plan, &reordered).is_err());
        let mut executable = plan.clone();
        if let PlannedExtern::File { kind, .. } = &mut executable.externs[0] {
            *kind = DependencyArtifactKind::ProcMacroDylib;
        }
        assert_eq!(
            dag_key(&executable, &directories),
            Err(RemoteDependencyRefusal::ExternInputs)
        );
        let mut bare = plan.clone();
        bare.invocation.externs[0].1 = None;
        bare.externs[0] = PlannedExtern::Toolchain {
            name: "middle".into(),
        };
        assert_eq!(
            dag_key(&bare, &directories),
            Err(RemoteDependencyRefusal::ExternInputs)
        );
        let mut divergent = plan.clone();
        divergent.invocation.externs[0].1 = Some("/unobserved/libother.rmeta".into());
        assert_eq!(
            dag_key(&divergent, &directories),
            Err(RemoteDependencyRefusal::ExternInputs)
        );
    }

    fn generated_plan(root: &str) -> DependencyActionPlan {
        let mut plan = plan(OUTPUT);
        plan.generated_root = Some(root.to_owned());
        for env in [&mut plan.execution_env, &mut plan.keyed_env] {
            env.push(("OUT_DIR".into(), root.to_owned()));
            env.push(("BUILD_LABEL".into(), "pinned".into()));
            env.sort();
        }
        plan
    }

    fn generated_inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let mut inputs = inputs(plan);
        inputs.directory_enumerations[0].entries = vec![RawBytes::from("nested")];
        inputs.directory_enumerations.push(DirectoryEnumeration {
            virtual_path: RawBytes::new(plan.generated_input_virtual_path("nested").into_bytes()),
            entries: vec![RawBytes::from("generated.rs")],
        });
        inputs.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(
                plan.generated_input_virtual_path("nested/generated.rs")
                    .into_bytes(),
            ),
            object: ObjectId(compute("rabs.test.v1", b"pub const VALUE: u32 = 17;")),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        inputs
    }

    fn generated_key(
        plan: &DependencyActionPlan,
        inputs: &ActionInputManifest,
        record: Option<&[u8]>,
    ) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
        remote_dependency_key(
            plan,
            &toolchain(),
            &directories(plan),
            inputs,
            record,
            if plan.canonical_cargo {
                "/__rabs/toolchain"
            } else {
                TOOLCHAIN
            },
            &[41; 32],
            &compute(RUNTIME_COHORT_DOMAIN, b"same-runtime"),
        )
    }

    #[test]
    fn canonical_generated_compiles_bind_complete_tree_and_cargo_record_in_both_output_modes() {
        let root = "/__rabs/out/cargo/debug/build/leaf-unit/out";
        let record = b"cargo::rustc-env=BUILD_LABEL=pinned\n";
        let mut keys = Vec::new();
        for emit in [
            "dep-info,metadata",
            "dep-info,link",
            "dep-info,metadata,link",
        ] {
            let plan =
                canonical_plan_with_generated("/__rabs/out/cargo/debug/deps", emit, Some(root));
            let retained = generated_inputs(&plan);
            let original = generated_key(&plan, &retained, Some(record)).unwrap();
            assert!(
                canonical_cargo_dependency_key(
                    &plan,
                    &toolchain(),
                    &[],
                    &directories(&plan),
                    Some(record),
                    &retained,
                )
                .is_err(),
                "a canonical local completion cannot acquire generated-input authority"
            );
            let mut changed = retained.clone();
            changed.inputs.last_mut().unwrap().object =
                ObjectId(compute("rabs.test.v1", b"pub const VALUE: u32 = 99;"));
            assert_ne!(
                generated_key(&plan, &changed, Some(record))
                    .unwrap()
                    .action_key,
                original.action_key,
                "generated bytes, including assembler inputs, are semantic"
            );
            let mut added = retained.clone();
            let mut file = added.inputs.last().unwrap().clone();
            file.virtual_path =
                RawBytes::new(plan.generated_input_virtual_path("extra.bin").into_bytes());
            added.inputs.push(file);
            added.directory_enumerations[0]
                .entries
                .insert(0, RawBytes::from("extra.bin"));
            assert_ne!(
                generated_key(&plan, &added, Some(record))
                    .unwrap()
                    .action_key,
                original.action_key,
                "complete generated membership is semantic"
            );
            let mut empty_directories = retained.clone();
            empty_directories.directory_enumerations[0]
                .entries
                .insert(0, RawBytes::from("empty"));
            empty_directories.directory_enumerations.extend([
                DirectoryEnumeration {
                    virtual_path: RawBytes::new(
                        plan.generated_input_virtual_path("empty").into_bytes(),
                    ),
                    entries: vec![RawBytes::from("child")],
                },
                DirectoryEnumeration {
                    virtual_path: RawBytes::new(
                        plan.generated_input_virtual_path("empty/child")
                            .into_bytes(),
                    ),
                    entries: Vec::new(),
                },
            ]);
            assert_ne!(
                generated_key(&plan, &empty_directories, Some(record))
                    .unwrap()
                    .action_key,
                original.action_key,
                "empty generated directories remain semantic in every remote output mode"
            );
            assert_ne!(
                generated_key(
                    &plan,
                    &retained,
                    Some(
                        b"cargo::rustc-env=BUILD_LABEL=pinned\ncargo::rerun-if-changed=input.dat\n"
                    )
                )
                .unwrap()
                .action_key,
                original.action_key,
                "the exact Cargo record is semantic"
            );
            assert!(generated_key(&plan, &retained, None).is_err());
            assert!(
                generated_key(
                    &plan,
                    &retained,
                    Some(b"cargo::rustc-env=BUILD_LABEL=stale\n")
                )
                .is_err()
            );
            let moved = canonical_plan_with_generated(
                "/__rabs/out/cargo/debug/deps",
                emit,
                Some("/__rabs/out/cargo/debug/build/other-unit/out"),
            );
            assert_ne!(
                generated_key(&moved, &retained, Some(record))
                    .unwrap()
                    .action_key,
                original.action_key,
                "original canonical OUT_DIR spelling is retained"
            );
            assert_eq!(
                original.action_key,
                compute_action_key(&original.descriptor).final_key
            );
            keys.push(original.action_key);
        }
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
    }

    #[test]
    fn canonical_empty_generated_tree_is_keyed_without_inventing_a_generated_file() {
        let plan = canonical_plan_with_generated(
            "/__rabs/out/cargo/debug/deps",
            "dep-info,metadata",
            Some("/__rabs/out/cargo/debug/build/leaf-unit/out"),
        );
        let source_only = inputs(&plan);
        let empty = generated_key(&plan, &source_only, Some(b"")).unwrap();
        let no_generated = canonical_plan("/__rabs/out/cargo/debug/deps");
        let absent = generated_key(&no_generated, &inputs(&no_generated), None).unwrap();
        assert_ne!(empty.action_key, absent.action_key);
        assert_ne!(
            empty.descriptor.negative_dependencies,
            absent.descriptor.negative_dependencies
        );
        assert!(generated_key(&plan, &source_only, None).is_err());
        assert!(generated_key(&no_generated, &inputs(&no_generated), Some(b"")).is_err());
        assert_ne!(
            empty.action_key,
            generated_key(&plan, &generated_inputs(&plan), Some(b""))
                .unwrap()
                .action_key
        );
    }

    #[test]
    fn canonical_generated_stdout_requires_matching_keyed_rustc_env() {
        let mut plan = canonical_plan_with_generated(
            "/__rabs/out/cargo/debug/deps",
            "dep-info,metadata",
            Some("/__rabs/out/cargo/debug/build/leaf-generated/out"),
        );
        let stdout = b"cargo::rustc-env=GENERATED_LABEL=one\n";
        assert!(generated_key(&plan, &inputs(&plan), Some(stdout)).is_err());
        plan.execution_env
            .push(("GENERATED_LABEL".into(), "one".into()));
        plan.keyed_env
            .push(("GENERATED_LABEL".into(), "one".into()));
        plan.execution_env.sort();
        plan.keyed_env.sort();
        let original = generated_key(&plan, &inputs(&plan), Some(stdout)).unwrap();
        let changed_stdout = b"cargo::rustc-env=GENERATED_LABEL=two\n";
        assert!(generated_key(&plan, &inputs(&plan), Some(changed_stdout)).is_err());
        for environment in [&mut plan.execution_env, &mut plan.keyed_env] {
            environment
                .iter_mut()
                .find(|(name, _)| name == "GENERATED_LABEL")
                .unwrap()
                .1 = "two".into();
        }
        assert_ne!(
            original.action_key,
            generated_key(&plan, &inputs(&plan), Some(changed_stdout))
                .unwrap()
                .action_key
        );
        assert!(generated_key(&plan, &inputs(&plan), Some(stdout)).is_err());
        assert!(generated_key(&plan, &inputs(&plan), Some(b"cargo::rustc-env=broken\n")).is_err());
    }

    #[test]
    fn canonical_generated_paths_and_dep_info_cannot_escape_the_retained_tree() {
        let root = "/__rabs/out/cargo/debug/build/leaf-unit/out";
        let plan = canonical_plan_with_generated(
            "/__rabs/out/cargo/debug/deps",
            "dep-info,metadata",
            Some(root),
        );
        let retained = generated_inputs(&plan);
        let record = b"cargo::rustc-env=BUILD_LABEL=pinned\n";
        generated_key(&plan, &retained, Some(record)).unwrap();
        let raw = format!(
            "{}/leaf.d: {}/src/lib.rs {root}/nested/generated.rs\n# env-dep:OUT_DIR={root}\n",
            plan.out_dir, plan.source_root
        );
        let captured = |path: &str| {
            retained
                .inputs
                .iter()
                .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
        };
        assert!(
            super::super::dep_info_closure_violation(&plan, raw.as_bytes(), captured).is_none()
        );
        assert_eq!(
            super::super::canonicalize_placements(raw.as_bytes(), &plan).unwrap(),
            raw.as_bytes()
        );
        let diagnostic = format!(
            "{{\"$message_type\":\"diagnostic\",\"message\":\"generated input {root}/nested/generated.rs\"}}\n"
        );
        assert_eq!(
            super::super::canonicalize_compiler_transcript(diagnostic.as_bytes(), &plan).unwrap(),
            diagnostic.as_bytes(),
        );
        let uncaptured = raw.replace("nested/generated.rs", "nested/missing.rs");
        assert!(
            super::super::dep_info_closure_violation(&plan, uncaptured.as_bytes(), captured)
                .is_some()
        );
        let escaped = raw.replace(
            &format!("{root}/nested/generated.rs"),
            "/__rabs/home/control/rustc.sock",
        );
        assert!(
            super::super::dep_info_closure_violation(&plan, escaped.as_bytes(), |_| true).is_some(),
            "a claimed capture cannot authorize a read outside the package and generated tree"
        );

        for bad in [
            "/__rabs/home/control",
            "/__rabs/cargo-home/registry/generated",
            "/__rabs/workspace/generated",
            "/__rabs/out/cargo",
            "/__rabs/out/cargo/debug/deps",
            "/__rabs/out/cargo/debug/deps/nested",
            "/__rabs/out/cargo/debug",
            "/__rabs/out/cargo/../escape",
            "/__rabs/out/cargo-other/debug/build/leaf/out",
            "/__rabs/toolchain/generated",
            "/tmp/host-generated",
            "/usr/generated",
        ] {
            let mut bad_plan = plan.clone();
            bad_plan.generated_root = Some(bad.into());
            for env in [&mut bad_plan.execution_env, &mut bad_plan.keyed_env] {
                env.iter_mut()
                    .find(|(name, _)| name == "OUT_DIR")
                    .unwrap()
                    .1 = bad.into();
            }
            assert!(
                generated_key(&bad_plan, &retained, Some(record)).is_err(),
                "{bad}"
            );
        }
        let mut missing = plan.clone();
        missing.generated_root = None;
        assert!(generated_key(&missing, &retained, Some(record)).is_err());
        let mut duplicate = plan.clone();
        duplicate
            .execution_env
            .push(("OUT_DIR".into(), root.into()));
        assert!(generated_key(&duplicate, &retained, Some(record)).is_err());
        let mut missing_environment = plan.clone();
        missing_environment
            .execution_env
            .retain(|(name, _)| name != "OUT_DIR");
        assert!(generated_key(&missing_environment, &retained, Some(record)).is_err());
        let mut mismatched_environment = plan.clone();
        mismatched_environment
            .execution_env
            .iter_mut()
            .find(|(name, _)| name == "OUT_DIR")
            .unwrap()
            .1 = "/__rabs/out/cargo/debug/build/other-unit/out".into();
        assert!(generated_key(&mismatched_environment, &retained, Some(record)).is_err());
        let mut candidate_alias = plan.clone();
        candidate_alias.dependency_dirs.push(root.into());
        assert!(generated_key(&candidate_alias, &retained, Some(record)).is_err());
    }

    #[test]
    fn canonical_generated_loader_parent_stays_empty_and_cannot_load_generated_libraries() {
        let root = "/__rabs/out/cargo/debug/build/leaf-unit/out";
        let plan = canonical_plan_with_generated(
            "/__rabs/out/cargo/debug/deps",
            "dep-info,metadata",
            Some(root),
        );
        // Cargo puts this ancestor on its loader path. It remains an empty
        // skeleton above the separately bound read-only generated input tree.
        assert!(
            remote_empty_loader_directories(&plan, "/__rabs/toolchain")
                .unwrap()
                .contains(&"/__rabs/out/cargo/debug".to_owned())
        );
        remote_dependency_shape(&plan, &directories(&plan), "/__rabs/toolchain").unwrap();
        for loader in [root.to_owned(), format!("{root}/lib")] {
            let mut changed = plan.clone();
            changed
                .execution_env
                .iter_mut()
                .find(|(name, _)| name == "LD_LIBRARY_PATH")
                .unwrap()
                .1 = loader;
            assert!(matches!(
                remote_dependency_shape(&changed, &directories(&changed), "/__rabs/toolchain"),
                Err(RemoteDependencyRefusal::LoaderEnvironment(_))
            ));
        }
    }

    #[test]
    fn generated_metadata_binds_complete_files_cargo_record_and_original_path() {
        let plan = generated_plan("/work/target/debug/build/leaf/out");
        let inputs = generated_inputs(&plan);
        let record = b"cargo::rustc-env=BUILD_LABEL=pinned\n";
        let remote = generated_key(&plan, &inputs, Some(record)).unwrap();
        let local = live_dependency_key(
            &plan,
            &toolchain(),
            &[],
            &directories(&plan),
            Some(record),
            &inputs,
        )
        .unwrap();
        assert_eq!(
            remote.descriptor.action_inputs,
            local.descriptor.action_inputs
        );
        assert_eq!(remote.descriptor.environment, local.descriptor.environment);
        assert_eq!(
            remote.descriptor.dependency_inputs,
            local.descriptor.dependency_inputs
        );
        assert_eq!(
            remote.descriptor.negative_dependencies,
            local.descriptor.negative_dependencies
        );
        assert_ne!(remote.action_key, local.action_key);

        let mut changed = inputs.clone();
        changed.inputs.last_mut().unwrap().object =
            ObjectId(compute("rabs.test.v1", b"pub const VALUE: u32 = 23;"));
        assert_ne!(
            remote.action_key,
            generated_key(&plan, &changed, Some(record))
                .unwrap()
                .action_key
        );

        let mut added = inputs.clone();
        let mut member = added.inputs.last().unwrap().clone();
        member.virtual_path =
            RawBytes::new(plan.generated_input_virtual_path("new.rs").into_bytes());
        added.inputs.push(member);
        added.directory_enumerations[0]
            .entries
            .push(RawBytes::from("new.rs"));
        assert_ne!(
            remote.action_key,
            generated_key(&plan, &added, Some(record))
                .unwrap()
                .action_key
        );

        let other_record =
            b"cargo::rustc-env=BUILD_LABEL=pinned\ncargo::rerun-if-env-changed=CONFIG\n";
        assert_ne!(
            remote.action_key,
            generated_key(&plan, &inputs, Some(other_record))
                .unwrap()
                .action_key
        );
        let relocated = generated_plan("/other/target/debug/build/leaf/out");
        let relocated = generated_key(&relocated, &inputs, Some(record)).unwrap();
        assert_eq!(
            remote.descriptor.action_inputs,
            relocated.descriptor.action_inputs
        );
        assert_ne!(
            remote.descriptor.environment,
            relocated.descriptor.environment
        );
        assert_ne!(
            remote.descriptor.negative_dependencies,
            relocated.descriptor.negative_dependencies
        );
        assert_ne!(remote.action_key, relocated.action_key);
    }

    #[test]
    fn empty_generated_tree_is_distinct_and_still_requires_the_cargo_record() {
        let generated = generated_plan("/work/build/leaf/out");
        let inputs = inputs(&generated);
        let empty = generated_key(&generated, &inputs, Some(b"")).unwrap();
        assert_ne!(
            empty.action_key,
            key(&plan(OUTPUT), b"same-runtime").action_key
        );
        assert!(matches!(
            generated_key(&generated, &inputs, None),
            Err(RemoteDependencyRefusal::Local(LiveRefusal::Facts(reason)))
                if reason.contains("missing build-script output record")
        ));
        assert!(matches!(
            generated_key(&plan(OUTPUT), &inputs, Some(b"")),
            Err(RemoteDependencyRefusal::Local(LiveRefusal::Facts(reason)))
                if reason.contains("unexpected build-script output record")
        ));
        let populated =
            generated_key(&generated, &generated_inputs(&generated), Some(b"")).unwrap();
        assert_ne!(empty.action_key, populated.action_key);
    }

    #[test]
    fn generated_rustc_env_and_read_closure_are_not_bypassed_remotely() {
        let mut plan = generated_plan("/work/build/leaf/out");
        let inputs = generated_inputs(&plan);
        assert_eq!(
            generated_key(
                &plan,
                &inputs,
                Some(b"cargo::rustc-env=BUILD_LABEL=stale\n")
            ),
            Err(RemoteDependencyRefusal::Local(LiveRefusal::RefusedEnv(
                "BUILD_LABEL".into()
            )))
        );
        let dep_info = format!(
            "{OUTPUT}/leaf.d: {PACKAGE}/src/lib.rs /work/build/leaf/out/nested/generated.rs\n# env-dep:OUT_DIR=/work/build/leaf/out\n"
        );
        let captured = |path: &str| {
            inputs
                .inputs
                .iter()
                .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
        };
        assert!(
            super::super::dep_info_closure_violation(&plan, dep_info.as_bytes(), captured)
                .is_none()
        );
        let unobserved = dep_info.replace("nested/generated.rs", "nested/unobserved.rs");
        assert!(
            super::super::dep_info_closure_violation(&plan, unobserved.as_bytes(), captured)
                .is_some()
        );
        // The existing empty-OUT_DIR optimization leaves a tracked-read veto
        // in the plan. Remote key composition must not restore that variable
        // silently or discard the veto when the environment is replayed.
        plan.keyed_env.retain(|(name, _)| name != "OUT_DIR");
        generated_key(&plan, &inputs, Some(b"")).unwrap();
        assert_eq!(
            super::super::dep_info_closure_violation(&plan, dep_info.as_bytes(), captured),
            Some("tracked read of unkeyed variable OUT_DIR".into())
        );
    }

    #[test]
    fn generated_binding_refuses_missing_duplicate_mismatched_or_overlapping_roots() {
        let generated = generated_plan("/work/build/leaf/out");
        remote_dependency_shape(&generated, &directories(&generated), TOOLCHAIN).unwrap();
        let mut missing = generated.clone();
        missing.execution_env.retain(|(name, _)| name != "OUT_DIR");
        let mut duplicate = generated.clone();
        duplicate
            .execution_env
            .push(("OUT_DIR".into(), "/work/build/leaf/out".into()));
        let mut mismatched = generated.clone();
        mismatched.generated_root = Some("/other/generated".into());
        let mut undeclared = generated.clone();
        undeclared.generated_root = None;
        for plan in [missing, duplicate, mismatched, undeclared] {
            assert_eq!(
                remote_dependency_shape(&plan, &directories(&plan), TOOLCHAIN),
                Err(RemoteDependencyRefusal::GeneratedInputs)
            );
        }
        for root in [
            PACKAGE,
            OUTPUT,
            "/work/target/debug",
            "/toolchain/generated",
            "/usr/generated",
            "/proc",
            "/work/../generated",
            "relative",
        ] {
            let plan = generated_plan(root);
            assert_eq!(
                remote_dependency_shape(&plan, &directories(&plan), TOOLCHAIN),
                Err(RemoteDependencyRefusal::GeneratedInputs),
                "{root}"
            );
        }
        let (mut plan, facts) = dag_fixture(OUTPUT);
        plan.generated_root = Some("/work/inputs/z-first/nested".into());
        plan.execution_env
            .push(("OUT_DIR".into(), "/work/inputs/z-first/nested".into()));
        assert_eq!(
            remote_dependency_shape(&plan, &facts, TOOLCHAIN),
            Err(RemoteDependencyRefusal::GeneratedInputs)
        );
    }

    #[test]
    fn generated_tree_cannot_silently_become_a_loader_directory() {
        let mut plan = generated_plan("/work/target/debug/build/leaf/out");
        for loader in [
            "/work/target/debug/build/leaf/out",
            "/work/target/debug/build/leaf/out/lib",
        ] {
            plan.execution_env
                .retain(|(name, _)| name != "LD_LIBRARY_PATH");
            plan.execution_env
                .push(("LD_LIBRARY_PATH".into(), loader.into()));
            assert!(matches!(
                remote_dependency_shape(&plan, &directories(&plan), TOOLCHAIN),
                Err(RemoteDependencyRefusal::LoaderEnvironment(_))
            ));
        }
        plan.execution_env
            .retain(|(name, _)| name != "LD_LIBRARY_PATH");
        plan.execution_env.push((
            "LD_LIBRARY_PATH".into(),
            "/work/target/debug:/toolchain/lib".into(),
        ));
        assert_eq!(
            remote_empty_loader_directories(&plan, TOOLCHAIN).unwrap(),
            ["/work/target/debug"]
        );
        remote_dependency_shape(&plan, &directories(&plan), TOOLCHAIN).unwrap();
    }

    #[test]
    fn generated_inputs_do_not_admit_undeclared_archive_outputs_or_reads() {
        let mut plan = generated_plan("/work/build/leaf/out");
        let mut inputs = generated_inputs(&plan);
        plan.invocation.emit.push("link".into());
        assert!(matches!(
            generated_key(&plan, &inputs, Some(b"")),
            Err(RemoteDependencyRefusal::Local(LiveRefusal::Facts(_)))
        ));
        plan.invocation.emit.pop();
        inputs.inputs.last_mut().unwrap().virtual_path =
            RawBytes::new(b"/usr/lib/unobserved".to_vec());
        assert!(matches!(
            generated_key(&plan, &inputs, Some(b"")),
            Err(RemoteDependencyRefusal::Local(LiveRefusal::Facts(_)))
        ));
    }

    #[test]
    fn unmodeled_link_extern_incoherent_generated_and_invented_runtime_inputs_are_refused() {
        let runtime = compute(RUNTIME_COHORT_DOMAIN, b"runtime");
        let call = |plan: &DependencyActionPlan, runtime: &TypedDigest| {
            remote_dependency_key(
                plan,
                &toolchain(),
                &directories(plan),
                &inputs(plan),
                None,
                TOOLCHAIN,
                &[41; 32],
                runtime,
            )
        };
        let mut linked = plan(OUTPUT);
        linked.invocation.emit.push("link".into());
        assert!(matches!(
            call(&linked, &runtime),
            Err(RemoteDependencyRefusal::Local(LiveRefusal::Facts(_)))
        ));
        let mut external = plan(OUTPUT);
        external.externs.push(PlannedExtern::Toolchain {
            name: "proc_macro".into(),
        });
        assert_eq!(
            call(&external, &runtime),
            Err(RemoteDependencyRefusal::ExternInputs)
        );
        let mut generated = plan(OUTPUT);
        generated.generated_root = Some("/work/generated".into());
        assert_eq!(
            call(&generated, &runtime),
            Err(RemoteDependencyRefusal::GeneratedInputs)
        );
        assert_eq!(
            call(
                &plan(OUTPUT),
                &compute("rabs.operator-cohort-label.v1", b"same-machine")
            ),
            Err(RemoteDependencyRefusal::RuntimeIdentity)
        );
        assert_eq!(
            call(
                &plan(OUTPUT),
                &compute("rabs.rustc-host-runtime.v1", b"runtime")
            ),
            Err(RemoteDependencyRefusal::RuntimeIdentity)
        );
    }

    #[test]
    fn loader_mapping_preserves_order_and_refuses_hidden_host_inputs() {
        let mut plan = plan(OUTPUT);
        let set = |plan: &mut DependencyActionPlan, value: &str| {
            plan.execution_env
                .retain(|(name, _)| name != "LD_LIBRARY_PATH");
            plan.execution_env
                .push(("LD_LIBRARY_PATH".into(), value.into()));
        };
        set(
            &mut plan,
            "/toolchain/lib:/work/target/debug/deps:/toolchain:/toolchain/lib/rustlib",
        );
        assert_eq!(
            remote_loader_search_paths(&plan, TOOLCHAIN).unwrap(),
            ["lib", "", "lib/rustlib"]
        );
        assert_eq!(
            remote_empty_loader_directories(&plan, TOOLCHAIN).unwrap(),
            [OUTPUT]
        );
        set(
            &mut plan,
            "/work/target/debug/deps:/work/target/debug:/toolchain/lib:/work/target/debug",
        );
        assert_eq!(
            remote_loader_search_paths(&plan, TOOLCHAIN).unwrap(),
            ["lib"]
        );
        assert_eq!(
            remote_empty_loader_directories(&plan, TOOLCHAIN).unwrap(),
            ["/work/target/debug", "/work/target/debug/deps"]
        );
        for value in [
            "",
            ":/toolchain/lib",
            "/toolchain/lib:",
            "lib",
            "/toolchain/lib/../other",
            "/usr/lib",
            "/work/target/debug/deps/subdir",
        ] {
            set(&mut plan, value);
            assert!(
                remote_loader_search_paths(&plan, TOOLCHAIN).is_err(),
                "{value:?}"
            );
        }
        set(&mut plan, "/toolchain/lib");
        for name in ["LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "GLIBC_TUNABLES"] {
            plan.execution_env.push((name.into(), "".into()));
            assert!(
                remote_loader_search_paths(&plan, TOOLCHAIN).is_err(),
                "{name}"
            );
            plan.execution_env.pop();
        }
        plan.execution_env
            .retain(|(name, _)| name != "LD_LIBRARY_PATH");
        assert_eq!(
            remote_loader_search_paths(&plan, TOOLCHAIN).unwrap(),
            Vec::<String>::new()
        );
    }
}
