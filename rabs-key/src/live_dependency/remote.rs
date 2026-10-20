//! Metadata-only dependency actions executed in a closed worker view.
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
//! and checked again by the worker before execution. A configured cohort label
//! or target triple cannot replace that observation. This pure module checks
//! its domain and binds its bytes; authenticated delivery, observation and
//! attempt authority remain the callers' responsibilities.

use rabs_protocol::input_evidence::ActionInputManifest;
use rabs_protocol::result_identity::TypedDigest;

use super::{
    DependencyActionPlan, DependencyDirectoryFact, ExternFact, LiveDependencyKey, LiveRefusal,
    PlannedExtern, ToolchainFacts, live_dependency_key, plain_path, within,
};
use crate::action_key::compute_action_key;
use crate::canonical::CanonicalEncoder;
use crate::extern_resolution::DependencyArtifactKind;
use crate::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use crate::output_derivation::derive_dependency_output_declarations;
use crate::output_platform::{CpuBaseline, OutputPlatformContract};
use crate::typed_digest::compute;

/// Required observer domain; kept in sync with the sandbox runtime observer.
pub const RUNTIME_COHORT_DOMAIN: &str = "rabs.rustc-host-runtime.v1";
/// Isolation policy domain for the remote metadata dependency class.
pub const REMOTE_DEPENDENCY_ISOLATION_DOMAIN: &str = "rabs.remote-leaf.isolation.v1";
/// Complete retained toolchain bytes, joined with the observed compiler contract.
pub const REMOTE_TOOLCHAIN_DOMAIN: &str = "rabs.remote-leaf.toolchain.v1";
/// Versioned execution policy, deliberately separate from local-edge evidence.
pub const REMOTE_DEPENDENCY_ISOLATION_PROFILE: &str = "remote-dependency-metadata-v5: \
    Linux worker namespace; subscriber paths preserved; complete regular-file \
    dependency source, exact toolchain and complete crate-candidate inventories \
    mounted read-only; explicit rmeta and complete rlib extern bytes retained; \
    complete generated OUT_DIR tree retained read-only at its original path, \
    including an empty tree, with exact captured Cargo stdout and rustc-env \
    directives bound; build-script execution is not cached; no bare extern, \
    proc-macro or native inputs; metadata and dep-info \
    only; shared input/output roots use exact read-only file mounts above private \
    writable output backing, with owned input placeholders verified and excluded \
    from exact output capture; declared outputs cannot alias inputs; empty inventories \
    receive private empty backings; outputs private until complete authenticated \
    delivery; network denied; compiler environment preserved by dependency-env-v2 \
    except process-local jobserver descriptors; all loader paths within the exact \
    toolchain or independently observed dependency-exec-v5 directories without \
    dynamic libraries, including Cargo output parents; host ELF runtime, CPU and \
    filesystem cohort observed and independently matched before execution; \
    dep-info closure and tracked-environment checks required before coordinator-only \
    publication; full-result readiness";

/// Why an otherwise admitted dependency cannot use this remote class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteDependencyRefusal {
    /// Source, toolchain, output or other local-plan facts were inconsistent.
    Local(LiveRefusal),
    /// Only --emit=dep-info,metadata is currently executed remotely.
    MetadataOnly,
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
            Self::MetadataOnly => "REMOTE_DEP_METADATA_ONLY",
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
/// Sorted and deduplicated for the dependency-exec-v5 worker context. This
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
    if !plain_path(toolchain_root)
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
            if !plain_path(entry) {
                return Err(RemoteDependencyRefusal::LoaderEnvironment(
                    "LD_LIBRARY_PATH contains an empty, relative or unrepresentable entry".into(),
                ));
            }
            if entry == toolchain_root {
                search_paths.push(String::new());
            } else if within(entry, toolchain_root) {
                search_paths.push(entry[toolchain_root.len() + 1..].to_owned());
            } else {
                if overlaps(entry, toolchain_root)
                    || overlaps(entry, &plan.source_root)
                    || [
                        "/__rabs", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc",
                        "/dev", "/sys", "/run",
                    ]
                    .iter()
                    .any(|reserved| overlaps(entry, reserved))
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

/// Check the remote metadata shape before expensive capture or runtime observation.
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
    if plan.invocation.emit.len() != 2
        || !plan.invocation.emit.iter().any(|kind| kind == "metadata")
        || !plan.invocation.emit.iter().any(|kind| kind == "dep-info")
    {
        return Err(RemoteDependencyRefusal::MetadataOnly);
    }
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
    if !plain_path(root)
        || root.contains(&plan.out_dir)
        || [
            plan.source_root.as_str(),
            plan.out_dir.as_str(),
            toolchain_root,
        ]
        .into_iter()
        .chain(plan.dependency_dirs.iter().map(String::as_str))
        .chain([
            "/__rabs", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/dev", "/sys",
            "/run",
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

/// Key an admitted, fully observed metadata-only dependency for remote execution.
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
    let mut key = live_dependency_key(
        plan,
        toolchain,
        &externs,
        directories,
        build_script_output,
        inputs,
    )?;
    let mut retained_toolchain = CanonicalEncoder::new();
    retained_toolchain
        .str(key.descriptor.toolchain.domain)
        .bytes(&key.descriptor.toolchain.bytes)
        .str("toolchain-dataset-v1")
        .bytes(retained_toolchain_sha256);
    key.descriptor.toolchain = compute(REMOTE_TOOLCHAIN_DOMAIN, &retained_toolchain.finish());
    let mut policy = CanonicalEncoder::new();
    policy
        .str(REMOTE_DEPENDENCY_ISOLATION_PROFILE)
        .str(plan.source_kind.as_str());
    key.descriptor.sandbox_semantic_policy =
        compute(REMOTE_DEPENDENCY_ISOLATION_DOMAIN, &policy.finish());
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
        linker_format: "metadata-only-no-linker-v1".to_owned(),
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
    use super::*;
    use crate::live_dependency::{LiveRustcRequest, plan_dependency_action};
    use rabs_protocol::input_evidence::{
        INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
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
            TOOLCHAIN,
            &[41; 32],
            &compute(RUNTIME_COHORT_DOMAIN, b"same-runtime"),
        )
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
    fn generated_inputs_do_not_admit_archive_codegen_or_undeclared_reads() {
        let mut plan = generated_plan("/work/build/leaf/out");
        let mut inputs = generated_inputs(&plan);
        plan.invocation.emit.push("link".into());
        assert_eq!(
            generated_key(&plan, &inputs, Some(b"")),
            Err(RemoteDependencyRefusal::MetadataOnly)
        );
        plan.invocation.emit.pop();
        inputs.inputs.last_mut().unwrap().virtual_path =
            RawBytes::new(b"/usr/lib/unobserved".to_vec());
        assert!(matches!(
            generated_key(&plan, &inputs, Some(b"")),
            Err(RemoteDependencyRefusal::Local(LiveRefusal::Facts(_)))
        ));
    }

    #[test]
    fn link_extern_incoherent_generated_and_invented_runtime_inputs_are_refused() {
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
        assert_eq!(
            call(&linked, &runtime),
            Err(RemoteDependencyRefusal::MetadataOnly)
        );
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
