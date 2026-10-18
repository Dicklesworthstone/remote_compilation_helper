//! Metadata-only dependency actions executed in a closed worker view.
//!
//! This class has distinct isolation and platform identity from unsandboxed
//! local dependency execution. The worker retains subscriber source, cwd,
//! toolchain and output spellings, mounts the complete captured package and
//! toolchain read-only, and supplies private empty dependency directories.
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
    DependencyActionPlan, DependencyDirectoryFact, LiveDependencyKey, LiveRefusal, ToolchainFacts,
    live_dependency_key, plain_path, within,
};
use crate::action_key::compute_action_key;
use crate::canonical::CanonicalEncoder;
use crate::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use crate::output_derivation::derive_dependency_output_declarations;
use crate::output_platform::{CpuBaseline, OutputPlatformContract};
use crate::typed_digest::compute;

/// Required observer domain; kept in sync with the sandbox runtime observer.
pub const RUNTIME_COHORT_DOMAIN: &str = "rabs.rustc-host-runtime.v1";
/// Isolation policy domain for the remote leaf class.
pub const REMOTE_DEPENDENCY_ISOLATION_DOMAIN: &str = "rabs.remote-leaf.isolation.v1";
/// Complete retained toolchain bytes, joined with the observed compiler contract.
pub const REMOTE_TOOLCHAIN_DOMAIN: &str = "rabs.remote-leaf.toolchain.v1";
/// Versioned execution policy, deliberately separate from local-edge evidence.
pub const REMOTE_DEPENDENCY_ISOLATION_PROFILE: &str = "remote-leaf-metadata-v2: \
    Linux worker namespace; subscriber paths preserved; complete regular-file \
    dependency source and exact toolchain mounted read-only; no extern, \
    proc-macro, generated or native inputs; metadata and dep-info only; \
    dependency search directories privately empty at spawn; outputs private \
    until complete authenticated delivery; network denied; compiler environment \
    preserved by dependency-env-v2 except process-local jobserver descriptors; \
    all loader paths within the exact toolchain or independently observed \
    private-empty dependency-exec-v2 directories, including Cargo output parents; \
    host ELF runtime, CPU and filesystem cohort observed and independently \
    matched before execution; dep-info closure and tracked-environment checks \
    required before coordinator-only publication; full-result readiness";

/// Why an otherwise admitted dependency cannot use this remote class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteDependencyRefusal {
    /// Source, toolchain, output or other local-plan facts were inconsistent.
    Local(LiveRefusal),
    /// Only --emit=dep-info,metadata is currently executed remotely.
    MetadataOnly,
    /// Generated/build-script inputs are outside the leaf closure.
    GeneratedInputs,
    /// Any explicit extern, including a bare name, leaves the leaf class.
    ExternInputs,
    /// Native input or host-dependent CPU selection.
    NativeInputs,
    /// A directory contains compiler-loadable candidates.
    NonemptyDependencyDirectory(String),
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
            Self::NonemptyDependencyDirectory(_) => "REMOTE_DEP_DIRECTORY_NOT_EMPTY",
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
            Self::NonemptyDependencyDirectory(path)
            | Self::ToolchainPath(path)
            | Self::LoaderEnvironment(path) => write!(formatter, "{}: {path}", self.code()),
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
/// Sorted and deduplicated for the dependency-exec-v2 worker context. This
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

/// Check the remote leaf shape before expensive capture or runtime observation.
///
/// This has no filesystem access and needs neither a retained toolchain nor a
/// runtime digest. It checks the same invocation, output, loader and complete
/// empty-directory restrictions that remote_dependency_key enforces again.
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
    if plan.generated_root.is_some() || plan.execution_env.iter().any(|(name, _)| name == "OUT_DIR")
    {
        return Err(RemoteDependencyRefusal::GeneratedInputs);
    }
    if !plan.externs.is_empty() || !plan.invocation.externs.is_empty() {
        return Err(RemoteDependencyRefusal::ExternInputs);
    }
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
    for directory in directories {
        if !directory.artifacts.is_empty() {
            return Err(RemoteDependencyRefusal::NonemptyDependencyDirectory(
                directory.path.clone(),
            ));
        }
    }
    remote_loader_search_paths(plan, toolchain_root)?;
    Ok(())
}

/// Key an admitted, fully observed metadata-only leaf for remote execution.
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
/// is the output directory, and every inventory must be empty. Retain and
/// revalidate these observations through dispatch and install fresh private
/// empty worker directories, never the worker's host target tree.
///
/// # Errors
/// A typed refusal for unsupported invocation shape, incomplete closure facts
/// or a runtime identity with another domain.
pub fn remote_dependency_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    directories: &[DependencyDirectoryFact],
    inputs: &ActionInputManifest,
    toolchain_root: &str,
    retained_toolchain_sha256: &[u8; 32],
    runtime: &TypedDigest,
) -> Result<LiveDependencyKey, RemoteDependencyRefusal> {
    if runtime.domain != RUNTIME_COHORT_DOMAIN {
        return Err(RemoteDependencyRefusal::RuntimeIdentity);
    }
    remote_dependency_shape(plan, directories, toolchain_root)?;
    let mut key = live_dependency_key(plan, toolchain, &[], directories, None, inputs)?;
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
    use crate::live_dependency::{
        ExternFact, LiveRustcRequest, PlannedExtern, plan_dependency_action,
    };
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
    fn every_search_inventory_is_required_and_must_be_empty() {
        let plan = plan(OUTPUT);
        let runtime = compute(RUNTIME_COHORT_DOMAIN, b"runtime");
        let call = |directories: &[DependencyDirectoryFact]| {
            remote_dependency_key(
                &plan,
                &toolchain(),
                directories,
                &inputs(&plan),
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
        assert!(matches!(
            call(&facts),
            Err(RemoteDependencyRefusal::NonemptyDependencyDirectory(_))
        ));
        assert!(call(&directories(&plan)).is_ok());
    }

    #[test]
    fn link_extern_generated_and_invented_runtime_inputs_are_refused() {
        let runtime = compute(RUNTIME_COHORT_DOMAIN, b"runtime");
        let call = |plan: &DependencyActionPlan, runtime: &TypedDigest| {
            remote_dependency_key(
                plan,
                &toolchain(),
                &directories(plan),
                &inputs(plan),
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
