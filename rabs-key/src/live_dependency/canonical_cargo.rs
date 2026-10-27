//! External dependency checks inside a coordinator-owned canonical Cargo run.
//!
//! Source admission remains the existing registry/Git/directory-source class.
//! The distinct isolation component prevents an ordinary edge execution from
//! supplying evidence to a canonical Cargo run, even if a caller happens to
//! use the same path spellings on its host. Local capture remains metadata-only;
//! archive codegen and generated inputs require the separately keyed, enforced
//! worker view. Neither
//! path grants workspace publication or claims that the whole Cargo process
//! has a minimal hermetic input view.

use super::{
    DependencyActionPlan, DependencyDirectoryFact, DependencyPlanningMode, DependencySourceKind,
    ExternFact, LiveDependencyKey, LiveRefusal, LiveRustcRequest, ToolchainFacts,
    check_dependency_cache_read_closure, dependency_key, dependency_source, directory_source,
    env_value, plain_path_in_profile, plan_with_directory_manifest, within,
};
use crate::action_key::compute_action_key;
use crate::canonical::CanonicalEncoder;
use crate::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use crate::typed_digest::compute;
use rabs_protocol::input_evidence::ActionInputManifest;
use rabs_protocol::result_identity::TypedDigest;

const COMPILER: &str = "/__rabs/toolchain/bin/rustc";
const CARGO_HOME: &str = "/__rabs/cargo-home";
const WORKSPACE: &str = "/__rabs/workspace";
const TARGET: &str = "/__rabs/out/cargo";
const HOME: &str = "/__rabs/home";
const ISOLATION_DOMAIN: &str = "rabs.canonical-cargo-dependency.isolation.v1";
const ISOLATION_PROFILE: &str = "canonical-cargo-external-metadata-v1: \
    local coordinator-owned Cargo namespace and retained logical-to-physical \
    input/output mappings; actual Cargo planning, rustc argv, cwd and compiler \
    environment use the fixed canonical layout; complete captured external \
    registry, Git or directory-source inputs and exact Rust crate-candidate \
    inventories revalidated before serving and after execution; metadata and \
    dep-info only; existing dep-info and tracked-environment closure required; \
    no workspace publication, primary packages, generated compiler inputs, \
    build-script execution, proc-macro execution or codegen authority; \
    actual compiler paths preserved through replay inside the same canonical \
    namespace; coordinator-only publication with the ordinary evidence gates";

pub(super) fn canonical_layout(plan: &DependencyActionPlan) -> Result<(), LiveRefusal> {
    if plan.source_kind == DependencySourceKind::WorkspaceExecutionOnly {
        return Err(LiveRefusal::Facts(
            "workspace execution-only plans cannot use canonical dependency authority".into(),
        ));
    }
    super::remote::validate_generated_native_inputs(
        &plan.invocation,
        plan.generated_root.as_deref(),
        plan.canonical_cargo,
    )?;
    let mut presented = plan
        .execution_env
        .iter()
        .filter(|(name, _)| name == "OUT_DIR")
        .map(|(_, value)| value.as_str());
    if presented.next() != plan.generated_root.as_deref() || presented.next().is_some() {
        return Err(LiveRefusal::Facts(
            "canonical Cargo generated inputs must bind the exact OUT_DIR environment".into(),
        ));
    }
    if let Some(root) = &plan.generated_root {
        let overlaps = |other: &str| root == other || within(root, other) || within(other, root);
        if !plain_path_in_profile(root, true)
            || !within(root, TARGET)
            || [
                plan.source_root.as_str(),
                plan.out_dir.as_str(),
                "/__rabs/toolchain",
            ]
            .into_iter()
            .chain(plan.dependency_dirs.iter().map(String::as_str))
            .any(overlaps)
        {
            return Err(LiveRefusal::Facts(
                "canonical Cargo generated inputs must be disjoint within the Cargo target".into(),
            ));
        }
    }
    if env_value(&plan.execution_env, "CARGO_PRIMARY_PACKAGE").is_some() {
        return Err(LiveRefusal::RefusedEnv("CARGO_PRIMARY_PACKAGE".into()));
    }
    if plan.invocation.cap_lints.as_deref() != Some("allow") {
        return Err(LiveRefusal::NotDependencyCompile(
            "canonical Cargo dependency checks retain external dependency lint admission",
        ));
    }
    if !plan.canonical_cargo
        || plan.compiler != COMPILER
        || plan.invocation.compiler_argv0 != COMPILER
        || env_value(&plan.execution_env, "CARGO_HOME") != Some(CARGO_HOME)
        || env_value(&plan.execution_env, "HOME") != Some(HOME)
        || env_value(&plan.execution_env, "CARGO_MANIFEST_DIR") != Some(plan.package_root.as_str())
        || plan.cwd != plan.package_root
        || !plain_path_in_profile(&plan.out_dir, true)
        || !within(&plan.out_dir, TARGET)
        || plan.invocation.out_dir.as_deref() != Some(plan.out_dir.as_str())
        || plan
            .dependency_dirs
            .iter()
            .any(|directory| !plain_path_in_profile(directory, true) || !within(directory, TARGET))
    {
        return Err(LiveRefusal::Facts(
            "canonical Cargo dependency facts do not use the prepared visible layout".into(),
        ));
    }
    let (kind, root, name) = match plan.source_kind {
        DependencySourceKind::RegistryPackage | DependencySourceKind::GitCheckout => {
            dependency_source(CARGO_HOME, &plan.package_root, true)?
        }
        DependencySourceKind::DirectoryPackage => {
            if !within(&plan.package_root, WORKSPACE) {
                return Err(LiveRefusal::NotDependencySource(plan.package_root.clone()));
            }
            directory_source(CARGO_HOME, &plan.package_root, true)?
        }
        DependencySourceKind::WorkspaceExecutionOnly => {
            return Err(LiveRefusal::NotDependencySource(plan.package_root.clone()));
        }
    };
    if kind != plan.source_kind || root != plan.source_root || name != plan.source_dir_name {
        return Err(LiveRefusal::Facts(
            "canonical Cargo dependency source differs from the admitted source layout".into(),
        ));
    }
    Ok(())
}

/// Mutable Cargo outputs require an independently retained closed worker
/// execution. Canonical path spelling alone cannot authorize local capture.
fn local_metadata_layout(plan: &DependencyActionPlan) -> Result<(), LiveRefusal> {
    canonical_layout(plan)?;
    if plan.generated_root.is_some() {
        return Err(LiveRefusal::Facts(
            "canonical Cargo generated inputs require isolated worker execution".into(),
        ));
    }
    Ok(())
}

/// Plan an external dependency check in a prepared canonical Cargo context.
///
/// Only the coordinator's retained per-command context may select this entry
/// point. An ordinary wrapper request must use [`super::plan_dependency_action`]
/// or [`super::plan_directory_dependency_action`], which continue to refuse
/// reserved canonical paths. An optional directory-source checksum identity
/// must come from observing the prepared package's actual checksum document;
/// the key builder binds it to the captured document again.
///
/// The admission rules for source kind, primary packages, lint capping,
/// dependency candidates and compiler outputs remain unchanged. This adapter
/// admits the fixed visible canonical layout and selects exact placement
/// identity/replay; it does not classify workspace packages as dependencies.
///
/// # Errors
/// All ordinary planning refusals and the bounded canonical-layout refusals.
pub fn plan_canonical_cargo_dependency_action(
    request: LiveRustcRequest<'_>,
    host_triple: &str,
    directory_source_checksum: Option<TypedDigest>,
) -> Result<DependencyActionPlan, LiveRefusal> {
    let plan = plan_with_directory_manifest(
        request,
        host_triple,
        directory_source_checksum,
        DependencyPlanningMode::CanonicalLocal,
    )?;
    local_metadata_layout(&plan)?;
    check_dependency_cache_read_closure(&plan.invocation)?;
    Ok(plan)
}

/// Plan an external dependency for an enforced canonical worker execution.
///
/// Unlike local capture, this admits Rust archive emission and a complete
/// generated OUT_DIR captured with its exact Cargo build-script stdout, including
/// static native libraries bundled from that retained tree. The caller
/// must retain canonical-driver ownership and use the remote key, independently
/// negotiated output mode and matching closed namespace before lookup or
/// execution. In particular, an archive may not fall through to local capture:
/// assembler reads can escape dep-info even when source bytes are immutable.
///
/// # Errors
/// Ordinary source/layout refusals and output classes other than exact metadata
/// plus dep-info or Rust archives with dep-info and optional metadata.
pub fn plan_canonical_remote_dependency_action(
    request: LiveRustcRequest<'_>,
    host_triple: &str,
    directory_source_checksum: Option<TypedDigest>,
) -> Result<DependencyActionPlan, LiveRefusal> {
    let plan = plan_with_directory_manifest(
        request,
        host_triple,
        directory_source_checksum,
        DependencyPlanningMode::CanonicalRemote,
    )?;
    canonical_layout(&plan)?;
    super::remote::remote_dependency_output_class(&plan.invocation)
        .map_err(|error| LiveRefusal::Facts(error.to_string()))?;
    Ok(plan)
}

/// Key an existing external metadata dependency in a canonical Cargo run.
///
/// The caller must hold the coordinator-created context for the running Cargo
/// command, its retained source/toolchain mappings, and its verified external
/// package membership. Canonical path spelling or a wrapper-supplied flag is
/// not that proof. This pure helper validates the bounded layout and creates a
/// distinct evidence namespace; it grants no execution or publication authority.
///
/// Facts and manifests use the actual compiler-visible canonical paths. Hidden
/// physical backings and command/snapshot identifiers never enter this key.
/// The ordinary dependency key still binds every captured package byte and
/// candidate, including negative membership. Its path policy remains preserving:
/// the producing compiler and consuming Cargo both observe the same canonical
/// paths, without claiming that those paths are opaque to application code.
///
/// # Errors
/// All ordinary dependency-key refusals, a noncanonical layout, any generated
/// input, or an output mode outside exactly metadata plus dep-info.
pub fn canonical_cargo_dependency_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    externs: &[ExternFact],
    directories: &[DependencyDirectoryFact],
    build_script_output: Option<&[u8]>,
    inputs: &ActionInputManifest,
) -> Result<LiveDependencyKey, LiveRefusal> {
    local_metadata_layout(plan)?;
    check_dependency_cache_read_closure(&plan.invocation)?;
    let mut key = canonical_dependency_key(
        plan,
        toolchain,
        externs,
        directories,
        build_script_output,
        inputs,
    )?;
    let mut isolation = CanonicalEncoder::new();
    // Retain the underlying source-policy epoch too: future dependency closure
    // corrections must invalidate canonical evidence along with ordinary keys.
    isolation
        .str(ISOLATION_PROFILE)
        .str(plan.source_kind.as_str())
        .str(key.descriptor.sandbox_semantic_policy.domain)
        .bytes(&key.descriptor.sandbox_semantic_policy.bytes);
    key.descriptor.sandbox_semantic_policy = compute(ISOLATION_DOMAIN, &isolation.finish());
    key.action_key = compute_action_key(&key.descriptor).final_key;
    key.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&key.descriptor));
    Ok(key)
}

/// Shared canonical input identity before either local metadata or remote
/// enforced-view policy is attached. This is deliberately not a public serving
/// key: its caller must select and validate the execution policy.
pub(super) fn canonical_dependency_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    externs: &[ExternFact],
    directories: &[DependencyDirectoryFact],
    build_script_output: Option<&[u8]>,
    inputs: &ActionInputManifest,
) -> Result<LiveDependencyKey, LiveRefusal> {
    canonical_layout(plan)?;
    dependency_key(
        plan,
        toolchain,
        externs,
        directories,
        build_script_output,
        inputs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_dependency::{
        canonicalize_compiler_transcript, canonicalize_placements, dep_info_closure_violation,
        live_dependency_key, plan_dependency_action, render_compiler_transcript, render_placements,
    };
    use crate::output_declarations::OutputClass;
    use rabs_protocol::descriptor::ActionClass;
    use rabs_protocol::input_evidence::{
        INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;

    const HOST: &str = "x86_64-unknown-linux-gnu";
    const PACKAGE: &str = "/__rabs/cargo-home/registry/src/index-example/fixture-1.0.0";
    const OUT: &str = "/__rabs/out/cargo/debug/deps";

    fn digest(bytes: &[u8]) -> TypedDigest {
        compute("rabs.test.canonical-cargo-input.v1", bytes)
    }

    fn plan(package: &str, checksum: Option<TypedDigest>) -> DependencyActionPlan {
        let argv = [
            COMPILER.to_owned(),
            "--crate-name=fixture".into(),
            "--edition=2021".into(),
            "--crate-type=lib".into(),
            "--emit=metadata,dep-info".into(),
            "--error-format=json".into(),
            "--out-dir".into(),
            OUT.into(),
            "-L".into(),
            format!("dependency={OUT}"),
            "--cap-lints=allow".into(),
            format!("{package}/src/lib.rs"),
        ];
        let env = [
            ("CARGO_HOME".into(), CARGO_HOME.into()),
            ("HOME".into(), HOME.into()),
            ("CARGO_MANIFEST_DIR".into(), package.into()),
            ("CARGO_PKG_NAME".into(), "fixture".into()),
            ("CARGO_INCREMENTAL".into(), "0".into()),
            ("CARGO_MAKEFLAGS".into(), "-j --jobserver-fds=3,4".into()),
        ];
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: package,
            env: &env,
        };
        assert!(plan_dependency_action(request, HOST).is_err());
        plan_canonical_cargo_dependency_action(request, HOST, checksum).unwrap()
    }

    fn toolchain() -> ToolchainFacts {
        ToolchainFacts {
            compiler_binary_digest: digest(b"compiler"),
            verbose_version: format!("rustc test\nhost: {HOST}\nLLVM version: 22.1.0\n"),
            sysroot_root_digest: digest(b"sysroot"),
            runtime_libraries: vec![digest(b"compiler runtime")],
        }
    }

    fn inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let source = plan
            .invocation
            .source
            .as_ref()
            .and_then(|source| match source {
                crate::invocation::SourceInput::Path(path) => {
                    path.strip_prefix(&format!("{}/", plan.source_root))
                }
                crate::invocation::SourceInput::Stdin(_) => None,
            })
            .unwrap();
        let mut files = vec![
            ("Cargo.toml", digest(b"package manifest")),
            (source, digest(b"pub const VALUE: u32 = 7;")),
        ];
        if let Some(witness) = &plan.directory_source_manifest {
            files.push((".cargo-checksum.json", witness.clone()));
        }
        ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: files
                .into_iter()
                .map(|(path, object)| PositiveInput {
                    virtual_path: RawBytes::new(plan.input_virtual_path(path).into_bytes()),
                    object: ObjectId(object),
                    file_type: InputFileType::Regular,
                    executable: false,
                    symlink_resolution: Vec::new(),
                })
                .collect(),
            ..ActionInputManifest::default()
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

    fn key(plan: &DependencyActionPlan) -> Result<LiveDependencyKey, LiveRefusal> {
        canonical_cargo_dependency_key(
            plan,
            &toolchain(),
            &[],
            &directories(plan),
            None,
            &inputs(plan),
        )
    }

    #[test]
    fn canonical_planning_preserves_existing_external_source_classes() {
        for (package, checksum, kind) in [
            (PACKAGE, None, DependencySourceKind::RegistryPackage),
            (
                "/__rabs/cargo-home/git/checkouts/fixture-cafe1234/0123456789ab/crates/member",
                None,
                DependencySourceKind::GitCheckout,
            ),
            (
                "/__rabs/workspace/vendor/fixture-1.0.0",
                Some(digest(b"checksum document")),
                DependencySourceKind::DirectoryPackage,
            ),
        ] {
            let plan = plan(package, checksum);
            assert_eq!(plan.source_kind, kind);
            let key = key(&plan).unwrap();
            assert_eq!(
                key.descriptor.action_class,
                ActionClass::RustcDependencyCompile
            );
            assert_eq!(
                key.descriptor.sandbox_semantic_policy.domain,
                ISOLATION_DOMAIN
            );
        }
    }

    #[test]
    fn canonical_evidence_cannot_alias_an_ordinary_edge_execution() {
        let plan = plan(PACKAGE, None);
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
        let ordinary = dependency_key(
            &plan,
            &toolchain(),
            &[],
            &directories(&plan),
            None,
            &inputs(&plan),
        )
        .unwrap();
        let canonical = key(&plan).unwrap();
        assert_ne!(canonical.action_key, ordinary.action_key);
        assert_ne!(canonical.descriptor_digest, ordinary.descriptor_digest);
        assert_ne!(
            canonical.descriptor.sandbox_semantic_policy,
            ordinary.descriptor.sandbox_semantic_policy
        );
        assert_eq!(
            canonical.descriptor.build_path_semantic_policy,
            ordinary.descriptor.build_path_semantic_policy
        );
        assert_eq!(
            canonical.action_key,
            compute_action_key(&canonical.descriptor).final_key
        );
        assert_eq!(
            canonical.descriptor_digest,
            descriptor_digest(&descriptor_canonical_bytes(&canonical.descriptor))
        );
        let mut expected = ordinary.descriptor;
        expected.sandbox_semantic_policy = canonical.descriptor.sandbox_semantic_policy.clone();
        assert_eq!(canonical.descriptor, expected);
    }

    #[test]
    fn canonical_keys_preserve_semantic_values_and_ignore_only_existing_controls() {
        let plan = plan(PACKAGE, None);
        let original = key(&plan).unwrap();
        let mut other_jobserver = plan.clone();
        other_jobserver
            .execution_env
            .iter_mut()
            .find(|(name, _)| name == "CARGO_MAKEFLAGS")
            .unwrap()
            .1 = "-j --jobserver-fds=17,18".into();
        assert_eq!(key(&other_jobserver).unwrap(), original);

        let mut changed_env = plan.clone();
        changed_env
            .execution_env
            .push(("FIXTURE_VALUE".into(), "changed".into()));
        changed_env
            .keyed_env
            .push(("FIXTURE_VALUE".into(), "changed".into()));
        assert_ne!(key(&changed_env).unwrap().action_key, original.action_key);

        let mut changed_source = inputs(&plan);
        changed_source.inputs[1].object = ObjectId(digest(b"pub const VALUE: u32 = 8;"));
        let changed = canonical_cargo_dependency_key(
            &plan,
            &toolchain(),
            &[],
            &directories(&plan),
            None,
            &changed_source,
        )
        .unwrap();
        assert_ne!(changed.action_key, original.action_key);
    }

    #[test]
    fn physical_paths_primary_packages_codegen_and_generated_inputs_stay_out() {
        let original = plan(PACKAGE, None);
        for change in 0..11 {
            let mut plan = original.clone();
            match change {
                0 => plan.compiler = "/tmp/toolchain/bin/rustc".into(),
                1 => plan.cwd = "/tmp/workspace/vendor/fixture-1.0.0".into(),
                2 => plan.out_dir = "/tmp/private-target/deps".into(),
                3 => plan.dependency_dirs[0] = "/__rabs/out/cargo-elsewhere/deps".into(),
                4 => {
                    plan.execution_env
                        .push(("CARGO_PRIMARY_PACKAGE".into(), "1".into()));
                }
                5 => plan.invocation.cap_lints = None,
                6 => plan.invocation.emit.push("link".into()),
                7 => plan.generated_root = Some("/__rabs/out/cargo/build/generated/out".into()),
                8 => {
                    plan.execution_env
                        .iter_mut()
                        .find(|(name, _)| name == "CARGO_HOME")
                        .unwrap()
                        .1 = "/tmp/private-cargo-home".into();
                }
                9 => plan.canonical_cargo = false,
                10 => {
                    plan.out_dir = "/__rabs/out/cargo/../elsewhere/deps".into();
                    plan.invocation.out_dir = Some(plan.out_dir.clone());
                }
                _ => unreachable!(),
            }
            assert!(key(&plan).is_err(), "mutation {change} acquired authority");
        }
        assert!(
            canonical_cargo_dependency_key(
                &original,
                &toolchain(),
                &[],
                &directories(&original),
                Some(b"cargo:rustc-cfg=generated\n"),
                &inputs(&original),
            )
            .is_err()
        );
    }

    #[test]
    fn dynamic_candidates_and_incomplete_inventories_still_refuse() {
        let plan = plan(PACKAGE, None);
        let mut observed = directories(&plan);
        observed[0].artifacts.push(ExternFact {
            path: format!("{OUT}/libderive.so"),
            content_digest: digest(b"proc-macro binary"),
        });
        assert!(
            canonical_cargo_dependency_key(
                &plan,
                &toolchain(),
                &[],
                &observed,
                None,
                &inputs(&plan),
            )
            .is_err()
        );
        assert!(
            canonical_cargo_dependency_key(&plan, &toolchain(), &[], &[], None, &inputs(&plan),)
                .is_err()
        );
    }

    #[test]
    fn canonical_target_and_dependency_placements_remain_semantic() {
        let plan = plan(PACKAGE, None);
        assert!(plan.placement_mappings().is_empty());
        let original = key(&plan).unwrap();
        let mut moved = plan.clone();
        let other = "/__rabs/out/cargo/custom/deps";
        moved.out_dir = other.into();
        moved.invocation.out_dir = Some(other.into());
        moved.invocation.lib_search = vec![format!("dependency={other}")];
        moved.dependency_dirs = vec![other.into()];
        assert_ne!(key(&moved).unwrap().action_key, original.action_key);

        // A different dependency search directory is observable even when its
        // complete candidate inventory happens to be empty in both executions.
        moved.out_dir.clone_from(&plan.out_dir);
        moved
            .invocation
            .out_dir
            .clone_from(&plan.invocation.out_dir);
        assert_ne!(key(&moved).unwrap().action_key, original.action_key);
    }

    #[test]
    fn canonical_transcripts_preserve_actual_paths_and_source_authored_literals() {
        let plan = plan(PACKAGE, None);
        let diagnostic = format!(
            " {{ \"$message_type\" : \"diagnostic\", \"message\" : \"literal /__rabs/out and {OUT}\", \"spans\" : [{{\"file_name\":\"{PACKAGE}/src/lib.rs\"}}] }}\r\n"
        );
        let escaped = b"{\"message\":\"literal \\u002f__rabs\\u002fout\\u002fcargo\"}\n";
        for output in &plan.outputs.declarations {
            let emit = match output.class {
                OutputClass::ProvisionalMetadata => "metadata",
                OutputClass::DepInfo => "dep-info",
                _ => panic!("unexpected metadata-only output"),
            };
            let artifact = format!(
                "  {{ \"emit\" : \"{emit}\", \"artifact\" : \"{OUT}/{}\", \"$message_type\" : \"artifact\" }}\r\n",
                output.virtual_path
            );
            let raw = [diagnostic.as_bytes(), escaped, artifact.as_bytes()].concat();
            let canonical = canonicalize_compiler_transcript(&raw, &plan).unwrap();
            assert_eq!(canonical, raw);
            assert_eq!(render_compiler_transcript(&canonical, &plan), raw);
        }
    }

    #[test]
    fn canonical_transcript_identity_still_checks_declared_artifact_events() {
        let plan = plan(PACKAGE, None);
        let output = plan
            .outputs
            .declarations
            .iter()
            .find(|output| output.class == OutputClass::ProvisionalMetadata)
            .unwrap();
        let path = format!("{OUT}/{}", output.virtual_path);
        for raw in [
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"/__rabs/out/{}\",\"emit\":\"metadata\"}}\n",
                output.virtual_path
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{OUT}/undeclared.rmeta\",\"emit\":\"metadata\"}}\n"
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{path}\",\"emit\":\"link\"}}\n"
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{path}\",\"emit\":\"metadata\",\"extra\":\"field\"}}\n"
            ),
            format!(
                r#"{{"\u0024message_type":"ar\u0074ifact","artifact":"{}","emit":"metadata"}}"#,
                path.replace('/', r"\u002f")
            ),
            r#"{"message":"invalid \q escape"}"#.into(),
        ] {
            assert!(
                canonicalize_compiler_transcript(raw.as_bytes(), &plan).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn canonical_dep_info_retains_exact_paths_after_closure_validation() {
        let plan = plan(PACKAGE, None);
        let raw = format!(
            "{OUT}/fixture.d: {PACKAGE}/src/lib.rs\n\n\
             {OUT}/libfixture.rmeta: {PACKAGE}/src/lib.rs\n\n\
             {PACKAGE}/src/lib.rs:\n"
        );
        let source = plan.input_virtual_path("src/lib.rs");
        let captured = |path: &str| path == source;
        assert_eq!(
            dep_info_closure_violation(&plan, raw.as_bytes(), captured),
            None
        );
        let canonical = canonicalize_placements(raw.as_bytes(), &plan).unwrap();
        assert_eq!(canonical, raw.as_bytes());
        assert_eq!(render_placements(&canonical, &plan), raw.as_bytes());

        for invalid in [
            format!("/__rabs/out/libfixture.rmeta: {PACKAGE}/src/lib.rs\n"),
            format!("{OUT}/fixture.d: {PACKAGE}/src/unkeyed.rs\n"),
            format!("{OUT}/fixture.d: /tmp/private-capture/src/lib.rs\n"),
        ] {
            assert!(
                dep_info_closure_violation(&plan, invalid.as_bytes(), captured).is_some(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn canonical_environment_reads_bind_exact_values_and_still_refuse_controls() {
        let mut plan = plan(PACKAGE, None);
        let value = format!("{OUT}:/__rabs/toolchain/lib");
        plan.execution_env
            .push(("LD_LIBRARY_PATH".into(), value.clone()));
        plan.keyed_env
            .push(("LD_LIBRARY_PATH".into(), value.clone()));
        let original = key(&plan).unwrap();
        let raw =
            format!("{OUT}/fixture.d: {PACKAGE}/src/lib.rs\n# env-dep:LD_LIBRARY_PATH={value}\n");
        let source = plan.input_virtual_path("src/lib.rs");
        let captured = |path: &str| path == source;
        assert_eq!(
            dep_info_closure_violation(&plan, raw.as_bytes(), captured),
            None
        );
        for name in ["CARGO_MAKEFLAGS", "RABS_SOCKET"] {
            let unkeyed = format!("{raw}# env-dep:{name}\n");
            assert!(
                dep_info_closure_violation(&plan, unkeyed.as_bytes(), captured).is_some(),
                "tracked read of {name} must still refuse"
            );
        }
        for env in [&mut plan.execution_env, &mut plan.keyed_env] {
            env.iter_mut()
                .find(|(name, _)| name == "LD_LIBRARY_PATH")
                .unwrap()
                .1 = "/__rabs/out/cargo/custom/deps:/__rabs/toolchain/lib".into();
        }
        assert_ne!(key(&plan).unwrap().action_key, original.action_key);
    }
}
