//! Reject requests that cannot enter the live lane before warming any facts.
//!
//! Cargo's version/target probes, primary packages and unsupported compiler
//! invocations must not wait for a cold sysroot hash. This is rejection-only:
//! `None` is NOT admission, an action key, or permission to skip rustc. The
//! normal planner still checks the observed host, source class, output model
//! and every input guard. In particular, do not fabricate a host triple here
//! or classify a directory source without its captured checksum witness.

use rabs_key::invocation::{NormalizedRustcInvocation, SourceInput, parse};
use rabs_key::live_dependency::remote::{
    canonical_generated_native_roots, remote_dependency_output_class,
    validate_generated_native_inputs_with_roots,
};
use rabs_key::live_dependency::{
    LiveRefusal, LiveRustcRequest, check_dependency_cache_read_closure,
};
use rabs_key::output_derivation::{
    check_dependency_output_options, check_workspace_output_options,
};

#[path = "sysroot_preflight.rs"]
mod sysroot_preflight;

/// A host-independent subset of the live dependency planner's refusals.
/// Keep this deliberately small; differential tests below require supported
/// requests to continue to the full planner, not become false cache misses.
pub(super) fn rejection(request: LiveRustcRequest<'_>) -> Option<LiveRefusal> {
    rejection_for(request, PreflightMode::LocalDependency)
}

/// A configured remote worker can enforce the archive read-closure profile.
/// This only avoids a premature local-only refusal: the complete remote key,
/// retained validation owner and worker context must still agree before lookup,
/// dispatch, publication or installation. An unavailable remote lane never
/// turns this preliminary check into local codegen cache authority.
pub(super) fn remote_rejection(request: LiveRustcRequest<'_>) -> Option<LiveRefusal> {
    rejection_for(request, PreflightMode::RemoteDependency)
}

/// Only the retained canonical Cargo unit capability can select this preflight.
/// Primary-package environment, original lint settings and workspace cwd remain
/// compiler inputs; the later pure planner and unit matcher grant execution.
pub(super) fn workspace_rejection(request: LiveRustcRequest<'_>) -> Option<LiveRefusal> {
    rejection_for(request, PreflightMode::WorkspaceExecutionOnly)
}

/// Only a retained canonical Cargo operation may prepare generated static
/// native inputs. Canonical-looking wrapper paths do not select this entry point;
/// the driver owns the complete generated-tree capture and worker-only policy.
pub(super) fn canonical_remote_rejection(request: LiveRustcRequest<'_>) -> Option<LiveRefusal> {
    rejection_for(request, PreflightMode::CanonicalRemoteDependency)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreflightMode {
    LocalDependency,
    RemoteDependency,
    CanonicalRemoteDependency,
    WorkspaceExecutionOnly,
}

fn rejection_for(request: LiveRustcRequest<'_>, mode: PreflightMode) -> Option<LiveRefusal> {
    let remote = mode != PreflightMode::LocalDependency;
    let workspace = mode == PreflightMode::WorkspaceExecutionOnly;
    let mut names: Vec<&str> = request.env.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
        return Some(LiveRefusal::DuplicateEnv(pair[0].to_owned()));
    }
    for name in [
        "CARGO_PRIMARY_PACKAGE",
        "LD_PRELOAD",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
    ] {
        if names.contains(&name) && !(workspace && name == "CARGO_PRIMARY_PACKAGE") {
            return Some(LiveRefusal::RefusedEnv(name.to_owned()));
        }
    }
    let env_value = |name: &str| {
        request
            .env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    for name in ["CARGO_MANIFEST_DIR", "CARGO_PKG_NAME"] {
        if env_value(name).is_none() {
            return Some(LiveRefusal::MissingEnv(name));
        }
    }
    if env_value("CARGO_HOME").is_none() && env_value("HOME").is_none() {
        return Some(LiveRefusal::MissingEnv("HOME"));
    }
    if !workspace && env_value("CARGO_MANIFEST_DIR") != Some(request.cwd) {
        return Some(LiveRefusal::WorkingDirectory(request.cwd.to_owned()));
    }
    let invocation = match parse(request.argv, None) {
        Ok(invocation) => invocation,
        Err(error) => return Some(LiveRefusal::Unparseable(format!("{error:?}"))),
    };
    if !workspace && invocation.cap_lints.as_deref() != Some("allow") {
        return Some(LiveRefusal::NotDependencyCompile(
            "Cargo caps lints for external dependencies; this invocation does not",
        ));
    }
    // Cargo also caps dependency build-script binaries and proc-macro
    // producers. They are prerequisites of otherwise cacheable work, but
    // this lane cannot serve their output classes. Do not make them wait
    // behind a cold sysroot merely to discover that after hashing it.
    // Workspace metadata checks also include selected binaries and test
    // harnesses. Their separate option adapter below validates this bounded
    // shape without granting final-link or dependency-cache authority.
    if !workspace
        && (invocation.crate_types.is_empty()
            || invocation
                .crate_types
                .iter()
                .any(|kind| !matches!(kind.as_str(), "lib" | "rlib")))
    {
        return Some(LiveRefusal::NotDependencyCompile(
            "dependency outputs require --crate-type lib or rlib",
        ));
    }
    let compiler = invocation.compiler_argv0.rsplit(['/', '\\']).next();
    if !matches!(compiler, Some("rustc" | "rustc.exe"))
        || !invocation.wrapper_chain.is_empty()
        || !invocation.stripped_wrapper_flags.is_empty()
    {
        return Some(LiveRefusal::NotDependencyCompile(
            "dependency outputs require an unwrapped rustc invocation",
        ));
    }
    if !matches!(&invocation.source, Some(SourceInput::Path(path)) if !path.starts_with('@')) {
        return Some(LiveRefusal::NotDependencyCompile(
            "dependency outputs require an explicit source file",
        ));
    }
    if invocation.out_dir.as_deref().is_none_or(str::is_empty) {
        return Some(LiveRefusal::NotDependencyCompile(
            "dependency outputs require --out-dir",
        ));
    }
    // The live capture path needs rustc's file/environment read report before
    // it can publish a result. Missing --emit defaults to link, not dep-info.
    // Do not warm facts for a compile that can never provide that evidence.
    // Exact destination/option validation still belongs to the output adapter.
    if !invocation.emit.iter().any(|kind| kind == "dep-info") {
        return Some(LiveRefusal::NotDependencyCompile(
            "live dependency serving requires dep-info read evidence",
        ));
    }
    // A .d file does not report assembler reads such as global_asm! .incbin.
    // Only an explicitly configured remote execution path may proceed toward
    // its separately enforced archive profile; the unsandboxed local lane
    // still refuses all codegen before warming facts or consulting a cache.
    if !(remote && remote_dependency_output_class(&invocation).is_ok())
        && let Err(refusal) = check_dependency_cache_read_closure(&invocation)
    {
        return Some(refusal);
    }
    if !invocation
        .passthrough
        .iter()
        .any(|arg| arg == "--error-format=json")
    {
        return Some(LiveRefusal::DiagnosticFormat);
    }
    if invocation
        .codegen
        .iter()
        .any(|(name, value)| name == "target-cpu" && value.as_deref() == Some("native"))
    {
        return Some(LiveRefusal::NativeCpu);
    }
    dependency_inputs_rejection(
        &invocation,
        env_value("OUT_DIR"),
        matches!(
            mode,
            PreflightMode::CanonicalRemoteDependency | PreflightMode::WorkspaceExecutionOnly
        ),
    )
    .or_else(|| sysroot_preflight::rejection(&invocation))
    // Use the SAME option model as final derivation, not a second flag
    // list or a fabricated host triple. Supported threaded compiles keep
    // going; incremental/save-temps/unknown modes never start cold hashing.
    .or_else(|| {
        let options = if workspace {
            check_workspace_output_options(&invocation)
        } else {
            check_dependency_output_options(&invocation)
        };
        options
            .err()
            .map(|error| LiveRefusal::Outputs(error.to_string()))
    })
}

fn dependency_inputs_rejection(
    invocation: &NormalizedRustcInvocation,
    generated_root: Option<&str>,
    canonical_archive_execution: bool,
) -> Option<LiveRefusal> {
    let native_roots = if canonical_archive_execution {
        match canonical_generated_native_roots(invocation, generated_root) {
            Ok(roots) => roots,
            Err(refusal) => return Some(refusal),
        }
    } else {
        Vec::new()
    };
    if let Err(refusal) = validate_generated_native_inputs_with_roots(
        invocation,
        generated_root,
        &native_roots,
        canonical_archive_execution,
    ) {
        return Some(refusal);
    }
    // A proc-macro PRODUCER is rejected above, but the ordinary lib/rlib
    // that CONSUMES it cannot enter this class either.
    // Unbound native search paths also refuse above, including those without
    // -l. Only canonical worker executions may continue with native searches
    // inside complete generated trees whose completed Cargo records and bytes
    // must still be captured by the coordinator. These checks need neither
    // a host probe, source capture, nor dependency enumeration
    // to establish this refusal. Let Cargo make progress immediately rather
    // than spend the wrapper's cold-readiness budget on an impossible hit.
    for (_, path) in &invocation.externs {
        let Some(path) = path else {
            // A bare --extern can name a toolchain crate. Only the full
            // planner and the observed sysroot can bind that dependency.
            continue;
        };
        if path.ends_with(".so") || path.ends_with(".dylib") {
            return Some(LiveRefusal::ProcMacroDependency(path.clone()));
        }
        if !path.ends_with(".rmeta") && !path.ends_with(".rlib") {
            return Some(LiveRefusal::Extern(path.clone()));
        }
    }
    // Admissible-looking inputs still need the full planner's path topology,
    // output-alias, target, and complete byte-closure checks. In particular,
    // unrelated .so files merely sharing a dependency directory are NOT
    // consumed externs and must not be rejected by this syntactic preflight.
    None
}

#[cfg(test)]
#[path = "dependency_preflight_tests.rs"]
mod dependency_preflight_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_key::live_dependency::plan_dependency_action;

    const HOST: &str = "x86_64-unknown-linux-gnu";
    const PACKAGE: &str = "/cargo/registry/src/index/leaf-1.0.0";

    fn fixture(package: &str) -> (Vec<String>, Vec<(String, String)>) {
        let mut argv: Vec<String> = [
            "/toolchain/bin/rustc",
            "--crate-name=leaf",
            "--crate-type=lib",
            "--emit=metadata,dep-info",
            "--out-dir",
            "/target/deps",
            "--cap-lints=allow",
            "--error-format=json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        argv.push(format!("{package}/lib.rs"));
        let env = vec![
            ("CARGO_HOME".into(), "/cargo".into()),
            ("CARGO_MANIFEST_DIR".into(), package.into()),
            ("CARGO_PKG_NAME".into(), "leaf".into()),
        ];
        (argv, env)
    }

    #[test]
    fn registry_git_and_generated_input_requests_still_need_the_full_planner() {
        for package in [PACKAGE, "/cargo/git/checkouts/leaf-123/abcdef123/member"] {
            for split_cap_lints in [false, true] {
                let (mut argv, mut env) = fixture(package);
                if split_cap_lints {
                    let at = argv
                        .iter()
                        .position(|arg| arg == "--cap-lints=allow")
                        .unwrap();
                    argv[at] = "--cap-lints".into();
                    argv.insert(at + 1, "allow".into());
                }
                env.push(("OUT_DIR".into(), "/target/build/leaf/out".into()));
                let request = LiveRustcRequest {
                    argv: &argv,
                    cwd: package,
                    env: &env,
                };
                assert_eq!(rejection(request), None);
                assert!(plan_dependency_action(request, HOST).is_ok());
            }
        }
    }

    #[test]
    fn workspace_preflight_preserves_primary_lints_and_workspace_cwd_without_relaxing_dependency_admission()
     {
        let (mut argv, mut env) = fixture("/__rabs/workspace/member");
        argv.retain(|arg| arg != "--cap-lints=allow");
        env.push(("CARGO_PRIMARY_PACKAGE".into(), "1".into()));
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: "/__rabs/workspace",
            env: &env,
        };
        assert!(rejection(request).is_some());
        assert!(remote_rejection(request).is_some());
        assert_eq!(workspace_rejection(request), None);
        let mut generated = env.clone();
        generated.push((
            "OUT_DIR".into(),
            "/__rabs/out/cargo/debug/build/member-hash/out".into(),
        ));
        for extra in [
            vec!["-Lnative=/__rabs/out/cargo/debug/build/member-hash/out"],
            vec![
                "-Lnative=/__rabs/out/cargo/debug/build/member-hash/out",
                "-lstatic=answer",
            ],
        ] {
            let mut native = argv.clone();
            native.retain(|arg| arg != "--emit=metadata,dep-info");
            native.push("--emit=dep-info,metadata,link".into());
            native.extend(extra.iter().map(|arg| (*arg).to_owned()));
            let candidate = LiveRustcRequest {
                argv: &native,
                cwd: "/__rabs/workspace",
                env: &generated,
            };
            assert_eq!(workspace_rejection(candidate), None);
            assert!(rejection(candidate).is_some());
            assert!(remote_rejection(candidate).is_some());
        }
        env.push(("LD_PRELOAD".into(), "/unretained.so".into()));
        assert!(
            workspace_rejection(LiveRustcRequest {
                argv: &argv,
                cwd: "/__rabs/workspace",
                env: &env,
            })
            .is_some()
        );
    }

    #[test]
    fn workspace_metadata_bins_and_harnesses_do_not_borrow_dependency_or_link_authority() {
        use rabs_key::live_dependency::plan_canonical_workspace_execution;

        for (crate_type, harness, test_cfg) in [
            (Some("bin"), false, false),
            (Some("bin"), true, false),
            (Some("lib"), true, false),
            (None, true, false),
            (None, false, true),
        ] {
            let mut argv = vec![
                "/__rabs/toolchain/bin/rustc".into(),
                "--crate-name=app".into(),
                "--emit=dep-info,metadata".into(),
                "--out-dir=/__rabs/out/cargo/debug/deps".into(),
                "--error-format=json".into(),
                "member/src/main.rs".into(),
            ];
            if let Some(kind) = crate_type {
                argv.push(format!("--crate-type={kind}"));
            }
            if harness {
                argv.push("--test".into());
            }
            if test_cfg {
                argv.extend(["--cfg".into(), "test".into()]);
            }
            let env = vec![
                ("HOME".into(), "/__rabs/home".into()),
                ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
                (
                    "CARGO_MANIFEST_DIR".into(),
                    "/__rabs/workspace/member".into(),
                ),
                ("CARGO_PKG_NAME".into(), "app".into()),
                ("CARGO_PRIMARY_PACKAGE".into(), "1".into()),
            ];
            let candidate = LiveRustcRequest {
                argv: &argv,
                cwd: "/__rabs/workspace",
                env: &env,
            };
            assert_eq!(workspace_rejection(candidate), None);
            assert!(plan_canonical_workspace_execution(candidate, HOST).is_ok());
            assert!(rejection(candidate).is_some());
            assert!(remote_rejection(candidate).is_some());
            assert!(canonical_remote_rejection(candidate).is_some());

            argv[2] = "--emit=dep-info,metadata,link".into();
            let linking = LiveRustcRequest {
                argv: &argv,
                cwd: "/__rabs/workspace",
                env: &env,
            };
            assert!(workspace_rejection(linking).is_some());
            assert!(plan_canonical_workspace_execution(linking, HOST).is_err());
        }
    }

    #[test]
    fn directory_source_is_not_rejected_without_observing_its_witness() {
        let (argv, env) = fixture("/workspace/vendor/leaf");
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: "/workspace/vendor/leaf",
            env: &env,
        };
        assert_eq!(rejection(request), None);
        // Ordinary planning cannot bless this path. The daemon must still
        // obtain the directory-source witness and use its dedicated planner.
        assert!(plan_dependency_action(request, HOST).is_err());
    }

    #[test]
    fn only_the_explicit_remote_preflight_can_consider_pure_rust_archives() {
        for package in [
            PACKAGE,
            "/cargo/git/checkouts/leaf-123/abcdef123/member",
            "/workspace/vendor/leaf",
        ] {
            for emit in ["dep-info,link", "dep-info,metadata,link"] {
                let (mut argv, env) = fixture(package);
                *argv
                    .iter_mut()
                    .find(|arg| arg.starts_with("--emit="))
                    .unwrap() = format!("--emit={emit}");
                let request = LiveRustcRequest {
                    argv: &argv,
                    cwd: package,
                    env: &env,
                };
                assert_eq!(rejection(request), Some(LiveRefusal::UnclosedCodegenInputs));
                assert_eq!(remote_rejection(request), None);
            }
        }
    }

    #[test]
    fn remote_archive_preflight_still_rejects_native_proc_macro_and_unmodeled_inputs() {
        for extra in [
            vec!["--crate-type=proc-macro"],
            vec!["--crate-type=cdylib"],
            vec!["-l", "ssl"],
            vec!["-L", "native=/usr/lib"],
            vec!["--extern", "derive=/target/deps/libderive.so"],
            vec!["-C", "target-cpu=native"],
            vec!["-C", "incremental=/target/incremental"],
        ] {
            let (mut argv, env) = fixture(PACKAGE);
            *argv
                .iter_mut()
                .find(|arg| arg.starts_with("--emit="))
                .unwrap() = "--emit=dep-info,metadata,link".into();
            argv.extend(extra.iter().map(|value| (*value).to_owned()));
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            assert!(remote_rejection(request).is_some(), "{extra:?}");
        }
        for emit in [
            "dep-info,obj",
            "dep-info,asm",
            "dep-info,llvm-ir",
            "dep-info,llvm-bc",
            "link",
        ] {
            let (mut argv, env) = fixture(PACKAGE);
            *argv
                .iter_mut()
                .find(|arg| arg.starts_with("--emit="))
                .unwrap() = format!("--emit={emit}");
            assert!(
                remote_rejection(LiveRustcRequest {
                    argv: &argv,
                    cwd: PACKAGE,
                    env: &env
                })
                .is_some(),
                "{emit}"
            );
        }
    }

    #[test]
    fn early_environment_refusals_agree_with_the_full_planner() {
        for name in [
            "CARGO_PRIMARY_PACKAGE",
            "LD_PRELOAD",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
        ] {
            let (argv, mut env) = fixture(PACKAGE);
            // Presence matters, even with an empty value.
            env.push((name.into(), String::new()));
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            assert_eq!(
                rejection(request),
                plan_dependency_action(request, HOST).err()
            );
            assert!(matches!(
                rejection(request),
                Some(LiveRefusal::RefusedEnv(_))
            ));
        }
        for missing in ["CARGO_MANIFEST_DIR", "CARGO_PKG_NAME", "CARGO_HOME"] {
            let (argv, mut env) = fixture(PACKAGE);
            env.retain(|(name, _)| name != missing);
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            assert_eq!(
                rejection(request),
                plan_dependency_action(request, HOST).err()
            );
            assert!(matches!(
                rejection(request),
                Some(LiveRefusal::MissingEnv(_))
            ));
        }
        let (argv, mut env) = fixture(PACKAGE);
        env.push(env[0].clone());
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: PACKAGE,
            env: &env,
        };
        assert_eq!(
            rejection(request),
            plan_dependency_action(request, HOST).err()
        );
        assert!(matches!(
            rejection(request),
            Some(LiveRefusal::DuplicateEnv(_))
        ));
    }

    #[test]
    fn uncapped_non_json_native_cpu_and_native_link_requests_never_need_hashing() {
        for (remove, add) in [
            ("--cap-lints=allow", "--cap-lints=warn"),
            ("--error-format=json", "--error-format=human"),
            ("", "-Ctarget-cpu=native"),
            ("", "-lz"),
        ] {
            let (mut argv, env) = fixture(PACKAGE);
            argv.retain(|arg| arg != remove);
            argv.push(add.into());
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            assert!(rejection(request).is_some());
            // Output policy can reject an invocation before the full planner
            // reaches this subset. The required invariant is rejection, not
            // precedence between independent refusal reasons.
            assert!(plan_dependency_action(request, HOST).is_err());
        }
    }

    #[test]
    fn compiler_probes_are_rejected_without_any_toolchain_identity() {
        for args in [vec!["/rustc", "-vV"], vec!["/rustc", "--print", "cfg"]] {
            let argv = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: "/workspace",
                env: &[],
            };
            assert_eq!(
                rejection(request),
                Some(LiveRefusal::MissingEnv("CARGO_MANIFEST_DIR"))
            );
        }
    }

    #[test]
    fn missing_read_evidence_is_rejected_by_preflight_and_the_full_planner() {
        for extra in [
            vec![],
            vec!["--emit=link"],
            vec!["--emit", "metadata"],
            vec!["--emit=metadata,link"],
            vec!["--emit=metadata", "-Cmetadata=dep-info"],
            vec!["--emit=metadata,dep-info=/tmp/elsewhere.d"],
        ] {
            let (mut argv, env) = fixture(PACKAGE);
            argv.retain(|arg| arg != "--emit=metadata,dep-info");
            argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            assert!(matches!(
                rejection(request),
                Some(LiveRefusal::NotDependencyCompile(
                    "live dependency serving requires dep-info read evidence"
                ))
            ));
            for host in [
                HOST,
                "x86_64-unknown-linux-musl",
                "aarch64-unknown-linux-gnu",
                "aarch64-unknown-linux-musl",
            ] {
                assert!(
                    plan_dependency_action(request, host).is_err(),
                    "{extra:?} on {host}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_edge_never_warms_or_serves_without_read_evidence() {
        use super::super::{Decided, LiveEdge, decide};
        use crate::coord::live::CoordLive;
        use crate::coord::live_dependency::LiveDependencyLane;
        use serde_json::json;
        use std::sync::Arc;

        let temporary = crate::test_util::private_tempdir();
        let cas = Arc::new(
            crate::janitor::store::mount_and_reconcile(&temporary.path().join("cas")).unwrap(),
        );
        let coord = Arc::new(CoordLive::with_cas(cas));
        coord
            .acquire_boot_authority("read-evidence-preflight")
            .unwrap();
        coord.mark_up();
        let live = LiveEdge::new(LiveDependencyLane::new(coord));
        for may_wait in [false, true] {
            for extra in [vec![], vec!["--emit=link"], vec!["--emit", "metadata,link"]] {
                let (mut argv, mut env) = fixture(PACKAGE);
                argv.retain(|arg| arg != "--emit=metadata,dep-info");
                argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
                // Read-veto projections must not gain an exception: even an
                // OUT_DIR consumer with otherwise ordinary Cargo args refuses.
                env.push(("OUT_DIR".into(), "/target/build/leaf/out".into()));
                let request = json!({
                    "kind": "rustc-request", "argv": argv, "cwd": PACKAGE,
                    "env": env, "wait_for_inflight": may_wait,
                });
                let Decided::Shadow(observed) = decide(&live, &request) else {
                    panic!("missing read evidence must bypass before native facts or cache lookup");
                };
                assert_eq!(
                    observed.argv, argv,
                    "fallback must preserve the exact emit request"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn codegen_with_dep_info_bypasses_before_warming_or_persisted_lookup() {
        use super::super::{Decided, LiveEdge, decide};
        use crate::coord::live::CoordLive;
        use crate::coord::live_dependency::LiveDependencyLane;
        use serde_json::json;
        use std::sync::Arc;

        let temporary = crate::test_util::private_tempdir();
        let cas = Arc::new(
            crate::janitor::store::mount_and_reconcile(&temporary.path().join("cas")).unwrap(),
        );
        let coord = Arc::new(CoordLive::with_cas(cas));
        coord
            .acquire_boot_authority("codegen-read-closure")
            .unwrap();
        coord.mark_up();
        let live = LiveEdge::new(LiveDependencyLane::new(coord));
        for package in [
            PACKAGE,
            "/cargo/git/checkouts/leaf-123/abcdef123/member",
            "/workspace/vendor/leaf",
        ] {
            for emit in [
                "dep-info,metadata,link",
                "dep-info,link",
                "dep-info,obj",
                "dep-info,asm",
                "dep-info,llvm-ir",
                "dep-info,llvm-bc",
            ] {
                let (mut argv, mut env) = fixture(package);
                *argv
                    .iter_mut()
                    .find(|argument| argument.starts_with("--emit="))
                    .unwrap() = format!("--emit={emit}");
                env.push(("OUT_DIR".into(), "/target/build/leaf/out".into()));
                env.push(("CARGO_TARGET_DIR".into(), "/target".into()));
                let request = LiveRustcRequest {
                    argv: &argv,
                    cwd: package,
                    env: &env,
                };
                assert_eq!(rejection(request), Some(LiveRefusal::UnclosedCodegenInputs));
                for may_wait in [false, true] {
                    let request = json!({
                        "kind": "rustc-request", "argv": argv, "cwd": package,
                        "env": env, "wait_for_inflight": may_wait,
                    });
                    let Decided::Shadow(observed) = decide(&live, &request) else {
                        panic!("codegen cannot warm, execute privately or serve: {emit}");
                    };
                    assert_eq!(observed.argv, argv, "fallback retains original outputs");
                    let mut advertised = request.clone();
                    advertised["remote_protocol"] = json!(1);
                    assert!(
                        matches!(decide(&live, &advertised), Decided::Shadow(_)),
                        "a wrapper hint cannot replace a configured enforcing worker: {emit}"
                    );
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_decide_shadows_cold_probes_and_primary_packages_without_starting_rustc() {
        use super::super::{Decided, LiveEdge, decide};
        use crate::coord::live::CoordLive;
        use crate::coord::live_dependency::LiveDependencyLane;
        use serde_json::json;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let compiler = root.join("rustc");
        let marker = root.join("probed");
        std::fs::write(
            &compiler,
            format!(
                "#!/bin/sh\nprintf invoked > '{}'\nexit 99\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cas = Arc::new(crate::janitor::store::mount_and_reconcile(&root.join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(cas));
        coord.acquire_boot_authority("preflight-fixture").unwrap();
        coord.mark_up();
        let live = LiveEdge::new(LiveDependencyLane::new(coord));
        let (mut argv, mut env) = fixture(PACKAGE);
        argv[0] = compiler.to_str().unwrap().into();
        env.push(("CARGO_PRIMARY_PACKAGE".into(), "1".into()));
        for may_wait in [true, false] {
            for request in [
                json!({
                    "kind": "rustc-request", "argv": [compiler.to_str().unwrap(), "-vV"],
                    "cwd": "/workspace", "env": [], "wait_for_inflight": may_wait,
                }),
                json!({
                    "kind": "rustc-request", "argv": argv, "cwd": PACKAGE,
                    "env": env, "wait_for_inflight": may_wait,
                }),
            ] {
                let Decided::Shadow(observed) = decide(&live, &request) else {
                    panic!("out-of-class requests must not wait for cold toolchain facts");
                };
                assert_eq!(observed.argv[0], compiler.to_str().unwrap());
                assert!(
                    !marker.exists(),
                    "preflight must not start an identity probe"
                );
            }
        }
    }

    #[test]
    fn non_library_producers_are_rejected_on_every_supported_host() {
        for host in [
            HOST,
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
        ] {
            for kind in [
                "",
                "bin",
                "proc-macro",
                "dylib",
                "cdylib",
                "staticlib",
                "lib,bin",
            ] {
                for split in [false, true] {
                    let (mut argv, env) = fixture(PACKAGE);
                    argv.retain(|arg| arg != "--crate-type=lib");
                    if !kind.is_empty() {
                        if split {
                            argv.extend(["--crate-type".into(), kind.into()]);
                        } else {
                            argv.push(format!("--crate-type={kind}"));
                        }
                    }
                    let request = LiveRustcRequest {
                        argv: &argv,
                        cwd: PACKAGE,
                        env: &env,
                    };
                    assert!(rejection(request).is_some(), "{kind:?} on {host}");
                    assert!(plan_dependency_action(request, host).is_err());
                }
            }
        }
    }

    #[test]
    fn supported_library_shapes_are_not_confused_with_producers() {
        for host in [
            HOST,
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
        ] {
            for kind in ["lib", "rlib"] {
                for emit in ["metadata,dep-info", "link,metadata,dep-info"] {
                    let (mut argv, env) = fixture(PACKAGE);
                    argv.retain(|arg| {
                        arg != "--crate-type=lib" && arg != "--emit=metadata,dep-info"
                    });
                    argv.extend([
                        "--crate-type".into(),
                        kind.into(),
                        format!("--emit={emit}"),
                        "--target".into(),
                        host.into(),
                    ]);
                    let request = LiveRustcRequest {
                        argv: &argv,
                        cwd: PACKAGE,
                        env: &env,
                    };
                    assert_eq!(
                        rejection(request),
                        emit.contains("link")
                            .then_some(LiveRefusal::UnclosedCodegenInputs),
                        "{kind} {emit} on {host}"
                    );
                    // Structural planning remains useful for discovery. It
                    // is not authority to serve a codegen result.
                    assert!(plan_dependency_action(request, host).is_ok());
                }
            }
        }
    }

    #[test]
    fn threaded_cargo_frontends_preserve_the_full_planner_path() {
        for host in [
            HOST,
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
        ] {
            for options in [
                vec!["-Zthreads=1"],
                vec!["-Z", "threads=8"],
                vec!["-Zthreads=8", "-Zembed-metadata=no"],
            ] {
                let (mut argv, env) = fixture(PACKAGE);
                argv.extend(options.iter().map(|option| (*option).to_owned()));
                let original = argv.clone();
                let request = LiveRustcRequest {
                    argv: &argv,
                    cwd: PACKAGE,
                    env: &env,
                };
                assert_eq!(rejection(request), None, "{options:?} on {host}");
                let plan = plan_dependency_action(request, host).unwrap();
                assert_eq!(argv, original, "admission must not rewrite the command");
                assert!(
                    plan.invocation
                        .unstable
                        .iter()
                        .any(|(name, _)| name == "threads")
                );
                assert!(plan.output_names().iter().any(|name| name.ends_with(".d")));
            }
        }
    }

    #[test]
    fn output_option_preflight_refusals_agree_with_the_full_planner() {
        for options in [
            vec!["-Cincremental=/target/incremental"],
            vec!["-C", "save-temps=yes"],
            vec!["-Csplit-debuginfo=unpacked"],
            vec!["-Zthreads=0"],
            vec!["-Z", "threads=auto"],
            vec!["-Zthreads=8", "-Zno-codegen"],
            vec!["-Zno-codegen", "-Zthreads=8"],
            vec!["--emit=dep-info,obj"],
            vec!["--emit=dep-info=/unmodeled/report"],
            vec!["--test"],
            vec!["--print=file-names"],
            vec!["--future-output-option"],
        ] {
            let (mut argv, env) = fixture(PACKAGE);
            argv.extend(options.iter().map(|option| (*option).to_owned()));
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            let actual = rejection(request);
            assert!(
                matches!(&actual, Some(LiveRefusal::Outputs(_))),
                "{options:?}"
            );
            assert_eq!(
                actual,
                plan_dependency_action(request, HOST).err(),
                "{options:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_edge_rejects_unmodeled_output_controls_without_cold_preparation() {
        use super::super::{Decided, LiveEdge, decide};
        use crate::coord::live::CoordLive;
        use crate::coord::live_dependency::LiveDependencyLane;
        use serde_json::json;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;

        let temporary = crate::test_util::private_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let compiler = root.join("toolchain/bin/rustc");
        let marker = root.join("probed");
        std::fs::create_dir_all(compiler.parent().unwrap()).unwrap();
        std::fs::write(
            &compiler,
            format!(
                "#!/bin/sh\nprintf invoked > '{}'\nexit 99\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o700)).unwrap();
        let cas = Arc::new(crate::janitor::store::mount_and_reconcile(&root.join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(cas));
        coord
            .acquire_boot_authority("output-controls-preflight")
            .unwrap();
        coord.mark_up();
        let live = LiveEdge::new(LiveDependencyLane::new(coord));
        for may_wait in [false, true] {
            for option in [
                "-Zthreads=0",
                "-Zno-codegen",
                "-Cincremental=/target/incremental",
                "-Csave-temps=yes",
                "--emit=dep-info,obj",
                "--test",
            ] {
                let (mut argv, env) = fixture(PACKAGE);
                argv[0] = compiler.to_str().unwrap().into();
                argv.push(option.into());
                let request = json!({
                    "kind": "rustc-request", "argv": argv, "cwd": PACKAGE,
                    "env": env, "wait_for_inflight": may_wait,
                });
                let Decided::Shadow(observed) = decide(&live, &request) else {
                    panic!("{option} must bypass, not warm facts for an impossible cache hit");
                };
                assert_eq!(observed.argv, argv);
                assert!(
                    !marker.exists(),
                    "an unsupported output control started rustc"
                );
            }
        }
    }

    #[test]
    fn unmodeled_compiler_source_and_output_shapes_do_not_warm() {
        for case in [
            "compiler",
            "stdin",
            "missing-source",
            "missing-out-dir",
            "empty-out-dir",
        ] {
            let (mut argv, env) = fixture(PACKAGE);
            match case {
                "compiler" => argv[0] = "/toolchain/bin/clippy-driver".into(),
                "stdin" => *argv.last_mut().unwrap() = "-".into(),
                "missing-source" => {
                    argv.pop();
                }
                "missing-out-dir" | "empty-out-dir" => {
                    let at = argv.iter().position(|arg| arg == "--out-dir").unwrap();
                    argv.remove(at + 1);
                    argv.remove(at);
                    if case == "empty-out-dir" {
                        argv.push("--out-dir=".into());
                    }
                }
                _ => unreachable!(),
            }
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            assert!(rejection(request).is_some(), "{case}");
            assert!(plan_dependency_action(request, HOST).is_err(), "{case}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_decide_never_prepares_capped_build_script_or_proc_macro_producers() {
        use super::super::{Decided, LiveEdge, decide};
        use crate::coord::live::CoordLive;
        use crate::coord::live_dependency::LiveDependencyLane;
        use serde_json::json;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let compiler = root.join("rustc");
        let marker = root.join("probed");
        std::fs::write(
            &compiler,
            format!(
                "#!/bin/sh\nprintf invoked > '{}'\nexit 99\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cas = Arc::new(crate::janitor::store::mount_and_reconcile(&root.join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(cas));
        coord
            .acquire_boot_authority("producer-preflight-fixture")
            .unwrap();
        coord.mark_up();
        let live = LiveEdge::new(LiveDependencyLane::new(coord));
        for may_wait in [true, false] {
            for (kind, source) in [("bin", "build.rs"), ("proc-macro", "src/lib.rs")] {
                let (mut argv, env) = fixture(PACKAGE);
                argv[0] = compiler.to_str().unwrap().into();
                argv.retain(|arg| arg != "--crate-type=lib");
                *argv.last_mut().unwrap() = format!("{PACKAGE}/{source}");
                argv.extend(["--crate-type".into(), kind.into()]);
                let request = json!({
                    "kind": "rustc-request", "argv": argv, "cwd": PACKAGE,
                    "env": env, "wait_for_inflight": may_wait,
                });
                let Decided::Shadow(observed) = decide(&live, &request) else {
                    panic!("{kind} must immediately pass through, not enter preparation");
                };
                assert_eq!(observed.argv, argv);
                assert!(
                    !marker.exists(),
                    "unsupported producers must not probe rustc"
                );
            }
        }
    }
}
