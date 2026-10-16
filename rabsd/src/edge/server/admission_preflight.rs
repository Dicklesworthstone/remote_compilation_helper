//! Reject requests that cannot enter the live lane before warming any facts.
//!
//! Cargo's version/target probes, primary packages and unsupported compiler
//! invocations must not wait for a cold sysroot hash. This is rejection-only:
//! `None` is NOT admission, an action key, or permission to skip rustc. The
//! normal planner still checks the observed host, source class, output model
//! and every input guard. In particular, do not fabricate a host triple here
//! or classify a directory source without its captured checksum witness.

use rabs_key::invocation::{NormalizedRustcInvocation, SourceInput, parse};
use rabs_key::live_dependency::{LiveRefusal, LiveRustcRequest};

/// A host-independent subset of the live dependency planner's refusals.
/// Keep this deliberately small; differential tests below require supported
/// requests to continue to the full planner, not become false cache misses.
pub(super) fn rejection(request: LiveRustcRequest<'_>) -> Option<LiveRefusal> {
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
        if names.contains(&name) {
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
    if env_value("CARGO_MANIFEST_DIR") != Some(request.cwd) {
        return Some(LiveRefusal::WorkingDirectory(request.cwd.to_owned()));
    }
    let invocation = match parse(request.argv, None) {
        Ok(invocation) => invocation,
        Err(error) => return Some(LiveRefusal::Unparseable(format!("{error:?}"))),
    };
    if invocation.cap_lints.as_deref() != Some("allow") {
        return Some(LiveRefusal::NotDependencyCompile(
            "Cargo caps lints for external dependencies; this invocation does not",
        ));
    }
    // Cargo also caps dependency build-script binaries and proc-macro
    // producers. They are prerequisites of otherwise cacheable work, but
    // this lane cannot serve their output classes. Do not make them wait
    // behind a cold sysroot merely to discover that after hashing it.
    // These checks mirror only the HOST-INDEPENDENT shape restrictions in
    // derive_dependency_output_declarations; the full planner still owns
    // target naming, option semantics and the complete output declaration.
    if invocation.crate_types.is_empty()
        || invocation
            .crate_types
            .iter()
            .any(|kind| !matches!(kind.as_str(), "lib" | "rlib"))
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
    dependency_inputs_rejection(&invocation)
}

fn dependency_inputs_rejection(invocation: &NormalizedRustcInvocation) -> Option<LiveRefusal> {
    if let Some(library) = invocation.native_libs.first() {
        return Some(LiveRefusal::NativeLibrary(library.clone()));
    }
    // A proc-macro PRODUCER is rejected above, but the ordinary lib/rlib
    // that CONSUMES it cannot enter this unsandboxed class either. Likewise,
    // build scripts commonly add native search directories even without -l.
    // Neither needs a host probe, source capture, or dependency enumeration
    // to establish this refusal. Let Cargo make progress immediately rather
    // than spend the wrapper's cold-readiness budget on an impossible hit.
    for entry in &invocation.lib_search {
        if !entry.starts_with("dependency=") {
            return Some(LiveRefusal::SearchPath(entry.clone()));
        }
    }
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
            assert_eq!(rejection(request), plan_dependency_action(request, HOST).err());
            assert!(matches!(rejection(request), Some(LiveRefusal::RefusedEnv(_))));
        }
        for missing in ["CARGO_MANIFEST_DIR", "CARGO_PKG_NAME", "CARGO_HOME"] {
            let (argv, mut env) = fixture(PACKAGE);
            env.retain(|(name, _)| name != missing);
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            assert_eq!(rejection(request), plan_dependency_action(request, HOST).err());
            assert!(matches!(rejection(request), Some(LiveRefusal::MissingEnv(_))));
        }
        let (argv, mut env) = fixture(PACKAGE);
        env.push(env[0].clone());
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: PACKAGE,
            env: &env,
        };
        assert_eq!(rejection(request), plan_dependency_action(request, HOST).err());
        assert!(matches!(rejection(request), Some(LiveRefusal::DuplicateEnv(_))));
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
            format!("#!/bin/sh\nprintf invoked > '{}'\nexit 99\n", marker.display()),
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
                assert!(!marker.exists(), "preflight must not start an identity probe");
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
            for kind in ["", "bin", "proc-macro", "dylib", "cdylib", "staticlib", "lib,bin"] {
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
                    assert_eq!(rejection(request), None, "{kind} {emit} on {host}");
                    assert!(plan_dependency_action(request, host).is_ok());
                }
            }
        }
    }

    #[test]
    fn unmodeled_compiler_source_and_output_shapes_do_not_warm() {
        for case in ["compiler", "stdin", "missing-source", "missing-out-dir", "empty-out-dir"] {
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
            format!("#!/bin/sh\nprintf invoked > '{}'\nexit 99\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cas = Arc::new(crate::janitor::store::mount_and_reconcile(&root.join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(cas));
        coord.acquire_boot_authority("producer-preflight-fixture").unwrap();
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
                assert!(!marker.exists(), "unsupported producers must not probe rustc");
            }
        }
    }
}
