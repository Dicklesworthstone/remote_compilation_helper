//! Real parser/planner and edge-decision regressions for cold consumer requests.

use super::rejection;
use rabs_key::live_dependency::{LiveRefusal, LiveRustcRequest, plan_dependency_action};

const PACKAGE: &str = "/cargo/registry/src/index/consumer-1.0.0";
const HOSTS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
];

fn fixture(extra: &[&str]) -> (Vec<String>, Vec<(String, String)>) {
    let mut argv: Vec<String> = [
        "/toolchain/bin/rustc",
        "--crate-name=consumer",
        "--crate-type=lib",
        "--emit=metadata,dep-info",
        "--out-dir=/target/deps",
        "--cap-lints=allow",
        "--error-format=json",
        "-Ldependency=/target/deps",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(str::to_owned)
    .collect();
    argv.push(format!("{PACKAGE}/src/lib.rs"));
    (
        argv,
        vec![
            ("CARGO_HOME".into(), "/cargo".into()),
            ("CARGO_MANIFEST_DIR".into(), PACKAGE.into()),
            ("CARGO_PKG_NAME".into(), "consumer".into()),
        ],
    )
}

#[test]
fn consumed_dynamic_artifacts_refuse_before_any_host_facts() {
    for extension in ["so", "dylib"] {
        let path = format!("/target/deps/libderive-123.{extension}");
        let binding = format!("derive={path}");
        for extra in [
            vec!["--extern".to_owned(), binding.clone()],
            vec![format!("--extern={binding}")],
        ] {
            let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
            let (argv, env) = fixture(&extra);
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            let expected = LiveRefusal::ProcMacroDependency(path.clone());
            assert_eq!(rejection(request), Some(expected.clone()));
            for host in HOSTS {
                assert_eq!(plan_dependency_action(request, host), Err(expected.clone()));
            }
        }
    }
}

#[test]
fn native_framework_and_untyped_search_directories_never_need_warming() {
    for entry in [
        "native=/target/build/native/out",
        "framework=/sdk/Frameworks",
        "crate=/target/deps",
        "all=/target/deps",
        "/target/deps",
    ] {
        for extra in [
            vec!["-L".to_owned(), entry.to_owned()],
            vec![format!("-L{entry}")],
        ] {
            let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
            let (argv, env) = fixture(&extra);
            let request = LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            };
            assert_eq!(
                rejection(request),
                Some(LiveRefusal::SearchPath(entry.into()))
            );
            for host in HOSTS {
                assert!(
                    plan_dependency_action(request, host).is_err(),
                    "{entry} on {host}"
                );
            }
        }
    }
}

#[test]
fn unmodeled_explicit_externs_refuse_instead_of_warming() {
    for path in [
        "/target/deps/foreign.dll",
        "/target/deps/native.a",
        "relative",
        "",
    ] {
        let binding = format!("foreign={path}");
        let (argv, env) = fixture(&["--extern", &binding]);
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: PACKAGE,
            env: &env,
        };
        assert!(rejection(request).is_some(), "{binding}");
        for host in HOSTS {
            assert!(
                plan_dependency_action(request, host).is_err(),
                "{binding} on {host}"
            );
        }
    }
}

#[test]
fn rust_artifacts_and_toolchain_externs_still_reach_full_admission() {
    for extra in [
        vec!["--extern", "core"],
        vec!["--extern", "upstream=/target/deps/libupstream.rmeta"],
        vec!["--extern=upstream=/target/deps/libupstream.rlib"],
        vec![
            "-L",
            "dependency=/other/deps",
            "--extern",
            "upstream=/other/deps/libupstream.rmeta",
        ],
    ] {
        let (argv, env) = fixture(&extra);
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: PACKAGE,
            env: &env,
        };
        assert_eq!(rejection(request), None, "{extra:?}");
        for host in HOSTS {
            assert!(
                plan_dependency_action(request, host).is_ok(),
                "{extra:?} on {host}"
            );
        }
    }
}

#[test]
fn syntactic_acceptance_does_not_bless_paths_or_output_aliases() {
    for path in [
        "relative.rmeta",
        "/target/deps/libconsumer.rmeta",
        "/cargo/libbad.rlib",
    ] {
        let binding = format!("upstream={path}");
        let (argv, env) = fixture(&["--extern", &binding]);
        let request = LiveRustcRequest {
            argv: &argv,
            cwd: PACKAGE,
            env: &env,
        };
        assert_eq!(rejection(request), None);
        assert!(plan_dependency_action(request, HOSTS[0]).is_err(), "{path}");
    }
}

#[test]
fn generated_static_archives_reach_only_retained_canonical_remote_planning() {
    use super::{canonical_remote_rejection, remote_rejection};
    use rabs_key::live_dependency::{
        plan_canonical_cargo_dependency_action, plan_canonical_remote_dependency_action,
    };

    let package = "/__rabs/cargo-home/registry/src/pinned/native-1.0.0";
    let generated = "/__rabs/out/cargo/debug/build/native-hash/out";
    let argv = vec![
        "/__rabs/toolchain/bin/rustc".into(),
        "--crate-name=native".into(),
        "--crate-type=lib".into(),
        "--emit=dep-info,metadata,link".into(),
        "--error-format=json".into(),
        "--out-dir=/__rabs/out/cargo/debug/deps".into(),
        "--cap-lints=allow".into(),
        "-Ldependency=/__rabs/out/cargo/debug/deps".into(),
        format!("-Lnative={generated}/native"),
        "-lstatic=answer".into(),
        format!("{package}/src/lib.rs"),
    ];
    let env = vec![
        ("HOME".into(), "/__rabs/home".into()),
        ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
        ("CARGO_MANIFEST_DIR".into(), package.into()),
        ("CARGO_PKG_NAME".into(), "native".into()),
        ("OUT_DIR".into(), generated.into()),
    ];
    let candidate = LiveRustcRequest {
        argv: &argv,
        cwd: package,
        env: &env,
    };
    assert_eq!(canonical_remote_rejection(candidate), None);
    assert!(remote_rejection(candidate).is_some());
    assert!(rejection(candidate).is_some());
    assert!(plan_canonical_remote_dependency_action(candidate, HOSTS[0], None).is_ok());
    assert!(plan_canonical_cargo_dependency_action(candidate, HOSTS[0], None).is_err());
    let mut metadata = argv.clone();
    *metadata
        .iter_mut()
        .find(|arg| arg.starts_with("--emit="))
        .unwrap() = "--emit=dep-info,metadata".into();
    let metadata = LiveRustcRequest {
        argv: &metadata,
        cwd: package,
        env: &env,
    };
    assert_eq!(canonical_remote_rejection(metadata), None);
    assert!(remote_rejection(metadata).is_some());
    assert!(rejection(metadata).is_some());
    assert!(plan_canonical_remote_dependency_action(metadata, HOSTS[0], None).is_ok());
    assert!(plan_canonical_cargo_dependency_action(metadata, HOSTS[0], None).is_err());

    for extra in [
        "-Lnative=/usr/lib",
        "-Lnative=/__rabs/out/cargo/debug/build/other/out",
        "-Lnative=/__rabs/out/cargo/debug/build/native-hash/outside",
        "-lanswer",
        "-ldylib=answer",
        "-lstatic:-bundle=answer",
        "-lstatic=../answer",
        "--emit=dep-info,metadata",
    ] {
        let mut unsupported = argv.clone();
        unsupported.push(extra.into());
        assert!(
            canonical_remote_rejection(LiveRustcRequest {
                argv: &unsupported,
                cwd: package,
                env: &env,
            })
            .is_some(),
            "{extra}"
        );
    }
    let mut primary = env.clone();
    primary.push(("CARGO_PRIMARY_PACKAGE".into(), "1".into()));
    assert!(matches!(
        canonical_remote_rejection(LiveRustcRequest {
            argv: &argv,
            cwd: package,
            env: &primary,
        }),
        Some(LiveRefusal::RefusedEnv(_))
    ));
}

#[test]
fn workspace_native_archives_reach_only_fresh_planning_with_the_exact_out_dir() {
    use super::{canonical_remote_rejection, remote_rejection, workspace_rejection};
    use rabs_key::live_dependency::plan_canonical_workspace_execution;

    let generated = "/__rabs/out/cargo/debug/build/member-hash/out";
    let argv = vec![
        "/__rabs/toolchain/bin/rustc".into(),
        "--crate-name=member".into(),
        "--crate-type=lib".into(),
        "--emit=dep-info,metadata,link".into(),
        "--error-format=json".into(),
        "--out-dir=/__rabs/out/cargo/debug/deps".into(),
        "-Ldependency=/__rabs/out/cargo/debug/deps".into(),
        format!("-Lnative={generated}/native"),
        "-lstatic=answer".into(),
        "member/src/lib.rs".into(),
    ];
    let env = vec![
        ("HOME".into(), "/__rabs/home".into()),
        ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
        (
            "CARGO_MANIFEST_DIR".into(),
            "/__rabs/workspace/member".into(),
        ),
        ("CARGO_PKG_NAME".into(), "member".into()),
        ("CARGO_PRIMARY_PACKAGE".into(), "1".into()),
        ("OUT_DIR".into(), generated.into()),
    ];
    let request = LiveRustcRequest {
        argv: &argv,
        env: &env,
        cwd: "/__rabs/workspace",
    };
    assert_eq!(workspace_rejection(request), None);
    assert!(rejection(request).is_some());
    assert!(remote_rejection(request).is_some());
    assert!(canonical_remote_rejection(request).is_some());
    for host in HOSTS {
        let plan = plan_canonical_workspace_execution(request, host).unwrap();
        assert_eq!(
            plan.invocation,
            rabs_key::invocation::parse(&argv, None).unwrap()
        );
        assert_eq!(plan.generated_root.as_deref(), Some(generated));
    }
    for extra in [
        "-Lnative=/usr/lib",
        "-Lnative=/__rabs/out/cargo/debug/build/other/out/native",
        "-Lnative=/__rabs/out/cargo/debug/build/member-hash/outside",
        "-ldylib=answer",
        "-lstatic:-bundle=answer",
        "-lstatic=../answer",
        "-Ctarget-cpu=native",
    ] {
        let mut changed = argv.clone();
        changed.push(extra.into());
        let request = LiveRustcRequest {
            argv: &changed,
            env: &env,
            cwd: "/__rabs/workspace",
        };
        assert!(workspace_rejection(request).is_some(), "{extra}");
        assert!(
            plan_canonical_workspace_execution(request, HOSTS[0]).is_err(),
            "{extra}"
        );
    }
    let mut metadata = argv.clone();
    *metadata
        .iter_mut()
        .find(|arg| arg.starts_with("--emit="))
        .unwrap() = "--emit=dep-info,metadata".into();
    let metadata = LiveRustcRequest {
        argv: &metadata,
        env: &env,
        cwd: "/__rabs/workspace",
    };
    assert_eq!(workspace_rejection(metadata), None);
    assert!(plan_canonical_workspace_execution(metadata, HOSTS[0]).is_ok());
    assert!(rejection(metadata).is_some());
    assert!(remote_rejection(metadata).is_some());
    assert!(canonical_remote_rejection(metadata).is_some());
    let mut missing_out_dir = env.clone();
    missing_out_dir.retain(|(name, _)| name != "OUT_DIR");
    let missing_out_dir = LiveRustcRequest {
        argv: &argv,
        env: &missing_out_dir,
        cwd: "/__rabs/workspace",
    };
    assert!(workspace_rejection(missing_out_dir).is_some());
    assert!(plan_canonical_workspace_execution(missing_out_dir, HOSTS[0]).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn actual_edge_passes_unservable_consumers_through_without_preparing() {
    use super::super::{Decided, LiveEdge, decide};
    use crate::coord::live::CoordLive;
    use crate::coord::live_dependency::LiveDependencyLane;
    use serde_json::json;
    use std::sync::Arc;

    let temporary = crate::test_util::private_tempdir();
    let root = temporary.path().canonicalize().unwrap();
    let cas = Arc::new(crate::janitor::store::mount_and_reconcile(&root.join("cas")).unwrap());
    let coord = Arc::new(CoordLive::with_cas(cas));
    coord
        .acquire_boot_authority("consumer-preflight-fixture")
        .unwrap();
    coord.mark_up();
    let live = LiveEdge::new(LiveDependencyLane::new(coord));
    // Neither the compiler nor source exists. These syntactic refusals must
    // not depend on probing either; the old path returned preparing first.
    for may_wait in [true, false] {
        for extra in [
            vec!["--extern", "derive=/target/deps/libderive.so"],
            vec!["--extern=derive=/target/deps/libderive.dylib"],
            vec!["-Lnative=/target/build/native/out"],
            vec!["--extern", "foreign=/target/deps/foreign.dll"],
        ] {
            let (argv, env) = fixture(&extra);
            let request = json!({
                "kind": "rustc-request", "argv": argv, "cwd": PACKAGE,
                "env": env, "wait_for_inflight": may_wait,
            });
            let Decided::Shadow(observed) = decide(&live, &request) else {
                panic!("unservable consumer must not wait for cold input facts: {extra:?}");
            };
            assert_eq!(observed.argv, argv);
        }
    }
}
