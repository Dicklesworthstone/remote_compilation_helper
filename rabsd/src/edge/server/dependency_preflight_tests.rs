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
