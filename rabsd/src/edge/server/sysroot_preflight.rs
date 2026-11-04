//! Bind explicit sysroot selection to the toolchain the live observer hashes.
//!
//! The current observer proves <native-root>/bin/rustc, its runtime inputs,
//! and that compiler's native sysroot. Hashing an alternate --sysroot pathname
//! in argv is not evidence of the bytes rustc reads there. Until an alternate
//! sysroot has its own complete observation/guard, that request must bypass
//! live reuse and execute its original command, not use the native-root key.

use rabs_key::invocation::NormalizedRustcInvocation;
use rabs_key::live_dependency::LiveRefusal;

pub(super) fn rejection(invocation: &NormalizedRustcInvocation) -> Option<LiveRefusal> {
    let native = invocation.compiler_argv0.strip_suffix("/bin/rustc");
    let native = native.map(|root| if root.is_empty() { "/" } else { root });
    let mut seen = false;
    let mut options = invocation.passthrough.iter();
    while let Some(option) = options.next() {
        // All passthrough options admitted by the output adapter take a
        // value. Consume that value even for non-sysroot options: an option's
        // payload must never be reinterpreted as another compiler option.
        // Unknown/missing-value options still face the full output adapter.
        let (name, inline) = option
            .split_once('=')
            .map_or((option.as_str(), None), |(name, value)| (name, Some(value)));
        let value = inline.or_else(|| options.next().map(String::as_str));
        if name != "--sysroot" {
            continue;
        }
        let matches_native = native.is_some_and(|root| {
            root.starts_with('/')
                && !root.contains('\0')
                && root.split('/').all(|part| part != "." && part != "..")
                && value == Some(root)
        });
        if seen || !matches_native {
            return Some(LiveRefusal::Facts(
                "explicit sysroot is not the single observed native toolchain root".into(),
            ));
        }
        seen = true;
    }
    // This is not admission: the real toolchain probe must still verify the
    // default sysroot, file bytes, root topology and retained generations.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_key::invocation::parse;

    fn invocation(compiler: &str, extra: &[&str]) -> NormalizedRustcInvocation {
        let argv = std::iter::once(compiler)
            .chain([
                "--crate-name=consumer",
                "--crate-type=lib",
                "--emit=metadata,dep-info",
                "--out-dir=/target/deps",
                "--cap-lints=allow",
                "--error-format=json",
            ])
            .chain(extra.iter().copied())
            .chain(["/cargo/registry/src/index/consumer-1.0.0/src/lib.rs"])
            .map(str::to_owned)
            .collect::<Vec<_>>();
        parse(&argv, None).unwrap()
    }

    #[test]
    fn implicit_and_explicit_native_roots_keep_the_full_observation_path() {
        for compiler in [
            "/toolchain/bin/rustc",
            "/a toolchain/bin/rustc",
            "/bin/rustc",
        ] {
            let root = compiler.strip_suffix("/bin/rustc").unwrap();
            let root = if root.is_empty() { "/" } else { root };
            let joined = format!("--sysroot={root}");
            for options in [vec![], vec!["--sysroot", root], vec![joined.as_str()]] {
                assert_eq!(rejection(&invocation(compiler, &options)), None);
            }
        }
    }

    #[test]
    fn unobserved_roots_and_alias_spellings_never_enter_the_live_lane() {
        for root in [
            "/alternate",
            "relative",
            ".",
            "..",
            "/toolchain/../toolchain",
            "/toolchain/",
            "/toolchain-alias",
            "",
        ] {
            let joined = format!("--sysroot={root}");
            for options in [vec!["--sysroot", root], vec![joined.as_str()]] {
                assert!(rejection(&invocation("/toolchain/bin/rustc", &options)).is_some());
            }
        }
    }

    #[test]
    fn repeated_sysroot_selection_is_not_guessed_or_last_value_wins() {
        for options in [
            vec!["--sysroot=/toolchain", "--sysroot=/toolchain"],
            vec!["--sysroot=/alternate", "--sysroot=/toolchain"],
            vec!["--sysroot=/toolchain", "--sysroot", "/alternate"],
        ] {
            assert!(rejection(&invocation("/toolchain/bin/rustc", &options)).is_some());
        }
    }

    #[test]
    fn unrelated_option_payloads_are_not_parsed_as_sysroot_flags() {
        for options in [
            vec!["--remap-path-prefix=/source=--sysroot=/alternate"],
            vec!["--remap-path-prefix", "--sysroot=/alternate"],
            vec![
                "--check-cfg",
                "cfg(feature,values(\"--sysroot=/alternate\"))",
            ],
        ] {
            assert_eq!(
                rejection(&invocation("/toolchain/bin/rustc", &options)),
                None
            );
        }
        assert!(
            rejection(&invocation(
                "/toolchain/bin/rustc",
                &[
                    "--remap-path-prefix",
                    "/source=/mapped",
                    "--sysroot=/alternate"
                ],
            ))
            .is_some()
        );
    }

    #[test]
    fn compiler_root_spelling_must_be_absolute_and_unambiguous() {
        for (compiler, root) in [
            ("rustc", "/toolchain"),
            ("toolchain/bin/rustc", "toolchain"),
            ("/toolchain/../other/bin/rustc", "/toolchain/../other"),
            ("/toolchain/./bin/rustc", "/toolchain/."),
        ] {
            assert!(rejection(&invocation(compiler, &["--sysroot", root])).is_some());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_actual_edge_never_prepares_or_serves_an_unobserved_sysroot() {
        use super::super::super::{Decided, LiveEdge, decide};
        use crate::coord::live::CoordLive;
        use crate::coord::live_dependency::LiveDependencyLane;
        use rabs_key::live_dependency::{LiveRustcRequest, plan_dependency_action};
        use serde_json::json;
        use std::sync::Arc;

        let temporary = crate::test_util::private_tempdir();
        let cas = Arc::new(
            crate::janitor::store::mount_and_reconcile(&temporary.path().join("cas")).unwrap(),
        );
        let coord = Arc::new(CoordLive::with_cas(cas));
        coord
            .acquire_boot_authority("sysroot-preflight-fixture")
            .unwrap();
        coord.mark_up();
        let live = LiveEdge::new(LiveDependencyLane::new(coord));
        let package = "/cargo/registry/src/index/consumer-1.0.0";
        let env = vec![
            ("CARGO_HOME".to_owned(), "/cargo".to_owned()),
            ("CARGO_MANIFEST_DIR".to_owned(), package.to_owned()),
            ("CARGO_PKG_NAME".to_owned(), "consumer".to_owned()),
        ];
        let argv: Vec<String> = [
            "/toolchain/bin/rustc",
            "--crate-name=consumer",
            "--crate-type=lib",
            "--emit=metadata,dep-info",
            "--out-dir=/target/deps",
            "--cap-lints=allow",
            "--error-format=json",
            "--sysroot=/unobserved",
            "/cargo/registry/src/index/consumer-1.0.0/src/lib.rs",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        // The pure planner accepts the output-neutral flag syntactically;
        // only the observing edge can say which actual sysroot it has closed.
        assert!(
            plan_dependency_action(
                LiveRustcRequest {
                    argv: &argv,
                    cwd: package,
                    env: &env,
                },
                "x86_64-unknown-linux-gnu",
            )
            .is_ok()
        );
        for may_wait in [false, true] {
            let request = json!({
                "kind": "rustc-request", "argv": argv, "cwd": package,
                "env": env, "wait_for_inflight": may_wait,
            });
            let Decided::Shadow(observed) = decide(&live, &request) else {
                panic!("unobserved sysroot must bypass before any native toolchain warm or hit");
            };
            assert_eq!(
                observed.argv, argv,
                "fallback must preserve the original sysroot selection"
            );
        }
    }
}
