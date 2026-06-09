//! Fuzz/property coverage for the classification → capability/exec derivation
//! surface (bd-review-test-classify-fuzz): `admit_preflight::preflight`,
//! `exec_policy::{decide_exec_policy, mutates_local_state}`, and
//! `exec_misuse::detect_exec_misuse` over arbitrary + structured command
//! strings. Mock-free, pure-function fuzzing — no daemon, no network.

use proptest::prelude::*;
use rch_common::admit_preflight::{AdmitRecommendation, preflight};
use rch_common::exec_misuse::detect_exec_misuse;
use rch_common::exec_policy::{ExecContext, ExecDisposition, decide_exec_policy, mutates_local_state};

/// Command-like strings built from realistic tokens (cargo/bun/wrappers/env/
/// operators/quotes) plus a free-form token, joined with spaces.
fn command_like() -> impl Strategy<Value = String> {
    let token = prop_oneof![
        Just("cargo".to_string()),
        Just("build".to_string()),
        Just("test".to_string()),
        Just("fmt".to_string()),
        Just("fix".to_string()),
        Just("--release".to_string()),
        Just("--target".to_string()),
        Just("wasm32-unknown-unknown".to_string()),
        Just("+nightly".to_string()),
        Just("--offline".to_string()),
        Just("bun".to_string()),
        Just("install".to_string()),
        Just("env".to_string()),
        Just("CARGO_TARGET_DIR=/tmp/t".to_string()),
        Just("nice".to_string()),
        Just("-n".to_string()),
        Just("10".to_string()),
        Just("ls".to_string()),
        Just("&&".to_string()),
        Just(";".to_string()),
        Just("|".to_string()),
        Just("'a quoted str'".to_string()),
        "[a-zA-Z0-9._/=+-]{1,10}",
    ];
    proptest::collection::vec(token, 0..9).prop_map(|toks| toks.join(" "))
}

/// Either a structured command-like string or fully arbitrary UTF-8.
fn any_command() -> impl Strategy<Value = String> {
    prop_oneof![command_like(), any::<String>()]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    /// preflight is total and DEFINITE: never panics; the base recommendation is
    /// always Offload or Local (Queue/Defer only arise from refinement with
    /// daemon data); compound is never empty; a non-compilation is always Local;
    /// and the function is deterministic.
    #[test]
    fn preflight_is_total_and_definite(cmd in any_command()) {
        for proof in [false, true] {
            let p = preflight(&cmd, proof);
            prop_assert!(
                matches!(
                    p.base_recommendation,
                    AdmitRecommendation::Offload | AdmitRecommendation::Local
                ),
                "non-definite base recommendation {:?} for {:?}",
                p.base_recommendation,
                cmd
            );
            prop_assert!(!p.compound.is_empty(), "empty compound for {:?}", cmd);
            if !p.is_compilation {
                prop_assert_eq!(p.base_recommendation, AdmitRecommendation::Local);
            }
            // Pure + deterministic: identical input yields an identical result.
            prop_assert_eq!(preflight(&cmd, proof), p);
        }
    }

    /// exec policy is total: never panics; disposition is one of the three;
    /// and a state-mutating non-compilation is NEVER shipped remote (even under
    /// force-remote) — the conservative invariant the policy exists to enforce.
    #[test]
    fn exec_policy_is_total_and_conservative(cmd in any_command()) {
        let _ = mutates_local_state(&cmd); // must not panic
        let contexts = [
            ExecContext::hook(),
            ExecContext::explicit(),
            ExecContext { explicit_exec: true, proof_mode: true, force_remote: false },
            ExecContext { explicit_exec: true, proof_mode: false, force_remote: true },
        ];
        for ctx in contexts {
            let d = decide_exec_policy(&cmd, &ctx);
            prop_assert!(matches!(
                d.disposition,
                ExecDisposition::RunRemote
                    | ExecDisposition::RunLocalFallback
                    | ExecDisposition::Reject
            ));
            if d.mutates_local_state && !d.is_compilation {
                prop_assert_ne!(
                    d.disposition,
                    ExecDisposition::RunRemote,
                    "mutating non-compilation shipped remote for {:?} ctx {:?}",
                    cmd,
                    ctx
                );
            }
        }
    }

    /// detect_exec_misuse is total and exactly matches its contract: misuse iff
    /// no `--` separator AND the argv is a single element containing whitespace;
    /// and misuse iff a correction suggestion is produced.
    #[test]
    fn exec_misuse_matches_contract(
        argv in proptest::collection::vec("[a-zA-Z0-9 _./=+-]{0,24}", 0..4),
        had_separator in any::<bool>(),
    ) {
        let report = detect_exec_misuse(&argv, had_separator);
        let single_whitespace_token =
            argv.len() == 1 && argv[0].split_whitespace().count() > 1;
        let expect_misuse = !had_separator && single_whitespace_token;
        prop_assert_eq!(report.misuse, expect_misuse, "argv={:?} sep={}", argv, had_separator);
        prop_assert_eq!(report.misuse, report.suggestion.is_some());
        prop_assert_eq!(report.misuse, report.reason_code.is_some());
    }
}

/// mutates_local_state is stable under benign env-prefix / flag permutations of
/// a known mutating command, and a non-mutating command stays non-mutating.
#[test]
fn mutates_stable_under_benign_prefixes() {
    assert!(mutates_local_state("cargo fmt"));
    for variant in [
        "env CARGO_TERM_COLOR=always cargo fmt",
        "env A=1 B=2 cargo fmt",
        "cargo fmt --all",
        "cargo fmt -- --check",
        "bun install --frozen-lockfile",
        "cargo +nightly fmt",
    ] {
        assert!(mutates_local_state(variant), "expected mutating: {variant}");
    }
    for safe in ["cargo build", "env A=1 cargo build", "bun test", "ls -la"] {
        assert!(!mutates_local_state(safe), "should not be mutating: {safe}");
    }
}
