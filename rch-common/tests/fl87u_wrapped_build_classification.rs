//! Deterministic probe for frankentorch-fl87u mode 1: "`rch exec -- sh -c \"...\"` does not sync
//! artifacts back".
//!
//! The bead attributes the missing sync-back to the `sh -c` wrapper. That is a CLASSIFICATION
//! claim — retrieval patterns are selected by `CompilationKind` (rch/src/hook/artifact_patterns.rs
//! `get_artifact_patterns`), so a wrapped command that classified as non-compilation, or as a
//! test-ish kind, would pull the wrong file set and leave a stale local binary.
//!
//! That claim is checkable without workers, without a cache, and without a network: the classifier
//! is a pure function. This pins the exact argv the bead used and the exact reassembly `rch exec`
//! performs, so the result is deterministic.

use rch_common::patterns::classify_command;

/// `rch exec -- sh -c "cargo clippy ... && cargo build ..."` arrives as three argv entries, the
/// third being the whole inner script (the caller's shell already stripped the outer quotes).
/// `rch/src/hook.rs::join_exec_command` reassembles it with `shell_words::join`, which RE-QUOTES
/// any entry containing shell-meaningful bytes — so the inner script comes back single-quoted.
const REASSEMBLED_WRAPPED: &str =
    "sh -c 'cargo clippy --workspace --all-targets && cargo build --release --example probe'";

#[test]
fn fl87u_sh_dash_c_wrapped_build_is_classified_as_compilation() {
    let c = classify_command(REASSEMBLED_WRAPPED);
    assert!(
        c.is_compilation,
        "the sh -c wrapper must classify as a compilation so it is offloaded AND its artifacts \
         retrieved; got {c:?}"
    );
}

/// The compound inside the wrapper ends in `cargo build`, and
/// `try_classify_compound_command` classifies the LAST segment. This matters more than it looks:
/// had it taken the FIRST segment it would resolve to `cargo clippy`, whose artifact patterns are
/// `default_rust_test_artifact_patterns()` — no binaries — and the built example would never be
/// pulled home while the command still reported success. That is precisely fl87u's symptom, so
/// this pins the segment choice rather than trusting it.
#[test]
fn fl87u_wrapped_compound_resolves_to_the_build_not_the_clippy() {
    let c = classify_command(REASSEMBLED_WRAPPED);
    let kind = format!("{:?}", c.kind);
    assert!(
        kind.contains("CargoBuild"),
        "wrapped `clippy && build` must resolve to the BUILD (last segment) so binary artifact \
         patterns are selected; got kind={kind}, extracted={:?}",
        c.extracted_command
    );
}

/// Contrast case, pinned so a future change to `join_exec_command` cannot silently regress the
/// wrapper handling: WITHOUT the re-quoting that `shell_words::join` performs, the remainder is no
/// longer a single quoted argument and `try_classify_wrapped_command` declines. This is the shape
/// the classifier would see if the reassembly ever switched to a plain `parts.join(" ")`.
#[test]
fn fl87u_unquoted_wrapper_is_not_treated_as_a_wrapped_compilation() {
    let unquoted = "sh -c cargo build --release --example probe";
    let c = classify_command(unquoted);
    assert!(
        !c.is_compilation,
        "an unquoted `sh -c cargo ...` is not a recognisable wrapper; if this ever starts \
         classifying as compilation, verify the artifact patterns follow the right kind. got {c:?}"
    );
}
