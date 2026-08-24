//! Failed build-script retry parity + rustc capability-probe fixtures
//! (bead T034; plan Epic T; R101/R23; consumes N013's preservation
//! contract and K018's probe classification).
//!
//! TWO fixture families, one acceptance each:
//!
//! 1. **Retry parity after failed build scripts (R101)**: stock Cargo
//!    retry semantics are ACCUMULATING — a failed run leaves partial
//!    OUT_DIR/cache contents in place and the retry observes them.
//!    N013's contract: RABS either preserves the EXACT observed
//!    failure post-state for the live retry (parity verified by
//!    [`verify_preserved_parity`]) or refuses to drive it at all
//!    ([`LiveOperationDecision::ExecuteLocally`] — fail-open). These
//!    fixtures pin the decision rule, the both-sections comparison,
//!    and the BOTH-DIRECTIONS divergence enumeration: missing observed
//!    partials AND live ghosts are named, never tolerated.
//! 2. **rustc capability-probe fixtures (R23/K018)**: `-vV`/`--print`
//!    probes are classified, dispatched on a bounded path (local
//!    passthrough, or the separately-keyed tiny cache ONLY under a
//!    toolchain identity), and served BYTE-EXACTLY or not at all
//!    ([`TinyProbeRecord::serves_exactly`]). The absolute latency cap
//!    is pinned so it cannot silently grow.

use rabs_action::capability_probe::{
    ClassifiedProbe, MAX_ADDED_PROBE_LATENCY_MS, ProbePath, ProbeShape, TinyProbeRecord,
    classify_rustc_probe, decide, tiny_probe_key,
};
use rabs_protocol::failure_post_state::{
    LiveOperationDecision, ParityResult, PreservationCapabilities, decide_live_operation,
    verify_preserved_parity,
};
use rabs_protocol::output_manifest::{OutputEntry, OutputTreeManifest};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn d(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn entry(path: &str, len: u64) -> OutputEntry {
    OutputEntry::new(path.as_bytes().to_vec(), len)
}

/// The post-state a STOCK failed build script leaves behind: partial
/// OUT_DIR artifacts (accumulated across attempts) plus Cargo's own
/// output-cache files at the run root.
fn observed_failure_post_state() -> OutputTreeManifest {
    OutputTreeManifest::new(
        vec![entry("out/a.o", 12), entry("out/sub/b.rmeta", 3)],
        vec![
            entry("invoked.timestamp", 8),
            entry("output", 5),
            entry("run/stdout", 40),
        ],
    )
    .unwrap()
}

// =====================================================================
// Family 1: failed build-script partial-state retry parity (R101/N013)
// =====================================================================

#[test]
fn t034_preservation_decision_fails_open_without_exact_staging() {
    // Without exact-tree staging the answer is ALWAYS local execution:
    // a guessed preservation is worse than stock behavior.
    assert_eq!(
        decide_live_operation(&PreservationCapabilities {
            can_stage_exact_tree: false,
        }),
        LiveOperationDecision::ExecuteLocally
    );
    assert_eq!(
        decide_live_operation(&PreservationCapabilities {
            can_stage_exact_tree: true,
        }),
        LiveOperationDecision::PreserveExactObservedState
    );
}

#[test]
fn t034_retry_parity_holds_when_live_matches_the_stock_failure_state() {
    let live = observed_failure_post_state();
    let observed = observed_failure_post_state();
    let parity = verify_preserved_parity(&live, &observed);
    assert_eq!(parity, ParityResult::Identical);
    assert!(parity.is_parity());
}

#[test]
fn t034_missing_observed_partials_break_parity_and_are_enumerated() {
    // The retry LOST an accumulated partial (`out/sub/b.rmeta`): the
    // live operation would observe LESS than stock did. The checker
    // names the missing entry exactly — not a boolean shrug.
    let mut live = observed_failure_post_state();
    live.out_dir_entries
        .retain(|e| e.path.as_slice() != b"out/sub/b.rmeta");
    let observed = observed_failure_post_state();

    match verify_preserved_parity(&live, &observed) {
        ParityResult::Diverged { missing, extra } => {
            assert_eq!(missing, vec![entry("out/sub/b.rmeta", 3)]);
            assert!(extra.is_empty());
        }
        other => panic!("expected enumerated divergence, got {other:?}"),
    }
    assert!(!verify_preserved_parity(&live, &observed).is_parity());
}

#[test]
fn t034_ghosts_length_drift_and_cache_section_divergences_are_enumerated() {
    let observed = observed_failure_post_state();
    // The live tree grew a GHOST file stock never produced, drifted a
    // same-path length (`out/a.o` 12 -> 13 bytes), AND diverged in the
    // OutputCache section too — every one of them must be named.
    let live = OutputTreeManifest::new(
        vec![entry("out/a.o", 13), entry("out/ghost.tmp", 1)],
        vec![entry("output", 6), entry("run/stdout", 40)],
    )
    .unwrap();

    match verify_preserved_parity(&live, &observed) {
        ParityResult::Diverged { missing, extra } => {
            // Missing = what stock saw and the retry will not.
            assert!(missing.contains(&entry("out/a.o", 12)));
            assert!(missing.contains(&entry("output", 5)));
            assert!(missing.contains(&entry("invoked.timestamp", 8)));
            // Extra = ghosts the retry sees that stock never produced.
            assert!(extra.contains(&entry("out/ghost.tmp", 1)));
            assert!(extra.contains(&entry("out/a.o", 13)));
            assert!(extra.contains(&entry("output", 6)));
            // Ordering discipline: path-then-length in BOTH directions.
            let sorted = |v: &[OutputEntry]| {
                v.windows(2)
                    .all(|w| (w[0].path.clone(), w[0].len) <= (w[1].path.clone(), w[1].len))
            };
            assert!(sorted(&missing));
            assert!(sorted(&extra));
        }
        other => panic!("expected enumerated divergence, got {other:?}"),
    }

    // Section coverage proof: a divergence confined to OutputCache is
    // caught even when OUT_DIR is perfectly preserved.
    let out_dir_intact = OutputTreeManifest::new(
        vec![entry("out/a.o", 12), entry("out/sub/b.rmeta", 3)],
        vec![entry("output", 999)],
    )
    .unwrap();
    assert!(matches!(
        verify_preserved_parity(&out_dir_intact, &observed),
        ParityResult::Diverged { .. }
    ));
}

// =====================================================================
// Family 2: rustc capability-probe fixtures (R23/K018)
// =====================================================================

#[test]
fn t034_version_and_print_probes_classify_with_target_capture() {
    // Version banner shape…
    assert_eq!(
        classify_rustc_probe(&args(&["rustc", "-vV"])),
        Some(ClassifiedProbe {
            shape: ProbeShape::VersionQuery,
            target_triple: None,
        })
    );
    // …--print with space and = spellings…
    assert_eq!(
        classify_rustc_probe(&args(&["rustc", "--print", "sysroot"])),
        Some(ClassifiedProbe {
            shape: ProbeShape::PrintQuery {
                query: "sysroot".to_owned()
            },
            target_triple: None,
        })
    );
    // …the = spelling with a cfg= query captures the full query…
    assert_eq!(
        classify_rustc_probe(&args(&["rustc", "--print=cfg=windows"])),
        Some(ClassifiedProbe {
            shape: ProbeShape::PrintQuery {
                query: "cfg=windows".to_owned()
            },
            target_triple: None,
        })
    );
    // …and explicit --target capture in BOTH spellings (the answer is
    // per-target even on one host).
    for argv in [
        args(&["rustc", "--target", "aarch64-unknown-linux-gnu", "-vV"]),
        args(&["rustc", "--target=aarch64-unknown-linux-gnu", "-vV"]),
    ] {
        assert_eq!(
            classify_rustc_probe(&argv),
            Some(ClassifiedProbe {
                shape: ProbeShape::VersionQuery,
                target_triple: Some(b"aarch64-unknown-linux-gnu".to_vec()),
            })
        );
    }
    // Unknown flags ride along without disqualifying (forward compat).
    assert!(classify_rustc_probe(&args(&["rustc", "--emit=future-kind", "-vV"])).is_some());
}

#[test]
fn t034_compiles_and_context_queries_never_classify_as_probes() {
    // Any positional input file makes it a COMPILE (K016 governs).
    assert_eq!(
        classify_rustc_probe(&args(&["rustc", "main.rs", "--crate-name", "x"])),
        None
    );
    // Context-requiring --print queries are NOT zero-input probes.
    for query in ["crate-name", "file-names", "native-static-libs"] {
        assert_eq!(
            classify_rustc_probe(&args(&["rustc", "--print", query])),
            None,
            "{query} needs source context"
        );
    }
    // A different driver is not our probe at all.
    assert_eq!(classify_rustc_probe(&args(&["gcc", "-vV"])), None);
}

#[test]
fn t034_probe_dispatch_is_absolutely_bounded_and_never_remote() {
    // The cap is a PINNED constant: it cannot silently grow.
    assert_eq!(MAX_ADDED_PROBE_LATENCY_MS, 50);

    let version = classify_rustc_probe(&args(&["rustc", "-vV"])).unwrap();

    // No toolchain identity => passthrough ONLY. A probe cache keyed
    // without compiler identity would serve answers from the WRONG
    // rustc — refused by construction.
    assert_eq!(decide(&version, None), ProbePath::LocalPassthrough);

    // With identity: separately-keyed tiny cache, disjoint domain.
    let toolchain = d("rabs.toolchain-contract.v1", 1);
    match decide(&version, Some(&toolchain)) {
        ProbePath::TinyCache { key } => {
            assert_eq!(key.domain, "rabs.tiny-probe.v1");
            assert_ne!(key, toolchain);
        }
        other => panic!("expected tiny-cache path, got {other:?}"),
    }
}

#[test]
fn t034_tiny_cache_keys_discriminate_shape_target_and_toolchain() {
    let toolchain_a = d("rabs.toolchain-contract.v1", 1);
    let toolchain_b = d("rabs.toolchain-contract.v1", 2);

    let version = classify_rustc_probe(&args(&["rustc", "-vV"])).unwrap();
    let sysroot = classify_rustc_probe(&args(&["rustc", "--print", "sysroot"])).unwrap();
    let targeted = classify_rustc_probe(&args(&["rustc", "--target=x86_64-macos", "-vV"])).unwrap();

    // Shape discriminates…
    assert_ne!(
        tiny_probe_key(&version, &toolchain_a),
        tiny_probe_key(&sysroot, &toolchain_a)
    );
    // …target presence discriminates…
    assert_ne!(
        tiny_probe_key(&version, &toolchain_a),
        tiny_probe_key(&targeted, &toolchain_a)
    );
    // …toolchain identity discriminates…
    assert_ne!(
        tiny_probe_key(&version, &toolchain_a),
        tiny_probe_key(&version, &toolchain_b)
    );
    // …and identical inputs are deterministic.
    assert_eq!(
        tiny_probe_key(&version, &toolchain_a),
        tiny_probe_key(&version, &toolchain_a)
    );
}

#[test]
fn t034_probe_serving_requires_byte_exact_identity_not_similarity() {
    let captured = TinyProbeRecord {
        exit_code: 0,
        stdout: b"rustc 1.100.0-nightly\nbinary: rustc\n".to_vec(),
        stderr: b"warning: nightly feature\n".to_vec(),
    };

    // Byte-identical live capture: serving allowed.
    assert!(captured.serves_exactly(&captured.clone()));

    // A TRAILING NEWLINE difference is a different answer.
    let mut trailing = captured.clone();
    trailing.stdout.push(b'\n');
    assert!(!captured.serves_exactly(&trailing));

    // A stderr warning appearing/disappearing is a different answer.
    let mut silent = captured.clone();
    silent.stderr.clear();
    assert!(!captured.serves_exactly(&silent));

    // An exit-code drift is a different answer.
    let mut failing = captured.clone();
    failing.exit_code = 1;
    assert!(!captured.serves_exactly(&failing));
}
