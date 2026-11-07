//! `rch advise` evidence reports (bead Q012; plan §104).
//!
//! Crate-architecture recommendations with ATTRIBUTABLE evidence:
//! every advice names the measured facts it rests on, an expected
//! saved latency, a confidence (permille), and explicit NON-CLAIMS.
//! The engine NEVER mutates source or config — the advice type has
//! only descriptive fields (no action/patch/apply arm exists), and
//! the module exposes no write API. Below-threshold inputs produce
//! no advice: the engine prices problems, it does not scold.

/// The recommendation kinds (closed registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AdviceKind {
    SplitRebuildTailCrate,
    ReduceFeatureCoupling,
    IsolateProcMacro,
    AlignVersions,
    LinkBottleneck,
    DominatingTests,
}

/// One recommendation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advice {
    /// What to consider doing.
    pub kind: AdviceKind,
    /// The subject (crate/bin/suite/dependency name).
    pub subject: String,
    /// Attributable evidence lines (measured facts, with numbers).
    pub evidence: Vec<String>,
    /// Expected saved latency per affected build (ms).
    pub expected_saved_ms: u64,
    /// Confidence (permille).
    pub confidence_permille: u32,
    /// What this advice does NOT claim.
    pub non_claims: Vec<&'static str>,
}

/// The measured inputs (from the DAG, Q011, and telemetry).
///
/// A `measured_ms` slot carries compiler wall time attributed from a build
/// timing report. When present it replaces the per-kind estimate and the
/// advice cites it; when absent the advice keeps the estimate and says so.
#[derive(Debug, Clone, Default)]
pub struct AdviseInputs {
    /// (crate, rebuild tail ms, dependents) — from R011 tails.
    pub rebuild_tails: Vec<(String, u64, u32)>,
    /// (crate, distinct feature variants, measured ms of every variant but
    /// the most expensive) — from Q011/F018 or build timings.
    pub feature_variants: Vec<(String, u32, Option<u64>)>,
    /// (proc-macro crate, downstream rebuilds it caused).
    pub proc_macro_rebuilds: Vec<(String, u64)>,
    /// (dependency, distinct versions in the graph, measured ms of every
    /// version but the newest).
    pub version_spread: Vec<(String, u32, Option<u64>)>,
    /// (binary, link ms).
    pub link_ms: Vec<(String, u64)>,
    /// (suite, permille of total wall time).
    pub test_dominance: Vec<(String, u32)>,
}

/// Thresholds (below = no advice).
pub const TAIL_THRESHOLD_MS: u64 = 5_000;
/// Feature variants above this fragment the cache.
pub const FEATURE_VARIANT_THRESHOLD: u32 = 3;
/// Proc-macro rebuild count worth isolating.
pub const PROC_MACRO_REBUILD_THRESHOLD: u64 = 50;
/// Version spread worth aligning.
pub const VERSION_SPREAD_THRESHOLD: u32 = 2;
/// Link time worth attacking.
pub const LINK_THRESHOLD_MS: u64 = 10_000;
/// Suite share of wall time worth splitting.
pub const TEST_DOMINANCE_THRESHOLD_PERMILLE: u32 = 400;

const ESTIMATE_NON_CLAIMS: [&str; 2] = [
    "NO_CLAIM_EXACT_SAVINGS (estimate assumes the window's edit distribution)",
    "NO_CLAIM_AUTOMATIC_CHANGE (rch never edits source or config)",
];

const MEASURED_NON_CLAIMS: [&str; 2] = [
    "NO_CLAIM_INCREMENTAL_SAVINGS (measured compiler time of duplicate compiles in the timed builds; a warm incremental build may not repeat them)",
    "NO_CLAIM_AUTOMATIC_CHANGE (rch never edits source or config)",
];

/// Measured duplicate compile time replaces the estimate; the evidence then
/// names the measurement so a reader can tell the two apart.
fn priced(
    evidence: String,
    estimate_ms: u64,
    measured_ms: Option<u64>,
    estimate_confidence: u32,
) -> (Vec<String>, u64, u32, Vec<&'static str>) {
    match measured_ms {
        Some(ms) => (
            vec![
                evidence,
                format!("measured: the duplicate compiles took {ms}ms of compiler time"),
            ],
            ms,
            900,
            MEASURED_NON_CLAIMS.to_vec(),
        ),
        None => (
            vec![evidence],
            estimate_ms,
            estimate_confidence,
            ESTIMATE_NON_CLAIMS.to_vec(),
        ),
    }
}

/// Produce the advice report, sorted by expected saving.
#[must_use]
pub fn advise(inputs: &AdviseInputs) -> Vec<Advice> {
    let mut advice = Vec::new();
    for (name, tail_ms, dependents) in &inputs.rebuild_tails {
        if *tail_ms >= TAIL_THRESHOLD_MS {
            advice.push(Advice {
                kind: AdviceKind::SplitRebuildTailCrate,
                subject: name.clone(),
                evidence: vec![format!(
                    "editing `{name}` drags a {tail_ms}ms rebuild tail across {dependents} dependents"
                )],
                expected_saved_ms: tail_ms / 2, // split halves the tail
                confidence_permille: 600,
                non_claims: ESTIMATE_NON_CLAIMS.to_vec(),
            });
        }
    }
    for (name, variants, measured_ms) in &inputs.feature_variants {
        if *variants >= FEATURE_VARIANT_THRESHOLD {
            let (evidence, expected_saved_ms, confidence_permille, non_claims) = priced(
                format!("`{name}` compiled under {variants} distinct feature sets in the window"),
                u64::from(variants - 1) * 1_000,
                *measured_ms,
                700,
            );
            advice.push(Advice {
                kind: AdviceKind::ReduceFeatureCoupling,
                subject: name.clone(),
                evidence,
                expected_saved_ms,
                confidence_permille,
                non_claims,
            });
        }
    }
    for (name, rebuilds) in &inputs.proc_macro_rebuilds {
        if *rebuilds >= PROC_MACRO_REBUILD_THRESHOLD {
            advice.push(Advice {
                kind: AdviceKind::IsolateProcMacro,
                subject: name.clone(),
                evidence: vec![format!(
                    "proc-macro `{name}` caused {rebuilds} downstream rebuilds in the window"
                )],
                expected_saved_ms: rebuilds * 100,
                confidence_permille: 500,
                non_claims: ESTIMATE_NON_CLAIMS.to_vec(),
            });
        }
    }
    for (name, versions, measured_ms) in &inputs.version_spread {
        if *versions >= VERSION_SPREAD_THRESHOLD {
            let (evidence, expected_saved_ms, confidence_permille, non_claims) = priced(
                format!("`{name}` appears at {versions} distinct versions in the dependency graph"),
                u64::from(versions - 1) * 2_000,
                *measured_ms,
                800,
            );
            advice.push(Advice {
                kind: AdviceKind::AlignVersions,
                subject: name.clone(),
                evidence,
                expected_saved_ms,
                confidence_permille,
                non_claims,
            });
        }
    }
    for (name, ms) in &inputs.link_ms {
        if *ms >= LINK_THRESHOLD_MS {
            advice.push(Advice {
                kind: AdviceKind::LinkBottleneck,
                subject: name.clone(),
                evidence: vec![format!("linking `{name}` takes {ms}ms per build")],
                expected_saved_ms: ms / 2,
                confidence_permille: 650,
                non_claims: ESTIMATE_NON_CLAIMS.to_vec(),
            });
        }
    }
    for (name, permille) in &inputs.test_dominance {
        if *permille >= TEST_DOMINANCE_THRESHOLD_PERMILLE {
            advice.push(Advice {
                kind: AdviceKind::DominatingTests,
                subject: name.clone(),
                evidence: vec![format!(
                    "suite `{name}` consumes {permille} permille of total test wall time"
                )],
                expected_saved_ms: u64::from(*permille) * 10,
                confidence_permille: 550,
                non_claims: ESTIMATE_NON_CLAIMS.to_vec(),
            });
        }
    }
    advice.sort_by(|a, b| {
        b.expected_saved_ms
            .cmp(&a.expected_saved_ms)
            .then_with(|| a.subject.cmp(&b.subject))
    });
    advice
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_repo() -> AdviseInputs {
        AdviseInputs {
            rebuild_tails: vec![("core-types".into(), 42_000, 31), ("leaf".into(), 900, 1)],
            feature_variants: vec![("common".into(), 5, None)],
            proc_macro_rebuilds: vec![("derive-everything".into(), 240)],
            version_spread: vec![("syn".into(), 3, None), ("serde".into(), 1, None)],
            link_ms: vec![("bin/rch".into(), 18_000)],
            test_dominance: vec![("daemon_lifecycle".into(), 620)],
        }
    }

    #[test]
    fn the_fixture_repo_yields_attributable_evidence() {
        // THE acceptance: every advice's evidence carries the
        // measured numbers and names it rests on.
        let report = advise(&fixture_repo());
        assert_eq!(report.len(), 6);
        let tail = report
            .iter()
            .find(|a| a.kind == AdviceKind::SplitRebuildTailCrate)
            .expect("tail advice");
        assert_eq!(tail.subject, "core-types");
        assert!(tail.evidence[0].contains("42000ms"));
        assert!(tail.evidence[0].contains("31 dependents"));
        let features = report
            .iter()
            .find(|a| a.kind == AdviceKind::ReduceFeatureCoupling)
            .expect("feature advice");
        assert!(features.evidence[0].contains("5 distinct feature sets"));
        let versions = report
            .iter()
            .find(|a| a.kind == AdviceKind::AlignVersions)
            .expect("version advice");
        assert_eq!(versions.subject, "syn");
        // Sorted by expected saving: the proc-macro isolation (240
        // rebuilds x 100ms = 24s) outranks the tail split (21s).
        assert_eq!(report[0].kind, AdviceKind::IsolateProcMacro);
        assert_eq!(report[0].expected_saved_ms, 24_000);
        assert_eq!(report[1].kind, AdviceKind::SplitRebuildTailCrate);
        assert_eq!(report[1].expected_saved_ms, 21_000);
    }

    #[test]
    fn measured_compiler_time_replaces_the_estimate_and_is_cited() {
        let inputs = AdviseInputs {
            version_spread: vec![("syn".into(), 2, Some(7_350))],
            feature_variants: vec![("common".into(), 3, Some(420))],
            ..AdviseInputs::default()
        };
        let report = advise(&inputs);
        let versions = report
            .iter()
            .find(|a| a.kind == AdviceKind::AlignVersions)
            .expect("version advice");
        assert_eq!(versions.expected_saved_ms, 7_350);
        assert!(versions.evidence[1].contains("7350ms of compiler time"));
        assert!(
            versions
                .non_claims
                .iter()
                .any(|nc| nc.starts_with("NO_CLAIM_INCREMENTAL_SAVINGS"))
        );
        // A measured row never also carries the estimate's disclaimer.
        assert!(
            !versions
                .non_claims
                .iter()
                .any(|nc| nc.starts_with("NO_CLAIM_EXACT_SAVINGS"))
        );
        let features = report
            .iter()
            .find(|a| a.kind == AdviceKind::ReduceFeatureCoupling)
            .expect("feature advice");
        assert_eq!(features.expected_saved_ms, 420);
        // Sorted by the measured saving, not the estimates (2000 vs 2000).
        assert_eq!(report[0].kind, AdviceKind::AlignVersions);
        // Measurement prices a problem; it never lowers the threshold.
        let quiet = AdviseInputs {
            version_spread: vec![("serde".into(), 1, Some(9_000))],
            feature_variants: vec![("common".into(), 2, Some(9_000))],
            ..AdviseInputs::default()
        };
        assert!(advise(&quiet).is_empty());
    }

    #[test]
    fn every_advice_carries_confidence_and_non_claims() {
        for advice in advise(&fixture_repo()) {
            assert!(advice.confidence_permille <= 1_000);
            assert!(advice.confidence_permille > 0);
            assert!(
                advice
                    .non_claims
                    .iter()
                    .any(|nc| nc.contains("NO_CLAIM_AUTOMATIC_CHANGE")),
                "every advice must disclaim automatic mutation"
            );
            assert!(!advice.evidence.is_empty());
        }
    }

    #[test]
    fn below_threshold_inputs_produce_no_advice() {
        // The 900ms leaf tail and single-version serde never appear;
        // a quiet repo yields an EMPTY report.
        let report = advise(&fixture_repo());
        assert!(!report.iter().any(|a| a.subject == "leaf"));
        assert!(!report.iter().any(|a| a.subject == "serde"));
        assert!(advise(&AdviseInputs::default()).is_empty());
    }

    #[test]
    fn the_engine_cannot_mutate_anything() {
        // Structural: the advice type is wholly descriptive — the
        // exhaustive destructure shows no action/patch/apply field,
        // and the module's only public function returns data.
        let report = advise(&fixture_repo());
        let Advice {
            kind: _,
            subject: _,
            evidence: _,
            expected_saved_ms: _,
            confidence_permille: _,
            non_claims: _,
        } = report[0].clone();
    }
}
