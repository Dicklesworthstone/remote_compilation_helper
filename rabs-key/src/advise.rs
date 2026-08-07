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
#[derive(Debug, Clone, Default)]
pub struct AdviseInputs {
    /// (crate, rebuild tail ms, dependents) — from R011 tails.
    pub rebuild_tails: Vec<(String, u64, u32)>,
    /// (crate, distinct feature variants) — from Q011/F018.
    pub feature_variants: Vec<(String, u32)>,
    /// (proc-macro crate, downstream rebuilds it caused).
    pub proc_macro_rebuilds: Vec<(String, u64)>,
    /// (dependency, distinct versions in the graph).
    pub version_spread: Vec<(String, u32)>,
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
    for (name, variants) in &inputs.feature_variants {
        if *variants >= FEATURE_VARIANT_THRESHOLD {
            advice.push(Advice {
                kind: AdviceKind::ReduceFeatureCoupling,
                subject: name.clone(),
                evidence: vec![format!(
                    "`{name}` compiled under {variants} distinct feature sets in the window"
                )],
                expected_saved_ms: u64::from(variants - 1) * 1_000,
                confidence_permille: 700,
                non_claims: ESTIMATE_NON_CLAIMS.to_vec(),
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
    for (name, versions) in &inputs.version_spread {
        if *versions >= VERSION_SPREAD_THRESHOLD {
            advice.push(Advice {
                kind: AdviceKind::AlignVersions,
                subject: name.clone(),
                evidence: vec![format!(
                    "`{name}` appears at {versions} distinct versions in the dependency graph"
                )],
                expected_saved_ms: u64::from(versions - 1) * 2_000,
                confidence_permille: 800,
                non_claims: ESTIMATE_NON_CLAIMS.to_vec(),
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
            feature_variants: vec![("common".into(), 5)],
            proc_macro_rebuilds: vec![("derive-everything".into(), 240)],
            version_spread: vec![("syn".into(), 3), ("serde".into(), 1)],
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
