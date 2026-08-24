//! Zero-divergence gate + cacheability report for build-script runs
//! (bead N008; plan M11 acceptance; composes the N006 volatility scan
//! ([`rabs_protocol::generator_detection`]), the N005 policy split
//! ([`rabs_protocol::build_script_policy`]), and the N007 re-execution
//! audit ([`crate::build_script_reexec_audit`])).
//!
//! M11's acceptance in executable form:
//!
//! - **Zero-divergence gate**: over an observed corpus of build
//!   scripts, the gate PASSES only when no observed script diverged
//!   under sampled re-execution AND none sits in the content-addressed
//!   quarantine. A quarantined script fails the gate even if a later
//!   sample happens to agree: history is evidence, and the denylist
//!   exists precisely because a script that lied once cannot be
//!   trusted on say-so.
//! - **Cacheability report**: what fraction of the observed corpus is
//!   SAFELY cacheable — audited deterministic AND admitted by policy
//!   AND not quarantined. UNAUDITED SCRIPTS ARE NEVER COUNTED
//!   CACHEABLE (volatility preferred over optimistic caching); they
//!   are reported separately so the denominator is honest. The report
//!   names the target fraction (strictly above 80% by default) and
//!   whether the corpus met it.
//!
//! Determinism: entries are ordered by script digest bytes, counts are
//! derived from those entries, and the cacheable fraction is an exact
//! integer (parts per million) — two runs over the same observations
//! in any order produce byte-identical reports. Pure policy over
//! captured facts; running scripts lives elsewhere.
//!
//! # Dependency rules
//!
//! Same as the crate: no Tokio, no Asupersync.

use crate::build_script_reexec_audit::{AuditVerdict, Denylist, Divergence};
use rabs_protocol::build_script_policy::{
    DependencyOrigin, PolicyRefusal, ProjectPolicyFlags, route_build_script_policy,
};
use rabs_protocol::generator_detection::{Volatility, classify_volatility, detect_generators};
use rabs_protocol::result_identity::TypedDigest;

/// One observed build script with everything the gate/report needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptObservation {
    /// Content-identity digest of the script source (a move cannot
    /// launder anything keyed on this).
    pub script_digest: TypedDigest,
    /// Where the script's package came from; drives the N005 posture.
    pub origin: DependencyOrigin,
    /// The N006 volatility classification ([`observe`] computes it
    /// from raw source; callers holding a capture-time scan may pass
    /// it directly).
    pub volatility: Volatility,
    /// The project's caching allow-flags.
    pub policy_flags: ProjectPolicyFlags,
    /// The sampled re-execution verdict, when one has run. `None`
    /// marks the script UNAUDITED.
    pub audit: Option<AuditVerdict>,
}

/// Convenience: observe a script from raw source bytes — runs the
/// full N006 scan + classification in one call.
#[must_use]
pub fn observe(
    script_digest: TypedDigest,
    origin: DependencyOrigin,
    source: &[u8],
    policy_flags: ProjectPolicyFlags,
    audit: Option<AuditVerdict>,
) -> ScriptObservation {
    let volatility = classify_volatility(&detect_generators(source));
    ScriptObservation {
        script_digest,
        origin,
        volatility,
        policy_flags,
        audit,
    }
}

/// Why a script is or is not safely cacheable.
///
/// Precedence order (first match wins):
/// `Quarantined` > `Divergent` > `Unaudited` > `PolicyBlocked` >
/// `Cacheable`. Quarantine dominates because the denylist is
/// content-addressed history that no later clean sample can launder;
/// divergence dominates unaudited because an OBSERVED lie is stronger
/// evidence than an absent check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cacheability {
    /// Audited deterministic, admitted by policy, not quarantined.
    Cacheable,
    /// No sampled re-execution verdict exists yet. Never counted
    /// cacheable — optimism is not evidence.
    Unaudited,
    /// A sampled re-execution diverged. Serving is already denied by
    /// the N007 wiring; this row keeps the report honest about why.
    Divergent,
    /// Listed in the shared-cache denylist. Fails the gate even if a
    /// later audit agrees — history is evidence.
    Quarantined,
    /// Audited deterministic but N005 policy refuses caching (an
    /// uncovered volatility flag). The refusals name the flags.
    PolicyBlocked,
}

impl Cacheability {
    /// Whether this classification permits serving from cache.
    #[must_use]
    pub const fn serving_allowed(&self) -> bool {
        matches!(self, Self::Cacheable)
    }

    /// Stable wire tag for metrics/aggregation.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Cacheable => "cacheable",
            Self::Unaudited => "unaudited",
            Self::Divergent => "divergent",
            Self::Quarantined => "quarantined",
            Self::PolicyBlocked => "policy-blocked",
        }
    }
}

/// Per-script row of the gate/report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptEntry {
    /// Content-identity digest of the script.
    pub script_digest: TypedDigest,
    /// Where the script's package came from.
    pub origin: DependencyOrigin,
    /// The classification this entry earned.
    pub cacheability: Cacheability,
    /// Actionable N005 refusals (present for `PolicyBlocked` rows;
    /// empty otherwise).
    pub refusals: Vec<PolicyRefusal>,
    /// Verbatim divergence evidence (`Divergent` rows carry the
    /// verdict's divergences; `Quarantined` rows carry the retained
    /// denylist evidence when available).
    pub divergences: Vec<Divergence>,
}

/// The zero-divergence gate verdict over one observed corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateVerdict {
    /// True only when NO observed script is `Divergent` or
    /// `Quarantined`. An empty corpus passes vacuously — there is
    /// nothing observed to have diverged — and [`GateVerdict::audited_count`]
    /// makes that honesty visible to the caller.
    pub passed: bool,
    /// How many observed scripts carried an audit verdict.
    pub audited_count: usize,
    /// The failing rows (`Divergent`/`Quarantined`), digest-ordered,
    /// with evidence retained verbatim.
    pub failing: Vec<ScriptEntry>,
}

impl GateVerdict {
    /// Whether every audited lens agreed across the whole corpus.
    #[must_use]
    pub const fn zero_divergence(&self) -> bool {
        self.passed
    }
}

/// The M11 cacheability report over one observed corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheabilityReport {
    /// Every observed script, digest-ordered.
    pub entries: Vec<ScriptEntry>,
    /// Total observed scripts (denominator of the fraction).
    pub total_observed: usize,
    /// Rows classified [`Cacheability::Cacheable`] (numerator).
    pub cacheable: usize,
    /// Rows classified [`Cacheability::Divergent`].
    pub divergent: usize,
    /// Rows classified [`Cacheability::Quarantined`].
    pub quarantined: usize,
    /// Rows classified [`Cacheability::Unaudited`].
    pub unaudited: usize,
    /// Rows classified [`Cacheability::PolicyBlocked`].
    pub policy_blocked: usize,
    /// Audited scripts count (corpus coverage visibility).
    pub audited: usize,
    /// Exact cacheable fraction in parts per million
    /// (`cacheable * 1_000_000 / total_observed`; 0 when the corpus
    /// is empty).
    pub cacheable_fraction_ppm: u64,
    /// The target threshold in percent (bead default 80).
    pub target_percent: u8,
    /// Whether the fraction is STRICTLY above the target
    /// (`> 80%`, as the bead states). An empty corpus never meets
    /// the target: 0/0 is undefined, not success.
    pub target_met: bool,
}

/// Classify one observation against the denylist and its own facts.
///
/// Laws, in evaluation order:
/// 1. Quarantine dominates — a denylisted digest is never cacheable,
///    whatever a later sample says;
/// 2. An observed divergence is next — the N007 wiring will have
///    quarantined it, but the classification stands on its own;
/// 3. Unaudited scripts are never cacheable;
/// 4. Audited-deterministic scripts still need N005 admission
///    (flags cover every detected volatility reason);
/// 5. Everything else is safely cacheable.
#[must_use]
fn classify_one(observation: &ScriptObservation, denylist: &Denylist) -> ScriptEntry {
    let mut entry = ScriptEntry {
        script_digest: observation.script_digest.clone(),
        origin: observation.origin,
        cacheability: Cacheability::Cacheable,
        refusals: Vec::new(),
        divergences: Vec::new(),
    };

    if denylist.is_quarantined(&observation.script_digest) {
        entry.cacheability = Cacheability::Quarantined;
        if let Some(evidence) = denylist.evidence_for(&observation.script_digest) {
            entry.divergences = evidence.to_vec();
        }
        return entry;
    }

    match &observation.audit {
        Some(AuditVerdict::Diverged { divergences }) => {
            entry.cacheability = Cacheability::Divergent;
            entry.divergences = divergences.clone();
            entry
        }
        None => {
            entry.cacheability = Cacheability::Unaudited;
            entry
        }
        Some(AuditVerdict::Deterministic) => {
            let routing = route_build_script_policy(
                observation.origin,
                &observation.volatility,
                &observation.policy_flags,
                // The determinism audit IS complete for this script —
                // the caller supplied its passing verdict.
                true,
            );
            if routing.allowed {
                entry
            } else {
                entry.cacheability = Cacheability::PolicyBlocked;
                entry.refusals = routing.refusals;
                entry
            }
        }
    }
}

/// Digest-ordered view of the corpus: the stable skeleton both the
/// gate and the report are built on.
#[must_use]
fn classified_corpus(observed: &[ScriptObservation], denylist: &Denylist) -> Vec<ScriptEntry> {
    let mut entries: Vec<ScriptEntry> =
        observed.iter().map(|o| classify_one(o, denylist)).collect();
    entries.sort_by(|a, b| {
        (a.script_digest.domain, a.script_digest.bytes.as_slice())
            .cmp(&(b.script_digest.domain, b.script_digest.bytes.as_slice()))
    });
    entries
}

/// Run the zero-divergence gate over an observed corpus.
///
/// Passes only when no observed script is `Divergent` or
/// `Quarantined`. Failing rows keep their divergence evidence
/// verbatim so the operator sees WHAT lied without re-running
/// anything. An empty corpus passes vacuously (`audited_count == 0`
/// makes that visible); the gate judges DIVERGENCE ONLY — unaudited
/// volume is the report's job, not the gate's.
#[must_use]
pub fn zero_divergence_gate(observed: &[ScriptObservation], denylist: &Denylist) -> GateVerdict {
    let entries = classified_corpus(observed, denylist);
    let failing: Vec<ScriptEntry> = entries
        .iter()
        .filter(|e| {
            matches!(
                e.cacheability,
                Cacheability::Divergent | Cacheability::Quarantined
            )
        })
        .cloned()
        .collect();
    let audited_count = observed.iter().filter(|o| o.audit.is_some()).count();
    GateVerdict {
        passed: failing.is_empty(),
        audited_count,
        failing,
    }
}

/// Build the M11 cacheability report.
///
/// The fraction is exact integer arithmetic (parts per million); the
/// target is STRICTLY exceeded or it is not met — exactly 80.0% does
/// not pass an ">80%" bar. Empty corpora report all zeros with
/// `target_met == false`.
#[must_use]
pub fn build_cacheability_report(
    observed: &[ScriptObservation],
    denylist: &Denylist,
    target_percent: u8,
) -> CacheabilityReport {
    let entries = classified_corpus(observed, denylist);
    let total_observed = entries.len();
    let mut cacheable = 0usize;
    let mut divergent = 0usize;
    let mut quarantined = 0usize;
    let mut unaudited = 0usize;
    let mut policy_blocked = 0usize;
    for e in &entries {
        match e.cacheability {
            Cacheability::Cacheable => cacheable += 1,
            Cacheability::Divergent => divergent += 1,
            Cacheability::Quarantined => quarantined += 1,
            Cacheability::Unaudited => unaudited += 1,
            Cacheability::PolicyBlocked => policy_blocked += 1,
        }
    }
    let audited = total_observed - unaudited;
    let cacheable_fraction_ppm = if total_observed == 0 {
        0
    } else {
        (cacheable as u64 * 1_000_000) / total_observed as u64
    };
    let target_met =
        total_observed > 0 && cacheable_fraction_ppm > u64::from(target_percent) * 10_000;
    CacheabilityReport {
        entries,
        total_observed,
        cacheable,
        divergent,
        quarantined,
        unaudited,
        policy_blocked,
        audited,
        cacheable_fraction_ppm,
        target_percent,
        target_met,
    }
}

// ---------------------------------------------------------------------
// Tests — N008 acceptance: zero-divergence gate + automated
// cacheability report with the >80% target.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_script_directives::capture_stdout;

    fn id(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
            domain: crate::build_script_reexec_audit::DOMAIN_BUILD_SCRIPT_DENYLIST,
            bytes: [tag; 32],
        }
    }

    fn clean_source() -> Vec<u8> {
        b"fn main() { println!(\"pure build\"); }".to_vec()
    }

    fn clock_source() -> Vec<u8> {
        b"use chrono::Utc;\nlet t = chrono::Utc::now();\n".to_vec()
    }

    fn deterministic(tag: u8, source: &[u8]) -> ScriptObservation {
        observe(
            id(tag),
            DependencyOrigin::WorkspaceMember,
            source,
            ProjectPolicyFlags::default(),
            Some(AuditVerdict::Deterministic),
        )
    }

    fn divergent_verdict() -> AuditVerdict {
        let cached = capture_stdout("cargo:rerun-if-changed=a.txt\n");
        let rerun = capture_stdout("cargo:rerun-if-changed=b.txt\n");
        crate::build_script_reexec_audit::judge(&cached, &rerun, 0, 0)
    }

    #[test]
    fn fully_deterministic_admitted_corpus_passes_gate_and_hits_target() {
        let corpus = vec![
            deterministic(1, &clean_source()),
            deterministic(2, &clean_source()),
            deterministic(3, &clean_source()),
        ];
        let dl = Denylist::new();

        let gate = zero_divergence_gate(&corpus, &dl);
        assert!(gate.zero_divergence());
        assert!(gate.passed);
        assert_eq!(gate.failing, vec![]);
        assert_eq!(gate.audited_count, 3);

        let report = build_cacheability_report(&corpus, &dl, 80);
        assert_eq!(report.total_observed, 3);
        assert_eq!(report.cacheable, 3);
        assert_eq!(report.audited, 3);
        assert_eq!(report.cacheable_fraction_ppm, 1_000_000);
        assert!(report.target_met);
        assert!(
            report
                .entries
                .iter()
                .all(|e| e.cacheability.serving_allowed())
        );
    }

    #[test]
    fn single_divergence_fails_gate_with_verbatim_evidence() {
        let mut bad = deterministic(9, &clean_source());
        bad.audit = Some(divergent_verdict());
        let corpus = vec![
            deterministic(1, &clean_source()),
            bad,
            deterministic(3, &clean_source()),
        ];
        let dl = Denylist::new();

        let gate = zero_divergence_gate(&corpus, &dl);
        assert!(!gate.passed);
        assert_eq!(gate.failing.len(), 1);
        assert_eq!(gate.failing[0].script_digest, id(9));
        assert!(
            gate.failing[0]
                .divergences
                .iter()
                .any(|d| d.tag() == "directive-drift")
        );

        let report = build_cacheability_report(&corpus, &dl, 80);
        assert_eq!(report.divergent, 1);
        assert_eq!(report.cacheable, 2);
        // 2/3 = 666_666 ppm — far below the bar, honestly unmet.
        assert_eq!(report.cacheable_fraction_ppm, 666_666);
        assert!(!report.target_met);
    }

    #[test]
    fn quarantined_script_fails_gate_even_when_a_later_sample_agrees() {
        let mut dl = Denylist::new();
        let evidence = vec![Divergence::ExitCodeDrift {
            cached_exit: 0,
            rerun_exit: 101,
        }];
        assert!(dl.quarantine(id(5), evidence));

        // The CURRENT audit is clean — history still governs.
        let corpus = vec![deterministic(5, &clean_source())];
        let gate = zero_divergence_gate(&corpus, &dl);
        assert!(!gate.passed);
        assert_eq!(gate.failing.len(), 1);
        assert_eq!(gate.failing[0].cacheability, Cacheability::Quarantined);
        // Retained denylist evidence travels with the row verbatim.
        assert_eq!(gate.failing[0].divergences.len(), 1);

        let report = build_cacheability_report(&corpus, &dl, 80);
        assert_eq!(report.quarantined, 1);
        assert_eq!(report.cacheable, 0);
        assert!(!report.target_met);
    }

    #[test]
    fn unaudited_scripts_are_never_cacheable_but_do_not_fail_the_gate() {
        let corpus = vec![
            deterministic(1, &clean_source()),
            observe(
                id(2),
                DependencyOrigin::RegistryOrGit,
                &clean_source(),
                ProjectPolicyFlags::default(),
                None,
            ),
            observe(
                id(3),
                DependencyOrigin::WorkspaceMember,
                &clock_source(),
                ProjectPolicyFlags::default(),
                None,
            ),
        ];
        let dl = Denylist::new();

        // Zero divergence means ZERO OBSERVED divergence; unaudited is
        // a coverage gap, not a divergence. The report exposes the
        // gap instead of letting it masquerade as safety.
        let gate = zero_divergence_gate(&corpus, &dl);
        assert!(gate.passed);
        assert_eq!(gate.audited_count, 1);

        let report = build_cacheability_report(&corpus, &dl, 80);
        assert_eq!(report.unaudited, 2);
        assert_eq!(report.audited, 1);
        assert_eq!(report.cacheable, 1);
        assert!(!report.target_met);
    }

    #[test]
    fn audited_deterministic_scripts_still_need_flag_coverage() {
        // A workspace clock-using script, cleanly audited, with the
        // clock flag ON: policy admits it and it is cacheable.
        let flags = ProjectPolicyFlags {
            clock: true,
            ..ProjectPolicyFlags::default()
        };
        let ok = observe(
            id(4),
            DependencyOrigin::WorkspaceMember,
            &clock_source(),
            flags,
            Some(AuditVerdict::Deterministic),
        );
        // Same script with the flag OFF: audited deterministic yet
        // policy-blocked, counted separately, refusal names the flag.
        let blocked = observe(
            id(6),
            DependencyOrigin::WorkspaceMember,
            &clock_source(),
            ProjectPolicyFlags::default(),
            Some(AuditVerdict::Deterministic),
        );
        let corpus = vec![ok, blocked];
        let dl = Denylist::new();

        let gate = zero_divergence_gate(&corpus, &dl);
        assert!(gate.passed);

        let report = build_cacheability_report(&corpus, &dl, 80);
        assert_eq!(report.policy_blocked, 1);
        assert_eq!(report.cacheable, 1);
        let blocked_entry = report
            .entries
            .iter()
            .find(|e| e.script_digest == id(6))
            .expect("entry present");
        assert_eq!(blocked_entry.cacheability, Cacheability::PolicyBlocked);
        assert!(
            blocked_entry
                .refusals
                .iter()
                .any(|r| r.required_flag == "clock")
        );
        assert!(!blocked_entry.cacheability.serving_allowed());
    }

    #[test]
    fn report_is_order_insensitive_and_fraction_math_is_exact() {
        let corpus_a = vec![
            deterministic(1, &clean_source()),
            deterministic(2, &clean_source()),
            deterministic(3, &clean_source()),
            deterministic(4, &clean_source()),
            {
                let mut bad = deterministic(7, &clean_source());
                bad.audit = Some(divergent_verdict());
                bad
            },
        ];
        let mut corpus_b = corpus_a.clone();
        corpus_b.reverse();
        let dl = Denylist::new();

        let ra = build_cacheability_report(&corpus_a, &dl, 80);
        let rb = build_cacheability_report(&corpus_b, &dl, 80);
        assert_eq!(ra, rb, "order must not change the report");

        // 4/5 = exactly 800_000 ppm; ">80%" is STRICT, so 80.0% misses.
        assert_eq!(ra.cacheable_fraction_ppm, 800_000);
        assert!(!ra.target_met);

        // One more clean script: 5/6 ≈ 833_333 ppm clears the bar.
        let corpus_c = {
            let mut c = corpus_a.clone();
            c.push(deterministic(8, &clean_source()));
            c
        };
        let rc = build_cacheability_report(&corpus_c, &dl, 80);
        assert_eq!(rc.cacheable_fraction_ppm, 833_333);
        assert!(rc.target_met);
    }

    #[test]
    fn empty_corpus_passes_gate_vacuously_and_never_meets_target() {
        let corpus: Vec<ScriptObservation> = vec![];
        let dl = Denylist::new();

        let gate = zero_divergence_gate(&corpus, &dl);
        assert!(gate.passed);
        assert_eq!(gate.audited_count, 0);

        let report = build_cacheability_report(&corpus, &dl, 80);
        assert_eq!(report.total_observed, 0);
        assert_eq!(report.cacheable_fraction_ppm, 0);
        assert!(!report.target_met, "0/0 is undefined, not success");
    }

    #[test]
    fn observe_runs_the_full_n006_scan_into_the_classification() {
        let o = observe(
            id(11),
            DependencyOrigin::RegistryOrGit,
            b"println!(\"vergen::build_date\");\n",
            ProjectPolicyFlags::default(),
            None,
        );
        assert!(matches!(o.volatility,
            Volatility::Volatile { reasons }
                if reasons.contains(&"volatile-generator-vergen")
        ));
    }
}
