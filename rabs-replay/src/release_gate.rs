//! The stock-differential corpus RELEASE gate (bead T011; trust ladder
//! above K008's per-action sampling).
//!
//! K008 decides, per action, whether one request may be served from
//! cache, and quarantines an individual served divergence the instant
//! it appears. That is the right shape for a single action and the
//! wrong shape for a release: by the time a per-action quarantine
//! fires, the divergent result has already been served once.
//!
//! This gate asks the corpus-level question instead — across a whole
//! stock-vs-RABS differential run, is every divergence ACCOUNTED FOR? —
//! and answers it as an authorization, not a report. Following the H024
//! authority gate's discipline: a gate is a chokepoint, and the only
//! way to obtain [`PromotionAuthorized`] is to pass.
//!
//! Three properties it is built around, each of which is a way gates
//! like this usually rot:
//!
//! - **An empty corpus REFUSES.** A gate that authorizes when nothing
//!   ran is worse than no gate, because it produces the evidence of
//!   safety without the safety. Zero replayed records is a refusal, not
//!   a pass.
//! - **"Explained" is a closed, declared set.** A divergence is
//!   explained only if an operator named that exact command in the
//!   policy beforehand. There is no "explained by category" escape,
//!   because every real corpus contains a category that would swallow
//!   the interesting case.
//! - **Skips are counted against coverage.** A corpus whose records
//!   were mostly skipped as redacted or malformed did not prove much,
//!   and a gate that ignored skips would let coverage silently decay to
//!   nothing while still authorizing.
//!
//! ## How it reaches the coordinator
//!
//! The gate runs here, in a replay harness; the coordinator that serves
//! is another process that cannot depend on this crate (A002). So a
//! passing [`PromotionAuthorized`] becomes data via
//! [`PromotionAuthorized::into_verdict`]: a
//! [`ReleaseVerdict`] that `rabs-cas` persists and `rabsd` consults
//! before it serves anything. `rabs_protocol::release_authorization`
//! owns that shape and the rules for reading it, so all three sides
//! name one dependency-free crate rather than each other.
//!
//! Minting is the ONLY constructor of a verdict from a gate result,
//! which is what carries this module's unforgeability across the
//! boundary: the private fields make `PromotionAuthorized`
//! unfabricatable, and `into_verdict` consuming one is what makes the
//! durable row mean something. A hand-written row is still possible —
//! it is a database — which is why the consulting side re-checks the
//! empty-run invariant rather than trusting the row's provenance.

use crate::shadow_pipeline::ShadowPipelineReport;
use rabs_protocol::release_authorization::ReleaseVerdict;
use rabs_protocol::serving::ServingValidity;
use std::collections::BTreeSet;

/// Operator policy for one release evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleasePolicy {
    /// Commands whose divergence an operator has explicitly accounted
    /// for, named EXACTLY. There is deliberately no pattern or
    /// category form: a wildcard that matched the interesting
    /// divergence would be indistinguishable from not running the gate.
    pub explained: BTreeSet<String>,
    /// Minimum records that must actually have REPLAYED (skips do not
    /// count) for the run to constitute evidence. Zero is rejected at
    /// evaluation: a policy that accepts no coverage is not a policy.
    pub minimum_replayed: usize,
    /// The largest fraction of parsed records, in basis points, that
    /// may be skipped before coverage is judged too thin to authorize.
    pub maximum_skipped_basis_points: u32,
}

/// Authorization to promote serving. Constructible ONLY by passing the
/// gate, so a caller cannot fabricate one by filling in a struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionAuthorized {
    /// Records that actually replayed under both paths.
    replayed: usize,
    /// Divergences an operator had named in advance.
    explained: usize,
}

impl PromotionAuthorized {
    /// Records that actually replayed.
    #[must_use]
    pub const fn replayed(&self) -> usize {
        self.replayed
    }

    /// Divergences that were explained by policy.
    #[must_use]
    pub const fn explained(&self) -> usize {
        self.explained
    }

    /// Mint the durable verdict that carries this authorization across
    /// the process boundary to the coordinator.
    ///
    /// The gate runs in a replay harness — in CI, or by an operator —
    /// and the coordinator that serves is a different process, often on
    /// a different machine, which cannot call into this crate at all
    /// (`rabs-cas` must not depend on the harness; A002). So the
    /// authorization has to become data. This is the only way to build
    /// a [`ReleaseVerdict`] from a gate result, which keeps the
    /// unforgeability the private fields buy: a verdict claiming a
    /// corpus run is one a corpus run actually produced.
    ///
    /// `build` must identify the RABS binary the corpus exercised, in
    /// whatever form the coordinator will report for itself — the two
    /// are compared exactly, and a verdict that names a different build
    /// authorizes nothing. `validity` is the operator's window, carried
    /// rather than invented here, because how long a corpus run stays
    /// good is a property of the deployment and not of this gate.
    #[must_use]
    pub fn into_verdict(
        self,
        build: impl Into<String>,
        corpus: impl Into<String>,
        validity: ServingValidity,
    ) -> ReleaseVerdict {
        ReleaseVerdict {
            build: build.into(),
            corpus: corpus.into(),
            // usize -> u64 is lossless on every target RABS builds for,
            // and saturating rather than wrapping in any case: a count
            // that saturated would still be non-zero, so it could never
            // turn a real run into the `NoEvidence` standing.
            replayed: self.replayed as u64,
            explained: self.explained as u64,
            validity,
        }
    }
}

/// Why promotion was refused. Every variant names what to look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseRefusal {
    /// The policy itself would accept no evidence.
    PolicyAcceptsNoCoverage,
    /// Nothing replayed: a gate cannot authorize on an empty run.
    NothingReplayed,
    /// Fewer records replayed than the policy requires.
    InsufficientCoverage {
        /// Records that replayed.
        replayed: usize,
        /// Records the policy required.
        required: usize,
    },
    /// Too much of the corpus was skipped to call the run evidence.
    CoverageTooThin {
        /// Skipped records (redacted + malformed).
        skipped: usize,
        /// Records parsed in total (replayed + skipped).
        parsed: usize,
        /// The policy's ceiling, in basis points.
        ceiling_basis_points: u32,
    },
    /// Divergences no operator accounted for. The gate names every one,
    /// because a count alone cannot be acted on.
    UnexplainedDivergence {
        /// The offending commands, sorted.
        commands: Vec<String>,
    },
    /// A served result diverged from authoritative stock. This is never
    /// explainable by policy: it means the cache already answered with
    /// something stock disagrees with, which is the soundness incident
    /// the whole ladder exists to prevent.
    ServedDivergence {
        /// The commands that were served and diverged.
        commands: Vec<String>,
    },
}

/// Evaluate a corpus run against an operator policy.
///
/// # Errors
/// [`ReleaseRefusal`] naming exactly what refused. A refusal is the
/// normal outcome of an unproven build, not an exceptional one.
pub fn evaluate_release_gate(
    report: &ShadowPipelineReport,
    policy: &ReleasePolicy,
) -> Result<PromotionAuthorized, ReleaseRefusal> {
    if policy.minimum_replayed == 0 {
        // Checked before anything else: a policy that requires no
        // coverage would authorize an empty run through the front door,
        // which is the failure this gate exists to make impossible.
        return Err(ReleaseRefusal::PolicyAcceptsNoCoverage);
    }

    let replayed = report.session.rows.len();
    if replayed == 0 {
        return Err(ReleaseRefusal::NothingReplayed);
    }
    if replayed < policy.minimum_replayed {
        return Err(ReleaseRefusal::InsufficientCoverage {
            replayed,
            required: policy.minimum_replayed,
        });
    }

    let skipped = report.session.skipped_redacted + report.session.skipped_malformed;
    let parsed = replayed + skipped;
    // Basis points against everything the corpus offered, so a corpus
    // that degraded into mostly-unparseable records cannot pass by
    // replaying the handful that still work.
    let skipped_basis_points = (skipped * 10_000) / parsed.max(1);
    if skipped_basis_points > policy.maximum_skipped_basis_points as usize {
        return Err(ReleaseRefusal::CoverageTooThin {
            skipped,
            parsed,
            ceiling_basis_points: policy.maximum_skipped_basis_points,
        });
    }

    // A SERVED divergence is checked before the explained set is
    // consulted, because it is not explainable: the cache already
    // answered with something stock disagrees with.
    if !report.quarantine_required.is_empty() {
        let mut commands = report.quarantine_required.clone();
        commands.sort();
        commands.dedup();
        return Err(ReleaseRefusal::ServedDivergence { commands });
    }

    let mut unexplained: Vec<String> = report
        .session
        .rows
        .iter()
        .filter(|row| row.diverged())
        .map(|row| row.command.clone())
        .filter(|command| !policy.explained.contains(command))
        .collect();
    unexplained.sort();
    unexplained.dedup();
    if !unexplained.is_empty() {
        return Err(ReleaseRefusal::UnexplainedDivergence {
            commands: unexplained,
        });
    }

    let explained = report
        .session
        .rows
        .iter()
        .filter(|row| row.diverged())
        .count();
    Ok(PromotionAuthorized {
        replayed,
        explained,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Availability, DivergenceRecord, SessionReport};

    fn row(command: &str, diverged: bool, served: bool) -> DivergenceRecord {
        DivergenceRecord {
            command: command.to_owned(),
            baseline_path: "stock".to_owned(),
            candidate_path: "rabs".to_owned(),
            baseline_availability: Availability::Executed,
            candidate_availability: if served {
                Availability::CacheHit
            } else {
                Availability::Executed
            },
            outcome_diverged: diverged,
            stdout_diverged: false,
            stderr_diverged: false,
            baseline_duration_ms: 1,
            candidate_duration_ms: 1,
        }
    }

    fn report(
        rows: Vec<DivergenceRecord>,
        redacted: usize,
        malformed: usize,
    ) -> ShadowPipelineReport {
        let quarantine_required: Vec<String> = rows
            .iter()
            .filter(|r| r.diverged() && r.candidate_availability == Availability::CacheHit)
            .map(|r| r.command.clone())
            .collect();
        let private_divergences = rows
            .iter()
            .filter(|r| r.diverged() && r.candidate_availability != Availability::CacheHit)
            .count();
        ShadowPipelineReport {
            session: SessionReport {
                rows,
                skipped_redacted: redacted,
                skipped_malformed: malformed,
            },
            quarantine_required,
            private_divergences,
        }
    }

    fn policy() -> ReleasePolicy {
        ReleasePolicy {
            explained: BTreeSet::new(),
            minimum_replayed: 3,
            maximum_skipped_basis_points: 2_000, // 20%
        }
    }

    #[test]
    fn a_clean_corpus_authorizes_promotion() {
        let clean = report(
            vec![
                row("cargo build", false, true),
                row("cargo test", false, true),
                row("cargo check", false, false),
            ],
            0,
            0,
        );
        let authorized = evaluate_release_gate(&clean, &policy()).expect("clean corpus authorizes");
        assert_eq!(authorized.replayed(), 3);
        assert_eq!(authorized.explained(), 0);
    }

    #[test]
    fn minting_carries_the_evidence_across_the_process_boundary() {
        use rabs_protocol::release_authorization::{
            ReleaseAuthorization, ReleaseAuthorizationMode, authorization,
        };

        let mut explained_policy = policy();
        explained_policy.explained.insert("cargo doc".to_owned());
        let run = report(
            vec![
                row("cargo build", false, true),
                row("cargo test", false, true),
                row("cargo check", false, false),
                row("cargo doc", true, false),
            ],
            0,
            0,
        );
        let authorized = evaluate_release_gate(&run, &explained_policy)
            .expect("explained divergence authorizes");

        let validity = ServingValidity {
            evaluated_at_unix_micros: 1_000,
            maximum_age_micros: Some(50_000),
            clock_uncertainty_micros: 0,
            coordinator_clock_epoch: 2,
        };
        let verdict = authorized.into_verdict("rabs-build-9", "corpus-xyz", validity);

        // The counts survive: the explained tally in particular, so the
        // explained set growing release over release is visible in the
        // durable record rather than only in a policy file.
        assert_eq!(verdict.replayed, 4);
        assert_eq!(verdict.explained, 1);
        assert_eq!(verdict.build, "rabs-build-9");
        assert_eq!(verdict.corpus, "corpus-xyz");

        // And the minted verdict actually authorizes the build it names,
        // under the strictest mode — the end-to-end point of minting.
        assert_eq!(
            authorization(Some(&verdict), "rabs-build-9", 2_000, 2),
            ReleaseAuthorization::Authorized { replayed: 4 }
        );
        assert!(
            authorization(Some(&verdict), "rabs-build-9", 2_000, 2)
                .permits_serving(ReleaseAuthorizationMode::Required)
        );
        // But says nothing about any other build.
        assert!(
            !authorization(Some(&verdict), "rabs-build-10", 2_000, 2)
                .permits_serving(ReleaseAuthorizationMode::Required)
        );
    }

    #[test]
    fn a_refused_run_cannot_produce_a_verdict_at_all() {
        // Not a runtime assertion — a type-level one, restated here so
        // it is not quietly removed. `into_verdict` consumes a
        // `PromotionAuthorized`, whose fields are private and which has
        // no public constructor, so the ONLY way to reach a verdict is
        // through a passing gate. A refusal is an `Err` carrying a
        // `ReleaseRefusal`, which has no path to one.
        let served_divergence = report(vec![row("cargo build", true, true)], 0, 0);
        let refusal = evaluate_release_gate(&served_divergence, &policy())
            .expect_err("a served divergence must refuse");
        assert!(matches!(refusal, ReleaseRefusal::ServedDivergence { .. }));
        // If a future edit gave `PromotionAuthorized` public fields or a
        // constructor, this comment is the thing that was violated; the
        // compiler cannot say so on its own.
    }

    #[test]
    fn an_empty_run_refuses_rather_than_authorizing_vacuously() {
        // THE property this gate is built around. A gate that passes
        // when nothing ran manufactures the evidence of safety without
        // the safety, and it is the single most likely way for this to
        // rot — a corpus path typo, a filter that matches nothing.
        assert_eq!(
            evaluate_release_gate(&report(Vec::new(), 0, 0), &policy()),
            Err(ReleaseRefusal::NothingReplayed)
        );
    }

    #[test]
    fn a_policy_that_requires_no_coverage_is_itself_refused() {
        // The other way to get a vacuous pass: leave the gate in place
        // and weaken the policy until it accepts nothing-at-all. Asking
        // for zero coverage is refused before the run is even examined.
        let mut permissive = policy();
        permissive.minimum_replayed = 0;
        assert_eq!(
            evaluate_release_gate(
                &report(vec![row("cargo build", false, false)], 0, 0),
                &permissive
            ),
            Err(ReleaseRefusal::PolicyAcceptsNoCoverage)
        );
    }

    #[test]
    fn a_thin_corpus_refuses_even_though_what_ran_was_clean() {
        // Coverage decay: most records skipped, the survivors all
        // clean. Without the skip ceiling this authorizes while proving
        // almost nothing.
        let thin = report(
            vec![
                row("cargo build", false, false),
                row("cargo test", false, false),
                row("cargo check", false, false),
            ],
            40,
            0,
        );
        let refusal = evaluate_release_gate(&thin, &policy()).expect_err("thin coverage refuses");
        assert!(
            matches!(refusal, ReleaseRefusal::CoverageTooThin { .. }),
            "got {refusal:?}"
        );
    }

    #[test]
    fn an_unexplained_divergence_refuses_and_names_every_command() {
        let diverging = report(
            vec![
                row("cargo build", false, false),
                row("cargo test --release", true, false),
                row("cargo check", false, false),
                row("cargo doc", true, false),
            ],
            0,
            0,
        );
        let refusal = evaluate_release_gate(&diverging, &policy()).expect_err("divergence refuses");
        assert_eq!(
            refusal,
            ReleaseRefusal::UnexplainedDivergence {
                commands: vec!["cargo doc".to_owned(), "cargo test --release".to_owned()],
            },
            "a count alone cannot be acted on: every offending command is named"
        );
    }

    #[test]
    fn an_explained_divergence_does_not_block_but_is_still_reported() {
        let mut accounted = policy();
        accounted
            .explained
            .insert("cargo test --release".to_owned());
        let diverging = report(
            vec![
                row("cargo build", false, false),
                row("cargo test --release", true, false),
                row("cargo check", false, false),
            ],
            0,
            0,
        );
        let authorized =
            evaluate_release_gate(&diverging, &accounted).expect("explained divergence authorizes");
        assert_eq!(
            authorized.explained(),
            1,
            "an explained divergence is still counted: silence would let the \
             explained set grow unnoticed until it explained everything"
        );
    }

    #[test]
    fn explaining_one_command_does_not_explain_a_different_one() {
        // The escape this gate must not have. The explained set is
        // matched EXACTLY; a near-miss is still unexplained.
        let mut accounted = policy();
        accounted.explained.insert("cargo test".to_owned());
        let diverging = report(
            vec![
                row("cargo build", false, false),
                row("cargo test --release", true, false),
                row("cargo check", false, false),
            ],
            0,
            0,
        );
        assert_eq!(
            evaluate_release_gate(&diverging, &accounted),
            Err(ReleaseRefusal::UnexplainedDivergence {
                commands: vec!["cargo test --release".to_owned()],
            })
        );
    }

    #[test]
    fn a_served_divergence_can_never_be_explained_away() {
        // The hard rule. A privately-executed divergence is an evidence
        // quality problem an operator may account for; a SERVED one
        // means the cache already answered with something stock
        // disagrees with. Naming it in the policy must not help.
        let mut accounted = policy();
        accounted.explained.insert("cargo build".to_owned());
        let served = report(
            vec![
                row("cargo build", true, true),
                row("cargo test", false, false),
                row("cargo check", false, false),
            ],
            0,
            0,
        );
        assert_eq!(
            evaluate_release_gate(&served, &accounted),
            Err(ReleaseRefusal::ServedDivergence {
                commands: vec!["cargo build".to_owned()],
            }),
            "a served divergence is a soundness incident, not an explainable difference"
        );
    }

    #[test]
    fn insufficient_coverage_names_what_it_wanted() {
        let refusal = evaluate_release_gate(
            &report(vec![row("cargo build", false, false)], 0, 0),
            &policy(),
        )
        .expect_err("one record is not a corpus");
        assert_eq!(
            refusal,
            ReleaseRefusal::InsufficientCoverage {
                replayed: 1,
                required: 3,
            }
        );
    }
}
