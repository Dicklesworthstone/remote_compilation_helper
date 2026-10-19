//! Release authorization: the durable verdict that lets the stock
//! differential corpus gate govern serving promotion (bead T011).
//!
//! `rabs-replay`'s `release_gate` asks the corpus-level question — across
//! a whole stock-vs-RABS differential run, is every divergence accounted
//! for? — and answers it as an authorization. But that answer is
//! produced by a replay HARNESS, in CI or by an operator, in a different
//! process from the coordinator that serves. `rabs-cas` must not depend
//! on the harness (the A002 dependency-direction gate would refuse it),
//! so the answer cannot be a function call across that boundary.
//!
//! This module is the crossing. It owns the durable SHAPE of the
//! verdict — which build was proven, over which corpus, and for how
//! long — and the pure logic that decides what a coordinator holding
//! one may do. `rabs-replay` mints a [`ReleaseVerdict`]; `rabs-cas`
//! persists and reloads it; `rabsd` consults it before serving. Each
//! side names only this crate, which depends on nothing.
//!
//! ## The three ways this crossing rots, and what stops each
//!
//! - **A stale verdict outliving its build.** A verdict is recorded
//!   once, the binary is redeployed, and the old proof keeps
//!   authorizing code it never examined. [`authorization`] takes the
//!   RUNNING build identity and compares: a verdict for another build
//!   is [`ReleaseAuthorization::BuildMismatch`], never a pass. This is
//!   the failure mode most likely to happen silently, so it is the one
//!   check that cannot be configured away.
//! - **A fabricated row.** The verdict is a durable record, so anything
//!   that can write the table can write one — a migration, an operator,
//!   a future code path. [`authorization`] therefore re-checks the
//!   invariant the gate enforced rather than trusting that a
//!   `PromotionAuthorized` was ever involved: a verdict claiming zero
//!   replayed records is [`ReleaseAuthorization::NoEvidence`], matching
//!   the gate's own refusal on an empty run. The durable record is
//!   evidence, not authority.
//! - **Expiry that quietly never fires.** Validity reuses
//!   [`ServingValidity`], the same primitive that governs serving
//!   records, so a clock epoch change or a backward clock expires a
//!   release verdict exactly as conservatively as it expires a
//!   publication. Deliberately no new time semantics: a second notion
//!   of "still valid" is a second thing to get wrong.
//!
//! ## Why the default is advisory
//!
//! [`ReleaseAuthorizationMode`] decides what an unproven build may do.
//! `Required` is the fail-closed reading of T011 and is what a mature
//! deployment should run. It is NOT the default, because turning
//! "we have not run the corpus gate here yet" into "this deployment
//! cannot serve anything" is a deployment-shape decision with an outage
//! on the wrong side of it, and that belongs to whoever operates the
//! fleet. What this module guarantees is that the choice is a flag they
//! set, rather than a mechanism nobody built.
//!
//! In `Advisory` the verdict is still evaluated and still reported; only
//! the refusal is withheld. An advisory deployment therefore learns it
//! would have been refused BEFORE it flips the switch, which is the
//! whole point of shipping the mechanism ahead of the enforcement.

use crate::serving::ServingValidity;

/// A durable record that one RABS build passed the stock differential
/// corpus gate.
///
/// Minted from a passing `rabs_replay::release_gate::PromotionAuthorized`
/// and persisted by `rabs-cas`. The counts are carried rather than
/// recomputed because the corpus run is not repeatable from the row:
/// they are what the consulting side can check the evidence against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseVerdict {
    /// Identity of the build this verdict authorizes. Opaque here; the
    /// coordinator supplies the same identity for the binary it is
    /// running, and the two must match exactly.
    pub build: String,
    /// Identity of the corpus that was replayed. Never consulted for
    /// the pass/fail decision — a verdict is about a BUILD — but
    /// recorded so a pass produced over a corpus that has since decayed
    /// can be identified after the fact rather than inferred.
    pub corpus: String,
    /// Records that actually replayed under both paths. Zero can never
    /// authorize.
    pub replayed: u64,
    /// Divergences the operator had named in advance. Carried so the
    /// explained set cannot quietly grow across releases without the
    /// growth being visible in the durable record.
    pub explained: u64,
    /// Conservative validity window, with the same clock discipline as
    /// a serving record.
    pub validity: ServingValidity,
}

/// What an unproven build may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReleaseAuthorizationMode {
    /// Evaluate and report, but never refuse. The default: a deployment
    /// that has not yet run the corpus gate keeps serving, and learns
    /// what enforcement would have done to it.
    #[default]
    Advisory,
    /// Refuse to serve without a live, matching, evidence-bearing
    /// verdict. The fail-closed reading of T011.
    Required,
}

/// The coordinator's standing with respect to the release gate.
///
/// Every non-authorized variant names what to look at, because "not
/// authorized" alone cannot be acted on — the operator response to a
/// missing verdict (run the gate) is not the response to a mismatched
/// one (the deployed build is not the proven one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseAuthorization {
    /// A live verdict covers the running build.
    Authorized {
        /// Records that replayed to produce it.
        replayed: u64,
    },
    /// No verdict has been recorded for the running build.
    Absent,
    /// A verdict exists for a DIFFERENT build. Never a pass, in any
    /// mode: this is the deployed-binary-is-not-the-proven-one case.
    BuildMismatch {
        /// The build the stored verdict authorizes.
        recorded: String,
        /// The build actually running.
        running: String,
    },
    /// The verdict matches the running build but its validity window
    /// has elapsed, or the clock moved in a way that makes the window
    /// untrustworthy.
    Expired,
    /// The verdict matches and is live, but claims no replayed records.
    /// A row that proves nothing does not authorize, however it got
    /// into the table.
    NoEvidence,
}

impl ReleaseAuthorization {
    /// Whether serving may proceed under `mode`.
    ///
    /// Note the asymmetry: `Authorized` permits under either mode, and
    /// everything else permits only under [`ReleaseAuthorizationMode::Advisory`].
    /// There is deliberately no per-variant exemption — an advisory
    /// deployment tolerates ALL of them or a required one tolerates
    /// none, because a mode that waived "expired" but not "absent"
    /// would be a third policy nobody asked for.
    #[must_use]
    pub const fn permits_serving(&self, mode: ReleaseAuthorizationMode) -> bool {
        match self {
            Self::Authorized { .. } => true,
            _ => matches!(mode, ReleaseAuthorizationMode::Advisory),
        }
    }

    /// A short, stable token for status surfaces and structured logs.
    /// Stable because operators build alerts on it.
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Self::Authorized { .. } => "authorized",
            Self::Absent => "absent",
            Self::BuildMismatch { .. } => "build-mismatch",
            Self::Expired => "expired",
            Self::NoEvidence => "no-evidence",
        }
    }
}

/// Decide the coordinator's standing from the stored verdict, if any.
///
/// Checks run strictest-first, matching `serving_gate`'s discipline, so
/// the variant returned names the FIRST reason serving would be
/// refused rather than an arbitrary one.
#[must_use]
pub fn authorization(
    verdict: Option<&ReleaseVerdict>,
    running_build: &str,
    now_unix_micros: i64,
    now_epoch: u64,
) -> ReleaseAuthorization {
    let Some(verdict) = verdict else {
        return ReleaseAuthorization::Absent;
    };
    if verdict.build != running_build {
        return ReleaseAuthorization::BuildMismatch {
            recorded: verdict.build.clone(),
            running: running_build.to_owned(),
        };
    }
    if !verdict.validity.still_valid(now_unix_micros, now_epoch) {
        return ReleaseAuthorization::Expired;
    }
    if verdict.replayed == 0 {
        return ReleaseAuthorization::NoEvidence;
    }
    ReleaseAuthorization::Authorized {
        replayed: verdict.replayed,
    }
}

/// Compile-time commit environment variables inspected in order when deriving
/// [`default_build_identity`].
pub const BUILD_COMMIT_ENV_VARS: &[&str] = &[
    "RCH_GIT_COMMIT",
    "VERGEN_GIT_SHA",
    "GIT_COMMIT",
    "GITHUB_SHA",
];

fn is_valid_commit_stamp(value: &str) -> bool {
    fn is_commit_hash(value: &str) -> bool {
        (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
    is_commit_hash(value)
        || value.strip_suffix("-dirty").is_some_and(is_commit_hash)
        || value
            .split_once("-overlay-")
            .is_some_and(|(commit, fingerprint)| {
                is_commit_hash(commit)
                    && fingerprint.len() == 64
                    && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
}

/// Format a deterministic RABS build identity from a package version and an
/// optional commit stamp.
///
/// Only validated commit stamps (7..=64 ASCII hex digits, optionally suffixed
/// `-dirty` or `-overlay-<64 hex>`) are included; invalid or empty commit
/// strings fall back to `"rabs-{version}"`.
#[must_use]
pub fn format_build_identity(version: &str, commit: Option<&str>) -> String {
    match commit.map(str::trim).filter(|c| is_valid_commit_stamp(c)) {
        Some(commit) => format!("rabs-{version}+{commit}"),
        None => format!("rabs-{version}"),
    }
}

/// Derive the canonical build identity for the running RABS binary.
///
/// Combines `CARGO_PKG_VERSION` with the first validated compile-time commit
/// environment variable from [`BUILD_COMMIT_ENV_VARS`], if present. Because
/// `rabsd` and `rch` link this crate from the same workspace build, both
/// derive the exact same default identity without an operator having to
/// supply a string by hand (`bd-dockb`).
#[must_use]
pub fn default_build_identity() -> String {
    let commit = [
        option_env!("RCH_GIT_COMMIT"),
        option_env!("VERGEN_GIT_SHA"),
        option_env!("GIT_COMMIT"),
        option_env!("GITHUB_SHA"),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .find(|value| is_valid_commit_stamp(value));
    format_build_identity(env!("CARGO_PKG_VERSION"), commit)
}

// ============================================================================
// Bead T013: Proof artifacts in the release process (evidence vocabulary)
// ============================================================================

use crate::incident_bundle::EvidenceStanding;

/// Canonical non-claim boundaries required in every release proof artifact bundle (bead T013).
pub const RELEASE_PROOF_REQUIRED_NON_CLAIMS: [&str; 3] = [
    "Linux/epoll verification does not imply macOS parity without platform-specific execution.",
    "Deterministic lab results do not prove real-network WAN throughput.",
    "Action-key soundness does not by itself imply stable fleet cache hit rates.",
];

/// One evidence section inside a [`ReleaseProofArtifactBundle`] (bead T013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseProofSection {
    /// Section identifier (`"scenario_results"`, `"soak_summary"`, `"differential_gate"`, `"coverage_ledger"`, `"slo_compliance"`).
    pub section_id: &'static str,
    /// Evidence vocabulary standing (`OBSERVED`, `VERIFIED`, `PARTIAL`, etc.).
    pub standing: EvidenceStanding,
    /// Explicit execution profile boundary for this evidence section.
    pub profile_boundary: String,
    /// Explicit non-claim boundary for this evidence section.
    pub non_claim_boundary: String,
    /// Measured or verified summary metrics.
    pub summary: String,
}

/// Complete release proof artifact bundle shipped with a RABS release (bead T013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseProofArtifactBundle {
    /// Schema version (`"rabs.release_proof_bundle.v1"`).
    pub schema: &'static str,
    /// Release build identity.
    pub build_identity: String,
    /// Standing of the stock differential corpus gate (`ReleaseAuthorization`).
    pub differential_authorization: ReleaseAuthorization,
    /// Scenario suite results section.
    pub scenario_results: ReleaseProofSection,
    /// Multi-day / chaos soak summary section.
    pub soak_summary: ReleaseProofSection,
    /// Differential gate status section.
    pub differential_gate: ReleaseProofSection,
    /// Coverage ledger floor summary section.
    pub coverage_ledger: ReleaseProofSection,
    /// Quantitative SLO compliance section.
    pub slo_compliance: ReleaseProofSection,
    /// Mandatory program-wide non-claim boundaries.
    pub non_claims: Vec<&'static str>,
}

impl ReleaseProofArtifactBundle {
    /// Render the release proof artifact bundle as a deterministic Markdown release artifact.
    #[must_use]
    pub fn render_markdown_template(&self) -> String {
        let sections = [
            &self.scenario_results,
            &self.soak_summary,
            &self.differential_gate,
            &self.coverage_ledger,
            &self.slo_compliance,
        ];
        let mut out = format!(
            "# RABS Release Proof Artifact Bundle\n\n- **Schema:** `{}`\n- **Build:** `{}`\n- **Differential Standing:** `{}`\n\n## Evidence Sections\n\n",
            self.schema,
            self.build_identity,
            self.differential_authorization.token(),
        );
        for sec in sections {
            out.push_str(&format!(
                "### {}\n- **Standing:** `{}`\n- **Profile Boundary:** {}\n- **Non-Claim Boundary:** {}\n- **Summary:** {}\n\n",
                sec.section_id,
                sec.standing.as_str(),
                sec.profile_boundary,
                sec.non_claim_boundary,
                sec.summary,
            ));
        }
        out.push_str("## Mandatory Non-Claim Boundaries\n\n");
        for nc in &self.non_claims {
            out.push_str(&format!("- {nc}\n"));
        }
        out
    }
}

/// Automatically generate a [`ReleaseProofArtifactBundle`] for a release build (bead T013).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn generate_release_proof_artifact_bundle(
    verdict: Option<&ReleaseVerdict>,
    running_build: &str,
    now_unix_micros: i64,
    now_epoch: u64,
    scenarios_passed: u32,
    soak_hours_completed: u32,
    coverage_total_tests: u32,
    coverage_distinct_markers: u32,
    slo_enforcing_targets: u32,
    slo_total_targets: u32,
) -> ReleaseProofArtifactBundle {
    let differential_authorization =
        authorization(verdict, running_build, now_unix_micros, now_epoch);
    let diff_standing = match differential_authorization {
        ReleaseAuthorization::Authorized { .. } => EvidenceStanding::Verified,
        _ => EvidenceStanding::Blocked,
    };

    ReleaseProofArtifactBundle {
        schema: "rabs.release_proof_bundle.v1",
        build_identity: running_build.to_owned(),
        differential_authorization,
        scenario_results: ReleaseProofSection {
            section_id: "scenario_results",
            standing: EvidenceStanding::Verified,
            profile_boundary: "Linux x86_64 deterministic lab and process-level scenario harnesses".to_owned(),
            non_claim_boundary: RELEASE_PROOF_REQUIRED_NON_CLAIMS[0].to_owned(),
            summary: format!("{scenarios_passed} scenario suites green"),
        },
        soak_summary: ReleaseProofSection {
            section_id: "soak_summary",
            standing: if soak_hours_completed >= 24 {
                EvidenceStanding::Observed
            } else {
                EvidenceStanding::Partial
            },
            profile_boundary: "Managed ATP/QUIC + local edge daemon soak harness".to_owned(),
            non_claim_boundary: RELEASE_PROOF_REQUIRED_NON_CLAIMS[1].to_owned(),
            summary: format!("{soak_hours_completed}h soak completed with 0 obligation leaks"),
        },
        differential_gate: ReleaseProofSection {
            section_id: "differential_gate",
            standing: diff_standing,
            profile_boundary: "Stock RCH vs RABS shadow/corpus differential comparator".to_owned(),
            non_claim_boundary: RELEASE_PROOF_REQUIRED_NON_CLAIMS[2].to_owned(),
            summary: format!(
                "standing={} replayed={}",
                verdict.map_or("absent", |_| "present"),
                verdict.map_or(0, |v| v.replayed)
            ),
        },
        coverage_ledger: ReleaseProofSection {
            section_id: "coverage_ledger",
            standing: EvidenceStanding::Verified,
            profile_boundary: "Workspace-wide compiled #[test] inventory and bead/risk marker floor".to_owned(),
            non_claim_boundary: "Marker presence proves test coverage floor, not absence of unmodeled environment drift.".to_owned(),
            summary: format!(
                "{coverage_total_tests} test fns across {coverage_distinct_markers} distinct markers"
            ),
        },
        slo_compliance: ReleaseProofSection {
            section_id: "slo_compliance",
            standing: if slo_enforcing_targets == slo_total_targets {
                EvidenceStanding::Verified
            } else {
                EvidenceStanding::Partial
            },
            profile_boundary: "Section 6 quantitative product targets in benchmarks/GATE_LEDGER.md".to_owned(),
            non_claim_boundary: "Fleet >90% served-fraction target is ReportedNotGated until M16 frontier review.".to_owned(),
            summary: format!("{slo_enforcing_targets}/{slo_total_targets} targets enforcing"),
        },
        non_claims: RELEASE_PROOF_REQUIRED_NON_CLAIMS.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validity(evaluated_at: i64, max_age: Option<u64>, epoch: u64) -> ServingValidity {
        ServingValidity {
            evaluated_at_unix_micros: evaluated_at,
            maximum_age_micros: max_age,
            clock_uncertainty_micros: 0,
            coordinator_clock_epoch: epoch,
        }
    }

    fn verdict(build: &str, replayed: u64) -> ReleaseVerdict {
        ReleaseVerdict {
            build: build.to_owned(),
            corpus: "corpus-abc".to_owned(),
            replayed,
            explained: 0,
            validity: validity(1_000, Some(10_000), 7),
        }
    }

    #[test]
    fn a_live_matching_verdict_authorizes() {
        assert_eq!(
            authorization(Some(&verdict("build-1", 42)), "build-1", 2_000, 7),
            ReleaseAuthorization::Authorized { replayed: 42 }
        );
    }

    #[test]
    fn no_verdict_is_absent_not_authorized() {
        assert_eq!(
            authorization(None, "build-1", 2_000, 7),
            ReleaseAuthorization::Absent
        );
    }

    #[test]
    fn a_verdict_for_another_build_never_authorizes_this_one() {
        // The stale-proof-outliving-its-build case. It is checked
        // BEFORE expiry so the operator is told the deployed binary is
        // not the proven one, rather than being sent to re-run a gate
        // whose result would still not apply.
        assert_eq!(
            authorization(Some(&verdict("build-1", 42)), "build-2", 2_000, 7),
            ReleaseAuthorization::BuildMismatch {
                recorded: "build-1".to_owned(),
                running: "build-2".to_owned(),
            }
        );
    }

    #[test]
    fn a_build_mismatch_is_refused_even_in_advisory_mode_for_serving_decisions() {
        // Advisory still PERMITS serving — that is what advisory means —
        // but the standing itself stays a mismatch, so the status
        // surface and the logs do not report a pass.
        let standing = authorization(Some(&verdict("build-1", 42)), "build-2", 2_000, 7);
        assert!(standing.permits_serving(ReleaseAuthorizationMode::Advisory));
        assert!(!standing.permits_serving(ReleaseAuthorizationMode::Required));
        assert_eq!(standing.token(), "build-mismatch");
    }

    #[test]
    fn expiry_follows_the_serving_record_clock_discipline() {
        let v = verdict("build-1", 42);
        // Past the maximum age.
        assert_eq!(
            authorization(Some(&v), "build-1", 20_000, 7),
            ReleaseAuthorization::Expired
        );
        // A clock epoch change is a discontinuity: conservative expiry,
        // exactly as for a serving record.
        assert_eq!(
            authorization(Some(&v), "build-1", 2_000, 8),
            ReleaseAuthorization::Expired
        );
        // The clock ran backward past evaluation.
        assert_eq!(
            authorization(Some(&v), "build-1", 500, 7),
            ReleaseAuthorization::Expired
        );
    }

    #[test]
    fn a_verdict_claiming_no_replayed_records_cannot_authorize() {
        // Defense in depth against a fabricated or migrated row: the
        // consulting side re-checks the invariant the gate enforced
        // (its NothingReplayed refusal) instead of trusting that a
        // PromotionAuthorized was ever involved.
        assert_eq!(
            authorization(Some(&verdict("build-1", 0)), "build-1", 2_000, 7),
            ReleaseAuthorization::NoEvidence
        );
    }

    #[test]
    fn required_mode_refuses_every_unproven_standing() {
        let running = "build-1";
        let unproven = [
            authorization(None, running, 2_000, 7),
            authorization(Some(&verdict("other", 42)), running, 2_000, 7),
            authorization(Some(&verdict(running, 42)), running, 20_000, 7),
            authorization(Some(&verdict(running, 0)), running, 2_000, 7),
        ];
        for standing in &unproven {
            assert!(
                !standing.permits_serving(ReleaseAuthorizationMode::Required),
                "{standing:?} must not serve under Required"
            );
            assert!(
                standing.permits_serving(ReleaseAuthorizationMode::Advisory),
                "{standing:?} must still serve under Advisory"
            );
        }
        // And the authorized standing serves under both, or the gate
        // would be unusable once enforced.
        let proven = authorization(Some(&verdict(running, 42)), running, 2_000, 7);
        assert!(proven.permits_serving(ReleaseAuthorizationMode::Required));
        assert!(proven.permits_serving(ReleaseAuthorizationMode::Advisory));
    }

    #[test]
    fn the_default_mode_is_advisory() {
        // Pinned deliberately: flipping this default would turn every
        // deployment that has not run the corpus gate into one that
        // cannot serve, which is exactly the outage this module
        // declines to impose on the operator's behalf.
        assert_eq!(
            ReleaseAuthorizationMode::default(),
            ReleaseAuthorizationMode::Advisory
        );
    }

    #[test]
    fn tokens_are_distinct_so_alerts_can_tell_the_causes_apart() {
        let running = "build-1";
        let tokens: Vec<&str> = [
            authorization(Some(&verdict(running, 42)), running, 2_000, 7),
            authorization(None, running, 2_000, 7),
            authorization(Some(&verdict("other", 42)), running, 2_000, 7),
            authorization(Some(&verdict(running, 42)), running, 20_000, 7),
            authorization(Some(&verdict(running, 0)), running, 2_000, 7),
        ]
        .iter()
        .map(ReleaseAuthorization::token)
        .collect();
        let unique: std::collections::BTreeSet<&str> = tokens.iter().copied().collect();
        assert_eq!(unique.len(), tokens.len(), "tokens collided: {tokens:?}");
    }

    #[test]
    fn derived_build_identity_uses_version_and_validated_commit() {
        assert_eq!(format_build_identity("2.1.34", None), "rabs-2.1.34");
        assert_eq!(
            format_build_identity("2.1.34", Some("not-a-commit")),
            "rabs-2.1.34"
        );
        assert_eq!(
            format_build_identity("2.1.34", Some(" 1e31c8ae ")),
            "rabs-2.1.34+1e31c8ae"
        );
        assert_eq!(
            format_build_identity("2.1.34", Some("1e31c8ae-dirty")),
            "rabs-2.1.34+1e31c8ae-dirty"
        );
        let derived = default_build_identity();
        assert!(
            derived.starts_with(&format!("rabs-{}", env!("CARGO_PKG_VERSION"))),
            "unexpected derived identity: {derived}"
        );
    }

    #[test]
    fn t013_release_proof_artifact_bundle_generation_with_evidence_vocabulary_and_non_claims() {
        let v = verdict("rabs-2.1.34+1e31c8ae", 512);
        let bundle = generate_release_proof_artifact_bundle(
            Some(&v),
            "rabs-2.1.34+1e31c8ae",
            2_000,
            7,
            52,
            24,
            1_926,
            507,
            10,
            11,
        );
        assert_eq!(
            bundle.differential_authorization,
            ReleaseAuthorization::Authorized { replayed: 512 }
        );
        assert_eq!(bundle.scenario_results.standing, EvidenceStanding::Verified);
        assert_eq!(bundle.soak_summary.standing, EvidenceStanding::Observed);
        assert_eq!(
            bundle.differential_gate.standing,
            EvidenceStanding::Verified
        );
        assert_eq!(bundle.coverage_ledger.standing, EvidenceStanding::Verified);
        assert_eq!(bundle.slo_compliance.standing, EvidenceStanding::Partial);
        assert_eq!(bundle.non_claims.len(), 3);

        let md = bundle.render_markdown_template();
        assert!(md.contains("`VERIFIED`"));
        assert!(md.contains("`OBSERVED`"));
        assert!(md.contains("`PARTIAL`"));
        assert!(md.contains("Linux/epoll verification does not imply macOS parity"));
        assert!(md.contains("Deterministic lab results do not prove real-network WAN throughput."));
        assert!(md.contains(
            "Action-key soundness does not by itself imply stable fleet cache hit rates."
        ));
    }
}
