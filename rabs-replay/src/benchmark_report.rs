//! The benchmark report: one format for every scenario (bead B008;
//! consumed by the B013 CI gates).
//!
//! One replay run → one machine-readable report. The full B008 metric
//! set appears in the schema, but every metric group is TYPED as
//! either measured or not-yet-instrumented:
//!
//! - what a replay run actually yields today computes FOR REAL:
//!   p50/p90/p95 whole-command latency per path (exact nearest-rank,
//!   no interpolation guesswork), served-vs-executed availability with
//!   hit rate and the miss taxonomy, and the correctness/divergence
//!   result per dimension;
//! - metrics whose measurement source does not exist yet
//!   (first-diagnostic latency needs the C007 stream tap;
//!   transfer/dedup needs the H-series store counters; CPU/memory
//!   needs the G-series cgroup envelopes; …) are emitted as
//!   [`MetricGroup::NotInstrumented`] NAMING the missing source — a
//!   consumer can distinguish "zero" from "unmeasured" forever, and
//!   nobody can quietly read a fabricated number out of this report.
//!
//! The NDJSON emission is the stable format B013's gates parse; keys
//! are pinned by test.

use crate::{Availability, SessionReport};

/// Exact nearest-rank percentiles over whole-command durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Percentiles {
    /// 50th percentile (ms).
    pub p50_ms: u64,
    /// 90th percentile (ms).
    pub p90_ms: u64,
    /// 95th percentile (ms).
    pub p95_ms: u64,
    /// Sample count the percentiles were computed over.
    pub samples: usize,
}

/// Nearest-rank percentile: the smallest value with at least `p`% of
/// samples at or below it. Exact, deterministic, no interpolation.
#[must_use]
pub fn percentiles(durations: &[u64]) -> Option<Percentiles> {
    if durations.is_empty() {
        return None;
    }
    let mut sorted = durations.to_vec();
    sorted.sort_unstable();
    let rank = |percent: u64| {
        let n = sorted.len() as u64;
        let position = (percent * n).div_ceil(100).max(1);
        sorted[usize::try_from(position - 1).unwrap_or(0)]
    };
    Some(Percentiles {
        p50_ms: rank(50),
        p90_ms: rank(90),
        p95_ms: rank(95),
        samples: sorted.len(),
    })
}

/// A metric group: measured, or honestly not yet measurable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricGroup<T> {
    /// Measured from this run's actual observations.
    Measured(T),
    /// The measurement source does not exist yet; the field names it.
    NotInstrumented {
        /// What has to land before this group can be measured.
        needs: &'static str,
    },
}

/// Availability + miss taxonomy across the candidate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvailabilityMetrics {
    /// Invocations the candidate served from cache.
    pub cache_hits: usize,
    /// Invocations the candidate executed.
    pub executed: usize,
    /// Typed refusals (the miss taxonomy's unavailable arm).
    pub unavailable: usize,
    /// Hits per thousand candidate observations.
    pub hit_rate_permille: u64,
}

/// Divergence result per compared dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DivergenceMetrics {
    /// Compared rows.
    pub rows: usize,
    /// Rows with any divergence.
    pub diverged: usize,
    /// Outcome (exit/signal) divergences.
    pub outcome: usize,
    /// stdout digest divergences.
    pub stdout: usize,
    /// stderr digest divergences.
    pub stderr: usize,
    /// Skipped records (redacted + malformed) — the coverage
    /// countermetric: a clean report over a mostly-skipped session is
    /// visible as such.
    pub skipped: usize,
}

/// The one report format (B008). Field-for-field, the full metric set;
/// unmeasurable groups carry their missing source by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkReport {
    /// Baseline whole-command latency.
    pub baseline_latency: Option<Percentiles>,
    /// Candidate whole-command latency.
    pub candidate_latency: Option<Percentiles>,
    /// Availability + miss taxonomy.
    pub availability: AvailabilityMetrics,
    /// Correctness/divergence result.
    pub divergence: DivergenceMetrics,
    /// First-diagnostic latency (needs the C007 stream tap).
    pub first_diagnostic_latency: MetricGroup<Percentiles>,
    /// First-metadata-ready latency (needs the K-series pipeline tap).
    pub first_metadata_ready_latency: MetricGroup<Percentiles>,
    /// Compiler/linker/test seconds executed vs saved (needs B003
    /// per-tool context capture).
    pub tool_seconds: MetricGroup<()>,
    /// Queue delay (needs the G-series scheduler counters).
    pub queue_delay: MetricGroup<Percentiles>,
    /// Transfer bytes/dedup/throughput (needs the H-series store
    /// counters).
    pub transfer: MetricGroup<()>,
    /// CPU + memory local/remote (needs the E004 cgroup envelopes).
    pub cpu_memory: MetricGroup<()>,
    /// Storage growth (needs the H014 GC accounting tap).
    pub storage_growth: MetricGroup<()>,
    /// Speculation cost/value (needs the L-series speculation engine).
    pub speculation: MetricGroup<()>,
}

impl BenchmarkReport {
    /// Build the report from one replay session. Every measured figure
    /// comes from the session's rows; every unmeasured group names its
    /// missing source.
    #[must_use]
    pub fn from_session(session: &SessionReport) -> Self {
        let baseline: Vec<u64> = session
            .rows
            .iter()
            .map(|r| r.baseline_duration_ms)
            .collect();
        let candidate: Vec<u64> = session
            .rows
            .iter()
            .map(|r| r.candidate_duration_ms)
            .collect();
        let mut cache_hits = 0;
        let mut executed = 0;
        let mut unavailable = 0;
        for row in &session.rows {
            match row.candidate_availability {
                Availability::CacheHit => cache_hits += 1,
                Availability::Executed => executed += 1,
                Availability::Unavailable => unavailable += 1,
            }
        }
        let total = cache_hits + executed + unavailable;
        let hit_rate_permille = if total == 0 {
            0
        } else {
            (cache_hits as u64 * 1000) / total as u64
        };
        Self {
            baseline_latency: percentiles(&baseline),
            candidate_latency: percentiles(&candidate),
            availability: AvailabilityMetrics {
                cache_hits,
                executed,
                unavailable,
                hit_rate_permille,
            },
            divergence: DivergenceMetrics {
                rows: session.rows.len(),
                diverged: session.divergences(),
                outcome: session.rows.iter().filter(|r| r.outcome_diverged).count(),
                stdout: session.rows.iter().filter(|r| r.stdout_diverged).count(),
                stderr: session.rows.iter().filter(|r| r.stderr_diverged).count(),
                skipped: session.skipped_redacted + session.skipped_malformed,
            },
            first_diagnostic_latency: MetricGroup::NotInstrumented {
                needs: "C007 stream tap (first-line timestamps)",
            },
            first_metadata_ready_latency: MetricGroup::NotInstrumented {
                needs: "K-series MetadataReady pipeline tap",
            },
            tool_seconds: MetricGroup::NotInstrumented {
                needs: "B003 per-tool context capture",
            },
            queue_delay: MetricGroup::NotInstrumented {
                needs: "G-series scheduler queue counters",
            },
            transfer: MetricGroup::NotInstrumented {
                needs: "H-series store transfer/dedup counters",
            },
            cpu_memory: MetricGroup::NotInstrumented {
                needs: "E004 cgroup resource envelopes",
            },
            storage_growth: MetricGroup::NotInstrumented {
                needs: "H014 GC accounting tap",
            },
            speculation: MetricGroup::NotInstrumented {
                needs: "L-series speculation engine",
            },
        }
    }

    /// The stable machine-readable line B013's gates parse.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let latency = |p: &Option<Percentiles>| match p {
            Some(p) => serde_json::json!({
                "p50_ms": p.p50_ms,
                "p90_ms": p.p90_ms,
                "p95_ms": p.p95_ms,
                "samples": p.samples,
            }),
            None => serde_json::Value::Null,
        };
        let group = |g: &MetricGroup<Percentiles>| match g {
            MetricGroup::Measured(p) => latency(&Some(*p)),
            MetricGroup::NotInstrumented { needs } => {
                serde_json::json!({ "not_instrumented": needs })
            }
        };
        let unit_group = |g: &MetricGroup<()>| match g {
            MetricGroup::Measured(()) => serde_json::json!({}),
            MetricGroup::NotInstrumented { needs } => {
                serde_json::json!({ "not_instrumented": needs })
            }
        };
        serde_json::json!({
            "schema": "rabs.benchmark-report",
            "schema_version": 1,
            "baseline_latency": latency(&self.baseline_latency),
            "candidate_latency": latency(&self.candidate_latency),
            "availability": {
                "cache_hits": self.availability.cache_hits,
                "executed": self.availability.executed,
                "unavailable": self.availability.unavailable,
                "hit_rate_permille": self.availability.hit_rate_permille,
            },
            "divergence": {
                "rows": self.divergence.rows,
                "diverged": self.divergence.diverged,
                "outcome": self.divergence.outcome,
                "stdout": self.divergence.stdout,
                "stderr": self.divergence.stderr,
                "skipped": self.divergence.skipped,
            },
            "first_diagnostic_latency": group(&self.first_diagnostic_latency),
            "first_metadata_ready_latency": group(&self.first_metadata_ready_latency),
            "tool_seconds": unit_group(&self.tool_seconds),
            "queue_delay": group(&self.queue_delay),
            "transfer": unit_group(&self.transfer),
            "cpu_memory": unit_group(&self.cpu_memory),
            "storage_growth": unit_group(&self.storage_growth),
            "speculation": unit_group(&self.speculation),
        })
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// B013: CI regression gates against the corpus (plan §143)
// ---------------------------------------------------------------------------

use std::collections::BTreeSet;

/// Baseline snapshot against which candidate PR corpus runs are gated (bead B013; plan §143).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusBaselineSnapshot {
    /// Stable identifier of the baseline snapshot (e.g. `"ci-stratified-v1"`).
    pub snapshot_id: String,
    /// Wrapper p95 overhead SLO in microseconds (`<= 10_000` us = 10ms).
    pub wrapper_p95_slo_us: u64,
    /// Baseline p95 intent-to-result latency in milliseconds.
    pub baseline_intent_to_result_p95_ms: u64,
    /// Baseline cache hit rate in permille (`0..=1000`).
    pub baseline_hit_rate_permille: u64,
    /// Maximum unexplained divergences permitted (`0`).
    pub max_allowed_divergences: usize,
    /// Maximum uncompensated storage or transfer bloat in permille over baseline.
    pub max_storage_transfer_growth_permille: u32,
    /// Minimum stratified corpus strata that must be covered in the sample.
    pub min_selected_strata: usize,
}

/// Canonical pinned baseline snapshot enforced by the B013 CI regression gate.
#[must_use]
pub fn canonical_ci_baseline_snapshot() -> CorpusBaselineSnapshot {
    CorpusBaselineSnapshot {
        snapshot_id: "ci-stratified-v1".to_owned(),
        wrapper_p95_slo_us: 10_000,
        baseline_intent_to_result_p95_ms: 4_500,
        baseline_hit_rate_permille: 750,
        max_allowed_divergences: 0,
        max_storage_transfer_growth_permille: 100,
        min_selected_strata: 3,
    }
}

/// Regression dimension evaluated by the B013 CI corpus gate (plan §143).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CorpusRegressionKind {
    /// Wrapper/miss overhead violated the p95 SLO.
    WrapperSloExceeded,
    /// p95 intent-to-result worsened without documented compensating benefit.
    IntentToResultP95Regressed,
    /// Cache hit rate degraded relative to baseline without explanation.
    HitRateDegraded,
    /// Semantic or output divergence count exceeded baseline (`> 0`).
    /// Never waivable by an override.
    DivergenceRegression,
    /// Storage or transfer cost grew beyond the documented value threshold.
    StorageOrTransferBloat,
    /// Stratified replay sample covered fewer strata than required.
    StratifiedCoverageInsufficient,
    /// Cancellation or cleanup health check failed.
    CancellationOrCleanupDegraded,
    /// Default-on feature lacks rollback posture or decision receipt.
    /// Never waivable by an override.
    MissingRollbackOrReceipt,
}

impl CorpusRegressionKind {
    /// Stable machine code for CI reports and override validation.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WrapperSloExceeded => "wrapper_slo_exceeded",
            Self::IntentToResultP95Regressed => "intent_to_result_p95_regressed",
            Self::HitRateDegraded => "hit_rate_degraded",
            Self::DivergenceRegression => "divergence_regression",
            Self::StorageOrTransferBloat => "storage_or_transfer_bloat",
            Self::StratifiedCoverageInsufficient => "stratified_coverage_insufficient",
            Self::CancellationOrCleanupDegraded => "cancellation_or_cleanup_degraded",
            Self::MissingRollbackOrReceipt => "missing_rollback_or_receipt",
        }
    }

    /// Correctness and rollback/receipt gates are never waivable by performance overrides.
    #[must_use]
    pub const fn is_waivable(self) -> bool {
        !matches!(
            self,
            Self::DivergenceRegression | Self::MissingRollbackOrReceipt
        )
    }
}

/// Specific violation recorded by the B013 CI regression gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusGateViolation {
    /// Which gate dimension failed.
    pub kind: CorpusRegressionKind,
    /// Human- and machine-readable detail naming baseline vs candidate figures.
    pub detail: String,
}

/// Candidate PR metrics evaluated against a [`CorpusBaselineSnapshot`] (bead B013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusCandidateMetrics {
    /// Benchmark report from the stratified replay sample (B008).
    pub benchmark: BenchmarkReport,
    /// Observed wrapper p95 overhead (microseconds).
    pub wrapper_p95_us: u64,
    /// Observed p95 intent-to-result latency (milliseconds, from B012 or candidate latency).
    pub intent_to_result_p95_ms: u64,
    /// Number of strata covered in the B010 stratified sample.
    pub selected_strata: usize,
    /// Observed storage/transfer growth in permille over baseline.
    pub storage_transfer_growth_permille: u32,
    /// Whether cancellation and cleanup invariants passed without leaks.
    pub cancellation_cleanup_healthy: bool,
    /// Whether the feature ships with an explicit rollback switch and decision receipt.
    pub has_rollback_and_receipt: bool,
    /// Whether an intentional p95 tradeoff has a documented compensating benefit.
    pub compensating_benefit_documented: bool,
}

/// Auditable, time-bounded override protocol for controlled B013 gate waivers.
///
/// Overrides must name the exact [`CorpusRegressionKind`]s being waived, carry
/// a non-empty ticket/approver/reason, and be unexpired at `now_unix_ms`.
/// `DivergenceRegression` and `MissingRollbackOrReceipt` can NEVER be waived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegressionGateOverride {
    /// Issue or bead identifier authorizing the waiver.
    pub override_id: String,
    /// Operator or reviewer who approved the waiver.
    pub approver: String,
    /// Documented rationale / compensating benefit.
    pub reason: String,
    /// Expiration timestamp (Unix milliseconds).
    pub expires_at_unix_ms: u64,
    /// Closed set of regression kinds this override is permitted to waive.
    pub waived_kinds: BTreeSet<CorpusRegressionKind>,
}

impl RegressionGateOverride {
    /// Whether this override is well-formed and live at `now_unix_ms`.
    #[must_use]
    pub fn is_valid_at(&self, now_unix_ms: u64) -> bool {
        !self.override_id.trim().is_empty()
            && !self.approver.trim().is_empty()
            && !self.reason.trim().is_empty()
            && now_unix_ms < self.expires_at_unix_ms
    }

    /// Whether this override may waive `kind` at `now_unix_ms`.
    #[must_use]
    pub fn waives(&self, kind: CorpusRegressionKind, now_unix_ms: u64) -> bool {
        kind.is_waivable() && self.is_valid_at(now_unix_ms) && self.waived_kinds.contains(&kind)
    }
}

/// Verdict of the B013 CI regression gate against the corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusRegressionVerdict {
    /// Whether the PR passes the CI gate (`unwaived_violations.is_empty()`).
    pub passed: bool,
    /// Baseline snapshot ID consulted.
    pub snapshot_id: String,
    /// Unwaived violations that fail the CI gate.
    pub unwaived_violations: Vec<CorpusGateViolation>,
    /// Violations explicitly waived by a valid [`RegressionGateOverride`].
    pub waived_violations: Vec<CorpusGateViolation>,
    /// Override ID applied, if any violation was waived.
    pub override_applied: Option<String>,
}

impl CorpusRegressionVerdict {
    /// Emit a stable machine-readable NDJSON receipt for CI logs and audit artefacts.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let unwaived: Vec<serde_json::Value> = self
            .unwaived_violations
            .iter()
            .map(|v| serde_json::json!({ "kind": v.kind.code(), "detail": v.detail }))
            .collect();
        let waived: Vec<serde_json::Value> = self
            .waived_violations
            .iter()
            .map(|v| serde_json::json!({ "kind": v.kind.code(), "detail": v.detail }))
            .collect();
        serde_json::json!({
            "schema": "rabs.corpus-regression-gate",
            "schema_version": 1,
            "passed": self.passed,
            "snapshot_id": self.snapshot_id,
            "unwaived_violations": unwaived,
            "waived_violations": waived,
            "override_applied": self.override_applied,
        })
        .to_string()
    }
}

/// Evaluate the B013 CI regression gate against a baseline snapshot and optional override.
#[must_use]
pub fn evaluate_corpus_regression_gate(
    baseline: &CorpusBaselineSnapshot,
    candidate: &CorpusCandidateMetrics,
    override_policy: Option<&RegressionGateOverride>,
    now_unix_ms: u64,
) -> CorpusRegressionVerdict {
    let mut raw_violations = Vec::new();

    if candidate.selected_strata < baseline.min_selected_strata {
        raw_violations.push(CorpusGateViolation {
            kind: CorpusRegressionKind::StratifiedCoverageInsufficient,
            detail: format!(
                "selected_strata={} < min_selected_strata={}",
                candidate.selected_strata, baseline.min_selected_strata
            ),
        });
    }

    if candidate.wrapper_p95_us > baseline.wrapper_p95_slo_us {
        raw_violations.push(CorpusGateViolation {
            kind: CorpusRegressionKind::WrapperSloExceeded,
            detail: format!(
                "wrapper_p95_us={} > wrapper_p95_slo_us={}",
                candidate.wrapper_p95_us, baseline.wrapper_p95_slo_us
            ),
        });
    }

    if candidate.intent_to_result_p95_ms > baseline.baseline_intent_to_result_p95_ms
        && !candidate.compensating_benefit_documented
    {
        raw_violations.push(CorpusGateViolation {
            kind: CorpusRegressionKind::IntentToResultP95Regressed,
            detail: format!(
                "intent_to_result_p95_ms={} > baseline_p95_ms={}",
                candidate.intent_to_result_p95_ms, baseline.baseline_intent_to_result_p95_ms
            ),
        });
    }

    if candidate.benchmark.availability.hit_rate_permille < baseline.baseline_hit_rate_permille {
        raw_violations.push(CorpusGateViolation {
            kind: CorpusRegressionKind::HitRateDegraded,
            detail: format!(
                "hit_rate_permille={} < baseline_hit_rate_permille={}",
                candidate.benchmark.availability.hit_rate_permille,
                baseline.baseline_hit_rate_permille
            ),
        });
    }

    if candidate.benchmark.divergence.diverged > baseline.max_allowed_divergences {
        raw_violations.push(CorpusGateViolation {
            kind: CorpusRegressionKind::DivergenceRegression,
            detail: format!(
                "diverged={} > max_allowed_divergences={}",
                candidate.benchmark.divergence.diverged, baseline.max_allowed_divergences
            ),
        });
    }

    if candidate.storage_transfer_growth_permille > baseline.max_storage_transfer_growth_permille {
        raw_violations.push(CorpusGateViolation {
            kind: CorpusRegressionKind::StorageOrTransferBloat,
            detail: format!(
                "storage_transfer_growth_permille={} > max_allowed_permille={}",
                candidate.storage_transfer_growth_permille,
                baseline.max_storage_transfer_growth_permille
            ),
        });
    }

    if !candidate.cancellation_cleanup_healthy {
        raw_violations.push(CorpusGateViolation {
            kind: CorpusRegressionKind::CancellationOrCleanupDegraded,
            detail: "cancellation or cleanup health check failed".to_owned(),
        });
    }

    if !candidate.has_rollback_and_receipt {
        raw_violations.push(CorpusGateViolation {
            kind: CorpusRegressionKind::MissingRollbackOrReceipt,
            detail: "default-on feature lacks rollback switch or decision receipt".to_owned(),
        });
    }

    let mut unwaived_violations = Vec::new();
    let mut waived_violations = Vec::new();
    for v in raw_violations {
        if override_policy.is_some_and(|ov| ov.waives(v.kind, now_unix_ms)) {
            waived_violations.push(v);
        } else {
            unwaived_violations.push(v);
        }
    }

    let override_applied = if waived_violations.is_empty() {
        None
    } else {
        override_policy.map(|ov| ov.override_id.clone())
    };

    CorpusRegressionVerdict {
        passed: unwaived_violations.is_empty(),
        snapshot_id: baseline.snapshot_id.clone(),
        unwaived_violations,
        waived_violations,
        override_applied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DivergenceRecord;

    #[test]
    fn b008_nearest_rank_percentiles_are_exact() {
        // Odd count: 1..=9 → p50=5, p90=9, p95=9.
        let odd: Vec<u64> = (1..=9).collect();
        let p = percentiles(&odd).unwrap();
        assert_eq!((p.p50_ms, p.p90_ms, p.p95_ms, p.samples), (5, 9, 9, 9));
        // 100 samples: exact ranks 50/90/95.
        let hundred: Vec<u64> = (1..=100).collect();
        let p = percentiles(&hundred).unwrap();
        assert_eq!((p.p50_ms, p.p90_ms, p.p95_ms), (50, 90, 95));
        // Single sample: everything is that sample.
        let one = [42u64];
        let p = percentiles(&one).unwrap();
        assert_eq!((p.p50_ms, p.p90_ms, p.p95_ms, p.samples), (42, 42, 42, 1));
        // Unsorted input sorts internally.
        let shuffled = [9u64, 1, 5, 3, 7];
        assert_eq!(percentiles(&shuffled).unwrap().p50_ms, 5);
        // Empty: None, never a fabricated zero.
        assert_eq!(percentiles(&[]), None);
    }

    fn row(
        cand_avail: Availability,
        base_ms: u64,
        cand_ms: u64,
        stdout_diverged: bool,
    ) -> DivergenceRecord {
        DivergenceRecord {
            command: "cargo build".to_owned(),
            baseline_path: "stock".to_owned(),
            candidate_path: "rabs".to_owned(),
            baseline_availability: Availability::Executed,
            candidate_availability: cand_avail,
            outcome_diverged: false,
            stdout_diverged,
            stderr_diverged: false,
            baseline_duration_ms: base_ms,
            candidate_duration_ms: cand_ms,
        }
    }

    #[test]
    fn b008_report_computes_real_figures_and_names_unmeasured_sources() {
        let session = SessionReport {
            rows: vec![
                row(Availability::CacheHit, 1000, 50, false),
                row(Availability::CacheHit, 2000, 60, false),
                row(Availability::Executed, 3000, 2900, false),
                row(Availability::Unavailable, 4000, 0, true),
            ],
            skipped_redacted: 2,
            skipped_malformed: 1,
        };
        let report = BenchmarkReport::from_session(&session);
        // Real figures from real rows.
        assert_eq!(report.baseline_latency.unwrap().p50_ms, 2000);
        assert_eq!(report.availability.cache_hits, 2);
        assert_eq!(report.availability.executed, 1);
        assert_eq!(report.availability.unavailable, 1);
        assert_eq!(report.availability.hit_rate_permille, 500);
        assert_eq!(report.divergence.rows, 4);
        assert_eq!(report.divergence.diverged, 1);
        assert_eq!(report.divergence.stdout, 1);
        assert_eq!(report.divergence.skipped, 3, "coverage countermetric");
        // Unmeasured groups NAME the missing source.
        let MetricGroup::NotInstrumented { needs } = &report.transfer else {
            panic!("transfer cannot be measured from a bare replay run");
        };
        assert!(needs.contains("H-series"));
        assert!(matches!(
            report.first_diagnostic_latency,
            MetricGroup::NotInstrumented { .. }
        ));
    }

    #[test]
    fn b008_ndjson_format_is_stable_for_the_ci_gates() {
        let session = SessionReport {
            rows: vec![row(Availability::CacheHit, 100, 10, false)],
            skipped_redacted: 0,
            skipped_malformed: 0,
        };
        let line = BenchmarkReport::from_session(&session).to_ndjson();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["schema"], "rabs.benchmark-report");
        assert_eq!(parsed["schema_version"], 1);
        // The B013 gates parse these keys — pin every top-level one.
        for key in [
            "baseline_latency",
            "candidate_latency",
            "availability",
            "divergence",
            "first_diagnostic_latency",
            "first_metadata_ready_latency",
            "tool_seconds",
            "queue_delay",
            "transfer",
            "cpu_memory",
            "storage_growth",
            "speculation",
        ] {
            assert!(parsed.get(key).is_some(), "missing key {key}");
        }
        // A consumer can ALWAYS distinguish unmeasured from zero.
        assert!(
            parsed["transfer"]["not_instrumented"].is_string(),
            "unmeasured groups carry the marker, never a zero"
        );
        assert_eq!(parsed["availability"]["hit_rate_permille"], 1000);
    }

    #[test]
    fn b008_report_generates_from_a_real_replay_run() {
        // THE acceptance: an actual replay (StockPath both sides via
        // the faithful-candidate pattern) produces the report.
        use crate::{ExecutionPath, StockPath, replay_session};
        use rabs_protocol::invocation_record::{InvocationRecord, NormalizedOutcome, ToolKind};
        use rabs_protocol::raw_bytes::RawBytes;
        let argv = [RawBytes::from("true")];
        let env: [(RawBytes, RawBytes); 0] = [];
        let record = InvocationRecord::capture(
            ToolKind::CargoWholeCommand,
            &argv,
            &env,
            &RawBytes::from("/tmp"),
            "",
            NormalizedOutcome::Exited(0),
            5,
        );
        let (outcome_kind, outcome_value) = ("exited", 0);
        let line = serde_json::json!({
            "argv_redacted": record.argv_redacted,
            "cwd_redacted": record.cwd_redacted,
            "outcome_kind": outcome_kind,
            "outcome_value": outcome_value,
            "duration_ms": record.duration_ms,
        })
        .to_string();
        struct Wrap(StockPath);
        impl ExecutionPath for Wrap {
            fn name(&self) -> &str {
                "candidate"
            }
            fn execute(&mut self, i: &crate::ReplayCommand) -> crate::PathObservation {
                self.0.execute(i)
            }
        }
        let mut baseline = StockPath;
        let mut candidate = Wrap(StockPath);
        let session = replay_session(&[line.as_str()], &mut baseline, &mut candidate);
        let report = BenchmarkReport::from_session(&session);
        assert_eq!(report.divergence.rows, 1);
        assert_eq!(report.divergence.diverged, 0);
        assert!(report.baseline_latency.is_some());
        let parsed: serde_json::Value = serde_json::from_str(&report.to_ndjson()).unwrap();
        assert_eq!(parsed["divergence"]["rows"], 1);
    }

    #[test]
    fn b013_ci_regression_gate_enforces_baseline_and_override_protocol() {
        let baseline = canonical_ci_baseline_snapshot();
        let healthy_bench = BenchmarkReport {
            baseline_latency: Some(Percentiles {
                p50_ms: 400,
                p90_ms: 700,
                p95_ms: 900,
                samples: 100,
            }),
            candidate_latency: Some(Percentiles {
                p50_ms: 350,
                p90_ms: 600,
                p95_ms: 750,
                samples: 100,
            }),
            availability: AvailabilityMetrics {
                cache_hits: 82,
                executed: 15,
                unavailable: 3,
                hit_rate_permille: 820,
            },
            divergence: DivergenceMetrics {
                rows: 100,
                diverged: 0,
                outcome: 0,
                stdout: 0,
                stderr: 0,
                skipped: 0,
            },
            first_diagnostic_latency: MetricGroup::NotInstrumented { needs: "C007" },
            first_metadata_ready_latency: MetricGroup::NotInstrumented { needs: "K-series" },
            tool_seconds: MetricGroup::NotInstrumented { needs: "B003" },
            queue_delay: MetricGroup::NotInstrumented { needs: "G-series" },
            transfer: MetricGroup::NotInstrumented { needs: "H-series" },
            cpu_memory: MetricGroup::NotInstrumented { needs: "E004" },
            storage_growth: MetricGroup::NotInstrumented { needs: "H014" },
            speculation: MetricGroup::NotInstrumented { needs: "L-series" },
        };

        let healthy_candidate = CorpusCandidateMetrics {
            benchmark: healthy_bench.clone(),
            wrapper_p95_us: 4_500,
            intent_to_result_p95_ms: 3_200,
            selected_strata: 4,
            storage_transfer_growth_permille: 50,
            cancellation_cleanup_healthy: true,
            has_rollback_and_receipt: true,
            compensating_benefit_documented: false,
        };
        let pass_verdict =
            evaluate_corpus_regression_gate(&baseline, &healthy_candidate, None, 1_760_100_000_000);
        assert!(pass_verdict.passed);
        assert!(pass_verdict.unwaived_violations.is_empty());

        // Introduce violations across all 8 dimensions.
        let mut regressed_bench = healthy_bench;
        regressed_bench.availability.hit_rate_permille = 500;
        regressed_bench.divergence.diverged = 1;
        let regressed_candidate = CorpusCandidateMetrics {
            benchmark: regressed_bench,
            wrapper_p95_us: 15_000,
            intent_to_result_p95_ms: 6_000,
            selected_strata: 1,
            storage_transfer_growth_permille: 250,
            cancellation_cleanup_healthy: false,
            has_rollback_and_receipt: false,
            compensating_benefit_documented: false,
        };

        let fail_verdict = evaluate_corpus_regression_gate(
            &baseline,
            &regressed_candidate,
            None,
            1_760_100_000_000,
        );
        assert!(!fail_verdict.passed);
        assert_eq!(fail_verdict.unwaived_violations.len(), 8);

        // DivergenceRegression and MissingRollbackOrReceipt are NEVER waivable even with an active override.
        let override_all = RegressionGateOverride {
            override_id: "ovr-b013-test".to_owned(),
            approver: "rel-eng".to_owned(),
            reason: "temporary storage migration".to_owned(),
            expires_at_unix_ms: 1_760_200_000_000,
            waived_kinds: BTreeSet::from([
                CorpusRegressionKind::WrapperSloExceeded,
                CorpusRegressionKind::IntentToResultP95Regressed,
                CorpusRegressionKind::HitRateDegraded,
                CorpusRegressionKind::DivergenceRegression,
                CorpusRegressionKind::StorageOrTransferBloat,
                CorpusRegressionKind::StratifiedCoverageInsufficient,
                CorpusRegressionKind::CancellationOrCleanupDegraded,
                CorpusRegressionKind::MissingRollbackOrReceipt,
            ]),
        };
        let still_blocked = evaluate_corpus_regression_gate(
            &baseline,
            &regressed_candidate,
            Some(&override_all),
            1_760_100_000_000,
        );
        assert!(!still_blocked.passed);
        assert_eq!(still_blocked.unwaived_violations.len(), 2);
        assert_eq!(still_blocked.waived_violations.len(), 6);

        // Once non-waivable dimensions (divergence + rollback/receipt) are resolved, the valid override passes.
        let mut waivable_only_candidate = regressed_candidate;
        waivable_only_candidate.benchmark.divergence.diverged = 0;
        waivable_only_candidate.has_rollback_and_receipt = true;
        let waived_verdict = evaluate_corpus_regression_gate(
            &baseline,
            &waivable_only_candidate,
            Some(&override_all),
            1_760_100_000_000,
        );
        assert!(waived_verdict.passed);
        assert_eq!(
            waived_verdict.override_applied.as_deref(),
            Some("ovr-b013-test")
        );

        // Expired override no longer waives.
        let expired_verdict = evaluate_corpus_regression_gate(
            &baseline,
            &waivable_only_candidate,
            Some(&override_all),
            1_760_300_000_000,
        );
        assert!(!expired_verdict.passed);
        let parsed: serde_json::Value = serde_json::from_str(&expired_verdict.to_ndjson()).unwrap();
        assert_eq!(parsed["passed"], false);
    }
}
