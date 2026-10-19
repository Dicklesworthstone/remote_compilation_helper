//! Fleet/cache/latency dashboard panels (bead R007, `bd-cl8mf`; plan §6, §105).
//!
//! The panels the plan names, as typed data models built from
//! metric inputs by deterministic integer math (nearest-rank
//! percentiles, permille rates — no floats):
//!
//! - fleet posture + worker pressure;
//! - user-visible latency distribution (p50/p95/p99);
//! - cache effectiveness + miss causes (by stable reason code,
//!   ranked);
//! - served-fraction telemetry (`bd-cl8mf`: `rustc` invocations served
//!   rather than executed from [`DecisionReceipt`]s, long-run `> 90%`
//!   goal, reported rather than gated until the M16 frontier review);
//! - top expensive/repeated crates (bounded, sorted);
//! - action critical paths (bounded, from the I015 estimates);
//! - transfer/CAS health (dedup ratio in permille);
//! - storage/GC/quarantine counters;
//! - determinism/verification status.
//!
//! Empty inputs produce honest zeros, never invented numbers.

use crate::decision_receipt::{CacheLookupDecision, DecisionReceipt};
use crate::descriptor::ActionClass;

/// Long-run §6 goal for fleet `rustc` invocations served rather than
/// executed (`> 90%` = strictly greater than `900` permille in warm,
/// converged workloads).
pub const LONG_RUN_SERVED_GOAL_PERMILLE: u32 = 900;

/// Governance standing of the §6 served-fraction metric (`bd-cl8mf`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ServedFractionStanding {
    /// Reported on dashboards from [`DecisionReceipt`]s, not a blocking
    /// release gate until the Phase 5 / M16 frontier review.
    #[default]
    ReportedNotGated,
}

/// Per-action-class served vs executed breakdown from [`DecisionReceipt`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassServedBreakdown {
    /// Semantic action class.
    pub action_class: ActionClass,
    /// Receipts in this class with [`CacheLookupDecision::Hit`].
    pub served: u64,
    /// Receipts in this class that executed or were refused cache lookup.
    pub executed_or_refused: u64,
    /// Served fraction in permille (`served * 1000 / total`).
    pub served_permille: u32,
}

/// Served-fraction telemetry panel computed from [`DecisionReceipt`]s (`bd-cl8mf`).
///
/// Tracks both the §6 headline metric ("Fleet `rustc` invocations served
/// rather than executed", excluding capability probes and non-`rustc` classes
/// via [`ActionClass::is_rustc_compile`]) and the all-receipts total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedFractionTelemetry {
    /// Total decision receipts inspected across all action classes.
    pub total_receipts: u64,
    /// Total receipts served from cache across all action classes.
    pub total_served: u64,
    /// Served rate across all action classes (permille).
    pub total_served_permille: u32,
    /// Cacheable `rustc` compile receipts inspected (`ActionClass::is_rustc_compile`).
    pub rustc_receipts: u64,
    /// Cacheable `rustc` compile receipts served from cache (`Hit`).
    pub rustc_served: u64,
    /// Cacheable `rustc` compile receipts executed or refused (`Miss` / `Refused`).
    pub rustc_executed: u64,
    /// Fleet `rustc` invocations served rate in permille (`0..=1000`).
    pub rustc_served_permille: u32,
    /// Long-run §6 target threshold in permille (`900` = 90%).
    pub goal_permille: u32,
    /// Whether the observed `rustc` served fraction strictly exceeds the
    /// long-run `> 90%` goal (`rustc_served * 10 > rustc_receipts * 9`).
    pub meets_long_run_goal: bool,
    /// Governance standing (`ReportedNotGated` until the M16 frontier review).
    pub standing: ServedFractionStanding,
    /// Per-class breakdown sorted deterministically by [`ActionClass`].
    pub by_class: Vec<ClassServedBreakdown>,
}

impl Default for ServedFractionTelemetry {
    fn default() -> Self {
        Self {
            total_receipts: 0,
            total_served: 0,
            total_served_permille: 0,
            rustc_receipts: 0,
            rustc_served: 0,
            rustc_executed: 0,
            rustc_served_permille: 0,
            goal_permille: LONG_RUN_SERVED_GOAL_PERMILLE,
            meets_long_run_goal: false,
            standing: ServedFractionStanding::ReportedNotGated,
            by_class: Vec::new(),
        }
    }
}

/// Compute [`ServedFractionTelemetry`] deterministically from a slice of
/// [`DecisionReceipt`]s (`bd-cl8mf`).
#[must_use]
pub fn served_fraction_from_receipts(receipts: &[DecisionReceipt]) -> ServedFractionTelemetry {
    let mut total_receipts = 0_u64;
    let mut total_served = 0_u64;
    let mut rustc_receipts = 0_u64;
    let mut rustc_served = 0_u64;
    let mut rustc_executed = 0_u64;
    let mut per_class: Vec<(ActionClass, u64, u64)> = Vec::new();

    for receipt in receipts {
        total_receipts += 1;
        let is_hit = matches!(receipt.cache_lookup, CacheLookupDecision::Hit);
        if is_hit {
            total_served += 1;
        }
        if receipt.invocation_class.is_rustc_compile() {
            rustc_receipts += 1;
            if is_hit {
                rustc_served += 1;
            } else {
                rustc_executed += 1;
            }
        }
        match per_class
            .iter_mut()
            .find(|(c, _, _)| *c == receipt.invocation_class)
        {
            Some((_, served, exec)) => {
                if is_hit {
                    *served += 1;
                } else {
                    *exec += 1;
                }
            }
            None => {
                let (s, e) = if is_hit { (1, 0) } else { (0, 1) };
                per_class.push((receipt.invocation_class, s, e));
            }
        }
    }

    per_class.sort_by_key(|(class, _, _)| *class);
    let by_class = per_class
        .into_iter()
        .map(|(action_class, served, executed_or_refused)| {
            let class_total = served + executed_or_refused;
            let served_permille =
                u32::try_from((served * 1_000).checked_div(class_total).unwrap_or(0)).unwrap_or(0);
            ClassServedBreakdown {
                action_class,
                served,
                executed_or_refused,
                served_permille,
            }
        })
        .collect();

    let total_served_permille = u32::try_from(
        (total_served * 1_000)
            .checked_div(total_receipts)
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let rustc_served_permille = u32::try_from(
        (rustc_served * 1_000)
            .checked_div(rustc_receipts)
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let meets_long_run_goal = rustc_receipts > 0
        && (rustc_served * 1_000) > rustc_receipts * u64::from(LONG_RUN_SERVED_GOAL_PERMILLE);

    ServedFractionTelemetry {
        total_receipts,
        total_served,
        total_served_permille,
        rustc_receipts,
        rustc_served,
        rustc_executed,
        rustc_served_permille,
        goal_permille: LONG_RUN_SERVED_GOAL_PERMILLE,
        meets_long_run_goal,
        standing: ServedFractionStanding::ReportedNotGated,
        by_class,
    }
}

/// Worker posture states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum WorkerState {
    Healthy,
    Degraded,
    Browned0ut,
    Excluded,
    Offline,
}

/// Fleet posture panel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FleetPosture {
    /// Workers per state: (state ordinal, count) — healthy, degraded,
    /// browned-out, excluded, offline.
    pub counts: [u32; 5],
    /// Mean pressure (permille) across reporting workers.
    pub mean_pressure_permille: u32,
}

/// Latency distribution panel (nearest-rank percentiles).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LatencyPanel {
    /// Samples observed.
    pub samples: u64,
    /// p50 (ms).
    pub p50_ms: u64,
    /// p95 (ms).
    pub p95_ms: u64,
    /// p99 (ms).
    pub p99_ms: u64,
}

/// Cache effectiveness panel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachePanel {
    /// Hit rate (permille of lookups).
    pub hit_rate_permille: u32,
    /// Miss causes ranked by count: (stable reason code, count).
    pub miss_causes: Vec<(&'static str, u64)>,
}

/// One top-crate row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateRow {
    /// Crate name.
    pub name: String,
    /// Total compile ms spent.
    pub total_ms: u64,
    /// Times compiled in the window.
    pub compiles: u64,
}

/// Transfer/CAS health panel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferPanel {
    /// Bytes requested logically.
    pub logical_bytes: u64,
    /// Bytes actually moved after dedup.
    pub physical_bytes: u64,
    /// Dedup savings (permille of logical bytes NOT moved).
    pub dedup_savings_permille: u32,
}

/// Storage/GC/quarantine panel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoragePanel {
    /// Bytes in the store.
    pub used_bytes: u64,
    /// Objects evicted by GC in the window.
    pub gc_evictions: u64,
    /// Objects currently quarantined (T044/H003).
    pub quarantined: u64,
}

/// Determinism/verification panel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationPanel {
    /// Verification runs in the window.
    pub runs: u64,
    /// Runs that passed.
    pub passed: u64,
    /// Divergence incidents opened.
    pub divergences: u64,
}

/// The dashboard: every panel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dashboard {
    /// Fleet posture.
    pub fleet: FleetPosture,
    /// Latency distribution.
    pub latency: LatencyPanel,
    /// Cache effectiveness.
    pub cache: CachePanel,
    /// Served-fraction telemetry from [`DecisionReceipt`]s (`bd-cl8mf`).
    pub served_fraction: ServedFractionTelemetry,
    /// Top crates (bounded to 10, sorted by total ms).
    pub top_crates: Vec<CrateRow>,
    /// Top critical paths (bounded to 10): (target label, chain ms).
    pub critical_paths: Vec<(String, u64)>,
    /// Transfer health.
    pub transfer: TransferPanel,
    /// Storage health.
    pub storage: StoragePanel,
    /// Verification status.
    pub verification: VerificationPanel,
}

/// Nearest-rank percentile over sorted samples.
fn percentile(sorted: &[u64], p: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * sorted.len() as u64).div_ceil(100).max(1) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

/// The raw metric inputs (from telemetry, on a fixture fleet here).
#[derive(Debug, Clone, Default)]
pub struct MetricInputs {
    /// Worker states + pressure permille.
    pub workers: Vec<(WorkerState, u32)>,
    /// Latency samples (ms).
    pub latencies_ms: Vec<u64>,
    /// Cache lookups: `Ok(())` hit, `Err(reason)` miss.
    pub lookups: Vec<Result<(), &'static str>>,
    /// Decision receipts feeding served-fraction telemetry (`bd-cl8mf`).
    pub receipts: Vec<DecisionReceipt>,
    /// Per-crate (name, ms, compiles).
    pub crates: Vec<(String, u64, u64)>,
    /// Critical paths: (label, chain ms).
    pub critical_paths: Vec<(String, u64)>,
    /// Transfer (logical, physical) bytes.
    pub transfer: (u64, u64),
    /// Storage (used, gc evictions, quarantined).
    pub storage: (u64, u64, u64),
    /// Verification (runs, passed, divergences).
    pub verification: (u64, u64, u64),
}

/// Build every panel from the inputs.
#[must_use]
pub fn build(inputs: &MetricInputs) -> Dashboard {
    // Fleet posture.
    let mut counts = [0_u32; 5];
    let mut pressure_sum = 0_u64;
    for (state, pressure) in &inputs.workers {
        let idx = match state {
            WorkerState::Healthy => 0,
            WorkerState::Degraded => 1,
            WorkerState::Browned0ut => 2,
            WorkerState::Excluded => 3,
            WorkerState::Offline => 4,
        };
        counts[idx] += 1;
        pressure_sum += u64::from(*pressure);
    }
    let mean_pressure_permille = u32::try_from(
        pressure_sum
            .checked_div(inputs.workers.len() as u64)
            .unwrap_or(0),
    )
    .unwrap_or(u32::MAX);
    // Latency percentiles.
    let mut sorted = inputs.latencies_ms.clone();
    sorted.sort_unstable();
    let latency = LatencyPanel {
        samples: sorted.len() as u64,
        p50_ms: percentile(&sorted, 50),
        p95_ms: percentile(&sorted, 95),
        p99_ms: percentile(&sorted, 99),
    };
    // Cache effectiveness + ranked miss causes.
    let hits = inputs.lookups.iter().filter(|l| l.is_ok()).count() as u64;
    let total = inputs.lookups.len() as u64;
    let hit_rate_permille =
        u32::try_from((hits * 1_000).checked_div(total).unwrap_or(0)).unwrap_or(0);
    let mut causes: Vec<(&'static str, u64)> = Vec::new();
    for lookup in &inputs.lookups {
        if let Err(reason) = lookup {
            match causes.iter_mut().find(|(r, _)| r == reason) {
                Some((_, n)) => *n += 1,
                None => causes.push((reason, 1)),
            }
        }
    }
    causes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let served_fraction = served_fraction_from_receipts(&inputs.receipts);
    // Top crates, bounded and sorted.
    let mut top_crates: Vec<CrateRow> = inputs
        .crates
        .iter()
        .map(|(name, total_ms, compiles)| CrateRow {
            name: name.clone(),
            total_ms: *total_ms,
            compiles: *compiles,
        })
        .collect();
    top_crates.sort_by(|a, b| b.total_ms.cmp(&a.total_ms).then(a.name.cmp(&b.name)));
    top_crates.truncate(10);
    let mut critical_paths = inputs.critical_paths.clone();
    critical_paths.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    critical_paths.truncate(10);
    // Transfer dedup.
    let (logical, physical) = inputs.transfer;
    let saved = logical.saturating_sub(physical);
    let dedup_savings_permille =
        u32::try_from((saved * 1_000).checked_div(logical).unwrap_or(0)).unwrap_or(0);
    Dashboard {
        fleet: FleetPosture {
            counts,
            mean_pressure_permille,
        },
        latency,
        cache: CachePanel {
            hit_rate_permille,
            miss_causes: causes,
        },
        served_fraction,
        top_crates,
        critical_paths,
        transfer: TransferPanel {
            logical_bytes: logical,
            physical_bytes: physical,
            dedup_savings_permille,
        },
        storage: StoragePanel {
            used_bytes: inputs.storage.0,
            gc_evictions: inputs.storage.1,
            quarantined: inputs.storage.2,
        },
        verification: VerificationPanel {
            runs: inputs.verification.0,
            passed: inputs.verification.1,
            divergences: inputs.verification.2,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_receipt::{
        PublicationDecision, RECEIPT_SCHEMA_VERSION, ReceiptStore, SingleflightDecision,
        VerificationDecision,
    };
    use crate::result_identity::{DigestAlgorithm, TypedDigest};
    use std::path::Path;

    fn sample_digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    fn receipt_with(
        request_id: u64,
        invocation_class: ActionClass,
        cache_lookup: CacheLookupDecision,
    ) -> DecisionReceipt {
        DecisionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION,
            request_id,
            invocation_class,
            key_breakdown_digest: sample_digest(1),
            snapshot_root: sample_digest(2),
            closure_object_count: 10,
            cache_lookup,
            singleflight: SingleflightDecision::Leader,
            subscriber_count: 1,
            worker_candidates: Vec::new(),
            selected_worker: Some(1),
            selection_reasons: vec!["BEST_HEALTH"],
            transfer_objects: 0,
            transfer_bytes_estimate: 0,
            priority_class_tag: 1,
            budget_ms: 10_000,
            attempt_authority: sample_digest(3),
            lifecycle_events: Vec::new(),
            provisional_events: Vec::new(),
            verification: VerificationDecision::NotRequired,
            publication: PublicationDecision::Published,
            latency_ms: 25,
            cpu_ms: 20,
            fallback_reason: None,
            non_claims: Vec::new(),
        }
    }

    fn fixture_fleet() -> MetricInputs {
        MetricInputs {
            workers: vec![
                (WorkerState::Healthy, 200),
                (WorkerState::Healthy, 400),
                (WorkerState::Browned0ut, 900),
                (WorkerState::Excluded, 1_000),
            ],
            latencies_ms: (1..=100).collect(), // 1..100ms uniform
            lookups: vec![
                Ok(()),
                Ok(()),
                Ok(()),
                Err("WHY_KEY_COMPONENT_CHANGED"),
                Err("WHY_KEY_COMPONENT_CHANGED"),
                Err("CACHE_REFUSED_BENCHMARK_OBSERVATION"),
            ],
            receipts: vec![
                receipt_with(
                    1,
                    ActionClass::RustcDependencyCompile,
                    CacheLookupDecision::Hit,
                ),
                receipt_with(
                    2,
                    ActionClass::RustcDependencyCompile,
                    CacheLookupDecision::Hit,
                ),
                receipt_with(
                    3,
                    ActionClass::RustcWorkspaceCompile,
                    CacheLookupDecision::Hit,
                ),
                receipt_with(
                    4,
                    ActionClass::RustcWorkspaceCompile,
                    CacheLookupDecision::Miss,
                ),
                receipt_with(
                    5,
                    ActionClass::ToolchainProbe,
                    CacheLookupDecision::Refused("PROBE_PASSTHROUGH"),
                ),
            ],
            crates: vec![
                ("serde".into(), 40_000, 12),
                ("tokio".into(), 90_000, 3),
                ("tiny".into(), 500, 40),
            ],
            critical_paths: vec![("bin/rch".into(), 2_900), ("tests".into(), 5_100)],
            transfer: (10_000_000, 2_500_000),
            storage: (4_000_000_000, 120, 2),
            verification: (500, 499, 1),
        }
    }

    #[test]
    fn the_fixture_fleet_feeds_every_panel_with_pinned_numbers() {
        // THE acceptance: every panel populated from live-shaped
        // metric inputs, numbers exact.
        let dash = build(&fixture_fleet());
        assert_eq!(dash.fleet.counts, [2, 0, 1, 1, 0]);
        assert_eq!(dash.fleet.mean_pressure_permille, 625);
        assert_eq!(dash.latency.samples, 100);
        assert_eq!(
            (
                dash.latency.p50_ms,
                dash.latency.p95_ms,
                dash.latency.p99_ms
            ),
            (50, 95, 99),
            "nearest-rank percentiles on the uniform fixture"
        );
        assert_eq!(dash.cache.hit_rate_permille, 500);
        assert_eq!(
            dash.cache.miss_causes,
            vec![
                ("WHY_KEY_COMPONENT_CHANGED", 2),
                ("CACHE_REFUSED_BENCHMARK_OBSERVATION", 1),
            ],
            "miss causes ranked by count with stable codes"
        );
        // Served-fraction telemetry from decision receipts (bd-cl8mf):
        // 4 rustc compile receipts (3 Hit, 1 Miss) = 750 permille;
        // ToolchainProbe is excluded from the rustc denominator but counted in total_receipts (3/5 = 600 permille).
        assert_eq!(dash.served_fraction.total_receipts, 5);
        assert_eq!(dash.served_fraction.total_served, 3);
        assert_eq!(dash.served_fraction.total_served_permille, 600);
        assert_eq!(dash.served_fraction.rustc_receipts, 4);
        assert_eq!(dash.served_fraction.rustc_served, 3);
        assert_eq!(dash.served_fraction.rustc_executed, 1);
        assert_eq!(dash.served_fraction.rustc_served_permille, 750);
        assert_eq!(
            dash.served_fraction.goal_permille,
            LONG_RUN_SERVED_GOAL_PERMILLE
        );
        assert!(!dash.served_fraction.meets_long_run_goal);
        assert_eq!(
            dash.served_fraction.standing,
            ServedFractionStanding::ReportedNotGated
        );
        // Top crates by total ms, not by compile count.
        assert_eq!(dash.top_crates[0].name, "tokio");
        assert_eq!(dash.top_crates[1].name, "serde");
        // Critical paths ranked.
        assert_eq!(dash.critical_paths[0], ("tests".into(), 5_100));
        // Transfer: 7.5MB of 10MB not moved = 750 permille.
        assert_eq!(dash.transfer.dedup_savings_permille, 750);
        assert_eq!(dash.storage.quarantined, 2);
        assert_eq!(dash.verification.divergences, 1);
    }

    #[test]
    fn empty_inputs_produce_honest_zeros() {
        let dash = build(&MetricInputs::default());
        assert_eq!(dash.fleet.counts, [0; 5]);
        assert_eq!(dash.latency.samples, 0);
        assert_eq!(dash.latency.p99_ms, 0);
        assert_eq!(dash.cache.hit_rate_permille, 0);
        assert!(dash.cache.miss_causes.is_empty());
        assert_eq!(dash.served_fraction.total_receipts, 0);
        assert_eq!(dash.served_fraction.rustc_receipts, 0);
        assert_eq!(dash.served_fraction.rustc_served_permille, 0);
        assert!(!dash.served_fraction.meets_long_run_goal);
        assert_eq!(
            dash.served_fraction.standing,
            ServedFractionStanding::ReportedNotGated
        );
        assert!(dash.served_fraction.by_class.is_empty());
        assert!(dash.top_crates.is_empty());
        assert_eq!(dash.transfer.dedup_savings_permille, 0);
    }

    #[test]
    fn served_fraction_from_receipt_store_enforces_strict_90_percent_goal() {
        let mut store = ReceiptStore::default();
        // 9 hits + 1 miss = 900 permille (exactly 90.0%, NOT "> 90%").
        for id in 1..=9 {
            store
                .append(receipt_with(
                    id,
                    ActionClass::RustcDependencyCompile,
                    CacheLookupDecision::Hit,
                ))
                .expect("valid v1 receipt");
        }
        store
            .append(receipt_with(
                10,
                ActionClass::RustcWorkspaceCompile,
                CacheLookupDecision::Miss,
            ))
            .expect("valid v1 receipt");

        let exact_90 = served_fraction_from_receipts(store.as_slice());
        assert_eq!(exact_90.rustc_served_permille, 900);
        assert!(
            !exact_90.meets_long_run_goal,
            "sec6 specifies '> 90%', so 900 permille does not yet cross the threshold"
        );

        // Add one more served rustc compile -> 10/11 = 909 permille (> 90%).
        store
            .append(receipt_with(
                11,
                ActionClass::ClippyCompile,
                CacheLookupDecision::Hit,
            ))
            .expect("valid v1 receipt");
        let above_90 = served_fraction_from_receipts(store.as_slice());
        assert_eq!(above_90.rustc_receipts, 11);
        assert_eq!(above_90.rustc_served, 10);
        assert_eq!(above_90.rustc_served_permille, 909);
        assert!(above_90.meets_long_run_goal);
        assert_eq!(above_90.standing, ServedFractionStanding::ReportedNotGated);
        assert_eq!(above_90.by_class.len(), 3);
    }

    #[test]
    fn gate_ledger_covers_every_section_6_target() {
        // bd-cl8mf rule: "benchmarks/GATE_LEDGER.md: one row per sec6 target
        // with status ENFORCING/PENDING(phase), owning gate bead, last result,
        // evidence link... a target absent from the ledger is a defect."
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let master_plan = std::fs::read_to_string(
            repo_root.join("COMPREHENSIVE_MASTER_PLAN_FOR_RABS_ASUPERSYNC_NATIVE.md"),
        )
        .expect("read master plan");
        let ledger = std::fs::read_to_string(repo_root.join("benchmarks/GATE_LEDGER.md"))
            .expect("read benchmarks/GATE_LEDGER.md");

        // Extract every target metric from §6 of the master plan.
        let sec6 = master_plan
            .split("## 6. Quantitative product targets")
            .nth(1)
            .and_then(|rest| rest.split("\n## 7.").next())
            .expect("locate §6 in master plan");
        let sec6_metrics: Vec<&str> = sec6
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if !trimmed.starts_with('|') {
                    return None;
                }
                let cols: Vec<&str> = trimmed.split('|').map(str::trim).collect();
                if cols.len() < 3 {
                    return None;
                }
                let metric = cols[1];
                if metric.is_empty() || metric == "Metric" || metric.starts_with("---") {
                    return None;
                }
                Some(metric)
            })
            .collect();
        assert_eq!(
            sec6_metrics.len(),
            11,
            "expected 11 §6 quantitative targets in master plan"
        );

        // Parse rows from benchmarks/GATE_LEDGER.md.
        let mut ledger_rows: Vec<(String, String, String, String, String)> = Vec::new();
        for line in ledger.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('|') {
                continue;
            }
            let cols: Vec<&str> = trimmed.split('|').map(str::trim).collect();
            if cols.len() < 7 {
                continue;
            }
            let metric = cols[1];
            if metric.is_empty() || metric == "Metric" || metric.starts_with("---") {
                continue;
            }
            let status = cols[3].trim_matches('`');
            let owning_bead = cols[4];
            let last_result = cols[5];
            let evidence = cols[6];
            assert!(
                status == "ENFORCING"
                    || (status.starts_with("PENDING(Phase ") && status.ends_with(')')),
                "invalid status `{status}` for metric `{metric}` in GATE_LEDGER.md"
            );
            assert!(
                !owning_bead.is_empty(),
                "missing owning gate bead for `{metric}` in GATE_LEDGER.md"
            );
            assert!(
                !last_result.is_empty(),
                "missing last result for `{metric}` in GATE_LEDGER.md"
            );
            assert!(
                evidence.contains("]("),
                "missing markdown evidence link for `{metric}` in GATE_LEDGER.md"
            );
            for segment in evidence.split("](").skip(1) {
                let rel_link = segment.split(')').next().unwrap_or("");
                let resolved = repo_root.join("benchmarks").join(rel_link);
                assert!(
                    resolved.exists(),
                    "evidence link `{rel_link}` for `{metric}` does not exist at {}",
                    resolved.display()
                );
            }
            ledger_rows.push((
                metric.to_string(),
                status.to_string(),
                owning_bead.to_string(),
                last_result.to_string(),
                evidence.to_string(),
            ));
        }

        for expected in &sec6_metrics {
            assert!(
                ledger_rows.iter().any(|(m, _, _, _, _)| m == expected),
                "§6 target `{expected}` is absent from benchmarks/GATE_LEDGER.md (defect per bd-cl8mf)"
            );
        }
        assert_eq!(
            ledger_rows.len(),
            sec6_metrics.len(),
            "GATE_LEDGER.md must have exactly one row per §6 target"
        );
    }

    #[test]
    fn top_lists_are_bounded() {
        let mut inputs = MetricInputs::default();
        for i in 0..50_u64 {
            inputs.crates.push((format!("crate{i}"), i, 1));
            inputs.critical_paths.push((format!("path{i}"), i));
        }
        let dash = build(&inputs);
        assert_eq!(dash.top_crates.len(), 10);
        assert_eq!(dash.critical_paths.len(), 10);
        // And they kept the LARGEST, sorted descending.
        assert_eq!(dash.top_crates[0].total_ms, 49);
        assert!(
            dash.top_crates
                .windows(2)
                .all(|w| w[0].total_ms >= w[1].total_ms)
        );
    }

    #[test]
    fn percentiles_are_deterministic_nearest_rank() {
        assert_eq!(percentile(&[], 99), 0);
        assert_eq!(percentile(&[7], 50), 7);
        assert_eq!(percentile(&[1, 2, 3, 4], 50), 2);
        assert_eq!(percentile(&[1, 2, 3, 4], 99), 4);
    }
}
