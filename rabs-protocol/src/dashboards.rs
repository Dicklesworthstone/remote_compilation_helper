//! Fleet/cache/latency dashboard panels (bead R007; plan §105).
//!
//! The eight panels the plan names, as typed data models built from
//! metric inputs by deterministic integer math (nearest-rank
//! percentiles, permille rates — no floats):
//!
//! - fleet posture + worker pressure;
//! - user-visible latency distribution (p50/p95/p99);
//! - cache effectiveness + miss causes (by stable reason code,
//!   ranked);
//! - top expensive/repeated crates (bounded, sorted);
//! - action critical paths (bounded, from the I015 estimates);
//! - transfer/CAS health (dedup ratio in permille);
//! - storage/GC/quarantine counters;
//! - determinism/verification status.
//!
//! Empty inputs produce honest zeros, never invented numbers.

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
        assert!(dash.top_crates.is_empty());
        assert_eq!(dash.transfer.dedup_savings_permille, 0);
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
