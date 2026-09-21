//! Advisory pool-sizing reports (bead I013; plan §84; ADVISORY only).
//!
//! Queueing-theoretic sizing for the eight pool families. The math is
//! the standard M/M/c heuristic on integer permille: with arrival
//! rate λ (jobs per tick, permille) and per-worker service rate μ,
//! utilization ρ = λ/(cμ); the recommendation targets a utilization
//! band — too hot (>800‰) recommends growth toward the band, too
//! cold (<300‰) recommends shrink, in-band holds. Confidence comes
//! from the observation count (the I005 discipline: earned, never
//! asserted).
//!
//! ADVISORY: the report type has no apply/resize method — the I017
//! opt-in gate consumes these reports as its evidence trail before
//! managed resizing may ever be enabled.

/// The eight pool families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PoolFamily {
    CompilerActions,
    HashingWorkers,
    CasReaders,
    CasWriters,
    CompressionWorkers,
    Linkers,
    NativeBuilds,
    TestProcesses,
}

impl PoolFamily {
    /// All families.
    pub const ALL: [Self; 8] = [
        Self::CompilerActions,
        Self::HashingWorkers,
        Self::CasReaders,
        Self::CasWriters,
        Self::CompressionWorkers,
        Self::Linkers,
        Self::NativeBuilds,
        Self::TestProcesses,
    ];
}

/// Observed load for one pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolObservation {
    /// The family.
    pub family: PoolFamily,
    /// Current pool size.
    pub current_size: u32,
    /// Arrival rate, jobs per 1000 ticks.
    pub arrival_rate_permille: u64,
    /// Per-worker service rate, jobs per 1000 ticks.
    pub service_rate_permille: u64,
    /// Completed-job observations backing the rates.
    pub observations: u64,
}

/// The advisory recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizingAdvice {
    /// Grow to the recommended size.
    Grow {
        /// Recommended size.
        to: u32,
    },
    /// Shrink to the recommended size.
    Shrink {
        /// Recommended size.
        to: u32,
    },
    /// Hold current size.
    Hold,
    /// The pool is hot but already has `u32::MAX` workers. No larger
    /// size is representable; this is not a healthy hold recommendation.
    CapacityLimitReached,
}

/// One report row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolReport {
    /// The family.
    pub family: PoolFamily,
    /// Utilization in whole permille, rounded down and capped at
    /// `u64::MAX`. Advice uses the exact ratio before this narrowing.
    pub utilization_permille: u64,
    /// The advice.
    pub advice: SizingAdvice,
    /// Confidence permille (earned from observations, capped 950).
    pub confidence_permille: u16,
}

/// Utilization band (permille).
pub const HOT_THRESHOLD: u64 = 800;
/// Cold threshold (permille).
pub const COLD_THRESHOLD: u64 = 300;
/// Target utilization for resize recommendations (permille).
pub const TARGET_UTILIZATION: u64 = 600;

/// Produce the advisory report for one pool.
#[must_use]
pub fn advise(observation: &PoolObservation) -> PoolReport {
    // Rates are u64 and sizes u32; their products and the threshold
    // comparisons fit in u128. Keep the existing one-unit service floor.
    let service = u128::from(observation.service_rate_permille.max(1));
    let capacity = u128::from(observation.current_size.max(1)) * service;
    let scaled_arrival = u128::from(observation.arrival_rate_permille) * 1_000;
    let utilization_permille = u64::try_from(scaled_arrival / capacity).unwrap_or(u64::MAX);
    // The minimum whole-worker size meeting the target must round UP.
    // Rounding down can turn a cold pool into an overloaded pool on shrink.
    let target_size = scaled_arrival
        .div_ceil(u128::from(TARGET_UTILIZATION) * service)
        .max(1);
    let target_size = u32::try_from(target_size).unwrap_or(u32::MAX);
    let needs_first_worker = observation.current_size == 0 && observation.arrival_rate_permille > 0;
    let advice = if scaled_arrival > u128::from(HOT_THRESHOLD) * capacity || needs_first_worker {
        match observation.current_size.checked_add(1) {
            Some(next_size) => SizingAdvice::Grow {
                to: target_size.max(next_size),
            },
            None => SizingAdvice::CapacityLimitReached,
        }
    } else if scaled_arrival < u128::from(COLD_THRESHOLD) * capacity && observation.current_size > 1 {
        SizingAdvice::Shrink {
            to: target_size.min(observation.current_size - 1).max(1),
        }
    } else {
        SizingAdvice::Hold
    };
    // Confidence earned by observations: 0 obs = 0; caps at 950 —
    // advisory output never claims certainty.
    let confidence = observation.observations.saturating_mul(10).min(950);
    PoolReport {
        family: observation.family,
        utilization_permille,
        advice,
        confidence_permille: u16::try_from(confidence).unwrap_or(950),
    }
}

/// Produce the full advisory report (one row per observed family).
#[must_use]
pub fn advisory_report(observations: &[PoolObservation]) -> Vec<PoolReport> {
    observations.iter().map(advise).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(
        family: PoolFamily,
        size: u32,
        arrival: u64,
        service: u64,
        n: u64,
    ) -> PoolObservation {
        PoolObservation {
            family,
            current_size: size,
            arrival_rate_permille: arrival,
            service_rate_permille: service,
            observations: n,
        }
    }

    #[test]
    fn reports_carry_recommendations_and_confidence() {
        // THE acceptance: a full report with advice + confidence.
        let observations: Vec<PoolObservation> = PoolFamily::ALL
            .iter()
            .map(|f| observation(*f, 4, 2_000, 1_000, 60))
            .collect();
        let report = advisory_report(&observations);
        assert_eq!(report.len(), 8, "one row per family");
        for row in &report {
            // 2000/(4*1000) = 500 permille: in-band, hold.
            assert_eq!(row.utilization_permille, 500);
            assert_eq!(row.advice, SizingAdvice::Hold);
            assert_eq!(row.confidence_permille, 600, "earned from 60 obs");
        }
    }

    #[test]
    fn hot_pools_grow_toward_the_target_band() {
        // Linkers saturated: 4 workers, utilization 1500 permille.
        let hot = observation(PoolFamily::Linkers, 4, 6_000, 1_000, 100);
        let report = advise(&hot);
        assert_eq!(report.utilization_permille, 1_500);
        let SizingAdvice::Grow { to } = report.advice else {
            panic!("hot pool must grow");
        };
        // Target: 6000*1000/(600*1000) = 10 workers -> 600 permille.
        assert_eq!(to, 10);
    }

    #[test]
    fn cold_pools_shrink_but_never_below_one() {
        let cold = observation(PoolFamily::CompressionWorkers, 8, 500, 1_000, 100);
        let report = advise(&cold);
        assert_eq!(report.utilization_permille, 62);
        assert_eq!(report.advice, SizingAdvice::Shrink { to: 1 });
        // A single cold worker holds (no shrink to zero).
        let lone = observation(PoolFamily::CasReaders, 1, 10, 1_000, 100);
        assert_eq!(advise(&lone).advice, SizingAdvice::Hold);
    }

    #[test]
    fn confidence_is_earned_and_capped_and_advice_is_advisory_only() {
        // Zero observations: zero confidence.
        let fresh = observation(PoolFamily::TestProcesses, 4, 2_000, 1_000, 0);
        assert_eq!(advise(&fresh).confidence_permille, 0);
        // Confidence caps below certainty.
        let seasoned = observation(PoolFamily::TestProcesses, 4, 2_000, 1_000, 1_000_000);
        assert_eq!(advise(&seasoned).confidence_permille, 950);
        // ADVISORY: the report type has no apply/resize surface — the
        // exhaustive destructure pins the fields (I017 consumes this
        // as evidence; nothing here mutates a pool).
        let PoolReport {
            family: _,
            utilization_permille: _,
            advice: _,
            confidence_permille: _,
        } = advise(&fresh);
    }

    #[test]
    fn rounding_up_prevents_shrinking_a_cold_pool_into_overload() {
        for family in PoolFamily::ALL {
            let mut load = observation(family, 4, 1_100, 1_000, 100);
            let report = advise(&load);
            assert_eq!(report.utilization_permille, 275);
            assert_eq!(report.advice, SizingAdvice::Shrink { to: 2 });
            // The old floor recommended one worker: utilization 1100.
            // Applying the advisory size in this model should instead hold
            // within the target band, not immediately call for more workers.
            load.current_size = 2;
            assert_eq!(advise(&load).utilization_permille, 550);
            assert_eq!(advise(&load).advice, SizingAdvice::Hold);
        }
    }

    #[test]
    fn utilization_thresholds_are_compared_before_display_rounding() {
        for (arrival, advice) in [
            (1_199, SizingAdvice::Shrink { to: 2 }),
            (1_200, SizingAdvice::Hold),
            (3_200, SizingAdvice::Hold),
            (3_201, SizingAdvice::Grow { to: 6 }),
        ] {
            let load = observation(PoolFamily::CompilerActions, 4, arrival, 1_000, 100);
            assert_eq!(advise(&load).advice, advice, "arrival={arrival}");
        }
        let barely_hot = observation(PoolFamily::CompilerActions, 4, 3_201, 1_000, 100);
        assert_eq!(advise(&barely_hot).utilization_permille, 800);
    }

    #[test]
    fn full_width_rates_and_capacity_keep_their_exact_quotients() {
        for (size, utilization, advice) in [
            (1, 1_000, SizingAdvice::Grow { to: 2 }),
            (4, 250, SizingAdvice::Shrink { to: 2 }),
            (u32::MAX, 0, SizingAdvice::Shrink { to: 2 }),
        ] {
            let load = observation(PoolFamily::HashingWorkers, size, u64::MAX, u64::MAX, 100);
            let report = advise(&load);
            assert_eq!(report.utilization_permille, utilization);
            assert_eq!(report.advice, advice);
        }
    }

    #[test]
    fn a_hot_maximum_size_pool_reports_the_limit_instead_of_wrapping() {
        let load = observation(PoolFamily::CasWriters, u32::MAX, u64::MAX, 1, 100);
        let report = advise(&load);
        assert_eq!(report.advice, SizingAdvice::CapacityLimitReached);
        // (2^64 - 1) / (2^32 - 1) = 2^32 + 1.
        assert_eq!(report.utilization_permille, 4_294_967_297_000);
    }

    #[test]
    fn oversized_reports_and_targets_saturate_only_after_exact_calculation() {
        let load = observation(PoolFamily::Linkers, 1, u64::MAX, 1, u64::MAX);
        let report = advise(&load);
        assert_eq!(report.utilization_permille, u64::MAX);
        assert_eq!(report.advice, SizingAdvice::Grow { to: u32::MAX });
        assert_eq!(report.confidence_permille, 950);
    }

    #[test]
    fn confidence_never_wraps_or_exceeds_its_evidence_cap() {
        for (samples, confidence) in [
            (0, 0),
            (1, 10),
            (94, 940),
            (95, 950),
            (u64::MAX / 10 + 1, 950),
            (u64::MAX, 950),
        ] {
            let load = observation(PoolFamily::TestProcesses, 1, 1, 1, samples);
            assert_eq!(advise(&load).confidence_permille, confidence);
        }
    }

    #[test]
    fn a_nonempty_arrival_stream_needs_a_worker_even_below_the_hot_threshold() {
        let idle = observation(PoolFamily::NativeBuilds, 0, 0, 0, 0);
        assert_eq!(advise(&idle).advice, SizingAdvice::Hold);
        assert_eq!(advise(&idle).utilization_permille, 0);
        for service in [0, 1_000, u64::MAX] {
            let load = observation(PoolFamily::NativeBuilds, 0, 1, service, 10);
            let expected = if service == 0 { 2 } else { 1 };
            assert_eq!(advise(&load).advice, SizingAdvice::Grow { to: expected });
        }
    }

    #[test]
    fn small_recommendations_match_a_minimum_worker_search() {
        for size in 1..=10_u32 {
            for service in 1..=10_u64 {
                for arrival in 0..=50_u64 {
                    let load =
                        observation(PoolFamily::CompilerActions, size, arrival, service, 100);
                    let report = advise(&load);
                    // Enumerate candidates instead of duplicating div_ceil.
                    let target = (1..=100_u32)
                        .find(|n| u64::from(*n) * service * 600 >= arrival * 1_000)
                        .unwrap();
                    let capacity = u64::from(size) * service;
                    let expected = if arrival * 1_000 > capacity * 800 {
                        assert!(target > size);
                        SizingAdvice::Grow { to: target }
                    } else if arrival * 1_000 < capacity * 300 && size > 1 {
                        assert!(target < size);
                        SizingAdvice::Shrink { to: target }
                    } else {
                        SizingAdvice::Hold
                    };
                    assert_eq!(
                        report.advice, expected,
                        "size={size}, service={service}, arrival={arrival}"
                    );
                }
            }
        }
    }
}
