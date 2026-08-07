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
}

/// One report row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolReport {
    /// The family.
    pub family: PoolFamily,
    /// Utilization, permille.
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
    let capacity =
        u64::from(observation.current_size.max(1)) * observation.service_rate_permille.max(1);
    let utilization_permille = observation.arrival_rate_permille * 1000 / capacity;
    // Size that lands utilization at the target.
    let target_size = (observation.arrival_rate_permille * 1000
        / (TARGET_UTILIZATION * observation.service_rate_permille.max(1)))
    .max(1);
    let target_size = u32::try_from(target_size).unwrap_or(u32::MAX);
    let advice = if utilization_permille > HOT_THRESHOLD {
        SizingAdvice::Grow {
            to: target_size.max(observation.current_size + 1),
        }
    } else if utilization_permille < COLD_THRESHOLD && observation.current_size > 1 {
        SizingAdvice::Shrink {
            to: target_size.min(observation.current_size - 1).max(1),
        }
    } else {
        SizingAdvice::Hold
    };
    // Confidence earned by observations: 0 obs = 0; caps at 950 —
    // advisory output never claims certainty.
    let confidence = (observation.observations * 10).min(950);
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
}
