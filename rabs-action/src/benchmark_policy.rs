//! Benchmark-run non-cacheability + hardware/load scoping (bead O016;
//! plan §102; risk R92; enforces the E001 BenchmarkRun row).
//!
//! A benchmark result is an OBSERVATION OF A MACHINE UNDER A LOAD —
//! serving one from cache reports a measurement of a run that did not
//! happen. The enforcement:
//!
//! - any cache attempt (lookup, publish, serve) against a
//!   `BenchmarkRun` action REFUSES with a typed reason — the policy
//!   has no cacheable arm;
//! - remote scheduling exists only against an EXPLICIT hardware +
//!   pressure profile: the requester names the CPU cohort and the
//!   maximum acceptable load, the observation records what actually
//!   held, and a mismatch is a refusal, not a footnote;
//! - a benchmark harness DECLARED functional/deterministic is not a
//!   benchmark run at all: it reclassifies to `TestBinaryBatch` and
//!   the ordinary test policy governs.

use rabs_protocol::descriptor::ActionClass;

/// Cache-attempt refusal for benchmark runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchCacheRefusal {
    /// The stable reason code.
    pub reason_code: &'static str,
}

/// The one refusal (constant: there is no condition under which a
/// bench-run result serves from cache).
pub const BENCH_RUN_NOT_CACHEABLE: BenchCacheRefusal = BenchCacheRefusal {
    reason_code: "CACHE_REFUSED_BENCHMARK_OBSERVATION",
};

/// Attempt a cache interaction for an action class.
///
/// # Errors
/// [`BenchCacheRefusal`] for `BenchmarkRun` — always.
pub fn cache_interaction(class: ActionClass) -> Result<(), BenchCacheRefusal> {
    if class == ActionClass::BenchmarkRun {
        return Err(BENCH_RUN_NOT_CACHEABLE);
    }
    Ok(())
}

/// The explicit hardware/pressure profile a bench run schedules under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchProfile {
    /// Required CPU cohort (the F008 cohort identity).
    pub cpu_cohort: String,
    /// Maximum acceptable load (permille) during the run.
    pub max_load_permille: u16,
}

/// Scheduling decision for a bench run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchScheduling {
    /// The worker matches the profile: run, recording the evidence.
    RunWithEvidence {
        /// The matched cohort.
        cohort: String,
    },
    /// Refused: profile mismatch (named).
    Refused(&'static str),
}

/// Decide bench scheduling against a candidate worker's facts.
#[must_use]
pub fn schedule_bench(
    profile: Option<&BenchProfile>,
    worker_cohort: &str,
    worker_load_permille: u16,
) -> BenchScheduling {
    let Some(profile) = profile else {
        return BenchScheduling::Refused(
            "benchmark runs schedule only against an explicit hardware/pressure profile",
        );
    };
    if profile.cpu_cohort != worker_cohort {
        return BenchScheduling::Refused("hardware cohort mismatch");
    }
    if worker_load_permille > profile.max_load_permille {
        return BenchScheduling::Refused("load exceeds the declared pressure bound");
    }
    BenchScheduling::RunWithEvidence {
        cohort: worker_cohort.to_owned(),
    }
}

/// Reclassify a harness declared functional/deterministic.
#[must_use]
pub const fn classify_bench_harness(declared_functional_deterministic: bool) -> ActionClass {
    if declared_functional_deterministic {
        // Not a benchmark at all: the ordinary test policy governs.
        ActionClass::TestBinaryBatch
    } else {
        ActionClass::BenchmarkRun
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_run_cache_attempts_always_refuse() {
        // THE acceptance: no condition serves a bench observation.
        assert_eq!(
            cache_interaction(ActionClass::BenchmarkRun),
            Err(BENCH_RUN_NOT_CACHEABLE)
        );
        assert_eq!(
            BENCH_RUN_NOT_CACHEABLE.reason_code,
            "CACHE_REFUSED_BENCHMARK_OBSERVATION"
        );
        // Compiles of the benchmark are ordinary cacheable actions.
        assert_eq!(cache_interaction(ActionClass::BenchmarkCompile), Ok(()));
        assert_eq!(
            cache_interaction(ActionClass::RustcDependencyCompile),
            Ok(())
        );
    }

    #[test]
    fn hardware_profile_scheduling_fixtures() {
        // THE acceptance fixtures: explicit profile required, cohort
        // must match, load must be inside the bound.
        let profile = BenchProfile {
            cpu_cohort: "epyc-9654".into(),
            max_load_permille: 100,
        };
        assert_eq!(
            schedule_bench(Some(&profile), "epyc-9654", 50),
            BenchScheduling::RunWithEvidence {
                cohort: "epyc-9654".into()
            }
        );
        // No profile: refused — never an implicit "wherever".
        assert!(matches!(
            schedule_bench(None, "epyc-9654", 0),
            BenchScheduling::Refused(_)
        ));
        // Wrong cohort.
        assert_eq!(
            schedule_bench(Some(&profile), "m3-max", 0),
            BenchScheduling::Refused("hardware cohort mismatch")
        );
        // Too loaded: a mismatch is a refusal, not a footnote.
        assert_eq!(
            schedule_bench(Some(&profile), "epyc-9654", 500),
            BenchScheduling::Refused("load exceeds the declared pressure bound")
        );
    }

    #[test]
    fn functional_harnesses_reclassify_to_test_batch() {
        assert_eq!(
            classify_bench_harness(true),
            ActionClass::TestBinaryBatch,
            "a declared-deterministic harness is a test, not a benchmark"
        );
        assert_eq!(classify_bench_harness(false), ActionClass::BenchmarkRun);
        // And the reclassified form is cacheable under the test policy
        // while the true bench run never is.
        assert!(cache_interaction(classify_bench_harness(true)).is_ok());
        assert!(cache_interaction(classify_bench_harness(false)).is_err());
    }
}
