//! Wait budgets for the tiny wrapper. No runtime or serialization dependency.
//!
//! The edge permits 64 requests and allows five seconds to receive each frame.
//! Cold sysroot/package hashing can outlive a minute. Extending the deadline
//! alone is ineffective: a one-second poll still consumes all 60 retries first.
//! Pace long waits without exceeding either bound, retaining fast initial polls.

use std::time::Duration;

pub(super) const MAX_RETRIES: u32 = 60;
const DEFAULT_WAIT_MS: u64 = 60_000;
const DEFAULT_PREPARATION_WAIT_MS: u64 = 180_000;
const MAX_WAIT_MS: u64 = 180_000;
const MAXIMUM_DELAY: Duration = Duration::from_secs(4);

#[derive(Clone, Copy)]
pub(super) struct WaitPolicy {
    pub(super) budget: Duration,
    pub(super) preparation_budget: Duration,
    pub(super) retries: u32,
    pub(super) initial_delay: Duration,
    pub(super) maximum_delay: Duration,
    pub(super) preparation_maximum_delay: Duration,
}

impl WaitPolicy {
    pub(super) fn from_environment() -> Self {
        let wait = std::env::var("RABS_SINGLEFLIGHT_WAIT_MS").ok();
        let preparation = std::env::var("RABS_PREPARATION_WAIT_MS").ok();
        Self::from_values(wait.as_deref(), preparation.as_deref())
    }

    fn from_values(wait: Option<&str>, preparation: Option<&str>) -> Self {
        let wait = parse_milliseconds(wait);
        let budget = Duration::from_millis(wait.unwrap_or(DEFAULT_WAIT_MS));
        // An explicit legacy setting still bounds the entire consultation,
        // including zero (disable waiting). A preparation-specific override
        // takes precedence only when explicitly supplied and valid.
        let preparation_budget = Duration::from_millis(
            parse_milliseconds(preparation)
                .or(wait)
                .unwrap_or(DEFAULT_PREPARATION_WAIT_MS),
        );
        Self {
            budget,
            preparation_budget,
            retries: MAX_RETRIES,
            initial_delay: Duration::from_millis(50),
            maximum_delay: maximum_delay(budget),
            preparation_maximum_delay: maximum_delay(preparation_budget),
        }
    }

    /// Select once, on the FIRST non-owning reply. Subsequent preparation
    /// stages and the transition to a keyed flight do not reset any counters.
    pub(super) fn for_preparation(mut self) -> Self {
        self.budget = self.preparation_budget;
        self.maximum_delay = self.preparation_maximum_delay;
        self
    }

    pub(super) fn delay_for(self, retries: u32) -> Duration {
        self.initial_delay
            .saturating_mul(1_u32 << retries.min(7))
            .min(self.maximum_delay)
    }
}

fn parse_milliseconds(value: Option<&str>) -> Option<u64> {
    value?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|ms| ms.min(MAX_WAIT_MS))
}

fn maximum_delay(budget: Duration) -> Duration {
    // Reserve the seven fast exponential polls (50ms through 3.2s). The
    // remaining polls can cover the full budget without quota exhaustion.
    // Four seconds leaves headroom below the edge's five-second read budget.
    (budget / (MAX_RETRIES - 7))
        .max(Duration::from_secs(1))
        .min(MAXIMUM_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_preparation_gets_time_without_slowing_the_first_polls() {
        let ordinary = WaitPolicy::from_values(None, None);
        let cold = ordinary.for_preparation();
        assert_eq!(ordinary.budget, Duration::from_secs(60));
        assert_eq!(cold.budget, Duration::from_secs(180));
        for retry in 0..4 {
            assert_eq!(ordinary.delay_for(retry), cold.delay_for(retry));
        }
        assert_eq!(cold.delay_for(0), Duration::from_millis(50));
        assert_eq!(cold.retries, ordinary.retries);
    }

    #[test]
    fn explicit_legacy_budgets_including_zero_cover_preparation() {
        for milliseconds in [0_u64, 1, 12_000, 60_000, 180_000] {
            let text = milliseconds.to_string();
            let policy = WaitPolicy::from_values(Some(&text), None);
            assert_eq!(policy.budget, Duration::from_millis(milliseconds));
            assert_eq!(policy.for_preparation().budget, policy.budget);
        }
    }

    #[test]
    fn preparation_override_does_not_extend_ordinary_contention() {
        let policy = WaitPolicy::from_values(Some("12000"), Some("180000"));
        assert_eq!(policy.budget, Duration::from_secs(12));
        assert_eq!(policy.for_preparation().budget, Duration::from_secs(180));
        let disabled = WaitPolicy::from_values(None, Some("0"));
        assert_eq!(disabled.for_preparation().budget, Duration::ZERO);
        assert_eq!(disabled.budget, Duration::from_secs(60));
    }

    #[test]
    fn values_are_bounded_and_invalid_values_do_not_disable_waits() {
        for value in ["", "-1", "no", "18446744073709551616"] {
            let policy = WaitPolicy::from_values(Some(value), Some(value));
            assert_eq!(policy.budget, Duration::from_secs(60));
            assert_eq!(policy.for_preparation().budget, Duration::from_secs(180));
        }
        let policy = WaitPolicy::from_values(Some("18446744073709551615"), Some(" 999999 "));
        assert_eq!(policy.budget, Duration::from_secs(180));
        assert_eq!(policy.for_preparation().budget, Duration::from_secs(180));
        let inherited = WaitPolicy::from_values(Some("12000"), Some("invalid"));
        assert_eq!(inherited.for_preparation().budget, Duration::from_secs(12));
    }

    #[test]
    fn every_supported_budget_is_reachable_before_quota_exhaustion() {
        // Model an immediately responding daemon: this is the fastest way to
        // exhaust retries. No wall-clock sleeps or global environment mutation.
        for milliseconds in [1_u64, 12_000, 60_000, 60_001, 120_000, 180_000] {
            let text = milliseconds.to_string();
            let policy = WaitPolicy::from_values(Some(&text), None);
            let mut elapsed = Duration::ZERO;
            for retry in 0..policy.retries {
                let delay = policy.delay_for(retry);
                assert!(delay < Duration::from_secs(5));
                elapsed += delay;
            }
            assert!(
                elapsed >= policy.budget,
                "budget {milliseconds}: {elapsed:?}"
            );
        }
        const { assert!(MAX_RETRIES + 1 < 64) };
    }

    #[test]
    fn saturated_retry_numbers_never_overflow_or_exceed_idle_budget() {
        let policy = WaitPolicy::from_values(None, None).for_preparation();
        assert_eq!(policy.delay_for(u32::MAX), policy.maximum_delay);
        assert!(policy.maximum_delay <= MAXIMUM_DELAY);
    }
}
