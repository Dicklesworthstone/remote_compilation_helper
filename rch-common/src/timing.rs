//! Bounded timing policy for remote control operations.
//!
//! Configuration is resolved once by each CLI invocation or daemon startup.
//! Installing it never mutates the process environment: embedded remote helpers
//! receive the validated value explicitly. Compilation lifetime, scheduling
//! cadence and process-ownership requirements are independent of this policy.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Environment override for `[timeouts].scale`.
pub const TIMING_SCALE_ENV: &str = "RCH_TIMING_SCALE";

/// Absolute ceiling for one slow-path control-operation budget.
///
/// A finite multiplier alone cannot make an arbitrary base duration safe for
/// constructing an absolute deadline. This cap also applies at scale one.
/// Workload runtime limits and signal-escalation grace do not use this policy.
pub const MAX_CONTROL_TIMEOUT: Duration = Duration::from_secs(3600);

/// A finite multiplier between one and ten, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct TimingScale(f64);

/// Invalid timeout configuration never silently shortens a safety deadline or
/// turns a bounded observation into an unbounded wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("timeouts.scale / RCH_TIMING_SCALE must be a finite number from 1.0 through 10.0")]
pub struct TimingScaleError;

impl Default for TimingScale {
    fn default() -> Self {
        Self(1.0)
    }
}

impl TryFrom<f64> for TimingScale {
    type Error = TimingScaleError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if value.is_finite() && (1.0..=10.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(TimingScaleError)
        }
    }
}

impl From<TimingScale> for f64 {
    fn from(value: TimingScale) -> Self {
        value.0
    }
}

impl std::str::FromStr for TimingScale {
    type Err = TimingScaleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .trim()
            .parse::<f64>()
            .map_err(|_| TimingScaleError)?
            .try_into()
    }
}

impl TimingScale {
    /// Scale a control-operation budget within the absolute one-hour ceiling.
    /// The default preserves every duration within that ceiling exactly.
    /// Overflow must never produce an effectively indefinite wait or an
    /// unrepresentable absolute deadline in a caller.
    #[must_use]
    pub fn duration(self, base: Duration) -> Duration {
        let base = base.min(MAX_CONTROL_TIMEOUT);
        if self.0.to_bits() == 1.0_f64.to_bits() {
            return base;
        }
        Duration::try_from_secs_f64(base.as_secs_f64() * self.0)
            .unwrap_or(MAX_CONTROL_TIMEOUT)
            .max(base)
            .min(MAX_CONTROL_TIMEOUT)
    }

    /// Numeric text safe to pass to a remote environment or shell assignment.
    #[must_use]
    pub fn env_value(self) -> String {
        self.0.to_string()
    }

    /// Explicitly export the resolved policy through nested remote shells.
    #[must_use]
    pub fn shell_prefix(self) -> String {
        format!("export {TIMING_SCALE_ENV}={};\n", self.env_value())
    }
}

/// Shared `[timeouts]` configuration for the client and daemon.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeoutsConfig {
    /// Multiplier for bounded slow-path deadlines, default 1.0, maximum 10.0.
    pub scale: TimingScale,
}

impl TimeoutsConfig {
    /// Resolve one optional environment value after the on-disk configuration.
    /// Kept pure so configuration precedence can be tested without changing the
    /// environment of concurrent worker or test threads.
    pub fn with_override(mut self, value: Option<&str>) -> Result<Self, TimingScaleError> {
        if let Some(value) = value {
            self.scale = value.parse()?;
        }
        Ok(self)
    }

    /// Apply the current process's override, including when no config file exists.
    pub fn with_environment(self) -> Result<Self, TimingScaleError> {
        match std::env::var(TIMING_SCALE_ENV) {
            Ok(value) => self.with_override(Some(&value)),
            Err(std::env::VarError::NotPresent) => Ok(self),
            Err(std::env::VarError::NotUnicode(_)) => Err(TimingScaleError),
        }
    }
}

static CONFIGURED_SCALE: AtomicU64 = AtomicU64::new(1.0_f64.to_bits());

/// Install a fully resolved policy before starting control work.
pub fn install(scale: TimingScale) {
    CONFIGURED_SCALE.store(scale.0.to_bits(), Ordering::Relaxed);
}

/// Snapshot the process-local policy. Readers never access mutable environment.
#[must_use]
pub fn configured() -> TimingScale {
    TimingScale(f64::from_bits(CONFIGURED_SCALE.load(Ordering::Relaxed)))
}

/// Scale a slow-path budget using the currently installed policy.
#[must_use]
pub fn scale_duration(base: Duration) -> Duration {
    configured().duration(base)
}

/// Export the installed policy explicitly for embedded remote helpers.
#[must_use]
pub fn shell_prefix() -> String {
    configured().shell_prefix()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preserves_control_durations_within_ceiling_exactly() {
        let scale = TimingScale::default();
        for duration in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(1500),
            Duration::new(3599, 123_456_789),
            MAX_CONTROL_TIMEOUT,
        ] {
            assert_eq!(scale.duration(duration), duration);
        }
        for seconds in [1, 2, 3, 5, 10, 15, 20, 25, 30, 33, 45, 60, 120] {
            let duration = Duration::from_secs(seconds);
            assert_eq!(scale.duration(duration), duration);
        }
        assert_eq!(scale.env_value(), "1");
    }

    #[test]
    fn fractional_and_maximum_scale_extend_budgets() {
        let fractional: TimingScale = " 1.5 ".parse().unwrap();
        assert_eq!(
            fractional.duration(Duration::from_secs(3)),
            Duration::from_millis(4500)
        );
        let maximum = TimingScale::try_from(10.0).unwrap();
        assert_eq!(
            maximum.duration(Duration::from_secs(30)),
            Duration::from_secs(300)
        );
        assert_eq!(maximum.duration(Duration::MAX), MAX_CONTROL_TIMEOUT);
        assert_eq!(fractional.duration(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn extreme_budgets_remain_finite_and_form_valid_absolute_deadlines() {
        let now = std::time::Instant::now();
        for value in [1.0, 1.001, 1.5, 10.0] {
            let scale = TimingScale::try_from(value).unwrap();
            for base in [
                MAX_CONTROL_TIMEOUT + Duration::from_nanos(1),
                Duration::from_secs(3601),
                Duration::new(1 << 60, 123_456_789),
                Duration::MAX,
            ] {
                let bounded = scale.duration(base);
                assert_eq!(bounded, MAX_CONTROL_TIMEOUT);
                assert!(
                    now.checked_add(bounded).is_some(),
                    "scale {value} produced an unrepresentable deadline"
                );
            }
        }
        let doubled = TimingScale::try_from(2.0).unwrap();
        assert_eq!(
            doubled.duration(Duration::from_secs(1799)),
            Duration::from_secs(3598)
        );
        assert_eq!(
            doubled.duration(Duration::from_secs(1801)),
            MAX_CONTROL_TIMEOUT
        );
    }

    #[test]
    fn invalid_values_are_rejected() {
        for value in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            0.0,
            -1.0,
            0.99,
            10.01,
            f64::MAX,
        ] {
            assert!(TimingScale::try_from(value).is_err(), "accepted {value}");
        }
        for value in [
            "", "nan", "inf", "-inf", "0", "-2", "0.5", "11", "1;echo unsafe", "1e999",
        ] {
            assert!(value.parse::<TimingScale>().is_err(), "accepted {value}");
        }
    }

    #[test]
    fn configuration_accepts_integers_and_floats_and_validates_both() {
        for (text, expected) in [
            ("", "1"),
            ("scale = 1", "1"),
            ("scale = 1.5", "1.5"),
            ("scale = 10", "10"),
        ] {
            let config: TimeoutsConfig = toml::from_str(text).unwrap();
            assert_eq!(config.scale.env_value(), expected);
            let encoded = serde_json::to_string(&config).unwrap();
            assert_eq!(
                serde_json::from_str::<TimeoutsConfig>(&encoded).unwrap(),
                config
            );
        }
        for text in [
            "scale = nan",
            "scale = inf",
            "scale = -inf",
            "scale = 0",
            "scale = -1",
            "scale = 0.5",
            "scale = 11",
            "scale = '2'",
            "scale = true",
        ] {
            assert!(
                toml::from_str::<TimeoutsConfig>(text).is_err(),
                "accepted {text}"
            );
        }
    }

    #[test]
    fn environment_precedence_and_remote_export_are_explicit() {
        let configured: TimeoutsConfig = toml::from_str("scale = 4").unwrap();
        assert_eq!(configured.with_override(None).unwrap(), configured);
        let reset = configured.with_override(Some("1")).unwrap();
        assert_eq!(reset, TimeoutsConfig::default());
        let override_value = configured.with_override(Some("2.5")).unwrap();
        assert_eq!(
            override_value.scale.shell_prefix(),
            "export RCH_TIMING_SCALE=2.5;\n"
        );
        assert!(configured.with_override(Some("invalid")).is_err());
    }
}
