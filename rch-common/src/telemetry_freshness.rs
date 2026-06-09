//! Adaptive telemetry freshness model.
//!
//! A worker's telemetry is "stale" only relative to how fast we could possibly
//! have re-sampled it. A fixed age threshold mis-classifies workers whenever the
//! *observer* is slow: a behind-schedule poll loop, a saturated poll-permit
//! pool, a high-latency cross-region SSH hop, or a run of poll timeouts all
//! inflate the age of perfectly healthy telemetry. Evicting those workers (and
//! falling back to local builds) "without explanation" is exactly the failure
//! this model prevents.
//!
//! [`assess`] turns the raw signals (poll interval, SSH timeout, last poll
//! duration, recent timeout count, host RTT, poller saturation, current sample
//! age) into a [`FreshnessAssessment`] carrying the bead's required outputs —
//! expected next sample, tolerated age, last poll duration, timeout count, and
//! a confidence — plus a verdict and a human reason. The model is pure: every
//! input is supplied by the caller, so it is fully deterministic and unit
//! testable.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Raw inputs to the freshness model. All durations are observer-side facts.
#[derive(Debug, Clone)]
pub struct FreshnessInputs {
    /// Base poll cadence.
    pub poll_interval: Duration,
    /// Per-poll SSH timeout.
    pub ssh_timeout: Duration,
    /// Wall-clock duration of the most recent poll *cycle* (a slow loop runs
    /// long; this is the primary "observer is behind" signal).
    pub last_poll_duration: Duration,
    /// Consecutive/recent poll timeouts observed for this worker.
    pub recent_timeout_count: u32,
    /// Round-trip latency to the worker host, if known ("host distance").
    pub host_rtt: Option<Duration>,
    /// Poll-permit-pool saturation in `[0.0, 1.0]` (1.0 = fully saturated).
    pub concurrency_pressure: f64,
    /// Age of the worker's latest telemetry sample. `None` = no sample yet.
    pub age: Option<Duration>,
}

impl FreshnessInputs {
    /// Minimal constructor for a worker with a known sample age and no
    /// adversity (no timeouts, no measured RTT, idle poller, on-pace loop).
    #[must_use]
    pub fn new(poll_interval: Duration, ssh_timeout: Duration, age: Duration) -> Self {
        Self {
            poll_interval,
            ssh_timeout,
            last_poll_duration: poll_interval,
            recent_timeout_count: 0,
            host_rtt: None,
            concurrency_pressure: 0.0,
            age: Some(age),
        }
    }
}

/// Freshness classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessVerdict {
    /// Within the expected sampling window — fully fresh.
    Fresh,
    /// Older than expected, but the excess is explained by observer slowness
    /// (slow loop / latency / timeouts / saturation). Still usable — do NOT
    /// evict.
    SlowObserver,
    /// Genuinely stale beyond the adaptive tolerance. Not usable.
    Stale,
    /// No telemetry sample yet — cannot assess. Not usable, but explained.
    Unknown,
}

impl FreshnessVerdict {
    /// Whether a worker with this verdict should remain eligible. Only a
    /// genuinely `Stale` (or never-sampled `Unknown`) worker is ineligible; a
    /// `SlowObserver` worker stays in the pool.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Fresh | Self::SlowObserver)
    }
}

/// The model's verdict plus the explanatory metrics the bead requires.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FreshnessAssessment {
    pub verdict: FreshnessVerdict,
    /// When the next sample is expected, as an age (relative to the last
    /// sample). Ages at or below this are fully fresh.
    pub expected_next_sample_ms: u64,
    /// Maximum age tolerated before a worker is genuinely stale.
    pub tolerated_age_ms: u64,
    /// Echoed last poll-cycle duration.
    pub last_poll_duration_ms: u64,
    /// Echoed recent timeout count.
    pub timeout_count: u32,
    /// Confidence in `[0.0, 1.0]` that the telemetry reflects current reality.
    pub confidence: f64,
    /// Current sample age (`None` when no sample exists).
    pub age_ms: Option<u64>,
    /// Whether the worker should remain eligible (mirror of `verdict.is_usable`).
    pub usable: bool,
    /// Short, stable human explanation (operator-facing).
    pub reason: &'static str,
}

/// Saturating conversion of a `Duration` to whole milliseconds.
fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Compute the adaptive freshness assessment.
// Confidence is a heuristic ratio over millisecond counts; f64 precision loss
// at that magnitude is immaterial.
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn assess(inputs: &FreshnessInputs) -> FreshnessAssessment {
    let pressure = inputs.concurrency_pressure.clamp(0.0, 1.0);

    // How far behind the loop is relative to its nominal cadence.
    let observer_extra = inputs
        .last_poll_duration
        .saturating_sub(inputs.poll_interval);
    // Slow SSH: budget two round trips of slack.
    let rtt_extra = inputs
        .host_rtt
        .map_or(Duration::ZERO, |r| r.saturating_mul(2));
    // Each recent timeout means a poll burned (up to) the full SSH timeout and
    // had to retry. Cap so a pathological streak cannot inflate tolerance
    // unboundedly.
    let timeout_units = inputs.recent_timeout_count.min(3);
    let timeout_extra = inputs.ssh_timeout.saturating_mul(timeout_units);

    // The next sample is expected one cadence out, plus however far the loop is
    // behind, plus a latency hop.
    let expected_next = inputs
        .poll_interval
        .saturating_add(observer_extra)
        .saturating_add(rtt_extra);

    // Base worst case for a single clean cycle: one interval + one SSH timeout.
    let base_tolerated = inputs.poll_interval.saturating_add(inputs.ssh_timeout);
    // Adaptive tolerance widens with observer slowness, latency, and timeouts,
    // then scales up under poller saturation (a saturated poller defers polls).
    let tolerated = base_tolerated
        .saturating_add(observer_extra)
        .saturating_add(rtt_extra)
        .saturating_add(timeout_extra)
        .mul_f64(1.0 + pressure);
    // Tolerance must never sit below the expected next sample.
    let tolerated = tolerated.max(expected_next);

    let Some(age) = inputs.age else {
        return FreshnessAssessment {
            verdict: FreshnessVerdict::Unknown,
            expected_next_sample_ms: ms(expected_next),
            tolerated_age_ms: ms(tolerated),
            last_poll_duration_ms: ms(inputs.last_poll_duration),
            timeout_count: inputs.recent_timeout_count,
            confidence: 0.0,
            age_ms: None,
            usable: false,
            reason: "no telemetry sample yet",
        };
    };

    let (verdict, confidence, reason) = if age <= expected_next {
        (
            FreshnessVerdict::Fresh,
            1.0,
            "within expected sampling window",
        )
    } else if age <= tolerated {
        // Confidence decays linearly across the explained band.
        let span = ms(tolerated).saturating_sub(ms(expected_next)).max(1);
        let over = ms(age).saturating_sub(ms(expected_next));
        let confidence = (1.0 - (over as f64 / span as f64)).clamp(0.0, 1.0);
        (
            FreshnessVerdict::SlowObserver,
            confidence,
            dominant_reason(observer_extra, rtt_extra, timeout_extra, pressure),
        )
    } else {
        (
            FreshnessVerdict::Stale,
            0.0,
            "telemetry genuinely stale beyond adaptive tolerance",
        )
    };

    FreshnessAssessment {
        verdict,
        expected_next_sample_ms: ms(expected_next),
        tolerated_age_ms: ms(tolerated),
        last_poll_duration_ms: ms(inputs.last_poll_duration),
        timeout_count: inputs.recent_timeout_count,
        confidence,
        age_ms: Some(ms(age)),
        usable: verdict.is_usable(),
        reason,
    }
}

/// Pick the dominant explanation for an extended tolerance.
fn dominant_reason(
    observer_extra: Duration,
    rtt_extra: Duration,
    timeout_extra: Duration,
    pressure: f64,
) -> &'static str {
    // Express saturation as a comparable duration weight so one ranking covers
    // all factors (1.0 pressure ~ "as significant as a 30s slowdown").
    let pressure_weight = Duration::from_secs_f64(30.0 * pressure);
    let mut best = ("poller saturation", pressure_weight);
    for (label, value) in [
        ("observer loop behind schedule", observer_extra),
        ("high host latency", rtt_extra),
        ("recent poll timeouts", timeout_extra),
    ] {
        if value > best.1 {
            best = (label, value);
        }
    }
    if best.1.is_zero() {
        "older than expected (observer effects)"
    } else {
        best.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLL: Duration = Duration::from_secs(30);
    const TIMEOUT: Duration = Duration::from_secs(20);

    #[test]
    fn fresh_within_expected_window() {
        let inputs = FreshnessInputs::new(POLL, TIMEOUT, Duration::from_secs(10));
        let a = assess(&inputs);
        assert_eq!(a.verdict, FreshnessVerdict::Fresh);
        assert!(a.usable);
        assert!((a.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn missing_telemetry_is_unknown_and_unusable() {
        let inputs = FreshnessInputs {
            age: None,
            ..FreshnessInputs::new(POLL, TIMEOUT, Duration::ZERO)
        };
        let a = assess(&inputs);
        assert_eq!(a.verdict, FreshnessVerdict::Unknown);
        assert!(!a.usable);
        assert_eq!(a.age_ms, None);
        assert_eq!(a.confidence, 0.0);
        assert_eq!(a.reason, "no telemetry sample yet");
    }

    #[test]
    fn genuinely_stale_worker_is_evicted() {
        // On-pace loop, no adversity, but the sample is ancient.
        let inputs = FreshnessInputs::new(POLL, TIMEOUT, Duration::from_secs(600));
        let a = assess(&inputs);
        assert_eq!(a.verdict, FreshnessVerdict::Stale);
        assert!(!a.usable);
        assert_eq!(a.confidence, 0.0);
    }

    #[test]
    fn cross_region_slow_polling_is_explained_not_stale() {
        // A high-RTT host whose age would exceed the *base* threshold (50s) but
        // is explained by latency — must stay usable.
        let inputs = FreshnessInputs {
            host_rtt: Some(Duration::from_secs(8)),
            age: Some(Duration::from_secs(60)),
            ..FreshnessInputs::new(POLL, TIMEOUT, Duration::from_secs(60))
        };
        let a = assess(&inputs);
        assert_eq!(a.verdict, FreshnessVerdict::SlowObserver);
        assert!(a.usable, "cross-region worker must not be evicted");
        assert_eq!(a.reason, "high host latency");
        // Tolerance widened beyond the static base (poll + timeout = 50s).
        assert!(a.tolerated_age_ms > 50_000);
    }

    #[test]
    fn overloaded_poller_extends_tolerance() {
        // The loop ran long (90s vs 30s nominal) and the permit pool is
        // saturated; a 70s-old sample is still usable, not stale.
        let inputs = FreshnessInputs {
            last_poll_duration: Duration::from_secs(90),
            concurrency_pressure: 1.0,
            age: Some(Duration::from_secs(70)),
            ..FreshnessInputs::new(POLL, TIMEOUT, Duration::from_secs(70))
        };
        let a = assess(&inputs);
        assert!(a.usable, "overloaded-poller staleness must not evict");
        assert!(matches!(
            a.verdict,
            FreshnessVerdict::SlowObserver | FreshnessVerdict::Fresh
        ));
        // The 90s loop alone pushes the expected-next window past 70s, so
        // tolerance far exceeds the 50s static base.
        assert!(a.tolerated_age_ms > 50_000);

        // Push the age into the explained band to exercise the SlowObserver
        // reason path (between expected-next and the saturation-scaled cap).
        let aged = FreshnessInputs {
            age: Some(Duration::from_secs(150)),
            ..inputs
        };
        let a2 = assess(&aged);
        assert_eq!(a2.verdict, FreshnessVerdict::SlowObserver);
        assert!(a2.usable);
        assert!(
            a2.reason == "observer loop behind schedule" || a2.reason == "poller saturation",
            "unexpected reason: {}",
            a2.reason
        );
    }

    #[test]
    fn recent_timeouts_widen_tolerance_but_are_capped() {
        let two = FreshnessInputs {
            recent_timeout_count: 2,
            age: Some(Duration::from_secs(80)),
            ..FreshnessInputs::new(POLL, TIMEOUT, Duration::from_secs(80))
        };
        let many = FreshnessInputs {
            recent_timeout_count: 50,
            ..two.clone()
        };
        let a_two = assess(&two);
        let a_many = assess(&many);
        // 2 timeouts already widen tolerance beyond the base.
        assert!(a_two.tolerated_age_ms > 50_000);
        // The cap (3 units) means 50 timeouts tolerate no more than 3.
        let capped = FreshnessInputs {
            recent_timeout_count: 3,
            ..two.clone()
        };
        assert_eq!(assess(&capped).tolerated_age_ms, a_many.tolerated_age_ms);
    }

    #[test]
    fn confidence_decays_monotonically_through_the_explained_band() {
        let mk = |age_secs: u64| FreshnessInputs {
            host_rtt: Some(Duration::from_secs(5)),
            age: Some(Duration::from_secs(age_secs)),
            ..FreshnessInputs::new(POLL, TIMEOUT, Duration::from_secs(age_secs))
        };
        let young = assess(&mk(45)).confidence;
        let mid = assess(&mk(55)).confidence;
        let old = assess(&mk(60)).confidence;
        assert!(young >= mid && mid >= old, "{young} {mid} {old}");
        assert!((0.0..=1.0).contains(&young));
    }

    #[test]
    fn assessment_serializes_with_required_fields() {
        let a = assess(&FreshnessInputs::new(
            POLL,
            TIMEOUT,
            Duration::from_secs(10),
        ));
        let v = serde_json::to_value(&a).unwrap();
        for key in [
            "verdict",
            "expected_next_sample_ms",
            "tolerated_age_ms",
            "last_poll_duration_ms",
            "timeout_count",
            "confidence",
            "usable",
            "reason",
        ] {
            assert!(v.get(key).is_some(), "missing field {key}");
        }
        assert_eq!(v["verdict"], "fresh");
    }
}
