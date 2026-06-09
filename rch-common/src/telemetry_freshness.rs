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
    /// Short, stable human explanation (operator-facing). Owned so the struct
    /// remains `Deserialize` for any lifetime (it nests inside other records).
    pub reason: String,
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
    // `f64::clamp` does NOT sanitize NaN (`NaN.clamp(0.0, 1.0) == NaN`), and a
    // non-finite pressure flows into `Duration::from_secs_f64` in
    // `dominant_reason`, which PANICS on NaN/inf — in a classifier documented
    // as never-failing. Coerce any non-finite pressure to 0.0 first.
    let pressure = if inputs.concurrency_pressure.is_finite() {
        inputs.concurrency_pressure.clamp(0.0, 1.0)
    } else {
        0.0
    };

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
    let tolerated_base = base_tolerated
        .saturating_add(observer_extra)
        .saturating_add(rtt_extra)
        .saturating_add(timeout_extra);
    // Scale by (1 + pressure) without `Duration::mul_f64`, which PANICS when the
    // product overflows `Duration` — and `tolerated_base` can saturate toward
    // `Duration::MAX` via the chain above (e.g. a pathological `ssh_timeout` or
    // `host_rtt`). Do the scale on the saturating millisecond count and clamp,
    // so this never-failing classifier never panics on extreme input.
    let scaled_ms = (ms(tolerated_base) as f64 * (1.0 + pressure)).min(u64::MAX as f64);
    let tolerated = Duration::from_millis(scaled_ms as u64);
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
            reason: "no telemetry sample yet".to_string(),
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
        reason: reason.to_string(),
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
    fn extreme_inputs_do_not_panic_in_tolerance_scaling() {
        // Regression: the tolerance scale must never `Duration::mul_f64`-panic
        // on a saturated chain. A pathological ssh_timeout/host_rtt that pushes
        // the saturating chain toward Duration::MAX, under full pressure, must
        // still yield a definite verdict rather than panicking.
        let inputs = FreshnessInputs {
            poll_interval: Duration::from_secs(u64::MAX),
            ssh_timeout: Duration::from_secs(u64::MAX),
            last_poll_duration: Duration::from_secs(u64::MAX),
            recent_timeout_count: u32::MAX,
            host_rtt: Some(Duration::from_secs(u64::MAX)),
            concurrency_pressure: 1.0,
            age: Some(Duration::from_secs(1)),
        };
        let a = assess(&inputs); // must not panic
        // A tiny age against an enormous tolerance is fresh.
        assert_eq!(a.verdict, FreshnessVerdict::Fresh);
        // And the unknown-age path is equally panic-free.
        let unknown = FreshnessInputs {
            age: None,
            ..inputs
        };
        assert_eq!(assess(&unknown).verdict, FreshnessVerdict::Unknown);
    }

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

    /// Property/fuzz + metamorphic coverage for `assess`
    /// (bd-review-test-freshness-fuzz). Mock-free, pure-function fuzzing.
    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        /// Durations spanning the full u64 millisecond range — including the
        /// extremes that exercise the saturating/overflow tolerance paths.
        fn any_duration() -> impl Strategy<Value = Duration> {
            any::<u64>().prop_map(Duration::from_millis)
        }

        /// Pressure including out-of-range and non-finite values, so the clamp
        /// and scale paths are stressed (must never panic or produce NaN
        /// confidence).
        fn any_pressure() -> impl Strategy<Value = f64> {
            prop_oneof![
                Just(f64::NAN),
                Just(f64::INFINITY),
                Just(f64::NEG_INFINITY),
                -5.0_f64..5.0_f64,
                any::<f64>(),
            ]
        }

        fn any_inputs() -> impl Strategy<Value = FreshnessInputs> {
            (
                any_duration(),
                any_duration(),
                any_duration(),
                any::<u32>(),
                proptest::option::of(any_duration()),
                any_pressure(),
                proptest::option::of(any_duration()),
            )
                .prop_map(
                    |(poll, timeout, last, timeouts, rtt, pressure, age)| FreshnessInputs {
                        poll_interval: poll,
                        ssh_timeout: timeout,
                        last_poll_duration: last,
                        recent_timeout_count: timeouts,
                        host_rtt: rtt,
                        concurrency_pressure: pressure,
                        age,
                    },
                )
        }

        /// Severity rank for the metamorphic monotonicity check (Unknown only
        /// arises when there is no sample, so it never participates here).
        fn verdict_rank(v: FreshnessVerdict) -> u8 {
            match v {
                FreshnessVerdict::Fresh => 0,
                FreshnessVerdict::SlowObserver => 1,
                FreshnessVerdict::Stale => 2,
                FreshnessVerdict::Unknown => 3,
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2048))]

            /// Never panics; confidence is always finite and in [0,1]; `usable`
            /// mirrors the verdict; `Unknown` iff there is no sample.
            #[test]
            fn assess_never_panics_and_holds_invariants(inputs in any_inputs()) {
                let a = assess(&inputs);
                prop_assert!(a.confidence.is_finite(), "confidence not finite: {}", a.confidence);
                prop_assert!(
                    (0.0..=1.0).contains(&a.confidence),
                    "confidence out of range: {}",
                    a.confidence
                );
                prop_assert_eq!(
                    a.usable,
                    matches!(a.verdict, FreshnessVerdict::Fresh | FreshnessVerdict::SlowObserver)
                );
                prop_assert_eq!(
                    matches!(a.verdict, FreshnessVerdict::Unknown),
                    inputs.age.is_none()
                );
                // tolerance is always at least the expected-next window.
                prop_assert!(a.tolerated_age_ms >= a.expected_next_sample_ms);
            }

            /// Metamorphic: with a sample present, a larger age never produces a
            /// FRESHER verdict (rank is monotonic non-decreasing in age).
            #[test]
            fn larger_age_is_never_fresher(base in any_inputs(), a in any_duration(), b in any_duration()) {
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                let mut inputs = base;
                inputs.age = Some(lo);
                let v_lo = assess(&inputs).verdict;
                inputs.age = Some(hi);
                let v_hi = assess(&inputs).verdict;
                prop_assert!(
                    verdict_rank(v_hi) >= verdict_rank(v_lo),
                    "monotonicity violated: {lo:?}->{v_lo:?} then {hi:?}->{v_hi:?}"
                );
            }

            /// Metamorphic: higher concurrency pressure never SHRINKS the
            /// tolerated age (a saturated poller defers polls → wider tolerance).
            #[test]
            fn higher_pressure_never_shrinks_tolerance(base in any_inputs(), age in any_duration()) {
                let mut inputs = base;
                inputs.age = Some(age);
                inputs.concurrency_pressure = 0.0;
                let tol_lo = assess(&inputs).tolerated_age_ms;
                inputs.concurrency_pressure = 1.0;
                let tol_hi = assess(&inputs).tolerated_age_ms;
                prop_assert!(tol_hi >= tol_lo, "pressure shrank tolerance: {tol_lo} -> {tol_hi}");
            }
        }
    }
}
