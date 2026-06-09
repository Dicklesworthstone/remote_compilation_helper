//! Telemetry age explanations and "why unhealthy" status model.
//!
//! When a worker's telemetry age is `None` (or it is otherwise unhealthy),
//! operators need to know *why* — and crucially whether the cause is the worker
//! or the observer. "Telemetry unknown" with no explanation is what drives
//! operators (and agents) to wrongly conclude a healthy worker is broken.
//!
//! This module classifies the unavailability cause from observable signals and
//! packages it, alongside the adaptive [`FreshnessAssessment`], into a
//! [`WhyUnhealthy`] record that `rch status --why-unhealthy` (and the dashboard
//! / metrics dependents) render: last probe result, last telemetry result, next
//! probe schedule, and observer-loop status.

use serde::{Deserialize, Serialize};

use crate::telemetry_freshness::FreshnessAssessment;

/// Why a worker's telemetry age is unknown / unusable. Ordered by diagnostic
/// precedence (most fundamental cause first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryUnavailabilityReason {
    /// The worker binary does not provide `rch-wkr telemetry`.
    WorkerLacksTelemetry,
    /// The most recent telemetry payload failed to parse.
    ParseFailed,
    /// The last retained sample was pruned by retention before re-sampling.
    Pruned,
    /// The daemon restarted and lost in-memory samples; none re-collected yet.
    DaemonRestarted,
    /// The observer/poll loop is saturated or behind, so no fresh sample exists.
    PollerOverloaded,
    /// Telemetry simply has not arrived yet (first sample pending).
    NeverArrived,
}

impl TelemetryUnavailabilityReason {
    /// Stable snake_case identifier (matches the serialized form).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkerLacksTelemetry => "worker_lacks_telemetry",
            Self::ParseFailed => "parse_failed",
            Self::Pruned => "pruned",
            Self::DaemonRestarted => "daemon_restarted",
            Self::PollerOverloaded => "poller_overloaded",
            Self::NeverArrived => "never_arrived",
        }
    }

    /// Operator-facing explanation.
    #[must_use]
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::WorkerLacksTelemetry => {
                "worker binary does not provide `rch-wkr telemetry` (upgrade the worker)"
            }
            Self::ParseFailed => "the last telemetry payload could not be parsed",
            Self::Pruned => "the last sample was pruned by retention before re-sampling",
            Self::DaemonRestarted => {
                "the daemon restarted and lost in-memory samples; awaiting re-collection"
            }
            Self::PollerOverloaded => {
                "the telemetry poll loop is saturated/behind; this is an observer issue, not the worker"
            }
            Self::NeverArrived => "telemetry has not arrived yet (first sample pending)",
        }
    }

    /// Whether the cause is the observer (daemon/poller) rather than the worker.
    /// Observer-side causes must NOT be read as "the worker is broken".
    #[must_use]
    pub const fn is_observer_side(self) -> bool {
        matches!(
            self,
            Self::Pruned | Self::DaemonRestarted | Self::PollerOverloaded
        )
    }
}

/// Outcome of a single probe / telemetry attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// Completed successfully.
    Ok,
    /// Timed out.
    Timeout,
    /// Failed with an error.
    Error,
    /// Not attempted yet (e.g. fresh start).
    NotAttempted,
}

/// Observable signals used to classify a missing/unhealthy telemetry age.
#[derive(Debug, Clone, Default)]
pub struct TelemetrySignals {
    /// Whether any sample has ever been received.
    pub ever_received_sample: bool,
    /// Whether the most recent payload failed to parse.
    pub last_payload_parse_failed: bool,
    /// Whether the worker supports `rch-wkr telemetry` (`None` = unknown).
    pub worker_supports_telemetry: Option<bool>,
    /// Whether the poll loop is behind/saturated.
    pub poller_behind: bool,
    /// Whether the daemon restarted since the last sample would have been taken.
    pub daemon_restarted_since_sample: bool,
    /// Whether the last sample was pruned by retention.
    pub sample_pruned: bool,
}

/// Classify why telemetry age is unknown from `signals`, in precedence order.
#[must_use]
pub fn explain_unavailability(signals: &TelemetrySignals) -> TelemetryUnavailabilityReason {
    use TelemetryUnavailabilityReason as R;
    if signals.worker_supports_telemetry == Some(false) {
        return R::WorkerLacksTelemetry;
    }
    if signals.last_payload_parse_failed {
        return R::ParseFailed;
    }
    if signals.sample_pruned {
        return R::Pruned;
    }
    if signals.daemon_restarted_since_sample {
        return R::DaemonRestarted;
    }
    if signals.poller_behind {
        return R::PollerOverloaded;
    }
    R::NeverArrived
}

/// The `rch status --why-unhealthy` record for one worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhyUnhealthy {
    pub worker_id: String,
    /// Final health verdict for the worker.
    pub healthy: bool,
    /// Adaptive freshness assessment when a sample age is known; `None` when age
    /// is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness: Option<FreshnessAssessment>,
    /// Unavailability cause when age is unknown / telemetry missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailability: Option<TelemetryUnavailabilityReason>,
    /// Result of the last health probe.
    pub last_probe_result: ProbeOutcome,
    /// Result of the last telemetry fetch.
    pub last_telemetry_result: ProbeOutcome,
    /// Estimated time until the next probe, in milliseconds (`None` = unknown).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_probe_in_ms: Option<u64>,
    /// Whether the observer/poll loop is behind schedule.
    pub observer_behind: bool,
    /// Composed operator-facing explanation.
    pub explanation: String,
}

impl WhyUnhealthy {
    /// Build a record for a worker whose telemetry age is **known** (a
    /// freshness assessment exists). Healthy iff the assessment is usable.
    #[must_use]
    pub fn from_freshness(
        worker_id: impl Into<String>,
        freshness: FreshnessAssessment,
        last_probe_result: ProbeOutcome,
        last_telemetry_result: ProbeOutcome,
        next_probe_in_ms: Option<u64>,
    ) -> Self {
        let observer_behind =
            freshness.verdict == crate::telemetry_freshness::FreshnessVerdict::SlowObserver;
        let healthy = freshness.usable;
        let explanation = if healthy {
            format!("usable: {}", freshness.reason)
        } else {
            format!("unhealthy: {}", freshness.reason)
        };
        Self {
            worker_id: worker_id.into(),
            healthy,
            freshness: Some(freshness),
            unavailability: None,
            last_probe_result,
            last_telemetry_result,
            next_probe_in_ms,
            observer_behind,
            explanation,
        }
    }

    /// Build a record for a worker whose telemetry age is **unknown** — the
    /// cause is classified from `signals`. Never healthy (no usable telemetry),
    /// but the explanation makes clear whether the worker or the observer is at
    /// fault.
    #[must_use]
    pub fn from_missing(
        worker_id: impl Into<String>,
        signals: &TelemetrySignals,
        last_probe_result: ProbeOutcome,
        last_telemetry_result: ProbeOutcome,
        next_probe_in_ms: Option<u64>,
    ) -> Self {
        let reason = explain_unavailability(signals);
        let explanation = format!(
            "telemetry unknown — {} ({})",
            reason.explanation(),
            if reason.is_observer_side() {
                "observer-side"
            } else {
                "worker-side"
            }
        );
        Self {
            worker_id: worker_id.into(),
            healthy: false,
            freshness: None,
            unavailability: Some(reason),
            last_probe_result,
            last_telemetry_result,
            next_probe_in_ms,
            observer_behind: signals.poller_behind,
            explanation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry_freshness::{FreshnessInputs, FreshnessVerdict, assess};
    use std::time::Duration;

    fn signals() -> TelemetrySignals {
        TelemetrySignals::default()
    }

    #[test]
    fn worker_lacks_telemetry_takes_precedence() {
        let s = TelemetrySignals {
            worker_supports_telemetry: Some(false),
            // Even with other signals set, the missing capability dominates.
            last_payload_parse_failed: true,
            poller_behind: true,
            ..signals()
        };
        let r = explain_unavailability(&s);
        assert_eq!(r, TelemetryUnavailabilityReason::WorkerLacksTelemetry);
        assert!(!r.is_observer_side());
    }

    #[test]
    fn parse_failure_is_detected() {
        let s = TelemetrySignals {
            last_payload_parse_failed: true,
            poller_behind: true,
            ..signals()
        };
        assert_eq!(
            explain_unavailability(&s),
            TelemetryUnavailabilityReason::ParseFailed
        );
    }

    #[test]
    fn pruned_before_poller_overloaded() {
        let s = TelemetrySignals {
            sample_pruned: true,
            daemon_restarted_since_sample: true,
            poller_behind: true,
            ..signals()
        };
        assert_eq!(
            explain_unavailability(&s),
            TelemetryUnavailabilityReason::Pruned
        );
    }

    #[test]
    fn daemon_restart_before_poller_overloaded() {
        let s = TelemetrySignals {
            daemon_restarted_since_sample: true,
            poller_behind: true,
            ..signals()
        };
        let r = explain_unavailability(&s);
        assert_eq!(r, TelemetryUnavailabilityReason::DaemonRestarted);
        assert!(r.is_observer_side());
    }

    #[test]
    fn poller_overloaded_is_observer_side() {
        let s = TelemetrySignals {
            poller_behind: true,
            ..signals()
        };
        let r = explain_unavailability(&s);
        assert_eq!(r, TelemetryUnavailabilityReason::PollerOverloaded);
        assert!(r.is_observer_side());
    }

    #[test]
    fn never_arrived_is_the_default() {
        let r = explain_unavailability(&signals());
        assert_eq!(r, TelemetryUnavailabilityReason::NeverArrived);
        assert!(!r.is_observer_side());
    }

    #[test]
    fn all_reasons_have_distinct_stable_ids() {
        let all = [
            TelemetryUnavailabilityReason::WorkerLacksTelemetry,
            TelemetryUnavailabilityReason::ParseFailed,
            TelemetryUnavailabilityReason::Pruned,
            TelemetryUnavailabilityReason::DaemonRestarted,
            TelemetryUnavailabilityReason::PollerOverloaded,
            TelemetryUnavailabilityReason::NeverArrived,
        ];
        let mut ids: Vec<&str> = all.iter().map(|r| r.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());
        // Serialized form matches as_str().
        for r in all {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(json, format!("\"{}\"", r.as_str()));
        }
    }

    #[test]
    fn why_unhealthy_from_missing_marks_unhealthy_and_explains() {
        let s = TelemetrySignals {
            poller_behind: true,
            ..signals()
        };
        let w = WhyUnhealthy::from_missing(
            "css",
            &s,
            ProbeOutcome::Ok,
            ProbeOutcome::Timeout,
            Some(15_000),
        );
        assert!(!w.healthy);
        assert_eq!(
            w.unavailability,
            Some(TelemetryUnavailabilityReason::PollerOverloaded)
        );
        assert!(w.freshness.is_none());
        assert!(w.observer_behind);
        assert!(w.explanation.contains("observer-side"));
        assert_eq!(w.last_telemetry_result, ProbeOutcome::Timeout);
        assert_eq!(w.next_probe_in_ms, Some(15_000));
    }

    #[test]
    fn why_unhealthy_from_fresh_assessment_is_healthy() {
        let assessment = assess(&FreshnessInputs::new(
            Duration::from_secs(30),
            Duration::from_secs(20),
            Duration::from_secs(10),
        ));
        assert_eq!(assessment.verdict, FreshnessVerdict::Fresh);
        let w = WhyUnhealthy::from_freshness(
            "css",
            assessment,
            ProbeOutcome::Ok,
            ProbeOutcome::Ok,
            Some(20_000),
        );
        assert!(w.healthy);
        assert!(!w.observer_behind);
        assert!(w.unavailability.is_none());
        assert!(w.freshness.is_some());
    }

    #[test]
    fn why_unhealthy_slow_observer_stays_healthy_but_flags_observer_behind() {
        // A high-RTT worker is usable (SlowObserver) — healthy, observer behind.
        let assessment = assess(&FreshnessInputs {
            host_rtt: Some(Duration::from_secs(8)),
            age: Some(Duration::from_secs(60)),
            ..FreshnessInputs::new(
                Duration::from_secs(30),
                Duration::from_secs(20),
                Duration::from_secs(60),
            )
        });
        assert_eq!(assessment.verdict, FreshnessVerdict::SlowObserver);
        let w = WhyUnhealthy::from_freshness(
            "fra",
            assessment,
            ProbeOutcome::Ok,
            ProbeOutcome::Ok,
            None,
        );
        assert!(w.healthy, "slow-observer worker must remain healthy");
        assert!(w.observer_behind);
    }

    #[test]
    fn why_unhealthy_serializes_with_status_fields() {
        let w = WhyUnhealthy::from_missing(
            "css",
            &TelemetrySignals {
                worker_supports_telemetry: Some(false),
                ..signals()
            },
            ProbeOutcome::Ok,
            ProbeOutcome::NotAttempted,
            None,
        );
        let v = serde_json::to_value(&w).unwrap();
        for key in [
            "worker_id",
            "healthy",
            "unavailability",
            "last_probe_result",
            "last_telemetry_result",
            "observer_behind",
            "explanation",
        ] {
            assert!(v.get(key).is_some(), "missing field {key}");
        }
        assert_eq!(v["unavailability"], "worker_lacks_telemetry");
        assert_eq!(v["last_telemetry_result"], "not_attempted");
        // Omitted optional fields stay absent.
        assert!(v.get("freshness").is_none());
        assert!(v.get("next_probe_in_ms").is_none());
    }
}
