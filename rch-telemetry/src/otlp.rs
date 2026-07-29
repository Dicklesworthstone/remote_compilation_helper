//! OpenTelemetry (OTLP) metrics export for RCH observability.
//!
//! The Prometheus inventory in [`crate::metrics`] is the single typed source of
//! truth for doctor / hook / request events. This module mirrors those same
//! metric families to an OTLP collector so operators who run an OpenTelemetry
//! pipeline (rather than scraping `/metrics`) get identical signals.
//!
//! Activation is env-gated and fail-open:
//! - `RCH_OTEL_ENABLED` = `1` / `true` turns the exporter on.
//! - `RCH_OTEL_EXPORTER_OTLP_ENDPOINT` (preferred) or the standard
//!   `OTEL_EXPORTER_OTLP_ENDPOINT` selects the collector (e.g.
//!   `http://localhost:4317`). With no endpoint the exporter stays off.
//! - `OTEL_SERVICE_NAME` names the resource (default `rch`).
//! - `RCH_OTEL_EXPORT_INTERVAL_SECS` tunes the periodic push cadence.
//!
//! If the exporter cannot be built (bad endpoint, no runtime, …) we log and
//! degrade to Prometheus-only rather than failing the caller.

use std::env;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider};
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

use crate::metrics::{DEFAULT_HISTOGRAM_BUCKETS, HOOK_HISTOGRAM_BUCKETS};

/// Resolved OTLP exporter configuration.
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// Master enable switch (`RCH_OTEL_ENABLED`).
    pub enabled: bool,
    /// Collector endpoint, if configured.
    pub endpoint: Option<String>,
    /// Resource `service.name`.
    pub service_name: String,
    /// Periodic export interval.
    pub interval: Duration,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: "rch".to_string(),
            interval: Duration::from_secs(30),
        }
    }
}

impl OtlpConfig {
    /// Resolve configuration from the environment.
    #[must_use]
    pub fn from_env() -> Self {
        let enabled = env::var("RCH_OTEL_ENABLED")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                v == "1" || v == "true" || v == "yes" || v == "on"
            })
            .unwrap_or(false);

        // RCH-specific override takes precedence over the OTel SDK standard var.
        let endpoint = env::var("RCH_OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .or_else(|| env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let service_name = env::var("OTEL_SERVICE_NAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "rch".to_string());

        let interval = env::var("RCH_OTEL_EXPORT_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|secs| *secs > 0)
            .map_or(Duration::from_secs(30), Duration::from_secs);

        Self {
            enabled,
            endpoint,
            service_name,
            interval,
        }
    }

    /// Whether export should actually be attempted (enabled *and* an endpoint
    /// is present).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && self.endpoint.is_some()
    }
}

/// OTLP-backed mirror of the Prometheus metric inventory.
///
/// Holds OpenTelemetry instruments whose names and label keys match the
/// Prometheus collectors one-for-one. Cheaply cloneable (instruments and the
/// provider are `Arc`-backed). The owned [`SdkMeterProvider`] keeps the export
/// pipeline alive; drop it (via [`OtelMetrics::shutdown`]) to flush and stop.
#[derive(Clone)]
pub struct OtelMetrics {
    provider: SdkMeterProvider,
    doctor_verdict_total: Counter<u64>,
    doctor_probe_duration_seconds: Histogram<f64>,
    doctor_diagnostic_total: Counter<u64>,
    doctor_fix_steps_total: Counter<u64>,
    doctor_fix_duration_seconds: Histogram<f64>,
    doctor_daemon_unreachable_total: Counter<u64>,
    hook_invocations_total: Counter<u64>,
    hook_duration_seconds: Histogram<f64>,
    hook_classify_duration_seconds: Histogram<f64>,
    hook_config_cache_total: Counter<u64>,
    hook_fail_open_total: Counter<u64>,
    hook_autostart_lock_total: Counter<u64>,
    request_duration_seconds: Histogram<f64>,
}

impl OtelMetrics {
    /// Build the OTLP pipeline from env. Returns `Ok(None)` when export is not
    /// active or the exporter could not be constructed (fail-open).
    ///
    /// Must be called from within a Tokio runtime: the OTLP/tonic exporter
    /// establishes its channel on the ambient runtime.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Self::from_config(&OtlpConfig::from_env())
    }

    /// Build the OTLP pipeline from an explicit config. Returns `Ok(None)` when
    /// inactive or on a non-fatal build failure (logged, fail-open).
    pub fn from_config(config: &OtlpConfig) -> anyhow::Result<Option<Self>> {
        if !config.is_active() {
            tracing::debug!(
                target: "rch::telemetry::otlp",
                enabled = config.enabled,
                has_endpoint = config.endpoint.is_some(),
                "otlp.export.inactive",
            );
            return Ok(None);
        }
        // Safe: `is_active()` guarantees the endpoint is present.
        let endpoint = config.endpoint.clone().unwrap_or_default();

        let exporter = match MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint.clone())
            .build()
        {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    target: "rch::telemetry::otlp",
                    endpoint = %endpoint,
                    error = %e,
                    "otlp.exporter.build_failed; degrading to prometheus-only",
                );
                return Ok(None);
            }
        };

        let reader = PeriodicReader::builder(exporter)
            .with_interval(config.interval)
            .build();
        let resource = Resource::builder()
            .with_service_name(config.service_name.clone())
            .build();
        let provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();

        tracing::info!(
            target: "rch::telemetry::otlp",
            endpoint = %endpoint,
            service = %config.service_name,
            interval_secs = config.interval.as_secs(),
            "otlp.export.enabled",
        );

        Ok(Some(Self::from_provider(provider)))
    }

    /// Build the instrument set against a provider's meter. Shared by the live
    /// OTLP path and tests (which inject an in-memory provider).
    fn from_provider(provider: SdkMeterProvider) -> Self {
        let meter = provider.meter("rch-telemetry");
        Self::from_meter(provider, &meter)
    }

    fn from_meter(provider: SdkMeterProvider, meter: &Meter) -> Self {
        Self {
            doctor_verdict_total: meter
                .u64_counter("rch_doctor_verdict_total")
                .with_description("Doctor verdicts by verdict and scope")
                .build(),
            doctor_probe_duration_seconds: meter
                .f64_histogram("rch_doctor_probe_duration_seconds")
                .with_description("Doctor probe duration in seconds")
                .with_unit("s")
                .with_boundaries(DEFAULT_HISTOGRAM_BUCKETS.to_vec())
                .build(),
            doctor_diagnostic_total: meter
                .u64_counter("rch_doctor_diagnostic_total")
                .with_description("Doctor diagnostics by code class and severity")
                .build(),
            doctor_fix_steps_total: meter
                .u64_counter("rch_doctor_fix_steps_total")
                .with_description("Doctor remediation steps by outcome")
                .build(),
            doctor_fix_duration_seconds: meter
                .f64_histogram("rch_doctor_fix_duration_seconds")
                .with_description("Doctor remediation step duration in seconds")
                .with_unit("s")
                .with_boundaries(DEFAULT_HISTOGRAM_BUCKETS.to_vec())
                .build(),
            doctor_daemon_unreachable_total: meter
                .u64_counter("rch_doctor_daemon_unreachable_total")
                .with_description("Doctor invocations where daemon data was unreachable")
                .build(),
            hook_invocations_total: meter
                .u64_counter("rch_hook_invocations_total")
                .with_description("Hook invocations by outcome")
                .build(),
            hook_duration_seconds: meter
                .f64_histogram("rch_hook_duration_seconds")
                .with_description("Hook duration in seconds by outcome")
                .with_unit("s")
                .with_boundaries(HOOK_HISTOGRAM_BUCKETS.to_vec())
                .build(),
            hook_classify_duration_seconds: meter
                .f64_histogram("rch_hook_classify_duration_seconds")
                .with_description("Hook classification duration in seconds by kind")
                .with_unit("s")
                .with_boundaries(HOOK_HISTOGRAM_BUCKETS.to_vec())
                .build(),
            hook_config_cache_total: meter
                .u64_counter("rch_hook_config_cache_total")
                .with_description("Hook config cache events by result and reason")
                .build(),
            hook_fail_open_total: meter
                .u64_counter("rch_hook_fail_open_total")
                .with_description("Hook fail-open events by reason")
                .build(),
            hook_autostart_lock_total: meter
                .u64_counter("rch_hook_autostart_lock_total")
                .with_description("Hook daemon autostart lock events by outcome")
                .build(),
            request_duration_seconds: meter
                .f64_histogram("rch_request_duration_seconds")
                .with_description("Entrypoint request duration in seconds")
                .with_unit("s")
                .with_boundaries(DEFAULT_HISTOGRAM_BUCKETS.to_vec())
                .build(),
            provider,
        }
    }

    /// Flush any buffered metrics and stop the export pipeline. Best-effort.
    pub fn shutdown(&self) {
        if let Err(e) = self.provider.shutdown() {
            tracing::debug!(
                target: "rch::telemetry::otlp",
                error = %e,
                "otlp.shutdown.error",
            );
        }
    }

    /// Force an immediate export (used by tests and graceful shutdown).
    pub fn force_flush(&self) {
        if let Err(e) = self.provider.force_flush() {
            tracing::debug!(
                target: "rch::telemetry::otlp",
                error = %e,
                "otlp.force_flush.error",
            );
        }
    }

    // ---- Mirror methods. Labels are pre-normalized by the caller in
    // `crate::metrics::Metrics` so OTLP and Prometheus carry identical values.

    pub(crate) fn record_doctor_verdict(&self, verdict: &str, scope: &str) {
        self.doctor_verdict_total.add(
            1,
            &[
                KeyValue::new("verdict", verdict.to_string()),
                KeyValue::new("scope", scope.to_string()),
            ],
        );
    }

    pub(crate) fn observe_doctor_probe_duration(&self, probe: &str, result: &str, seconds: f64) {
        self.doctor_probe_duration_seconds.record(
            seconds,
            &[
                KeyValue::new("probe", probe.to_string()),
                KeyValue::new("result", result.to_string()),
            ],
        );
    }

    pub(crate) fn record_doctor_diagnostic(&self, code: &str, severity: &str) {
        self.doctor_diagnostic_total.add(
            1,
            &[
                KeyValue::new("code", code.to_string()),
                KeyValue::new("severity", severity.to_string()),
            ],
        );
    }

    pub(crate) fn record_doctor_fix_step(&self, outcome: &str) {
        self.doctor_fix_steps_total
            .add(1, &[KeyValue::new("outcome", outcome.to_string())]);
    }

    pub(crate) fn observe_doctor_fix_duration(&self, outcome: &str, seconds: f64) {
        self.doctor_fix_duration_seconds
            .record(seconds, &[KeyValue::new("outcome", outcome.to_string())]);
    }

    pub(crate) fn record_doctor_daemon_unreachable(&self) {
        self.doctor_daemon_unreachable_total.add(1, &[]);
    }

    pub(crate) fn record_hook_invocation(&self, outcome: &str) {
        self.hook_invocations_total
            .add(1, &[KeyValue::new("outcome", outcome.to_string())]);
    }

    pub(crate) fn observe_hook_duration(&self, outcome: &str, seconds: f64) {
        self.hook_duration_seconds
            .record(seconds, &[KeyValue::new("outcome", outcome.to_string())]);
    }

    pub(crate) fn observe_hook_classify_duration(&self, kind: &str, seconds: f64) {
        self.hook_classify_duration_seconds
            .record(seconds, &[KeyValue::new("kind", kind.to_string())]);
    }

    pub(crate) fn record_hook_config_cache(&self, result: &str, reason: &str) {
        self.hook_config_cache_total.add(
            1,
            &[
                KeyValue::new("result", result.to_string()),
                KeyValue::new("reason", reason.to_string()),
            ],
        );
    }

    pub(crate) fn record_hook_fail_open(&self, reason: &str) {
        self.hook_fail_open_total
            .add(1, &[KeyValue::new("reason", reason.to_string())]);
    }

    pub(crate) fn record_hook_autostart_lock(&self, outcome: &str) {
        self.hook_autostart_lock_total
            .add(1, &[KeyValue::new("outcome", outcome.to_string())]);
    }

    pub(crate) fn observe_request_duration(&self, entrypoint: &str, seconds: f64) {
        self.request_duration_seconds.record(
            seconds,
            &[KeyValue::new("entrypoint", entrypoint.to_string())],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::metrics::InMemoryMetricExporter;

    /// Build an `OtelMetrics` backed by an in-memory exporter so recordings can
    /// be inspected without a network collector.
    fn in_memory() -> (OtelMetrics, InMemoryMetricExporter) {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        (OtelMetrics::from_provider(provider), exporter)
    }

    #[test]
    fn config_from_env_default_is_inactive() {
        let cfg = OtlpConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.is_active());
        assert_eq!(cfg.service_name, "rch");
        assert_eq!(cfg.interval, Duration::from_secs(30));
    }

    #[test]
    fn config_is_active_requires_enabled_and_endpoint() {
        let mut cfg = OtlpConfig {
            enabled: true,
            endpoint: None,
            ..OtlpConfig::default()
        };
        assert!(!cfg.is_active(), "enabled but no endpoint must be inactive");
        cfg.endpoint = Some("http://localhost:4317".to_string());
        assert!(cfg.is_active());
        cfg.enabled = false;
        assert!(!cfg.is_active(), "endpoint but disabled must be inactive");
    }

    #[test]
    fn from_config_inactive_returns_none() {
        let cfg = OtlpConfig::default();
        let got = OtelMetrics::from_config(&cfg).expect("inactive build is Ok");
        assert!(got.is_none());
    }

    #[test]
    fn instruments_record_and_export_expected_metric_names() {
        let (otel, exporter) = in_memory();

        // Exercise every instrument at least once.
        otel.record_doctor_verdict("degraded", "all");
        otel.observe_doctor_probe_duration("topology", "completed", 0.02);
        otel.record_doctor_diagnostic("RCH-R001", "critical");
        otel.record_doctor_fix_step("applied");
        otel.observe_doctor_fix_duration("applied", 0.5);
        otel.record_doctor_daemon_unreachable();
        otel.record_hook_invocation("redirect");
        otel.observe_hook_duration("redirect", 0.001);
        otel.observe_hook_classify_duration("cargo_build", 0.0005);
        otel.record_hook_config_cache("hit", "none");
        otel.record_hook_fail_open("daemon_unavailable");
        otel.record_hook_autostart_lock("acquired_flock");
        otel.observe_request_duration("hook", 0.01);

        otel.force_flush();

        let exported = exporter.get_finished_metrics().expect("metrics exported");
        let mut names: Vec<String> = Vec::new();
        for rm in &exported {
            for scope in rm.scope_metrics() {
                for metric in scope.metrics() {
                    names.push(metric.name().to_string());
                }
            }
        }

        for expected in [
            "rch_doctor_verdict_total",
            "rch_doctor_probe_duration_seconds",
            "rch_doctor_diagnostic_total",
            "rch_doctor_fix_steps_total",
            "rch_doctor_fix_duration_seconds",
            "rch_doctor_daemon_unreachable_total",
            "rch_hook_invocations_total",
            "rch_hook_duration_seconds",
            "rch_hook_classify_duration_seconds",
            "rch_hook_config_cache_total",
            "rch_hook_fail_open_total",
            "rch_hook_autostart_lock_total",
            "rch_request_duration_seconds",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing exported metric {expected}; got {names:?}"
            );
        }
    }

    #[test]
    fn flush_with_no_recordings_is_safe() {
        // Force-flush before any instrument is touched must not panic and must
        // yield no (or empty) metric data — the export pipeline tolerates an
        // idle daemon.
        let (otel, exporter) = in_memory();
        otel.force_flush();
        let exported = exporter.get_finished_metrics().expect("flush is Ok");
        let total: usize = exported
            .iter()
            .map(|rm| {
                rm.scope_metrics()
                    .map(|s| s.metrics().count())
                    .sum::<usize>()
            })
            .sum();
        assert_eq!(total, 0, "no instruments recorded => no metric data");
    }
}
