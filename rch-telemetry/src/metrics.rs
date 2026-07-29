//! Prometheus metrics and tracing-event bridge for RCH observability.
//!
//! The metrics in this module intentionally use bounded label vocabularies.
//! Raw command text, absolute paths, worker identities, and secret-like values
//! must not become metric labels.

use prometheus::{Counter, CounterVec, HistogramOpts, HistogramVec, Opts, Registry};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

pub(crate) const DEFAULT_HISTOGRAM_BUCKETS: &[f64] =
    &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0];
pub(crate) const HOOK_HISTOGRAM_BUCKETS: &[f64] =
    &[0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05];
const MAX_TRACKED_REQUESTS: usize = 1024;

const VERDICT_LABELS: &[&str] = &["healthy", "degraded", "failing", "unknown"];
const SCOPE_LABELS: &[&str] = &[
    "all",
    "topology",
    "convergence",
    "pressure",
    "triage",
    "helpers",
    "rollout",
    "schema",
    "other",
];
const PROBE_LABELS: &[&str] = &[
    "daemon_status",
    "repo_convergence",
    "helper_compatibility",
    "topology",
    "convergence",
    "pressure",
    "triage",
    "helpers",
    "rollout",
    "schema",
    "other",
];
const PROBE_RESULT_LABELS: &[&str] = &[
    "completed",
    "timeout",
    "panic",
    "cancelled",
    "inner_error",
    "skipped",
    "error",
    "other",
];
const SEVERITY_LABELS: &[&str] = &["info", "warning", "critical", "error", "other"];
const FIX_OUTCOME_LABELS: &[&str] = &[
    "applied",
    "failed",
    "skipped",
    "dry_run",
    "rejected_by_policy",
    "other",
];
const HOOK_OUTCOME_LABELS: &[&str] = &["allow", "redirect", "fail_open", "deny", "error", "other"];
const CLASSIFY_KIND_LABELS: &[&str] = &[
    "cargo_build",
    "cargo_check",
    "cargo_clippy",
    "cargo_test",
    "cargo_doc",
    "cargo_nextest",
    "cargo_bench",
    "rustc",
    "bun_test",
    "bun_typecheck",
    "cc",
    "build_system",
    "non_compilation",
    "unknown",
    "other",
];
const CONFIG_CACHE_RESULT_LABELS: &[&str] = &[
    "hit",
    "miss",
    "disabled",
    "corrupt_recovered",
    "write_failed",
    "written",
    "other",
];
const CONFIG_CACHE_REASON_LABELS: &[&str] = &[
    "none",
    "schema_bumped",
    "source_changed",
    "disabled",
    "corrupt",
    "write_failed",
    "source_changed_during_parse",
    "other",
];
const FAIL_OPEN_REASON_LABELS: &[&str] = &[
    "daemon_unavailable",
    "invalid_hook_input",
    "config_error",
    "classification_error",
    "timeout",
    "worker_unavailable",
    "dependency_preflight",
    "remote_pipeline_failed",
    "panic",
    "other",
];
const AUTOSTART_LOCK_OUTCOME_LABELS: &[&str] = &[
    "acquired_flock",
    "acquired_content_fallback",
    "contended",
    "stale_replaced",
    "failed",
    "other",
];
const ENTRYPOINT_LABELS: &[&str] = &[
    "run_hook",
    "run_doctor",
    "run_reliability_doctor",
    "run_quick_check",
    "apply_remediation_step",
    "rchd_api",
    "other",
];

/// Static inventory metadata used by tests and documentation generators.
#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    /// Prometheus metric name.
    pub name: &'static str,
    /// Label names in declaration order.
    pub labels: &'static [&'static str],
    /// Bounded values accepted for each label.
    pub label_values: &'static [&'static [&'static str]],
}

const METRIC_SPECS: &[MetricSpec] = &[
    MetricSpec {
        name: "rch_doctor_verdict_total",
        labels: &["verdict", "scope"],
        label_values: &[VERDICT_LABELS, SCOPE_LABELS],
    },
    MetricSpec {
        name: "rch_doctor_probe_duration_seconds",
        labels: &["probe", "result"],
        label_values: &[PROBE_LABELS, PROBE_RESULT_LABELS],
    },
    MetricSpec {
        name: "rch_doctor_diagnostic_total",
        labels: &["code", "severity"],
        label_values: &[&["known", "other"], SEVERITY_LABELS],
    },
    MetricSpec {
        name: "rch_doctor_fix_steps_total",
        labels: &["outcome"],
        label_values: &[FIX_OUTCOME_LABELS],
    },
    MetricSpec {
        name: "rch_doctor_fix_duration_seconds",
        labels: &["outcome"],
        label_values: &[FIX_OUTCOME_LABELS],
    },
    MetricSpec {
        name: "rch_doctor_daemon_unreachable_total",
        labels: &[],
        label_values: &[],
    },
    MetricSpec {
        name: "rch_hook_invocations_total",
        labels: &["outcome"],
        label_values: &[HOOK_OUTCOME_LABELS],
    },
    MetricSpec {
        name: "rch_hook_duration_seconds",
        labels: &["outcome"],
        label_values: &[HOOK_OUTCOME_LABELS],
    },
    MetricSpec {
        name: "rch_hook_classify_duration_seconds",
        labels: &["kind"],
        label_values: &[CLASSIFY_KIND_LABELS],
    },
    MetricSpec {
        name: "rch_hook_config_cache_total",
        labels: &["result", "reason"],
        label_values: &[CONFIG_CACHE_RESULT_LABELS, CONFIG_CACHE_REASON_LABELS],
    },
    MetricSpec {
        name: "rch_hook_fail_open_total",
        labels: &["reason"],
        label_values: &[FAIL_OPEN_REASON_LABELS],
    },
    MetricSpec {
        name: "rch_hook_autostart_lock_total",
        labels: &["outcome"],
        label_values: &[AUTOSTART_LOCK_OUTCOME_LABELS],
    },
    MetricSpec {
        name: "rch_request_duration_seconds",
        labels: &["entrypoint"],
        label_values: &[ENTRYPOINT_LABELS],
    },
];

/// Prometheus collectors for doctor, hook, and request-correlation events.
#[derive(Clone)]
pub struct Metrics {
    /// Doctor verdicts by bounded verdict and scope.
    pub doctor_verdict_total: CounterVec,
    /// Doctor probe durations in seconds by probe and result.
    pub doctor_probe_duration_seconds: HistogramVec,
    /// Doctor diagnostics by bounded code class and severity.
    pub doctor_diagnostic_total: CounterVec,
    /// Doctor remediation steps by outcome.
    pub doctor_fix_steps_total: CounterVec,
    /// Doctor remediation step durations in seconds by outcome.
    pub doctor_fix_duration_seconds: HistogramVec,
    /// Doctor invocations where daemon data was unavailable.
    pub doctor_daemon_unreachable_total: Counter,
    /// Hook invocations by final outcome.
    pub hook_invocations_total: CounterVec,
    /// Hook wall-clock duration in seconds by outcome.
    pub hook_duration_seconds: HistogramVec,
    /// Hook classification duration in seconds by normalized command kind.
    pub hook_classify_duration_seconds: HistogramVec,
    /// Hook config cache events by result and reason.
    pub hook_config_cache_total: CounterVec,
    /// Hook fail-open events by bounded reason.
    pub hook_fail_open_total: CounterVec,
    /// Hook autostart lock events by outcome.
    pub hook_autostart_lock_total: CounterVec,
    /// Entrypoint request durations in seconds.
    pub request_duration_seconds: HistogramVec,
    /// Optional OTLP mirror. When present, every record/observe call is also
    /// forwarded to OpenTelemetry instruments carrying the same (already
    /// normalized) labels, so a configured OTLP collector receives identical
    /// signals to the Prometheus exposition. `None` = Prometheus-only.
    otel: Option<crate::otlp::OtelMetrics>,
}

impl Metrics {
    /// Create a metrics inventory without registering it.
    pub fn new() -> prometheus::Result<Self> {
        Ok(Self {
            doctor_verdict_total: counter_vec(
                "rch_doctor_verdict_total",
                "Doctor verdicts by verdict and scope",
                &["verdict", "scope"],
            )?,
            doctor_probe_duration_seconds: histogram_vec(
                "rch_doctor_probe_duration_seconds",
                "Doctor probe duration in seconds",
                DEFAULT_HISTOGRAM_BUCKETS,
                &["probe", "result"],
            )?,
            doctor_diagnostic_total: counter_vec(
                "rch_doctor_diagnostic_total",
                "Doctor diagnostics by code class and severity",
                &["code", "severity"],
            )?,
            doctor_fix_steps_total: counter_vec(
                "rch_doctor_fix_steps_total",
                "Doctor remediation steps by outcome",
                &["outcome"],
            )?,
            doctor_fix_duration_seconds: histogram_vec(
                "rch_doctor_fix_duration_seconds",
                "Doctor remediation step duration in seconds",
                DEFAULT_HISTOGRAM_BUCKETS,
                &["outcome"],
            )?,
            doctor_daemon_unreachable_total: Counter::with_opts(Opts::new(
                "rch_doctor_daemon_unreachable_total",
                "Doctor invocations where daemon data was unreachable",
            ))?,
            hook_invocations_total: counter_vec(
                "rch_hook_invocations_total",
                "Hook invocations by outcome",
                &["outcome"],
            )?,
            hook_duration_seconds: histogram_vec(
                "rch_hook_duration_seconds",
                "Hook duration in seconds by outcome",
                HOOK_HISTOGRAM_BUCKETS,
                &["outcome"],
            )?,
            hook_classify_duration_seconds: histogram_vec(
                "rch_hook_classify_duration_seconds",
                "Hook classification duration in seconds by kind",
                HOOK_HISTOGRAM_BUCKETS,
                &["kind"],
            )?,
            hook_config_cache_total: counter_vec(
                "rch_hook_config_cache_total",
                "Hook config cache events by result and reason",
                &["result", "reason"],
            )?,
            hook_fail_open_total: counter_vec(
                "rch_hook_fail_open_total",
                "Hook fail-open events by reason",
                &["reason"],
            )?,
            hook_autostart_lock_total: counter_vec(
                "rch_hook_autostart_lock_total",
                "Hook daemon autostart lock events by outcome",
                &["outcome"],
            )?,
            request_duration_seconds: histogram_vec(
                "rch_request_duration_seconds",
                "Entrypoint request duration in seconds",
                DEFAULT_HISTOGRAM_BUCKETS,
                &["entrypoint"],
            )?,
            otel: None,
        })
    }

    /// Attach an OTLP mirror so subsequent record/observe calls also export via
    /// OpenTelemetry. Replaces any previously attached mirror; pass the value
    /// returned by [`crate::otlp::OtelMetrics::from_env`].
    #[must_use]
    pub fn with_otel(mut self, otel: Option<crate::otlp::OtelMetrics>) -> Self {
        self.otel = otel;
        self
    }

    /// Whether an OTLP mirror is currently attached.
    #[must_use]
    pub fn otel_enabled(&self) -> bool {
        self.otel.is_some()
    }

    /// Create and register metrics in the global Prometheus default registry.
    ///
    /// Duplicate registration is treated as success so repeated test setup or
    /// process initialization does not panic.
    pub fn registered_default() -> prometheus::Result<Self> {
        let metrics = Self::new()?;
        metrics.register(prometheus::default_registry())?;
        Ok(metrics)
    }

    /// Register every collector in the supplied registry.
    pub fn register(&self, registry: &Registry) -> prometheus::Result<()> {
        register_collector(registry, Box::new(self.doctor_verdict_total.clone()))?;
        register_collector(
            registry,
            Box::new(self.doctor_probe_duration_seconds.clone()),
        )?;
        register_collector(registry, Box::new(self.doctor_diagnostic_total.clone()))?;
        register_collector(registry, Box::new(self.doctor_fix_steps_total.clone()))?;
        register_collector(registry, Box::new(self.doctor_fix_duration_seconds.clone()))?;
        register_collector(
            registry,
            Box::new(self.doctor_daemon_unreachable_total.clone()),
        )?;
        register_collector(registry, Box::new(self.hook_invocations_total.clone()))?;
        register_collector(registry, Box::new(self.hook_duration_seconds.clone()))?;
        register_collector(
            registry,
            Box::new(self.hook_classify_duration_seconds.clone()),
        )?;
        register_collector(registry, Box::new(self.hook_config_cache_total.clone()))?;
        register_collector(registry, Box::new(self.hook_fail_open_total.clone()))?;
        register_collector(registry, Box::new(self.hook_autostart_lock_total.clone()))?;
        register_collector(registry, Box::new(self.request_duration_seconds.clone()))?;
        Ok(())
    }

    /// Return the static metric inventory.
    pub fn specs() -> &'static [MetricSpec] {
        METRIC_SPECS
    }

    /// Increment `rch_doctor_verdict_total`.
    pub fn record_doctor_verdict(&self, verdict: &str, scope: &str) {
        let (verdict, scope) = (normalize_verdict(verdict), normalize_scope(scope));
        self.doctor_verdict_total
            .with_label_values(&[verdict, scope])
            .inc();
        if let Some(otel) = &self.otel {
            otel.record_doctor_verdict(verdict, scope);
        }
    }

    /// Observe `rch_doctor_probe_duration_seconds`.
    pub fn observe_doctor_probe_duration(&self, probe: &str, result: &str, seconds: f64) {
        let (probe, result) = (normalize_probe(probe), normalize_probe_result(result));
        let seconds = sanitize_duration(seconds);
        self.doctor_probe_duration_seconds
            .with_label_values(&[probe, result])
            .observe(seconds);
        if let Some(otel) = &self.otel {
            otel.observe_doctor_probe_duration(probe, result, seconds);
        }
    }

    /// Increment `rch_doctor_diagnostic_total`.
    pub fn record_doctor_diagnostic(&self, code: &str, severity: &str) {
        let (code, severity) = (normalize_code(code), normalize_severity(severity));
        self.doctor_diagnostic_total
            .with_label_values(&[code, severity])
            .inc();
        if let Some(otel) = &self.otel {
            otel.record_doctor_diagnostic(code, severity);
        }
    }

    /// Increment `rch_doctor_fix_steps_total`.
    pub fn record_doctor_fix_step(&self, outcome: &str) {
        let outcome = normalize_fix_outcome(outcome);
        self.doctor_fix_steps_total
            .with_label_values(&[outcome])
            .inc();
        if let Some(otel) = &self.otel {
            otel.record_doctor_fix_step(outcome);
        }
    }

    /// Observe `rch_doctor_fix_duration_seconds`.
    pub fn observe_doctor_fix_duration(&self, outcome: &str, seconds: f64) {
        let outcome = normalize_fix_outcome(outcome);
        let seconds = sanitize_duration(seconds);
        self.doctor_fix_duration_seconds
            .with_label_values(&[outcome])
            .observe(seconds);
        if let Some(otel) = &self.otel {
            otel.observe_doctor_fix_duration(outcome, seconds);
        }
    }

    /// Increment `rch_doctor_daemon_unreachable_total`.
    pub fn record_doctor_daemon_unreachable(&self) {
        self.doctor_daemon_unreachable_total.inc();
        if let Some(otel) = &self.otel {
            otel.record_doctor_daemon_unreachable();
        }
    }

    /// Increment `rch_hook_invocations_total`.
    pub fn record_hook_invocation(&self, outcome: &str) {
        let outcome = normalize_hook_outcome(outcome);
        self.hook_invocations_total
            .with_label_values(&[outcome])
            .inc();
        if let Some(otel) = &self.otel {
            otel.record_hook_invocation(outcome);
        }
    }

    /// Observe `rch_hook_duration_seconds`.
    pub fn observe_hook_duration(&self, outcome: &str, seconds: f64) {
        let outcome = normalize_hook_outcome(outcome);
        let seconds = sanitize_duration(seconds);
        self.hook_duration_seconds
            .with_label_values(&[outcome])
            .observe(seconds);
        if let Some(otel) = &self.otel {
            otel.observe_hook_duration(outcome, seconds);
        }
    }

    /// Observe `rch_hook_classify_duration_seconds`.
    pub fn observe_hook_classify_duration(&self, kind: &str, seconds: f64) {
        let kind = normalize_classify_kind(kind);
        let seconds = sanitize_duration(seconds);
        self.hook_classify_duration_seconds
            .with_label_values(&[kind])
            .observe(seconds);
        if let Some(otel) = &self.otel {
            otel.observe_hook_classify_duration(kind, seconds);
        }
    }

    /// Increment `rch_hook_config_cache_total`.
    pub fn record_hook_config_cache(&self, result: &str, reason: &str) {
        let (result, reason) = (
            normalize_config_cache_result(result),
            normalize_config_cache_reason(reason),
        );
        self.hook_config_cache_total
            .with_label_values(&[result, reason])
            .inc();
        if let Some(otel) = &self.otel {
            otel.record_hook_config_cache(result, reason);
        }
    }

    /// Increment `rch_hook_fail_open_total`.
    pub fn record_hook_fail_open(&self, reason: &str) {
        let reason = normalize_fail_open_reason(reason);
        self.hook_fail_open_total.with_label_values(&[reason]).inc();
        if let Some(otel) = &self.otel {
            otel.record_hook_fail_open(reason);
        }
    }

    /// Increment `rch_hook_autostart_lock_total`.
    pub fn record_hook_autostart_lock(&self, outcome: &str) {
        let outcome = normalize_autostart_lock_outcome(outcome);
        self.hook_autostart_lock_total
            .with_label_values(&[outcome])
            .inc();
        if let Some(otel) = &self.otel {
            otel.record_hook_autostart_lock(outcome);
        }
    }

    /// Observe `rch_request_duration_seconds`.
    pub fn observe_request_duration(&self, entrypoint: &str, seconds: f64) {
        let entrypoint = normalize_entrypoint(entrypoint);
        let seconds = sanitize_duration(seconds);
        self.request_duration_seconds
            .with_label_values(&[entrypoint])
            .observe(seconds);
        if let Some(otel) = &self.otel {
            otel.observe_request_duration(entrypoint, seconds);
        }
    }
}

/// A `tracing-subscriber` layer that maps known RCH events into metrics.
#[derive(Clone)]
pub struct MetricsLayer {
    metrics: Metrics,
    request_starts: Arc<Mutex<HashMap<String, RequestStart>>>,
}

impl MetricsLayer {
    /// Create a tracing layer backed by the provided metrics inventory.
    pub fn new(metrics: Metrics) -> Self {
        Self {
            metrics,
            request_starts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Access the underlying metrics.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    fn record_event(&self, metadata_target: &str, fields: &EventFields) -> bool {
        if metadata_target == "rch::telemetry::metrics_layer"
            && fields.string("message") == Some("metrics.layer.event_unmapped")
        {
            return true;
        }

        let Some(event_name) = fields.event_name() else {
            return false;
        };
        match event_name {
            "doctor.verdict" => {
                let verdict = fields.string("verdict").unwrap_or("unknown");
                let scope = fields.string("scope").unwrap_or("all");
                self.metrics.record_doctor_verdict(verdict, scope);
                if fields.bool("daemon_unreachable").unwrap_or(false) {
                    self.metrics.record_doctor_daemon_unreachable();
                }
                true
            }
            "doctor.probe.end" => {
                let probe = fields.string("probe").unwrap_or("other");
                let result = fields
                    .string("result")
                    .or_else(|| fields.string("outcome"))
                    .unwrap_or("other");
                let seconds = fields.duration_seconds().unwrap_or(0.0);
                self.metrics
                    .observe_doctor_probe_duration(probe, result, seconds);
                true
            }
            "doctor.probe.timeout"
            | "doctor.probe.panicked"
            | "doctor.probe.cancelled"
            | "doctor.probe.inner_error" => {
                let probe = fields.string("probe").unwrap_or("other");
                let result = probe_result_from_event(event_name);
                let seconds = fields.duration_seconds().unwrap_or(0.0);
                self.metrics
                    .observe_doctor_probe_duration(probe, result, seconds);
                true
            }
            "doctor.diagnostic" => {
                let code = fields.string("code").unwrap_or("other");
                let severity = fields.string("severity").unwrap_or("other");
                self.metrics.record_doctor_diagnostic(code, severity);
                true
            }
            "doctor.fix.step.applied" | "doctor.fix.step.failed" => {
                let outcome = fields
                    .string("outcome")
                    .unwrap_or_else(|| fix_outcome_from_event(event_name));
                self.metrics.record_doctor_fix_step(outcome);
                if let Some(seconds) = fields.duration_seconds() {
                    self.metrics.observe_doctor_fix_duration(outcome, seconds);
                }
                true
            }
            "hook.invocation" | "hook.invocation.end" => {
                let outcome = fields.string("outcome").unwrap_or("other");
                self.metrics.record_hook_invocation(outcome);
                if let Some(seconds) = fields.duration_seconds() {
                    self.metrics.observe_hook_duration(outcome, seconds);
                }
                true
            }
            "hook.timing.record" | "hook.classify" | "hook.classify.end" => {
                let kind = fields
                    .string("kind")
                    .or_else(|| fields.string("classification_kind"))
                    .unwrap_or("unknown");
                let seconds = fields.duration_seconds().unwrap_or(0.0);
                self.metrics.observe_hook_classify_duration(kind, seconds);
                true
            }
            "config.cache.hit"
            | "config.cache.miss_schema_bumped"
            | "config.cache.miss_source_changed"
            | "config.cache.corrupt_recovered"
            | "config.cache.write_failed"
            | "config.cache.written"
            | "config.cache.write_skipped_source_changed_during_parse" => {
                let (result, reason) = config_cache_result_reason(event_name);
                self.metrics.record_hook_config_cache(result, reason);
                true
            }
            "hook.config.cache_hit" | "hook.config.cache_miss" => {
                let result = fields
                    .string("result")
                    .unwrap_or_else(|| hook_config_cache_result_from_event(event_name));
                let reason = fields.string("reason").unwrap_or("none");
                self.metrics.record_hook_config_cache(result, reason);
                true
            }
            "hook.fail_open" => {
                let reason = fields.string("reason").unwrap_or("other");
                self.metrics.record_hook_fail_open(reason);
                true
            }
            "hook.autostart_lock" => {
                let outcome = fields.string("outcome").unwrap_or("other");
                self.metrics.record_hook_autostart_lock(outcome);
                true
            }
            "request.start" => {
                self.record_request_start(fields);
                true
            }
            "request.end" => {
                self.record_request_end(fields);
                true
            }
            "metrics.layer.event_unmapped" => true,
            _ if metadata_target.starts_with("rch::") => {
                tracing::debug!(
                    target: "rch::telemetry::metrics_layer",
                    event_target = metadata_target,
                    event_name,
                    "metrics.layer.event_unmapped",
                );
                false
            }
            _ => false,
        }
    }

    fn record_request_start(&self, fields: &EventFields) {
        // A request with no id cannot be correlated to its later `request.end`.
        // Tracking it under a shared "default" key would conflate concurrent
        // unidentified requests (they'd overwrite each other), so skip tracking
        // — such a request only contributes a duration if its end carries an
        // inline `duration_seconds`.
        let Some(request_id) = fields.string("request_id") else {
            return;
        };
        let entrypoint = fields.string("entrypoint").unwrap_or("other").to_string();
        if let Ok(mut starts) = self.request_starts.lock() {
            // Bound the map by evicting the OLDEST in-flight entry rather than
            // clearing the whole map — clearing dropped every pending request's
            // duration (its later `request.end` would find no start). Only
            // evict when actually growing (a re-start of a known id replaces in
            // place).
            if starts.len() >= MAX_TRACKED_REQUESTS
                && !starts.contains_key(request_id)
                && let Some(oldest_key) = starts
                    .iter()
                    .min_by_key(|(_, started)| started.start)
                    .map(|(key, _)| key.clone())
            {
                starts.remove(&oldest_key);
            }
            starts.insert(
                request_id.to_string(),
                RequestStart {
                    entrypoint,
                    start: Instant::now(),
                },
            );
        }
    }

    fn record_request_end(&self, fields: &EventFields) {
        let entrypoint = fields.string("entrypoint").unwrap_or("other");
        if let Some(seconds) = fields.duration_seconds() {
            self.metrics.observe_request_duration(entrypoint, seconds);
            return;
        }
        // No inline duration: correlate to the tracked start by request_id.
        // Without an id there is nothing to correlate (the start was not
        // tracked), so there is no duration to record.
        let Some(request_id) = fields.string("request_id") else {
            return;
        };
        if let Ok(mut starts) = self.request_starts.lock()
            && let Some(started) = starts.remove(request_id)
        {
            self.metrics.observe_request_duration(
                &started.entrypoint,
                started.start.elapsed().as_secs_f64(),
            );
        }
    }
}

impl<S> Layer<S> for MetricsLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = EventFields::default();
        event.record(&mut fields);
        self.record_event(event.metadata().target(), &fields);
    }
}

#[derive(Debug)]
struct RequestStart {
    entrypoint: String,
    start: Instant,
}

#[derive(Default)]
struct EventFields {
    values: BTreeMap<String, FieldValue>,
}

impl EventFields {
    fn event_name(&self) -> Option<&str> {
        self.string("event_name")
            .or_else(|| self.string("message"))
            .filter(|value| !value.is_empty())
    }

    fn string(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(FieldValue::as_str)
    }

    fn bool(&self, name: &str) -> Option<bool> {
        self.values.get(name).and_then(FieldValue::as_bool)
    }

    fn number(&self, name: &str) -> Option<f64> {
        self.values.get(name).and_then(FieldValue::as_f64)
    }

    fn duration_seconds(&self) -> Option<f64> {
        self.number("duration_seconds")
            .or_else(|| self.number("duration_secs"))
            .or_else(|| self.number("elapsed_seconds"))
            .or_else(|| self.number("elapsed_secs"))
            .or_else(|| self.number("duration_ms").map(|value| value / 1000.0))
            .or_else(|| self.number("elapsed_ms").map(|value| value / 1000.0))
            .or_else(|| self.number("join_elapsed_ms").map(|value| value / 1000.0))
            .or_else(|| self.number("duration_us").map(|value| value / 1_000_000.0))
            .or_else(|| self.number("elapsed_us").map(|value| value / 1_000_000.0))
            .or_else(|| {
                self.number("classification_duration_us")
                    .map(|value| value / 1_000_000.0)
            })
    }
}

impl Visit for EventFields {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.values
            .insert(field.name().to_string(), FieldValue::F64(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.values
            .insert(field.name().to_string(), FieldValue::I64(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.values
            .insert(field.name().to_string(), FieldValue::U64(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.values
            .insert(field.name().to_string(), FieldValue::Bool(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.values.insert(
            field.name().to_string(),
            FieldValue::String(clean_debug_string(value)),
        );
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.values.insert(
            field.name().to_string(),
            FieldValue::String(clean_debug_string(&format!("{value:?}"))),
        );
    }
}

#[derive(Debug, Clone)]
enum FieldValue {
    String(String),
    F64(f64),
    I64(i64),
    U64(u64),
    Bool(bool),
}

impl FieldValue {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::F64(_) | Self::I64(_) | Self::U64(_) | Self::Bool(_) => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            Self::String(value) => value.parse().ok(),
            Self::F64(_) | Self::I64(_) | Self::U64(_) => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Self::F64(value) => Some(*value),
            Self::I64(value) => Some(*value as f64),
            Self::U64(value) => Some(*value as f64),
            Self::String(value) => value.parse().ok(),
            Self::Bool(_) => None,
        }
    }
}

fn counter_vec(name: &str, help: &str, labels: &[&str]) -> prometheus::Result<CounterVec> {
    CounterVec::new(Opts::new(name, help), labels)
}

fn histogram_vec(
    name: &str,
    help: &str,
    buckets: &[f64],
    labels: &[&str],
) -> prometheus::Result<HistogramVec> {
    HistogramVec::new(
        HistogramOpts::new(name, help).buckets(buckets.to_vec()),
        labels,
    )
}

fn register_collector(
    registry: &Registry,
    collector: Box<dyn prometheus::core::Collector>,
) -> prometheus::Result<()> {
    match registry.register(collector) {
        Ok(()) | Err(prometheus::Error::AlreadyReg) => Ok(()),
        Err(error) => Err(error),
    }
}

fn clean_debug_string(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn sanitize_duration(seconds: f64) -> f64 {
    if seconds.is_finite() && seconds >= 0.0 {
        seconds
    } else {
        0.0
    }
}

fn normalize_from(
    value: &str,
    allowed: &'static [&'static str],
    default: &'static str,
) -> &'static str {
    let token = normalize_token(value);
    allowed
        .iter()
        .copied()
        .find(|candidate| candidate.eq(&token.as_str()))
        .unwrap_or(default)
}

fn normalize_token(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .chars()
        .map(|ch| match ch {
            'A'..='Z' => ch.to_ascii_lowercase(),
            'a'..='z' | '0'..='9' => ch,
            '-' | '.' | ':' | '/' | ' ' => '_',
            '_' => '_',
            _ => '_',
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn normalize_verdict(value: &str) -> &'static str {
    normalize_from(value, VERDICT_LABELS, "unknown")
}

fn normalize_scope(value: &str) -> &'static str {
    normalize_from(value, SCOPE_LABELS, "other")
}

fn normalize_probe(value: &str) -> &'static str {
    normalize_from(value, PROBE_LABELS, "other")
}

fn normalize_probe_result(value: &str) -> &'static str {
    match normalize_token(value).as_str() {
        "ok" | "success" | "completed" => "completed",
        "panicked" | "panic" => "panic",
        "timeout" | "timed_out" => "timeout",
        "cancelled" | "canceled" => "cancelled",
        "inner_error" => "inner_error",
        "skipped" => "skipped",
        "error" | "failed" => "error",
        _ => "other",
    }
}

fn normalize_code(value: &str) -> &'static str {
    let token = normalize_token(value);
    if token.starts_with("rch_e")
        && token.len() == "rch_e000".len()
        && token
            .chars()
            .skip("rch_e".len())
            .all(|ch| ch.is_ascii_digit())
    {
        "known"
    } else {
        "other"
    }
}

fn normalize_severity(value: &str) -> &'static str {
    normalize_from(value, SEVERITY_LABELS, "other")
}

fn normalize_fix_outcome(value: &str) -> &'static str {
    normalize_from(value, FIX_OUTCOME_LABELS, "other")
}

fn normalize_hook_outcome(value: &str) -> &'static str {
    normalize_from(value, HOOK_OUTCOME_LABELS, "other")
}

fn normalize_classify_kind(value: &str) -> &'static str {
    let token = normalize_token(value);
    match token.as_str() {
        "cargobuild" => "cargo_build",
        "cargocheck" => "cargo_check",
        "cargoclippy" => "cargo_clippy",
        "cargotest" => "cargo_test",
        "cargodoc" => "cargo_doc",
        "cargonextest" => "cargo_nextest",
        "cargobench" => "cargo_bench",
        "bun_test" | "buntest" => "bun_test",
        "bun_typecheck" | "buntypecheck" => "bun_typecheck",
        "gcc" | "g__" | "clang" | "clang__" | "cc" => "cc",
        "make" | "cmake" | "ninja" | "meson" | "buildsystem" | "build_system" => "build_system",
        _ => normalize_from(&token, CLASSIFY_KIND_LABELS, "other"),
    }
}

fn normalize_config_cache_result(value: &str) -> &'static str {
    normalize_from(value, CONFIG_CACHE_RESULT_LABELS, "other")
}

fn normalize_config_cache_reason(value: &str) -> &'static str {
    normalize_from(value, CONFIG_CACHE_REASON_LABELS, "other")
}

fn normalize_fail_open_reason(value: &str) -> &'static str {
    normalize_from(value, FAIL_OPEN_REASON_LABELS, "other")
}

fn normalize_autostart_lock_outcome(value: &str) -> &'static str {
    normalize_from(value, AUTOSTART_LOCK_OUTCOME_LABELS, "other")
}

fn normalize_entrypoint(value: &str) -> &'static str {
    normalize_from(value, ENTRYPOINT_LABELS, "other")
}

fn probe_result_from_event(event_name: &str) -> &'static str {
    match event_name {
        "doctor.probe.timeout" => "timeout",
        "doctor.probe.panicked" => "panic",
        "doctor.probe.cancelled" => "cancelled",
        "doctor.probe.inner_error" => "inner_error",
        _ => "other",
    }
}

fn fix_outcome_from_event(event_name: &str) -> &'static str {
    match event_name {
        "doctor.fix.step.applied" => "applied",
        "doctor.fix.step.failed" => "failed",
        _ => "other",
    }
}

fn hook_config_cache_result_from_event(event_name: &str) -> &'static str {
    match event_name {
        "hook.config.cache_hit" => "hit",
        "hook.config.cache_miss" => "miss",
        _ => "other",
    }
}

fn config_cache_result_reason(event_name: &str) -> (&'static str, &'static str) {
    match event_name {
        "config.cache.hit" => ("hit", "none"),
        "config.cache.miss_schema_bumped" => ("miss", "schema_bumped"),
        "config.cache.miss_source_changed" => ("miss", "source_changed"),
        "config.cache.corrupt_recovered" => ("corrupt_recovered", "corrupt"),
        "config.cache.write_failed" => ("write_failed", "write_failed"),
        "config.cache.written" => ("written", "none"),
        "config.cache.write_skipped_source_changed_during_parse" => {
            ("miss", "source_changed_during_parse")
        }
        _ => ("other", "other"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    fn metrics_with_layer() -> (Metrics, MetricsLayer) {
        let metrics = Metrics::new().expect("metrics construct");
        let layer = MetricsLayer::new(metrics.clone());
        (metrics, layer)
    }

    fn run_with_layer(layer: MetricsLayer, f: impl FnOnce()) {
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
    }

    #[test]
    fn metrics_register_no_panic() {
        let metrics = Metrics::new().expect("metrics construct");
        let registry = Registry::new();
        metrics.register(&registry).expect("first register");
        metrics
            .register(&registry)
            .expect("duplicate register is ignored");
        metrics.record_doctor_verdict("healthy", "all");
        metrics.observe_hook_classify_duration("cargo_test", 0.001);
        let names = registry
            .gather()
            .into_iter()
            .map(|family| family.name().to_string())
            .collect::<Vec<_>>();
        assert!(names.contains(&"rch_doctor_verdict_total".to_string()));
        assert!(names.contains(&"rch_hook_classify_duration_seconds".to_string()));
    }

    #[test]
    fn metrics_label_cardinality_bounded() {
        for spec in Metrics::specs() {
            assert_eq!(spec.labels.len(), spec.label_values.len());
            let cardinality = spec
                .label_values
                .iter()
                .map(|values| values.len().max(1))
                .product::<usize>();
            assert!(
                cardinality < 200,
                "{} cardinality was {cardinality}",
                spec.name
            );
        }
    }

    #[test]
    fn metrics_naming_convention() {
        for spec in Metrics::specs() {
            assert!(spec.name.starts_with("rch_"));
            assert!(
                spec.name.ends_with("_total")
                    || spec.name.ends_with("_seconds")
                    || spec.name.ends_with("_bytes")
            );
            assert!(
                spec.name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || matches!(ch, '_') || ch.is_ascii_digit())
            );
        }
    }

    #[test]
    fn doctor_verdict_event_increments_counter() {
        let (metrics, layer) = metrics_with_layer();
        run_with_layer(layer, || {
            tracing::info!(
                target: "rch::doctor::verdict",
                verdict = "degraded",
                scope = "all",
                "doctor.verdict",
            );
        });

        assert_eq!(
            metrics
                .doctor_verdict_total
                .with_label_values(&["degraded", "all"])
                .get(),
            1.0
        );
    }

    #[test]
    fn hook_classify_event_increments_histogram() {
        let (metrics, layer) = metrics_with_layer();
        run_with_layer(layer, || {
            tracing::debug!(
                target: "rch::hook::timing",
                kind = "CargoTest",
                duration_us = 2_500_u64,
                "hook.classify",
            );
        });

        assert_eq!(
            metrics
                .hook_classify_duration_seconds
                .with_label_values(&["cargo_test"])
                .get_sample_count(),
            1
        );
    }

    #[test]
    fn config_cache_event_increments_bounded_counter() {
        let (metrics, layer) = metrics_with_layer();
        run_with_layer(layer, || {
            tracing::debug!(
                target: "rch::hook::config_cache",
                path = "/home/alice/.config/rch/config.cache.json",
                "config.cache.hit",
            );
        });

        assert_eq!(
            metrics
                .hook_config_cache_total
                .with_label_values(&["hit", "none"])
                .get(),
            1.0
        );
        assert_eq!(
            metrics
                .hook_config_cache_total
                .with_label_values(&["other", "other"])
                .get(),
            0.0
        );
    }

    #[test]
    fn unmapped_rch_event_returns_false_and_self_signal_is_ignored() {
        let (_, layer) = metrics_with_layer();
        let mut fields = EventFields::default();
        fields.values.insert(
            "message".to_string(),
            FieldValue::String("future.event".to_string()),
        );
        assert!(!layer.record_event("rch::future_surface", &fields));

        fields.values.insert(
            "message".to_string(),
            FieldValue::String("metrics.layer.event_unmapped".to_string()),
        );
        fields.values.insert(
            "event_name".to_string(),
            FieldValue::String("future.event".to_string()),
        );
        assert!(layer.record_event("rch::telemetry::metrics_layer", &fields));
    }

    #[test]
    fn request_start_end_records_duration() {
        let (metrics, layer) = metrics_with_layer();
        run_with_layer(layer, || {
            tracing::info!(
                target: "rch::request",
                request_id = "req-1",
                entrypoint = "run_hook",
                "request.start",
            );
            tracing::info!(
                target: "rch::request",
                request_id = "req-1",
                "request.end",
            );
        });

        assert_eq!(
            metrics
                .request_duration_seconds
                .with_label_values(&["run_hook"])
                .get_sample_count(),
            1
        );
    }

    fn request_fields(pairs: &[(&str, &str)]) -> EventFields {
        let mut values = std::collections::BTreeMap::new();
        for (k, v) in pairs {
            values.insert((*k).to_string(), FieldValue::String((*v).to_string()));
        }
        EventFields { values }
    }

    #[test]
    fn request_start_then_end_records_duration_by_correlation() {
        let layer = MetricsLayer::new(Metrics::new().expect("metrics"));
        let label = normalize_entrypoint("hook");
        let before = layer
            .metrics
            .request_duration_seconds
            .with_label_values(&[label])
            .get_sample_count();
        layer.record_request_start(&request_fields(&[
            ("request_id", "r1"),
            ("entrypoint", "hook"),
        ]));
        // request.end without an inline duration must correlate to the start.
        layer.record_request_end(&request_fields(&[
            ("request_id", "r1"),
            ("entrypoint", "hook"),
        ]));
        let after = layer
            .metrics
            .request_duration_seconds
            .with_label_values(&[label])
            .get_sample_count();
        assert_eq!(after, before + 1, "correlated duration must be recorded");
    }

    #[test]
    fn full_map_evicts_one_not_clears_all() {
        // Regression (bd-review-metrics-request-starts-clear): filling the map
        // then adding one more must evict a single oldest entry, NOT wipe every
        // in-flight start (which dropped all their pending durations).
        let layer = MetricsLayer::new(Metrics::new().expect("metrics"));
        for i in 0..MAX_TRACKED_REQUESTS {
            layer.record_request_start(&request_fields(&[
                ("request_id", &format!("r{i}")),
                ("entrypoint", "hook"),
            ]));
        }
        assert_eq!(
            layer.request_starts.lock().unwrap().len(),
            MAX_TRACKED_REQUESTS
        );
        layer.record_request_start(&request_fields(&[
            ("request_id", "r_new"),
            ("entrypoint", "hook"),
        ]));
        let starts = layer.request_starts.lock().unwrap();
        // clear() would have collapsed the map to 1; evict-oldest keeps it full.
        assert_eq!(
            starts.len(),
            MAX_TRACKED_REQUESTS,
            "evict-one keeps the map bounded but full, not cleared"
        );
        assert!(starts.contains_key("r_new"), "newest start retained");
    }

    #[test]
    fn missing_request_id_is_not_tracked_under_default() {
        // A start with no request_id must not be inserted under a shared
        // "default" key (which would conflate concurrent unidentified requests).
        let layer = MetricsLayer::new(Metrics::new().expect("metrics"));
        layer.record_request_start(&request_fields(&[("entrypoint", "hook")]));
        assert!(
            layer.request_starts.lock().unwrap().is_empty(),
            "untracked start must not create a 'default' entry"
        );
        // And an end with no id + no inline duration is a no-op (nothing to
        // correlate), not a panic.
        layer.record_request_end(&request_fields(&[("entrypoint", "hook")]));
    }

    #[test]
    fn labels_do_not_expose_raw_high_cardinality_values() {
        let metrics = Metrics::new().expect("metrics construct");
        metrics.record_doctor_diagnostic("RCH-E100", "critical");
        metrics.record_doctor_diagnostic("/home/alice/private/token", "super_secret");
        metrics.record_hook_fail_open("--password=hunter2");

        assert_eq!(
            metrics
                .doctor_diagnostic_total
                .with_label_values(&["known", "critical"])
                .get(),
            1.0
        );
        assert_eq!(
            metrics
                .doctor_diagnostic_total
                .with_label_values(&["other", "other"])
                .get(),
            1.0
        );
        assert_eq!(
            metrics
                .hook_fail_open_total
                .with_label_values(&["other"])
                .get(),
            1.0
        );
    }
}
