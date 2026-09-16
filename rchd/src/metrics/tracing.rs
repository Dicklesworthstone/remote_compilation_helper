//! Daemon request metrics with an optional OTLP metrics mirror.
//!
//! This does not export tracing spans or logs. Request observations always reach
//! the daemon's Prometheus registry; OTLP export is explicitly opt-in.
//!
//! # Environment Variables
//!
//! - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint URL (e.g., "http://localhost:4317")
//! - `RCH_OTEL_EXPORTER_OTLP_ENDPOINT`: Preferred endpoint override
//! - `OTEL_SERVICE_NAME`: Service name (defaults to "rchd")
//! - `RCH_OTEL_ENABLED`: Set to "1" or "true" to enable OpenTelemetry
//! - `RCH_OTEL_EXPORT_INTERVAL_SECS`: Positive export interval (default 30)

use anyhow::{Result, anyhow};
use rch_telemetry::metrics::Metrics;
use rch_telemetry::otlp::{OtelMetrics, OtlpConfig};
use std::sync::{LazyLock, RwLock};
use std::time::Instant;

// Reuse registered collectors across initialization cycles. Only the active
// mirror is replaceable; disabled initialization cannot pin an exporter forever.
static PROMETHEUS_METRICS: LazyLock<Result<Metrics>> = LazyLock::new(|| {
    let metrics = Metrics::new()?;
    metrics.register(&super::REGISTRY)?;
    Ok(metrics)
});
static REQUEST_METRICS: RwLock<Option<Metrics>> = RwLock::new(None);

/// Initialize metrics inside the Tokio runtime, before accepting requests.
pub fn init_otel() -> Result<OtelGuard> {
    let mut config = OtlpConfig::from_env();
    if std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .is_none_or(|name| name.trim().is_empty())
    {
        config.service_name = "rchd".to_string();
    }
    init_with_config(&config)
}

pub(crate) fn init_with_config(config: &OtlpConfig) -> Result<OtelGuard> {
    let mut current = REQUEST_METRICS
        .write()
        .map_err(|_| anyhow!("daemon request metrics lock poisoned"))?;
    if current.is_some() {
        return Err(anyhow!("daemon request metrics already initialized"));
    }
    let metrics = PROMETHEUS_METRICS
        .as_ref()
        .map_err(|error| anyhow!("registering daemon request metrics: {error}"))?;
    let (metrics, exporter) = configured_metrics(config, metrics.clone())?;
    *current = Some(metrics);
    Ok(OtelGuard { exporter })
}

fn configured_metrics(
    config: &OtlpConfig,
    metrics: Metrics,
) -> Result<(Metrics, Option<OtelMetrics>)> {
    let exporter = OtelMetrics::from_config(config)?;
    Ok((metrics.with_otel(exporter.clone()), exporter))
}

pub fn request_metrics() -> Option<Metrics> {
    REQUEST_METRICS
        .read()
        .ok()
        .and_then(|current| current.clone())
}

/// Owns the active metrics mirror. Call `shutdown` before stopping the runtime.
pub struct OtelGuard {
    exporter: Option<OtelMetrics>,
}

impl OtelGuard {
    /// Whether an exporter was configured, not proof of collector receipt.
    pub fn otel_enabled(&self) -> bool {
        self.exporter.is_some()
    }

    /// Detach the mirror and flush its provider without blocking a runtime thread.
    /// The caller must first finish or cancel and join request tasks.
    pub async fn shutdown(self) {
        if let Ok(mut current) = REQUEST_METRICS.write() {
            *current = None;
        }
        if let Some(exporter) = self.exporter
            && let Err(error) = tokio::task::spawn_blocking(move || exporter.shutdown()).await
        {
            tracing::warn!(%error, "OTLP metrics shutdown task failed");
        }
    }
}

/// Measures a finite request through normal return, error, or cancellation.
/// No completion outcome is inferred from dropping the timer.
pub struct RequestDuration {
    metrics: Option<Metrics>,
    started: Instant,
}

impl RequestDuration {
    pub fn start(metrics: Option<Metrics>) -> Self {
        Self {
            metrics,
            started: Instant::now(),
        }
    }
}

impl Drop for RequestDuration {
    fn drop(&mut self) {
        if let Some(metrics) = &self.metrics {
            metrics.observe_request_duration("rchd_api", self.started.elapsed().as_secs_f64());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Encoder;
    use rch_common::test_guard;

    #[test]
    fn explicitly_disabled_exporter_preserves_prometheus_recording() {
        let _guard = test_guard!();
        let config = OtlpConfig {
            enabled: false,
            endpoint: Some("http://127.0.0.1:4317".to_string()),
            service_name: "rchd".to_string(),
            ..OtlpConfig::default()
        };
        let registry = prometheus::Registry::new();
        let metrics = Metrics::new().expect("metrics");
        metrics.register(&registry).expect("register metrics");
        let (metrics, exporter) = configured_metrics(&config, metrics).expect("disabled config");
        assert!(
            exporter.is_none(),
            "disabled even with a configured endpoint"
        );
        assert!(!metrics.otel_enabled());
        drop(RequestDuration::start(Some(metrics)));
        let mut text = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&registry.gather(), &mut text)
            .expect("encode registered metrics");
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("rch_request_duration_seconds_count{entrypoint=\"rchd_api\"} 1\n")
        );
    }
}
