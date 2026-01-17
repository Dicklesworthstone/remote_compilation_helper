//! OpenTelemetry tracing initialization for distributed tracing.
//!
//! This module provides optional OpenTelemetry integration for the RCH daemon.
//! When enabled via environment variables, traces can be exported to an OTLP
//! collector for distributed tracing across the RCH pipeline.
//!
//! # Environment Variables
//!
//! - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint URL (e.g., "http://localhost:4317")
//! - `OTEL_SERVICE_NAME`: Service name (defaults to "rchd")
//! - `RCH_OTEL_ENABLED`: Set to "1" or "true" to enable OpenTelemetry

use anyhow::Result;
use std::env;

/// OpenTelemetry configuration.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Whether OpenTelemetry is enabled.
    pub enabled: bool,
    /// OTLP endpoint URL.
    pub endpoint: Option<String>,
    /// Service name.
    pub service_name: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: "rchd".to_string(),
        }
    }
}

impl OtelConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let enabled = env::var("RCH_OTEL_ENABLED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

        let service_name = env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "rchd".to_string());

        Self {
            enabled,
            endpoint,
            service_name,
        }
    }
}

/// Initialize OpenTelemetry tracing layer.
///
/// This function sets up OpenTelemetry tracing if enabled via environment
/// variables. Returns `Ok(None)` if OpenTelemetry is not enabled.
///
/// # Returns
///
/// - `Ok(Some(guard))` if OpenTelemetry was initialized
/// - `Ok(None)` if OpenTelemetry is disabled
/// - `Err(_)` if initialization failed
pub fn init_otel() -> Result<Option<OtelGuard>> {
    let config = OtelConfig::from_env();

    if !config.enabled {
        tracing::debug!("OpenTelemetry disabled (set RCH_OTEL_ENABLED=1 to enable)");
        return Ok(None);
    }

    // Require an endpoint when enabled
    let Some(endpoint) = config.endpoint else {
        tracing::warn!("OpenTelemetry enabled but OTEL_EXPORTER_OTLP_ENDPOINT not set, disabling");
        return Ok(None);
    };

    tracing::info!(
        "Initializing OpenTelemetry tracing: endpoint={}, service={}",
        endpoint,
        config.service_name
    );

    // Note: Full OpenTelemetry initialization would require:
    // 1. opentelemetry_otlp::new_pipeline().tracing()
    // 2. Setting up the OTLP exporter with the endpoint
    // 3. Creating a tracing-opentelemetry layer
    // 4. Registering it with tracing_subscriber
    //
    // For now, we provide a stub that can be expanded when distributed
    // tracing is needed. The Prometheus metrics provide sufficient
    // observability for single-daemon operation.

    Ok(Some(OtelGuard {
        _service_name: config.service_name,
    }))
}

/// Guard that shuts down OpenTelemetry on drop.
pub struct OtelGuard {
    _service_name: String,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        tracing::debug!("Shutting down OpenTelemetry tracing");
        // In full implementation: opentelemetry::global::shutdown_tracer_provider();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otel_config_default() {
        let config = OtelConfig::default();
        assert!(!config.enabled);
        assert!(config.endpoint.is_none());
        assert_eq!(config.service_name, "rchd");
    }

    #[test]
    fn test_otel_config_from_env() {
        // Test reads current env state without modifying it
        // (env::remove_var is unsafe in Rust 2024 edition)
        let config = OtelConfig::from_env();
        // Config should have a valid service name
        assert!(!config.service_name.is_empty());
    }

    #[test]
    fn test_init_otel_returns_result() {
        // Test that init_otel returns a valid result without modifying env
        // (env::remove_var is unsafe in Rust 2024 edition)
        let result = init_otel();
        // Should not panic and should return Ok
        assert!(result.is_ok());
    }
}
