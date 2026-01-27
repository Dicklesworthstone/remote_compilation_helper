//! Prometheus metrics for the RCH daemon.
//!
//! This module provides comprehensive observability metrics including:
//! - Worker metrics (status, slots, latency)
//! - Build metrics (total, active, duration)
//! - Transfer metrics (bytes, files, duration)
//! - Circuit breaker metrics (state, trips, recoveries)
//! - Decision latency metrics (CRITICAL for AGENTS.md compliance)
//! - Classification tier metrics (per-tier breakdown)
//! - OpenTelemetry tracing support (optional)

// Allow dead code for metric helpers that are part of the public API but not yet used
// These will be used as the metrics integration is completed
#![allow(dead_code)]

pub mod budget;
pub mod latency;
pub mod tracing;

use anyhow::Result;
use lazy_static::lazy_static;
use prometheus::{
    CounterVec, Encoder, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
};

lazy_static! {
    /// Global Prometheus registry for all RCH metrics.
    pub static ref REGISTRY: Registry = Registry::new();

    // =========================================================================
    // Worker Metrics
    // =========================================================================

    /// Worker status gauge (0=down, 1=up, 2=draining).
    pub static ref WORKER_STATUS: GaugeVec = GaugeVec::new(
        Opts::new("rch_worker_status", "Worker status (0=down, 1=up, 2=draining)"),
        &["worker", "status"]
    ).expect("Failed to create WORKER_STATUS metric");

    /// Total build slots per worker.
    pub static ref WORKER_SLOTS_TOTAL: GaugeVec = GaugeVec::new(
        Opts::new("rch_worker_slots_total", "Total build slots per worker"),
        &["worker"]
    ).expect("Failed to create WORKER_SLOTS_TOTAL metric");

    /// Available build slots per worker.
    pub static ref WORKER_SLOTS_AVAILABLE: GaugeVec = GaugeVec::new(
        Opts::new("rch_worker_slots_available", "Available build slots per worker"),
        &["worker"]
    ).expect("Failed to create WORKER_SLOTS_AVAILABLE metric");

    /// Worker health check latency in milliseconds.
    pub static ref WORKER_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_worker_latency_ms", "Worker health check latency in milliseconds")
            .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]),
        &["worker"]
    ).expect("Failed to create WORKER_LATENCY metric");

    /// Unix timestamp of last successful health check per worker.
    pub static ref WORKER_LAST_SEEN: GaugeVec = GaugeVec::new(
        Opts::new("rch_worker_last_seen_timestamp", "Unix timestamp of last successful health check"),
        &["worker"]
    ).expect("Failed to create WORKER_LAST_SEEN metric");

    // =========================================================================
    // Circuit Breaker Metrics
    // =========================================================================

    /// Circuit breaker state (0=closed, 1=half_open, 2=open).
    pub static ref CIRCUIT_STATE: GaugeVec = GaugeVec::new(
        Opts::new("rch_circuit_state", "Circuit breaker state (0=closed, 1=half_open, 2=open)"),
        &["worker"]
    ).expect("Failed to create CIRCUIT_STATE metric");

    /// Total failures triggering circuit breaker.
    pub static ref CIRCUIT_FAILURES_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_circuit_failures_total", "Total failures triggering circuit"),
        &["worker"]
    ).expect("Failed to create CIRCUIT_FAILURES_TOTAL metric");

    /// Total circuit trips to open state.
    pub static ref CIRCUIT_TRIPS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_circuit_trips_total", "Total circuit trips to open"),
        &["worker"]
    ).expect("Failed to create CIRCUIT_TRIPS_TOTAL metric");

    /// Total recoveries from open to closed state.
    pub static ref CIRCUIT_RECOVERIES_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_circuit_recoveries_total", "Total recoveries to closed"),
        &["worker"]
    ).expect("Failed to create CIRCUIT_RECOVERIES_TOTAL metric");

    // =========================================================================
    // Build Metrics
    // =========================================================================

    /// Total builds by result and location.
    pub static ref BUILDS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_builds_total", "Total builds"),
        &["result", "location"]
    ).expect("Failed to create BUILDS_TOTAL metric");

    /// Currently active builds by location.
    pub static ref BUILDS_ACTIVE: GaugeVec = GaugeVec::new(
        Opts::new("rch_builds_active", "Currently active builds"),
        &["location"]
    ).expect("Failed to create BUILDS_ACTIVE metric");

    /// Build duration distribution in seconds.
    pub static ref BUILD_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_build_duration_seconds", "Build duration in seconds")
            .buckets(vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]),
        &["location"]
    ).expect("Failed to create BUILD_DURATION metric");

    /// Pending builds in queue.
    pub static ref BUILD_QUEUE_DEPTH: prometheus::Gauge = prometheus::Gauge::new(
        "rch_build_queue_depth", "Pending builds in queue"
    ).expect("Failed to create BUILD_QUEUE_DEPTH metric");

    /// Classification decisions by tier and outcome.
    pub static ref BUILD_CLASSIFICATION_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_build_classification_total", "Classification decisions by tier and outcome"),
        &["tier", "decision"]
    ).expect("Failed to create BUILD_CLASSIFICATION_TOTAL metric");

    // =========================================================================
    // Transfer Metrics
    // =========================================================================

    /// Total bytes transferred by direction.
    pub static ref TRANSFER_BYTES_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_transfer_bytes_total", "Bytes transferred"),
        &["direction"]
    ).expect("Failed to create TRANSFER_BYTES_TOTAL metric");

    /// Total files transferred by direction.
    pub static ref TRANSFER_FILES_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_transfer_files_total", "Files transferred"),
        &["direction"]
    ).expect("Failed to create TRANSFER_FILES_TOTAL metric");

    /// Transfer duration in seconds by direction.
    pub static ref TRANSFER_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_transfer_duration_seconds", "Transfer duration in seconds")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]),
        &["direction"]
    ).expect("Failed to create TRANSFER_DURATION metric");

    /// Compression effectiveness ratio.
    pub static ref TRANSFER_COMPRESSION_RATIO: prometheus::Histogram = prometheus::Histogram::with_opts(
        HistogramOpts::new("rch_transfer_compression_ratio", "Compression effectiveness ratio")
            .buckets(vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    ).expect("Failed to create TRANSFER_COMPRESSION_RATIO metric");

    // =========================================================================
    // Daemon Metrics
    // =========================================================================

    /// Daemon uptime in seconds.
    pub static ref DAEMON_UPTIME: prometheus::Counter = prometheus::Counter::new(
        "rch_daemon_uptime_seconds", "Daemon uptime in seconds"
    ).expect("Failed to create DAEMON_UPTIME metric");

    /// Daemon version info (always 1, with version label).
    pub static ref DAEMON_INFO: GaugeVec = GaugeVec::new(
        Opts::new("rch_daemon_info", "Daemon version info (always 1)"),
        &["version"]
    ).expect("Failed to create DAEMON_INFO metric");

    /// Active client connections.
    pub static ref DAEMON_CONNECTIONS_ACTIVE: prometheus::Gauge = prometheus::Gauge::new(
        "rch_daemon_connections_active", "Active client connections"
    ).expect("Failed to create DAEMON_CONNECTIONS_ACTIVE metric");

    /// Total API requests by endpoint.
    pub static ref DAEMON_REQUESTS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_daemon_requests_total", "Total API requests"),
        &["endpoint"]
    ).expect("Failed to create DAEMON_REQUESTS_TOTAL metric");

    // =========================================================================
    // Decision Latency Metrics (CRITICAL for AGENTS.md compliance)
    // =========================================================================

    /// Decision latency histogram with fine-grained buckets.
    /// Non-compilation must be < 1ms, compilation must be < 5ms (95th percentile).
    pub static ref DECISION_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_decision_latency_seconds", "Decision latency in seconds")
            .buckets(vec![
                0.0001,   // 100µs
                0.0002,   // 200µs
                0.0005,   // 500µs
                0.001,    // 1ms   <-- non-compilation budget
                0.002,    // 2ms
                0.005,    // 5ms   <-- compilation budget
                0.01,     // 10ms
                0.025,    // 25ms
                0.05,     // 50ms
                0.1,      // 100ms
            ]),
        &["decision_type"]  // "non_compilation" or "compilation"
    ).expect("Failed to create DECISION_LATENCY metric");

    /// Decision latency budget violations.
    pub static ref DECISION_BUDGET_VIOLATIONS: CounterVec = CounterVec::new(
        Opts::new("rch_decision_budget_violations_total", "Decision latency budget violations"),
        &["decision_type"]
    ).expect("Failed to create DECISION_BUDGET_VIOLATIONS metric");

    // =========================================================================
    // Classification Tier Metrics
    // =========================================================================

    /// Classifications by tier (0-4).
    pub static ref CLASSIFICATION_TIER_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_classification_tier_total", "Classifications by tier"),
        &["tier"]
    ).expect("Failed to create CLASSIFICATION_TIER_TOTAL metric");

    /// Latency per classification tier in seconds.
    pub static ref CLASSIFICATION_TIER_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_classification_tier_latency_seconds", "Latency per classification tier")
            .buckets(vec![
                0.000001, // 1µs   - Tier 0 target
                0.000005, // 5µs   - Tier 1 target
                0.00001,  // 10µs
                0.00005,  // 50µs  - Tier 2 target
                0.0001,   // 100µs - Tier 3 target
                0.0005,   // 500µs - Tier 4 target
                0.001,    // 1ms
            ]),
        &["tier"]
    ).expect("Failed to create CLASSIFICATION_TIER_LATENCY metric");
}

/// Register all metrics with the global registry.
///
/// Should be called once at daemon startup.
pub fn register_metrics() -> Result<()> {
    // Worker metrics
    REGISTRY.register(Box::new(WORKER_STATUS.clone()))?;
    REGISTRY.register(Box::new(WORKER_SLOTS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(WORKER_SLOTS_AVAILABLE.clone()))?;
    REGISTRY.register(Box::new(WORKER_LATENCY.clone()))?;
    REGISTRY.register(Box::new(WORKER_LAST_SEEN.clone()))?;

    // Circuit breaker metrics
    REGISTRY.register(Box::new(CIRCUIT_STATE.clone()))?;
    REGISTRY.register(Box::new(CIRCUIT_FAILURES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CIRCUIT_TRIPS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CIRCUIT_RECOVERIES_TOTAL.clone()))?;

    // Build metrics
    REGISTRY.register(Box::new(BUILDS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(BUILDS_ACTIVE.clone()))?;
    REGISTRY.register(Box::new(BUILD_DURATION.clone()))?;
    REGISTRY.register(Box::new(BUILD_QUEUE_DEPTH.clone()))?;
    REGISTRY.register(Box::new(BUILD_CLASSIFICATION_TOTAL.clone()))?;

    // Transfer metrics
    REGISTRY.register(Box::new(TRANSFER_BYTES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(TRANSFER_FILES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(TRANSFER_DURATION.clone()))?;
    REGISTRY.register(Box::new(TRANSFER_COMPRESSION_RATIO.clone()))?;

    // Daemon metrics
    REGISTRY.register(Box::new(DAEMON_UPTIME.clone()))?;
    REGISTRY.register(Box::new(DAEMON_INFO.clone()))?;
    REGISTRY.register(Box::new(DAEMON_CONNECTIONS_ACTIVE.clone()))?;
    REGISTRY.register(Box::new(DAEMON_REQUESTS_TOTAL.clone()))?;

    // Decision latency metrics (CRITICAL)
    REGISTRY.register(Box::new(DECISION_LATENCY.clone()))?;
    REGISTRY.register(Box::new(DECISION_BUDGET_VIOLATIONS.clone()))?;

    // Classification tier metrics
    REGISTRY.register(Box::new(CLASSIFICATION_TIER_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CLASSIFICATION_TIER_LATENCY.clone()))?;

    Ok(())
}

/// Encode all metrics as Prometheus text format.
pub fn encode_metrics() -> Result<String> {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

// ============================================================================
// Worker Metric Helpers
// ============================================================================

/// Update worker status metric.
pub fn set_worker_status(worker_id: &str, status: &str, value: f64) {
    WORKER_STATUS
        .with_label_values(&[worker_id, status])
        .set(value);
}

/// Update worker slots total.
pub fn set_worker_slots_total(worker_id: &str, total: u32) {
    WORKER_SLOTS_TOTAL
        .with_label_values(&[worker_id])
        .set(f64::from(total));
}

/// Update worker slots available.
pub fn set_worker_slots_available(worker_id: &str, available: u32) {
    WORKER_SLOTS_AVAILABLE
        .with_label_values(&[worker_id])
        .set(f64::from(available));
}

/// Record worker health check latency.
pub fn observe_worker_latency(worker_id: &str, latency_ms: f64) {
    WORKER_LATENCY
        .with_label_values(&[worker_id])
        .observe(latency_ms);
}

/// Update worker last seen timestamp.
pub fn set_worker_last_seen(worker_id: &str, timestamp: f64) {
    WORKER_LAST_SEEN
        .with_label_values(&[worker_id])
        .set(timestamp);
}

// ============================================================================
// Circuit Breaker Metric Helpers
// ============================================================================

/// Update circuit breaker state (0=closed, 1=half_open, 2=open).
pub fn set_circuit_state(worker_id: &str, state: u8) {
    CIRCUIT_STATE
        .with_label_values(&[worker_id])
        .set(f64::from(state));
}

/// Record a circuit breaker failure.
pub fn inc_circuit_failure(worker_id: &str) {
    CIRCUIT_FAILURES_TOTAL.with_label_values(&[worker_id]).inc();
}

/// Record a circuit trip to open state.
pub fn inc_circuit_trip(worker_id: &str) {
    CIRCUIT_TRIPS_TOTAL.with_label_values(&[worker_id]).inc();
}

/// Record a circuit recovery to closed state.
pub fn inc_circuit_recovery(worker_id: &str) {
    CIRCUIT_RECOVERIES_TOTAL
        .with_label_values(&[worker_id])
        .inc();
}

// ============================================================================
// Build Metric Helpers
// ============================================================================

/// Record a completed build.
pub fn inc_build_total(result: &str, location: &str) {
    BUILDS_TOTAL.with_label_values(&[result, location]).inc();
}

/// Increment active builds.
pub fn inc_active_builds(location: &str) {
    BUILDS_ACTIVE.with_label_values(&[location]).inc();
}

/// Decrement active builds.
pub fn dec_active_builds(location: &str) {
    BUILDS_ACTIVE.with_label_values(&[location]).dec();
}

/// Record build duration.
pub fn observe_build_duration(location: &str, duration_secs: f64) {
    BUILD_DURATION
        .with_label_values(&[location])
        .observe(duration_secs);
}

/// Set build queue depth.
pub fn set_build_queue_depth(depth: usize) {
    BUILD_QUEUE_DEPTH.set(depth as f64);
}

/// Record a classification decision.
pub fn inc_build_classification(tier: u8, decision: &str) {
    let tier_str = tier.to_string();
    BUILD_CLASSIFICATION_TOTAL
        .with_label_values(&[tier_str.as_str(), decision])
        .inc();
}

// ============================================================================
// Transfer Metric Helpers
// ============================================================================

/// Record bytes transferred.
pub fn inc_transfer_bytes(direction: &str, bytes: u64) {
    TRANSFER_BYTES_TOTAL
        .with_label_values(&[direction])
        .inc_by(bytes as f64);
}

/// Record files transferred.
pub fn inc_transfer_files(direction: &str, files: u64) {
    TRANSFER_FILES_TOTAL
        .with_label_values(&[direction])
        .inc_by(files as f64);
}

/// Record transfer duration.
pub fn observe_transfer_duration(direction: &str, duration_secs: f64) {
    TRANSFER_DURATION
        .with_label_values(&[direction])
        .observe(duration_secs);
}

/// Record compression ratio.
pub fn observe_compression_ratio(ratio: f64) {
    TRANSFER_COMPRESSION_RATIO.observe(ratio);
}

// ============================================================================
// Daemon Metric Helpers
// ============================================================================

/// Update daemon uptime (call periodically).
pub fn inc_daemon_uptime(seconds: f64) {
    DAEMON_UPTIME.inc_by(seconds);
}

/// Set daemon info (call once at startup).
pub fn set_daemon_info(version: &str) {
    DAEMON_INFO.with_label_values(&[version]).set(1.0);
}

/// Increment active connections.
pub fn inc_connections() {
    DAEMON_CONNECTIONS_ACTIVE.inc();
}

/// Decrement active connections.
pub fn dec_connections() {
    DAEMON_CONNECTIONS_ACTIVE.dec();
}

/// Record an API request.
pub fn inc_requests(endpoint: &str) {
    DAEMON_REQUESTS_TOTAL.with_label_values(&[endpoint]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::tracing::info;
    use rch_common::test_guard;

    fn setup_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(::tracing::Level::INFO)
            .try_init();
    }

    #[test]
    fn test_metrics_registration() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_metrics_registration");

        // Create a new registry for testing (don't pollute global)
        let test_registry = Registry::new();

        info!("INPUT: Creating counter metric with label");
        let counter =
            CounterVec::new(Opts::new("test_counter", "A test counter"), &["label"]).unwrap();
        test_registry.register(Box::new(counter.clone())).unwrap();

        // Increment the counter
        counter.with_label_values(&["value"]).inc();
        info!("ACTION: Incremented counter once");

        // Gather and verify
        let metrics = test_registry.gather();
        assert!(!metrics.is_empty());
        let names: Vec<_> = metrics.iter().map(|m| m.name()).collect();
        assert!(names.contains(&"test_counter"));

        info!("VERIFY: Metric registered and gatherable");
        info!("TEST PASS: test_metrics_registration");
    }

    #[test]
    fn test_histogram_observe() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_histogram_observe");

        let histogram = prometheus::Histogram::with_opts(
            HistogramOpts::new("test_histogram", "A test histogram")
                .buckets(vec![0.1, 0.5, 1.0, 5.0]),
        )
        .unwrap();

        info!("INPUT: Observing values 0.3, 0.8, 3.0");
        histogram.observe(0.3);
        histogram.observe(0.8);
        histogram.observe(3.0);

        assert_eq!(histogram.get_sample_count(), 3);
        info!(
            "VERIFY: Histogram has {} samples",
            histogram.get_sample_count()
        );
        info!("TEST PASS: test_histogram_observe");
    }

    #[test]
    fn test_gauge_set() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_gauge_set");

        let gauge = prometheus::Gauge::new("test_gauge", "A test gauge").unwrap();

        info!("INPUT: Setting gauge to 42.0");
        gauge.set(42.0);
        assert_eq!(gauge.get(), 42.0);

        info!("ACTION: Incrementing gauge");
        gauge.inc();
        assert_eq!(gauge.get(), 43.0);

        info!("ACTION: Decrementing gauge");
        gauge.dec();
        assert_eq!(gauge.get(), 42.0);

        info!("VERIFY: Gauge operations work correctly");
        info!("TEST PASS: test_gauge_set");
    }

    #[test]
    fn test_encode_format() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_encode_format");

        let test_registry = Registry::new();
        let counter = prometheus::Counter::new("test_counter", "A test counter").unwrap();
        test_registry.register(Box::new(counter.clone())).unwrap();
        counter.inc();

        info!("ACTION: Encoding metrics to Prometheus text format");
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder
            .encode(&test_registry.gather(), &mut buffer)
            .unwrap();

        let output = String::from_utf8(buffer).unwrap();
        info!("OUTPUT: Encoded {} bytes", output.len());

        assert!(output.contains("# HELP test_counter"));
        assert!(output.contains("# TYPE test_counter counter"));
        assert!(output.contains("test_counter 1"));

        info!("VERIFY: Output contains HELP, TYPE, and value");
        info!("TEST PASS: test_encode_format");
    }

    #[test]
    fn test_worker_metric_helpers() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_worker_metric_helpers");

        // Use a unique worker ID to avoid conflicts with other tests
        let worker_id = "test-worker-helpers";

        info!("INPUT: Setting worker metrics for {}", worker_id);

        set_worker_slots_total(worker_id, 16);
        set_worker_slots_available(worker_id, 12);
        set_worker_status(worker_id, "healthy", 1.0);
        set_worker_last_seen(worker_id, 1705936800.0);
        observe_worker_latency(worker_id, 5.5);

        // Verify by checking metric values directly
        let total = WORKER_SLOTS_TOTAL.with_label_values(&[worker_id]).get();
        let available = WORKER_SLOTS_AVAILABLE.with_label_values(&[worker_id]).get();
        let status = WORKER_STATUS
            .with_label_values(&[worker_id, "healthy"])
            .get();

        assert_eq!(total, 16.0);
        assert_eq!(available, 12.0);
        assert_eq!(status, 1.0);

        info!(
            "VERIFY: Worker slots total={}, available={}, status={}",
            total, available, status
        );
        info!("TEST PASS: test_worker_metric_helpers");
    }

    #[test]
    fn test_circuit_breaker_metric_helpers() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_circuit_breaker_metric_helpers");

        let worker_id = "test-worker-circuit";

        info!("INPUT: Recording circuit breaker events for {}", worker_id);

        set_circuit_state(worker_id, 0); // closed
        inc_circuit_failure(worker_id);
        inc_circuit_failure(worker_id);
        set_circuit_state(worker_id, 2); // open
        inc_circuit_trip(worker_id);
        set_circuit_state(worker_id, 0); // closed again
        inc_circuit_recovery(worker_id);

        let state = CIRCUIT_STATE.with_label_values(&[worker_id]).get();
        let failures = CIRCUIT_FAILURES_TOTAL.with_label_values(&[worker_id]).get();
        let trips = CIRCUIT_TRIPS_TOTAL.with_label_values(&[worker_id]).get();
        let recoveries = CIRCUIT_RECOVERIES_TOTAL
            .with_label_values(&[worker_id])
            .get();

        assert_eq!(state, 0.0); // closed
        assert_eq!(failures, 2.0);
        assert_eq!(trips, 1.0);
        assert_eq!(recoveries, 1.0);

        info!(
            "VERIFY: Circuit state={}, failures={}, trips={}, recoveries={}",
            state, failures, trips, recoveries
        );
        info!("TEST PASS: test_circuit_breaker_metric_helpers");
    }

    #[test]
    fn test_build_metric_helpers() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_build_metric_helpers");

        info!("INPUT: Recording build events");

        inc_active_builds("remote");
        inc_active_builds("remote");
        inc_build_total("success", "remote");
        observe_build_duration("remote", 15.5);
        dec_active_builds("remote");
        set_build_queue_depth(5);

        let active = BUILDS_ACTIVE.with_label_values(&["remote"]).get();
        let total = BUILDS_TOTAL.with_label_values(&["success", "remote"]).get();
        let queue_depth = BUILD_QUEUE_DEPTH.get();

        assert_eq!(active, 1.0); // 2 inc - 1 dec
        assert_eq!(total, 1.0);
        assert_eq!(queue_depth, 5.0);

        info!(
            "VERIFY: Active builds={}, total={}, queue_depth={}",
            active, total, queue_depth
        );
        info!("TEST PASS: test_build_metric_helpers");
    }

    #[test]
    fn test_transfer_metric_helpers() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_transfer_metric_helpers");

        info!("INPUT: Recording transfer events");

        inc_transfer_bytes("upload", 1_000_000);
        inc_transfer_files("upload", 50);
        observe_transfer_duration("upload", 2.5);
        observe_compression_ratio(0.65);

        let bytes = TRANSFER_BYTES_TOTAL.with_label_values(&["upload"]).get();
        let files = TRANSFER_FILES_TOTAL.with_label_values(&["upload"]).get();

        assert_eq!(bytes, 1_000_000.0);
        assert_eq!(files, 50.0);

        info!("VERIFY: Transfer bytes={}, files={}", bytes, files);
        info!("TEST PASS: test_transfer_metric_helpers");
    }

    #[test]
    fn test_daemon_metric_helpers() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_daemon_metric_helpers");

        info!("INPUT: Recording daemon metrics");

        set_daemon_info("0.1.0-test");
        inc_connections();
        inc_connections();
        inc_requests("select-worker");
        inc_requests("status");
        dec_connections();

        let info_val = DAEMON_INFO.with_label_values(&["0.1.0-test"]).get();
        let connections = DAEMON_CONNECTIONS_ACTIVE.get();
        let select_requests = DAEMON_REQUESTS_TOTAL
            .with_label_values(&["select-worker"])
            .get();
        let status_requests = DAEMON_REQUESTS_TOTAL.with_label_values(&["status"]).get();

        assert_eq!(info_val, 1.0);
        assert_eq!(connections, 1.0); // 2 inc - 1 dec
        assert_eq!(select_requests, 1.0);
        assert_eq!(status_requests, 1.0);

        info!(
            "VERIFY: Daemon info={}, connections={}, requests={}",
            info_val,
            connections,
            select_requests + status_requests
        );
        info!("TEST PASS: test_daemon_metric_helpers");
    }

    #[test]
    fn test_classification_metric_helpers() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_classification_metric_helpers");

        info!("INPUT: Recording classification decisions");

        inc_build_classification(0, "reject");
        inc_build_classification(1, "reject");
        inc_build_classification(2, "pass");
        inc_build_classification(3, "pass");
        inc_build_classification(4, "intercept");

        let tier0 = BUILD_CLASSIFICATION_TOTAL
            .with_label_values(&["0", "reject"])
            .get();
        let tier4 = BUILD_CLASSIFICATION_TOTAL
            .with_label_values(&["4", "intercept"])
            .get();

        assert_eq!(tier0, 1.0);
        assert_eq!(tier4, 1.0);

        info!("VERIFY: Classification metrics recorded for tiers 0-4");
        info!("TEST PASS: test_classification_metric_helpers");
    }
}
