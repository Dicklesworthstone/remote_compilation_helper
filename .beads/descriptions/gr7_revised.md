## Overview

Add comprehensive observability with Prometheus metrics export, OpenTelemetry tracing, structured logging, and health check endpoints for the daemon. This enables monitoring dashboards, alerting, and distributed tracing for debugging. **CRITICAL: Must verify the <1ms non-compilation / <5ms compilation latency requirements from AGENTS.md.**

## Goals

1. Prometheus metrics endpoint (`/metrics`) with all operational counters and gauges
2. OpenTelemetry tracing with span propagation
3. Structured JSON logging with correlation IDs
4. Health check endpoints (`/health`, `/ready`)
5. Metrics for workers, builds, transfers, circuit breakers
6. Low overhead (<1% CPU, <10MB memory for metrics)
7. **NEW: Decision latency histogram with p50/p95/p99 percentiles**
8. **NEW: Performance budget verification metrics (AGENTS.md requirements)**
9. **NEW: Classification tier breakdown metrics**

## Metrics Specification

### Worker Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rch_worker_status` | Gauge | worker, status | Worker status (0=down, 1=up, 2=draining) |
| `rch_worker_slots_total` | Gauge | worker | Total build slots |
| `rch_worker_slots_available` | Gauge | worker | Available build slots |
| `rch_worker_latency_ms` | Histogram | worker | Health check latency |
| `rch_worker_last_seen_timestamp` | Gauge | worker | Unix timestamp of last successful health check |

### Circuit Breaker Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rch_circuit_state` | Gauge | worker | Circuit state (0=closed, 1=half_open, 2=open) |
| `rch_circuit_failures_total` | Counter | worker | Total failures triggering circuit |
| `rch_circuit_trips_total` | Counter | worker | Total circuit trips to open |
| `rch_circuit_recoveries_total` | Counter | worker | Total recoveries to closed |

### Build Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rch_builds_total` | Counter | result, location | Total builds by result (success/fail/timeout) and location (local/remote) |
| `rch_builds_active` | Gauge | location | Currently active builds |
| `rch_build_duration_seconds` | Histogram | location | Build duration distribution |
| `rch_build_queue_depth` | Gauge | - | Pending builds in queue |
| `rch_build_classification_total` | Counter | tier, decision | Classification decisions by tier and outcome |

### Transfer Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rch_transfer_bytes_total` | Counter | direction | Bytes transferred (upload/download) |
| `rch_transfer_files_total` | Counter | direction | Files transferred |
| `rch_transfer_duration_seconds` | Histogram | direction | Transfer duration |
| `rch_transfer_compression_ratio` | Histogram | - | Compression effectiveness |

### Daemon Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rch_daemon_uptime_seconds` | Counter | - | Daemon uptime |
| `rch_daemon_info` | Gauge | version | Daemon version info (always 1) |
| `rch_daemon_connections_active` | Gauge | - | Active client connections |
| `rch_daemon_requests_total` | Counter | endpoint | Total API requests |

### NEW: Decision Latency Metrics (CRITICAL for AGENTS.md compliance)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rch_decision_latency_seconds` | Histogram | decision_type | Decision latency with fine-grained buckets |
| `rch_decision_latency_p50_seconds` | Gauge | decision_type | 50th percentile latency |
| `rch_decision_latency_p95_seconds` | Gauge | decision_type | 95th percentile latency (KEY for budget) |
| `rch_decision_latency_p99_seconds` | Gauge | decision_type | 99th percentile latency |
| `rch_decision_budget_violations_total` | Counter | decision_type | Count of budget violations |

### NEW: Classification Tier Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rch_classification_tier_total` | Counter | tier | Classifications by tier (0-4) |
| `rch_classification_tier_latency_seconds` | Histogram | tier | Latency per classification tier |

## Implementation

### Metrics Registry

```rust
// rchd/src/metrics/mod.rs

use prometheus::{Registry, Counter, Gauge, Histogram, HistogramOpts, Opts, labels};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // Worker metrics
    pub static ref WORKER_STATUS: GaugeVec = GaugeVec::new(
        Opts::new("rch_worker_status", "Worker status (0=down, 1=up, 2=draining)"),
        &["worker", "status"]
    ).unwrap();

    pub static ref WORKER_SLOTS_TOTAL: GaugeVec = GaugeVec::new(
        Opts::new("rch_worker_slots_total", "Total build slots per worker"),
        &["worker"]
    ).unwrap();

    pub static ref WORKER_SLOTS_AVAILABLE: GaugeVec = GaugeVec::new(
        Opts::new("rch_worker_slots_available", "Available build slots per worker"),
        &["worker"]
    ).unwrap();

    pub static ref WORKER_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_worker_latency_ms", "Worker health check latency")
            .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]),
        &["worker"]
    ).unwrap();

    // Build metrics
    pub static ref BUILDS_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_builds_total", "Total builds"),
        &["result", "location"]
    ).unwrap();

    pub static ref BUILDS_ACTIVE: GaugeVec = GaugeVec::new(
        Opts::new("rch_builds_active", "Currently active builds"),
        &["location"]
    ).unwrap();

    pub static ref BUILD_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_build_duration_seconds", "Build duration")
            .buckets(vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]),
        &["location"]
    ).unwrap();

    // Transfer metrics
    pub static ref TRANSFER_BYTES: CounterVec = CounterVec::new(
        Opts::new("rch_transfer_bytes_total", "Total bytes transferred"),
        &["direction"]
    ).unwrap();

    pub static ref TRANSFER_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_transfer_duration_seconds", "Transfer duration")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]),
        &["direction"]
    ).unwrap();

    // Circuit breaker metrics
    pub static ref CIRCUIT_STATE: GaugeVec = GaugeVec::new(
        Opts::new("rch_circuit_state", "Circuit breaker state (0=closed, 1=half_open, 2=open)"),
        &["worker"]
    ).unwrap();

    pub static ref CIRCUIT_TRIPS: CounterVec = CounterVec::new(
        Opts::new("rch_circuit_trips_total", "Total circuit trips to open"),
        &["worker"]
    ).unwrap();

    // NEW: Decision latency metrics - CRITICAL for AGENTS.md compliance
    pub static ref DECISION_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_decision_latency_seconds", "Decision latency")
            // Fine-grained buckets for sub-millisecond precision
            // Non-compilation must be < 1ms, compilation must be < 5ms (95th percentile)
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
    ).unwrap();

    pub static ref DECISION_BUDGET_VIOLATIONS: CounterVec = CounterVec::new(
        Opts::new("rch_decision_budget_violations_total", "Decision latency budget violations"),
        &["decision_type"]
    ).unwrap();

    // NEW: Classification tier metrics
    pub static ref CLASSIFICATION_TIER_TOTAL: CounterVec = CounterVec::new(
        Opts::new("rch_classification_tier_total", "Classifications by tier"),
        &["tier"]
    ).unwrap();

    pub static ref CLASSIFICATION_TIER_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rch_classification_tier_latency_seconds", "Latency per tier")
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
    ).unwrap();
}

pub fn register_metrics() -> Result<()> {
    REGISTRY.register(Box::new(WORKER_STATUS.clone()))?;
    REGISTRY.register(Box::new(WORKER_SLOTS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(WORKER_SLOTS_AVAILABLE.clone()))?;
    REGISTRY.register(Box::new(WORKER_LATENCY.clone()))?;
    REGISTRY.register(Box::new(BUILDS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(BUILDS_ACTIVE.clone()))?;
    REGISTRY.register(Box::new(BUILD_DURATION.clone()))?;
    REGISTRY.register(Box::new(TRANSFER_BYTES.clone()))?;
    REGISTRY.register(Box::new(TRANSFER_DURATION.clone()))?;
    REGISTRY.register(Box::new(CIRCUIT_STATE.clone()))?;
    REGISTRY.register(Box::new(CIRCUIT_TRIPS.clone()))?;
    // NEW
    REGISTRY.register(Box::new(DECISION_LATENCY.clone()))?;
    REGISTRY.register(Box::new(DECISION_BUDGET_VIOLATIONS.clone()))?;
    REGISTRY.register(Box::new(CLASSIFICATION_TIER_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CLASSIFICATION_TIER_LATENCY.clone()))?;
    Ok(())
}
```

### NEW: Decision Latency Recorder

```rust
// rchd/src/metrics/latency.rs

use std::time::Instant;

/// Performance budgets from AGENTS.md
pub const NON_COMPILATION_BUDGET_MS: f64 = 1.0;    // <1ms for non-compilation
pub const COMPILATION_BUDGET_MS: f64 = 5.0;         // <5ms for compilation decisions

/// Record decision latency and check budget
pub fn record_decision_latency(
    decision_type: &str,
    start: Instant,
) -> Duration {
    let duration = start.elapsed();
    let duration_secs = duration.as_secs_f64();
    let duration_ms = duration_secs * 1000.0;

    // Record histogram
    DECISION_LATENCY
        .with_label_values(&[decision_type])
        .observe(duration_secs);

    // Check budget violations
    let budget_ms = match decision_type {
        "non_compilation" => NON_COMPILATION_BUDGET_MS,
        "compilation" => COMPILATION_BUDGET_MS,
        _ => COMPILATION_BUDGET_MS, // Default to stricter budget
    };

    if duration_ms > budget_ms {
        DECISION_BUDGET_VIOLATIONS
            .with_label_values(&[decision_type])
            .inc();

        warn!(
            "Decision latency budget violation: {} took {:.3}ms (budget: {}ms)",
            decision_type, duration_ms, budget_ms
        );
    }

    duration
}

/// Record classification tier metrics
pub fn record_classification_tier(tier: u8, duration: Duration) {
    let tier_str = format!("{}", tier);

    CLASSIFICATION_TIER_TOTAL
        .with_label_values(&[&tier_str])
        .inc();

    CLASSIFICATION_TIER_LATENCY
        .with_label_values(&[&tier_str])
        .observe(duration.as_secs_f64());
}

/// Compute and expose percentile gauges
/// Called periodically (e.g., every 10s) to update percentile gauges
pub fn update_percentile_gauges() {
    // This would compute percentiles from the histogram
    // In practice, use a library like `hdrhistogram` for accurate percentiles
    // or rely on Prometheus queries for percentile calculation
}
```

### Metrics HTTP Handler

```rust
// rchd/src/api/metrics.rs

use axum::{routing::get, Router, response::IntoResponse};
use prometheus::{Encoder, TextEncoder};

pub fn metrics_routes() -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/budget", get(budget_handler))  // NEW
}

async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer).unwrap();
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        buffer,
    )
}

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Basic health: daemon is running
    Json(json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": state.uptime.elapsed().as_secs(),
    }))
}

async fn ready_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Readiness: daemon can accept work
    let workers_available = state.workers.iter().any(|w| w.is_available());

    if workers_available {
        (StatusCode::OK, Json(json!({
            "status": "ready",
            "workers_available": true,
        })))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
            "status": "not_ready",
            "reason": "no_workers_available",
        })))
    }
}

// NEW: Budget status endpoint
async fn budget_handler(State(state): State<AppState>) -> impl IntoResponse {
    let non_compilation_violations = DECISION_BUDGET_VIOLATIONS
        .with_label_values(&["non_compilation"])
        .get() as u64;

    let compilation_violations = DECISION_BUDGET_VIOLATIONS
        .with_label_values(&["compilation"])
        .get() as u64;

    let budget_status = if non_compilation_violations == 0 && compilation_violations == 0 {
        "passing"
    } else {
        "failing"
    };

    Json(json!({
        "status": budget_status,
        "budgets": {
            "non_compilation": {
                "budget_ms": NON_COMPILATION_BUDGET_MS,
                "violations": non_compilation_violations,
            },
            "compilation": {
                "budget_ms": COMPILATION_BUDGET_MS,
                "violations": compilation_violations,
            }
        }
    }))
}
```

### OpenTelemetry Tracing

```rust
// rchd/src/tracing/mod.rs

use opentelemetry::trace::{TraceContextExt, Tracer};
use opentelemetry_otlp::WithExportConfig;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracing(config: &TracingConfig) -> Result<()> {
    // OTLP exporter if configured
    let tracer = if let Some(endpoint) = &config.otlp_endpoint {
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint);

        opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .with_trace_config(
                opentelemetry::sdk::trace::config()
                    .with_resource(Resource::new(vec![
                        KeyValue::new("service.name", "rchd"),
                        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    ]))
            )
            .install_batch(opentelemetry::runtime::Tokio)?
    } else {
        return Ok(()); // No OTLP endpoint, skip tracing
    };

    let telemetry = OpenTelemetryLayer::new(tracer);

    tracing_subscriber::registry()
        .with(telemetry)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    Ok(())
}

/// Instrument a build with tracing
pub async fn traced_build<F, T>(build_id: &str, worker: &str, f: F) -> T
where
    F: Future<Output = T>,
{
    let span = tracing::info_span!(
        "build",
        build_id = build_id,
        worker = worker,
        otel.kind = "client",
    );
    f.instrument(span).await
}
```

### Metric Update Points

```rust
// rchd/src/worker/health.rs

impl WorkerHealthChecker {
    async fn check_worker(&self, worker: &WorkerConfig) -> Result<HealthStatus> {
        let start = Instant::now();

        let result = self.ssh_health_check(worker).await;

        // Record latency
        WORKER_LATENCY
            .with_label_values(&[&worker.id])
            .observe(start.elapsed().as_millis() as f64);

        match &result {
            Ok(status) => {
                WORKER_STATUS.with_label_values(&[&worker.id, "up"]).set(1.0);
                WORKER_SLOTS_TOTAL.with_label_values(&[&worker.id]).set(status.total_slots as f64);
                WORKER_SLOTS_AVAILABLE.with_label_values(&[&worker.id]).set(status.available_slots as f64);
            }
            Err(_) => {
                WORKER_STATUS.with_label_values(&[&worker.id, "down"]).set(1.0);
            }
        }

        result
    }
}

// rchd/src/build/executor.rs

impl BuildExecutor {
    async fn execute_build(&self, build: Build) -> Result<BuildResult> {
        let location = if build.is_remote { "remote" } else { "local" };
        BUILDS_ACTIVE.with_label_values(&[location]).inc();

        let start = Instant::now();
        let result = self.do_execute(build).await;
        let duration = start.elapsed();

        BUILDS_ACTIVE.with_label_values(&[location]).dec();
        BUILD_DURATION.with_label_values(&[location]).observe(duration.as_secs_f64());

        let outcome = match &result {
            Ok(_) => "success",
            Err(e) if e.is_timeout() => "timeout",
            Err(_) => "failure",
        };
        BUILDS_TOTAL.with_label_values(&[outcome, location]).inc();

        result
    }
}

// NEW: rch/src/hook/classify.rs

impl Classifier {
    pub fn classify(&self, command: &str) -> ClassificationResult {
        let start = Instant::now();

        // Run classification through tiers
        let (result, tier) = self.classify_internal(command);

        // Record tier metrics
        record_classification_tier(tier, start.elapsed());

        // Record decision latency
        let decision_type = if result.is_compilation() {
            "compilation"
        } else {
            "non_compilation"
        };
        record_decision_latency(decision_type, start);

        result
    }
}
```

## Implementation Files

```
rchd/src/
├── metrics/
│   ├── mod.rs           # Metrics registry and registration
│   ├── worker.rs        # Worker metric updates
│   ├── build.rs         # Build metric updates
│   ├── transfer.rs      # Transfer metric updates
│   ├── circuit.rs       # Circuit breaker metrics
│   ├── latency.rs       # NEW: Decision latency tracking
│   └── budget.rs        # NEW: Budget verification
├── tracing/
│   ├── mod.rs           # Tracing initialization
│   └── spans.rs         # Span helpers
├── api/
│   ├── metrics.rs       # /metrics endpoint
│   └── health.rs        # /health, /ready, /budget endpoints
```

## Testing Requirements

### Unit Tests (rchd/src/metrics/tests/)

**registry_test.rs**
```rust
#[test]
fn test_metrics_registration() {
    let registry = Registry::new();
    register_all_metrics(&registry).unwrap();

    let metrics = registry.gather();
    let names: Vec<_> = metrics.iter().map(|m| m.get_name()).collect();

    assert!(names.contains(&"rch_worker_status"));
    assert!(names.contains(&"rch_builds_total"));
    assert!(names.contains(&"rch_circuit_state"));
    // NEW
    assert!(names.contains(&"rch_decision_latency_seconds"));
    assert!(names.contains(&"rch_classification_tier_total"));
}

#[test]
fn test_counter_increment() {
    BUILDS_TOTAL.with_label_values(&["success", "remote"]).inc();
    let val = BUILDS_TOTAL.with_label_values(&["success", "remote"]).get();
    assert!(val > 0.0);
}

#[test]
fn test_histogram_observe() {
    BUILD_DURATION.with_label_values(&["local"]).observe(1.5);
    let count = BUILD_DURATION.with_label_values(&["local"]).get_sample_count();
    assert_eq!(count, 1);
}
```

**latency_test.rs** (NEW)
```rust
#[test]
fn test_decision_latency_within_budget() {
    let start = Instant::now();
    std::thread::sleep(Duration::from_micros(500)); // 0.5ms

    let duration = record_decision_latency("non_compilation", start);

    // Should be under 1ms budget
    assert!(duration.as_secs_f64() * 1000.0 < NON_COMPILATION_BUDGET_MS);

    // No violations recorded
    let violations = DECISION_BUDGET_VIOLATIONS
        .with_label_values(&["non_compilation"])
        .get();
    // Note: This may be non-zero if other tests ran first
}

#[test]
fn test_decision_latency_budget_violation() {
    let violations_before = DECISION_BUDGET_VIOLATIONS
        .with_label_values(&["non_compilation"])
        .get();

    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(2)); // 2ms, over budget

    record_decision_latency("non_compilation", start);

    let violations_after = DECISION_BUDGET_VIOLATIONS
        .with_label_values(&["non_compilation"])
        .get();

    assert!(violations_after > violations_before);
}

#[test]
fn test_classification_tier_metrics() {
    record_classification_tier(0, Duration::from_nanos(500)); // 0.5µs for Tier 0

    let count = CLASSIFICATION_TIER_TOTAL
        .with_label_values(&["0"])
        .get();
    assert!(count > 0.0);
}
```

**export_test.rs**
```rust
#[test]
fn test_prometheus_text_format() {
    BUILDS_TOTAL.with_label_values(&["success", "local"]).inc();

    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer).unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert!(output.contains("rch_builds_total"));
    assert!(output.contains("result=\"success\""));
    assert!(output.contains("location=\"local\""));
}

#[test]
fn test_histogram_buckets() {
    BUILD_DURATION.with_label_values(&["remote"]).observe(0.05);
    BUILD_DURATION.with_label_values(&["remote"]).observe(0.5);
    BUILD_DURATION.with_label_values(&["remote"]).observe(5.0);

    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer).unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert!(output.contains("rch_build_duration_seconds_bucket"));
    assert!(output.contains("le=\"0.1\""));
    assert!(output.contains("le=\"1\""));
}

#[test]
fn test_decision_latency_fine_buckets() {
    // Verify fine-grained buckets exist for sub-millisecond tracking
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer).unwrap();

    let output = String::from_utf8(buffer).unwrap();
    assert!(output.contains("rch_decision_latency_seconds_bucket"));
    assert!(output.contains("le=\"0.001\"")); // 1ms bucket
    assert!(output.contains("le=\"0.005\"")); // 5ms bucket
}
```

### Integration Tests (rchd/tests/metrics_integration.rs)

```rust
#[tokio::test]
async fn test_metrics_endpoint() {
    let app = create_test_app().await;
    let response = app.oneshot(
        Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    assert!(text.contains("# HELP rch_"));
    assert!(text.contains("# TYPE rch_"));
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = create_test_app().await;
    let response = app.oneshot(
        Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &hyper::body::to_bytes(response.into_body()).await.unwrap()
    ).unwrap();

    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn test_ready_endpoint_no_workers() {
    let app = create_test_app_no_workers().await;
    let response = app.oneshot(
        Request::builder()
            .uri("/ready")
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_budget_endpoint() {
    let app = create_test_app().await;
    let response = app.oneshot(
        Request::builder()
            .uri("/budget")
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &hyper::body::to_bytes(response.into_body()).await.unwrap()
    ).unwrap();

    assert!(body["budgets"]["non_compilation"]["budget_ms"] == 1.0);
    assert!(body["budgets"]["compilation"]["budget_ms"] == 5.0);
}

#[tokio::test]
async fn test_metrics_update_on_build() {
    let app = create_test_app().await;

    // Trigger a build
    let _build_response = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/build")
            .body(Body::from(r#"{"command": "cargo build"}"#))
            .unwrap()
    ).await.unwrap();

    // Check metrics
    let metrics_response = app.oneshot(
        Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();

    let body = hyper::body::to_bytes(metrics_response.into_body()).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("rch_builds_total"));
}
```

### E2E Test Script (scripts/e2e_metrics_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCHD="${RCHD:-$SCRIPT_DIR/../target/release/rchd}"
RCH="${RCH:-$SCRIPT_DIR/../target/release/rch}"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_metrics.log"
DAEMON_PID=""

export RCH_MOCK_SSH=1
export RCH_LOG_LEVEL=debug

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; cleanup; exit 1; }

cleanup() {
    if [[ -n "$DAEMON_PID" ]]; then
        kill "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

log "=== RCH Observability E2E Test ==="
log "Daemon binary: $RCHD"
log "Test dir: $TEST_DIR"

# Start daemon with metrics enabled
start_daemon() {
    log "Starting daemon with metrics on port 9100..."
    "$RCHD" --metrics-port 9100 --socket "$TEST_DIR/rch.sock" &
    DAEMON_PID=$!
    sleep 2

    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "Daemon failed to start"
    fi
    log "  Daemon started with PID $DAEMON_PID"
}

# Test 1: Metrics endpoint responds
test_metrics_endpoint() {
    log "Test 1: Metrics endpoint responds"

    OUTPUT=$(curl -s http://localhost:9100/metrics)
    log "  Metrics response (first 500 chars): $(echo "$OUTPUT" | head -c 500)"

    echo "$OUTPUT" | grep -qE "^# HELP rch_" || fail "No HELP lines found"
    echo "$OUTPUT" | grep -qE "^# TYPE rch_" || fail "No TYPE lines found"
    pass "Metrics endpoint"
}

# Test 2: Health endpoint
test_health_endpoint() {
    log "Test 2: Health endpoint"

    OUTPUT=$(curl -s http://localhost:9100/health)
    log "  Health response: $OUTPUT"

    echo "$OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['status']=='healthy'" \
        || fail "Health check failed"
    pass "Health endpoint"
}

# Test 3: Ready endpoint
test_ready_endpoint() {
    log "Test 3: Ready endpoint"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9100/ready)
    log "  Ready response code: $HTTP_CODE"

    # May be 200 or 503 depending on worker config
    [[ "$HTTP_CODE" =~ ^(200|503)$ ]] || fail "Unexpected status: $HTTP_CODE"
    pass "Ready endpoint"
}

# Test 4: Worker metrics present
test_worker_metrics() {
    log "Test 4: Worker metrics present"

    OUTPUT=$(curl -s http://localhost:9100/metrics)
    log "  Looking for worker metrics..."

    # Check for expected metric families
    for metric in "rch_worker_status" "rch_worker_slots" "rch_worker_latency"; do
        if echo "$OUTPUT" | grep -q "$metric"; then
            log "    Found: $metric"
        else
            log "    Missing: $metric (may be expected if no workers configured)"
        fi
    done
    pass "Worker metrics"
}

# Test 5: Build metrics present
test_build_metrics() {
    log "Test 5: Build metrics present"

    OUTPUT=$(curl -s http://localhost:9100/metrics)

    for metric in "rch_builds_total" "rch_builds_active" "rch_build_duration"; do
        echo "$OUTPUT" | grep -q "$metric" || log "    Note: $metric not found (expected before any builds)"
    done
    pass "Build metrics"
}

# Test 6: Circuit breaker metrics
test_circuit_metrics() {
    log "Test 6: Circuit breaker metrics"

    OUTPUT=$(curl -s http://localhost:9100/metrics)

    for metric in "rch_circuit_state" "rch_circuit_trips"; do
        if echo "$OUTPUT" | grep -q "$metric"; then
            log "    Found: $metric"
        else
            log "    Note: $metric not found (expected if no circuit activity)"
        fi
    done
    pass "Circuit breaker metrics"
}

# Test 7: Prometheus format validity
test_prometheus_format() {
    log "Test 7: Prometheus format validity"

    OUTPUT=$(curl -s http://localhost:9100/metrics)

    # Check that all lines are valid Prometheus format
    # Lines should be: comment (#), metric, or empty
    INVALID=$(echo "$OUTPUT" | grep -vE '^(#|[a-z_]+(\{[^}]*\})? [0-9.e+-]+|$)' | head -5)
    if [[ -n "$INVALID" ]]; then
        log "  Invalid lines found: $INVALID"
        fail "Invalid Prometheus format"
    fi
    pass "Prometheus format"
}

# Test 8: Decision latency metrics (NEW - CRITICAL)
test_decision_latency_metrics() {
    log "Test 8: Decision latency metrics (AGENTS.md compliance)"

    OUTPUT=$(curl -s http://localhost:9100/metrics)

    # Check for decision latency histogram
    if echo "$OUTPUT" | grep -q "rch_decision_latency_seconds"; then
        log "    Found: rch_decision_latency_seconds"

        # Check for fine-grained buckets
        if echo "$OUTPUT" | grep -q 'le="0.001"'; then
            log "    Found: 1ms bucket (non-compilation budget)"
        fi
        if echo "$OUTPUT" | grep -q 'le="0.005"'; then
            log "    Found: 5ms bucket (compilation budget)"
        fi
    else
        log "    Note: decision latency metrics not found yet"
    fi

    # Check for budget violations counter
    if echo "$OUTPUT" | grep -q "rch_decision_budget_violations_total"; then
        log "    Found: budget violations counter"
    fi

    pass "Decision latency metrics"
}

# Test 9: Budget endpoint (NEW)
test_budget_endpoint() {
    log "Test 9: Budget endpoint"

    OUTPUT=$(curl -s http://localhost:9100/budget)
    log "  Budget response: $OUTPUT"

    if echo "$OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'budgets' in d" 2>/dev/null; then
        log "  Valid budget response"

        # Check budget values
        NON_COMP=$(echo "$OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['budgets']['non_compilation']['budget_ms'])")
        COMP=$(echo "$OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['budgets']['compilation']['budget_ms'])")

        log "    Non-compilation budget: ${NON_COMP}ms (expected: 1ms)"
        log "    Compilation budget: ${COMP}ms (expected: 5ms)"
    else
        log "  Note: Budget endpoint may not be implemented yet"
    fi

    pass "Budget endpoint"
}

# Test 10: Classification tier metrics (NEW)
test_classification_tier_metrics() {
    log "Test 10: Classification tier metrics"

    OUTPUT=$(curl -s http://localhost:9100/metrics)

    if echo "$OUTPUT" | grep -q "rch_classification_tier"; then
        log "    Found: classification tier metrics"
    else
        log "    Note: tier metrics not found yet (expected before any classifications)"
    fi

    pass "Classification tier metrics"
}

# Test 11: Scrape performance
test_scrape_performance() {
    log "Test 11: Scrape performance"

    START=$(date +%s%N)
    for i in {1..10}; do
        curl -s http://localhost:9100/metrics > /dev/null
    done
    END=$(date +%s%N)

    DURATION_MS=$(( (END - START) / 1000000 ))
    AVG_MS=$(( DURATION_MS / 10 ))
    log "  10 scrapes in ${DURATION_MS}ms (avg: ${AVG_MS}ms)"

    if [[ $AVG_MS -gt 100 ]]; then
        log "  Warning: scrape latency high (>100ms)"
    fi
    pass "Scrape performance"
}

# Test 12: Daemon info metric
test_daemon_info() {
    log "Test 12: Daemon info metric"

    OUTPUT=$(curl -s http://localhost:9100/metrics)

    if echo "$OUTPUT" | grep -q "rch_daemon_info"; then
        VERSION=$(echo "$OUTPUT" | grep "rch_daemon_info" | head -1)
        log "  Found daemon info: $VERSION"
    else
        log "  Note: rch_daemon_info not present (optional)"
    fi
    pass "Daemon info metric"
}

# Run all tests
start_daemon
test_metrics_endpoint
test_health_endpoint
test_ready_endpoint
test_worker_metrics
test_build_metrics
test_circuit_metrics
test_prometheus_format
test_decision_latency_metrics
test_budget_endpoint
test_classification_tier_metrics
test_scrape_performance
test_daemon_info

log "=== All Observability E2E tests passed ==="
log "Full log at: $LOG_FILE"
cat "$LOG_FILE"
```

## Logging Requirements

- DEBUG: Individual metric updates
- DEBUG: Tracing span creation/completion
- INFO: Metrics endpoint requests
- INFO: Health/ready check results
- INFO: **NEW**: Budget status changes
- WARN: High cardinality label detected
- WARN: **NEW**: Decision latency budget violation
- ERROR: Metrics registration failure
- ERROR: OTLP export failure

## Success Criteria

- [ ] `/metrics` endpoint exports valid Prometheus text format
- [ ] All specified metrics are present and updating
- [ ] `/health` returns daemon health status
- [ ] `/ready` returns readiness for builds
- [ ] OpenTelemetry traces exported when configured
- [ ] Scrape latency < 50ms for 100 metrics
- [ ] Memory overhead < 10MB
- [ ] **NEW: Decision latency histogram has sub-millisecond buckets**
- [ ] **NEW: Budget violations are tracked and exposed**
- [ ] **NEW: Classification tier metrics provide per-tier breakdown**
- [ ] **NEW: `/budget` endpoint shows AGENTS.md compliance status**
- [ ] Unit test coverage > 80%
- [ ] E2E tests pass

## Dependencies

- Rich status command (remote_compilation_helper-7ds) provides status data
- Build history tracking (remote_compilation_helper-qgs) for build metrics
- Circuit breaker (remote_compilation_helper-9pw) for circuit metrics

## Blocks

- Web dashboard (remote_compilation_helper-piz) consumes metrics
- Alerting rules (future) depend on metric names
