//! HTTP API for metrics and health endpoints.
//!
//! Provides:
//! - `/metrics` - Prometheus metrics export
//! - `/health` - Basic daemon health check
//! - `/ready` - Readiness probe (workers available)
//! - `/budget` - AGENTS.md budget compliance status

use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use serde_json::json;

use crate::metrics::{self, budget};
use crate::workers::WorkerPool;

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpState {
    /// Worker pool for readiness checks.
    pub pool: WorkerPool,
    /// Daemon version.
    pub version: &'static str,
    /// Daemon start time.
    pub started_at: Instant,
    /// Daemon PID.
    pub pid: u32,
}

/// Create the HTTP router for observability endpoints.
pub fn create_router(state: HttpState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/budget", get(budget_handler))
        .with_state(Arc::new(state))
}

/// Handler for `/metrics` - Prometheus metrics export.
async fn metrics_handler() -> impl IntoResponse {
    match metrics::encode_metrics() {
        Ok(output) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            output,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to encode metrics: {}", e),
        )
            .into_response(),
    }
}

/// Handler for `/health` - Basic daemon health check.
///
/// Returns 200 OK if the daemon is running.
async fn health_handler(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    let uptime_secs = state.started_at.elapsed().as_secs();

    Json(json!({
        "status": "healthy",
        "version": state.version,
        "pid": state.pid,
        "uptime_seconds": uptime_secs,
    }))
}

/// Handler for `/ready` - Readiness probe.
///
/// Returns 200 OK if workers are available, 503 otherwise.
async fn ready_handler(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    let workers = state.pool.all_workers().await;
    let healthy_workers: Vec<_> = workers
        .iter()
        .filter(|w| {
            // Consider a worker available if it has available slots
            w.available_slots() > 0
        })
        .collect();

    let workers_available = !healthy_workers.is_empty();
    let total_slots: u32 = healthy_workers.iter().map(|w| w.available_slots()).sum();

    if workers_available {
        (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "workers_available": true,
                "available_workers": healthy_workers.len(),
                "total_available_slots": total_slots,
            })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "reason": "no_workers_available",
                "workers_available": false,
                "available_workers": 0,
                "total_available_slots": 0,
            })),
        )
    }
}

/// Handler for `/budget` - AGENTS.md budget compliance status.
async fn budget_handler() -> impl IntoResponse {
    let status = budget::get_budget_status();
    Json(status)
}

/// Start the HTTP server for observability endpoints.
///
/// # Arguments
/// * `port` - The port to listen on.
/// * `state` - Shared state for handlers.
///
/// # Returns
/// A handle to the spawned server task.
pub async fn start_server(
    port: u16,
    state: HttpState,
) -> tokio::task::JoinHandle<Result<(), std::io::Error>> {
    let router = create_router(state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!("Starting HTTP server for observability on port {}", port);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn make_test_state() -> HttpState {
        HttpState {
            pool: WorkerPool::new(),
            version: "0.1.0-test",
            started_at: Instant::now(),
            pid: 12345,
        }
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = make_test_state();
        let router = create_router(state);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "healthy");
        assert_eq!(json["version"], "0.1.0-test");
        assert_eq!(json["pid"], 12345);
    }

    #[tokio::test]
    async fn test_ready_endpoint_no_workers() {
        let state = make_test_state();
        let router = create_router(state);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // No workers configured, should be not ready
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "not_ready");
        assert_eq!(json["reason"], "no_workers_available");
    }

    #[tokio::test]
    async fn test_budget_endpoint() {
        let state = make_test_state();
        let router = create_router(state);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/budget")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Should have budget info
        assert!(json["budgets"]["non_compilation"]["budget_ms"].is_number());
        assert!(json["budgets"]["compilation"]["budget_ms"].is_number());
        assert!(json["budgets"]["worker_selection"]["budget_ms"].is_number());
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        // Register metrics first
        let _ = metrics::register_metrics();

        let state = make_test_state();
        let router = create_router(state);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        // Should contain Prometheus format markers
        assert!(text.contains("# HELP") || text.is_empty());
    }
}
