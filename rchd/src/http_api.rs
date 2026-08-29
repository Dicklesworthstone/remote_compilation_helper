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
use rch_common::WorkerStatus;

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
    let mut healthy_workers = Vec::new();
    let mut total_slots = 0;

    for w in workers {
        // Consider a worker available if it is healthy/degraded AND has available slots
        let status = w.status().await;
        let is_status_healthy = matches!(status, WorkerStatus::Healthy | WorkerStatus::Degraded);
        let available = w.available_slots().await;

        if is_status_healthy && available > 0 {
            healthy_workers.push(w);
            total_slots += available;
        }
    }

    let workers_available = !healthy_workers.is_empty();

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
    // Bind to localhost only for security
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    tracing::info!("Starting HTTP server for observability on {}", addr);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await
    })
}

// =============================================================================
// Tailnet status API (bd-2f5ms)
// =============================================================================
//
// The rich daemon state — `/status`, `/workers/capabilities` — lives on a
// `0600` Unix socket that only the local user can read. Agents and the fleet
// dashboard on OTHER machines could reach it only by ssh-ing in and running
// `rch status --json`, which is how the collector worked and why the fleet
// view lagged by a 20-minute cron tick. This second listener serves the same
// JSON over TCP, intended for a tailnet:
//
//   * the bind address must be loopback or a Tailscale address
//     (100.64.0.0/10, fd7a:115c:a1e0::/48) unless `[api] allow_any_addr` is
//     set — a typo'd `0.0.0.0` never exposes worker hosts and IPs to the
//     internet;
//   * the status routes require a bearer token (`Authorization: Bearer` or
//     `X-Rch-Token`) unless the operator explicitly sets `no_token = true`
//     with no token configured — an empty token is never an open door;
//   * `/health`, `/ready`, `/metrics` and `/budget` are served unauthenticated
//     on this listener too, exactly as on loopback, so a tailnet Prometheus can
//     scrape without ssh.
//
// The loopback observability listener above is unchanged.

use crate::DaemonContext;
use axum::{
    extract::{Query, Request},
    middleware::{self, Next},
    response::Response,
};
use rch_common::ApiConfig;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Default port for the tailnet API when `bind = "tailscale"` names none.
pub const DEFAULT_API_PORT: u16 = 9101;

/// State for the tailnet API handlers.
#[derive(Clone)]
pub struct ApiState {
    /// Full daemon context — the same one the socket handlers use.
    pub ctx: DaemonContext,
    /// Bearer token the status routes require; `None` only when the operator
    /// set `[api] no_token = true`.
    pub token: Option<String>,
}

/// Is `ip` inside Tailscale's address space?
///
/// IPv4: the CGNAT range 100.64.0.0/10. IPv6: Tailscale's ULA prefix
/// fd7a:115c:a1e0::/48.
pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

/// Refuse a bind address that would expose the daemon beyond loopback or the
/// tailnet, unless the operator explicitly allowed it.
pub fn check_bind_addr(addr: SocketAddr, allow_any: bool) -> Result<(), String> {
    let ip = addr.ip();
    if ip.is_loopback() || is_tailscale_ip(ip) || allow_any {
        return Ok(());
    }
    Err(format!(
        "[api] bind {addr} is neither loopback nor a Tailscale address (100.64.0.0/10, \
         fd7a:115c:a1e0::/48); the status API would carry worker hosts and IPs to whatever \
         can reach that interface. Use \"tailscale\", a 100.x address, 127.0.0.1, or set \
         allow_any_addr = true if you really mean it"
    ))
}

/// This machine's Tailscale IPv4 address, without shelling out.
///
/// Connecting a UDP socket to Tailscale's MagicDNS resolver (100.100.100.100)
/// sends nothing on the wire but makes the kernel pick the route and therefore
/// the source address — which is the tailnet interface's address when Tailscale
/// is up. Anything outside 100.64.0.0/10 means it is not.
pub fn detect_tailscale_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(100, 100, 100, 100), 53)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if is_tailscale_ip(IpAddr::V4(ip)) => Some(ip),
        _ => None,
    }
}

/// Turn the `[api] bind` spec into a socket address.
///
/// Accepts `"tailscale"`, `"tailscale:PORT"`, `"IP:PORT"`, `"[v6]:PORT"`, or a
/// bare IP (default port). Empty = the API is off (`Ok(None)`).
pub fn resolve_api_bind(spec: &str) -> Result<Option<SocketAddr>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(None);
    }
    if let Some(rest) = spec.strip_prefix("tailscale") {
        let port = match rest {
            "" => DEFAULT_API_PORT,
            r => r
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| {
                    format!("[api] bind {spec:?}: expected \"tailscale\" or \"tailscale:PORT\"")
                })?,
        };
        let ip = detect_tailscale_ipv4().ok_or_else(|| {
            "[api] bind \"tailscale\": no Tailscale IPv4 address on this machine (is tailscaled up?); \
             set an explicit \"IP:PORT\" instead"
                .to_string()
        })?;
        return Ok(Some(SocketAddr::from((ip, port))));
    }
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok(Some(addr));
    }
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(Some(SocketAddr::from((ip, DEFAULT_API_PORT))));
    }
    Err(format!(
        "[api] bind {spec:?} is not \"tailscale\", \"tailscale:PORT\", \"IP:PORT\" or \"IP\""
    ))
}

/// The bearer token the status routes will require.
///
/// `token_file` (trimmed, `~` expanded) wins over `token`. Neither configured
/// is an error unless `no_token` was set explicitly: an operator who forgets the
/// token must get a refusal at startup, not an open listener.
pub fn resolve_api_token(cfg: &ApiConfig) -> Result<Option<String>, String> {
    if let Some(path) = cfg
        .token_file
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let expanded = if let Some(rest) = path.strip_prefix("~/") {
            std::env::var_os("HOME")
                .map(|h| std::path::PathBuf::from(h).join(rest))
                .ok_or_else(|| {
                    format!("[api] token_file {path:?}: cannot resolve ~ (HOME unset)")
                })?
        } else {
            std::path::PathBuf::from(path)
        };
        let raw = std::fs::read_to_string(&expanded)
            .map_err(|e| format!("[api] token_file {}: {e}", expanded.display()))?;
        let token = raw.trim();
        if token.is_empty() {
            return Err(format!("[api] token_file {} is empty", expanded.display()));
        }
        return Ok(Some(token.to_string()));
    }
    if let Some(token) = cfg
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        return Ok(Some(token.to_string()));
    }
    if cfg.no_token {
        return Ok(None);
    }
    Err(
        "[api] has no token: set api.token or api.token_file, or api.no_token = true to serve \
         the status routes without one (loopback / a trusted tailnet only)"
            .to_string(),
    )
}

/// Constant-time equality, so a wrong token cannot be narrowed down by timing
/// the comparison. Length is not hidden (a mismatch in length is still a
/// mismatch), which is the usual and accepted trade-off.
fn tokens_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Bearer-token middleware for the status routes.
async fn require_token(State(state): State<Arc<ApiState>>, req: Request, next: Next) -> Response {
    let Some(expected) = state.token.as_deref() else {
        return next.run(req).await;
    };
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
        })
        .or_else(|| {
            req.headers()
                .get("x-rch-token")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
        })
        .filter(|t| !t.is_empty());
    match presented {
        Some(t) if tokens_equal(t, expected) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer realm=\"rchd\"")],
            "401 supply the rchd api token via Authorization: Bearer <token> or X-Rch-Token\n",
        )
            .into_response(),
    }
}

/// `GET /status` — the same `DaemonFullStatus` the Unix socket serves.
async fn api_status_handler(State(state): State<Arc<ApiState>>) -> Response {
    match crate::api::handle_status(&state.ctx).await {
        Ok(status) => Json(status).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("500 status failed: {e}\n"),
        )
            .into_response(),
    }
}

/// `GET /workers/capabilities[?refresh=1]` — the same body as the socket's
/// `/workers/capabilities`.
async fn api_capabilities_handler(
    State(state): State<Arc<ApiState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let refresh = q
        .get("refresh")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
        .unwrap_or(false);
    Json(crate::workers::get_workers_capabilities(&state.ctx, refresh).await).into_response()
}

/// `GET /workers/config` — the static half of the worker view (tags, priority,
/// configured slots), which the socket only exposes through `rch workers list`.
async fn api_workers_config_handler(State(state): State<Arc<ApiState>>) -> Response {
    let mut rows = Vec::new();
    for worker in state.ctx.pool.all_workers().await {
        let status = worker.status().await;
        let config = worker.config.read().await;
        rows.push(json!({
            "id": config.id.to_string(),
            "host": config.host,
            "user": config.user,
            "total_slots": config.total_slots,
            "priority": config.priority,
            "tags": config.tags,
            "status": status,
        }));
    }
    Json(json!({ "workers": rows })).into_response()
}

/// `GET /repo-convergence/status[?worker=<id>]` — the same body as the
/// socket's `/repo-convergence/status`: which workers are missing repos this
/// dispatcher's builds depend on. `rch status --json` folds this into its
/// `convergence` field; the fleet collector does the same over the API so
/// `worker.convergence_drift` is raised whichever transport served the box.
async fn api_convergence_handler(
    State(state): State<Arc<ApiState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let worker = q
        .get("worker")
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .map(rch_common::WorkerId::new);
    Json(crate::api::handle_repo_convergence_status(&state.ctx, worker.as_ref()).await)
        .into_response()
}

/// The tailnet API router: token-gated status routes merged with the
/// unauthenticated observability routes.
pub fn create_api_router(api_state: ApiState, http_state: HttpState) -> Router {
    let shared = Arc::new(api_state);
    let protected = Router::new()
        .route("/status", get(api_status_handler))
        .route("/workers/capabilities", get(api_capabilities_handler))
        .route("/workers/config", get(api_workers_config_handler))
        .route("/repo-convergence/status", get(api_convergence_handler))
        .route_layer(middleware::from_fn_with_state(
            shared.clone(),
            require_token,
        ))
        .with_state(shared);
    protected.merge(create_router(http_state))
}

/// Resolve `[api]` (plus CLI overrides), validate it, and start the listener.
///
/// Returns `Ok(None)` when the API is not configured. Every refusal is an
/// `Err` with the exact fix in it — the caller logs it and keeps the daemon
/// running, because a mis-set dashboard knob must never stop builds.
pub async fn start_api_server(
    cfg: &ApiConfig,
    bind_override: Option<&str>,
    token_file_override: Option<&str>,
    ctx: DaemonContext,
    http_state: HttpState,
) -> Result<Option<tokio::task::JoinHandle<Result<(), std::io::Error>>>, String> {
    let mut cfg = cfg.clone();
    if let Some(b) = bind_override {
        cfg.bind = b.to_string();
    }
    if let Some(f) = token_file_override {
        cfg.token_file = Some(f.to_string());
    }
    if cfg.bind.trim().is_empty() {
        return Ok(None);
    }
    // Token problems are configuration errors: refuse now, at startup, where
    // the operator is looking.
    let token = resolve_api_token(&cfg)?;
    let allow_any = cfg.allow_any_addr;

    match resolve_api_bind(&cfg.bind) {
        Ok(Some(addr)) => {
            check_bind_addr(addr, allow_any)?;
            let listener = bind_api_listener(addr, token.is_some()).await?;
            let router = create_api_router(ApiState { ctx, token }, http_state);
            Ok(Some(tokio::spawn(async move {
                axum::serve(listener, router).await
            })))
        }
        Ok(None) => Ok(None),
        // `bind = "tailscale"` and no tailnet address YET: at boot rchd can
        // come up before tailscaled has one. That is not a configuration
        // error, so do not give up — keep trying in the background and serve
        // as soon as the address appears. Any other failure is definite.
        Err(e) if is_tailscale_pending(&e) => {
            tracing::warn!(
                "Tailnet status API: {e}; retrying every {}s for up to {} attempts",
                TAILSCALE_RETRY_SECS,
                TAILSCALE_RETRY_ATTEMPTS
            );
            let spec = cfg.bind.clone();
            Ok(Some(tokio::spawn(async move {
                for attempt in 1..=TAILSCALE_RETRY_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_secs(TAILSCALE_RETRY_SECS)).await;
                    let addr = match resolve_api_bind(&spec) {
                        Ok(Some(addr)) => addr,
                        Ok(None) => return Ok(()),
                        Err(e) if is_tailscale_pending(&e) => {
                            tracing::debug!("Tailnet status API: attempt {attempt}: {e}");
                            continue;
                        }
                        Err(e) => {
                            tracing::error!("Tailnet status API not started: {e}");
                            return Ok(());
                        }
                    };
                    if let Err(e) = check_bind_addr(addr, allow_any) {
                        tracing::error!("Tailnet status API not started: {e}");
                        return Ok(());
                    }
                    match bind_api_listener(addr, token.is_some()).await {
                        Ok(listener) => {
                            let router = create_api_router(ApiState { ctx, token }, http_state);
                            return axum::serve(listener, router).await;
                        }
                        Err(e) => {
                            tracing::error!("Tailnet status API not started: {e}");
                            return Ok(());
                        }
                    }
                }
                tracing::error!(
                    "Tailnet status API not started: no Tailscale IPv4 address appeared in {} attempts; \
                     restart rchd once tailscaled is up, or set an explicit [api] bind",
                    TAILSCALE_RETRY_ATTEMPTS
                );
                Ok(())
            })))
        }
        Err(e) => Err(e),
    }
}

/// How the boot-time race with tailscaled is waited out: 15 s × 40 = 10 min.
const TAILSCALE_RETRY_SECS: u64 = 15;
const TAILSCALE_RETRY_ATTEMPTS: u32 = 40;

/// The one `resolve_api_bind` failure that is worth waiting on.
fn is_tailscale_pending(err: &str) -> bool {
    err.contains("no Tailscale IPv4 address")
}

async fn bind_api_listener(
    addr: SocketAddr,
    token_required: bool,
) -> Result<tokio::net::TcpListener, String> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("[api] cannot bind {addr}: {e}"))?;
    tracing::info!(
        "Tailnet status API listening on {} ({})",
        addr,
        if token_required {
            "bearer token required"
        } else {
            "NO token — no_token = true"
        }
    );
    Ok(listener)
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

    #[tokio::test]
    async fn test_ready_endpoint_with_healthy_worker() {
        use rch_common::{WorkerConfig, WorkerId};

        let pool = WorkerPool::new();

        // Add a healthy worker with available slots
        let worker_config = WorkerConfig {
            id: WorkerId::new("test-worker-1"),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(worker_config).await;

        let state = HttpState {
            pool,
            version: "0.1.0-test",
            started_at: Instant::now(),
            pid: 12345,
        };
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

        // Worker is healthy by default and has slots available
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "ready");
        assert_eq!(json["workers_available"], true);
        assert_eq!(json["available_workers"], 1);
        assert_eq!(json["total_available_slots"], 8);
    }

    #[tokio::test]
    async fn test_ready_endpoint_with_multiple_workers() {
        use rch_common::{WorkerConfig, WorkerId};

        let pool = WorkerPool::new();

        // Add multiple workers
        for i in 1..=3 {
            let worker_config = WorkerConfig {
                id: WorkerId::new(format!("worker-{}", i)),
                host: format!("host{}.example.com", i),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                total_slots: 4 * i as u32,
                priority: 100 - i as u32,
                tags: vec![format!("tag-{}", i)],
            };
            pool.add_worker(worker_config).await;
        }

        let state = HttpState {
            pool,
            version: "0.1.0-test",
            started_at: Instant::now(),
            pid: 12345,
        };
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

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "ready");
        assert_eq!(json["workers_available"], true);
        assert_eq!(json["available_workers"], 3);
        // Total slots: 4 + 8 + 12 = 24
        assert_eq!(json["total_available_slots"], 24);
    }

    #[tokio::test]
    async fn test_health_endpoint_uptime() {
        use std::time::Duration;

        let started_at = Instant::now() - Duration::from_secs(100);
        let state = HttpState {
            pool: WorkerPool::new(),
            version: "0.2.0",
            started_at,
            pid: 99999,
        };
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
        assert_eq!(json["version"], "0.2.0");
        assert_eq!(json["pid"], 99999);
        // Uptime should be around 100 seconds (allow some tolerance)
        let uptime = json["uptime_seconds"].as_u64().unwrap();
        assert!((100..=105).contains(&uptime));
    }

    // ==================== Additional Coverage Tests ====================

    #[test]
    fn test_http_state_clone() {
        let state1 = make_test_state();
        let state2 = state1.clone();

        assert_eq!(state1.version, state2.version);
        assert_eq!(state1.pid, state2.pid);
        // started_at is Copy, so we can compare durations
        let diff = state1.started_at.elapsed().as_nanos() as i64
            - state2.started_at.elapsed().as_nanos() as i64;
        assert!(diff.abs() < 1_000_000); // Within 1ms
    }

    #[test]
    fn test_http_state_fields() {
        let pool = WorkerPool::new();
        let started_at = Instant::now();
        let state = HttpState {
            pool,
            version: "1.2.3-custom",
            started_at,
            pid: 54321,
        };

        assert_eq!(state.version, "1.2.3-custom");
        assert_eq!(state.pid, 54321);
    }

    #[tokio::test]
    async fn test_create_router_returns_valid_router() {
        let state = make_test_state();
        let router = create_router(state);

        // Test that the router responds to all registered routes
        let routes = ["/health", "/ready", "/budget", "/metrics"];

        for route in routes {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
                .await
                .unwrap();

            // All routes should return either 200 or 503 (for ready without workers)
            let status = response.status();
            assert!(
                status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE,
                "Route {} returned unexpected status {}",
                route,
                status
            );
        }
    }

    #[tokio::test]
    async fn test_router_returns_404_for_unknown_routes() {
        let state = make_test_state();
        let router = create_router(state);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_ready_endpoint_with_degraded_worker() {
        use rch_common::{WorkerConfig, WorkerId, WorkerStatus};

        let pool = WorkerPool::new();

        let worker_config = WorkerConfig {
            id: WorkerId::new("degraded-worker"),
            host: "degraded.example.com".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(worker_config.clone()).await;

        // Set worker status to Degraded
        if let Some(worker) = pool.get(&worker_config.id).await {
            worker.set_status(WorkerStatus::Degraded).await;
        }

        let state = HttpState {
            pool,
            version: "0.1.0-test",
            started_at: Instant::now(),
            pid: 12345,
        };
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

        // Degraded workers are still considered available
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "ready");
        assert_eq!(json["workers_available"], true);
    }

    #[tokio::test]
    async fn test_ready_endpoint_with_unreachable_worker() {
        use rch_common::{WorkerConfig, WorkerId, WorkerStatus};

        let pool = WorkerPool::new();

        let worker_config = WorkerConfig {
            id: WorkerId::new("unreachable-worker"),
            host: "unreachable.example.com".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(worker_config.clone()).await;

        // Set worker status to Unreachable
        if let Some(worker) = pool.get(&worker_config.id).await {
            worker.set_status(WorkerStatus::Unreachable).await;
        }

        let state = HttpState {
            pool,
            version: "0.1.0-test",
            started_at: Instant::now(),
            pid: 12345,
        };
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

        // Unreachable workers are NOT considered available
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "not_ready");
        assert_eq!(json["workers_available"], false);
    }

    #[tokio::test]
    async fn test_ready_endpoint_mixed_worker_status() {
        use rch_common::{WorkerConfig, WorkerId, WorkerStatus};

        let pool = WorkerPool::new();

        // Add healthy worker
        let healthy_config = WorkerConfig {
            id: WorkerId::new("healthy-worker"),
            host: "healthy.example.com".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(healthy_config).await;

        // Add unreachable worker
        let unreachable_config = WorkerConfig {
            id: WorkerId::new("unreachable-worker"),
            host: "unreachable.example.com".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 50,
            tags: vec![],
        };
        pool.add_worker(unreachable_config.clone()).await;

        // Set second worker as unreachable
        if let Some(worker) = pool.get(&unreachable_config.id).await {
            worker.set_status(WorkerStatus::Unreachable).await;
        }

        let state = HttpState {
            pool,
            version: "0.1.0-test",
            started_at: Instant::now(),
            pid: 12345,
        };
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

        // Should be ready because at least one worker is healthy
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "ready");
        assert_eq!(json["available_workers"], 1); // Only healthy worker
        assert_eq!(json["total_available_slots"], 4); // Only healthy worker's slots
    }

    #[tokio::test]
    async fn test_ready_endpoint_worker_with_no_slots() {
        use rch_common::{WorkerConfig, WorkerId};

        let pool = WorkerPool::new();

        let worker_config = WorkerConfig {
            id: WorkerId::new("busy-worker"),
            host: "busy.example.com".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 2,
            priority: 100,
            tags: vec![],
        };
        pool.add_worker(worker_config.clone()).await;

        // Reserve all slots
        if let Some(worker) = pool.get(&worker_config.id).await {
            worker.reserve_slots(2).await;
        }

        let state = HttpState {
            pool,
            version: "0.1.0-test",
            started_at: Instant::now(),
            pid: 12345,
        };
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

        // Worker is healthy but has no slots - should be not ready
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "not_ready");
        assert_eq!(json["workers_available"], false);
    }

    #[tokio::test]
    async fn test_health_endpoint_json_content_type() {
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

        // Check content type is JSON
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or(""));
        assert!(content_type.unwrap().contains("application/json"));
    }

    #[tokio::test]
    async fn test_metrics_endpoint_content_type() {
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

        // Check content type is text/plain with version
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or(""));
        assert!(
            content_type.unwrap().contains("text/plain"),
            "Expected text/plain content type for metrics"
        );
    }

    // ==================== Tailnet status API ====================

    #[test]
    fn tailscale_ranges_are_recognised() {
        let v4 = |s: &str| IpAddr::V4(s.parse().unwrap());
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());
        assert!(is_tailscale_ip(v4("100.64.0.1")));
        assert!(is_tailscale_ip(v4("100.68.51.94")));
        assert!(is_tailscale_ip(v4("100.127.255.255")));
        assert!(!is_tailscale_ip(v4("100.63.255.255")));
        assert!(!is_tailscale_ip(v4("100.128.0.0")));
        assert!(!is_tailscale_ip(v4("10.10.10.1")));
        assert!(!is_tailscale_ip(v4("0.0.0.0")));
        assert!(is_tailscale_ip(v6("fd7a:115c:a1e0::1")));
        assert!(!is_tailscale_ip(v6("fd7a:115c:a1e1::1")));
        assert!(!is_tailscale_ip(v6("::")));
    }

    #[test]
    fn bind_guard_allows_loopback_and_tailnet_only() {
        let ok = |s: &str| check_bind_addr(s.parse().unwrap(), false).is_ok();
        assert!(ok("127.0.0.1:9101"));
        assert!(ok("[::1]:9101"));
        assert!(ok("100.90.148.85:9101"));
        assert!(!ok("0.0.0.0:9101"));
        assert!(!ok("[::]:9101"));
        assert!(!ok("10.10.10.1:9101"));
        assert!(!ok("192.168.1.5:9101"));
        // The override is explicit and total.
        assert!(check_bind_addr("0.0.0.0:9101".parse().unwrap(), true).is_ok());
        // The refusal names the fix.
        let err = check_bind_addr("0.0.0.0:9101".parse().unwrap(), false).unwrap_err();
        assert!(err.contains("allow_any_addr"), "{err}");
        assert!(err.contains("100.64.0.0/10"), "{err}");
    }

    #[test]
    fn bind_spec_parsing() {
        assert_eq!(resolve_api_bind("").unwrap(), None);
        assert_eq!(resolve_api_bind("   ").unwrap(), None);
        assert_eq!(
            resolve_api_bind("127.0.0.1:9200").unwrap(),
            Some("127.0.0.1:9200".parse().unwrap())
        );
        assert_eq!(
            resolve_api_bind("100.68.51.94").unwrap(),
            Some(SocketAddr::from(([100, 68, 51, 94], DEFAULT_API_PORT)))
        );
        assert_eq!(
            resolve_api_bind("[fd7a:115c:a1e0::1]:9101").unwrap(),
            Some("[fd7a:115c:a1e0::1]:9101".parse().unwrap())
        );
        assert!(resolve_api_bind("tailscale:notaport").is_err());
        assert!(resolve_api_bind("nonsense").is_err());
        // "tailscale" resolves only when tailscaled is up; either outcome must
        // be well-formed, never a panic.
        match resolve_api_bind("tailscale:9109") {
            Ok(Some(addr)) => {
                assert!(is_tailscale_ip(addr.ip()));
                assert_eq!(addr.port(), 9109);
            }
            Ok(None) => panic!("\"tailscale\" must never mean off"),
            Err(e) => assert!(e.contains("tailscaled"), "{e}"),
        }
    }

    #[test]
    fn token_resolution_precedence_and_refusals() {
        let base = ApiConfig::default();
        // Nothing configured, no explicit opt-out: refuse, naming the fix.
        let err = resolve_api_token(&base).unwrap_err();
        assert!(
            err.contains("api.token") && err.contains("no_token"),
            "{err}"
        );
        // Explicit opt-out.
        let open = ApiConfig {
            no_token: true,
            ..base.clone()
        };
        assert_eq!(resolve_api_token(&open).unwrap(), None);
        // Inline token, trimmed.
        let inline = ApiConfig {
            token: Some("  s3cret \n".into()),
            ..base.clone()
        };
        assert_eq!(
            resolve_api_token(&inline).unwrap().as_deref(),
            Some("s3cret")
        );
        // A whitespace-only token is "no token", not an empty credential.
        let blank = ApiConfig {
            token: Some("   ".into()),
            ..base.clone()
        };
        assert!(resolve_api_token(&blank).is_err());
        // token_file wins over token, and is trimmed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.token");
        std::fs::write(&path, "from-file\n").unwrap();
        let file = ApiConfig {
            token: Some("inline".into()),
            token_file: Some(path.display().to_string()),
            ..base.clone()
        };
        assert_eq!(
            resolve_api_token(&file).unwrap().as_deref(),
            Some("from-file")
        );
        // An empty file is a refusal, never an open door.
        std::fs::write(&path, "\n").unwrap();
        assert!(resolve_api_token(&file).unwrap_err().contains("empty"));
        // A missing file names the path.
        let missing = ApiConfig {
            token_file: Some(dir.path().join("nope").display().to_string()),
            ..base
        };
        assert!(resolve_api_token(&missing).unwrap_err().contains("nope"));
    }

    #[test]
    fn token_compare_is_exact() {
        assert!(tokens_equal("abc", "abc"));
        assert!(!tokens_equal("abc", "abd"));
        assert!(!tokens_equal("abc", "ab"));
        assert!(!tokens_equal("", "a"));
        assert!(tokens_equal("", ""));
    }

    fn make_api_ctx() -> DaemonContext {
        crate::test_daemon_context(WorkerPool::new())
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn api_router_gates_status_routes_with_the_token() {
        let router = create_api_router(
            ApiState {
                ctx: make_api_ctx(),
                token: Some("s3cret".into()),
            },
            make_test_state(),
        );
        let get = |uri: &str, auth: Option<&str>| {
            let mut b = Request::builder().uri(uri);
            if let Some(a) = auth {
                b = b.header(header::AUTHORIZATION, a);
            }
            b.body(Body::empty()).unwrap()
        };

        for uri in [
            "/status",
            "/workers/capabilities",
            "/workers/config",
            "/repo-convergence/status",
        ] {
            let r = router.clone().oneshot(get(uri, None)).await.unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{uri} without token");
            assert!(r.headers().contains_key(header::WWW_AUTHENTICATE));
            let r = router
                .clone()
                .oneshot(get(uri, Some("Bearer wrong")))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{uri} wrong token");
            let r = router
                .clone()
                .oneshot(get(uri, Some("Bearer s3cret")))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK, "{uri} right token");
        }
        // X-Rch-Token is the header for callers that cannot set Authorization.
        let r = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .header("x-rch-token", "s3cret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        // The observability routes stay open on this listener.
        for uri in ["/health", "/metrics", "/budget"] {
            let r = router.clone().oneshot(get(uri, None)).await.unwrap();
            assert_eq!(r.status(), StatusCode::OK, "{uri} open");
        }
    }

    #[tokio::test]
    async fn api_status_matches_the_socket_shape() {
        use rch_common::{WorkerConfig, WorkerId};
        let pool = WorkerPool::new();
        pool.add_worker(WorkerConfig {
            id: WorkerId::new("w1"),
            host: "100.64.0.9".to_string(),
            user: "u".to_string(),
            identity_file: "~/.ssh/id".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec!["rust".to_string()],
        })
        .await;
        let ctx = crate::test_daemon_context(pool.clone());
        let router = create_api_router(
            ApiState { ctx, token: None },
            HttpState {
                pool,
                version: "t",
                started_at: Instant::now(),
                pid: 1,
            },
        );
        let status = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        // The keys the collector and `rch status --json` read.
        for key in [
            "daemon",
            "workers",
            "active_builds",
            "queued_builds",
            "recent_builds",
            "alerts",
            "issues",
        ] {
            assert!(status.get(key).is_some(), "status missing {key}");
        }
        assert_eq!(status["workers"][0]["id"], "w1");
        assert_eq!(status["workers"][0]["total_slots"], 4);

        let cfg = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/workers/config")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(cfg["workers"][0]["id"], "w1");
        assert_eq!(cfg["workers"][0]["tags"][0], "rust");
        assert_eq!(cfg["workers"][0]["priority"], 100);

        let caps = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/workers/capabilities")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(caps["workers"][0]["id"], "w1");

        // `/repo-convergence/status` carries the socket's body: a fleet with no
        // convergence data is "unknown" (never "healthy"), and asking about a
        // worker the service has not tracked yields the explicit "stale" view.
        let conv = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/repo-convergence/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        for key in ["status", "workers", "summary", "recent_outcomes"] {
            assert!(conv.get(key).is_some(), "convergence missing {key}");
        }
        assert_eq!(conv["status"], "unknown");
        assert_eq!(conv["summary"]["total_workers"], 0);
        let one = body_json(
            router
                .oneshot(
                    Request::builder()
                        .uri("/repo-convergence/status?worker=w1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(one["workers"][0]["worker_id"], "w1");
        assert_eq!(one["workers"][0]["drift_state"], "stale");
        assert_eq!(one["summary"]["stale"], 1);
    }

    #[tokio::test]
    async fn test_budget_endpoint_returns_json() {
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

        // Check content type is JSON
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or(""));
        assert!(content_type.unwrap().contains("application/json"));
    }
}
