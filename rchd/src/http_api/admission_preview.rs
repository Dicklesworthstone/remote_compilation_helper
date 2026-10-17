//! Authenticated, non-owning placement observations for remote agents.
//!
//! GET uses the shared percent-encoded `request` query; POST accepts the same
//! typed request as JSON. Both enter the normal preview selector, never the
//! reservation/queue handler. An observation can become stale immediately:
//! it is not permission to execute, transfer sources, or release worker slots.

use super::ApiState;
use crate::DaemonContext;
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, RawQuery, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use rch_common::admission_preview::{
    MAX_REQUEST_BYTES, PROTOCOL_VERSION, PreviewRequest, PreviewResponse, ROUTE,
};
use rch_common::{SelectedWorker, SelectionReason, SelectionRequest, SelectionResponse};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_CONCURRENT_PREVIEWS: usize = 8;
const PREVIEW_TIMEOUT: Duration = Duration::from_secs(2);

/// Merge BEFORE the parent router installs its bearer-token middleware.
pub(super) fn router() -> Router<Arc<ApiState>> {
    router_with_limit(Arc::new(Semaphore::new(MAX_CONCURRENT_PREVIEWS)))
}

fn router_with_limit(limit: Arc<Semaphore>) -> Router<Arc<ApiState>> {
    Router::new()
        .route(ROUTE, get(get_preview).post(post_preview))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(Extension(limit))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error(status: StatusCode, message: &str) -> Response {
    no_store(
        (
            status,
            Json(serde_json::json!({
                "protocol_version": PROTOCOL_VERSION,
                "error": message,
            })),
        )
            .into_response(),
    )
}

async fn get_preview(
    State(state): State<Arc<ApiState>>,
    Extension(limit): Extension<Arc<Semaphore>>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = query.as_deref().unwrap_or_default();
    // Match the shared wire request's complete line budget, not just its JSON.
    if query.len().saturating_add(ROUTE.len() + 6) > MAX_REQUEST_BYTES {
        return error(
            StatusCode::URI_TOO_LONG,
            "admission-preview request is too large",
        );
    }
    match PreviewRequest::from_query(query) {
        Ok(request) => preview(state, limit, request).await,
        Err(_) => error(StatusCode::BAD_REQUEST, "invalid admission-preview request"),
    }
}

async fn post_preview(
    State(state): State<Arc<ApiState>>,
    Extension(limit): Extension<Arc<Semaphore>>,
    payload: Result<Json<PreviewRequest>, JsonRejection>,
) -> Response {
    match payload {
        Ok(Json(request)) => preview(state, limit, request).await,
        // Preserve 413/415 and syntax/data rejection status, but do not echo
        // command contents, tool names or credentials in parser diagnostics.
        Err(rejection) => error(rejection.status(), "invalid admission-preview JSON"),
    }
}

async fn preview(
    state: Arc<ApiState>,
    limit: Arc<Semaphore>,
    request: PreviewRequest,
) -> Response {
    let request = match request.into_selection() {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid admission-preview request"),
    };
    let permit = match limit.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let mut response = error(
                StatusCode::TOO_MANY_REQUESTS,
                "admission-preview capacity exhausted",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            return response;
        }
    };
    match tokio::time::timeout(PREVIEW_TIMEOUT, observe(&state.ctx, request, permit)).await {
        Ok(Ok(response)) => no_store(Json(response).into_response()),
        Ok(Err(message)) => error(StatusCode::SERVICE_UNAVAILABLE, message),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission-preview timed out; no build was admitted",
        ),
    }
}

fn refused(reason: &str) -> PreviewResponse {
    PreviewResponse {
        protocol_version: PROTOCOL_VERSION,
        selection: SelectionResponse {
            worker: None,
            reason: SelectionReason::SelectionError(reason.to_string()),
            build_id: None,
            diagnostics: None,
        },
    }
}

async fn observe(
    ctx: &DaemonContext,
    request: SelectionRequest,
    permit: OwnedSemaphorePermit,
) -> Result<PreviewResponse, &'static str> {
    // A restart cannot close admission between this check and the observation.
    // The outer timeout bounds this read-lock hold; no reservation is created.
    let admission = ctx.admission_barrier.read().await;
    if *admission {
        return Ok(refused("restart_admission_barrier_active"));
    }
    if ctx.history.ownership_failed() {
        return Ok(refused("durable_ownership_uncertain"));
    }

    // Use the same history-owned exclusion sources as Unix admission. Source
    // fences may inspect lease files: do not perform those reads on the async
    // runtime. Keep the permit in that task until it finishes even if the HTTP
    // caller leaves, so cancelled reads cannot evade the concurrency budget.
    let history = Arc::clone(&ctx.history);
    let project = request.project.clone();
    let (mut excluded, _permit) = tokio::task::spawn_blocking(move || {
        let mut excluded = history.active_workers_for_project(&project);
        excluded.extend(
            history.source_fenced_workers(&project, crate::cancellation::client_lease_owns_source),
        );
        excluded.extend(history.live_checkout_fenced_workers(&project));
        excluded.extend(history.source_busy_fenced_workers(&project));
        (excluded, permit)
    })
    .await
    .map_err(|_| "admission-preview could not inspect source ownership")?;

    // A starving queued job's hold also prevents a real, non-owning newcomer
    // from taking that worker. Match the execution path's steer-then-busy rule
    // rather than reporting that held capacity as immediately available.
    let held_worker = ctx.history.queue_hold_against(None);
    let mut steered_off_hold = false;
    loop {
        let result = ctx
            .worker_selector
            .preview_with_exclusions(&ctx.pool, &request, &excluded)
            .await;
        let selected = match result.worker {
            Some(worker) => {
                let endpoint = worker.endpoint_snapshot().await;
                if held_worker.as_deref() == Some(endpoint.config.id.as_str()) {
                    steered_off_hold = true;
                    excluded.insert(endpoint.config.id.to_string());
                    continue;
                }
                let slots_available = worker.available_slots().await;
                let speed_score = worker.get_speed_score();
                // Do not combine old host/identity details with new capability
                // or slot observations after a concurrent worker retarget.
                let Some(config) = worker.lock_current_endpoint(&endpoint).await else {
                    return Ok(refused("worker_endpoint_changed_during_preview"));
                };
                Some(SelectedWorker {
                    id: config.id.clone(),
                    host: config.host.clone(),
                    user: config.user.clone(),
                    identity_file: config.identity_file.clone(),
                    slots_available,
                    speed_score,
                    declared_os: rch_common::declared_os(&config.tags),
                })
            }
            None => None,
        };
        if ctx.history.ownership_failed() {
            return Ok(refused("durable_ownership_uncertain"));
        }
        let reason = if selected.is_none() && steered_off_hold {
            SelectionReason::AllWorkersBusy
        } else {
            result.reason
        };
        let response = PreviewResponse {
            protocol_version: PROTOCOL_VERSION,
            selection: SelectionResponse {
                worker: selected,
                reason,
                build_id: None,
                diagnostics: result.diagnostics,
            },
        };
        response
            .validate()
            .map_err(|_| "admission-preview selector result was inconsistent")?;
        return Ok(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_api::{HttpState, create_api_router, create_router};
    use crate::workers::WorkerPool;
    use axum::body::Body;
    use axum::http::Request;
    use rch_common::{RequiredRuntime, WorkerConfig, WorkerId};
    use std::time::Instant;
    use tower::ServiceExt;

    fn input() -> PreviewRequest {
        PreviewRequest {
            protocol_version: PROTOCOL_VERSION,
            project: "http-preview-fixture".into(),
            command: "make".into(),
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new("requested")],
            toolchain: None,
            required_runtime: RequiredRuntime::None,
            job_mode: false,
            required_tools: Vec::new(),
        }
    }

    async fn fixture() -> (DaemonContext, Router) {
        let pool = WorkerPool::new();
        for id in ["requested", "alternate"] {
            pool.add_worker(WorkerConfig {
                id: WorkerId::new(id),
                host: "localhost".into(),
                user: "fixture".into(),
                identity_file: "/no-test-key".into(),
                total_slots: 4,
                priority: 100,
                tags: Vec::new(),
                tools: Vec::new(),
            })
            .await;
        }
        let ctx = crate::test_daemon_context(pool.clone());
        let router = create_api_router(
            ApiState {
                ctx: ctx.clone(),
                token: Some("fixture-token".into()),
            },
            HttpState {
                pool,
                version: "fixture",
                started_at: Instant::now(),
                pid: 1,
            },
        );
        (ctx, router)
    }

    fn http_request(input: &PreviewRequest, post: bool, token: Option<&str>) -> Request<Body> {
        let (method, uri, body) = if post {
            (
                "POST",
                ROUTE.to_string(),
                Body::from(serde_json::to_vec(input).unwrap()),
            )
        } else {
            let line = input.request_line().unwrap();
            (
                "GET",
                line.trim_end_matches('\n')
                    .strip_prefix("GET ")
                    .unwrap()
                    .to_string(),
                Body::empty(),
            )
        };
        let mut request = Request::builder().method(method).uri(uri);
        if post {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        if let Some(token) = token {
            request = request.header("x-rch-token", token);
        }
        request.body(body).unwrap()
    }

    async fn decoded(response: Response) -> PreviewResponse {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 131_072)
            .await
            .unwrap();
        let response: PreviewResponse = serde_json::from_slice(&body).unwrap();
        response.validate().unwrap();
        response
    }

    async fn assert_unowned(ctx: &DaemonContext, expected_free: u32) {
        assert!(ctx.history.active_builds().is_empty());
        assert_eq!(ctx.history.queue_depth(), 0);
        for (id, expected) in [("requested", expected_free), ("alternate", 4)] {
            assert_eq!(
                ctx.pool
                    .get(&WorkerId::new(id))
                    .await
                    .unwrap()
                    .available_slots()
                    .await,
                expected,
            );
        }
    }

    #[tokio::test]
    async fn preview_requires_auth_for_both_transports_and_never_appears_on_metrics_listener() {
        let _guard = rch_common::test_guard!();
        let (ctx, router) = fixture().await;
        for post in [false, true] {
            for token in [None, Some("wrong")] {
                let response = router
                    .clone()
                    .oneshot(http_request(&input(), post, token))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
            let response = router
                .clone()
                .oneshot(http_request(&input(), post, Some("fixture-token")))
                .await
                .unwrap();
            assert_eq!(
                decoded(response).await.selection.worker.unwrap().id.as_str(),
                "requested",
            );
        }
        let metrics = create_router(HttpState {
            pool: ctx.pool.clone(),
            version: "fixture",
            started_at: Instant::now(),
            pid: 1,
        });
        let response = metrics
            .oneshot(http_request(&input(), false, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_unowned(&ctx, 4).await;
    }

    #[tokio::test]
    async fn repeated_previews_and_busy_pins_never_reserve_enqueue_or_switch_workers() {
        let _guard = rch_common::test_guard!();
        let (ctx, router) = fixture().await;
        for post in [false, true, false, true] {
            let response = router
                .clone()
                .oneshot(http_request(&input(), post, Some("fixture-token")))
                .await
                .unwrap();
            assert_eq!(
                decoded(response).await.selection.worker.unwrap().id.as_str(),
                "requested",
            );
            assert_unowned(&ctx, 4).await;
        }
        let worker = ctx.pool.get(&WorkerId::new("requested")).await.unwrap();
        assert!(worker.reserve_slots(4).await);
        let response = router
            .oneshot(http_request(&input(), true, Some("fixture-token")))
            .await
            .unwrap();
        let response = decoded(response).await;
        assert!(response.selection.worker.is_none());
        assert_eq!(response.selection.reason, SelectionReason::AllWorkersBusy);
        assert_unowned(&ctx, 0).await;
        worker.release_slots(4).await;
    }

    #[tokio::test]
    async fn source_fences_tool_requirements_and_unknown_disk_budget_are_not_dropped() {
        let _guard = rch_common::test_guard!();
        for fence in ["live", "busy", "tools", "disk"] {
            let (ctx, router) = fixture().await;
            let mut request = input();
            match fence {
                "live" => ctx.history.fence_live_checkout(&request.project, "requested"),
                "busy" => ctx.history.fence_source_busy(&request.project, "requested"),
                "tools" => request.required_tools.push("never-probed-tool".into()),
                "disk" => request.disk_headroom_gib = 23,
                _ => unreachable!(),
            }
            let response = router
                .oneshot(http_request(&request, true, Some("fixture-token")))
                .await
                .unwrap();
            let response = decoded(response).await;
            assert!(response.selection.worker.is_none(), "{fence}");
            assert!(response.selection.diagnostics.is_some(), "{fence}");
            assert_unowned(&ctx, 4).await;
        }
    }

    #[tokio::test]
    async fn restart_barrier_is_observed_without_reopening_it_or_admitting_a_build() {
        let _guard = rch_common::test_guard!();
        let (ctx, router) = fixture().await;
        *ctx.admission_barrier.write().await = true;
        let response = router
            .oneshot(http_request(&input(), false, Some("fixture-token")))
            .await
            .unwrap();
        let response = decoded(response).await;
        assert!(response.selection.worker.is_none());
        assert_eq!(
            response.selection.reason,
            SelectionReason::SelectionError("restart_admission_barrier_active".into()),
        );
        assert!(*ctx.admission_barrier.read().await);
        assert_unowned(&ctx, 4).await;
    }

    #[tokio::test]
    async fn invalid_or_oversized_payloads_cannot_fall_through_to_execution() {
        let _guard = rch_common::test_guard!();
        let (ctx, router) = fixture().await;
        let valid = serde_json::to_string(&input()).unwrap();
        let mut invalid = vec![
            "{".to_string(),
            format!("{{\"estimated_cores\":1,{}", &valid[1..]),
        ];
        for field in [
            "wait",
            "queue",
            "dry_run",
            "hook_pid",
            "local_wrapper_id",
            "future_requirement",
        ] {
            let mut value = serde_json::to_value(input()).unwrap();
            value[field] = serde_json::json!(1);
            invalid.push(value.to_string());
        }
        let mut version = input();
        version.protocol_version += 1;
        invalid.push(serde_json::to_string(&version).unwrap());
        invalid.push(" ".repeat(MAX_REQUEST_BYTES + 1));
        for body in invalid {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(ROUTE)
                        .header("x-rch-token", "fixture-token")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(response.status().is_client_error());
        }
        let line = input().request_line().unwrap();
        let uri = line.trim_end().strip_prefix("GET ").unwrap();
        for suffix in ["&wait=1", "&dry_run=0", "&request={}"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("{uri}{suffix}"))
                        .header("x-rch-token", "fixture-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert_unowned(&ctx, 4).await;
    }

    #[tokio::test]
    async fn saturated_preview_budget_refuses_instead_of_queueing() {
        let _guard = rch_common::test_guard!();
        let (ctx, _) = fixture().await;
        let limit = Arc::new(Semaphore::new(1));
        let _held = limit.clone().acquire_owned().await.unwrap();
        // Only this resource-budget fixture omits the auth layer; the actual
        // protected router is exercised above with absent and wrong tokens.
        let router = router_with_limit(limit).with_state(Arc::new(ApiState {
            ctx: ctx.clone(),
            token: None,
        }));
        let response = router
            .oneshot(http_request(&input(), true, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        assert_unowned(&ctx, 4).await;
    }

    #[tokio::test]
    async fn a_stalled_restart_lock_times_out_without_claiming_a_selection() {
        let _guard = rch_common::test_guard!();
        let (ctx, router) = fixture().await;
        let _held = ctx.admission_barrier.write().await;
        let response = tokio::time::timeout(
            PREVIEW_TIMEOUT + Duration::from_secs(2),
            router.oneshot(http_request(&input(), true, Some("fixture-token"))),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_unowned(&ctx, 4).await;
    }
}
