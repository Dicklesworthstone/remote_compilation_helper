//! Verdict-transition webhook dispatch for `rch doctor --reliability --watch`.
//!
//! When the watch loop observes a reliability verdict transition
//! (`Healthy → Degraded`, `Degraded → Failing`, …) this module fires the
//! configured webhooks so an on-call engineer is paged directly, without an
//! intervening log-shipper pipeline.
//!
//! Design notes:
//! - **Secrets are never stored in config.** Routing keys, bearer tokens, and
//!   HMAC signing secrets are referenced by env-var *name* (`*_env` fields on
//!   [`DoctorWebhookEndpoint`]) and resolved here at dispatch time.
//! - **Queue-bounded.** A shared [`Semaphore`] caps in-flight deliveries; when
//!   it is exhausted the transition is dropped and journaled rather than
//!   growing an unbounded backlog of spawned tasks.
//! - **Audit trail.** Every attempt (and its outcome) is emitted as a
//!   structured tracing event on `target: "rch::doctor::webhook"` so a
//!   post-mortem can reconstruct exactly when RCH tried to alert and what the
//!   receiver returned.
//! - **Fail-open.** Webhook dispatch never affects the watch loop's verdict or
//!   exit code; all errors are logged and swallowed.

use std::sync::Arc;
use std::time::Duration;

use rch_common::{DoctorWebhookEndpoint, DoctorWebhookFormat, DoctorWebhooksConfig};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::doctor::ReliabilityVerdict;

/// A minimal, decoupled view of one diagnostic, built by the watch loop from
/// its private `ReliabilityDiagnostic` so this module needs no access to the
/// doctor internals.
#[derive(Debug, Clone)]
pub struct WebhookDiagnostic {
    pub code: String,
    pub severity: String,
    pub category: String,
    pub message: String,
}

/// Everything a formatter needs to render a transition payload.
#[derive(Debug, Clone)]
pub struct WebhookTransition {
    pub from: ReliabilityVerdict,
    pub to: ReliabilityVerdict,
    pub host: String,
    /// RFC3339 timestamp string.
    pub ts: String,
    pub scope: Vec<String>,
    pub diagnostics: Vec<WebhookDiagnostic>,
}

/// Best-effort local hostname for payload attribution. Mirrors the helper in
/// `fleet::audit` (no portable std API exists).
#[must_use]
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        })
}

/// Stable lowercase label for a verdict (matches the config-predicate spelling
/// and the doctor JSON `summary.overall`).
fn verdict_token(v: ReliabilityVerdict) -> &'static str {
    match v {
        ReliabilityVerdict::Healthy => "healthy",
        ReliabilityVerdict::Degraded => "degraded",
        ReliabilityVerdict::Failing => "failing",
    }
}

/// Does a single transition predicate match this `from → to` change?
///
/// Unknown predicate strings never match (the caller warns once). A predicate
/// only matches a genuine change (`from != to`); `any_to_*` excludes the case
/// where the target state was already held.
#[must_use]
pub fn predicate_matches(
    predicate: &str,
    from: ReliabilityVerdict,
    to: ReliabilityVerdict,
) -> bool {
    use ReliabilityVerdict::{Degraded, Failing, Healthy};
    match predicate {
        "any_to_any" => from != to,
        "healthy_to_degraded" => from == Healthy && to == Degraded,
        "degraded_to_failing" => from == Degraded && to == Failing,
        "any_to_failing" => to == Failing && from != Failing,
        "any_to_degraded" => to == Degraded && from != Degraded,
        "failing_to_healthy" => from == Failing && to == Healthy,
        "degraded_to_healthy" => from == Degraded && to == Healthy,
        "any_to_healthy" => to == Healthy && from != Healthy,
        _ => false,
    }
}

/// Should `endpoint` fire for this transition? True iff enabled and at least
/// one of its `on_transitions` predicates matches.
#[must_use]
pub fn endpoint_should_fire(
    endpoint: &DoctorWebhookEndpoint,
    from: ReliabilityVerdict,
    to: ReliabilityVerdict,
) -> bool {
    endpoint.enabled
        && endpoint
            .on_transitions
            .iter()
            .any(|p| predicate_matches(p, from, to))
}

/// Slack attachment color for a verdict (red / amber / green).
fn slack_color(v: ReliabilityVerdict) -> &'static str {
    match v {
        ReliabilityVerdict::Healthy => "#2eb886",
        ReliabilityVerdict::Degraded => "#daa038",
        ReliabilityVerdict::Failing => "#a30200",
    }
}

/// PagerDuty severity for a verdict.
fn pagerduty_severity(v: ReliabilityVerdict) -> &'static str {
    match v {
        ReliabilityVerdict::Healthy => "info",
        ReliabilityVerdict::Degraded => "warning",
        ReliabilityVerdict::Failing => "critical",
    }
}

/// Concise human summary line shared across formats.
fn summary_line(t: &WebhookTransition) -> String {
    format!(
        "RCH reliability {} → {} on {}",
        verdict_token(t.from),
        verdict_token(t.to),
        t.host
    )
}

/// Build the opinionated generic-JSON body.
fn build_generic(t: &WebhookTransition) -> Value {
    json!({
        "schema_version": "1.0.0",
        "ts": t.ts,
        "host": t.host,
        "scope": t.scope,
        "transition": { "from": verdict_token(t.from), "to": verdict_token(t.to) },
        "verdict": verdict_token(t.to),
        "summary": summary_line(t),
        "diagnostics": t.diagnostics.iter().map(|d| json!({
            "code": d.code,
            "severity": d.severity,
            "category": d.category,
            "message": d.message,
        })).collect::<Vec<_>>(),
    })
}

/// Build a Slack Block Kit body.
fn build_slack(t: &WebhookTransition) -> Value {
    // Surface only the actionable (non-pass) diagnostics as fields, capped so
    // a noisy sweep can't produce an oversized Slack payload.
    let fields: Vec<Value> = t
        .diagnostics
        .iter()
        .filter(|d| d.severity != "pass")
        .take(10)
        .map(|d| {
            json!({
                "type": "mrkdwn",
                "text": format!("*{}* ({})\n{}", d.code, d.severity, d.message),
            })
        })
        .collect();

    let mut blocks = vec![
        json!({
            "type": "header",
            "text": { "type": "plain_text", "text": summary_line(t), "emoji": true },
        }),
        json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(
                    "*Transition:* `{}` → `{}`\n*Host:* `{}`\n*When:* {}",
                    verdict_token(t.from), verdict_token(t.to), t.host, t.ts
                ),
            },
        }),
    ];
    if !fields.is_empty() {
        blocks.push(json!({ "type": "section", "fields": fields }));
    }

    json!({
        "attachments": [{
            "color": slack_color(t.to),
            "blocks": blocks,
        }],
    })
}

/// Build a PagerDuty Events API v2 body. `routing_key` is the resolved secret.
fn build_pagerduty(t: &WebhookTransition, routing_key: &str) -> Value {
    // Resolve when returning to healthy; trigger otherwise. The dedup key is
    // host-scoped so a resolve clears the matching trigger incident.
    let event_action = if t.to == ReliabilityVerdict::Healthy {
        "resolve"
    } else {
        "trigger"
    };
    json!({
        "routing_key": routing_key,
        "event_action": event_action,
        "dedup_key": format!("rch-reliability-{}", t.host),
        "payload": {
            "summary": summary_line(t),
            "source": t.host,
            "severity": pagerduty_severity(t.to),
            "component": "rch-reliability",
            "custom_details": {
                "from": verdict_token(t.from),
                "to": verdict_token(t.to),
                "scope": t.scope,
                "ts": t.ts,
                "diagnostics": t.diagnostics.iter().map(|d| json!({
                    "code": d.code,
                    "severity": d.severity,
                    "category": d.category,
                    "message": d.message,
                })).collect::<Vec<_>>(),
            },
        },
    })
}

/// Resolved request body plus any auth/routing material that had to be read
/// from the environment.
#[derive(Debug)]
struct RenderedRequest {
    body: String,
    /// Optional bearer token (already resolved from env).
    bearer: Option<String>,
    /// Optional HMAC signing secret (already resolved from env). `Some` iff the
    /// endpoint configured `signing_secret_env` and it resolved successfully; a
    /// configured-but-unset secret is a `RenderError::MissingEnv` rather than a
    /// silent downgrade to unsigned delivery.
    signing_secret: Option<String>,
}

/// An error that aborts rendering before any network call (e.g. a required
/// secret env var is unset). These are journaled and the endpoint is skipped.
#[derive(Debug)]
enum RenderError {
    MissingEnv { field: &'static str, var: String },
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenderError::MissingEnv { field, var } => {
                write!(f, "{field} references env var `{var}` which is unset")
            }
        }
    }
}

/// Read an env var by name, treating empty as unset.
fn read_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// Render the body for `endpoint`, resolving any required secrets from env.
fn render_request(
    endpoint: &DoctorWebhookEndpoint,
    t: &WebhookTransition,
) -> Result<RenderedRequest, RenderError> {
    let body_value = match endpoint.format {
        DoctorWebhookFormat::GenericJson => build_generic(t),
        DoctorWebhookFormat::Slack => build_slack(t),
        DoctorWebhookFormat::Pagerduty => {
            let var = endpoint.routing_key_env.as_deref().unwrap_or("");
            let routing_key = read_env(var).ok_or_else(|| RenderError::MissingEnv {
                field: "routing_key_env",
                var: var.to_string(),
            })?;
            build_pagerduty(t, &routing_key)
        }
    };
    let bearer = match endpoint.bearer_token_env.as_deref() {
        Some(var) => Some(read_env(var).ok_or_else(|| RenderError::MissingEnv {
            field: "bearer_token_env",
            var: var.to_string(),
        })?),
        None => None,
    };
    // A configured signing secret that is unset/empty must abort delivery
    // (skip + journal), never silently downgrade to an unsigned payload — a
    // strict receiver would 4xx-reject (non-retryable) and drop the alert.
    let signing_secret = match endpoint.signing_secret_env.as_deref() {
        Some(var) => Some(read_env(var).ok_or_else(|| RenderError::MissingEnv {
            field: "signing_secret_env",
            var: var.to_string(),
        })?),
        None => None,
    };
    Ok(RenderedRequest {
        // `to_string` on a serde_json::Value never fails.
        body: body_value.to_string(),
        bearer,
        signing_secret,
    })
}

/// HMAC-SHA256, computed with the `sha2` crate only (no extra dependency).
/// Returns the lowercase hex digest. Follows RFC 2104 with SHA-256's 64-byte
/// block size.
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        block_key[..digest.len()].copy_from_slice(&digest);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut i_pad = [0x36u8; BLOCK];
    let mut o_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        i_pad[i] ^= block_key[i];
        o_pad[i] ^= block_key[i];
    }

    let mut inner = Sha256::new();
    inner.update(i_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(o_pad);
    outer.update(inner_digest);
    let mac = outer.finalize();

    let mut hex = String::with_capacity(mac.len() * 2);
    for byte in mac {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Classify an HTTP status: retry on 408/429 and any 5xx; give up on other
/// 4xx (the request itself is broken and won't get better).
fn status_is_retryable(status: u16) -> bool {
    status == 408 || status == 429 || (500..600).contains(&status)
}

/// Deliver one rendered request with retry + exponential backoff. Returns
/// `true` on eventual success. Every attempt is journaled.
async fn deliver(
    client: &reqwest::Client,
    endpoint: &DoctorWebhookEndpoint,
    rendered: &RenderedRequest,
    signing_secret: Option<&str>,
) {
    let signature = signing_secret.map(|s| {
        format!(
            "sha256={}",
            hmac_sha256_hex(s.as_bytes(), rendered.body.as_bytes())
        )
    });
    let timeout = Duration::from_millis(endpoint.timeout_ms.max(1));
    let max_attempts = endpoint.retry_max.saturating_add(1);

    for attempt in 1..=max_attempts {
        let mut req = client
            .post(&endpoint.url)
            .timeout(timeout)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(rendered.body.clone());
        if let Some(bearer) = &rendered.bearer {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        if let Some(sig) = &signature {
            req = req.header("X-RCH-Signature", sig.clone());
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if resp.status().is_success() {
                    tracing::info!(
                        target: "rch::doctor::webhook",
                        endpoint = %endpoint.name,
                        attempt,
                        status,
                        "doctor.webhook.delivered",
                    );
                    return;
                }
                let retryable = status_is_retryable(status);
                tracing::warn!(
                    target: "rch::doctor::webhook",
                    endpoint = %endpoint.name,
                    attempt,
                    status,
                    retryable,
                    "doctor.webhook.attempt_failed",
                );
                if !retryable {
                    return;
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "rch::doctor::webhook",
                    endpoint = %endpoint.name,
                    attempt,
                    error = %e,
                    "doctor.webhook.attempt_error",
                );
            }
        }

        if attempt < max_attempts {
            // Exponential backoff: base * 2^(attempt-1).
            let backoff = endpoint
                .retry_backoff_ms
                .saturating_mul(1u64 << (attempt - 1).min(16));
            tokio::time::sleep(Duration::from_millis(backoff)).await;
        }
    }

    tracing::error!(
        target: "rch::doctor::webhook",
        endpoint = %endpoint.name,
        attempts = max_attempts,
        "doctor.webhook.exhausted",
    );
}

/// Dispatches verdict-transition webhooks. Cheaply cloneable (all state is
/// behind `Arc`). Construct once at watch-loop start; call [`Self::on_transition`]
/// for each observed transition.
#[derive(Clone)]
pub struct WebhookDispatcher {
    endpoints: Arc<Vec<DoctorWebhookEndpoint>>,
    client: reqwest::Client,
    inflight: Arc<Semaphore>,
}

impl WebhookDispatcher {
    /// Build a dispatcher from config. Returns `None` when no endpoints are
    /// configured (the common case), so the watch loop pays nothing.
    /// Unknown transition predicates are warned about once, here, at startup.
    #[must_use]
    pub fn from_config(cfg: &DoctorWebhooksConfig) -> Option<Self> {
        if cfg.endpoints.is_empty() {
            return None;
        }
        for ep in &cfg.endpoints {
            for pred in &ep.on_transitions {
                if !KNOWN_PREDICATES.contains(&pred.as_str()) {
                    tracing::warn!(
                        target: "rch::doctor::webhook",
                        endpoint = %ep.name,
                        predicate = %pred,
                        "doctor.webhook.unknown_predicate",
                    );
                }
            }
        }
        let client = reqwest::Client::builder()
            .user_agent(concat!("rch/", env!("CARGO_PKG_VERSION")))
            .build()
            .ok()?;
        Some(Self {
            endpoints: Arc::new(cfg.endpoints.clone()),
            client,
            inflight: Arc::new(Semaphore::new(cfg.max_inflight.max(1))),
        })
    }

    /// Fire all matching webhooks for one transition. Never blocks the caller
    /// on the network: each delivery is spawned under the shared in-flight
    /// permit budget. Returns the number of endpoints dispatched.
    pub fn on_transition(&self, t: &WebhookTransition) -> usize {
        let mut dispatched = 0;
        for endpoint in self.endpoints.iter() {
            if !endpoint_should_fire(endpoint, t.from, t.to) {
                continue;
            }
            // Resolve body + secrets up front so a misconfiguration is
            // journaled against this transition rather than swallowed in a
            // detached task.
            let rendered = match render_request(endpoint, t) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        target: "rch::doctor::webhook",
                        endpoint = %endpoint.name,
                        error = %e,
                        "doctor.webhook.skipped_misconfigured",
                    );
                    continue;
                }
            };

            // Queue-bound: acquire a permit without waiting. If the budget is
            // exhausted, drop this delivery (journaled) instead of growing an
            // unbounded task backlog.
            let permit = match Arc::clone(&self.inflight).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        target: "rch::doctor::webhook",
                        endpoint = %endpoint.name,
                        "doctor.webhook.dropped_queue_full",
                    );
                    continue;
                }
            };

            let client = self.client.clone();
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                let _permit = permit; // released on task completion
                let signing_secret = rendered.signing_secret.clone();
                deliver(&client, &endpoint, &rendered, signing_secret.as_deref()).await;
            });
            dispatched += 1;
        }
        dispatched
    }
}

/// Every predicate the matcher understands. Used only for startup validation
/// warnings; the matcher itself is the source of truth.
const KNOWN_PREDICATES: &[&str] = &[
    "any_to_any",
    "healthy_to_degraded",
    "degraded_to_failing",
    "any_to_failing",
    "any_to_degraded",
    "failing_to_healthy",
    "degraded_to_healthy",
    "any_to_healthy",
];

#[cfg(test)]
mod tests {
    use super::*;
    use ReliabilityVerdict::{Degraded, Failing, Healthy};

    fn endpoint(format: DoctorWebhookFormat, transitions: &[&str]) -> DoctorWebhookEndpoint {
        DoctorWebhookEndpoint {
            name: "t".to_string(),
            url: "https://example.com/hook".to_string(),
            format,
            on_transitions: transitions.iter().map(|s| (*s).to_string()).collect(),
            retry_max: 3,
            retry_backoff_ms: 200,
            timeout_ms: 5000,
            enabled: true,
            routing_key_env: None,
            bearer_token_env: None,
            signing_secret_env: None,
        }
    }

    fn transition(from: ReliabilityVerdict, to: ReliabilityVerdict) -> WebhookTransition {
        WebhookTransition {
            from,
            to,
            host: "css".to_string(),
            ts: "2026-06-09T12:35:00Z".to_string(),
            scope: vec!["all".to_string()],
            diagnostics: vec![WebhookDiagnostic {
                code: "RCH-R001".to_string(),
                severity: "critical".to_string(),
                category: "daemon".to_string(),
                message: "daemon unreachable".to_string(),
            }],
        }
    }

    #[test]
    fn predicate_specific_transitions() {
        assert!(predicate_matches("healthy_to_degraded", Healthy, Degraded));
        assert!(!predicate_matches("healthy_to_degraded", Healthy, Failing));
        assert!(predicate_matches("degraded_to_failing", Degraded, Failing));
        assert!(predicate_matches("failing_to_healthy", Failing, Healthy));
        assert!(predicate_matches("degraded_to_healthy", Degraded, Healthy));
    }

    #[test]
    fn predicate_any_to_variants_exclude_self_transition() {
        assert!(predicate_matches("any_to_failing", Healthy, Failing));
        assert!(predicate_matches("any_to_failing", Degraded, Failing));
        // Already failing → still failing is not a transition.
        assert!(!predicate_matches("any_to_failing", Failing, Failing));
        assert!(predicate_matches("any_to_healthy", Failing, Healthy));
        assert!(!predicate_matches("any_to_healthy", Healthy, Healthy));
    }

    #[test]
    fn predicate_any_to_any_requires_change() {
        assert!(predicate_matches("any_to_any", Healthy, Failing));
        assert!(!predicate_matches("any_to_any", Healthy, Healthy));
    }

    #[test]
    fn predicate_unknown_never_matches() {
        assert!(!predicate_matches("nonsense", Healthy, Failing));
        assert!(!predicate_matches("", Healthy, Failing));
    }

    #[test]
    fn endpoint_disabled_never_fires() {
        let mut ep = endpoint(DoctorWebhookFormat::Slack, &["any_to_failing"]);
        ep.enabled = false;
        assert!(!endpoint_should_fire(&ep, Healthy, Failing));
    }

    #[test]
    fn endpoint_empty_transitions_never_fires() {
        let ep = endpoint(DoctorWebhookFormat::Slack, &[]);
        assert!(!endpoint_should_fire(&ep, Healthy, Failing));
    }

    #[test]
    fn endpoint_fires_on_any_matching_predicate() {
        let ep = endpoint(
            DoctorWebhookFormat::Slack,
            &["healthy_to_degraded", "any_to_failing"],
        );
        assert!(endpoint_should_fire(&ep, Healthy, Failing));
        assert!(endpoint_should_fire(&ep, Healthy, Degraded));
        assert!(!endpoint_should_fire(&ep, Failing, Healthy));
    }

    #[test]
    fn generic_payload_shape() {
        let t = transition(Healthy, Degraded);
        let v = build_generic(&t);
        assert_eq!(v["schema_version"], "1.0.0");
        assert_eq!(v["transition"]["from"], "healthy");
        assert_eq!(v["transition"]["to"], "degraded");
        assert_eq!(v["verdict"], "degraded");
        assert_eq!(v["host"], "css");
        assert_eq!(v["diagnostics"][0]["code"], "RCH-R001");
    }

    #[test]
    fn slack_payload_has_color_and_blocks() {
        let t = transition(Degraded, Failing);
        let v = build_slack(&t);
        assert_eq!(v["attachments"][0]["color"], "#a30200");
        // header + section + diagnostic-fields section
        assert_eq!(v["attachments"][0]["blocks"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn slack_payload_omits_empty_fields_section() {
        let mut t = transition(Healthy, Degraded);
        t.diagnostics.clear();
        let v = build_slack(&t);
        assert_eq!(v["attachments"][0]["blocks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn pagerduty_triggers_on_failing_resolves_on_healthy() {
        let trig = build_pagerduty(&transition(Healthy, Failing), "rk-123");
        assert_eq!(trig["event_action"], "trigger");
        assert_eq!(trig["routing_key"], "rk-123");
        assert_eq!(trig["payload"]["severity"], "critical");
        assert_eq!(trig["dedup_key"], "rch-reliability-css");

        let res = build_pagerduty(&transition(Failing, Healthy), "rk-123");
        assert_eq!(res["event_action"], "resolve");
        // Same dedup key clears the matching incident.
        assert_eq!(res["dedup_key"], "rch-reliability-css");
    }

    #[test]
    fn render_pagerduty_requires_routing_key_env() {
        let mut ep = endpoint(DoctorWebhookFormat::Pagerduty, &["any_to_failing"]);
        ep.routing_key_env = Some("RCH_TEST_PD_KEY_DEFINITELY_UNSET".to_string());
        let err = render_request(&ep, &transition(Healthy, Failing)).unwrap_err();
        match err {
            RenderError::MissingEnv { field, .. } => assert_eq!(field, "routing_key_env"),
        }
    }

    #[test]
    fn render_refuses_configured_but_unset_signing_secret() {
        // Regression (bd-review-webhook-unsigned-silent): a configured signing
        // secret whose env var is unset must abort with MissingEnv (skip +
        // journal), NOT silently dispatch an unsigned payload.
        let mut ep = endpoint(DoctorWebhookFormat::GenericJson, &["any_to_failing"]);
        ep.signing_secret_env = Some("RCH_TEST_SIGNING_SECRET_DEFINITELY_UNSET".to_string());
        let err = render_request(&ep, &transition(Healthy, Failing)).unwrap_err();
        match err {
            RenderError::MissingEnv { field, .. } => assert_eq!(field, "signing_secret_env"),
        }
    }

    #[test]
    fn render_omits_signature_when_signing_unconfigured() {
        // No signing_secret_env => unsigned delivery is intentional, not a
        // downgrade; render succeeds with signing_secret = None.
        let ep = endpoint(DoctorWebhookFormat::GenericJson, &["any_to_failing"]);
        let rendered = render_request(&ep, &transition(Healthy, Failing)).expect("renders");
        assert!(rendered.signing_secret.is_none());
    }

    #[test]
    fn status_retry_classification() {
        assert!(status_is_retryable(500));
        assert!(status_is_retryable(503));
        assert!(status_is_retryable(429));
        assert!(status_is_retryable(408));
        assert!(!status_is_retryable(400));
        assert!(!status_is_retryable(401));
        assert!(!status_is_retryable(404));
        assert!(!status_is_retryable(200));
    }

    #[test]
    fn hmac_matches_rfc4231_test_case_2() {
        // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?"
        let mac = hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn dispatcher_none_when_no_endpoints() {
        let cfg = DoctorWebhooksConfig::default();
        assert!(WebhookDispatcher::from_config(&cfg).is_none());
    }
}
