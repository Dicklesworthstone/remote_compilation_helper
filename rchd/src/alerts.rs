//! Worker health alerting.
//!
//! Tracks alert-worthy events and exposes active alerts for status reporting.
//! Also supports webhook dispatch for external notification systems.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::WorkerStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Webhook configuration for alert dispatch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook endpoint URL.
    pub url: Option<String>,
    /// Secret for HMAC signing (optional).
    pub secret: Option<String>,
    /// Timeout in seconds for webhook requests.
    pub timeout_secs: u64,
    /// Number of retries on failure.
    pub retry_count: u32,
    /// Events to send (empty = all events).
    pub events: Vec<String>,
}

/// Alert configuration.
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Enable or disable alert generation.
    pub enabled: bool,
    /// Suppress duplicate alerts for this duration.
    pub suppress_duplicates: ChronoDuration,
    /// How long to retain an alert after it is cleared before dropping it
    /// entirely. During this window the alert is reported with status
    /// `cleared_pending_clean` so UIs can visually grey it out instead of
    /// making humans chase a warning that has already healed (bd-3ogaz).
    pub cleared_retention: ChronoDuration,
    /// Webhook configuration for external notifications.
    pub webhook: Option<WebhookConfig>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suppress_duplicates: ChronoDuration::seconds(300),
            cleared_retention: ChronoDuration::seconds(300),
            webhook: None,
        }
    }
}

/// Severity for an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    #[allow(dead_code)]
    Info,
    Warning,
    Error,
    Critical,
}

impl AlertSeverity {
    fn rank(&self) -> u8 {
        match self {
            AlertSeverity::Critical => 0,
            AlertSeverity::Error => 1,
            AlertSeverity::Warning => 2,
            AlertSeverity::Info => 3,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Error => "error",
            AlertSeverity::Critical => "critical",
        }
    }
}

/// Alert kind identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    WorkerOffline,
    WorkerDegraded,
    CircuitOpen,
    AllWorkersOffline,
}

impl AlertKind {
    fn as_str(&self) -> &'static str {
        match self {
            AlertKind::WorkerOffline => "worker_offline",
            AlertKind::WorkerDegraded => "worker_degraded",
            AlertKind::CircuitOpen => "circuit_open",
            AlertKind::AllWorkersOffline => "all_workers_offline",
        }
    }
}

/// Internal key used to deduplicate alerts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AlertKey {
    WorkerOffline(String),
    WorkerDegraded(String),
    CircuitOpen(String),
    AllWorkersOffline,
}

/// Lifecycle state for an alert (bd-3ogaz).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertState {
    /// The condition that raised the alert is still present.
    Active,
    /// The condition has healed but the alert is kept around briefly so
    /// operators can see that it just self-cleared. Dropped from the
    /// active-alerts list once `cleared_retention` elapses.
    ClearedPendingClean,
}

impl AlertState {
    fn as_str(&self) -> &'static str {
        match self {
            AlertState::Active => "active",
            AlertState::ClearedPendingClean => "cleared_pending_clean",
        }
    }
}

/// Alert record stored in memory.
#[derive(Debug, Clone)]
pub struct Alert {
    id: String,
    kind: AlertKind,
    severity: AlertSeverity,
    message: String,
    worker_id: Option<String>,
    /// First time this alert instance was observed. Stable across duplicate
    /// re-raises within the same lifecycle.
    first_seen: DateTime<Utc>,
    /// Last time the underlying condition was re-observed. Updated on every
    /// `upsert_alert` call.
    last_seen: DateTime<Utc>,
    /// Timestamp at which the alert was cleared. `None` while the alert is
    /// still active.
    cleared_at: Option<DateTime<Utc>>,
    /// Retained for backwards compatibility with existing callers — equal to
    /// `first_seen`.
    created_at: DateTime<Utc>,
}

impl Alert {
    fn new(
        kind: AlertKind,
        severity: AlertSeverity,
        message: String,
        worker_id: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            kind,
            severity,
            message,
            worker_id,
            first_seen: now,
            last_seen: now,
            cleared_at: None,
            created_at: now,
        }
    }

    fn state(&self) -> AlertState {
        if self.cleared_at.is_some() {
            AlertState::ClearedPendingClean
        } else {
            AlertState::Active
        }
    }

    fn to_info(&self) -> AlertInfo {
        AlertInfo {
            id: self.id.clone(),
            kind: self.kind.as_str().to_string(),
            severity: self.severity.as_str().to_string(),
            message: self.message.clone(),
            worker_id: self.worker_id.clone(),
            created_at: self.created_at.to_rfc3339(),
            first_seen: self.first_seen.to_rfc3339(),
            last_seen: self.last_seen.to_rfc3339(),
            cleared_at: self.cleared_at.map(|t| t.to_rfc3339()),
            state: self.state().as_str().to_string(),
        }
    }
}

/// API-visible alert representation.
#[derive(Debug, Clone, Serialize)]
pub struct AlertInfo {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    pub created_at: String,
    /// First time the alert instance was raised. Stable across duplicate
    /// re-raises within a single lifecycle.
    pub first_seen: String,
    /// Last time the underlying condition was re-observed.
    pub last_seen: String,
    /// Timestamp at which the alert was cleared. Present only when the alert
    /// is in the `cleared_pending_clean` state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleared_at: Option<String>,
    /// Lifecycle state: `active` while the condition persists,
    /// `cleared_pending_clean` while a recently-healed alert is still shown.
    pub state: String,
}

struct AlertStore {
    active: HashMap<AlertKey, Alert>,
    last_sent: HashMap<AlertKey, DateTime<Utc>>,
}

/// Manages active alerts and suppression logic.
pub struct AlertManager {
    config: AlertConfig,
    state: RwLock<AlertStore>,
}

impl AlertManager {
    /// Create a new alert manager.
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            state: RwLock::new(AlertStore {
                active: HashMap::new(),
                last_sent: HashMap::new(),
            }),
        }
    }

    /// Return the currently active alerts.
    ///
    /// Side effect: any alert whose `cleared_at` is older than the configured
    /// `cleared_retention` window is evicted from the store on this call.
    /// Still-healing alerts (within the retention window) are returned with
    /// `state = "cleared_pending_clean"` so UIs can grey them out.
    pub fn active_alerts(&self) -> Vec<AlertInfo> {
        self.sweep_stale_cleared();

        let mut alerts: Vec<Alert> = {
            let state = self.state.read().unwrap();
            state.active.values().cloned().collect()
        };

        alerts.sort_by(|a, b| {
            // Active alerts first; within each group sort by severity then recency.
            let a_state = a.state();
            let b_state = b.state();
            a_state
                .cmp(&b_state)
                .then_with(|| a.severity.rank().cmp(&b.severity.rank()))
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        });

        alerts.into_iter().map(|alert| alert.to_info()).collect()
    }

    /// Remove alerts that have been in the `cleared_pending_clean` state for
    /// longer than the retention window. Best-effort; caller does not need
    /// to observe the result.
    fn sweep_stale_cleared(&self) {
        let now = Utc::now();
        let retention = self.config.cleared_retention;
        let mut state = self.state.write().unwrap();
        state.active.retain(|_, alert| match alert.cleared_at {
            Some(cleared) => now - cleared < retention,
            None => true,
        });
    }

    /// Handle worker status transitions.
    pub fn handle_worker_status_change(
        &self,
        worker_id: &str,
        previous: WorkerStatus,
        current: WorkerStatus,
        last_error: Option<&str>,
    ) {
        if !self.config.enabled || previous == current {
            return;
        }

        let offline_key = AlertKey::WorkerOffline(worker_id.to_string());
        let degraded_key = AlertKey::WorkerDegraded(worker_id.to_string());

        match current {
            WorkerStatus::Healthy => {
                self.clear_alert(&offline_key);
                self.clear_alert(&degraded_key);
            }
            WorkerStatus::Unreachable => {
                self.clear_alert(&degraded_key);
                let reason = last_error.unwrap_or("worker unreachable");
                let message = format!("Worker '{}' is offline: {}", worker_id, reason.trim());
                let alert = Alert::new(
                    AlertKind::WorkerOffline,
                    AlertSeverity::Error,
                    message,
                    Some(worker_id.to_string()),
                );
                self.upsert_alert(offline_key, alert);
            }
            WorkerStatus::Degraded => {
                self.clear_alert(&offline_key);
                let message = format!("Worker '{}' is degraded", worker_id);
                let alert = Alert::new(
                    AlertKind::WorkerDegraded,
                    AlertSeverity::Warning,
                    message,
                    Some(worker_id.to_string()),
                );
                self.upsert_alert(degraded_key, alert);
            }
            WorkerStatus::Draining | WorkerStatus::Drained | WorkerStatus::Disabled => {}
        }
    }

    /// Handle circuit breaker opening.
    pub fn handle_circuit_open(&self, worker_id: &str) {
        if !self.config.enabled {
            return;
        }

        let key = AlertKey::CircuitOpen(worker_id.to_string());
        let message = format!("Circuit opened for worker '{}'", worker_id);
        let alert = Alert::new(
            AlertKind::CircuitOpen,
            AlertSeverity::Warning,
            message,
            Some(worker_id.to_string()),
        );
        self.upsert_alert(key, alert);
    }

    /// Handle circuit breaker returning to closed (or half-open) state.
    ///
    /// Transitions the corresponding `CircuitOpen` alert to
    /// `cleared_pending_clean` so UIs can grey it out. `active_alerts()`
    /// evicts it after `cleared_retention` elapses.
    ///
    /// This is the counterpart to [`handle_circuit_open`] and is the key
    /// fix for bd-3ogaz: without it, a transient circuit-open alert would
    /// persist forever in `rch status` even after the worker recovers.
    pub fn handle_circuit_closed(&self, worker_id: &str) {
        if !self.config.enabled {
            return;
        }
        let key = AlertKey::CircuitOpen(worker_id.to_string());
        self.clear_alert(&key);
    }

    /// Handle all-workers-offline aggregation.
    pub fn handle_all_workers_offline(&self, total: usize, unreachable: usize) {
        if !self.config.enabled || total == 0 {
            return;
        }

        let key = AlertKey::AllWorkersOffline;

        if unreachable == total {
            let message = "All workers are offline".to_string();
            let alert = Alert::new(
                AlertKind::AllWorkersOffline,
                AlertSeverity::Critical,
                message,
                None,
            );
            self.upsert_alert(key, alert);
        } else {
            self.clear_alert(&key);
        }
    }

    fn upsert_alert(&self, key: AlertKey, mut alert: Alert) {
        let now = alert.created_at;
        let mut state = self.state.write().unwrap();

        // If the same alert condition is being re-raised (either active or
        // recently-cleared), preserve the original `id`, `first_seen`, and
        // `created_at` so downstream correlates this as the same incident
        // rather than a new one. `last_seen` is stamped to now so UIs can
        // show "still ongoing" age, and `cleared_at` is reset.
        if let Some(existing) = state.active.get(&key) {
            alert.id = existing.id.clone();
            alert.first_seen = existing.first_seen;
            alert.created_at = existing.created_at;
        }
        alert.last_seen = now;
        alert.cleared_at = None;

        if let Some(last) = state.last_sent.get(&key)
            && now - *last < self.config.suppress_duplicates
        {
            debug!(
                alert_kind = alert.kind.as_str(),
                alert_id = %alert.id,
                "Alert suppressed (duplicate within window)"
            );
            // Merge into existing entry to keep first_seen/last_seen fresh;
            // if no existing entry, seed one so re-raises after suppression
            // still surface.
            state
                .active
                .entry(key)
                .and_modify(|a| {
                    a.last_seen = now;
                    a.cleared_at = None;
                })
                .or_insert(alert);
            return;
        }

        // Log the alert for audit purposes
        match alert.severity {
            AlertSeverity::Critical => {
                warn!(
                    alert_kind = alert.kind.as_str(),
                    alert_id = %alert.id,
                    severity = "critical",
                    worker_id = ?alert.worker_id,
                    message = %alert.message,
                    "ALERT: Critical alert raised"
                );
            }
            AlertSeverity::Error => {
                warn!(
                    alert_kind = alert.kind.as_str(),
                    alert_id = %alert.id,
                    severity = "error",
                    worker_id = ?alert.worker_id,
                    message = %alert.message,
                    "ALERT: Error alert raised"
                );
            }
            AlertSeverity::Warning => {
                info!(
                    alert_kind = alert.kind.as_str(),
                    alert_id = %alert.id,
                    severity = "warning",
                    worker_id = ?alert.worker_id,
                    message = %alert.message,
                    "ALERT: Warning alert raised"
                );
            }
            AlertSeverity::Info => {
                info!(
                    alert_kind = alert.kind.as_str(),
                    alert_id = %alert.id,
                    severity = "info",
                    worker_id = ?alert.worker_id,
                    message = %alert.message,
                    "ALERT: Info alert raised"
                );
            }
        }

        // Dispatch webhook if configured
        self.dispatch_webhook(&alert);

        state.active.insert(key.clone(), alert);
        state.last_sent.insert(key, now);
    }

    fn clear_alert(&self, key: &AlertKey) {
        let now = Utc::now();
        let mut state = self.state.write().unwrap();
        // Mark-cleared rather than remove: the alert lingers as
        // `cleared_pending_clean` so operators can see a transient condition
        // just resolved. `active_alerts()` evicts it after the retention
        // window (bd-3ogaz).
        if let Some(alert) = state.active.get_mut(key)
            && alert.cleared_at.is_none()
        {
            alert.cleared_at = Some(now);
            debug!(
                alert_kind = alert.kind.as_str(),
                alert_id = %alert.id,
                "Alert transitioned to cleared_pending_clean"
            );
        }
    }

    /// Dispatch alert to webhook if configured.
    fn dispatch_webhook(&self, alert: &Alert) {
        let Some(webhook) = &self.config.webhook else {
            return;
        };
        let Some(url) = &webhook.url else {
            return;
        };

        // Check if this event type should be sent
        let event_type = alert.kind.as_str();
        if !webhook.events.is_empty() && !webhook.events.iter().any(|e| e == event_type) {
            debug!(
                event_type = event_type,
                "Skipping webhook dispatch (event type not in filter)"
            );
            return;
        }

        let payload = WebhookPayload {
            event: event_type.to_string(),
            timestamp: alert.created_at.to_rfc3339(),
            severity: alert.severity.as_str().to_string(),
            message: alert.message.clone(),
            worker_id: alert.worker_id.clone(),
            details: WebhookDetails {
                alert_id: alert.id.clone(),
            },
        };

        // Spawn a blocking task for the HTTP request with retry support
        let url = url.clone();
        let timeout_secs = webhook.timeout_secs;
        let retry_count = webhook.retry_count;
        let secret = webhook.secret.clone();

        tokio::task::spawn_blocking(move || {
            if let Err(e) = send_webhook_with_retries(
                &url,
                &payload,
                timeout_secs,
                retry_count,
                secret.as_deref(),
            ) {
                warn!(
                    url = %url,
                    error = %e,
                    retries = retry_count,
                    "Failed to dispatch webhook after all retries"
                );
            } else {
                debug!(
                    url = %url,
                    event = payload.event,
                    "Webhook dispatched successfully"
                );
            }
        });
    }
}

/// Webhook payload structure.
#[derive(Debug, Serialize)]
struct WebhookPayload {
    event: String,
    timestamp: String,
    severity: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_id: Option<String>,
    details: WebhookDetails,
}

#[derive(Debug, Serialize)]
struct WebhookDetails {
    alert_id: String,
}

/// Send webhook with retry support.
fn send_webhook_with_retries(
    url: &str,
    payload: &WebhookPayload,
    timeout_secs: u64,
    retry_count: u32,
    secret: Option<&str>,
) -> Result<(), String> {
    let mut last_error = String::new();
    let max_attempts = retry_count.saturating_add(1); // retry_count=0 means 1 attempt

    for attempt in 0..max_attempts {
        if attempt > 0 {
            // Exponential backoff: 100ms, 200ms, 400ms, ...
            let backoff_ms = 100 * (1u64 << (attempt - 1).min(5));
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            debug!(
                url = %url,
                attempt = attempt + 1,
                max_attempts = max_attempts,
                "Retrying webhook dispatch"
            );
        }

        match send_webhook_sync(url, payload, timeout_secs, secret) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_error = e;
                // Only retry on transient errors (network issues, 5xx)
                if !is_retryable_webhook_error(&last_error) {
                    return Err(last_error);
                }
            }
        }
    }

    Err(format!(
        "Failed after {} attempts: {}",
        max_attempts, last_error
    ))
}

/// Check if a webhook error is worth retrying.
fn is_retryable_webhook_error(error: &str) -> bool {
    // Retry on network errors and server errors (5xx)
    error.contains("timed out")
        || error.contains("connection")
        || error.contains("HTTP 5")
        || error.contains("network")
}

/// Compute HMAC-SHA256 signature for webhook payload.
fn compute_hmac_signature(body: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(body.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();

    // Return as hex string with sha256= prefix (GitHub-style)
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("sha256={}", hex)
}

/// Send webhook synchronously (blocking).
fn send_webhook_sync(
    url: &str,
    payload: &WebhookPayload,
    timeout_secs: u64,
    secret: Option<&str>,
) -> Result<(), String> {
    let body = serde_json::to_string(payload).map_err(|e| e.to_string())?;

    // Build agent with timeout configuration
    let config = ureq::config::Config::builder()
        .timeout_global(Some(std::time::Duration::from_secs(timeout_secs)))
        .build();
    let agent = ureq::Agent::new_with_config(config);

    let mut request = agent
        .post(url)
        .content_type("application/json")
        .header("User-Agent", "rchd-alerts/1.0");

    // Add HMAC signature if secret is configured
    if let Some(secret) = secret {
        let signature = compute_hmac_signature(&body, secret);
        request = request.header("X-Signature-256", &signature);
    }

    let response = request
        .send(&body)
        .map_err(|e: ureq::Error| e.to_string())?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    // ============== WebhookConfig Tests ==============

    #[test]
    fn test_webhook_config_default() {
        let _guard = test_guard!();
        let config = WebhookConfig::default();
        assert!(config.url.is_none());
        assert!(config.secret.is_none());
        assert_eq!(config.timeout_secs, 0);
        assert_eq!(config.retry_count, 0);
        assert!(config.events.is_empty());
    }

    #[test]
    fn test_webhook_config_serialization() {
        let _guard = test_guard!();
        let config = WebhookConfig {
            url: Some("https://hooks.example.com/rch".to_string()),
            secret: Some("test-secret".to_string()),
            timeout_secs: 5,
            retry_count: 3,
            events: vec![
                "worker_offline".to_string(),
                "all_workers_offline".to_string(),
            ],
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("hooks.example.com"));
        assert!(json.contains("worker_offline"));

        // Round-trip
        let parsed: WebhookConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, config.url);
        assert_eq!(parsed.events.len(), 2);
    }

    // ============== WebhookPayload Tests ==============

    #[test]
    fn test_webhook_payload_format() {
        let _guard = test_guard!();
        let payload = WebhookPayload {
            event: "worker_offline".to_string(),
            timestamp: "2026-01-27T10:30:00Z".to_string(),
            severity: "error".to_string(),
            message: "Worker 'gpu-1' is offline".to_string(),
            worker_id: Some("gpu-1".to_string()),
            details: WebhookDetails {
                alert_id: "abc-123".to_string(),
            },
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("worker_offline"));
        assert!(json.contains("gpu-1"));
        assert!(json.contains("abc-123"));
    }

    #[test]
    fn test_webhook_payload_without_worker_id() {
        let _guard = test_guard!();
        let payload = WebhookPayload {
            event: "all_workers_offline".to_string(),
            timestamp: "2026-01-27T10:30:00Z".to_string(),
            severity: "critical".to_string(),
            message: "All workers are offline".to_string(),
            worker_id: None,
            details: WebhookDetails {
                alert_id: "xyz-789".to_string(),
            },
        };

        let json = serde_json::to_string(&payload).unwrap();
        // worker_id should be skipped due to skip_serializing_if
        assert!(!json.contains("worker_id"));
        assert!(json.contains("critical"));
    }

    // ============== AlertConfig Tests ==============

    #[test]
    fn test_alert_config_default() {
        let _guard = test_guard!();
        let config = AlertConfig::default();
        assert!(config.enabled);
        assert_eq!(config.suppress_duplicates, ChronoDuration::seconds(300));
        assert!(config.webhook.is_none());
    }

    #[test]
    fn test_alert_config_with_webhook() {
        let _guard = test_guard!();
        let webhook = WebhookConfig {
            url: Some("https://example.com/webhook".to_string()),
            secret: None,
            timeout_secs: 10,
            retry_count: 2,
            events: vec!["worker_offline".to_string()],
        };

        let config = AlertConfig {
            enabled: true,
            suppress_duplicates: ChronoDuration::seconds(60),
            cleared_retention: ChronoDuration::seconds(300),
            webhook: Some(webhook),
        };

        assert!(config.webhook.is_some());
        assert_eq!(config.webhook.as_ref().unwrap().timeout_secs, 10);
    }

    #[test]
    fn test_alert_config_custom() {
        let _guard = test_guard!();
        let config = AlertConfig {
            enabled: false,
            suppress_duplicates: ChronoDuration::seconds(60),
            cleared_retention: ChronoDuration::seconds(300),
            webhook: None,
        };
        assert!(!config.enabled);
        assert_eq!(config.suppress_duplicates, ChronoDuration::seconds(60));
    }

    // ============== AlertSeverity Tests ==============

    #[test]
    fn test_severity_rank_ordering() {
        let _guard = test_guard!();
        // Critical < Error < Warning < Info (lower rank = higher priority)
        assert!(AlertSeverity::Critical.rank() < AlertSeverity::Error.rank());
        assert!(AlertSeverity::Error.rank() < AlertSeverity::Warning.rank());
        assert!(AlertSeverity::Warning.rank() < AlertSeverity::Info.rank());
    }

    #[test]
    fn test_severity_as_str() {
        let _guard = test_guard!();
        assert_eq!(AlertSeverity::Info.as_str(), "info");
        assert_eq!(AlertSeverity::Warning.as_str(), "warning");
        assert_eq!(AlertSeverity::Error.as_str(), "error");
        assert_eq!(AlertSeverity::Critical.as_str(), "critical");
    }

    // ============== AlertKind Tests ==============

    #[test]
    fn test_alert_kind_as_str() {
        let _guard = test_guard!();
        assert_eq!(AlertKind::WorkerOffline.as_str(), "worker_offline");
        assert_eq!(AlertKind::WorkerDegraded.as_str(), "worker_degraded");
        assert_eq!(AlertKind::CircuitOpen.as_str(), "circuit_open");
        assert_eq!(AlertKind::AllWorkersOffline.as_str(), "all_workers_offline");
    }

    // ============== Alert Tests ==============

    #[test]
    fn test_alert_new() {
        let _guard = test_guard!();
        let alert = Alert::new(
            AlertKind::WorkerOffline,
            AlertSeverity::Error,
            "Worker 'w1' is offline".to_string(),
            Some("w1".to_string()),
        );

        assert!(!alert.id.is_empty());
        assert_eq!(alert.kind, AlertKind::WorkerOffline);
        assert_eq!(alert.severity, AlertSeverity::Error);
        assert_eq!(alert.message, "Worker 'w1' is offline");
        assert_eq!(alert.worker_id, Some("w1".to_string()));
    }

    #[test]
    fn test_alert_to_info() {
        let _guard = test_guard!();
        let alert = Alert::new(
            AlertKind::CircuitOpen,
            AlertSeverity::Warning,
            "Circuit opened".to_string(),
            Some("worker-1".to_string()),
        );

        let info = alert.to_info();
        assert_eq!(info.id, alert.id);
        assert_eq!(info.kind, "circuit_open");
        assert_eq!(info.severity, "warning");
        assert_eq!(info.message, "Circuit opened");
        assert_eq!(info.worker_id, Some("worker-1".to_string()));
        assert!(!info.created_at.is_empty());
    }

    #[test]
    fn test_alert_to_info_no_worker_id() {
        let _guard = test_guard!();
        let alert = Alert::new(
            AlertKind::AllWorkersOffline,
            AlertSeverity::Critical,
            "All workers are offline".to_string(),
            None,
        );

        let info = alert.to_info();
        assert!(info.worker_id.is_none());
    }

    // ============== AlertManager Tests ==============

    #[test]
    fn test_manager_new_empty() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());
        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_alert_suppression() {
        let _guard = test_guard!();
        let config = AlertConfig {
            enabled: true,
            suppress_duplicates: ChronoDuration::seconds(300),
            cleared_retention: ChronoDuration::seconds(300),
            webhook: None,
        };
        let manager = AlertManager::new(config);
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Unreachable,
            Some("connection refused"),
        );

        let first = manager.active_alerts();
        assert_eq!(first.len(), 1);

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Degraded,
            WorkerStatus::Unreachable,
            Some("connection refused"),
        );

        let second = manager.active_alerts();
        assert_eq!(second.len(), 1);
    }

    #[test]
    fn test_clear_alert_on_recovery() {
        let _guard = test_guard!();
        // With zero cleared_retention, a cleared alert is evicted on the
        // next query. Use this to keep the original "cleared = disappears"
        // contract while still exercising the new lifecycle.
        let config = AlertConfig {
            cleared_retention: ChronoDuration::zero(),
            ..AlertConfig::default()
        };
        let manager = AlertManager::new(config);
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Degraded,
            None,
        );
        assert_eq!(manager.active_alerts().len(), 1);

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Degraded,
            WorkerStatus::Healthy,
            None,
        );
        assert_eq!(manager.active_alerts().len(), 0);
    }

    #[test]
    fn test_cleared_alert_retained_and_marked() {
        let _guard = test_guard!();
        // Default retention is 5 minutes, so a just-cleared alert should
        // still appear but with state "cleared_pending_clean" (bd-3ogaz).
        let manager = AlertManager::new(AlertConfig::default());
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Degraded,
            None,
        );
        assert_eq!(manager.active_alerts().len(), 1);
        assert_eq!(manager.active_alerts()[0].state, "active");
        assert!(manager.active_alerts()[0].cleared_at.is_none());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Degraded,
            WorkerStatus::Healthy,
            None,
        );
        let after = manager.active_alerts();
        assert_eq!(after.len(), 1, "cleared alert should be retained");
        assert_eq!(after[0].state, "cleared_pending_clean");
        assert!(after[0].cleared_at.is_some());
    }

    #[test]
    fn test_circuit_open_reraise_preserves_identity() {
        let _guard = test_guard!();
        // Re-raising the same circuit_open condition should correlate to a
        // single incident: same id, same first_seen, last_seen bumped.
        let manager = AlertManager::new(AlertConfig::default());
        manager.handle_circuit_open("w1");
        assert_eq!(manager.active_alerts()[0].state, "active");

        let first_alert = manager.active_alerts()[0].clone();
        manager.handle_circuit_open("w1");
        let second = manager.active_alerts();
        assert_eq!(second[0].id, first_alert.id, "re-raise should keep id");
        assert_eq!(second[0].first_seen, first_alert.first_seen);
    }

    #[test]
    fn test_circuit_closed_transitions_alert_to_cleared() {
        let _guard = test_guard!();
        // Core bd-3ogaz behaviour: circuit opens, then closes → alert must
        // flip to cleared_pending_clean so `rch status` doesn't keep
        // warning about a condition that has already healed.
        let manager = AlertManager::new(AlertConfig::default());
        manager.handle_circuit_open("w1");
        assert_eq!(manager.active_alerts()[0].state, "active");

        manager.handle_circuit_closed("w1");
        let after = manager.active_alerts();
        assert_eq!(after.len(), 1, "alert retained during retention window");
        assert_eq!(after[0].state, "cleared_pending_clean");
        assert!(after[0].cleared_at.is_some());
    }

    #[test]
    fn test_circuit_closed_then_expires() {
        let _guard = test_guard!();
        let config = AlertConfig {
            cleared_retention: ChronoDuration::zero(),
            ..AlertConfig::default()
        };
        let manager = AlertManager::new(config);
        manager.handle_circuit_open("w1");
        manager.handle_circuit_closed("w1");
        assert!(
            manager.active_alerts().is_empty(),
            "zero retention should evict on next read"
        );
    }

    #[test]
    fn test_circuit_reopen_after_clear_reactivates() {
        let _guard = test_guard!();
        // If a circuit clears and then re-opens before eviction, the alert
        // should reactivate (state=active, cleared_at=None) with the same
        // id so operators see one continuing incident.
        let manager = AlertManager::new(AlertConfig::default());
        manager.handle_circuit_open("w1");
        let original_id = manager.active_alerts()[0].id.clone();

        manager.handle_circuit_closed("w1");
        assert_eq!(manager.active_alerts()[0].state, "cleared_pending_clean");

        manager.handle_circuit_open("w1");
        let reactivated = manager.active_alerts();
        assert_eq!(reactivated[0].state, "active");
        assert!(reactivated[0].cleared_at.is_none());
        assert_eq!(reactivated[0].id, original_id);
    }

    #[test]
    fn test_cleared_pending_clean_evicted_after_retention() {
        let _guard = test_guard!();
        let config = AlertConfig {
            cleared_retention: ChronoDuration::zero(),
            ..AlertConfig::default()
        };
        let manager = AlertManager::new(config);
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Degraded,
            None,
        );
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Degraded,
            WorkerStatus::Healthy,
            None,
        );
        // With zero retention, the alert evicts immediately on next read.
        assert_eq!(manager.active_alerts().len(), 0);
    }

    #[test]
    fn test_disabled_config_no_alerts() {
        let _guard = test_guard!();
        let config = AlertConfig {
            enabled: false,
            suppress_duplicates: ChronoDuration::seconds(300),
            cleared_retention: ChronoDuration::seconds(300),
            webhook: None,
        };
        let manager = AlertManager::new(config);

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Unreachable,
            None,
        );

        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_same_status_no_alert() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Healthy,
            None,
        );

        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_healthy_to_unreachable() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Unreachable,
            Some("SSH timeout"),
        );

        let alerts = manager.active_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "worker_offline");
        assert_eq!(alerts[0].severity, "error");
        assert!(alerts[0].message.contains("w1"));
        assert!(alerts[0].message.contains("SSH timeout"));
    }

    #[test]
    fn test_healthy_to_degraded() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Degraded,
            None,
        );

        let alerts = manager.active_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "worker_degraded");
        assert_eq!(alerts[0].severity, "warning");
    }

    #[test]
    fn test_unreachable_to_degraded() {
        let _guard = test_guard!();
        // Use zero retention so this test keeps its "the other alert
        // disappears" contract after the bd-3ogaz lifecycle changes.
        let config = AlertConfig {
            cleared_retention: ChronoDuration::zero(),
            ..AlertConfig::default()
        };
        let manager = AlertManager::new(config);

        // First become unreachable
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Unreachable,
            None,
        );
        assert_eq!(manager.active_alerts().len(), 1);
        assert_eq!(manager.active_alerts()[0].kind, "worker_offline");

        // Then become degraded (offline alert should be cleared, degraded added)
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Unreachable,
            WorkerStatus::Degraded,
            None,
        );
        let alerts = manager.active_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "worker_degraded");
    }

    #[test]
    fn test_degraded_to_unreachable() {
        let _guard = test_guard!();
        let config = AlertConfig {
            cleared_retention: ChronoDuration::zero(),
            ..AlertConfig::default()
        };
        let manager = AlertManager::new(config);

        // First become degraded
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Degraded,
            None,
        );
        assert_eq!(manager.active_alerts()[0].kind, "worker_degraded");

        // Then become unreachable (degraded alert should be cleared, offline added)
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Degraded,
            WorkerStatus::Unreachable,
            Some("connection lost"),
        );
        let alerts = manager.active_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "worker_offline");
    }

    #[test]
    fn test_draining_no_alert() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Draining,
            None,
        );

        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_disabled_no_alert() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Disabled,
            None,
        );

        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_circuit_open() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_circuit_open("worker-1");

        let alerts = manager.active_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "circuit_open");
        assert_eq!(alerts[0].severity, "warning");
        assert!(alerts[0].message.contains("worker-1"));
    }

    #[test]
    fn test_circuit_open_disabled() {
        let _guard = test_guard!();
        let config = AlertConfig {
            enabled: false,
            suppress_duplicates: ChronoDuration::seconds(300),
            cleared_retention: ChronoDuration::seconds(300),
            webhook: None,
        };
        let manager = AlertManager::new(config);

        manager.handle_circuit_open("worker-1");

        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_all_workers_offline() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_all_workers_offline(3, 3); // All 3 workers offline

        let alerts = manager.active_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "all_workers_offline");
        assert_eq!(alerts[0].severity, "critical");
    }

    #[test]
    fn test_all_workers_offline_clears_on_recovery() {
        let _guard = test_guard!();
        let config = AlertConfig {
            cleared_retention: ChronoDuration::zero(),
            ..AlertConfig::default()
        };
        let manager = AlertManager::new(config);

        manager.handle_all_workers_offline(3, 3); // All offline
        assert_eq!(manager.active_alerts().len(), 1);

        manager.handle_all_workers_offline(3, 2); // One recovered
        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_all_workers_offline_zero_total() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_all_workers_offline(0, 0); // No workers configured

        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_all_workers_offline_disabled() {
        let _guard = test_guard!();
        let config = AlertConfig {
            enabled: false,
            suppress_duplicates: ChronoDuration::seconds(300),
            cleared_retention: ChronoDuration::seconds(300),
            webhook: None,
        };
        let manager = AlertManager::new(config);

        manager.handle_all_workers_offline(3, 3);

        assert!(manager.active_alerts().is_empty());
    }

    #[test]
    fn test_multiple_workers_multiple_alerts() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Unreachable,
            None,
        );
        manager.handle_worker_status_change(
            "w2",
            WorkerStatus::Healthy,
            WorkerStatus::Degraded,
            None,
        );
        manager.handle_circuit_open("w3");

        let alerts = manager.active_alerts();
        assert_eq!(alerts.len(), 3);
    }

    #[test]
    fn test_alerts_sorted_by_severity() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        // Add in non-priority order: warning, error, critical
        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Degraded, // Warning
            None,
        );
        manager.handle_worker_status_change(
            "w2",
            WorkerStatus::Healthy,
            WorkerStatus::Unreachable, // Error
            None,
        );
        manager.handle_all_workers_offline(3, 3); // Critical

        let alerts = manager.active_alerts();
        assert_eq!(alerts.len(), 3);

        // Should be sorted: Critical, Error, Warning
        assert_eq!(alerts[0].severity, "critical");
        assert_eq!(alerts[1].severity, "error");
        assert_eq!(alerts[2].severity, "warning");
    }

    #[test]
    fn test_unreachable_default_reason() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Unreachable,
            None, // No specific error
        );

        let alerts = manager.active_alerts();
        assert!(alerts[0].message.contains("worker unreachable"));
    }

    #[test]
    fn test_alert_unique_ids() {
        let _guard = test_guard!();
        let manager = AlertManager::new(AlertConfig::default());

        manager.handle_worker_status_change(
            "w1",
            WorkerStatus::Healthy,
            WorkerStatus::Unreachable,
            None,
        );
        manager.handle_worker_status_change(
            "w2",
            WorkerStatus::Healthy,
            WorkerStatus::Degraded,
            None,
        );

        let alerts = manager.active_alerts();
        assert_ne!(alerts[0].id, alerts[1].id);
    }

    // ============== HMAC Signing Tests ==============

    #[test]
    fn test_hmac_signature_format() {
        let _guard = test_guard!();
        let body = r#"{"event":"test"}"#;
        let secret = "test-secret-key";

        let signature = compute_hmac_signature(body, secret);

        // Should start with sha256= prefix
        assert!(signature.starts_with("sha256="));

        // Signature should be hex-encoded (64 chars for SHA256)
        let hex_part = &signature[7..];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_signature_consistency() {
        let _guard = test_guard!();
        let body = r#"{"event":"worker_offline","message":"test"}"#;
        let secret = "my-webhook-secret";

        // Same input should produce same signature
        let sig1 = compute_hmac_signature(body, secret);
        let sig2 = compute_hmac_signature(body, secret);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_signature_different_secrets() {
        let _guard = test_guard!();
        let body = r#"{"event":"test"}"#;

        let sig1 = compute_hmac_signature(body, "secret-1");
        let sig2 = compute_hmac_signature(body, "secret-2");

        // Different secrets should produce different signatures
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_signature_different_bodies() {
        let _guard = test_guard!();
        let secret = "same-secret";

        let sig1 = compute_hmac_signature(r#"{"a":1}"#, secret);
        let sig2 = compute_hmac_signature(r#"{"a":2}"#, secret);

        // Different bodies should produce different signatures
        assert_ne!(sig1, sig2);
    }

    // ============== Retry Logic Tests ==============

    #[test]
    fn test_retryable_webhook_error_detection() {
        let _guard = test_guard!();

        // Should retry on network/server errors
        assert!(is_retryable_webhook_error("connection timed out"));
        assert!(is_retryable_webhook_error("HTTP 502"));
        assert!(is_retryable_webhook_error("HTTP 503"));
        assert!(is_retryable_webhook_error("HTTP 500"));
        assert!(is_retryable_webhook_error("network unreachable"));

        // Should NOT retry on client errors
        assert!(!is_retryable_webhook_error("HTTP 400"));
        assert!(!is_retryable_webhook_error("HTTP 401"));
        assert!(!is_retryable_webhook_error("HTTP 404"));
        assert!(!is_retryable_webhook_error("invalid JSON"));
    }
}
