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
    /// Webhook configuration for external notifications.
    pub webhook: Option<WebhookConfig>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suppress_duplicates: ChronoDuration::seconds(300),
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

/// Alert record stored in memory.
#[derive(Debug, Clone)]
pub struct Alert {
    id: String,
    kind: AlertKind,
    severity: AlertSeverity,
    message: String,
    worker_id: Option<String>,
    created_at: DateTime<Utc>,
}

impl Alert {
    fn new(
        kind: AlertKind,
        severity: AlertSeverity,
        message: String,
        worker_id: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind,
            severity,
            message,
            worker_id,
            created_at: Utc::now(),
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
}

struct AlertState {
    active: HashMap<AlertKey, Alert>,
    last_sent: HashMap<AlertKey, DateTime<Utc>>,
}

/// Manages active alerts and suppression logic.
pub struct AlertManager {
    config: AlertConfig,
    state: RwLock<AlertState>,
}

impl AlertManager {
    /// Create a new alert manager.
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            state: RwLock::new(AlertState {
                active: HashMap::new(),
                last_sent: HashMap::new(),
            }),
        }
    }

    /// Return the currently active alerts.
    pub fn active_alerts(&self) -> Vec<AlertInfo> {
        let mut alerts: Vec<Alert> = {
            let state = self.state.read().unwrap();
            state.active.values().cloned().collect()
        };

        alerts.sort_by(|a, b| {
            a.severity
                .rank()
                .cmp(&b.severity.rank())
                .then_with(|| b.created_at.cmp(&a.created_at))
        });

        alerts.into_iter().map(|alert| alert.to_info()).collect()
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
            WorkerStatus::Draining | WorkerStatus::Disabled => {}
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

    fn upsert_alert(&self, key: AlertKey, alert: Alert) {
        let now = alert.created_at;
        let mut state = self.state.write().unwrap();

        if let Some(last) = state.last_sent.get(&key)
            && now - *last < self.config.suppress_duplicates
        {
            debug!(
                alert_kind = alert.kind.as_str(),
                alert_id = %alert.id,
                "Alert suppressed (duplicate within window)"
            );
            state.active.entry(key).or_insert(alert);
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
        let mut state = self.state.write().unwrap();
        if let Some(alert) = state.active.remove(key) {
            debug!(
                alert_kind = alert.kind.as_str(),
                alert_id = %alert.id,
                "Alert cleared"
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

        // Spawn a blocking task for the HTTP request
        // Note: In production, this should use an async HTTP client
        let url = url.clone();
        let timeout_secs = webhook.timeout_secs;
        let _retry_count = webhook.retry_count;

        std::thread::spawn(move || {
            if let Err(e) = send_webhook_sync(&url, &payload, timeout_secs) {
                warn!(
                    url = %url,
                    error = %e,
                    "Failed to dispatch webhook"
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

/// Send webhook synchronously (blocking).
fn send_webhook_sync(url: &str, payload: &WebhookPayload, timeout_secs: u64) -> Result<(), String> {
    let body = serde_json::to_string(payload).map_err(|e| e.to_string())?;

    // Build agent with timeout configuration
    let config = ureq::config::Config::builder()
        .timeout_global(Some(std::time::Duration::from_secs(timeout_secs)))
        .build();
    let agent = ureq::Agent::new_with_config(config);

    let response = agent
        .post(url)
        .content_type("application/json")
        .header("User-Agent", "rchd-alerts/1.0")
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
        let manager = AlertManager::new(AlertConfig::default());
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
    fn test_disabled_config_no_alerts() {
        let _guard = test_guard!();
        let config = AlertConfig {
            enabled: false,
            suppress_duplicates: ChronoDuration::seconds(300),
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
        let manager = AlertManager::new(AlertConfig::default());

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
        let manager = AlertManager::new(AlertConfig::default());

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
        let manager = AlertManager::new(AlertConfig::default());

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
}
