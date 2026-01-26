//! Worker health alerting.
//!
//! Tracks alert-worthy events and exposes active alerts for status reporting.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::WorkerStatus;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

/// Alert configuration.
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Enable or disable alert generation.
    pub enabled: bool,
    /// Suppress duplicate alerts for this duration.
    pub suppress_duplicates: ChronoDuration,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suppress_duplicates: ChronoDuration::seconds(300),
        }
    }
}

/// Severity for an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
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

        if let Some(last) = state.last_sent.get(&key) {
            if now - *last < self.config.suppress_duplicates {
                state.active.entry(key).or_insert(alert);
                return;
            }
        }

        state.active.insert(key.clone(), alert);
        state.last_sent.insert(key, now);
    }

    fn clear_alert(&self, key: &AlertKey) {
        let mut state = self.state.write().unwrap();
        state.active.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_suppression() {
        let config = AlertConfig {
            enabled: true,
            suppress_duplicates: ChronoDuration::seconds(300),
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
}
