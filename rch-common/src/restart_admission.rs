//! Fenced maintenance admission protocol shared by the daemon and CLI.

use crate::process_identity::ProcessIdentity;
use serde::{Deserialize, Deserializer, Serialize};

// Serde normally treats a missing Option field as None. Proof of an open,
// inspected admission state requires an explicit null from the daemon instead
// of silently accepting an incomplete or older protocol response.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// One maintenance operation. The token is a client-generated UUID, bound by
/// the daemon to the authenticated socket peer and this daemon incarnation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaintenanceOwner {
    pub token: String,
    pub pid: u32,
    pub process_identity: ProcessIdentity,
    pub purpose: String,
    pub generation: u64,
    pub acquired_unix_ms: u64,
    /// Informational wall-clock deadline; expiry is enforced with a monotonic clock.
    pub deadline_unix_ms: u64,
    pub remaining_ms: u64,
    /// `live`, `absent`, or `unknown`; uncertainty never proves death.
    pub owner_presence: String,
}

/// Most recent automatic or explicit recovery of an abandoned operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaintenanceRecovery {
    pub token: String,
    pub pid: u32,
    pub reason: String,
    pub recovered_unix_ms: u64,
}

/// Verifiable admission snapshot returned by maintenance operations and status.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RestartAdmissionResponse {
    pub success: bool,
    pub status: String,
    pub message: Option<String>,
    pub daemon_incarnation: String,
    /// Effective state, including a durable ownership fault and committed shutdown.
    pub admission_closed: bool,
    pub maintenance_closed: bool,
    pub ownership_failed: bool,
    pub ownership_error: Option<String>,
    pub shutdown_committed: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub maintenance_owner: Option<MaintenanceOwner>,
    pub last_recovery: Option<MaintenanceRecovery>,
    pub restart_permitted: bool,
    pub active_build_ids: Vec<u64>,
    pub queued_build_ids: Vec<u64>,
    pub client_lease_ids: Vec<String>,
    /// Any failure to inspect durable leases prevents proof of quiescence.
    #[serde(deserialize_with = "required_nullable")]
    pub client_lease_scan_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::RestartAdmissionResponse;

    #[test]
    fn admission_snapshot_requires_explicit_owner_and_scan_state() {
        let complete = serde_json::to_value(RestartAdmissionResponse::default()).unwrap();
        assert!(complete["maintenance_owner"].is_null());
        assert!(complete["client_lease_scan_error"].is_null());
        assert!(serde_json::from_value::<RestartAdmissionResponse>(complete.clone()).is_ok());

        for field in ["maintenance_owner", "client_lease_scan_error"] {
            let mut incomplete = complete.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            let error = serde_json::from_value::<RestartAdmissionResponse>(incomplete).unwrap_err();
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn admission_snapshot_preserves_explicit_scan_uncertainty() {
        let response = RestartAdmissionResponse {
            client_lease_scan_error: Some("lease scan timed out".into()),
            ..RestartAdmissionResponse::default()
        };
        let restored: RestartAdmissionResponse =
            serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
        assert_eq!(
            restored.client_lease_scan_error,
            response.client_lease_scan_error
        );
    }
}
