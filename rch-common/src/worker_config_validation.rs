//! `workers.toml` vs SSH-config / live-fact validation
//! (bd-session-history-remediation-ocv9i.12.4).
//!
//! A worker entry in `workers.toml` drifts from reality in many quiet ways: the
//! SSH config resolves a different user or host alias, the identity file moved,
//! the configured build root or slot count no longer matches the host, the
//! `rch-wkr` binary isn't where it should be, or the host is a different
//! platform than assumed. [`validate_worker_config`] compares one configured
//! [`WorkerConfig`] against a [`LiveHostObservation`] (SSH facts + the 12.1/12.2
//! probed [`WorkerFacts`]) and reports each drift with a **safe, non-mutating**
//! remediation step. It never changes config; applying a fix is the caller's
//! explicit, separate action.

use serde::{Deserialize, Serialize};

use crate::types::WorkerConfig;
use crate::worker_facts::WorkerFacts;

/// A class of `workers.toml` drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDriftKind {
    /// Configured user differs from the SSH-resolved / live user.
    UserDrift,
    /// Configured host differs from the SSH-resolved canonical host.
    HostAliasDrift,
    /// The configured identity file does not exist.
    IdentityFileMissing,
    /// The configured build root is not among the worker's live build roots.
    PathMismatch,
    /// Configured slot count differs from the host's detected capacity.
    SlotMismatch,
    /// The `rch-wkr` binary did not report at its configured path.
    MissingWorkerBinaryPath,
    /// The worker's live platform differs from the expected target triple.
    PlatformMismatch,
}

impl ConfigDriftKind {
    /// Stable snake_case id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDrift => "user_drift",
            Self::HostAliasDrift => "host_alias_drift",
            Self::IdentityFileMissing => "identity_file_missing",
            Self::PathMismatch => "path_mismatch",
            Self::SlotMismatch => "slot_mismatch",
            Self::MissingWorkerBinaryPath => "missing_worker_binary_path",
            Self::PlatformMismatch => "platform_mismatch",
        }
    }
}

/// One drift finding with a safe remediation hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDriftFinding {
    pub kind: ConfigDriftKind,
    pub worker_id: String,
    pub detail: String,
    /// A safe, non-mutating remediation step the operator can take.
    pub remediation: String,
}

/// Live observation of a host to validate a config entry against. All fields
/// optional/best-effort — an absent observation simply skips that check.
#[derive(Debug, Clone, Default)]
pub struct LiveHostObservation {
    /// User the SSH config resolves to / the probe ran as.
    pub ssh_user: Option<String>,
    /// Canonical host the SSH config resolves to (for alias-drift detection).
    pub resolved_host: Option<String>,
    /// Whether the configured identity file exists.
    pub identity_file_exists: Option<bool>,
    /// Live probed facts (12.1/12.2).
    pub facts: Option<WorkerFacts>,
    /// Detected build-slot capacity (e.g. CPU cores).
    pub detected_slots: Option<u32>,
    /// The remote build root the controller expects this worker to offload into.
    pub expected_build_root: Option<String>,
    /// The target triple the controller will deploy artifacts for.
    pub expected_target_triple: Option<String>,
}

/// Validate one configured worker against a live observation. Returns every
/// drift finding (empty = clean). Never mutates anything.
#[must_use]
pub fn validate_worker_config(
    entry: &WorkerConfig,
    obs: &LiveHostObservation,
) -> Vec<ConfigDriftFinding> {
    let id = entry.id.as_str().to_string();
    let mut findings = Vec::new();
    let mut push = |kind: ConfigDriftKind, detail: String, remediation: String| {
        findings.push(ConfigDriftFinding {
            kind,
            worker_id: id.clone(),
            detail,
            remediation,
        });
    };

    if let Some(ssh_user) = &obs.ssh_user
        && *ssh_user != entry.user
    {
        push(
            ConfigDriftKind::UserDrift,
            format!(
                "workers.toml user '{}' != resolved '{ssh_user}'",
                entry.user
            ),
            format!("set this worker's user to '{ssh_user}' or fix the SSH config"),
        );
    }

    if let Some(resolved) = &obs.resolved_host
        && *resolved != entry.host
    {
        push(
            ConfigDriftKind::HostAliasDrift,
            format!(
                "workers.toml host '{}' resolves to '{resolved}'",
                entry.host
            ),
            format!("point this worker at '{resolved}' or align the SSH host alias"),
        );
    }

    if obs.identity_file_exists == Some(false) {
        push(
            ConfigDriftKind::IdentityFileMissing,
            format!("identity file '{}' does not exist", entry.identity_file),
            "restore the key or update identity_file to its real path".to_string(),
        );
    }

    if let Some(detected) = obs.detected_slots
        && detected != entry.total_slots
    {
        push(
            ConfigDriftKind::SlotMismatch,
            format!(
                "configured slots {} != detected capacity {detected}",
                entry.total_slots
            ),
            format!("set total_slots to {detected} (the host's detected capacity)"),
        );
    }

    if let Some(expected_root) = &obs.expected_build_root
        && let Some(facts) = &obs.facts
        && !facts.user.build_roots.iter().any(|r| r == expected_root)
    {
        push(
            ConfigDriftKind::PathMismatch,
            format!(
                "expected build root '{expected_root}' not among live roots {:?}",
                facts.user.build_roots
            ),
            "create the build root on the worker or update the configured path".to_string(),
        );
    }

    if let Some(facts) = &obs.facts {
        // An empty version / path means the binary at the configured path did
        // not report (missing or unusable as the configured user).
        if facts.worker.version.is_empty() || facts.worker.rch_wkr_path.is_empty() {
            push(
                ConfigDriftKind::MissingWorkerBinaryPath,
                "rch-wkr did not report a version at its configured path".to_string(),
                "redeploy rch-wkr to the configured path (rch update --fleet)".to_string(),
            );
        }
        if let Some(expected_triple) = &obs.expected_target_triple
            && *expected_triple != facts.host.target_triple
        {
            push(
                ConfigDriftKind::PlatformMismatch,
                format!(
                    "expected target triple '{expected_triple}' != live '{}'",
                    facts.host.target_triple
                ),
                "deploy the artifact matching the worker's platform; do not reuse the controller's"
                    .to_string(),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WorkerConfig, WorkerId};
    use crate::worker_facts::{HostFacts, UserFacts, WorkerBinaryFacts};

    fn entry() -> WorkerConfig {
        WorkerConfig {
            id: WorkerId("css".to_string()),
            host: "css".to_string(),
            user: "rch".to_string(),
            identity_file: "/home/rch/.ssh/id_ed25519".to_string(),
            total_slots: 8,
            ..WorkerConfig::default()
        }
    }

    fn facts() -> WorkerFacts {
        WorkerFacts::new(
            "css",
            1_700_000_000_000,
            HostFacts {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                libc: Some("gnu".to_string()),
                shell: None,
                target_triple: "x86_64-unknown-linux-gnu".to_string(),
                artifact_platforms: vec![],
            },
            UserFacts {
                remote_user: "rch".to_string(),
                home: "/home/rch".to_string(),
                temp_root: "/data/tmp".to_string(),
                build_roots: vec!["/data/tmp/rch-targets".to_string()],
            },
            WorkerBinaryFacts {
                rch_wkr_path: "/home/rch/.local/bin/rch-wkr".to_string(),
                version: "1.0.41".to_string(),
                protocol_version: 3,
            },
        )
    }

    #[test]
    fn clean_config_has_no_findings() {
        let obs = LiveHostObservation {
            ssh_user: Some("rch".to_string()),
            resolved_host: Some("css".to_string()),
            identity_file_exists: Some(true),
            facts: Some(facts()),
            detected_slots: Some(8),
            expected_build_root: Some("/data/tmp/rch-targets".to_string()),
            expected_target_triple: Some("x86_64-unknown-linux-gnu".to_string()),
        };
        assert!(validate_worker_config(&entry(), &obs).is_empty());
    }

    fn kinds(findings: &[ConfigDriftFinding]) -> Vec<ConfigDriftKind> {
        findings.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn user_drift_detected() {
        let obs = LiveHostObservation {
            ssh_user: Some("ubuntu".to_string()),
            ..LiveHostObservation::default()
        };
        let f = validate_worker_config(&entry(), &obs);
        assert_eq!(kinds(&f), vec![ConfigDriftKind::UserDrift]);
        assert!(f[0].detail.contains("ubuntu"));
        assert!(f[0].remediation.contains("ubuntu"));
        assert_eq!(f[0].worker_id, "css");
    }

    #[test]
    fn host_alias_drift_detected() {
        let obs = LiveHostObservation {
            resolved_host: Some("css.contabo.net".to_string()),
            ..LiveHostObservation::default()
        };
        assert_eq!(
            kinds(&validate_worker_config(&entry(), &obs)),
            vec![ConfigDriftKind::HostAliasDrift]
        );
    }

    #[test]
    fn identity_file_missing_detected() {
        let obs = LiveHostObservation {
            identity_file_exists: Some(false),
            ..LiveHostObservation::default()
        };
        assert_eq!(
            kinds(&validate_worker_config(&entry(), &obs)),
            vec![ConfigDriftKind::IdentityFileMissing]
        );
    }

    #[test]
    fn slot_mismatch_detected_and_suggests_detected() {
        let obs = LiveHostObservation {
            detected_slots: Some(16),
            ..LiveHostObservation::default()
        };
        let f = validate_worker_config(&entry(), &obs);
        assert_eq!(kinds(&f), vec![ConfigDriftKind::SlotMismatch]);
        assert!(f[0].remediation.contains("16"));
    }

    #[test]
    fn path_mismatch_detected() {
        let mut fx = facts();
        fx.user.build_roots = vec!["/tmp/other".to_string()];
        let obs = LiveHostObservation {
            facts: Some(fx),
            expected_build_root: Some("/data/tmp/rch-targets".to_string()),
            ..LiveHostObservation::default()
        };
        assert_eq!(
            kinds(&validate_worker_config(&entry(), &obs)),
            vec![ConfigDriftKind::PathMismatch]
        );
    }

    #[test]
    fn missing_worker_binary_detected() {
        let mut fx = facts();
        fx.worker.version = String::new(); // binary didn't report a version
        let obs = LiveHostObservation {
            facts: Some(fx),
            ..LiveHostObservation::default()
        };
        assert_eq!(
            kinds(&validate_worker_config(&entry(), &obs)),
            vec![ConfigDriftKind::MissingWorkerBinaryPath]
        );
    }

    #[test]
    fn platform_mismatch_detected() {
        let obs = LiveHostObservation {
            facts: Some(facts()),
            expected_target_triple: Some("aarch64-apple-darwin".to_string()),
            ..LiveHostObservation::default()
        };
        let f = validate_worker_config(&entry(), &obs);
        assert_eq!(kinds(&f), vec![ConfigDriftKind::PlatformMismatch]);
        assert!(f[0].remediation.contains("do not reuse the controller"));
    }

    #[test]
    fn multiple_drifts_reported_together() {
        let obs = LiveHostObservation {
            ssh_user: Some("ubuntu".to_string()),
            identity_file_exists: Some(false),
            detected_slots: Some(4),
            ..LiveHostObservation::default()
        };
        let f = validate_worker_config(&entry(), &obs);
        assert_eq!(f.len(), 3);
        assert!(kinds(&f).contains(&ConfigDriftKind::UserDrift));
        assert!(kinds(&f).contains(&ConfigDriftKind::SlotMismatch));
    }

    #[test]
    fn findings_serialize_with_stable_fields() {
        let obs = LiveHostObservation {
            ssh_user: Some("ubuntu".to_string()),
            ..LiveHostObservation::default()
        };
        let f = &validate_worker_config(&entry(), &obs)[0];
        let v = serde_json::to_value(f).unwrap();
        assert_eq!(v["kind"], "user_drift");
        assert_eq!(v["worker_id"], "css");
        assert!(v.get("detail").is_some() && v.get("remediation").is_some());
        let back: ConfigDriftFinding = serde_json::from_value(v).unwrap();
        assert_eq!(*f, back);
    }
}
