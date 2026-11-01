//! Evidence-cleared E104 orphan quarantines (issue #62, bd-g8m4g).
//!
//! When a client-side SSH timeout cannot verify that the remote build's
//! process group died, the hook quarantines the worker: the orphan may still
//! hold the project's Cargo build-directory lock. That quarantine used to be
//! permanent — observed 2026-09-27, the fleet's two largest workers sat
//! disabled on five dispatchers for days after the orphan was long gone.
//!
//! The quarantine reason now carries the evidence needed to re-run the SAME
//! kill probe later ([`kill_probe_script`]); the daemon clears the quarantine
//! when that probe reports the identity-matched group verified dead, or when
//! the worker-side record has stayed absent past a grace period (see rchd's
//! `orphan_quarantine`). Still alive and channel failures keep it.

use crate::{WorkerConfig, WorkerId, declared_os, os_tag};
use serde::{Deserialize, Serialize};
use shell_escape::escape;
use std::borrow::Cow;

/// Stable prefix of every E104 orphan quarantine reason.
pub const E104_QUARANTINE_TAG: &str = "e104-timeout-orphan-unverified";

const EVIDENCE_MARKER: &str = " (pgid_file=";
const BOUND_EVIDENCE_MARKER: &str = " (evidence_v1=";

/// Immutable SSH coordinates of the endpoint that owned the timed-out build.
/// Capacity and descriptive tags are not endpoint identity; these fields use
/// the same identity semantics as the SSH pool and daemon admission snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineEndpoint {
    pub id: WorkerId,
    pub host: String,
    pub user: String,
    pub identity_file: String,
    pub declared_os: Option<String>,
}

impl QuarantineEndpoint {
    pub fn from_config(config: &WorkerConfig) -> Self {
        Self {
            id: config.id.clone(),
            host: config.host.clone(),
            user: config.user.clone(),
            identity_file: config.identity_file.clone(),
            declared_os: declared_os(&config.tags),
        }
    }

    pub fn matches_config(&self, config: &WorkerConfig) -> bool {
        self == &Self::from_config(config)
    }

    /// Build a transport-only configuration. This must never be inserted into
    /// scheduling inventory: it deliberately carries no capacity or tools.
    pub fn worker_config(&self) -> WorkerConfig {
        WorkerConfig {
            id: self.id.clone(),
            host: self.host.clone(),
            user: self.user.clone(),
            identity_file: self.identity_file.clone(),
            total_slots: 0,
            priority: 0,
            tags: self
                .declared_os
                .as_deref()
                .map(os_tag)
                .into_iter()
                .collect(),
            tools: Vec::new(),
        }
    }
}

/// What the daemon needs to re-probe a quarantined build's process group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineEvidence {
    pub build_id: u64,
    /// Absolute path of the worker-side `RCH_REMOTE_PROCESS_V1` record.
    pub pgid_file: String,
    /// The admitted execution endpoint. Older reasons have no coordinates;
    /// their target must be proven from durable build ownership before dialing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<QuarantineEndpoint>,
}

/// POSIX `sh` script that SIGKILLs the process group recorded in `pgid_file`
/// (only if its boot/start identity still matches) and verifies it is gone.
/// Emits exactly one `RCH_E104_KILL=<verdict>` line and always exits 0, so a
/// non-zero exit means the CHANNEL failed, not the probe. A missing record is
/// reported as `record_absent`: nothing can re-probe a group without it.
///
/// Group kill is `kill -KILL -PGID` with NO `--`: dash's kill builtin
/// mishandles `kill -KILL -- -PGID`.
pub fn kill_probe_script(pgid_file: &str, build_id: u64) -> String {
    let escaped_file = escape(Cow::from(pgid_file));
    format!(
        "f={escaped_file}\n\
         if [ ! -e \"$f\" ] && [ ! -L \"$f\" ]; then echo RCH_E104_KILL=record_absent; exit 0; fi\n\
         {identity}\n\
         if rch_remote_cancel \"$f\" {build_id} kill; then\n\
         echo RCH_E104_KILL=verified_dead\n\
         else echo RCH_E104_KILL=still_alive; fi\n",
        identity = crate::REMOTE_PROCESS_IDENTITY_SCRIPT,
    )
}

/// Whether the probe's last verdict line proves the group dead.
pub fn probe_verified_dead(stdout: &str) -> bool {
    probe_verdict(stdout) == Some("RCH_E104_KILL=verified_dead")
}

/// Whether the probe found no worker-side record for the group.
pub fn probe_record_absent(stdout: &str) -> bool {
    probe_verdict(stdout) == Some("RCH_E104_KILL=record_absent")
}

fn probe_verdict(stdout: &str) -> Option<&str> {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.starts_with("RCH_E104_KILL="))
}

/// The durable disable reason for an E104 orphan quarantine. With evidence
/// the daemon can clear it once the group is verified dead; without it
/// (Windows, mock transport, no build id) it stays until an operator enables.
pub fn quarantine_reason(evidence: Option<&QuarantineEvidence>) -> String {
    const HUMAN: &str = "remote build process group not verified dead after client timeout; \
                         possible orphan holding the project's Cargo target lock";
    match evidence {
        Some(evidence) if evidence.endpoint.is_some() => {
            // A separate version prefix keeps old daemons from interpreting
            // this as legacy evidence and choosing today's worker endpoint.
            let json = serde_json::to_string(evidence)
                .expect("quarantine evidence contains only strings and integers");
            format!(
                "{E104_QUARANTINE_TAG}[v1]: {HUMAN}; rchd clears this once the group is \
                 verified dead{BOUND_EVIDENCE_MARKER}{json})"
            )
        }
        Some(evidence) => format!(
            "{E104_QUARANTINE_TAG}[build={}]: {HUMAN}; rchd clears this once the group is \
             verified dead{EVIDENCE_MARKER}{})",
            evidence.build_id, evidence.pgid_file
        ),
        None => format!("{E104_QUARANTINE_TAG}: {HUMAN}"),
    }
}

/// Recover the evidence from a reason written by [`quarantine_reason`].
/// Legacy process evidence has no endpoint and must not authorize a probe on
/// its own. Reasons without process evidence and unrelated reasons return
/// `None`; malformed versioned reasons never fall back to legacy parsing.
pub fn parse_quarantine_reason(reason: &str) -> Option<QuarantineEvidence> {
    let rest = reason.strip_prefix(E104_QUARANTINE_TAG)?;
    if let Some(rest) = rest.strip_prefix("[v1]:") {
        let (_, json) = rest.split_once(BOUND_EVIDENCE_MARKER)?;
        let evidence: QuarantineEvidence = serde_json::from_str(json.strip_suffix(')')?).ok()?;
        let endpoint = evidence.endpoint.as_ref()?;
        return (valid_record_path(&evidence.pgid_file)
            && endpoint.matches_config(&endpoint.worker_config()))
        .then_some(evidence);
    }
    let rest = rest.strip_prefix("[build=")?;
    let (build, rest) = rest.split_once("]:")?;
    let build_id = build.parse().ok()?;
    let (_, file) = rest.rsplit_once(EVIDENCE_MARKER)?;
    let pgid_file = file.strip_suffix(')')?;
    valid_record_path(pgid_file).then(|| QuarantineEvidence {
        build_id,
        pgid_file: pgid_file.to_owned(),
        endpoint: None,
    })
}

fn valid_record_path(path: &str) -> bool {
    path.starts_with('/') && !path.contains(['\n', '\r', '\0'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn probe_reports_an_absent_record_without_touching_anything() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone/7.pgid");
        let output = std::process::Command::new("sh")
            .args(["-c", &kill_probe_script(missing.to_str().unwrap(), 7)])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(probe_record_absent(&stdout), "{stdout}");
        assert!(!probe_verified_dead(&stdout));
        assert!(!missing.parent().unwrap().exists());
        assert!(probe_verified_dead("x\nRCH_E104_KILL=verified_dead"));
        assert!(!probe_record_absent("RCH_E104_KILL=still_alive"));
    }

    #[test]
    fn reason_round_trips_evidence_including_awkward_paths() {
        let worker = WorkerConfig {
            id: WorkerId::new("worker-a"),
            host: "original.invalid".into(),
            user: "build-user".into(),
            identity_file: "/keys/one (evidence_v1=\"quoted\") key".into(),
            tags: vec!["fast".into(), "os:Linux".into()],
            ..WorkerConfig::default()
        };
        for path in [
            "/data/projects/app/.rch-run/42.pgid",
            "/data/tmp/rch/we ird (x)]: y/42.pgid",
            "/data/tmp/rch/embedded (evidence_v1=\"x\")/42.pgid",
        ] {
            for endpoint in [None, Some(QuarantineEndpoint::from_config(&worker))] {
                let evidence = QuarantineEvidence {
                    build_id: 42,
                    pgid_file: path.to_owned(),
                    endpoint,
                };
                let reason = quarantine_reason(Some(&evidence));
                assert!(reason.starts_with(E104_QUARANTINE_TAG), "{reason}");
                assert_eq!(parse_quarantine_reason(&reason), Some(evidence));
            }
        }
    }

    #[test]
    fn endpoint_identity_uses_only_admitted_ssh_coordinates() {
        let mut worker = WorkerConfig {
            tags: vec!["os:LINUX".into(), "fast".into()],
            ..WorkerConfig::default()
        };
        let endpoint = QuarantineEndpoint::from_config(&worker);
        worker.total_slots += 8;
        worker.priority += 10;
        worker.tags = vec!["os:linux".into(), "other-description".into()];
        assert!(endpoint.matches_config(&worker));
        assert!(endpoint.matches_config(&endpoint.worker_config()));
        assert_eq!(endpoint.worker_config().total_slots, 0);
        for field in 0..5 {
            let mut replacement = worker.clone();
            match field {
                0 => replacement.id = WorkerId::new("replacement"),
                1 => replacement.host = "replacement.invalid".into(),
                2 => replacement.user = "replacement".into(),
                3 => replacement.identity_file = "/keys/replacement".into(),
                4 => replacement.tags = vec!["os:windows".into()],
                _ => unreachable!(),
            }
            assert!(!endpoint.matches_config(&replacement), "field {field}");
        }
    }

    #[test]
    fn malformed_versioned_evidence_never_falls_back_to_an_unbound_probe() {
        let evidence = QuarantineEvidence {
            build_id: 42,
            pgid_file: "/tmp/rch-run/42.pgid".into(),
            endpoint: Some(QuarantineEndpoint::from_config(&WorkerConfig::default())),
        };
        let reason = quarantine_reason(Some(&evidence));
        assert!(reason.starts_with(&format!("{E104_QUARANTINE_TAG}[v1]:")));
        assert!(parse_quarantine_reason(&reason.replace("[v1]:", "[v2]:")).is_none());
        let encoded = serde_json::to_value(&evidence).unwrap();
        for field in 0..5 {
            let mut malformed = encoded.clone();
            match field {
                0 => {
                    malformed.as_object_mut().unwrap().remove("endpoint");
                }
                1 => malformed["pgid_file"] = serde_json::json!("relative/42.pgid"),
                2 => malformed["endpoint"]["declared_os"] = serde_json::json!(" WINDOWS "),
                3 => {
                    malformed["pgid_file"] =
                        serde_json::json!("/tmp/rch-run/42.pgid\n (pgid_file=/replacement)");
                }
                4 => malformed["unknown_authority"] = serde_json::json!("replacement"),
                _ => unreachable!(),
            };
            let reason = format!("{E104_QUARANTINE_TAG}[v1]: x{BOUND_EVIDENCE_MARKER}{malformed})");
            assert!(parse_quarantine_reason(&reason).is_none(), "{reason}");
        }
    }

    #[test]
    fn legacy_and_unrelated_reasons_carry_no_evidence() {
        assert_eq!(parse_quarantine_reason(&quarantine_reason(None)), None);
        assert_eq!(
            parse_quarantine_reason(
                "e104-timeout-orphan-unverified: remote build process group not verified dead"
            ),
            None
        );
        assert_eq!(parse_quarantine_reason("corrupt cargo cache"), None);
        assert_eq!(
            parse_quarantine_reason(
                "e104-timeout-orphan-unverified[build=7]: x (pgid_file=relative/7.pgid)"
            ),
            None,
            "only an absolute record path is probed"
        );
    }

    #[test]
    fn only_a_verified_dead_last_verdict_clears() {
        assert!(probe_verified_dead("noise\nRCH_E104_KILL=verified_dead\n"));
        assert!(!probe_verified_dead("RCH_E104_KILL=still_alive"));
        assert!(!probe_verified_dead(
            "RCH_E104_KILL=verified_dead\nRCH_E104_KILL=still_alive"
        ));
        assert!(!probe_verified_dead(""));
        assert!(!probe_verified_dead("garbage"));
    }

    #[test]
    fn probe_script_targets_the_recorded_build() {
        let script = kill_probe_script("/tmp/rch-run/proj-abc/42.pgid", 42);
        assert!(script.contains("/tmp/rch-run/proj-abc/42.pgid"));
        assert!(script.contains("rch_remote_cancel \"$f\" 42 kill"));
        assert!(script.contains("RCH_E104_KILL=verified_dead"));
    }
}
