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
//! only when that probe reports the identity-matched group verified dead.
//! Anything else (still alive, record missing, channel failure) keeps it.

use shell_escape::escape;
use std::borrow::Cow;

/// Stable prefix of every E104 orphan quarantine reason.
pub const E104_QUARANTINE_TAG: &str = "e104-timeout-orphan-unverified";

const EVIDENCE_MARKER: &str = " (pgid_file=";

/// What the daemon needs to re-probe a quarantined build's process group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEvidence {
    pub build_id: u64,
    /// Absolute path of the worker-side `RCH_REMOTE_PROCESS_V1` record.
    pub pgid_file: String,
}

/// POSIX `sh` script that SIGKILLs the process group recorded in `pgid_file`
/// (only if its boot/start identity still matches) and verifies it is gone.
/// Emits exactly one `RCH_E104_KILL=<verdict>` line and always exits 0, so a
/// non-zero exit means the CHANNEL failed, not the probe.
///
/// Group kill is `kill -KILL -PGID` with NO `--`: dash's kill builtin
/// mishandles `kill -KILL -- -PGID`.
pub fn kill_probe_script(pgid_file: &str, build_id: u64) -> String {
    let escaped_file = escape(Cow::from(pgid_file));
    format!(
        "f={escaped_file}\n\
         {identity}\n\
         if rch_remote_cancel \"$f\" {build_id} kill; then\n\
         echo RCH_E104_KILL=verified_dead\n\
         else echo RCH_E104_KILL=still_alive; fi\n",
        identity = crate::REMOTE_PROCESS_IDENTITY_SCRIPT,
    )
}

/// Whether the probe's last verdict line proves the group dead.
pub fn probe_verified_dead(stdout: &str) -> bool {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.starts_with("RCH_E104_KILL="))
        == Some("RCH_E104_KILL=verified_dead")
}

/// The durable disable reason for an E104 orphan quarantine. With evidence
/// the daemon can clear it once the group is verified dead; without it
/// (Windows, mock transport, no build id) it stays until an operator enables.
pub fn quarantine_reason(evidence: Option<&QuarantineEvidence>) -> String {
    const HUMAN: &str = "remote build process group not verified dead after client timeout; \
                         possible orphan holding the project's Cargo target lock";
    match evidence {
        Some(evidence) => format!(
            "{E104_QUARANTINE_TAG}[build={}]: {HUMAN}; rchd clears this once the group is \
             verified dead{EVIDENCE_MARKER}{})",
            evidence.build_id, evidence.pgid_file
        ),
        None => format!("{E104_QUARANTINE_TAG}: {HUMAN}"),
    }
}

/// Recover the evidence from a reason written by [`quarantine_reason`].
/// Legacy reasons (no evidence) and unrelated reasons return `None`.
pub fn parse_quarantine_reason(reason: &str) -> Option<QuarantineEvidence> {
    let rest = reason
        .strip_prefix(E104_QUARANTINE_TAG)?
        .strip_prefix("[build=")?;
    let (build, rest) = rest.split_once("]:")?;
    let build_id = build.parse().ok()?;
    let (_, file) = rest.rsplit_once(EVIDENCE_MARKER)?;
    let pgid_file = file.strip_suffix(')')?;
    (pgid_file.starts_with('/') && !pgid_file.contains('\n')).then(|| QuarantineEvidence {
        build_id,
        pgid_file: pgid_file.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_round_trips_evidence_including_awkward_paths() {
        for path in [
            "/data/projects/app/.rch-run/42.pgid",
            "/data/tmp/rch/we ird (x)]: y/42.pgid",
        ] {
            let evidence = QuarantineEvidence {
                build_id: 42,
                pgid_file: path.to_owned(),
            };
            let reason = quarantine_reason(Some(&evidence));
            assert!(reason.starts_with(E104_QUARANTINE_TAG), "{reason}");
            assert_eq!(parse_quarantine_reason(&reason), Some(evidence));
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
