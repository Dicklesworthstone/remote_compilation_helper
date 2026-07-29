//! Transfer hardening against volatile files and retryable transport failures
//! (bd-session-history-remediation-ocv9i.8.2).
//!
//! rsync/SSH transfers race against a live working tree: `.git/index.lock`
//! appears and vanishes, build artifacts are rewritten mid-flight, and the
//! network blips. Treating every nonzero rsync exit as corruption causes
//! spurious build failures. This module classifies a transfer outcome
//! ([`classify_rsync_outcome`]) — separating a *vanished source file* (rsync
//! exit 24) and *retryable transport* errors from genuine corruption / disk /
//! permission faults — and yields a bounded [`RetryDecision`]. It also knows
//! which paths are *ephemeral* ([`is_ephemeral_path`]) and should be excluded
//! up front. Pure + deterministic.

use serde::{Deserialize, Serialize};

use crate::incident::IncidentReasonCode;
use crate::ssh_utils::is_retryable_transport_error_text;

/// Default bounded retry attempts for a hardenable transfer failure.
pub const DEFAULT_MAX_TRANSFER_ATTEMPTS: u32 = 3;
/// rsync exit code: partial transfer because source files vanished.
pub const RSYNC_EXIT_VANISHED: i32 = 24;
/// rsync exit code: partial transfer due to a real error.
pub const RSYNC_EXIT_PARTIAL_ERROR: i32 = 23;

/// Classification of a single rsync/transfer outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsyncFailureClass {
    /// Transfer succeeded.
    Success,
    /// A source file vanished mid-transfer (exit 24 / "vanished") — benign;
    /// retry/ignore.
    VanishedFile,
    /// A bounded, retryable SSH/network transport error.
    RetryableTransport,
    /// The destination disk is full.
    DiskFull,
    /// A permission error on source or destination.
    PermissionDenied,
    /// A partial transfer due to a real (non-vanished) error.
    PartialCorruption,
    /// A non-retryable, fatal error.
    Fatal,
}

impl RsyncFailureClass {
    /// Is this a success?
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    /// The incident reason this class maps to, if any.
    #[must_use]
    pub const fn incident_reason(self) -> Option<IncidentReasonCode> {
        match self {
            Self::VanishedFile => Some(IncidentReasonCode::RsyncVanishedFile),
            Self::DiskFull => Some(IncidentReasonCode::DiskFull),
            _ => None,
        }
    }

    /// Bounded retry decision for this class on `attempt` (1-based) of
    /// `max_attempts`.
    #[must_use]
    pub fn retry_decision(self, attempt: u32, max_attempts: u32) -> RetryDecision {
        let exhausted = attempt >= max_attempts;
        match self {
            Self::Success => RetryDecision::done("transfer succeeded"),
            // Vanished files are benign: re-run (excluding the vanished path) up
            // to the cap; treat exhaustion as ignorable, not a hard failure.
            Self::VanishedFile if !exhausted => {
                RetryDecision::retry(0, "source file vanished; retrying (ignoring vanished path)")
            }
            Self::VanishedFile => RetryDecision {
                should_retry: false,
                backoff_ms: 0,
                ignorable: true,
                reason: "vanished files persisted across retries; ignoring (benign)",
            },
            Self::RetryableTransport if !exhausted => RetryDecision::retry(
                backoff_ms(attempt),
                "retryable transport error; retrying with backoff",
            ),
            Self::PartialCorruption if !exhausted => {
                RetryDecision::retry(backoff_ms(attempt), "partial transfer; retrying")
            }
            // Non-retryable or exhausted.
            Self::DiskFull => RetryDecision::fatal("destination disk full"),
            Self::PermissionDenied => RetryDecision::fatal("permission denied"),
            Self::Fatal => RetryDecision::fatal("fatal transfer error"),
            _ => RetryDecision::fatal("retry attempts exhausted"),
        }
    }
}

/// Exponential backoff (250ms base, doubling), capped.
fn backoff_ms(attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(5);
    250u64.saturating_mul(1u64 << shift)
}

/// What to do after a classified transfer failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryDecision {
    pub should_retry: bool,
    pub backoff_ms: u64,
    /// True when the failure is benign and may be ignored if retries run out
    /// (e.g. vanished files).
    pub ignorable: bool,
    pub reason: &'static str,
}

impl RetryDecision {
    const fn retry(backoff_ms: u64, reason: &'static str) -> Self {
        Self {
            should_retry: true,
            backoff_ms,
            ignorable: false,
            reason,
        }
    }
    const fn done(reason: &'static str) -> Self {
        Self {
            should_retry: false,
            backoff_ms: 0,
            ignorable: true,
            reason,
        }
    }
    const fn fatal(reason: &'static str) -> Self {
        Self {
            should_retry: false,
            backoff_ms: 0,
            ignorable: false,
            reason,
        }
    }
}

/// Classify a transfer outcome from rsync's exit code and stderr. Order matters:
/// vanished is detected before generic partial-error so a benign race is not
/// mistaken for corruption.
#[must_use]
pub fn classify_rsync_outcome(exit_code: i32, stderr: &str) -> RsyncFailureClass {
    if exit_code == 0 {
        return RsyncFailureClass::Success;
    }
    let lower = stderr.to_ascii_lowercase();
    if exit_code == RSYNC_EXIT_VANISHED || lower.contains("vanished") {
        return RsyncFailureClass::VanishedFile;
    }
    if lower.contains("no space left") || lower.contains("disk quota exceeded") {
        return RsyncFailureClass::DiskFull;
    }
    if lower.contains("permission denied") {
        return RsyncFailureClass::PermissionDenied;
    }
    if is_retryable_transport_error_text(stderr) {
        return RsyncFailureClass::RetryableTransport;
    }
    if exit_code == RSYNC_EXIT_PARTIAL_ERROR {
        return RsyncFailureClass::PartialCorruption;
    }
    RsyncFailureClass::Fatal
}

/// Whether a path is an ephemeral / volatile store that should be excluded from
/// transfer and convergence (it appears and vanishes during normal operation,
/// so syncing it is pointless and race-prone).
#[must_use]
pub fn is_ephemeral_path(path: &str) -> bool {
    const EPHEMERAL_SUFFIXES: &[&str] = &[
        "/.git/index.lock",
        "/.git/HEAD.lock",
        "/.git/config.lock",
        "/.git/packed-refs.lock",
        "/.cargo-lock",
        "/.rch.lock",
    ];
    const EPHEMERAL_SUBSTRINGS: &[&str] = &[
        "/.git/objects/tmp_", // packing temp objects
        "/.git/refs/",        // ref lock churn
        "/incremental/",      // cargo incremental cruft
    ];
    let p = path.trim_end_matches('/');
    if EPHEMERAL_SUFFIXES.iter().any(|s| p.ends_with(s)) {
        return true;
    }
    // A `.lock` directly under any `.git` dir.
    if p.ends_with(".lock") && p.contains("/.git/") {
        return true;
    }
    EPHEMERAL_SUBSTRINGS.iter().any(|s| p.contains(s))
}

/// Accumulates the FIRST concrete failing path/command across a multi-attempt
/// transfer, so selection/doctor output can name the original cause rather than
/// the last (possibly less informative) retry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstFailure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl FirstFailure {
    /// Record a failure, keeping only the first one seen.
    pub fn record(&mut self, path: Option<&str>, command: Option<&str>, detail: &str) {
        if self.detail.is_none() {
            self.path = path.map(str::to_string);
            self.command = command.map(str::to_string);
            self.detail = Some(detail.to_string());
        }
    }

    #[must_use]
    pub fn is_set(&self) -> bool {
        self.detail.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vanished_file_classified_from_exit_24() {
        assert_eq!(
            classify_rsync_outcome(24, ""),
            RsyncFailureClass::VanishedFile
        );
    }

    #[test]
    fn vanished_file_classified_from_stderr() {
        let class = classify_rsync_outcome(23, "file has vanished: \"/proj/.git/index.lock\"");
        assert_eq!(class, RsyncFailureClass::VanishedFile);
        assert_eq!(
            class.incident_reason(),
            Some(IncidentReasonCode::RsyncVanishedFile)
        );
    }

    #[test]
    fn success_disk_permission_and_fatal() {
        assert_eq!(classify_rsync_outcome(0, ""), RsyncFailureClass::Success);
        assert_eq!(
            classify_rsync_outcome(11, "rsync: write failed: No space left on device (28)"),
            RsyncFailureClass::DiskFull
        );
        assert_eq!(
            classify_rsync_outcome(23, "rsync: mkdir failed: Permission denied (13)"),
            RsyncFailureClass::PermissionDenied
        );
        assert_eq!(
            classify_rsync_outcome(23, "some unrecognized partial error"),
            RsyncFailureClass::PartialCorruption
        );
        assert_eq!(
            classify_rsync_outcome(99, "totally unknown"),
            RsyncFailureClass::Fatal
        );
    }

    #[test]
    fn retryable_transport_detected() {
        // Reuses the shared transport-error classifier.
        let class = classify_rsync_outcome(255, "ssh: connect to host: Connection timed out");
        assert_eq!(class, RsyncFailureClass::RetryableTransport);
    }

    #[test]
    fn vanished_file_retries_then_becomes_ignorable() {
        let v = RsyncFailureClass::VanishedFile;
        let d1 = v.retry_decision(1, 3);
        assert!(d1.should_retry);
        assert_eq!(d1.backoff_ms, 0); // vanished retries immediately
        // Exhausted: not a hard failure — ignorable (benign).
        let d3 = v.retry_decision(3, 3);
        assert!(!d3.should_retry);
        assert!(d3.ignorable);
    }

    #[test]
    fn retryable_transport_backs_off_then_stops() {
        let t = RsyncFailureClass::RetryableTransport;
        let d1 = t.retry_decision(1, 3);
        assert!(d1.should_retry && d1.backoff_ms == 250);
        let d2 = t.retry_decision(2, 3);
        assert!(d2.should_retry && d2.backoff_ms == 500);
        let d3 = t.retry_decision(3, 3);
        assert!(!d3.should_retry && !d3.ignorable);
    }

    #[test]
    fn fatal_classes_never_retry() {
        assert!(
            !RsyncFailureClass::DiskFull
                .retry_decision(1, 3)
                .should_retry
        );
        assert!(
            !RsyncFailureClass::PermissionDenied
                .retry_decision(1, 3)
                .should_retry
        );
        assert!(!RsyncFailureClass::Fatal.retry_decision(1, 3).should_retry);
    }

    #[test]
    fn ephemeral_paths_detected() {
        assert!(is_ephemeral_path("/proj/.git/index.lock"));
        assert!(is_ephemeral_path("/proj/.git/refs/heads/main.lock"));
        assert!(is_ephemeral_path("/proj/target/debug/incremental/foo"));
        assert!(is_ephemeral_path("/proj/.git/objects/tmp_abc"));
        // Real source files are not ephemeral.
        assert!(!is_ephemeral_path("/proj/src/lib.rs"));
        assert!(!is_ephemeral_path("/proj/Cargo.toml"));
        assert!(!is_ephemeral_path("/proj/.gitignore"));
    }

    #[test]
    fn first_failure_keeps_the_first() {
        let mut f = FirstFailure::default();
        assert!(!f.is_set());
        f.record(Some("/a"), Some("rsync ..."), "first error");
        f.record(Some("/b"), Some("retry ..."), "second error");
        assert!(f.is_set());
        assert_eq!(f.path.as_deref(), Some("/a"));
        assert_eq!(f.detail.as_deref(), Some("first error"));
    }

    #[test]
    fn serde_roundtrips() {
        let class = RsyncFailureClass::VanishedFile;
        let v = serde_json::to_value(class).unwrap();
        assert_eq!(v, "vanished_file");
        let mut f = FirstFailure::default();
        f.record(Some("/a"), None, "boom");
        let back: FirstFailure = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(f, back);
    }
}
