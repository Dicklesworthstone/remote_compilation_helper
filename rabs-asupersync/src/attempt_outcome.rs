//! Precise attempt-outcome classification (bead G009; invariants I16/R28).
//!
//! Every completed attempt ends in exactly ONE observable process state,
//! but "what happened" and "what may be published" are different
//! questions. This module answers both with an explicit, precedence-
//! documented mapping from raw termination evidence onto the RABS
//! outcome taxonomy:
//!
//! `Succeeded` / `DeterministicFailure` / `VolatileFailure` /
//! `InfrastructureFailure` / `WorkerLost` / `LeaseExpired` /
//! `Cancelled` / `OomKilled` / `SignalTerminated` / `InternalPanic` /
//! `PolicyRefused`.
//!
//! ## The publication law (I16/R28)
//!
//! **Only [`OutcomeClass::Succeeded`] and
//! [`OutcomeClass::DeterministicFailure`] are publication-eligible**
//! ([`OutcomeClass::publication_eligible`]). A deterministic nonzero
//! exit is a property of the INPUTS: rebuild it anywhere and it fails
//! again, so caching/refusing identically is sound. Everything else —
//! signals, OOM, cancellation, timeouts, lost workers — depends on the
//! environment that ran the attempt; publishing its result would poison
//! the cache for inputs that would succeed elsewhere.
//!
//! ## Signal decoding and the OOM heuristic
//!
//! Workers encode signal deaths as exit code `128+signal` on the wire
//! (AGENTS.md semantics); [`decode_exit_code`] recovers the split. The
//! kernel's OOM killer manifests as a bare `SIGKILL`; within a managed
//! group the POLICY also sends SIGKILL — but only during cancellation,
//! which carries its own context flag. So: `SIGKILL` death without a
//! policy-delivered kill classifies as [`TerminationCause::OomKilled`]
//! (documented heuristic: inside our groups, an unsolicited SIGKILL is
//! the OOM killer or an administrator — both are non-deterministic
//! environment events, so misclassification between them has no safety
//! consequence). `SIGABRT` maps to [`TerminationCause::InternalPanic`]
//! (`abort()` is how Rust/C panic paths terminate). All other signals →
//! [`TerminationCause::Signalled`].
//!
//! ## Precedence (evaluated top to bottom, first match wins)
//!
//! 1. `PolicyRefused` — admission refused before any exec;
//! 2. `WorkerLost` — the worker itself died mid-attempt;
//! 3. `LeaseExpired` — the attempt's lease lapsed;
//! 4. deadline exceeded → `VolatileFailure` (a timeout IS a
//!    cancellation, but the taxonomy keeps the richer cause);
//! 5. policy-signalled + signal death → `Cancelled`;
//! 6. unsolicited `SIGKILL` → `OomKilled`;
//! 7. `SIGABRT` → `InternalPanic`;
//! 8. other signal → `SignalTerminated`;
//! 9. exit 0 → `Succeeded`;
//! 10. exit n ≠ 0 → `DeterministicFailure{n}`.

use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

/// Signals with dedicated taxonomy meanings.
const SIGABRT: i32 = 6;
const SIGKILL: i32 = 9;

/// The precise process-level cause of one attempt's end, BEFORE
/// taxonomy mapping. Evidence-carrying: callers supply what they know;
/// absent context defaults to the pure process view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationCause {
    /// Exited normally with code 0.
    ExitZero,
    /// Exited normally with a nonzero code (deterministic failure).
    ExitNonZero(i32),
    /// Killed by an unsolicited signal (`SIGKILL` without a policy kill
    /// reads as the kernel OOM killer; see module docs).
    Signalled(i32),
    /// The kernel OOM killer terminated the attempt.
    OomKilled,
    /// Our own teardown policy delivered the fatal signal (cancellation).
    CancelledByPolicy,
    /// A declared deadline expired before completion.
    DeadlineExceeded,
    /// The attempt's lease lapsed mid-flight.
    LeaseExpired,
    /// The worker host died or became unreachable mid-attempt.
    WorkerLost,
    /// The process aborted (`SIGABRT`) — the panic path.
    InternalPanic,
    /// Admission refused the action before it ever ran.
    PolicyRefused,
}

/// Context flags that override the bare process view, supplied by the
/// layer that owned the attempt (policy receipts, scheduler grants,
/// lease clocks). Defaults to "no overrides".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutcomeContext {
    /// The attempt was refused before execution (admission layer).
    pub policy_refused: bool,
    /// The worker died or vanished mid-attempt.
    pub worker_lost: bool,
    /// The attempt's lease expired mid-flight.
    pub lease_expired: bool,
    /// A declared deadline expired and teardown was initiated for it.
    pub deadline_exceeded: bool,
    /// OUR teardown policy delivered the fatal signal (cancellation
    /// path: `TerminationReceipt::kill_sent || term_sent` reaching the
    /// leader). Distinguishes our SIGKILL from the OOM killer's.
    pub cancelled_by_policy: bool,
}

/// The RABS outcome taxonomy — WHAT the attempt counts as, and
/// therefore whether its result may enter the CAS (I16/R28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeClass {
    /// Completed with exit 0: eligible for SUCCESS publication.
    Succeeded,
    /// Deterministic nonzero exit: same inputs fail the same way
    /// everywhere. The ONLY FAILURE class eligible for publication.
    DeterministicFailure(i32),
    /// Environment-dependent failure that may pass on a retry elsewhere
    /// (timeout is the canonical case).
    VolatileFailure,
    /// Infrastructure-level interference (reserved; reached via
    /// explicit caller context extensions).
    InfrastructureFailure,
    /// The worker died mid-attempt.
    WorkerLost,
    /// The attempt's lease lapsed.
    LeaseExpired,
    /// Deliberately torn down by policy (cancellation / escalation).
    Cancelled,
    /// Killed by the kernel OOM killer.
    OomKilled,
    /// Terminated by an unsolicited signal other than the OOM/panic
    /// specials.
    SignalTerminated(i32),
    /// Aborted via `SIGABRT` — the panic path.
    InternalPanic,
    /// Admission refused the action pre-exec.
    PolicyRefused,
}

impl OutcomeClass {
    /// Whether this outcome may be written into the CAS as an
    /// authoritative result (I16/R28): success always, failures ONLY
    /// when deterministic. Every other class describes the ENVIRONMENT
    /// that ran the attempt, not the inputs.
    #[must_use]
    pub fn publication_eligible(self) -> bool {
        matches!(
            self,
            OutcomeClass::Succeeded | OutcomeClass::DeterministicFailure(_)
        )
    }
}

/// Decode a wire exit code under AGENTS.md semantics: values ≥ 128 are
/// `128+signal` encodings of a signal death.
#[must_use]
pub fn decode_exit_code(code: i32) -> TerminationCause {
    if code >= 128 {
        map_signal(code - 128, false)
    } else if code == 0 {
        TerminationCause::ExitZero
    } else {
        TerminationCause::ExitNonZero(code)
    }
}

/// Map a raw signal number to its cause, honoring the policy-kill
/// distinction (`policy_killed`: OUR teardown delivered the signal).
#[must_use]
fn map_signal(sig: i32, policy_killed: bool) -> TerminationCause {
    if policy_killed {
        TerminationCause::CancelledByPolicy
    } else {
        match sig {
            SIGKILL => TerminationCause::OomKilled,
            SIGABRT => TerminationCause::InternalPanic,
            other => TerminationCause::Signalled(other),
        }
    }
}

/// Build a cause from a captured leader exit (the
/// [`crate::termination::LeaderExit`] shape: optional code, optional
/// signal) plus whether OUR policy killed the leader. A leader with NO
/// observable ending (never reaped) reads as [`TerminationCause::
/// WorkerLost`] — an attempt whose death nobody witnessed cannot be
/// deterministic.
#[must_use]
pub fn cause_from_exit(
    exit_code: Option<i32>,
    signal: Option<i32>,
    policy_killed: bool,
) -> TerminationCause {
    match (signal, exit_code) {
        (Some(sig), _) => map_signal(sig, policy_killed),
        (None, Some(0)) => TerminationCause::ExitZero,
        (None, Some(n)) => TerminationCause::ExitNonZero(n),
        (None, None) => TerminationCause::WorkerLost,
    }
}

/// THE classifier: cause + context → taxonomy outcome, by the
/// documented precedence.
#[must_use]
pub fn classify(cause: TerminationCause, ctx: &OutcomeContext) -> OutcomeClass {
    // Precedence 1-4: context overrides beat the process view.
    if ctx.policy_refused {
        return OutcomeClass::PolicyRefused;
    }
    if ctx.worker_lost {
        return OutcomeClass::WorkerLost;
    }
    if ctx.lease_expired {
        return OutcomeClass::LeaseExpired;
    }
    if ctx.deadline_exceeded {
        return OutcomeClass::VolatileFailure;
    }
    // Precedence 5: deliberate policy teardown.
    if matches!(cause, TerminationCause::CancelledByPolicy) {
        return OutcomeClass::Cancelled;
    }
    // Precedence 6-10: the process view.
    match cause {
        TerminationCause::OomKilled => OutcomeClass::OomKilled,
        TerminationCause::InternalPanic => OutcomeClass::InternalPanic,
        TerminationCause::Signalled(s) => OutcomeClass::SignalTerminated(s),
        TerminationCause::ExitZero => OutcomeClass::Succeeded,
        TerminationCause::ExitNonZero(n) => OutcomeClass::DeterministicFailure(n),
        // Explicit causes are honored even without their context
        // flags; only a deadline/policy-kill cause that LOST its
        // context degrades to volatile — never to anything publishable.
        TerminationCause::WorkerLost => OutcomeClass::WorkerLost,
        TerminationCause::LeaseExpired => OutcomeClass::LeaseExpired,
        TerminationCause::PolicyRefused => OutcomeClass::PolicyRefused,
        TerminationCause::DeadlineExceeded | TerminationCause::CancelledByPolicy => {
            OutcomeClass::VolatileFailure
        }
    }
}

/// Convenience: classify straight from a captured [`ExitStatus`] with
/// no cancellation context (pure process view; callers that cancelled
/// should go through [`cause_from_exit`] with the receipt's policy
/// flags instead).
#[must_use]
pub fn classify_status(status: ExitStatus, ctx: &OutcomeContext) -> OutcomeClass {
    let code = status.code();
    let sig = status.signal().or_else(|| status.stopped_signal());
    classify(cause_from_exit(code, sig, false), ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, ExitStatus};

    fn status_from(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    fn status_signalled(sig: i32) -> ExitStatus {
        ExitStatus::from_raw(sig)
    }

    #[test]
    fn g009_deterministic_nonzero_exit_is_the_only_publishable_failure() {
        let cls = classify(
            TerminationCause::ExitNonZero(101),
            &OutcomeContext::default(),
        );
        assert_eq!(cls, OutcomeClass::DeterministicFailure(101));
        assert!(cls.publication_eligible());
        assert_eq!(
            classify_status(status_from(101), &OutcomeContext::default()),
            cls
        );
    }

    #[test]
    fn g009_success_is_publication_eligible() {
        let cls = classify(TerminationCause::ExitZero, &OutcomeContext::default());
        assert_eq!(cls, OutcomeClass::Succeeded);
        assert!(cls.publication_eligible());
        assert_eq!(decode_exit_code(0), TerminationCause::ExitZero);
    }

    #[test]
    fn g009_oom_never_classifies_deterministic() {
        for cause in [TerminationCause::OomKilled, decode_exit_code(128 + SIGKILL)] {
            let cls = classify(cause, &OutcomeContext::default());
            assert!(!cls.publication_eligible(), "{cause:?} must never publish");
        }
        let cls = classify_status(status_signalled(SIGKILL), &OutcomeContext::default());
        assert_eq!(cls, OutcomeClass::OomKilled);
        assert!(!cls.publication_eligible());
    }

    #[test]
    fn g009_plain_signal_termination_never_classifies_deterministic() {
        let cls = classify_status(status_signalled(15), &OutcomeContext::default());
        assert_eq!(cls, OutcomeClass::SignalTerminated(15));
        assert!(!cls.publication_eligible());
        assert_eq!(decode_exit_code(128 + 15), TerminationCause::Signalled(15));
    }

    #[test]
    fn g009_policy_killed_reads_cancelled_not_oom() {
        // Same SIGKILL, but OUR teardown delivered it: cancellation,
        // never OOM (the heuristic hinges on the policy distinction).
        let cls = classify(map_signal(SIGKILL, true), &OutcomeContext::default());
        assert_eq!(cls, OutcomeClass::Cancelled);
        assert!(!cls.publication_eligible());
    }

    #[test]
    fn g009_sigabrt_maps_internal_panic() {
        let cls = classify_status(status_signalled(SIGABRT), &OutcomeContext::default());
        assert_eq!(cls, OutcomeClass::InternalPanic);
        assert!(!cls.publication_eligible());
    }

    #[test]
    fn g009_context_overrides_beat_process_view_in_documented_order() {
        // Refusal beats everything, even a lost worker + expired lease.
        let ctx = OutcomeContext {
            policy_refused: true,
            worker_lost: true,
            lease_expired: true,
            ..OutcomeContext::default()
        };
        assert_eq!(
            classify(TerminationCause::ExitNonZero(1), &ctx),
            OutcomeClass::PolicyRefused
        );
        let ctx = OutcomeContext {
            worker_lost: true,
            lease_expired: true,
            ..Default::default()
        };
        assert_eq!(
            classify(TerminationCause::ExitNonZero(1), &ctx),
            OutcomeClass::WorkerLost
        );
        let ctx = OutcomeContext {
            lease_expired: true,
            ..Default::default()
        };
        assert_eq!(
            classify(TerminationCause::ExitZero, &ctx),
            OutcomeClass::LeaseExpired,
            "even exit-0 is untrustworthy once the lease lapsed"
        );
        let ctx = OutcomeContext {
            deadline_exceeded: true,
            ..Default::default()
        };
        assert_eq!(
            classify(TerminationCause::ExitZero, &ctx),
            OutcomeClass::VolatileFailure,
            "timeout poisons even a zero exit"
        );
    }

    #[test]
    fn g009_unreaped_leader_reads_worker_loss_not_success() {
        // No code, no signal: we never observed the ending.
        let cls = classify(
            cause_from_exit(None, None, false),
            &OutcomeContext::default(),
        );
        assert_eq!(cls, OutcomeClass::WorkerLost);
        assert!(!cls.publication_eligible());
    }

    // ---- REAL-PROCESS FIXTURES: causes driven through actual managed
    // ---- process groups, classified from OBSERVED evidence.

    use crate::process_groups::ManagedProcessGroup;
    use crate::region_tree::Attribution;

    fn spawn_sh(script: &str) -> ManagedProcessGroup {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(script);
        ManagedProcessGroup::spawn_command(cmd, Attribution::default()).expect("managed spawn")
    }

    #[test]
    fn g009_fixture_deterministic_exit_from_real_process() {
        let mut g = spawn_sh("exit 7");
        let status = g.wait_leader().expect("wait");
        assert_eq!(
            classify_status(status, &OutcomeContext::default()),
            OutcomeClass::DeterministicFailure(7)
        );
    }

    #[test]
    fn g009_fixture_self_termination_reads_signal_not_deterministic() {
        let mut g = spawn_sh("kill -TERM $$");
        let status = g.wait_leader().expect("wait");
        let cls = classify_status(status, &OutcomeContext::default());
        assert_eq!(cls, OutcomeClass::SignalTerminated(15));
        assert!(!cls.publication_eligible());
    }

    #[test]
    fn g009_fixture_unsolicited_sigkill_reads_oom() {
        // Stand-in for the kernel OOM killer: an unsolicited SIGKILL
        // from inside. The classifier cannot tell them apart — and per
        // module docs that misclassification is consequence-free (both
        // are non-deterministic environment events).
        let mut g = spawn_sh("kill -KILL $$");
        let status = g.wait_leader().expect("wait");
        let cls = classify_status(status, &OutcomeContext::default());
        assert_eq!(cls, OutcomeClass::OomKilled);
        assert!(!cls.publication_eligible());
    }

    #[test]
    fn g009_fixture_policy_teardown_reads_cancelled() {
        use crate::termination::{TerminationPolicy, graceful_shutdown};
        let mut g = spawn_sh("sleep 30");
        // Policy tears the group down: TERM -> escalate -> KILL, with
        // bounded windows pinned short for fixture speed.
        let policy = TerminationPolicy {
            grace: std::time::Duration::from_millis(200),
            poll: std::time::Duration::from_millis(10),
            final_wait: std::time::Duration::from_millis(200),
        };
        let receipt = graceful_shutdown(&mut g, &policy);
        assert!(receipt.kill_sent || receipt.term_sent, "policy signalled");
        // Leader death evidence is signal-borne (we killed it). With
        // the policy context set, classification MUST read Cancelled —
        // even though a bare SIGTERM/SIGKILL decode would read
        // signal/OOM.
        let cause = match receipt.leader_exit {
            Some(le) => cause_from_exit(le.exit_code, le.signal, true),
            None => TerminationCause::CancelledByPolicy,
        };
        let cls = classify(
            cause,
            &OutcomeContext {
                cancelled_by_policy: true,
                ..Default::default()
            },
        );
        assert_eq!(cls, OutcomeClass::Cancelled);
        assert!(!cls.publication_eligible());
    }

    #[test]
    fn g009_fixture_policy_refusal_beats_any_exit_evidence() {
        // Admission refused: no process ever ran; the "exit" fields are
        // defaults (-1) from the non-result shape.
        let ctx = OutcomeContext {
            policy_refused: true,
            ..Default::default()
        };
        let cls = classify(decode_exit_code(-1), &ctx);
        assert_eq!(cls, OutcomeClass::PolicyRefused);
        assert!(!cls.publication_eligible());
    }
}
