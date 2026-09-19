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
//! Only [`OutcomeClass::Succeeded`] and valid nonzero
//! [`OutcomeClass::DeterministicFailure`] outcomes are publication
//! CANDIDATES ([`OutcomeClass::publication_eligible`]). A normal exit
//! alone does not prove determinism: closed inputs, complete capture,
//! and class/trust policy must still admit the result. Signals, OOM,
//! cancellation, timeouts, lost workers and malformed status evidence
//! never pass even this preliminary process-outcome gate.
//!
//! ## Signal decoding and the OOM heuristic
//!
//! Workers encode signal deaths as exit code `128+signal` on the wire
//! (AGENTS.md semantics); [`decode_exit_code`] recovers the split. Native
//! [`ExitStatus`] is different: an actual normal `exit(137)` is not a
//! SIGKILL receipt. Native and wire statuses are deliberately decoded by
//! different entry points rather than discarding native signal evidence.
//!
//! The kernel's OOM killer manifests as a bare `SIGKILL`; within a managed
//! group the POLICY also sends SIGKILL during cancellation. An unsolicited
//! SIGKILL maps to [`TerminationCause::OomKilled`] (an administrator kill
//! is indistinguishable here, but also non-publishable). `SIGABRT` maps to
//! [`TerminationCause::InternalPanic`]. Other signals map to
//! [`TerminationCause::Signalled`].
//!
//! ## Precedence (evaluated top to bottom, first match wins)
//!
//! 1. `PolicyRefused` — admission refused before any exec;
//! 2. `WorkerLost` — the worker itself died mid-attempt;
//! 3. `LeaseExpired` — the attempt's lease lapsed;
//! 4. deadline exceeded → `VolatileFailure`;
//! 5. policy cancellation → `Cancelled`, INCLUDING a process that
//!    traps TERM and exits zero or otherwise exits normally;
//! 6. unsolicited `SIGKILL` → `OomKilled`;
//! 7. `SIGABRT` → `InternalPanic`;
//! 8. other signal → `SignalTerminated`;
//! 9. exit 0 → `Succeeded`;
//! 10. normal exit 1..=255 → `DeterministicFailure{n}`;
//! 11. invalid status evidence → `InfrastructureFailure`.

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
    /// Exited normally with a nonzero code; other publication gates
    /// must still establish determinism.
    ExitNonZero(i32),
    /// Killed by an unsolicited signal (`SIGKILL` without a policy kill
    /// reads as the kernel OOM killer; see module docs).
    Signalled(i32),
    /// The kernel OOM killer terminated the attempt.
    OomKilled,
    /// Our own teardown policy cancelled the attempt, even when the
    /// process handled its signal and subsequently exited normally.
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
    /// A supplied exit code or signal is outside its representation's
    /// valid range. Preserve the raw value, but never invent an exit.
    InvalidStatus(i32),
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
    /// OUR teardown policy cancelled this attempt. A caught TERM followed
    /// by exit zero does not erase this receipt. Set from the attempt's
    /// cancellation frontier, not from a later unrelated process signal.
    pub cancelled_by_policy: bool,
}

/// The RABS outcome taxonomy — WHAT the attempt counts as, and
/// whether it may be considered for publication (I16/R28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeClass {
    /// Completed with exit 0: candidate for SUCCESS publication.
    Succeeded,
    /// Normal nonzero exit: the only failure candidate for publication.
    /// Determinism still requires the action's input/capture/policy gates.
    DeterministicFailure(i32),
    /// Environment-dependent failure that may pass on a retry elsewhere
    /// (timeout is the canonical case).
    VolatileFailure,
    /// Infrastructure-level interference or invalid termination evidence.
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
    /// Preliminary process-outcome gate, NOT authorization to commit.
    /// Other publication gates must establish closed inputs, complete
    /// observations and admitted trust. Validate even directly constructed
    /// failure variants so malformed values cannot bypass classification.
    #[must_use]
    pub fn publication_eligible(self) -> bool {
        matches!(
            self,
            OutcomeClass::Succeeded | OutcomeClass::DeterministicFailure(1..=255)
        )
    }
}

/// Decode a wire exit code under AGENTS.md semantics. `129..=255`
/// represents `128+signal`; 128 itself encodes no signal. Negative
/// sentinel values and values above one byte are invalid evidence.
/// Use [`cause_from_exit`] or [`classify_status`] for native wait results.
#[must_use]
pub fn decode_exit_code(code: i32) -> TerminationCause {
    match code {
        0 => TerminationCause::ExitZero,
        1..=127 => TerminationCause::ExitNonZero(code),
        129..=255 => map_signal(code - 128, false),
        _ => TerminationCause::InvalidStatus(code),
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
            1..=127 => TerminationCause::Signalled(sig),
            _ => TerminationCause::InvalidStatus(sig),
        }
    }
}

/// Build a cause from a captured leader exit (the
/// [`crate::termination::LeaderExit`] shape: optional code, optional
/// signal) plus whether OUR policy cancelled the leader. Cancellation
/// is retained even after a signal handler exits zero. Without an
/// observable ending or cancellation receipt, the attempt is worker-lost,
/// never deterministic. Native normal high exit codes are not wire signals.
#[must_use]
pub fn cause_from_exit(
    exit_code: Option<i32>,
    signal: Option<i32>,
    policy_killed: bool,
) -> TerminationCause {
    if policy_killed {
        return TerminationCause::CancelledByPolicy;
    }
    match (signal, exit_code) {
        (Some(sig), _) => map_signal(sig, false),
        (None, Some(0)) => TerminationCause::ExitZero,
        (None, Some(n @ 1..=255)) => TerminationCause::ExitNonZero(n),
        (None, Some(n)) => TerminationCause::InvalidStatus(n),
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
    // A cancellation receipt cannot be erased by an exit code, including
    // zero from a caught TERM, or by decoding SIGKILL without its context.
    if ctx.cancelled_by_policy || matches!(cause, TerminationCause::CancelledByPolicy) {
        return OutcomeClass::Cancelled;
    }
    match cause {
        TerminationCause::OomKilled => OutcomeClass::OomKilled,
        TerminationCause::InternalPanic => OutcomeClass::InternalPanic,
        TerminationCause::Signalled(s) => OutcomeClass::SignalTerminated(s),
        TerminationCause::ExitZero => OutcomeClass::Succeeded,
        TerminationCause::ExitNonZero(n @ 1..=255) => OutcomeClass::DeterministicFailure(n),
        TerminationCause::ExitNonZero(_) | TerminationCause::InvalidStatus(_) => {
            OutcomeClass::InfrastructureFailure
        }
        // Explicit causes remain non-publishable without context flags.
        TerminationCause::WorkerLost => OutcomeClass::WorkerLost,
        TerminationCause::LeaseExpired => OutcomeClass::LeaseExpired,
        TerminationCause::PolicyRefused => OutcomeClass::PolicyRefused,
        TerminationCause::DeadlineExceeded | TerminationCause::CancelledByPolicy => {
            OutcomeClass::VolatileFailure
        }
    }
}

/// Classify a native [`ExitStatus`] while honoring the supplied attempt
/// context. A stopped process has not terminated: its stop signal must
/// not be manufactured into a terminal signal receipt.
#[must_use]
pub fn classify_status(status: ExitStatus, ctx: &OutcomeContext) -> OutcomeClass {
    classify(cause_from_exit(status.code(), status.signal(), false), ctx)
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

    #[test]
    fn cancellation_context_fences_every_native_exit_and_signal() {
        let ctx = OutcomeContext {
            cancelled_by_policy: true,
            ..Default::default()
        };
        for code in 0..=255 {
            let outcome = classify_status(status_from(code), &ctx);
            assert_eq!(outcome, OutcomeClass::Cancelled, "native exit {code}");
            assert!(!outcome.publication_eligible());
            assert_eq!(
                cause_from_exit(Some(code), None, true),
                TerminationCause::CancelledByPolicy
            );
        }
        for signal in [SIGABRT, SIGKILL, 15] {
            assert_eq!(
                classify_status(status_signalled(signal), &ctx),
                OutcomeClass::Cancelled
            );
        }
        for (ctx, expected) in [
            (OutcomeContext { policy_refused: true, ..ctx }, OutcomeClass::PolicyRefused),
            (OutcomeContext { worker_lost: true, ..ctx }, OutcomeClass::WorkerLost),
            (OutcomeContext { lease_expired: true, ..ctx }, OutcomeClass::LeaseExpired),
            (OutcomeContext { deadline_exceeded: true, ..ctx }, OutcomeClass::VolatileFailure),
        ] {
            assert_eq!(classify_status(status_from(0), &ctx), expected);
        }
    }

    #[test]
    fn malformed_statuses_cannot_become_deterministic_failures() {
        let ctx = OutcomeContext::default();
        for code in [i32::MIN, -1, 256, i32::MAX] {
            assert_eq!(decode_exit_code(code), TerminationCause::InvalidStatus(code));
            assert_eq!(
                cause_from_exit(Some(code), None, false),
                TerminationCause::InvalidStatus(code)
            );
            assert_eq!(
                classify(TerminationCause::ExitNonZero(code), &ctx),
                OutcomeClass::InfrastructureFailure
            );
            assert!(!OutcomeClass::DeterministicFailure(code).publication_eligible());
        }
        assert_eq!(decode_exit_code(128), TerminationCause::InvalidStatus(128));
        assert!(!OutcomeClass::DeterministicFailure(0).publication_eligible());
        assert_eq!(
            classify(TerminationCause::ExitNonZero(0), &ctx),
            OutcomeClass::InfrastructureFailure
        );
        for signal in [-1, 0, 128, i32::MAX] {
            assert_eq!(
                cause_from_exit(None, Some(signal), false),
                TerminationCause::InvalidStatus(signal)
            );
        }
    }

    #[test]
    fn native_high_exits_are_not_confused_with_wire_signal_encodings() {
        let ctx = OutcomeContext::default();
        for code in 1..=255 {
            assert_eq!(
                classify_status(status_from(code), &ctx),
                OutcomeClass::DeterministicFailure(code)
            );
        }
        for code in 129..=255 {
            assert!(!classify(decode_exit_code(code), &ctx).publication_eligible());
        }
        assert_eq!(classify(decode_exit_code(137), &ctx), OutcomeClass::OomKilled);
    }

    #[test]
    fn stopped_process_is_not_a_terminal_signal_receipt() {
        let stopped = ExitStatus::from_raw((15 << 8) | 0x7f);
        assert_eq!(stopped.stopped_signal(), Some(15));
        assert_eq!(
            classify_status(stopped, &OutcomeContext::default()),
            OutcomeClass::WorkerLost
        );
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

    #[test]
    fn caught_term_with_zero_exit_still_honors_cancellation_receipt() {
        // Deterministic fixture: install the handler before signalling the
        // same shell, with no sleeps or parent/child signal timing race.
        let mut group = spawn_sh("trap 'exit 0' TERM; kill -TERM $$; exit 99");
        let status = group.wait_leader().expect("wait");
        assert!(status.success(), "the handler must have exited zero");
        let ctx = OutcomeContext {
            cancelled_by_policy: true,
            ..Default::default()
        };
        assert_eq!(classify_status(status, &ctx), OutcomeClass::Cancelled);
        assert!(!classify_status(status, &ctx).publication_eligible());
    }
}
