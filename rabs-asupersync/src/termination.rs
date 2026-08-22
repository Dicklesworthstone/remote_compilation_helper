//! Graceful TERM → drain → escalate → reap teardown policy (bead G008;
//! Epic G process lifecycle; invariant I6 reference-counted
//! cancellation, I7 region-owned external effects).
//!
//! Composes the [`crate::process_groups`] primitives into THE bounded
//! cancellation policy every managed action shares:
//!
//! 1. **Graceful request** — one `SIGTERM` to the whole group;
//! 2. **Drain window** — cooperative members exit while output keeps
//!    draining (stream ownership stays with whoever holds the pipes;
//!    this policy never touches them);
//! 3. **Escalation** — one group `SIGKILL` after the bounded grace;
//! 4. **Reap + verify** — leader reaped, membership verified EMPTY.
//!
//! [`TerminationReceipt::ownership_resolved`] is the release gate:
//! slots, tokens, and leases may be freed ONLY once it is set —
//! releasing earlier is how double-slot bugs happen (M2 acceptance:
//! "exactly-once slot release"). The receipt doubles as the
//! cancellation progress record for crashpacks and the coordinator.
//!
//! Idempotence: running the policy against an already-dead group is a
//! successful no-op (`ESRCH` from `kill(1)` reads as "already
//! resolved", never as an error), so callers may retry safely.
//!
//! Exactly-once has TWO halves: the policy guarantees
//! `ownership_resolved` can only be true with zero live members (safe
//! to release), and the CALLER latches on the resolution transition
//! (`if resolved && !already_released { release(); }`) — the flag is
//! idempotently true on retries, which is what makes retry loops safe.

use std::io;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use crate::process_groups::{ManagedProcessGroup, members_from_proc};
use crate::region_tree::Attribution;

/// Bounded timings for one shutdown. All fields are explicit so tests
/// and callers pin behavior deterministically — no hidden constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationPolicy {
    /// Maximum wait for COOPERATIVE exit after `SIGTERM` before
    /// escalating to `SIGKILL`.
    pub grace: Duration,
    /// Membership polling cadence while draining. Clamped to ≥1ms.
    pub poll: Duration,
    /// Verification budget after escalation (KILL needs no cooperation;
    /// this only waits for the kernel + reparent-reaping to catch up).
    pub final_wait: Duration,
}

impl Default for TerminationPolicy {
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(5),
            poll: Duration::from_millis(20),
            final_wait: Duration::from_secs(2),
        }
    }
}

impl TerminationPolicy {
    /// Poll cadence floored at 1ms so a zero poll cannot busy-spin.
    #[must_use]
    pub fn poll_clamped(&self) -> Duration {
        self.poll.max(Duration::from_millis(1))
    }
}

/// Ordered milestones recorded with milliseconds since shutdown start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationStage {
    /// Graceful `SIGTERM` delivered to the group.
    TermSent,
    /// The group was already gone — no signal was necessary.
    AlreadyGone,
    /// Cooperative drain window expired with survivors present.
    GraceExpired,
    /// Escalation `SIGKILL` delivered.
    KillSent,
    /// Leader reaped (status captured).
    LeaderReaped,
    /// Membership verified empty — ownership fully resolved.
    Resolved,
}

/// How the leader ended, decoded from [`ExitStatus`] (signal deaths
/// carry the signal number; normal exits carry the code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderExit {
    /// Exit code, if the leader exited normally.
    pub exit_code: Option<i32>,
    /// Fatal signal number, if the leader was killed (unix only).
    pub signal: Option<i32>,
}

impl LeaderExit {
    fn capture(status: ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self {
                exit_code: status.code(),
                signal: status.signal(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                exit_code: status.code(),
                signal: None,
            }
        }
    }
}

/// The cancellation progress receipt: what was signaled, when, and
/// whether ownership fully resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationReceipt {
    /// Attempt attribution carried onto the record (I7 chain).
    pub attribution: Attribution,
    /// A graceful `SIGTERM` was actually delivered.
    pub term_sent: bool,
    /// An escalatory `SIGKILL` was actually delivered.
    pub kill_sent: bool,
    /// The leader had ALREADY exited before the policy started (kept
    /// distinct from the post-policy leader status below).
    pub leader_already_exited: bool,
    /// How the leader ended (`None` when another owner of the child
    /// reaped it first, e.g. after consuming `wait_with_output`).
    pub leader_exit: Option<LeaderExit>,
    /// Live members still present when the grace window closed.
    pub residuals_after_grace: u32,
    /// Live members after the final verification window. 0 = clean.
    pub residuals_final: u32,
    /// Release gate: zero live residual members. Slot/token/lease
    /// release MUST be gated on this flag (exactly-once contract).
    pub ownership_resolved: bool,
    /// Milestones in order, `(stage, elapsed_ms)`.
    pub stages: Vec<(TerminationStage, u64)>,
    /// Total wall-clock duration of the shutdown.
    pub elapsed_ms: u64,
}

/// Outcome of trying to deliver one group signal.
enum Signalled {
    /// Delivered to at least one live member.
    Delivered,
    /// Nothing alive to signal (`ESRCH`) — that IS resolution.
    GroupGone,
}

fn send_group_signal(pgid: u32, signal: &str) -> io::Result<()> {
    // `--` guards the negative operand from option parsing (procps);
    // same discipline as `ManagedProcessGroup::signal_group`.
    let status = std::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(format!("-{pgid}"))
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "kill -{signal} -- -{pgid} failed: {status}"
        )))
    }
}

fn signal_receipt(
    pgid: u32,
    signal: &str,
    sent_flag: impl FnOnce(&mut TerminationReceipt),
    stage: TerminationStage,
    receipt: &mut TerminationReceipt,
    start: Instant,
) -> Signalled {
    match send_group_signal(pgid, signal) {
        Ok(()) => {
            sent_flag(receipt);
            receipt.record(stage, start);
            Signalled::Delivered
        }
        Err(_) => {
            receipt.record(TerminationStage::AlreadyGone, start);
            finish_resolution(receipt, start, 0);
            Signalled::GroupGone
        }
    }
}

/// Poll membership until empty or the bounded window closes; returns
/// the survivor count at window close.
fn drain_until(pgid: u32, window: Duration, policy: &TerminationPolicy) -> u32 {
    let deadline = Instant::now() + window;
    loop {
        let survivors = members_from_proc(pgid).len() as u32;
        if survivors == 0 || Instant::now() >= deadline {
            return survivors;
        }
        std::thread::sleep(policy.poll_clamped());
    }
}

fn finish_resolution(receipt: &mut TerminationReceipt, start: Instant, residuals_final: u32) {
    receipt.residuals_final = residuals_final;
    receipt.ownership_resolved = residuals_final == 0;
    receipt.record(TerminationStage::Resolved, start);
    receipt.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
}

impl TerminationReceipt {
    fn fresh(attribution: Attribution) -> Self {
        Self {
            attribution,
            term_sent: false,
            kill_sent: false,
            leader_already_exited: false,
            leader_exit: None,
            residuals_after_grace: 0,
            residuals_final: 0,
            ownership_resolved: false,
            stages: Vec::new(),
            elapsed_ms: 0,
        }
    }

    fn record(&mut self, stage: TerminationStage, start: Instant) {
        let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.stages.push((stage, ms));
    }
}

/// Run the full TERM → drain → escalate → reap policy against a LIVE
/// handle. Streams are the caller's concern: with piped stdio keep
/// draining concurrently — this policy never blocks on pipe state.
///
/// Safe to call twice: the second pass observes emptiness and returns
/// a resolved receipt without re-signaling (idempotent cancellation).
pub fn graceful_shutdown(
    group: &mut ManagedProcessGroup,
    policy: &TerminationPolicy,
) -> TerminationReceipt {
    let attribution = group.attribution.clone();
    let mut receipt = TerminationReceipt::fresh(attribution);
    let start = Instant::now();

    // Leader state BEFORE any signaling: an already-exited leader gets
    // no special treatment (survivors still get the full policy), but
    // the fact is recorded honestly.
    // Reaped by an earlier owner, or probe failed: either way the
    // signals below decide the outcome.
    if let Ok(Some(status)) = group.leader_try_wait() {
        receipt.leader_already_exited = true;
        receipt.leader_exit = Some(LeaderExit::capture(status));
    }

    let pgid = group.pgid();

    // Fast path: nothing alive at all — pure bookkeeping resolution.
    if receipt.leader_already_exited && members_from_proc(pgid).is_empty() {
        receipt.record(TerminationStage::AlreadyGone, start);
        finish_resolution(&mut receipt, start, 0);
        return receipt;
    }

    // 1+2. Graceful request, then the bounded cooperative-drain window.
    match signal_receipt(
        pgid,
        "TERM",
        |r| r.term_sent = true,
        TerminationStage::TermSent,
        &mut receipt,
        start,
    ) {
        Signalled::GroupGone => return receipt, // already finished resolved
        Signalled::Delivered => {}
    }
    receipt.residuals_after_grace = drain_until(pgid, policy.grace, policy);

    // 3. Escalate only if cooperation failed.
    if receipt.residuals_after_grace > 0 {
        receipt.record(TerminationStage::GraceExpired, start);
        // Vanished between scan and KILL: fine, verification below
        // confirms emptiness either way.
        if send_group_signal(pgid, "KILL").is_ok() {
            receipt.kill_sent = true;
            receipt.record(TerminationStage::KillSent, start);
        }
    }

    // 4. Reap the leader so its status completes the attempt record.
    // Same status the pre-check captured for a natural exit — rewriting
    // it is harmless; for a KILLed leader this is the only capture.
    // leader_already_exited is intentionally NOT touched: it describes
    // the PRE-policy observation.
    if let Ok(status) = group.wait_leader() {
        receipt.leader_exit = Some(LeaderExit::capture(status));
        receipt.record(TerminationStage::LeaderReaped, start);
    }

    let residuals_final = drain_until(pgid, policy.final_wait, policy);
    finish_resolution(&mut receipt, start, residuals_final);
    receipt
}

/// Resolution-only variant for pgids whose group handle is already
/// consumed (`wait_with_output` takes ownership): runs the identical
/// TERM → drain → escalate → verify policy without any leader access.
pub fn resolve_residuals(
    pgid: u32,
    attribution: Attribution,
    policy: &TerminationPolicy,
) -> TerminationReceipt {
    let mut receipt = TerminationReceipt::fresh(attribution);
    receipt.leader_already_exited = true;
    let start = Instant::now();

    if members_from_proc(pgid).is_empty() {
        receipt.record(TerminationStage::AlreadyGone, start);
        finish_resolution(&mut receipt, start, 0);
        return receipt;
    }

    match signal_receipt(
        pgid,
        "TERM",
        |r| r.term_sent = true,
        TerminationStage::TermSent,
        &mut receipt,
        start,
    ) {
        Signalled::GroupGone => return receipt,
        Signalled::Delivered => {}
    }
    receipt.residuals_after_grace = drain_until(pgid, policy.grace, policy);

    if receipt.residuals_after_grace > 0 {
        receipt.record(TerminationStage::GraceExpired, start);
        // Vanished between scan and KILL: verification below confirms.
        if send_group_signal(pgid, "KILL").is_ok() {
            receipt.kill_sent = true;
            receipt.record(TerminationStage::KillSent, start);
        }
    }

    let residuals_final = drain_until(pgid, policy.final_wait, policy);
    finish_resolution(&mut receipt, start, residuals_final);
    receipt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_bounds_are_sane_and_poll_floors() {
        let policy = TerminationPolicy::default();
        assert_eq!(policy.grace, Duration::from_secs(5));
        assert_eq!(policy.final_wait, Duration::from_secs(2));
        assert_eq!(policy.poll_clamped(), Duration::from_millis(20));
        let hostile = TerminationPolicy {
            poll: Duration::ZERO,
            ..TerminationPolicy::default()
        };
        assert_eq!(
            hostile.poll_clamped(),
            Duration::from_millis(1),
            "zero poll must clamp to avoid a busy-spin"
        );
    }

    #[cfg(target_os = "linux")]
    mod live {
        use super::*;
        use crate::process_groups::{ManagedProcessGroup, ProcessGroupSpec};

        fn quick(grace_ms: u64, final_ms: u64) -> TerminationPolicy {
            TerminationPolicy {
                grace: Duration::from_millis(grace_ms),
                poll: Duration::from_millis(5),
                final_wait: Duration::from_millis(final_ms),
            }
        }

        fn spec(script: &str) -> ProcessGroupSpec {
            ProcessGroupSpec::new("sh", ["-c".to_owned(), script.to_owned()])
        }

        #[test]
        fn double_shutdown_is_idempotent_without_redundant_signals() {
            let mut group =
                ManagedProcessGroup::spawn(&spec("sleep 30 & sleep 30 & wait")).expect("spawn");
            let policy = quick(400, 400);

            let first = graceful_shutdown(&mut group, &policy);
            assert!(first.ownership_resolved);
            assert!(first.term_sent && !first.kill_sent, "cooperative exit");

            let second = graceful_shutdown(&mut group, &policy);
            assert!(second.ownership_resolved, "retry also resolves");
            assert!(
                !second.term_sent && !second.kill_sent,
                "no redundant signals on the retry"
            );
        }

        #[test]
        fn natural_exit_before_shutdown_skips_signals() {
            let mut group = ManagedProcessGroup::spawn(&spec("exit 0")).expect("spawn");
            std::thread::sleep(Duration::from_millis(50)); // corpse settles
            let receipt = graceful_shutdown(&mut group, &quick(100, 100));
            assert!(receipt.leader_already_exited);
            assert!(!receipt.term_sent, "no signal needed for a quiet corpse");
            assert!(receipt.ownership_resolved);
        }

        #[test]
        fn resolve_residuals_handles_consumed_handle_shape() {
            use crate::process_groups::members_from_proc;
            let group = ManagedProcessGroup::spawn(&spec("exit 0")).expect("spawn");
            let pgid = group.pgid();
            let _ = group.wait_with_output(); // handle consumed, like exec paths

            let receipt = resolve_residuals(pgid, Attribution::default(), &quick(100, 100));
            assert!(receipt.leader_already_exited);
            assert!(receipt.ownership_resolved);
            assert!(members_from_proc(pgid).is_empty());
        }
    }
}
