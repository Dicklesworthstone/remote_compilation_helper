//! Wrapper connect gating: tiny bounded timeouts and a persisted
//! circuit breaker (bead C004; risk R27).
//!
//! Every intercepted command starts a FRESH tiny wrapper process, so an
//! in-memory breaker would be useless: the state here is designed to be
//! persisted in a small state file between invocations (the codec is
//! this module's canonical byte format; the actual file I/O lives in
//! the wrapper binary — this crate has no filesystem effects).
//!
//! R27 discipline — fail-open must not make every command pay:
//!
//! - while the breaker is OPEN and inside the cooldown window, the
//!   decision is [`ConnectDecision::SkipToLocal`]: the wrapper runs the
//!   original chain immediately, paying ZERO connect or decision
//!   timeout;
//! - after the cooldown, exactly ONE probe per window is permitted, and
//!   the probe start is recorded WRITE-AHEAD
//!   ([`BreakerState::probe_started`]) so a wrapper that crashes
//!   mid-probe cannot cause the next invocation to probe again inside
//!   the same window;
//! - a successful probe (or any successful connect) resets the breaker
//!   — recovery is immediate, never queued behind residual state;
//! - decoding a missing, corrupt, or future-versioned state file fails
//!   OPEN to a fresh closed breaker: broken bookkeeping may cost one
//!   connect timeout, it must never block or bias a build;
//! - timestamps come from the caller and are compared conservatively:
//!   an implausibly-future stored timestamp (beyond one cooldown ahead
//!   of `now`) is treated as corrupt state, so a clock step can never
//!   strand the breaker open forever.

/// Timeout and threshold policy. All budgets are tiny and bounded: the
/// wrapper's whole value proposition dies if a dead edge taxes builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerPolicy {
    /// Budget for the Unix-socket connect itself, milliseconds.
    pub connect_timeout_ms: u32,
    /// Budget for the edge's placement decision after connect,
    /// milliseconds.
    pub decision_timeout_ms: u32,
    /// Consecutive failures that OPEN the breaker.
    pub open_after_consecutive_failures: u32,
    /// How long an open breaker skips locally before ONE probe is
    /// allowed, milliseconds.
    pub cooldown_ms: u64,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 25,
            decision_timeout_ms: 50,
            open_after_consecutive_failures: 3,
            cooldown_ms: 5_000,
        }
    }
}

/// Persisted breaker state (one tiny record per wrapper socket).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Edge believed healthy; failures counted toward opening.
    Closed {
        /// Consecutive connect/decision failures so far.
        consecutive_failures: u32,
    },
    /// Edge believed dead; skip locally until a probe succeeds.
    Open {
        /// When the breaker opened (caller-supplied milliseconds).
        opened_at_ms: u64,
        /// When the last probe STARTED, recorded write-ahead — a crash
        /// mid-probe must not let the next wrapper probe again inside
        /// the same window.
        last_probe_started_at_ms: Option<u64>,
    },
}

impl BreakerState {
    /// A fresh breaker.
    #[must_use]
    pub const fn fresh() -> Self {
        Self::Closed {
            consecutive_failures: 0,
        }
    }

    /// Record (write-ahead, BEFORE attempting) that a probe is starting
    /// now. On a closed breaker this is a no-op.
    #[must_use]
    pub const fn probe_started(self, now_ms: u64) -> Self {
        match self {
            Self::Closed { .. } => self,
            Self::Open { opened_at_ms, .. } => Self::Open {
                opened_at_ms,
                last_probe_started_at_ms: Some(now_ms),
            },
        }
    }
}

/// What the wrapper should do about connecting, decided in pure logic
/// before any socket is touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectDecision {
    /// Attempt the edge connect under the tiny bounded budgets.
    Attempt {
        /// Connect budget, milliseconds.
        connect_timeout_ms: u32,
        /// Decision budget, milliseconds.
        decision_timeout_ms: u32,
    },
    /// Breaker is open and the cooldown elapsed: ONE probe is allowed.
    /// Callers must persist [`BreakerState::probe_started`] BEFORE
    /// attempting.
    Probe {
        /// Connect budget, milliseconds.
        connect_timeout_ms: u32,
        /// Decision budget, milliseconds.
        decision_timeout_ms: u32,
    },
    /// Breaker is open inside the cooldown: run the original chain
    /// immediately, zero added latency.
    SkipToLocal,
}

/// One connect attempt's outcome, as the wrapper observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Connected and received a decision inside the budgets.
    Succeeded,
    /// Connect failed or timed out, the decision timed out, or the
    /// edge answered with an incompatible/unusable protocol.
    Failed,
}

const fn cooldown_reference(state: &BreakerState) -> u64 {
    match state {
        BreakerState::Closed { .. } => 0,
        BreakerState::Open {
            opened_at_ms,
            last_probe_started_at_ms,
        } => match last_probe_started_at_ms {
            Some(probe) if *probe > *opened_at_ms => *probe,
            _ => *opened_at_ms,
        },
    }
}

/// Decide what to do at `now_ms`, purely. An implausibly-future stored
/// timestamp (more than one cooldown ahead of `now_ms`) is treated as
/// corrupt bookkeeping and fails OPEN to an attempt.
#[must_use]
pub fn decide(policy: &BreakerPolicy, state: &BreakerState, now_ms: u64) -> ConnectDecision {
    let attempt = ConnectDecision::Attempt {
        connect_timeout_ms: policy.connect_timeout_ms,
        decision_timeout_ms: policy.decision_timeout_ms,
    };
    match state {
        BreakerState::Closed { .. } => attempt,
        BreakerState::Open { .. } => {
            let reference = cooldown_reference(state);
            if reference > now_ms.saturating_add(policy.cooldown_ms) {
                // Stored time is beyond plausibility: a clock step must
                // never strand the breaker open forever.
                return attempt;
            }
            if now_ms.saturating_sub(reference) >= policy.cooldown_ms {
                ConnectDecision::Probe {
                    connect_timeout_ms: policy.connect_timeout_ms,
                    decision_timeout_ms: policy.decision_timeout_ms,
                }
            } else {
                ConnectDecision::SkipToLocal
            }
        }
    }
}

/// Fold one attempt outcome into the state. Success ALWAYS resets to a
/// fresh closed breaker (recovery is immediate); failure counts toward
/// opening, and a failed probe re-arms the cooldown from `now_ms`.
#[must_use]
pub fn on_outcome(
    policy: &BreakerPolicy,
    state: &BreakerState,
    outcome: AttemptOutcome,
    now_ms: u64,
) -> BreakerState {
    match outcome {
        AttemptOutcome::Succeeded => BreakerState::fresh(),
        AttemptOutcome::Failed => match state {
            BreakerState::Closed {
                consecutive_failures,
            } => {
                let failures = consecutive_failures.saturating_add(1);
                if failures >= policy.open_after_consecutive_failures {
                    BreakerState::Open {
                        opened_at_ms: now_ms,
                        last_probe_started_at_ms: None,
                    }
                } else {
                    BreakerState::Closed {
                        consecutive_failures: failures,
                    }
                }
            }
            BreakerState::Open { .. } => BreakerState::Open {
                opened_at_ms: now_ms,
                last_probe_started_at_ms: None,
            },
        },
    }
}

/// Canonical persisted encoding, version-tagged. One tiny line-oriented
/// record; the wrapper writes it with atomic rename.
#[must_use]
pub fn encode_state(state: &BreakerState) -> String {
    match state {
        BreakerState::Closed {
            consecutive_failures,
        } => {
            format!("rabs-breaker v1\nclosed {consecutive_failures}\n")
        }
        BreakerState::Open {
            opened_at_ms,
            last_probe_started_at_ms,
        } => {
            let probe =
                last_probe_started_at_ms.map_or_else(|| "-".to_owned(), |probe| probe.to_string());
            format!("rabs-breaker v1\nopen {opened_at_ms} {probe}\n")
        }
    }
}

/// Decode a persisted record. Returns `None` — and the caller starts
/// from [`BreakerState::fresh`] — on ANY corruption, truncation, or
/// unknown version: broken bookkeeping fails open, never closed.
#[must_use]
pub fn decode_state(bytes: &[u8]) -> Option<BreakerState> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "rabs-breaker v1" {
        return None;
    }
    let record = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let mut parts = record.split(' ');
    match parts.next()? {
        "closed" => {
            let failures: u32 = parts.next()?.parse().ok()?;
            if parts.next().is_some() {
                return None;
            }
            Some(BreakerState::Closed {
                consecutive_failures: failures,
            })
        }
        "open" => {
            let opened_at_ms: u64 = parts.next()?.parse().ok()?;
            let probe_field = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            let last_probe_started_at_ms = if probe_field == "-" {
                None
            } else {
                Some(probe_field.parse().ok()?)
            };
            Some(BreakerState::Open {
                opened_at_ms,
                last_probe_started_at_ms,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: BreakerPolicy = BreakerPolicy {
        connect_timeout_ms: 25,
        decision_timeout_ms: 50,
        open_after_consecutive_failures: 3,
        cooldown_ms: 5_000,
    };

    #[test]
    fn opens_after_consecutive_failures_and_success_resets_the_count() {
        let mut state = BreakerState::fresh();
        state = on_outcome(&POLICY, &state, AttemptOutcome::Failed, 10);
        state = on_outcome(&POLICY, &state, AttemptOutcome::Failed, 20);
        // A success in between resets the streak: no opening.
        state = on_outcome(&POLICY, &state, AttemptOutcome::Succeeded, 30);
        assert_eq!(state, BreakerState::fresh());
        state = on_outcome(&POLICY, &state, AttemptOutcome::Failed, 40);
        state = on_outcome(&POLICY, &state, AttemptOutcome::Failed, 50);
        assert!(matches!(state, BreakerState::Closed { .. }));
        state = on_outcome(&POLICY, &state, AttemptOutcome::Failed, 60);
        assert_eq!(
            state,
            BreakerState::Open {
                opened_at_ms: 60,
                last_probe_started_at_ms: None,
            }
        );
    }

    #[test]
    fn open_breaker_pays_zero_tax_until_the_cooldown_elapses() {
        // THE R27 acceptance at this layer: while open and inside the
        // cooldown, the decision is SkipToLocal — no connect attempt,
        // no timeout budget spent, nothing added to the command.
        let state = BreakerState::Open {
            opened_at_ms: 1_000,
            last_probe_started_at_ms: None,
        };
        for now in [1_000, 1_001, 3_000, 5_999] {
            assert_eq!(decide(&POLICY, &state, now), ConnectDecision::SkipToLocal);
        }
        // Cooldown elapsed: exactly one probe is permitted.
        assert_eq!(
            decide(&POLICY, &state, 6_000),
            ConnectDecision::Probe {
                connect_timeout_ms: 25,
                decision_timeout_ms: 50,
            }
        );
    }

    #[test]
    fn write_ahead_probe_recording_prevents_probe_storms() {
        // A wrapper that crashes mid-probe never records an outcome;
        // because the probe START was persisted write-ahead, the next
        // invocations inside the window still skip locally.
        let state = BreakerState::Open {
            opened_at_ms: 1_000,
            last_probe_started_at_ms: None,
        };
        assert!(matches!(
            decide(&POLICY, &state, 6_000),
            ConnectDecision::Probe { .. }
        ));
        let state = state.probe_started(6_000);
        assert_eq!(decide(&POLICY, &state, 6_001), ConnectDecision::SkipToLocal);
        assert_eq!(
            decide(&POLICY, &state, 10_999),
            ConnectDecision::SkipToLocal
        );
        // The NEXT window allows the next probe.
        assert!(matches!(
            decide(&POLICY, &state, 11_000),
            ConnectDecision::Probe { .. }
        ));
    }

    #[test]
    fn probe_success_recovers_immediately_and_failure_rearms() {
        let open = BreakerState::Open {
            opened_at_ms: 1_000,
            last_probe_started_at_ms: Some(6_000),
        };
        // Recovery: one successful probe fully closes the breaker.
        assert_eq!(
            on_outcome(&POLICY, &open, AttemptOutcome::Succeeded, 6_010),
            BreakerState::fresh()
        );
        let closed = on_outcome(&POLICY, &open, AttemptOutcome::Succeeded, 6_010);
        assert!(matches!(
            decide(&POLICY, &closed, 6_011),
            ConnectDecision::Attempt { .. }
        ));
        // Failure re-arms the cooldown from the failure instant.
        let rearmed = on_outcome(&POLICY, &open, AttemptOutcome::Failed, 6_010);
        assert_eq!(
            rearmed,
            BreakerState::Open {
                opened_at_ms: 6_010,
                last_probe_started_at_ms: None,
            }
        );
        assert_eq!(
            decide(&POLICY, &rearmed, 11_009),
            ConnectDecision::SkipToLocal
        );
    }

    #[test]
    fn closed_breaker_attempts_with_tiny_bounded_budgets() {
        let policy = BreakerPolicy::default();
        assert_eq!(
            decide(&policy, &BreakerState::fresh(), 0),
            ConnectDecision::Attempt {
                connect_timeout_ms: 25,
                decision_timeout_ms: 50,
            }
        );
        // The defaults stay tiny: a dead edge before the breaker opens
        // costs at most connect+decision per command.
        assert!(policy.connect_timeout_ms <= 100);
        assert!(policy.decision_timeout_ms <= 200);
    }

    #[test]
    fn implausible_future_timestamps_fail_open_not_stuck() {
        // A wall-clock step backward makes stored timestamps look
        // far-future; the breaker must attempt rather than skip
        // forever.
        let state = BreakerState::Open {
            opened_at_ms: 1_000_000,
            last_probe_started_at_ms: None,
        };
        assert!(matches!(
            decide(&POLICY, &state, 10),
            ConnectDecision::Attempt { .. }
        ));
        // A merely-slightly-future timestamp (inside one cooldown) is
        // treated as within cooldown, not corrupt.
        assert_eq!(
            decide(&POLICY, &state, 996_000),
            ConnectDecision::SkipToLocal
        );
    }

    #[test]
    fn state_codec_round_trips_and_corruption_fails_open() {
        let states = [
            BreakerState::fresh(),
            BreakerState::Closed {
                consecutive_failures: 2,
            },
            BreakerState::Open {
                opened_at_ms: 123,
                last_probe_started_at_ms: None,
            },
            BreakerState::Open {
                opened_at_ms: 123,
                last_probe_started_at_ms: Some(456),
            },
        ];
        for state in states {
            assert_eq!(decode_state(encode_state(&state).as_bytes()), Some(state));
        }
        for garbage in [
            &b""[..],
            b"rabs-breaker v1\n",
            b"rabs-breaker v2\nclosed 0\n",
            b"rabs-breaker v1\nclosed x\n",
            b"rabs-breaker v1\nopen 1\n",
            b"rabs-breaker v1\nopen 1 2 3\n",
            b"rabs-breaker v1\nclosed 0 extra\n",
            b"rabs-breaker v1\nclosed 0\ntrailing\n",
            b"rabs-breaker v1\nnonsense 0\n",
            b"\xff\xfe",
        ] {
            assert_eq!(
                decode_state(garbage),
                None,
                "corrupt record must decode to None (caller starts fresh): {garbage:?}"
            );
        }
    }
}
