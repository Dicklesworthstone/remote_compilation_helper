//! Recovery-probe + canary decision state machine for temporarily bypassed
//! workers (bd-session-history-remediation-ocv9i.1.3).
//!
//! A bypassed worker ([`crate::bypass_record::BypassRecord`]) may only rejoin
//! the fleet after it passes a recovery probe across **every** required
//! dimension for [`AutoRejoinCriteria::required_consecutive_passes`] consecutive
//! rounds AND then passes a single canary build through the same path real
//! builds use. This module is the pure decision core of that loop:
//!
//! - [`decide_probe`] takes a worker's record + the [`RecoveryProbe`] result and
//!   returns the next [`ProbeDecision`] (stay bypassed, keep probing, ready for a
//!   canary, or — when no canary is required — rejoin), updating the record's
//!   pass/fail counters and backoff via the [`BypassRecord`] bookkeeping methods.
//! - [`decide_canary`] takes the canary [`CanaryOutcome`] and returns the final
//!   [`CanaryDecision`] (rejoin or relapse back into bypass).
//!
//! ## Cardinal safety invariant
//!
//! A worker rejoins ONLY after the required number of *fully healthy* probes
//! (every hard dimension green) followed by a passing canary — never on one
//! lucky SSH response, and never while any hard dimension is failing. A single
//! failing dimension resets the pass streak. The daemon must also never probe an
//! admin-disabled worker for auto-rejoin; that is an admin-axis decision the
//! caller enforces ([`AutoRejoinCriteria`] lives on the eligibility axis only).
//!
//! The probe *execution* (SSH/shell, exact `rch-wkr --version`, protocol
//! handshake, toolchain/target, disk+inode, load, telemetry) and the canary
//! *build* are the daemon's job; this module decides what the results mean so
//! the policy is deterministic and exhaustively testable.

use serde::{Deserialize, Serialize};

use crate::bypass_record::BypassRecord;

/// Outcome of one recovery probe across every required dimension. Each field is
/// a hard gate: a worker is only "fully healthy" when they are ALL green.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryProbe {
    /// SSH connect + shell round-trip succeeded.
    pub ssh_ok: bool,
    /// `rch-wkr` exists at the exact configured path and `--version` matched.
    pub worker_binary_ok: bool,
    /// `rch-wkr --protocol-version` is compatible with the daemon.
    pub protocol_ok: bool,
    /// Required runtime/toolchain/Rust target are present.
    pub toolchain_ok: bool,
    /// Disk and inode thresholds are satisfied on all relevant roots.
    pub disk_ok: bool,
    /// Load / process pressure is within limits.
    pub load_ok: bool,
    /// Telemetry is fresh (age within tolerance).
    pub telemetry_ok: bool,
}

impl RecoveryProbe {
    /// A probe with every dimension passing (a base for builders/tests).
    #[must_use]
    pub const fn all_ok() -> Self {
        Self {
            ssh_ok: true,
            worker_binary_ok: true,
            protocol_ok: true,
            toolchain_ok: true,
            disk_ok: true,
            load_ok: true,
            telemetry_ok: true,
        }
    }

    /// Whether every hard dimension passed — the gate for counting a probe pass.
    #[must_use]
    pub const fn fully_healthy(&self) -> bool {
        self.ssh_ok
            && self.worker_binary_ok
            && self.protocol_ok
            && self.toolchain_ok
            && self.disk_ok
            && self.load_ok
            && self.telemetry_ok
    }

    /// The first failing dimension, in a stable check order, for diagnostics.
    #[must_use]
    pub const fn first_failure(&self) -> Option<&'static str> {
        if !self.ssh_ok {
            Some("ssh")
        } else if !self.worker_binary_ok {
            Some("worker_binary")
        } else if !self.protocol_ok {
            Some("protocol")
        } else if !self.toolchain_ok {
            Some("toolchain")
        } else if !self.disk_ok {
            Some("disk")
        } else if !self.load_ok {
            Some("load")
        } else if !self.telemetry_ok {
            Some("telemetry")
        } else {
            None
        }
    }
}

/// The result of running the canary build during a recovery trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryOutcome {
    /// The canary build succeeded through the real build path.
    Passed,
    /// The canary build failed (or errored).
    Failed,
}

/// What the recovery loop should do after a probe round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum ProbeDecision {
    /// A hard dimension failed — stay bypassed. The record's failure count and
    /// backoff were advanced and the next probe rescheduled.
    StayBypassed {
        /// The first failing dimension.
        failed_dimension: String,
        /// The updated record (persist it).
        record: Box<BypassRecord>,
    },
    /// The probe was fully healthy but not yet enough consecutive passes — keep
    /// probing. The record's pass count was advanced.
    KeepProbing {
        /// Consecutive passing probes so far.
        consecutive_passes: u32,
        /// Passes required before a canary.
        required: u32,
        /// The updated record (persist it).
        record: Box<BypassRecord>,
    },
    /// Enough consecutive full passes — run a canary build, then call
    /// [`decide_canary`] with the outcome. The record is in
    /// `RecoveredPendingCanary`.
    ReadyForCanary {
        /// The updated record (persist it).
        record: Box<BypassRecord>,
    },
    /// No canary is required and the pass criteria are met — rejoin the worker
    /// (clear the bypass record, restore eligibility).
    Rejoin,
}

/// What the recovery loop should do after the canary build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum CanaryDecision {
    /// The canary passed — rejoin the worker (clear the bypass record).
    Rejoin,
    /// The canary failed — relapse into bypass. The record's failure count and
    /// backoff were advanced; persist it.
    Relapse {
        /// The updated record (persist it).
        record: Box<BypassRecord>,
    },
}

/// Decide the next move after a recovery probe of a bypassed worker.
///
/// Pure: mutates a local copy of `record` via its bookkeeping methods and
/// returns the updated record inside the decision. A failing dimension resets
/// the pass streak (so a flapping worker never accumulates enough passes), and a
/// fully-healthy probe advances toward — but never directly completes — rejoin
/// unless the criteria are met and no canary is required.
#[must_use]
pub fn decide_probe(
    record: BypassRecord,
    probe: &RecoveryProbe,
    now_unix_ms: u64,
) -> ProbeDecision {
    let mut record = record;
    if !probe.fully_healthy() {
        let dim = probe.first_failure().unwrap_or("unknown");
        record.record_failure(now_unix_ms, format!("recovery probe failed: {dim}"));
        return ProbeDecision::StayBypassed {
            failed_dimension: dim.to_string(),
            record: Box::new(record),
        };
    }

    // Fully healthy probe — count the pass. `record_probe_pass` returns whether
    // the consecutive-pass criteria are now met (and advances to
    // RecoveredPendingCanary when a canary is required).
    let criteria_met = record.record_probe_pass(now_unix_ms);
    if !criteria_met {
        return ProbeDecision::KeepProbing {
            consecutive_passes: record.consecutive_passes,
            required: record.auto_rejoin.required_consecutive_passes,
            record: Box::new(record),
        };
    }
    if record.auto_rejoin.canary_required {
        ProbeDecision::ReadyForCanary {
            record: Box::new(record),
        }
    } else {
        ProbeDecision::Rejoin
    }
}

/// Decide the final move after the canary build for a `RecoveredPendingCanary`
/// worker. A pass rejoins; a failure relapses into bypass with advanced backoff.
#[must_use]
pub fn decide_canary(
    record: BypassRecord,
    outcome: CanaryOutcome,
    now_unix_ms: u64,
) -> CanaryDecision {
    match outcome {
        CanaryOutcome::Passed => CanaryDecision::Rejoin,
        CanaryOutcome::Failed => {
            let mut record = record;
            record.record_failure(now_unix_ms, "canary build failed");
            CanaryDecision::Relapse {
                record: Box::new(record),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass_record::{AutoRejoinCriteria, BypassFailureClass, BypassRecord, BypassState};

    const TS: u64 = 1_700_000_000_000;

    fn record() -> BypassRecord {
        BypassRecord::new("css", "h", "u", BypassFailureClass::Ssh, TS)
    }

    fn probe_failing(dim: &str) -> RecoveryProbe {
        let mut p = RecoveryProbe::all_ok();
        match dim {
            "ssh" => p.ssh_ok = false,
            "worker_binary" => p.worker_binary_ok = false,
            "protocol" => p.protocol_ok = false,
            "toolchain" => p.toolchain_ok = false,
            "disk" => p.disk_ok = false,
            "load" => p.load_ok = false,
            "telemetry" => p.telemetry_ok = false,
            _ => unreachable!(),
        }
        p
    }

    #[test]
    fn fully_healthy_requires_every_dimension() {
        assert!(RecoveryProbe::all_ok().fully_healthy());
        for dim in [
            "ssh",
            "worker_binary",
            "protocol",
            "toolchain",
            "disk",
            "load",
            "telemetry",
        ] {
            let p = probe_failing(dim);
            assert!(!p.fully_healthy(), "{dim} failure should not be healthy");
            assert_eq!(p.first_failure(), Some(dim));
        }
    }

    #[test]
    fn failing_probe_stays_bypassed_and_advances_backoff() {
        let r = record();
        let before = r.backoff.current_ms;
        match decide_probe(r, &probe_failing("disk"), TS + 1) {
            ProbeDecision::StayBypassed {
                failed_dimension,
                record,
            } => {
                assert_eq!(failed_dimension, "disk");
                assert!(record.backoff.current_ms > before);
                assert_eq!(record.consecutive_passes, 0);
                assert_eq!(record.state, BypassState::TemporaryBypass);
            }
            other => panic!("expected StayBypassed, got {other:?}"),
        }
    }

    #[test]
    fn one_lucky_ssh_does_not_rejoin() {
        // A single fully-healthy probe with the default 2-pass criteria must NOT
        // rejoin — it only advances the streak.
        let r = record();
        match decide_probe(r, &RecoveryProbe::all_ok(), TS + 1) {
            ProbeDecision::KeepProbing {
                consecutive_passes,
                required,
                ..
            } => {
                assert_eq!(consecutive_passes, 1);
                assert_eq!(required, 2);
            }
            other => panic!("one pass must keep probing, not {other:?}"),
        }
    }

    #[test]
    fn ssh_only_probe_never_counts_as_a_pass() {
        // ssh_ok but every other dimension failing — the classic "lucky SSH
        // response" — must stay bypassed, never count toward rejoin.
        let mut p = RecoveryProbe::all_ok();
        p.worker_binary_ok = false;
        p.toolchain_ok = false;
        p.disk_ok = false;
        assert!(p.ssh_ok);
        match decide_probe(record(), &p, TS + 1) {
            ProbeDecision::StayBypassed { .. } => {}
            other => panic!("lucky SSH must stay bypassed, got {other:?}"),
        }
    }

    #[test]
    fn two_consecutive_passes_reach_canary() {
        let r = record();
        let r = match decide_probe(r, &RecoveryProbe::all_ok(), TS + 1) {
            ProbeDecision::KeepProbing { record, .. } => *record,
            other => panic!("expected KeepProbing, got {other:?}"),
        };
        match decide_probe(r, &RecoveryProbe::all_ok(), TS + 2) {
            ProbeDecision::ReadyForCanary { record } => {
                assert_eq!(record.state, BypassState::RecoveredPendingCanary);
                assert_eq!(record.consecutive_passes, 2);
            }
            other => panic!("expected ReadyForCanary, got {other:?}"),
        }
    }

    #[test]
    fn flapping_worker_never_reaches_canary() {
        // Alternating pass/fail: each failure resets the streak, so the worker
        // never accumulates the consecutive passes needed for a canary.
        let mut r = record();
        for i in 0..10 {
            let probe = if i % 2 == 0 {
                RecoveryProbe::all_ok()
            } else {
                probe_failing("ssh")
            };
            r = match decide_probe(r, &probe, TS + i) {
                ProbeDecision::KeepProbing { record, .. } => *record,
                ProbeDecision::StayBypassed { record, .. } => *record,
                other => panic!("flapping must never reach {other:?}"),
            };
            assert!(
                r.consecutive_passes < 2,
                "flapping must never reach 2 consecutive passes"
            );
        }
    }

    #[test]
    fn no_canary_required_rejoins_after_passes() {
        let mut r = record().with_auto_rejoin(AutoRejoinCriteria {
            required_consecutive_passes: 2,
            canary_required: false,
        });
        // First pass keeps probing.
        r = match decide_probe(r, &RecoveryProbe::all_ok(), TS + 1) {
            ProbeDecision::KeepProbing { record, .. } => *record,
            other => panic!("expected KeepProbing, got {other:?}"),
        };
        // Second pass meets criteria; no canary required -> rejoin directly.
        assert_eq!(
            decide_probe(r, &RecoveryProbe::all_ok(), TS + 2),
            ProbeDecision::Rejoin
        );
    }

    #[test]
    fn canary_pass_rejoins_canary_fail_relapses() {
        // Drive to ReadyForCanary.
        let mut r = record();
        r = match decide_probe(r, &RecoveryProbe::all_ok(), TS + 1) {
            ProbeDecision::KeepProbing { record, .. } => *record,
            other => panic!("{other:?}"),
        };
        let pending = match decide_probe(r, &RecoveryProbe::all_ok(), TS + 2) {
            ProbeDecision::ReadyForCanary { record } => *record,
            other => panic!("{other:?}"),
        };

        // Canary pass -> rejoin.
        assert_eq!(
            decide_canary(pending.clone(), CanaryOutcome::Passed, TS + 3),
            CanaryDecision::Rejoin
        );

        // Canary fail -> relapse with advanced backoff and reset streak.
        match decide_canary(pending, CanaryOutcome::Failed, TS + 3) {
            CanaryDecision::Relapse { record } => {
                assert_eq!(record.state, BypassState::TemporaryBypass);
                assert_eq!(record.consecutive_passes, 0);
                assert!(record.last_diagnostic.contains("canary"));
            }
            other => panic!("expected Relapse, got {other:?}"),
        }
    }

    #[test]
    fn wrong_binary_and_stale_telemetry_stay_bypassed() {
        for dim in ["worker_binary", "telemetry"] {
            match decide_probe(record(), &probe_failing(dim), TS + 1) {
                ProbeDecision::StayBypassed {
                    failed_dimension, ..
                } => assert_eq!(failed_dimension, dim),
                other => panic!("{dim}: expected StayBypassed, got {other:?}"),
            }
        }
    }

    #[test]
    fn decisions_serialize_with_stable_tags() {
        let d = decide_probe(record(), &probe_failing("ssh"), TS + 1);
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["decision"], "stay_bypassed");
        assert_eq!(v["failed_dimension"], "ssh");

        let c = serde_json::to_value(CanaryDecision::Rejoin).unwrap();
        assert_eq!(c["decision"], "rejoin");
    }
}
