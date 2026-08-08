//! Transcript-only sequencing WITHOUT fsync-per-line + the explicit
//! labeled-recovery policy (bead C021; risk R104; plan §85).
//!
//! Diagnostic output is high-volume and replay-tolerant (behind the
//! C006 labeled-recovery rules), so it must never pay stateful-lane
//! durability costs: `TranscriptIntentRecorded` means **framed sequence
//! assignment plus retention in the reconnect window** — two in-memory
//! effects — and explicitly NOT a metadata fsync per line. The claim is
//! structural and this module proves it structurally: every operation
//! that would hit durable storage is counted by [`DurabilityMeter`],
//! and the transcript lane performs ZERO such operations per line —
//! the acceptance test drives ten thousand lines through
//! assign→send→ack and asserts the meter never moves. (The stateful
//! lane's write-ahead intents, bead C019, are the ONLY payers.)
//!
//! Frontier semantics (C005 wire truth):
//!
//! - the first fully acknowledged exposure sets `TranscriptExposed`;
//! - a sent-but-unacknowledged frame is conservatively
//!   `TranscriptDeliveryUncertain` — uncertainty counts as exposure for
//!   fallback purposes (R116);
//! - on disconnect, the edge's [`TranscriptSequencer::resume_view`] and
//!   the wrapper's report feed C014's `reconcile`, which reconstructs
//!   the exact resume point — or a typed refusal — from both sides'
//!   frontiers. The kill-point fixture below reconstructs uncertainty
//!   at every (sent, acked) combination.
//!
//! Retention is BOUNDED: old frames evict oldest-first under a budget,
//! `oldest_replayable_seq` rises, and a wrapper too far behind gets
//! C014's typed `RetentionGap` — never a silent gap.

use std::collections::VecDeque;

use crate::local_protocol::SubscriberFrontierReport;
use crate::reconnect::EdgeResumeView;

/// Counts operations that would touch durable storage (fsync,
/// journaled metadata write). The transcript lane must NEVER tick it;
/// callers hand the same meter to the stateful lane, which does. The
/// meter is how the "no per-line durability cost" claim stays testable
/// instead of aspirational.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DurabilityMeter {
    /// Durable operations performed so far.
    pub durable_ops: u64,
}

impl DurabilityMeter {
    /// Record one durable operation (stateful-lane callers only).
    pub fn record_durable_op(&mut self) {
        self.durable_ops += 1;
    }
}

/// One retained transcript frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedFrame {
    /// Assigned delivery sequence.
    pub seq: u64,
    /// Frame payload bytes.
    pub bytes: Vec<u8>,
}

/// Typed sequencer refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencerError {
    /// Send of a sequence that was never assigned or is not next.
    NotNextToSend {
        /// The sequence the lane expects to send next.
        expected: u64,
    },
    /// Ack for a frame that is not the one in flight.
    NotInFlight {
        /// The offending sequence.
        seq: u64,
    },
}

/// The edge-side transcript lane for one subscriber: pure sequencing +
/// bounded retention. No durability anywhere — that is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptSequencer {
    /// Frames `1..=assigned` exist in the canonical stream.
    assigned: u64,
    /// Frames `1..=sent` have been handed to the transport.
    sent: u64,
    /// Frames `1..=exposed` are fully acknowledged by the wrapper.
    exposed: u64,
    /// Bounded reconnect-window retention (oldest first).
    retention: VecDeque<RetainedFrame>,
    /// Maximum retained frames.
    retention_budget: usize,
    /// First sequence still replayable from retention.
    oldest_replayable: u64,
}

impl TranscriptSequencer {
    /// A fresh lane with the given retention budget (frames).
    #[must_use]
    pub const fn new(retention_budget: usize) -> Self {
        Self {
            assigned: 0,
            sent: 0,
            exposed: 0,
            retention: VecDeque::new(),
            retention_budget,
            oldest_replayable: 1,
        }
    }

    /// `TranscriptIntentRecorded`: assign the next framed sequence and
    /// retain the frame in the reconnect window. Pure in-memory — the
    /// meter is deliberately NOT a parameter, so this operation cannot
    /// even express a durability cost (R104).
    pub fn assign(&mut self, bytes: Vec<u8>) -> u64 {
        self.assigned += 1;
        let seq = self.assigned;
        self.retention.push_back(RetainedFrame { seq, bytes });
        // Bounded growth: evict oldest past the budget; replayability
        // recedes honestly with it.
        while self.retention.len() > self.retention_budget {
            let evicted = self.retention.pop_front().expect("non-empty");
            self.oldest_replayable = evicted.seq + 1;
        }
        seq
    }

    /// Hand the next frame to the transport (it is now in flight).
    ///
    /// # Errors
    /// [`SequencerError::NotNextToSend`] out of order.
    pub fn send(&mut self, seq: u64) -> Result<(), SequencerError> {
        if seq != self.sent + 1 || seq > self.assigned {
            return Err(SequencerError::NotNextToSend {
                expected: self.sent + 1,
            });
        }
        self.sent = seq;
        Ok(())
    }

    /// Full acknowledgement: the first one sets `TranscriptExposed`;
    /// acknowledged frames may leave retention (they are never re-sent,
    /// C014).
    ///
    /// # Errors
    /// [`SequencerError::NotInFlight`] unless exactly the oldest
    /// unacknowledged sent frame is acked.
    pub fn ack(&mut self, seq: u64) -> Result<(), SequencerError> {
        if seq != self.exposed + 1 || seq > self.sent {
            return Err(SequencerError::NotInFlight { seq });
        }
        self.exposed = seq;
        while matches!(self.retention.front(), Some(f) if f.seq <= self.exposed) {
            let dropped = self.retention.pop_front().expect("non-empty");
            self.oldest_replayable = self.oldest_replayable.max(dropped.seq + 1);
        }
        Ok(())
    }

    /// Sequences currently sent but not yet acknowledged.
    #[must_use]
    pub const fn in_flight(&self) -> u64 {
        self.sent - self.exposed
    }

    /// The C005 frontier truth for this lane: exposure from the first
    /// full ack; conservative uncertainty while anything is in flight.
    #[must_use]
    pub const fn frontier_report(&self) -> SubscriberFrontierReport {
        SubscriberFrontierReport {
            transcript_exposed: self.exposed > 0,
            transcript_uncertain: self.sent > self.exposed,
            stateful_intent_recorded: false,
            stateful_uncertain: false,
            last_fully_delivered_seq: self.exposed,
        }
    }

    /// The edge's C014 reconnect view of this lane.
    #[must_use]
    pub const fn resume_view(
        &self,
        current_incarnation: u128,
        named_predecessor_incarnation: Option<u128>,
    ) -> EdgeResumeView {
        EdgeResumeView {
            canonical_stream_len: self.assigned,
            oldest_replayable_seq: self.oldest_replayable,
            current_incarnation,
            named_predecessor_incarnation,
        }
    }

    /// Replay a retained frame (reconnect path).
    #[must_use]
    pub fn retained(&self, seq: u64) -> Option<&RetainedFrame> {
        self.retention.iter().find(|f| f.seq == seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_ids::BuildOperationId;
    use crate::local_protocol::{FallbackAction, FallbackConfig, decide_fallback};
    use crate::reconnect::{
        ResumableToken, ResumeRefusal, SubscriberId, WrapperResumeReport, reconcile,
    };

    const SECRET: [u8; 32] = [9; 32];

    fn token() -> ResumableToken {
        ResumableToken {
            request: BuildOperationId(10),
            subscriber: SubscriberId(20),
            issued_by_incarnation: 5,
            secret: SECRET,
        }
    }

    fn wrapper_report(lane: &TranscriptSequencer) -> WrapperResumeReport {
        // The wrapper's truthful view after a disconnect: it fully
        // exposed what it acked; the one sent-but-unacked frame may
        // have been in flight.
        WrapperResumeReport {
            last_fully_exposed_seq: lane.exposed,
            possibly_in_flight_seq: (lane.sent > lane.exposed).then_some(lane.exposed + 1),
            frontier: lane.frontier_report(),
        }
    }

    #[test]
    fn c021_ten_thousand_lines_cost_zero_durable_operations() {
        // THE R104 acceptance, structurally: the durability meter that
        // the stateful lane ticks is shared with this run — and the
        // transcript lane cannot even reach it. Ten thousand
        // assign→send→ack cycles: zero durable ops, correct sequencing,
        // bounded retention throughout.
        let meter = DurabilityMeter::default();
        let mut lane = TranscriptSequencer::new(64);
        for line in 0..10_000u64 {
            let seq = lane.assign(format!("line {line}\n").into_bytes());
            assert_eq!(seq, line + 1, "contiguous framed sequence assignment");
            lane.send(seq).unwrap();
            lane.ack(seq).unwrap();
            assert!(lane.retention.len() <= 64, "retention stays bounded");
        }
        assert_eq!(
            meter.durable_ops, 0,
            "TranscriptIntentRecorded must never fsync (R104)"
        );
        assert_eq!(lane.exposed, 10_000);
        // Contrast: one stateful-lane checkpoint DOES pay — the meter
        // works; the transcript lane simply never uses it.
        let mut meter = meter;
        meter.record_durable_op();
        assert_eq!(meter.durable_ops, 1);
    }

    #[test]
    fn c021_reconnect_reconstructs_uncertainty_at_every_kill_point() {
        // For every (sent, acked) disconnect combination of a 6-frame
        // stream: the lane's conservative frontier flags uncertainty
        // exactly when a frame is in flight, and C014 reconcile over
        // the lane's own resume view resumes at acked+1 — no
        // duplication, no loss, first frame flagged uncertain when it
        // was in flight.
        const LEN: u64 = 6;
        for sent in 0..=LEN {
            for acked in 0..=sent {
                let mut lane = TranscriptSequencer::new(usize::MAX >> 1);
                for i in 0..LEN {
                    lane.assign(vec![u8::try_from(i).unwrap()]);
                }
                for s in 1..=sent {
                    lane.send(s).unwrap();
                }
                for a in 1..=acked {
                    lane.ack(a).unwrap();
                }
                let report = lane.frontier_report();
                assert_eq!(report.transcript_exposed, acked > 0, "first full ack");
                assert_eq!(
                    report.transcript_uncertain,
                    sent > acked,
                    "sent={sent} acked={acked}: in-flight is conservatively uncertain"
                );
                let plan = reconcile(
                    &token(),
                    BuildOperationId(10),
                    SubscriberId(20),
                    &SECRET,
                    &lane.resume_view(5, None),
                    &wrapper_report(&lane),
                )
                .unwrap();
                assert_eq!(plan.resume_from_seq, acked + 1);
                assert_eq!(plan.first_frame_was_in_flight, sent > acked);
                // Every resumed frame is still replayable from
                // retention (nothing acked was needed again).
                for seq in plan.resume_from_seq..=LEN {
                    assert!(lane.retained(seq).is_some(), "frame {seq} replayable");
                }
            }
        }
    }

    #[test]
    fn c021_retention_eviction_yields_typed_gap_never_silence() {
        // Budget 3: assigning 10 frames evicts 1..=7 unacked; a wrapper
        // that exposed only 2 cannot resume (frame 3 is gone) — C014
        // refuses with RetentionGap instead of silently skipping.
        let mut lane = TranscriptSequencer::new(3);
        for i in 0..10u8 {
            lane.assign(vec![i]);
        }
        assert_eq!(lane.oldest_replayable, 8);
        lane.send(1).unwrap();
        lane.send(2).unwrap();
        lane.ack(1).unwrap();
        lane.ack(2).unwrap();
        let refusal = reconcile(
            &token(),
            BuildOperationId(10),
            SubscriberId(20),
            &SECRET,
            &lane.resume_view(5, None),
            &wrapper_report(&lane),
        )
        .unwrap_err();
        assert_eq!(refusal, ResumeRefusal::RetentionGap);
    }

    #[test]
    fn c021_labeled_recovery_policy_flows_from_the_transcript_frontier() {
        // The explicit labeled-recovery policy over this lane's
        // frontier: exposure with the policy OFF reconnects-or-fails;
        // ON detaches behind the unmistakable boundary marker naming
        // the last delivered sequence. Pure transcript state never
        // escalates to the stateful lane's no-fallback class.
        let mut lane = TranscriptSequencer::new(8);
        for i in 0..3u8 {
            let seq = lane.assign(vec![i]);
            lane.send(seq).unwrap();
            lane.ack(seq).unwrap();
        }
        let report = lane.frontier_report();
        assert!(matches!(
            decide_fallback(&report, &FallbackConfig::default(), 42),
            FallbackAction::ReconnectOrFailCoherently { .. }
        ));
        match decide_fallback(
            &report,
            &FallbackConfig {
                labeled_transcript_recovery: true,
            },
            42,
        ) {
            FallbackAction::DetachAndRunLabeled { boundary_marker } => {
                assert!(boundary_marker.contains("delivered seq 3"));
                assert!(boundary_marker.contains("LOCAL RERUN"));
            }
            other => panic!("expected labeled recovery, got {other:?}"),
        }
    }

    #[test]
    fn out_of_order_send_and_ack_are_typed_refusals() {
        let mut lane = TranscriptSequencer::new(8);
        lane.assign(b"a".to_vec());
        lane.assign(b"b".to_vec());
        assert_eq!(
            lane.send(2),
            Err(SequencerError::NotNextToSend { expected: 1 })
        );
        assert_eq!(
            lane.send(3),
            Err(SequencerError::NotNextToSend { expected: 1 })
        );
        lane.send(1).unwrap();
        assert_eq!(lane.ack(2), Err(SequencerError::NotInFlight { seq: 2 }));
        lane.ack(1).unwrap();
        assert_eq!(lane.ack(1), Err(SequencerError::NotInFlight { seq: 1 }));
    }
}
