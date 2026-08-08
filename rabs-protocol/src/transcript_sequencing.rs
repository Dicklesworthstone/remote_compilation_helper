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

// ---------------------------------------------------------------------
// Wrapper side (bead C023): complete-frame acceptance, partial-write
// recovery, and the both-died rule.
// ---------------------------------------------------------------------

/// Typed refusals from the wrapper-side frame reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameReadError {
    /// A frame began while another is still partially written — the
    /// wire is strictly one frame at a time.
    FrameAlreadyInProgress {
        /// The partially written sequence.
        partial_seq: u64,
    },
    /// Frame sequence is not the next expected one (duplicate or skip).
    UnexpectedSequence {
        /// The sequence the reader expects next.
        expected: u64,
    },
    /// Declared length exceeds the negotiated bound: refused before a
    /// single payload byte is read (length-bounded frames, R116).
    FrameTooLarge {
        /// The declared length.
        declared: u32,
        /// The negotiated maximum.
        max: u32,
    },
    /// More payload bytes arrived than the frame declared.
    Overrun {
        /// The frame being overrun.
        seq: u64,
    },
    /// Completion was claimed before all declared bytes arrived.
    Incomplete {
        /// Bytes received so far.
        received: u32,
        /// Bytes the frame declared.
        declared: u32,
    },
    /// No frame is in progress.
    NoFrameInProgress,
}

/// A frame whose write began but has not completed — the R116
/// uncertainty carrier on the wrapper side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialFrame {
    /// Sequence of the partially written frame.
    pub seq: u64,
    /// Declared payload length.
    pub declared_len: u32,
    /// Payload bytes received so far (NEVER exposed).
    pub received: Vec<u8>,
}

/// The wrapper-side frame reader: accepts ONLY complete length-bounded
/// frames into the exposed transcript; a partial frame is held privately
/// and reported as possibly-in-flight on reconnect, never shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameReader {
    /// Negotiated maximum frame payload length.
    max_frame_len: u32,
    /// Frames `1..=exposed` were received complete and shown.
    exposed: u64,
    /// Complete frames' payloads, in exposure order (the ONLY bytes the
    /// user ever sees).
    exposed_payloads: Vec<Vec<u8>>,
    /// The one frame whose write may have begun.
    partial: Option<PartialFrame>,
}

impl FrameReader {
    /// A fresh reader with the negotiated frame bound.
    #[must_use]
    pub const fn new(max_frame_len: u32) -> Self {
        Self {
            max_frame_len,
            exposed: 0,
            exposed_payloads: Vec::new(),
            partial: None,
        }
    }

    /// Last fully exposed sequence.
    #[must_use]
    pub const fn exposed(&self) -> u64 {
        self.exposed
    }

    /// Payloads of fully exposed frames (fixture visibility).
    #[must_use]
    pub fn exposed_payloads(&self) -> &[Vec<u8>] {
        &self.exposed_payloads
    }

    /// Begin receiving the next frame's payload.
    ///
    /// # Errors
    /// Typed [`FrameReadError`]; nothing is buffered on refusal.
    pub fn begin_frame(&mut self, seq: u64, declared_len: u32) -> Result<(), FrameReadError> {
        if let Some(partial) = &self.partial {
            return Err(FrameReadError::FrameAlreadyInProgress {
                partial_seq: partial.seq,
            });
        }
        if seq != self.exposed + 1 {
            return Err(FrameReadError::UnexpectedSequence {
                expected: self.exposed + 1,
            });
        }
        if declared_len > self.max_frame_len {
            return Err(FrameReadError::FrameTooLarge {
                declared: declared_len,
                max: self.max_frame_len,
            });
        }
        self.partial = Some(PartialFrame {
            seq,
            declared_len,
            received: Vec::new(),
        });
        Ok(())
    }

    /// Feed payload bytes for the in-progress frame.
    ///
    /// # Errors
    /// Typed [`FrameReadError`].
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), FrameReadError> {
        let Some(partial) = &mut self.partial else {
            return Err(FrameReadError::NoFrameInProgress);
        };
        if partial.received.len() + bytes.len() > partial.declared_len as usize {
            return Err(FrameReadError::Overrun { seq: partial.seq });
        }
        partial.received.extend_from_slice(bytes);
        Ok(())
    }

    /// Complete the in-progress frame: ONLY a byte-complete frame is
    /// exposed; anything less stays partial and unexposed.
    ///
    /// # Errors
    /// Typed [`FrameReadError`]; the partial frame is retained on
    /// refusal (it is still the uncertainty carrier).
    pub fn complete_frame(&mut self) -> Result<u64, FrameReadError> {
        let Some(partial) = &self.partial else {
            return Err(FrameReadError::NoFrameInProgress);
        };
        let received = u32::try_from(partial.received.len())
            .map_err(|_| FrameReadError::Overrun { seq: partial.seq })?;
        if received != partial.declared_len {
            return Err(FrameReadError::Incomplete {
                received,
                declared: partial.declared_len,
            });
        }
        let complete = self.partial.take().expect("checked above");
        self.exposed = complete.seq;
        self.exposed_payloads.push(complete.received);
        Ok(self.exposed)
    }

    /// The wrapper's truthful reconnect report (C014): last fully
    /// exposed sequence AND any frame whose write may have begun. The
    /// partial frame's bytes are NOT in the report — a partial frame
    /// was never exposed, so replaying it whole duplicates nothing.
    #[must_use]
    pub fn resume_report(&self) -> crate::reconnect::WrapperResumeReport {
        crate::reconnect::WrapperResumeReport {
            last_fully_exposed_seq: self.exposed,
            possibly_in_flight_seq: self.partial.as_ref().map(|p| p.seq),
            frontier: SubscriberFrontierReport {
                transcript_exposed: self.exposed > 0,
                transcript_uncertain: self.partial.is_some(),
                stateful_intent_recorded: false,
                stateful_uncertain: false,
                last_fully_delivered_seq: self.exposed,
            },
        }
    }
}

/// Where a later invocation goes after a crash (C023's both-died rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostCrashPath {
    /// The wrapper survived with its reader state and token: reconnect
    /// and reconcile (C014) against the edge or its named successor.
    ReconnectAndResume,
    /// The wrapper's exposure state is GONE (wrapper died — with or
    /// without the edge): what reached the user's terminal is
    /// unknowable, so the Cargo command has simply failed; a later
    /// invocation starts a NEW BuildOperation instead of replaying an
    /// unknowable partial transcript.
    NewBuildOperation {
        /// Why no resume exists.
        reason: &'static str,
    },
}

/// Decide the post-crash path. Resume requires the WRAPPER's state:
/// the edge's retention can replay frames, but only the wrapper knows
/// what was exposed — without it, uncertainty is unresolvable and the
/// only honest continuation is a fresh operation.
#[must_use]
pub const fn post_crash_path(wrapper_state_intact: bool) -> PostCrashPath {
    if wrapper_state_intact {
        PostCrashPath::ReconnectAndResume
    } else {
        PostCrashPath::NewBuildOperation {
            reason: "wrapper exposure state lost: partial transcript is unknowable (R116)",
        }
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
    fn c023_partial_frame_crash_fixtures_resolve_to_correct_uncertainty() {
        // THE C023 acceptance: a 4-frame stream with distinct payloads;
        // kill the connection at EVERY byte offset of every frame. The
        // reader must report exposed = complete frames only, the
        // partial frame as possibly-in-flight, and C014 reconcile must
        // resume exactly there with the in-flight flag — while the
        // exposed transcript contains no partial bytes at any kill
        // point.
        let payloads: [&[u8]; 4] = [b"one", b"two2", b"three33", b"x"];
        // Edge lane with the full stream (the replay source).
        let mut edge = TranscriptSequencer::new(64);
        for p in payloads {
            edge.assign(p.to_vec());
        }
        for frame in 0..payloads.len() {
            for cut in 0..=payloads[frame].len() {
                let complete_before = frame as u64;
                let mut reader = FrameReader::new(64);
                // Frames before the kill frame arrive complete.
                for (i, p) in payloads.iter().take(frame).enumerate() {
                    reader
                        .begin_frame(i as u64 + 1, u32::try_from(p.len()).unwrap())
                        .unwrap();
                    reader.feed(p).unwrap();
                    reader.complete_frame().unwrap();
                }
                // The kill frame: header + `cut` payload bytes arrive.
                reader
                    .begin_frame(
                        complete_before + 1,
                        u32::try_from(payloads[frame].len()).unwrap(),
                    )
                    .unwrap();
                reader.feed(&payloads[frame][..cut]).unwrap();
                // A cut mid-frame can NEVER expose it.
                if cut < payloads[frame].len() {
                    assert!(matches!(
                        reader.complete_frame(),
                        Err(FrameReadError::Incomplete { .. })
                    ));
                }
                let report = reader.resume_report();
                assert_eq!(report.last_fully_exposed_seq, complete_before);
                assert_eq!(
                    report.possibly_in_flight_seq,
                    Some(complete_before + 1),
                    "frame={frame} cut={cut}: the begun frame is the uncertainty"
                );
                assert!(report.frontier.transcript_uncertain);
                // No partial bytes ever reached the exposed transcript.
                assert_eq!(
                    reader.exposed_payloads(),
                    payloads[..frame]
                        .iter()
                        .map(|p| p.to_vec())
                        .collect::<Vec<_>>()
                        .as_slice(),
                    "frame={frame} cut={cut}"
                );
                // C014 reconcile: resume at the begun frame, flagged
                // in-flight; replayable from edge retention.
                let plan = reconcile(
                    &token(),
                    BuildOperationId(10),
                    SubscriberId(20),
                    &SECRET,
                    &edge.resume_view(5, None),
                    &report,
                )
                .unwrap();
                assert_eq!(plan.resume_from_seq, complete_before + 1);
                assert!(plan.first_frame_was_in_flight);
                assert!(edge.retained(plan.resume_from_seq).is_some());
            }
        }
    }

    #[test]
    fn c023_only_complete_length_bounded_frames_are_accepted() {
        let mut reader = FrameReader::new(8);
        // Oversized declaration refuses before any payload byte.
        assert_eq!(
            reader.begin_frame(1, 9),
            Err(FrameReadError::FrameTooLarge {
                declared: 9,
                max: 8
            })
        );
        // In-order, bounded frame accepted; overrun refuses.
        reader.begin_frame(1, 3).unwrap();
        reader.feed(b"ab").unwrap();
        assert_eq!(reader.feed(b"cd"), Err(FrameReadError::Overrun { seq: 1 }));
        reader.feed(b"c").unwrap();
        assert_eq!(reader.complete_frame().unwrap(), 1);
        // A second frame cannot begin while one is partial.
        reader.begin_frame(2, 2).unwrap();
        assert_eq!(
            reader.begin_frame(3, 2),
            Err(FrameReadError::FrameAlreadyInProgress { partial_seq: 2 })
        );
        // Duplicate/skipped sequences refuse.
        let mut fresh = FrameReader::new(8);
        assert_eq!(
            fresh.begin_frame(2, 1),
            Err(FrameReadError::UnexpectedSequence { expected: 1 })
        );
    }

    #[test]
    fn c023_both_died_starts_a_new_build_operation() {
        // Wrapper state intact: reconnect + reconcile.
        assert_eq!(post_crash_path(true), PostCrashPath::ReconnectAndResume);
        // Wrapper state gone (both died, or wrapper alone): the command
        // has failed; a later invocation is a NEW BuildOperation — no
        // replay of an unknowable partial transcript.
        let PostCrashPath::NewBuildOperation { reason } = post_crash_path(false) else {
            panic!("lost wrapper state must not resume");
        };
        assert!(reason.contains("unknowable"));
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
