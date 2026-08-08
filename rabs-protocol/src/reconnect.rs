//! Resumable request/subscriber tokens and edge-restart reconnect
//! reconciliation (bead C014; risks R97/R116/R118; plan §85).
//!
//! A wrapper that loses its edge connection mid-stream holds a
//! [`ResumableToken`] issued at admission. On reconnect it presents the
//! token plus a [`WrapperResumeReport`] — its last FULLY exposed
//! delivery sequence and the one frame that may have been in flight —
//! and the edge reconciles both frontiers against its own view before
//! any delivery resumes:
//!
//! - frames at or below the wrapper's exposed frontier are NEVER
//!   re-sent (no duplication — the framing discipline means a partial
//!   frame was never exposed, R116);
//! - delivery resumes exactly at `exposed + 1`; if the edge can no
//!   longer replay from there, the resume is a typed refusal, never a
//!   silent gap (no loss);
//! - a report that contradicts the canonical stream (claiming exposure
//!   beyond what exists, or an in-flight frame that is not the next
//!   frame) is refused coherently — uncertainty never becomes a guess;
//! - across an edge restart, the token's issuing incarnation must be
//!   the CURRENT incarnation or its ONE named predecessor (the H038
//!   edge-handoff model, R118); anything else is refused.
//!
//! This module is the pure reconciliation core: sockets, ledgers, and
//! frame transport live in the edge daemon.

use crate::durable_ids::BuildOperationId;
use crate::local_protocol::SubscriberFrontierReport;

/// Durable subscriber identity within one build operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriberId(pub u128);

/// Bearer token issued at admission; the wrapper stores it and presents
/// it on every reconnect. Possession of the exact secret (plus matching
/// bindings) is the resume credential on the local socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumableToken {
    /// The build operation this token belongs to.
    pub request: BuildOperationId,
    /// The subscriber this token belongs to.
    pub subscriber: SubscriberId,
    /// Edge incarnation that issued the token.
    pub issued_by_incarnation: u128,
    /// Unforgeable bearer secret.
    pub secret: [u8; 32],
}

/// What the wrapper reports on reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapperResumeReport {
    /// Last delivery sequence FULLY exposed (received, complete, acked).
    pub last_fully_exposed_seq: u64,
    /// The one frame that may have been in flight when the connection
    /// died (`None` when the wrapper saw no partial frame).
    pub possibly_in_flight_seq: Option<u64>,
    /// The wrapper's exposure frontiers (drives fallback permission,
    /// C005).
    pub frontier: SubscriberFrontierReport,
}

/// The edge's view at reconnect time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeResumeView {
    /// Frames `1..=len` exist in the canonical action stream.
    pub canonical_stream_len: u64,
    /// The edge can replay frames from this sequence onward (`1` =
    /// everything is still replayable).
    pub oldest_replayable_seq: u64,
    /// The incarnation answering this reconnect.
    pub current_incarnation: u128,
    /// The ONE named predecessor during a bounded handoff window, if
    /// any (H038 edge-handoff model).
    pub named_predecessor_incarnation: Option<u128>,
}

/// Typed coherent refusals: the wrapper gets a reason, never a stall,
/// a duplicate, or a silent gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeRefusal {
    /// Token bound to a different build operation.
    TokenRequestMismatch,
    /// Token bound to a different subscriber.
    TokenSubscriberMismatch,
    /// Bearer secret does not match.
    TokenSecretMismatch,
    /// Token issued by an incarnation that is neither current nor the
    /// named predecessor (R118).
    UnknownIssuerIncarnation,
    /// The report claims exposure or in-flight state the canonical
    /// stream cannot support.
    FrontierContradiction,
    /// The edge can no longer replay from the resume point; resuming
    /// would silently lose frames.
    RetentionGap,
}

/// A validated resume: where delivery restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePlan {
    /// First sequence the edge will (re)send.
    pub resume_from_seq: u64,
    /// Whether `resume_from_seq` was possibly in flight at disconnect —
    /// it stays delivery-uncertain until acked again (R116 accounting).
    pub first_frame_was_in_flight: bool,
}

/// Reconcile a reconnect attempt. Every check is a typed refusal;
/// success names the exact resume point.
///
/// # Errors
/// A [`ResumeRefusal`]; refusals resume nothing.
pub fn reconcile(
    token: &ResumableToken,
    expected_request: BuildOperationId,
    expected_subscriber: SubscriberId,
    expected_secret: &[u8; 32],
    view: &EdgeResumeView,
    report: &WrapperResumeReport,
) -> Result<ResumePlan, ResumeRefusal> {
    if token.request != expected_request {
        return Err(ResumeRefusal::TokenRequestMismatch);
    }
    if token.subscriber != expected_subscriber {
        return Err(ResumeRefusal::TokenSubscriberMismatch);
    }
    if token.secret != *expected_secret {
        return Err(ResumeRefusal::TokenSecretMismatch);
    }
    let issuer_known = token.issued_by_incarnation == view.current_incarnation
        || view.named_predecessor_incarnation == Some(token.issued_by_incarnation);
    if !issuer_known {
        return Err(ResumeRefusal::UnknownIssuerIncarnation);
    }
    if report.last_fully_exposed_seq > view.canonical_stream_len {
        return Err(ResumeRefusal::FrontierContradiction);
    }
    if let Some(in_flight) = report.possibly_in_flight_seq {
        // The only frame that can be in flight is the NEXT one, and it
        // must exist in the canonical stream.
        if in_flight != report.last_fully_exposed_seq + 1 || in_flight > view.canonical_stream_len {
            return Err(ResumeRefusal::FrontierContradiction);
        }
    }
    let resume_from_seq = report.last_fully_exposed_seq + 1;
    if view.oldest_replayable_seq > resume_from_seq {
        return Err(ResumeRefusal::RetentionGap);
    }
    Ok(ResumePlan {
        resume_from_seq,
        first_frame_was_in_flight: report.possibly_in_flight_seq == Some(resume_from_seq),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7; 32];

    fn token() -> ResumableToken {
        ResumableToken {
            request: BuildOperationId(10),
            subscriber: SubscriberId(20),
            issued_by_incarnation: 5,
            secret: SECRET,
        }
    }

    fn view(len: u64) -> EdgeResumeView {
        EdgeResumeView {
            canonical_stream_len: len,
            oldest_replayable_seq: 1,
            current_incarnation: 5,
            named_predecessor_incarnation: None,
        }
    }

    fn report(exposed: u64, in_flight: Option<u64>) -> WrapperResumeReport {
        WrapperResumeReport {
            last_fully_exposed_seq: exposed,
            possibly_in_flight_seq: in_flight,
            frontier: SubscriberFrontierReport {
                transcript_exposed: exposed > 0,
                transcript_uncertain: in_flight.is_some(),
                ..Default::default()
            },
        }
    }

    fn reconcile_ok(
        view: &EdgeResumeView,
        report: &WrapperResumeReport,
    ) -> Result<ResumePlan, ResumeRefusal> {
        reconcile(
            &token(),
            BuildOperationId(10),
            SubscriberId(20),
            &SECRET,
            view,
            report,
        )
    }

    #[test]
    fn kill_edge_at_every_point_resumes_without_duplication_or_loss() {
        // THE C014 acceptance, as an exhaustive kill-point fixture: a
        // 5-frame stream, killed at every (sent, acked) combination.
        // The wrapper exposed exactly frames 1..=acked; the plan must
        // replay exactly acked+1..=len — union covers every frame once,
        // intersection is empty.
        const LEN: u64 = 5;
        for sent in 0..=LEN {
            for acked in 0..=sent {
                let in_flight = (sent > acked).then_some(acked + 1);
                let plan = reconcile_ok(&view(LEN), &report(acked, in_flight)).unwrap();
                assert_eq!(plan.resume_from_seq, acked + 1, "sent={sent} acked={acked}");
                assert_eq!(plan.first_frame_was_in_flight, in_flight.is_some());
                // Exposed ∪ replayed == 1..=LEN exactly once.
                let exposed: Vec<u64> = (1..=acked).collect();
                let replayed: Vec<u64> = (plan.resume_from_seq..=LEN).collect();
                let mut union = exposed.clone();
                union.extend(&replayed);
                assert_eq!(union, (1..=LEN).collect::<Vec<u64>>());
                assert!(exposed.iter().all(|frame| !replayed.contains(frame)));
            }
        }
    }

    #[test]
    fn retention_gap_refuses_instead_of_silently_losing_frames() {
        // The edge dropped frames up to 4; a wrapper that only exposed
        // 2 would silently lose frame 3 — refuse coherently instead.
        let mut gapped = view(5);
        gapped.oldest_replayable_seq = 4;
        assert_eq!(
            reconcile_ok(&gapped, &report(2, None)),
            Err(ResumeRefusal::RetentionGap)
        );
        // A wrapper that already exposed 3 resumes fine at 4.
        assert_eq!(
            reconcile_ok(&gapped, &report(3, None))
                .unwrap()
                .resume_from_seq,
            4
        );
    }

    #[test]
    fn contradictory_reports_are_refused_coherently() {
        // Claiming exposure beyond the canonical stream.
        assert_eq!(
            reconcile_ok(&view(5), &report(6, None)),
            Err(ResumeRefusal::FrontierContradiction)
        );
        // An in-flight frame that is not the next frame.
        assert_eq!(
            reconcile_ok(&view(5), &report(2, Some(4))),
            Err(ResumeRefusal::FrontierContradiction)
        );
        // An in-flight frame beyond the canonical stream.
        assert_eq!(
            reconcile_ok(&view(5), &report(5, Some(6))),
            Err(ResumeRefusal::FrontierContradiction)
        );
    }

    #[test]
    fn token_bindings_are_each_typed_refusals() {
        let t = token();
        assert_eq!(
            reconcile(
                &t,
                BuildOperationId(11),
                SubscriberId(20),
                &SECRET,
                &view(5),
                &report(0, None),
            ),
            Err(ResumeRefusal::TokenRequestMismatch)
        );
        assert_eq!(
            reconcile(
                &t,
                BuildOperationId(10),
                SubscriberId(21),
                &SECRET,
                &view(5),
                &report(0, None),
            ),
            Err(ResumeRefusal::TokenSubscriberMismatch)
        );
        assert_eq!(
            reconcile(
                &t,
                BuildOperationId(10),
                SubscriberId(20),
                &[8; 32],
                &view(5),
                &report(0, None),
            ),
            Err(ResumeRefusal::TokenSecretMismatch)
        );
    }

    #[test]
    fn edge_restart_honors_exactly_one_named_predecessor() {
        // Token issued by incarnation 5; the edge restarted as 6 with 5
        // as the named predecessor: resume works through the handoff.
        let handed_off = EdgeResumeView {
            current_incarnation: 6,
            named_predecessor_incarnation: Some(5),
            ..view(5)
        };
        assert!(reconcile_ok(&handed_off, &report(2, None)).is_ok());
        // Without the named predecessor, the issuer is unknown.
        let cold = EdgeResumeView {
            current_incarnation: 6,
            named_predecessor_incarnation: None,
            ..view(5)
        };
        assert_eq!(
            reconcile_ok(&cold, &report(2, None)),
            Err(ResumeRefusal::UnknownIssuerIncarnation)
        );
        // A predecessor-of-predecessor is NOT honored (exactly one).
        let two_back = EdgeResumeView {
            current_incarnation: 7,
            named_predecessor_incarnation: Some(6),
            ..view(5)
        };
        assert_eq!(
            reconcile_ok(&two_back, &report(2, None)),
            Err(ResumeRefusal::UnknownIssuerIncarnation)
        );
    }

    #[test]
    fn fresh_stream_resumes_from_the_beginning() {
        let plan = reconcile_ok(&view(5), &report(0, None)).unwrap();
        assert_eq!(plan.resume_from_seq, 1);
        assert!(!plan.first_frame_was_in_flight);
    }
}
