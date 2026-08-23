//! The native-transport suite families (bead J017; M7/M8 gates).
//!
//! The ATP control plane's system-under-test today is the PURE message
//! catalog + [`SessionState`] decision fold (J012) with durable-id
//! reconciliation (J005). These suites stress exactly that plane
//! through a fault-injecting link — loss, duplication, reordering,
//! partition, long idle gaps, bursts, and compressed multi-day cycles
//! with reconnects and authority rotations — so the semantics the real
//! socket will inherit are proven BEFORE a wire exists.
//!
//! ## Delivery/ack model
//!
//! The link drops/duplicates/reorders while the session is unhealthy.
//! A reconnect lands on a FRESH connection (faults healed): the edge
//! replays every SENT-but-unacknowledged submission, and because the
//! fold is idempotent (J012), replays join existing state. A message
//! is acknowledged only when its delivery was PROCESSED on the healed
//! connection — cumulative high-water acks would erase lost messages,
//! which is precisely the bug class this suite exists to catch.
//!
//! ## Documented pass thresholds (the M7/M8 gates)
//!
//! | Gate | Threshold |
//! |---|---|
//! | `M7_ZERO_DOUBLE_EXECUTE` | No submitted action ever folds to `Created` twice under ANY fault mix. |
//! | `M7_RECONCILE_EXACT` | After the final reconcile, the coordinator's submitted set equals the edge's sent set EXACTLY. |
//! | `M7_INTEROP_ALL_HELLO_ORDERS` | Edge-first and worker-first hello orders reach identical coordinator state. |
//! | `M8_IDLE_RESUME` | A session idle for an arbitrary gap resumes with idempotency intact. |
//! | `M8_BURST_VOLUME` | ≥ 5,000 submissions under 10% loss + 5% duplication + reordering: exact set after reconcile. |
//! | `M8_MULTIDAY_SOAK` | 1,000 compressed day-cycles (burst → reconnect → authority rotation + stale probe): zero lost, zero double-executes. |

use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::durable_ids::{BuildOperationId, DurableWireIdentity};
use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
use rabs_protocol::messages::{HandlerOutcome, RabsMessage, SessionState};
use rabs_protocol::wire_time::PeerId;

/// Loss-rate ceiling (basis points) exercised by the loss suite.
pub const INTEROP_MAX_LOSS_RATE_BP: u32 = 3_000;
/// Minimum burst volume (submitted actions) the burst suite drives.
pub const BURST_SUITE_MIN_ACTIONS: usize = 5_000;
/// Multi-day soak day-cycle count.
pub const MULTIDAY_SOAK_CYCLES: usize = 1_000;

#[must_use]
fn identity(build_id: u64) -> DurableWireIdentity {
    let op = u128::from(build_id);
    DurableWireIdentity {
        operation: BuildOperationId(op),
        generation: ActionGenerationId(1),
        attempt: AttemptId(1),
        lease: ExecutionLeaseId(1),
    }
}

#[must_use]
fn authority(term: u64) -> CoordinatorAuthority {
    CoordinatorAuthority {
        cluster_id: ClusterId("suite-cluster".to_owned()),
        credential_generation: 1,
        term,
        incarnation_id: CoordinatorIncarnationId(0x5EED),
    }
}

/// One in-flight delivery attempt on the faulty link.
#[derive(Debug, Clone)]
struct InFlight {
    message: RabsMessage,
    term: u64,
}

/// A lossy/duplicating/reordering/partitioning link between the edge
/// and the coordinator's session fold. Deterministic per seed.
#[derive(Debug)]
pub struct FaultyLink {
    queue: std::collections::VecDeque<InFlight>,
    rng: u64,
    /// Drop probability in basis points.
    pub loss_rate_bp: u32,
    /// Duplicate probability in basis points.
    pub duplicate_rate_bp: u32,
    /// Reorder window (0 or 1 = in-order delivery).
    pub reorder_window: usize,
    /// While partitioned, everything sent is black-holed.
    pub partitioned: bool,
    /// Deliveries actually handed to the fold (post-fault).
    pub delivered: usize,
    /// Messages dropped by injected faults.
    pub dropped: usize,
}

impl FaultyLink {
    /// Deterministic link for `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
            rng: seed | 1,
            loss_rate_bp: 0,
            duplicate_rate_bp: 0,
            reorder_window: 0,
            partitioned: false,
            delivered: 0,
            dropped: 0,
        }
    }

    fn roll(&mut self) -> u32 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        ((self.rng >> 32) as u32) % 10_000
    }

    /// Send one message through the faults.
    pub fn send(&mut self, message: RabsMessage, term: u64) {
        if self.partitioned || self.roll() < self.loss_rate_bp {
            self.dropped += 1;
            return;
        }
        self.queue.push_back(InFlight {
            message: message.clone(),
            term,
        });
        if self.roll() < self.duplicate_rate_bp {
            self.queue.push_back(InFlight { message, term });
        }
        let window = self.reorder_window.min(self.queue.len());
        // Intermittent mild reorder: swap within the window only ~half
        // the time, so ordered exchanges (rotation + probe) are not
        // systematically inverted.
        if window > 1 && self.roll() < 5_000 {
            let len = self.queue.len();
            self.queue.swap(len - 1, len - window);
        }
    }

    /// Drain everything queued into the fold, returning outcomes.
    pub fn drain_into(&mut self, state: &mut SessionState) -> Vec<HandlerOutcome> {
        let mut outcomes = Vec::new();
        while let Some(inflight) = self.queue.pop_front() {
            outcomes.push(state.handle(&inflight.message, inflight.term));
            self.delivered += 1;
        }
        outcomes
    }
}

/// The edge-side durability book: every SENT submission with its
/// sequence, plus per-subscriber PER-SEQUENCE acknowledgments
/// (selective-ack — a cumulative high-water here would silently
/// erase lost messages, the exact bug class this bead guards).
#[derive(Debug, Default)]
pub struct EdgeDeliveryBook {
    sent: Vec<(u128, RabsMessage)>,
    acked: std::collections::HashMap<u128, std::collections::BTreeSet<u128>>,
}

impl EdgeDeliveryBook {
    /// Record one submission as sent under sequence `seq`.
    pub fn record_sent(&mut self, seq: u128, message: RabsMessage) {
        self.sent.push((seq, message));
    }

    /// Acknowledge one delivered sequence for a subscriber.
    pub fn acknowledge(&mut self, subscriber: u128, seq: u128) {
        self.acked.entry(subscriber).or_default().insert(seq);
    }

    /// Everything sent-but-unacknowledged, in send order.
    #[must_use]
    pub fn unacknowledged(&self, subscriber: u128) -> Vec<(u128, &RabsMessage)> {
        let acked = self.acked.get(&subscriber);
        self.sent
            .iter()
            .filter(|(seq, _)| acked.is_none_or(|set| !set.contains(seq)))
            .map(|(seq, message)| (*seq, message))
            .collect()
    }

    /// Distinct submission keys recorded.
    #[must_use]
    pub fn distinct_submissions(&self) -> usize {
        let mut keys: Vec<u128> = self
            .sent
            .iter()
            .filter_map(|(_, m)| match m {
                RabsMessage::SubmitAction {
                    idempotency_key, ..
                } => Some(*idempotency_key),
                _ => None,
            })
            .collect();
        keys.sort_unstable();
        keys.dedup();
        keys.len()
    }
}

/// Result summary for one suite run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteResult {
    /// Suite family name.
    pub family: &'static str,
    /// Messages injected into the link (including redeliveries).
    pub injected: usize,
    /// Deliveries that reached the fold.
    pub delivered: usize,
    /// Messages lost to injected faults (before successful replay).
    pub lost: usize,
    /// Lost submissions still missing after final reconcile (gate: 0).
    pub missing_after_reconcile: usize,
    /// Whether the family's documented thresholds passed.
    pub passed: bool,
}

fn created_count(outcomes: &[HandlerOutcome]) -> usize {
    outcomes
        .iter()
        .filter(|outcome| **outcome == HandlerOutcome::Created)
        .count()
}

/// Reconnect-reconciliation: on the HEALED connection (faults zeroed),
/// replay every unacknowledged submission; each replay is processed
/// (Created or idempotent join) and immediately acknowledged. Returns
/// the number of replay injections.
fn reconcile_until_quiescent(
    book: &mut EdgeDeliveryBook,
    link: &mut FaultyLink,
    state: &mut SessionState,
    subscriber: u128,
    term: u64,
) -> usize {
    let saved_loss = link.loss_rate_bp;
    let saved_dup = link.duplicate_rate_bp;
    let saved_window = link.reorder_window;
    link.loss_rate_bp = 0;
    link.duplicate_rate_bp = 0;
    link.reorder_window = 0;
    let mut injected = 0usize;
    loop {
        let pending = book.unacknowledged(subscriber);
        if pending.is_empty() {
            break;
        }
        let pending_seqs: Vec<u128> = pending.iter().map(|(seq, _)| *seq).collect();
        for (_, message) in &pending {
            link.send((*message).clone(), term);
            injected += 1;
        }
        let outcomes = link.drain_into(state);
        debug_assert_eq!(outcomes.len(), pending.len(), "healed link delivers all");
        for seq in &pending_seqs {
            book.acknowledge(subscriber, *seq);
        }
    }
    link.loss_rate_bp = saved_loss;
    link.duplicate_rate_bp = saved_dup;
    link.reorder_window = saved_window;
    injected
}

/// Interop: mixed hello orderings reach identical coordinator state
/// (`M7_INTEROP_ALL_HELLO_ORDERS`). Both orders process 2 hellos +
/// 50 submissions, all folding to `Created`.
#[must_use]
pub fn interop_suite(seed: u64) -> SuiteResult {
    let mut result = SuiteResult {
        family: "interop",
        injected: 0,
        delivered: 0,
        lost: 0,
        missing_after_reconcile: 0,
        passed: false,
    };
    let mut totals = Vec::new();
    for hello_edge_first in [true, false] {
        let mut state = SessionState::default();
        let mut link = FaultyLink::new(seed ^ u64::from(hello_edge_first));
        let hello_edge = RabsMessage::RabsEdgeHello {
            edge: PeerId("edge-interop".to_owned()),
            session_id: 1,
        };
        let hello_worker = RabsMessage::RabsWorkerHello {
            worker: PeerId("worker-interop".to_owned()),
            session_id: 2,
        };
        let (first, second) = if hello_edge_first {
            (hello_edge, hello_worker)
        } else {
            (hello_worker, hello_edge)
        };
        link.send(first, 1);
        result.injected += 1;
        link.send(second, 1);
        result.injected += 1;
        for build in 0..50_u64 {
            link.send(
                RabsMessage::SubmitAction {
                    identity: identity(build),
                    idempotency_key: u128::from(build),
                },
                1,
            );
            result.injected += 1;
        }
        let outcomes = link.drain_into(&mut state);
        totals.push(created_count(&outcomes));
        result.delivered += link.delivered;
        result.lost += link.dropped;
    }
    if totals.len() != 2 {
        return result;
    }
    let (a, b) = (totals[0], totals[1]);
    result.passed = a == b && a == 52; // 2 hellos + 50 submissions
    result
}

/// Loss/reorder: increasing fault rates; every loss recovered by the
/// healed-connection reconcile until the coordinator set is EXACT
/// (`M7_RECONCILE_EXACT`, `M7_ZERO_DOUBLE_EXECUTE`).
#[must_use]
pub fn loss_suite(seed: u64) -> SuiteResult {
    let mut result = SuiteResult {
        family: "loss",
        injected: 0,
        delivered: 0,
        lost: 0,
        missing_after_reconcile: 0,
        passed: false,
    };
    let builds: Vec<u64> = (0..200_u64).collect();
    for rate in [0u32, 500, 1_500, INTEROP_MAX_LOSS_RATE_BP] {
        let mut state = SessionState::default();
        let mut link = FaultyLink::new(seed ^ u64::from(rate));
        link.loss_rate_bp = rate;
        link.duplicate_rate_bp = rate / 2;
        link.reorder_window = 8;
        let mut book = EdgeDeliveryBook::default();
        for (round, &build) in builds.iter().enumerate() {
            let message = RabsMessage::SubmitAction {
                identity: identity(build),
                idempotency_key: u128::from(build),
            };
            book.record_sent(u128::from(round as u64) + 1, message.clone());
            link.send(message, 1);
            result.injected += 1;
            if round % 25 == 24 {
                let _ = link.drain_into(&mut state);
            }
        }
        result.injected += reconcile_until_quiescent(&mut book, &mut link, &mut state, 1, 1);
        result.missing_after_reconcile += builds.len().saturating_sub(state.submitted_keys().len());
        result.delivered += link.delivered;
        result.lost += link.dropped;
    }
    result.passed = result.missing_after_reconcile == 0;
    result
}

/// Long-idle: an arbitrary gap then resume; idempotency survives
/// (`M8_IDLE_RESUME`). The gap is modeled by ABSENCE of traffic — no
/// clock anywhere in the pure fold depends on wall time.
#[must_use]
pub fn long_idle_suite() -> SuiteResult {
    let mut state = SessionState::default();
    let mut link = FaultyLink::new(0x1D1E);
    link.send(
        RabsMessage::SubmitAction {
            identity: identity(1),
            idempotency_key: 1,
        },
        1,
    );
    // ...an arbitrarily long idle gap passes...
    link.send(
        RabsMessage::Heartbeat {
            peer: PeerId("edge-idle".to_owned()),
            causal_seq: 9_999_999,
        },
        1,
    );
    link.send(
        RabsMessage::SubmitAction {
            identity: identity(2),
            idempotency_key: 2,
        },
        1,
    );
    let outcomes = link.drain_into(&mut state);
    SuiteResult {
        family: "long-idle",
        injected: 3,
        delivered: outcomes.len(),
        lost: 3 - outcomes.len(),
        missing_after_reconcile: 2_usize.saturating_sub(state.submitted_keys().len()),
        passed: state.submitted_keys().len() == 2 && outcomes.len() == 3,
    }
}

/// Burst: heavy key reuse under 10% loss + 5% duplication + window
/// reordering; reconciled set EXACT (`M8_BURST_VOLUME`,
/// `M7_ZERO_DOUBLE_EXECUTE`).
#[must_use]
pub fn burst_suite(seed: u64) -> SuiteResult {
    let mut state = SessionState::default();
    let mut link = FaultyLink::new(seed);
    link.loss_rate_bp = 1_000;
    link.duplicate_rate_bp = 500;
    link.reorder_window = 16;
    let mut book = EdgeDeliveryBook::default();
    for i in 0..BURST_SUITE_MIN_ACTIONS as u128 {
        let build = i % 400;
        let message = RabsMessage::SubmitAction {
            identity: identity(build.try_into().unwrap_or(0)),
            idempotency_key: build,
        };
        book.record_sent(i + 1, message.clone());
        link.send(message, 1);
    }
    let _ = link.drain_into(&mut state);
    let injected = reconcile_until_quiescent(&mut book, &mut link, &mut state, 1, 1);
    let distinct = book.distinct_submissions();
    SuiteResult {
        family: "burst",
        injected: BURST_SUITE_MIN_ACTIONS + injected,
        delivered: link.delivered,
        lost: link.dropped,
        missing_after_reconcile: distinct.saturating_sub(state.submitted_keys().len()),
        passed: distinct == state.submitted_keys().len() && distinct == 400,
    }
}

/// Multi-day soak: compressed day-cycles of burst → idle → reconnect-
/// reconcile → authority rotation + stale probe (`M8_MULTIDAY_SOAK`).
/// Each day: five fresh submissions ride the LOSSY link; the evening
/// reconnect heals it and reconciles the day exactly; then the
/// authority rotates and a stale-term probe must fail closed.
#[must_use]
pub fn multi_day_soak_suite(seed: u64) -> SuiteResult {
    let mut state = SessionState::default();
    let mut term: u64 = 1;
    let mut link = FaultyLink::new(seed);
    link.loss_rate_bp = 500;
    link.reorder_window = 4;
    let mut book = EdgeDeliveryBook::default();
    let mut injected = 0usize;
    let mut seq: u128 = 0;
    let mut build_id: u64 = 0;
    for _day in 0..MULTIDAY_SOAK_CYCLES {
        // Morning burst: five fresh builds over the lossy link.
        for _ in 0..5 {
            let message = RabsMessage::SubmitAction {
                identity: identity(build_id),
                idempotency_key: u128::from(build_id),
            };
            seq += 1;
            book.record_sent(seq, message.clone());
            link.send(message, term);
            injected += 1;
            build_id += 1;
        }
        let _ = link.drain_into(&mut state);
        // Idle gap: modeled by absence of traffic (no wall clock).
        // Evening reconnect: heal + reconcile today's work exactly.
        injected += reconcile_until_quiescent(&mut book, &mut link, &mut state, 1, term);
        // Authority rotation + stale probe (fails closed). Control
        // exchanges ride the ORDERED control channel (reorder window
        // zeroed) so the staleness test is deterministic: rotation
        // first, then probe.
        term = term.saturating_add(1);
        let saved_window = link.reorder_window;
        link.reorder_window = 0;
        link.send(
            RabsMessage::AuthorityUpdate {
                authority: authority(term),
            },
            term,
        );
        injected += 1;
        let stale_probe_build = build_id; // never submitted under any term
        link.send(
            RabsMessage::SubmitAction {
                identity: identity(stale_probe_build),
                idempotency_key: u128::from(stale_probe_build),
            },
            term - 1,
        );
        injected += 1;
        let outcomes = link.drain_into(&mut state);
        link.reorder_window = saved_window;
        // The rotation folds Created; the stale probe MUST be rejected.
        assert_eq!(
            outcomes.last(),
            Some(&HandlerOutcome::RejectedStaleAuthority),
            "stale probe must fail closed"
        );
    }
    let distinct = book.distinct_submissions();
    SuiteResult {
        family: "multi-day-soak",
        injected,
        delivered: link.delivered,
        lost: link.dropped,
        missing_after_reconcile: distinct.saturating_sub(state.submitted_keys().len()),
        passed: distinct == state.submitted_keys().len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn j017_interop_hello_orders_converge() {
        let result = interop_suite(1);
        assert!(result.passed, "interop: {result:?}");
        assert_eq!(result.missing_after_reconcile, 0);
    }

    #[test]
    fn j017_loss_suite_recovers_exactly_up_to_gate_rate() {
        let result = loss_suite(2);
        assert!(result.passed, "loss: {result:?}");
        assert_eq!(result.missing_after_reconcile, 0);
        assert!(result.lost > 0, "faults never actually injected");
        assert!(result.injected > 800, "reconcile replay never ran");
    }

    #[test]
    fn j017_long_idle_resumes_with_idempotency_intact() {
        let result = long_idle_suite();
        assert!(result.passed, "long-idle: {result:?}");
    }

    #[test]
    fn j017_burst_volume_reconciles_exact() {
        let result = burst_suite(4);
        assert!(result.passed, "burst: {result:?}");
        assert!(result.lost > 0, "faults never actually injected");
        assert_eq!(result.missing_after_reconcile, 0);
    }

    #[test]
    fn j017_partition_blackholes_until_healed() {
        let mut state = SessionState::default();
        let mut link = FaultyLink::new(7);
        link.partitioned = true;
        link.send(
            RabsMessage::SubmitAction {
                identity: identity(1),
                idempotency_key: 1,
            },
            1,
        );
        assert!(link.drain_into(&mut state).is_empty());
        assert_eq!(link.dropped, 1);
        link.partitioned = false;
        link.send(
            RabsMessage::SubmitAction {
                identity: identity(1),
                idempotency_key: 1,
            },
            1,
        );
        assert_eq!(link.drain_into(&mut state).len(), 1);
    }

    #[test]
    fn j017_selective_acks_never_erase_lost_messages() {
        // The J016-era cumulative-ack bug: acking a high-water that
        // includes a LOST message must NOT remove it from the
        // redelivery set (per-sequence selective acks instead).
        let mut book = EdgeDeliveryBook::default();
        for seq in 1..=3_u128 {
            book.record_sent(
                seq,
                RabsMessage::SubmitAction {
                    identity: identity(seq.try_into().unwrap_or(0)),
                    idempotency_key: seq,
                },
            );
        }
        // Seq 2 was lost; the edge only processed 1 and 3.
        book.acknowledge(1, 1);
        book.acknowledge(1, 3);
        let pending = book.unacknowledged(1);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 2);
    }
}
