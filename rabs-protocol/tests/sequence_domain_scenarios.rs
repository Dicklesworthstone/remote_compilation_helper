//! Cross-stream bulk-gap vs cancellation/lease scenario suite (bead
//! T040; risk R109; invariant I52; drives the J023 windows + J026
//! leases together).
//!
//! The law under scenario test: **no domain's progress is ever
//! inferred from another's.** A missing `ObjectTransfer` range —
//! even one that exhausts the bulk window — never delays
//! `AuthorityControl` (cancellation, lease renewal) or
//! `ActionLifecycle` traffic; and after a reconnect, every domain
//! resumes from ITS OWN acked high-water independently.

use rabs_protocol::generation::LeaseRenewalSeq;
use rabs_protocol::lease_semantics::{MonotonicLease, RenewalOutcome};
use rabs_protocol::sequence_domains::{DomainSet, ReceiveOutcome, SequenceDomain as D};

#[test]
fn a_bulk_gap_never_delays_cancellation_traffic() {
    // SCENARIO: a 10-object transfer loses object 2; objects 3..=10
    // buffer behind the gap. Mid-stall, the user hits Ctrl-C: the
    // cancel rides AuthorityControl and must DELIVER immediately.
    let mut set = DomainSet::new(16);
    assert_eq!(
        set.window(D::ObjectTransfer).receive(1),
        ReceiveOutcome::Deliver
    );
    for seq in 3..=10 {
        assert_eq!(
            set.window(D::ObjectTransfer).receive(seq),
            ReceiveOutcome::Buffered,
            "bulk stalls behind the lost range"
        );
    }
    assert_eq!(set.window(D::ObjectTransfer).acked_high_water, 1);
    // The cancellation: in-order on ITS domain, delivered NOW.
    assert_eq!(
        set.window(D::AuthorityControl).receive(1),
        ReceiveOutcome::Deliver
    );
    assert_eq!(
        set.window(D::AuthorityControl).receive(2),
        ReceiveOutcome::Deliver
    );
    assert_eq!(set.window(D::AuthorityControl).acked_high_water, 2);
    // Lifecycle events flow too.
    assert_eq!(
        set.window(D::ActionLifecycle).receive(1),
        ReceiveOutcome::Deliver
    );
}

#[test]
fn even_window_exhaustion_on_bulk_leaves_control_untouched() {
    // SCENARIO: an adversarial/degenerate transfer exhausts the bulk
    // buffer entirely (WindowExceeded). Control still delivers —
    // bulk backpressure is not control backpressure.
    let mut set = DomainSet::new(4);
    for seq in 2..=5 {
        assert_eq!(
            set.window(D::ObjectTransfer).receive(seq),
            ReceiveOutcome::Buffered
        );
    }
    assert_eq!(
        set.window(D::ObjectTransfer).receive(6),
        ReceiveOutcome::WindowExceeded,
        "the bulk window is genuinely exhausted"
    );
    for seq in 1..=3 {
        assert_eq!(
            set.window(D::AuthorityControl).receive(seq),
            ReceiveOutcome::Deliver,
            "control delivery independent of bulk exhaustion"
        );
    }
}

#[test]
fn lease_renewals_survive_a_bulk_stall() {
    // SCENARIO: the transfer stalls for longer than the lease TTL.
    // Renewals ride AuthorityControl (unblocked), so the lease stays
    // live the whole way — a bulk gap can never expire authority.
    let mut set = DomainSet::new(8);
    let mut lease = MonotonicLease {
        ttl_ms: 5_000,
        armed_at_own_monotonic_ms: 0,
        renewal_seq: LeaseRenewalSeq(0),
    };
    // Bulk gap opens at t=0 (object 2 lost).
    assert_eq!(
        set.window(D::ObjectTransfer).receive(1),
        ReceiveOutcome::Deliver
    );
    assert_eq!(
        set.window(D::ObjectTransfer).receive(3),
        ReceiveOutcome::Buffered
    );
    // Renewals arrive at t=4000 and t=8000 on the control domain.
    for (control_seq, renewal_seq, now) in [(1_u64, 1_u64, 4_000_u64), (2, 2, 8_000)] {
        assert_eq!(
            set.window(D::AuthorityControl).receive(control_seq),
            ReceiveOutcome::Deliver
        );
        assert_eq!(
            lease.renew(LeaseRenewalSeq(renewal_seq), now, 5_000),
            RenewalOutcome::Accepted
        );
    }
    // t=10000: five seconds past the ORIGINAL arming — live, because
    // the renewals kept flowing past the stalled bulk stream.
    assert!(lease.live(10_000));
    assert!(!lease.live(13_001), "and expiry still works normally");
    // The bulk gap is STILL open; nothing about the lease closed it.
    assert_eq!(set.window(D::ObjectTransfer).acked_high_water, 1);
}

#[test]
fn per_domain_resume_after_reconnect_is_independent() {
    // SCENARIO: domains at different high-waters when the connection
    // drops. Each resumes from ITS OWN acked high-water; buffered-
    // but-unacked entries are discarded and retransmission heals
    // each domain separately.
    let mut set = DomainSet::new(8);
    // AuthorityControl: 1..=5 delivered.
    for seq in 1..=5 {
        set.window(D::AuthorityControl).receive(seq);
    }
    // ActionLifecycle: 1..=2 delivered.
    for seq in 1..=2 {
        set.window(D::ActionLifecycle).receive(seq);
    }
    // ObjectTransfer: 1 delivered, 3..=6 buffered (2 lost in flight).
    set.window(D::ObjectTransfer).receive(1);
    for seq in 3..=6 {
        set.window(D::ObjectTransfer).receive(seq);
    }
    // ── reconnect ──
    assert_eq!(set.window(D::AuthorityControl).resume_from(), 5);
    assert_eq!(set.window(D::ActionLifecycle).resume_from(), 2);
    assert_eq!(
        set.window(D::ObjectTransfer).resume_from(),
        1,
        "bulk resumes from ITS high-water — unacked buffer discarded"
    );
    // Retransmission from each resume point heals each domain.
    for seq in 2..=6 {
        assert_eq!(
            set.window(D::ObjectTransfer).receive(seq),
            ReceiveOutcome::Deliver,
            "retransmitted bulk delivers in order"
        );
    }
    assert_eq!(set.window(D::ObjectTransfer).acked_high_water, 6);
    // Control retransmissions at-or-below its high-water are
    // idempotent duplicates — resume points never regress a domain.
    assert_eq!(
        set.window(D::AuthorityControl).receive(5),
        ReceiveOutcome::DuplicateIgnored
    );
    assert_eq!(
        set.window(D::AuthorityControl).receive(6),
        ReceiveOutcome::Deliver
    );
}

#[test]
fn resume_points_are_never_inferred_across_domains() {
    // The negative-space check: advancing one domain to 100 moves no
    // other domain's resume point off zero.
    let mut set = DomainSet::new(128);
    for seq in 1..=100 {
        set.window(D::TelemetryBestEffort).receive(seq);
    }
    for domain in [
        D::AuthorityControl,
        D::ActionLifecycle,
        D::SubscriberDelivery,
        D::ObjectTransfer,
    ] {
        assert_eq!(
            set.window(domain).resume_from(),
            0,
            "{domain:?} must not inherit telemetry's progress"
        );
    }
    assert_eq!(set.window(D::TelemetryBestEffort).resume_from(), 100);
}
