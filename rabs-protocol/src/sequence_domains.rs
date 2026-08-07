//! Independent per-domain sequence/replay windows (bead J023;
//! invariant I52; risk R109; fixture family T040).
//!
//! Five sequence domains, each with its OWN monotonic sequence, ack
//! high-water, and bounded out-of-order window — and the rule with
//! teeth: **no domain's progress is ever inferred from another's**.
//! A missing bulk range can never block cancellation or lease
//! traffic, stream closure never implies commit, and reconnect
//! resumes each domain independently from its own acked high-water.

/// The five sequence domains (I52).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum SequenceDomain {
    AuthorityControl,
    ActionLifecycle,
    SubscriberDelivery,
    ObjectTransfer,
    TelemetryBestEffort,
}

impl SequenceDomain {
    /// All domains.
    pub const ALL: [Self; 5] = [
        Self::AuthorityControl,
        Self::ActionLifecycle,
        Self::SubscriberDelivery,
        Self::ObjectTransfer,
        Self::TelemetryBestEffort,
    ];

    /// Whether sequences in this domain must persist BEFORE ack
    /// (terminal/authority-bearing domains).
    #[must_use]
    pub const fn persist_before_ack(self) -> bool {
        matches!(self, Self::AuthorityControl | Self::ActionLifecycle)
    }
}

/// Outcome of receiving one sequenced message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveOutcome {
    /// In order: deliver and advance the high-water.
    Deliver,
    /// Duplicate (at or below the high-water): idempotent no-op.
    DuplicateIgnored,
    /// Ahead of the window: buffered, awaiting the gap.
    Buffered,
    /// Beyond the bounded window: refused (sender must resume).
    WindowExceeded,
}

/// One domain's receive window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainWindow {
    /// The domain.
    pub domain: SequenceDomain,
    /// Highest contiguously delivered + acked sequence.
    pub acked_high_water: u64,
    /// Out-of-order buffer (bounded).
    buffered: Vec<u64>,
    /// Maximum buffered entries.
    max_buffer: usize,
}

impl DomainWindow {
    /// New window for a domain.
    #[must_use]
    pub fn new(domain: SequenceDomain, max_buffer: usize) -> Self {
        Self {
            domain,
            acked_high_water: 0,
            buffered: Vec::new(),
            max_buffer,
        }
    }

    /// Receive sequence `seq`.
    pub fn receive(&mut self, seq: u64) -> ReceiveOutcome {
        if seq <= self.acked_high_water {
            return ReceiveOutcome::DuplicateIgnored;
        }
        if seq == self.acked_high_water + 1 {
            self.acked_high_water = seq;
            // Drain any now-contiguous buffered entries.
            loop {
                let next = self.acked_high_water + 1;
                if let Some(pos) = self.buffered.iter().position(|s| *s == next) {
                    self.buffered.remove(pos);
                    self.acked_high_water = next;
                } else {
                    break;
                }
            }
            return ReceiveOutcome::Deliver;
        }
        // A gap: an already-buffered duplicate is idempotent; new
        // entries buffer within the bound.
        if self.buffered.contains(&seq) {
            return ReceiveOutcome::Buffered;
        }
        if self.buffered.len() >= self.max_buffer {
            return ReceiveOutcome::WindowExceeded;
        }
        self.buffered.push(seq);
        ReceiveOutcome::Buffered
    }

    /// Resume point after reconnect: THIS domain's acked high-water
    /// (buffered-but-unacked entries are discarded — the sender
    /// retransmits from here).
    pub fn resume_from(&mut self) -> u64 {
        self.buffered.clear();
        self.acked_high_water
    }
}

/// The full per-peer domain set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSet {
    windows: [DomainWindow; 5],
}

impl DomainSet {
    /// New set with one bounded window per domain.
    #[must_use]
    pub fn new(max_buffer: usize) -> Self {
        Self {
            windows: [
                DomainWindow::new(SequenceDomain::AuthorityControl, max_buffer),
                DomainWindow::new(SequenceDomain::ActionLifecycle, max_buffer),
                DomainWindow::new(SequenceDomain::SubscriberDelivery, max_buffer),
                DomainWindow::new(SequenceDomain::ObjectTransfer, max_buffer),
                DomainWindow::new(SequenceDomain::TelemetryBestEffort, max_buffer),
            ],
        }
    }

    /// The window for a domain.
    pub fn window(&mut self, domain: SequenceDomain) -> &mut DomainWindow {
        self.windows
            .iter_mut()
            .find(|w| w.domain == domain)
            .expect("all domains present")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SequenceDomain as D;

    #[test]
    fn domains_are_independent_and_gaps_never_cross() {
        // THE T040 cross-stream gap scenario: a missing bulk range in
        // ObjectTransfer never blocks AuthorityControl (cancel/lease).
        let mut set = DomainSet::new(16);
        // Bulk stalls with a gap: 1 delivered, 3..10 buffered, 2 lost.
        assert_eq!(
            set.window(D::ObjectTransfer).receive(1),
            ReceiveOutcome::Deliver
        );
        for seq in 3..10 {
            assert_eq!(
                set.window(D::ObjectTransfer).receive(seq),
                ReceiveOutcome::Buffered
            );
        }
        // Control traffic flows regardless.
        for seq in 1..=5 {
            assert_eq!(
                set.window(D::AuthorityControl).receive(seq),
                ReceiveOutcome::Deliver,
                "cancel/lease sequence {seq} must not wait for bulk"
            );
        }
        assert_eq!(set.window(D::AuthorityControl).acked_high_water, 5);
        assert_eq!(set.window(D::ObjectTransfer).acked_high_water, 1);
        // The gap fills: buffered entries drain contiguously.
        assert_eq!(
            set.window(D::ObjectTransfer).receive(2),
            ReceiveOutcome::Deliver
        );
        assert_eq!(set.window(D::ObjectTransfer).acked_high_water, 9);
    }

    #[test]
    fn duplicates_are_idempotent_and_windows_bound() {
        let mut window = DomainWindow::new(D::SubscriberDelivery, 4);
        assert_eq!(window.receive(1), ReceiveOutcome::Deliver);
        assert_eq!(window.receive(1), ReceiveOutcome::DuplicateIgnored);
        // Fill the out-of-order buffer to its bound.
        for seq in [3, 4, 5, 6] {
            assert_eq!(window.receive(seq), ReceiveOutcome::Buffered);
        }
        assert_eq!(
            window.receive(7),
            ReceiveOutcome::WindowExceeded,
            "bounded buffering: the sender must resume, not flood"
        );
        // A buffered duplicate is also idempotent.
        assert_eq!(window.receive(3), ReceiveOutcome::Buffered);
        assert_eq!(window.buffered.len(), 4, "no duplicate buffering");
    }

    #[test]
    fn reconnect_resumes_each_domain_from_its_own_high_water() {
        let mut set = DomainSet::new(16);
        for seq in 1..=7 {
            set.window(D::ActionLifecycle).receive(seq);
        }
        for seq in 1..=3 {
            set.window(D::SubscriberDelivery).receive(seq);
        }
        set.window(D::SubscriberDelivery).receive(5); // buffered, unacked
        // Reconnect: each domain resumes independently; the buffered
        // unacked entry is discarded (the sender retransmits).
        assert_eq!(set.window(D::ActionLifecycle).resume_from(), 7);
        assert_eq!(set.window(D::SubscriberDelivery).resume_from(), 3);
        assert_eq!(
            set.window(D::SubscriberDelivery).receive(4),
            ReceiveOutcome::Deliver,
            "delivery resumes at high-water + 1"
        );
    }

    #[test]
    fn terminal_domains_persist_before_ack_and_closure_infers_nothing() {
        // The persist-before-ack rule is a per-domain FACT the runtime
        // consults; terminal/authority domains carry it.
        assert!(D::AuthorityControl.persist_before_ack());
        assert!(D::ActionLifecycle.persist_before_ack());
        assert!(!D::TelemetryBestEffort.persist_before_ack());
        // Commit is never inferred from closure or another domain:
        // structurally, a DomainWindow exposes only receive/resume —
        // there is no close-implies-commit or cross-domain method to
        // call. The exhaustive match pins the outcome vocabulary.
        for outcome in [
            ReceiveOutcome::Deliver,
            ReceiveOutcome::DuplicateIgnored,
            ReceiveOutcome::Buffered,
            ReceiveOutcome::WindowExceeded,
        ] {
            match outcome {
                ReceiveOutcome::Deliver
                | ReceiveOutcome::DuplicateIgnored
                | ReceiveOutcome::Buffered
                | ReceiveOutcome::WindowExceeded => {}
            }
        }
    }
}
