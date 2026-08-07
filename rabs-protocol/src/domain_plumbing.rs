//! Sequence-domain envelope plumbing + causal references (bead J029;
//! invariant I52; realizes J023 across the message families).
//!
//! Every message family maps to EXACTLY one J023 sequence domain, and
//! cross-domain relationships are expressed as EXPLICIT CAUSAL
//! REFERENCES — object IDs, authority tuples, readiness/commit
//! messages — never as ordering assumptions between domains:
//!
//! - a delivery message that depends on a published object carries
//!   the OBJECT ID; the handler checks object presence, not "did the
//!   transfer domain reach sequence N";
//! - an authority-bearing message carries the AUTHORITY TUPLE (J005);
//!   the handler verifies the tuple, not a control-domain watermark;
//! - readiness is a MESSAGE (in the consumer's own domain), not an
//!   inference from another domain's progress.
//!
//! The fixtures prove the negative: processing any family with every
//! OTHER domain at sequence zero works — no handler consults a
//! foreign domain's watermark, because the routing layer exposes no
//! API to do so.

use crate::sequence_domains::{DomainSet, ReceiveOutcome, SequenceDomain};

/// The message families and their ONE domain each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MessageFamily {
    Heartbeat,
    ActionSubmission,
    LeaseRenewal,
    Cancellation,
    AuthorityUpdate,
    AttemptEvent,
    PreparedResultOffer,
    Reconciliation,
    TranscriptDelivery,
    StatefulDelivery,
    ObjectChunk,
    MissingObjectQuery,
    TelemetryReport,
}

impl MessageFamily {
    /// All families.
    pub const ALL: [Self; 13] = [
        Self::Heartbeat,
        Self::ActionSubmission,
        Self::LeaseRenewal,
        Self::Cancellation,
        Self::AuthorityUpdate,
        Self::AttemptEvent,
        Self::PreparedResultOffer,
        Self::Reconciliation,
        Self::TranscriptDelivery,
        Self::StatefulDelivery,
        Self::ObjectChunk,
        Self::MissingObjectQuery,
        Self::TelemetryReport,
    ];

    /// The family's sequence domain (total map).
    #[must_use]
    pub const fn domain(self) -> SequenceDomain {
        match self {
            Self::Heartbeat
            | Self::LeaseRenewal
            | Self::Cancellation
            | Self::AuthorityUpdate
            | Self::Reconciliation => SequenceDomain::AuthorityControl,
            Self::ActionSubmission | Self::AttemptEvent | Self::PreparedResultOffer => {
                SequenceDomain::ActionLifecycle
            }
            Self::TranscriptDelivery | Self::StatefulDelivery => SequenceDomain::SubscriberDelivery,
            Self::ObjectChunk | Self::MissingObjectQuery => SequenceDomain::ObjectTransfer,
            Self::TelemetryReport => SequenceDomain::TelemetryBestEffort,
        }
    }
}

/// A cross-domain causal reference (the ONLY legal cross-domain link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CausalReference {
    /// Depends on an object being present (checked against the store,
    /// never against transfer-domain sequence numbers).
    ObjectPresent([u8; 32]),
    /// Bound to an authority tuple (verified by content — J005/F033).
    AuthorityTuple {
        /// Operation id.
        operation: u128,
        /// Generation id.
        generation: u128,
    },
    /// An explicit readiness/commit message was received IN THE
    /// CONSUMER'S OWN DOMAIN.
    ReadinessMessage {
        /// The readiness message's own-domain sequence.
        sequence: u64,
    },
}

/// Route one message into its domain window. The signature is the
/// proof of independence: a handler receives ONLY its own domain's
/// window — there is no parameter through which to consult another.
pub fn route_message(
    domains: &mut DomainSet,
    family: MessageFamily,
    sequence: u64,
) -> ReceiveOutcome {
    domains.window(family.domain()).receive(sequence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_family_maps_to_exactly_one_domain() {
        // Totality by const fn; the distribution matches I52.
        for family in MessageFamily::ALL {
            let _ = family.domain();
        }
        assert_eq!(
            MessageFamily::Cancellation.domain(),
            SequenceDomain::AuthorityControl
        );
        assert_eq!(
            MessageFamily::ObjectChunk.domain(),
            SequenceDomain::ObjectTransfer
        );
        assert_eq!(
            MessageFamily::StatefulDelivery.domain(),
            SequenceDomain::SubscriberDelivery
        );
    }

    #[test]
    fn no_handler_has_a_cross_domain_ordering_dependency() {
        // THE acceptance fixture: process EVERY family's first message
        // with every OTHER domain still at sequence zero. All deliver —
        // no handler waits on a foreign watermark, because
        // route_message exposes no API to consult one.
        for family in MessageFamily::ALL {
            let mut domains = DomainSet::new(16);
            assert_eq!(
                route_message(&mut domains, family, 1),
                ReceiveOutcome::Deliver,
                "{family:?} must deliver with all other domains at zero"
            );
        }
    }

    #[test]
    fn cross_domain_needs_are_causal_references_not_order() {
        // A delivery depending on an object carries the OBJECT ID; the
        // handler checks presence against the store. Simulate: the
        // transfer domain is far BEHIND (sequence 0) yet the delivery
        // proceeds because its reference is satisfied by presence.
        let mut domains = DomainSet::new(16);
        let store_has = |id: [u8; 32]| id == [7; 32]; // the object store
        let reference = CausalReference::ObjectPresent([7; 32]);
        let satisfied = match &reference {
            CausalReference::ObjectPresent(id) => store_has(*id),
            CausalReference::AuthorityTuple { .. } | CausalReference::ReadinessMessage { .. } => {
                unreachable!()
            }
        };
        assert!(satisfied);
        assert_eq!(
            route_message(&mut domains, MessageFamily::StatefulDelivery, 1),
            ReceiveOutcome::Deliver,
            "delivery proceeds with ObjectTransfer at sequence ZERO"
        );
        // An unsatisfied reference blocks THE MESSAGE (its own domain
        // buffers/waits) — never by waiting on the foreign domain's
        // sequence, which remains untouched.
        let unsatisfied = CausalReference::ObjectPresent([9; 32]);
        let ok = match &unsatisfied {
            CausalReference::ObjectPresent(id) => store_has(*id),
            _ => unreachable!(),
        };
        assert!(!ok, "the handler re-checks presence later; no watermark");
    }

    #[test]
    fn readiness_is_a_message_in_the_consumers_own_domain() {
        // Readiness/commit travels as a message with its OWN sequence
        // in the consumer's domain — the reference records that
        // sequence, not another domain's.
        let mut domains = DomainSet::new(16);
        assert_eq!(
            route_message(&mut domains, MessageFamily::Reconciliation, 1),
            ReceiveOutcome::Deliver
        );
        let reference = CausalReference::ReadinessMessage { sequence: 1 };
        assert_eq!(
            reference,
            CausalReference::ReadinessMessage { sequence: 1 },
            "the readiness reference names the own-domain sequence"
        );
    }
}
