//! The bounded RABS application envelope (bead J004; plan §87; risks
//! R64/R95's wire arm).
//!
//! Every application message travels inside one envelope shape.
//! Decoding discipline:
//!
//! - **limits enforce BEFORE allocation**: claimed byte lengths,
//!   collection counts, and nesting depths are validated against the
//!   negotiated [`EnvelopeLimits`] while still integers — a hostile
//!   claim of a 4 GiB payload or 10^9-entry collection is refused
//!   without ever reserving a byte for it;
//! - **unknown authority-bearing fields fail closed**: an envelope
//!   carrying an authority-class field tag the negotiated schema does
//!   not define is rejected (safe ignorance must be NEGOTIATED, never
//!   assumed) — unknown non-authority fields may skip when the schema
//!   version says so.

use crate::authority::CoordinatorAuthority;
use crate::durable_ids::DurableWireIdentity;
use crate::wire_time::PeerId;

/// Decoder limits (negotiated per session; conservative defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeLimits {
    /// Max payload bytes.
    pub max_payload_bytes: u64,
    /// Max entries in any collection field.
    pub max_collection_entries: u64,
    /// Max nesting depth for structured payloads.
    pub max_nesting_depth: u32,
    /// Max manifest fan-out referenced from one message.
    pub max_manifest_fanout: u64,
    /// Max decompressed size a compressed payload may claim.
    pub max_decompressed_bytes: u64,
}

/// Conservative defaults.
pub const DEFAULT_LIMITS: EnvelopeLimits = EnvelopeLimits {
    max_payload_bytes: 64 << 20,
    max_collection_entries: 1 << 20,
    max_nesting_depth: 64,
    max_manifest_fanout: 1 << 16,
    max_decompressed_bytes: 256 << 20,
};

/// Redaction/privacy classification of the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PrivacyClass {
    FleetShareable,
    ProjectScoped,
    EdgePrivate,
}

/// The application envelope (schema; wire encoding rides J001/J003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RabsEnvelope {
    /// Negotiated application version this message speaks (J002).
    pub application_version: u32,
    /// Session identity.
    pub session_id: u128,
    /// Authenticated role names for the sender.
    pub authenticated_roles: Vec<String>,
    /// Coordinator authority — REQUIRED on authority-bearing ops.
    pub coordinator_authority: Option<CoordinatorAuthority>,
    /// Causal trace ID.
    pub trace_id: u128,
    /// Sender peer.
    pub sender: PeerId,
    /// Destination peer.
    pub destination: PeerId,
    /// Durable identity — REQUIRED on authority-bearing messages
    /// (operation/generation/attempt/lease; J005), and carries the
    /// worker boot/incarnation context there.
    pub durable_identity: Option<DurableWireIdentity>,
    /// Subscriber identity for delivery messages.
    pub subscriber_id: Option<u128>,
    /// Idempotency key.
    pub idempotency_key: u128,
    /// Sequence domain name.
    pub sequence_domain: String,
    /// Per-domain monotonic sequence.
    pub sequence: u64,
    /// CLAIMED payload length (validated pre-allocation).
    pub payload_length: u64,
    /// CLAIMED collection counts (validated pre-allocation).
    pub collection_counts: Vec<u64>,
    /// CLAIMED nesting depth.
    pub nesting_depth: u32,
    /// CLAIMED manifest fan-out.
    pub manifest_fanout: u64,
    /// CLAIMED decompressed size (0 = uncompressed).
    pub decompressed_bytes: u64,
    /// Capability scope names in effect.
    pub capability_scope: Vec<String>,
    /// Privacy classification.
    pub privacy: PrivacyClass,
    /// Optional response-to envelope idempotency key.
    pub response_to: Option<u128>,
    /// Optional resume-from sequence.
    pub resume_from: Option<u64>,
    /// Unknown field tags seen during decode, split by class.
    pub unknown_authority_fields: Vec<u32>,
    /// Unknown non-authority field tags (skippable when negotiated).
    pub unknown_plain_fields: Vec<u32>,
}

/// Pre-allocation admission failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeRejection {
    /// Claimed payload exceeds the limit.
    PayloadTooLarge {
        /// Claimed.
        claimed: u64,
        /// Limit.
        limit: u64,
    },
    /// A claimed collection count exceeds the limit.
    CollectionTooLarge {
        /// Claimed.
        claimed: u64,
    },
    /// Claimed nesting exceeds the limit.
    NestingTooDeep,
    /// Claimed manifest fan-out exceeds the limit.
    FanoutTooWide,
    /// Claimed decompressed size exceeds the limit (zip-bomb guard).
    DecompressionTooLarge,
    /// Unknown authority-bearing field with no negotiated safe
    /// ignorance: fail closed.
    UnknownAuthorityField(u32),
    /// An authority-bearing operation without authority/identity.
    MissingAuthority,
}

/// Admit an envelope BEFORE allocating for its payload. `is_authority_
/// bearing` marks ops that mutate authority-bearing state;
/// `negotiated_safe_ignorance` lists non-authority tags the schema
/// version declared skippable.
///
/// # Errors
/// [`EnvelopeRejection`] naming the violated limit.
pub fn admit_envelope(
    envelope: &RabsEnvelope,
    limits: &EnvelopeLimits,
    is_authority_bearing: bool,
    negotiated_safe_ignorance: &[u32],
) -> Result<(), EnvelopeRejection> {
    if envelope.payload_length > limits.max_payload_bytes {
        return Err(EnvelopeRejection::PayloadTooLarge {
            claimed: envelope.payload_length,
            limit: limits.max_payload_bytes,
        });
    }
    for claimed in &envelope.collection_counts {
        if *claimed > limits.max_collection_entries {
            return Err(EnvelopeRejection::CollectionTooLarge { claimed: *claimed });
        }
    }
    if envelope.nesting_depth > limits.max_nesting_depth {
        return Err(EnvelopeRejection::NestingTooDeep);
    }
    if envelope.manifest_fanout > limits.max_manifest_fanout {
        return Err(EnvelopeRejection::FanoutTooWide);
    }
    if envelope.decompressed_bytes > limits.max_decompressed_bytes {
        return Err(EnvelopeRejection::DecompressionTooLarge);
    }
    // Unknown AUTHORITY fields fail closed, always.
    if let Some(tag) = envelope.unknown_authority_fields.first() {
        return Err(EnvelopeRejection::UnknownAuthorityField(*tag));
    }
    // Unknown plain fields: allowed only when negotiated.
    for tag in &envelope.unknown_plain_fields {
        if !negotiated_safe_ignorance.contains(tag) {
            return Err(EnvelopeRejection::UnknownAuthorityField(*tag));
        }
    }
    if is_authority_bearing
        && (envelope.coordinator_authority.is_none() || envelope.durable_identity.is_none())
    {
        return Err(EnvelopeRejection::MissingAuthority);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{ClusterId, CoordinatorIncarnationId};
    use crate::durable_ids::BuildOperationId;
    use crate::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};

    fn envelope() -> RabsEnvelope {
        RabsEnvelope {
            application_version: 7,
            session_id: 1,
            authenticated_roles: vec!["edge".into()],
            coordinator_authority: Some(CoordinatorAuthority {
                cluster_id: ClusterId("fleet-1".into()),
                credential_generation: 1,
                term: 3,
                incarnation_id: CoordinatorIncarnationId(7),
            }),
            trace_id: 42,
            sender: PeerId("edge-1".into()),
            destination: PeerId("coord".into()),
            durable_identity: Some(DurableWireIdentity {
                operation: BuildOperationId(1),
                generation: ActionGenerationId(2),
                attempt: AttemptId(3),
                lease: ExecutionLeaseId(4),
            }),
            subscriber_id: Some(9),
            idempotency_key: 100,
            sequence_domain: "edge-1/deliveries".into(),
            sequence: 5,
            payload_length: 1024,
            collection_counts: vec![10, 20],
            nesting_depth: 3,
            manifest_fanout: 100,
            decompressed_bytes: 0,
            capability_scope: vec![],
            privacy: PrivacyClass::ProjectScoped,
            response_to: None,
            resume_from: None,
            unknown_authority_fields: vec![],
            unknown_plain_fields: vec![],
        }
    }

    #[test]
    fn well_formed_envelopes_admit() {
        assert_eq!(
            admit_envelope(&envelope(), &DEFAULT_LIMITS, true, &[]),
            Ok(())
        );
    }

    #[test]
    fn hostile_claims_reject_before_allocation() {
        // THE limit-enforcement corpus: each limit violated by CLAIM —
        // validation happens on integers, no buffer is ever reserved.
        let mut giant = envelope();
        giant.payload_length = 4 << 30;
        assert!(matches!(
            admit_envelope(&giant, &DEFAULT_LIMITS, false, &[]),
            Err(EnvelopeRejection::PayloadTooLarge { .. })
        ));
        let mut wide = envelope();
        wide.collection_counts = vec![10, 1_000_000_000];
        assert!(matches!(
            admit_envelope(&wide, &DEFAULT_LIMITS, false, &[]),
            Err(EnvelopeRejection::CollectionTooLarge {
                claimed: 1_000_000_000
            })
        ));
        let mut deep = envelope();
        deep.nesting_depth = 10_000;
        assert_eq!(
            admit_envelope(&deep, &DEFAULT_LIMITS, false, &[]),
            Err(EnvelopeRejection::NestingTooDeep)
        );
        let mut fanned = envelope();
        fanned.manifest_fanout = 1 << 30;
        assert_eq!(
            admit_envelope(&fanned, &DEFAULT_LIMITS, false, &[]),
            Err(EnvelopeRejection::FanoutTooWide)
        );
        // Zip bomb: small payload, giant decompressed claim.
        let mut bomb = envelope();
        bomb.payload_length = 1024;
        bomb.decompressed_bytes = 1 << 40;
        assert_eq!(
            admit_envelope(&bomb, &DEFAULT_LIMITS, false, &[]),
            Err(EnvelopeRejection::DecompressionTooLarge)
        );
    }

    #[test]
    fn unknown_authority_fields_fail_closed() {
        let mut unknown = envelope();
        unknown.unknown_authority_fields = vec![999];
        assert_eq!(
            admit_envelope(&unknown, &DEFAULT_LIMITS, true, &[999]),
            Err(EnvelopeRejection::UnknownAuthorityField(999)),
            "authority fields NEVER skip, even if listed as ignorable"
        );
        // Plain unknown fields skip ONLY when negotiated.
        let mut plain = envelope();
        plain.unknown_plain_fields = vec![7];
        assert!(admit_envelope(&plain, &DEFAULT_LIMITS, true, &[7]).is_ok());
        assert_eq!(
            admit_envelope(&plain, &DEFAULT_LIMITS, true, &[]),
            Err(EnvelopeRejection::UnknownAuthorityField(7))
        );
    }

    #[test]
    fn authority_bearing_ops_require_authority_and_identity() {
        let mut missing = envelope();
        missing.coordinator_authority = None;
        assert_eq!(
            admit_envelope(&missing, &DEFAULT_LIMITS, true, &[]),
            Err(EnvelopeRejection::MissingAuthority)
        );
        // The same envelope is FINE for a non-authority message.
        assert_eq!(
            admit_envelope(&missing, &DEFAULT_LIMITS, false, &[]),
            Ok(())
        );
        let mut no_identity = envelope();
        no_identity.durable_identity = None;
        assert_eq!(
            admit_envelope(&no_identity, &DEFAULT_LIMITS, true, &[]),
            Err(EnvelopeRejection::MissingAuthority)
        );
    }

    #[test]
    fn envelope_carries_every_bead_field() {
        // Exhaustive destructure: schema completeness against the bead
        // list.
        let RabsEnvelope {
            application_version: _,
            session_id: _,
            authenticated_roles: _,
            coordinator_authority: _,
            trace_id: _,
            sender: _,
            destination: _,
            durable_identity: _,
            subscriber_id: _,
            idempotency_key: _,
            sequence_domain: _,
            sequence: _,
            payload_length: _,
            collection_counts: _,
            nesting_depth: _,
            manifest_fanout: _,
            decompressed_bytes: _,
            capability_scope: _,
            privacy: _,
            response_to: _,
            resume_from: _,
            unknown_authority_fields: _,
            unknown_plain_fields: _,
        } = envelope();
    }
}
