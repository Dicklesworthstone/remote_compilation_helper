//! Collision fail-closed admission (bead T044's store half; H003
//! rule 8).
//!
//! When an object arrives whose digest the store already holds, there
//! are exactly three outcomes — and "pick one of the two contents"
//! is NOT among them:
//!
//! - digest unknown → store it;
//! - digest known, bytes IDENTICAL → idempotent duplicate (a no-op);
//! - digest known, bytes DIFFER → a collision (or corruption): the
//!   admission REFUSES with a typed quarantine that preserves BOTH
//!   candidates for forensics. The store never chooses a winner —
//!   a SHA-256 collision or a corrupted upload is an incident, not
//!   a tie-break.

use rabs_protocol::result_identity::TypedDigest;

/// Stable reason code for the quarantine refusal.
pub const REASON_OBJECT_COLLISION_QUARANTINED: &str = "OBJECT_COLLISION_QUARANTINED";

/// Successful admission outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Digest was unknown: the object is stored.
    Stored,
    /// Digest known with byte-identical content: idempotent no-op.
    IdempotentDuplicate,
}

/// The fail-closed refusal: existing digest, different bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionQuarantine {
    /// The contested digest.
    pub digest: TypedDigest,
    /// Stable reason code.
    pub reason_code: &'static str,
    /// Length of the bytes already held (preserved, never replaced).
    pub existing_len: u64,
    /// Length of the refused incoming candidate (preserved for
    /// forensics alongside, never promoted).
    pub incoming_len: u64,
}

/// Admit an object under `digest`.
///
/// `existing` — the bytes already stored under this digest, if any.
///
/// # Errors
/// [`CollisionQuarantine`] when the digest exists with different
/// bytes: the store refuses rather than choosing, and both
/// candidates are preserved.
pub fn admit(
    digest: &TypedDigest,
    existing: Option<&[u8]>,
    incoming: &[u8],
) -> Result<Admission, CollisionQuarantine> {
    match existing {
        None => Ok(Admission::Stored),
        Some(held) if held == incoming => Ok(Admission::IdempotentDuplicate),
        Some(held) => Err(CollisionQuarantine {
            digest: digest.clone(),
            reason_code: REASON_OBJECT_COLLISION_QUARANTINED,
            existing_len: held.len() as u64,
            incoming_len: incoming.len() as u64,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    #[test]
    fn unknown_digest_stores_and_identical_bytes_are_idempotent() {
        assert_eq!(admit(&d(1), None, b"content"), Ok(Admission::Stored));
        assert_eq!(
            admit(&d(1), Some(b"content"), b"content"),
            Ok(Admission::IdempotentDuplicate)
        );
    }

    #[test]
    fn existing_digest_different_bytes_quarantines_never_chooses() {
        // THE H003-rule-8 fixture: the simulated collision. The store
        // refuses; the result type offers no way to pick a winner.
        let refusal = admit(&d(1), Some(b"original artifact bytes"), b"DIFFERENT bytes")
            .expect_err("collision must refuse");
        assert_eq!(refusal.reason_code, REASON_OBJECT_COLLISION_QUARANTINED);
        assert_eq!(refusal.digest, d(1));
        // Both candidates preserved for forensics — the refusal
        // records both, and Admission has no "replaced"/"kept-mine"
        // variant (exhaustive match is the proof).
        assert_eq!(refusal.existing_len, 23);
        assert_eq!(refusal.incoming_len, 15);
        match admit(&d(2), None, b"x").expect("stores") {
            Admission::Stored | Admission::IdempotentDuplicate => {}
        }
    }

    #[test]
    fn empty_content_edge_cases_stay_fail_closed() {
        // Empty vs nonempty under one digest is still a collision.
        let refusal = admit(&d(3), Some(b""), b"now nonempty").expect_err("refuses");
        assert_eq!(refusal.existing_len, 0);
        // Empty vs empty is idempotent.
        assert_eq!(
            admit(&d(3), Some(b""), b""),
            Ok(Admission::IdempotentDuplicate)
        );
    }
}
