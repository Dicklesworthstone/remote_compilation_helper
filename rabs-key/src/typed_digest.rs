//! Typed SHA-256 V1 digest computation (bead F034; plan §56; risk R121).
//!
//! Every authoritative V1 digest is:
//!
//! ```text
//! SHA-256( domain_bytes || 0x00 || u64-LE(len(canonical)) || canonical )
//! ```
//!
//! - the **domain separator** plus the `0x00` terminator makes digests
//!   from different domains structurally incomparable (and prevents a
//!   domain string from bleeding into payload bytes);
//! - the **length framing** prevents boundary ambiguity between domain,
//!   length, and payload;
//! - the result is an [`rabs_protocol::result_identity::TypedDigest`]
//!   carrying algorithm + domain + bytes, so equality already requires
//!   all three (the type-level half of R121; this module is the
//!   computation half);
//! - changing algorithm, framing, or a domain string is a new epoch and a
//!   cold namespace (F002) — never an in-place reinterpretation.
//!
//! BLAKE3 may accelerate local prechecks elsewhere but is never
//! substituted for an authoritative V1 digest.

use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use sha2::{Digest, Sha256};

/// Digest domain for action keys.
pub const DOMAIN_ACTION_KEY: &str = "rabs.action-key.sha256.v1";
/// Digest domain for canonical descriptors.
pub const DOMAIN_DESCRIPTOR: &str = "rabs.descriptor.sha256.v1";
/// Digest domain for coordinator authority values.
pub const DOMAIN_COORDINATOR_AUTHORITY: &str = "rabs.coordinator-authority.v1";
/// Digest domain for semantic result projections.
pub const DOMAIN_SEMANTIC_RESULT: &str = "rabs.semantic-result.v1";
/// Digest domain for observable result projections.
pub const DOMAIN_OBSERVABLE_RESULT: &str = "rabs.observable-result.v1";

/// Compute the typed SHA-256 V1 digest of `canonical` bytes in `domain`.
#[must_use]
pub fn compute(domain: &'static str, canonical: &[u8]) -> TypedDigest {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update((canonical.len() as u64).to_le_bytes());
    h.update(canonical);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// GOLDEN known-answer: pins algorithm + framing forever. Drift means
    /// a new digest epoch (cold namespace), not a fixture update.
    #[test]
    fn golden_known_answer_is_pinned() {
        let d = compute(DOMAIN_ACTION_KEY, b"example-canonical-bytes");
        assert_eq!(
            hex(&d.bytes),
            "91dab8de8f7e2d4df87f10c66d50f0f930debccf2b58bc9162ebe51f89870a2e",
            "digest framing drifted — that is a NEW DIGEST EPOCH (F002), \
             never a golden update; got {}",
            hex(&d.bytes)
        );
    }

    #[test]
    fn same_bytes_different_domains_never_collide() {
        let a = compute(DOMAIN_ACTION_KEY, b"payload");
        let b = compute(DOMAIN_DESCRIPTOR, b"payload");
        assert_ne!(a, b, "typed inequality (different domain field)");
        assert_ne!(a.bytes, b.bytes, "raw bytes differ too (domain separation)");
    }

    #[test]
    fn framing_prevents_domain_payload_boundary_ambiguity() {
        // Without the 0x00 + length framing, domain "rabs.a" + payload
        // "b…" could collide with domain "rabs.ab" + shifted payload.
        let a = compute("rabs.frame-test.a", b"b-payload");
        let b = compute("rabs.frame-test.ab", b"-payload");
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn empty_and_prefix_payloads_are_distinct() {
        let empty = compute(DOMAIN_ACTION_KEY, b"");
        let one = compute(DOMAIN_ACTION_KEY, b"\0");
        assert_ne!(empty.bytes, one.bytes);
    }

    #[test]
    fn deterministic_across_invocations() {
        let a = compute(DOMAIN_SEMANTIC_RESULT, b"same input");
        let b = compute(DOMAIN_SEMANTIC_RESULT, b"same input");
        assert_eq!(a, b);
    }
}
