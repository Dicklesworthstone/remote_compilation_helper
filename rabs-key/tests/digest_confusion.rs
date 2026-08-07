//! Typed-digest confusion + framing fixtures (bead T044; risks
//! R121; F034 framing; H003 rule 8's key-side half).
//!
//! The fixture suite that tries to CONFUSE the digest machinery and
//! proves each attempt fails closed:
//!
//! - cross-domain comparison never succeeds (type-level AND
//!   value-level);
//! - the canonical length framing defeats every boundary-shift
//!   spelling of the same byte stream;
//! - a hand-forged digest with the right bytes but the wrong domain
//!   is a different value, not a hit.

use rabs_key::typed_digest::{DOMAIN_ACTION_KEY, DOMAIN_DESCRIPTOR, compute};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

#[test]
fn cross_domain_digests_never_compare_equal() {
    // Same payload, two domains: different bytes AND unequal values.
    let action = compute(DOMAIN_ACTION_KEY, b"identical payload");
    let descriptor = compute(DOMAIN_DESCRIPTOR, b"identical payload");
    assert_ne!(action.bytes, descriptor.bytes, "domain separation holds");
    assert_ne!(action, descriptor);
    // The confusion attack proper: graft the action-key BYTES onto
    // the descriptor DOMAIN. Equality requires all three fields, so
    // the forgery is simply a different value.
    let forged = TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: DOMAIN_DESCRIPTOR,
        bytes: action.bytes,
    };
    assert_ne!(forged, action, "same bytes, wrong domain: not equal");
    assert_ne!(forged, descriptor, "right domain, wrong bytes: not equal");
}

#[test]
fn boundary_shift_spellings_all_produce_distinct_digests() {
    // Every way of slicing one concatenated byte stream across the
    // domain/payload boundary digests differently (the length framing
    // plus the domain terminator).
    let candidates = [
        compute("rabs.t044.a", b"bc-payload"),
        compute("rabs.t044.ab", b"c-payload"),
        compute("rabs.t044.abc", b"-payload"),
    ];
    for (i, x) in candidates.iter().enumerate() {
        for y in &candidates[i + 1..] {
            assert_ne!(x.bytes, y.bytes, "boundary shift must not collide");
        }
    }
}

#[test]
fn length_framing_defeats_suffix_and_nul_games() {
    // Empty vs single-NUL payloads.
    let empty = compute(DOMAIN_ACTION_KEY, b"");
    let nul = compute(DOMAIN_ACTION_KEY, b"\0");
    assert_ne!(empty.bytes, nul.bytes);
    // A payload and the same payload with a trailing NUL (a classic
    // unframed-concatenation ambiguity).
    let plain = compute(DOMAIN_ACTION_KEY, b"payload");
    let trailing = compute(DOMAIN_ACTION_KEY, b"payload\0");
    assert_ne!(plain.bytes, trailing.bytes);
    // Embedded NUL cannot re-slice into the domain: the domain ends
    // at ITS terminator, and the payload length is framed.
    let embedded = compute(DOMAIN_ACTION_KEY, b"pay\0load");
    assert_ne!(embedded.bytes, plain.bytes);
    assert_ne!(embedded.bytes, trailing.bytes);
}

#[test]
fn determinism_is_exact_and_the_algorithm_set_is_closed() {
    // Recomputation is bit-exact (the suite's control), and the V1
    // algorithm registry has exactly one member — an exhaustive
    // match, so admitting a second algorithm forces review here.
    let a = compute(DOMAIN_ACTION_KEY, b"stable");
    let b = compute(DOMAIN_ACTION_KEY, b"stable");
    assert_eq!(a, b);
    match a.algorithm {
        DigestAlgorithm::Sha256V1 => {}
    }
}
