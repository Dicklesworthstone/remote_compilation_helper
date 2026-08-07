//! Recursion/decompression/count limit fuzzing (bead J025; the J004,
//! H031-style, and framing limits under deterministic adversarial
//! input; risk R95).
//!
//! A deterministic PRNG drives thousands of adversarial claims at the
//! pre-allocation admission surfaces (envelope limits, frame length
//! claims, extension blocks) — every hostile input must be rejected
//! CHEAPLY (by integer comparison, before any allocation sized from
//! the claim), and no input may panic. The seeded-bomb corpus pins
//! the canonical attacks by name.

use rabs_protocol::envelope::{
    DEFAULT_LIMITS, EnvelopeRejection, PrivacyClass, RabsEnvelope, admit_envelope,
};
use rabs_protocol::frame_extensions::decode_extensions;
use rabs_protocol::framing::{FrameCodec, FrameError};
use rabs_protocol::wire_time::PeerId;

/// Deterministic PRNG (splitmix64) — no clocks, no OS randomness.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn envelope_with(
    payload: u64,
    counts: Vec<u64>,
    nesting: u32,
    fanout: u64,
    decompressed: u64,
) -> RabsEnvelope {
    RabsEnvelope {
        application_version: 7,
        session_id: 1,
        authenticated_roles: vec![],
        coordinator_authority: None,
        trace_id: 1,
        sender: PeerId("peer".into()),
        destination: PeerId("daemon".into()),
        durable_identity: None,
        subscriber_id: None,
        idempotency_key: 1,
        sequence_domain: "d".into(),
        sequence: 1,
        payload_length: payload,
        collection_counts: counts,
        nesting_depth: nesting,
        manifest_fanout: fanout,
        decompressed_bytes: decompressed,
        capability_scope: vec![],
        privacy: PrivacyClass::ProjectScoped,
        response_to: None,
        resume_from: None,
        unknown_authority_fields: vec![],
        unknown_plain_fields: vec![],
    }
}

#[test]
fn fuzzed_envelope_claims_never_panic_and_over_limit_always_rejects() {
    // 5000 adversarial claim tuples: extreme values everywhere.
    let mut rng = Rng(0xDEAD_BEEF);
    for _ in 0..5000 {
        let payload = rng.next();
        let counts = vec![rng.next(), rng.next() % 1000];
        let nesting = (rng.next() % (1 << 20)) as u32;
        let fanout = rng.next();
        let decompressed = rng.next();
        let envelope = envelope_with(payload, counts.clone(), nesting, fanout, decompressed);
        let verdict = admit_envelope(&envelope, &DEFAULT_LIMITS, false, &[]);
        // Soundness: any over-limit claim MUST reject; an in-limit
        // claim must admit. No panic occurred by reaching here.
        let over_limit = payload > DEFAULT_LIMITS.max_payload_bytes
            || counts
                .iter()
                .any(|c| *c > DEFAULT_LIMITS.max_collection_entries)
            || nesting > DEFAULT_LIMITS.max_nesting_depth
            || fanout > DEFAULT_LIMITS.max_manifest_fanout
            || decompressed > DEFAULT_LIMITS.max_decompressed_bytes;
        assert_eq!(verdict.is_err(), over_limit);
    }
}

#[test]
fn seeded_bombs_reject_cheaply_by_name() {
    // The canonical attacks, pinned: each rejects via the intended
    // limit — an integer comparison, no allocation sized by the claim.
    let zip_bomb = envelope_with(1024, vec![], 1, 1, u64::MAX);
    assert_eq!(
        admit_envelope(&zip_bomb, &DEFAULT_LIMITS, false, &[]),
        Err(EnvelopeRejection::DecompressionTooLarge)
    );
    let count_bomb = envelope_with(1024, vec![u64::MAX], 1, 1, 0);
    assert!(matches!(
        admit_envelope(&count_bomb, &DEFAULT_LIMITS, false, &[]),
        Err(EnvelopeRejection::CollectionTooLarge { .. })
    ));
    let recursion_bomb = envelope_with(1024, vec![], u32::MAX, 1, 0);
    assert_eq!(
        admit_envelope(&recursion_bomb, &DEFAULT_LIMITS, false, &[]),
        Err(EnvelopeRejection::NestingTooDeep)
    );
    let fanout_bomb = envelope_with(1024, vec![], 1, u64::MAX, 0);
    assert_eq!(
        admit_envelope(&fanout_bomb, &DEFAULT_LIMITS, false, &[]),
        Err(EnvelopeRejection::FanoutTooWide)
    );
}

#[test]
fn fuzzed_frame_headers_reject_oversized_claims_before_payload() {
    // The framing layer: hostile 4-byte length claims. The decoder
    // must reject over-limit claims from the HEADER alone (the buffer
    // holds only 4 bytes — nothing to allocate from).
    let codec = FrameCodec::default();
    let mut rng = Rng(0xFEED_FACE);
    for _ in 0..2000 {
        let claim = (rng.next() % (1 << 33)) as u32;
        let header = claim.to_le_bytes();
        match codec.decode(&header) {
            Err(FrameError::ClaimedLengthTooLarge { claimed, .. }) => {
                assert!(claimed > codec.max_frame_bytes);
            }
            Ok(_) => assert!(claim <= codec.max_frame_bytes),
            Err(other) => panic!("unexpected: {other:?}"),
        }
    }
}

#[test]
fn fuzzed_extension_blocks_never_panic() {
    // Random byte soup at the extension decoder: malformed input must
    // error or decode, never panic, and hostile COUNT claims must not
    // cause huge allocations (the decoder walks bytes; a count beyond
    // the buffer dies at the first truncated read).
    let mut rng = Rng(0x0BAD_F00D);
    for _ in 0..2000 {
        let len = (rng.next() % 64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (rng.next() >> 56) as u8).collect();
        let _ = decode_extensions(&bytes); // must not panic
    }
    // The canonical count-bomb: claims 2^63 entries in 8 bytes.
    let mut bomb = Vec::new();
    bomb.extend_from_slice(&(1u64 << 63).to_le_bytes());
    assert!(decode_extensions(&bomb).is_err(), "dies at the first read");
}
