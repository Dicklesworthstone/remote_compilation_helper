//! Bounded wrapper-chain recursion detection and authenticated
//! self-host bypass (bead C015; invariant I36; risk R70).
//!
//! Two environment markers ride the wrapper chain, and BOTH are
//! authenticated with the per-installation key, because arbitrary user
//! env values must never silently change policy:
//!
//! - the **chain marker** carries the authenticated re-entry depth. A
//!   wrapper mints depth `d+1` for its children; at
//!   [`MAX_WRAPPER_DEPTH`] the loop breaks by running the original
//!   chain — a REPORTED loop incident, never a silent skip. A forged or
//!   corrupt chain marker authenticates nothing: it counts as a fresh
//!   chain (depth 0), so tampering yields MORE interception, not less;
//! - the **bypass marker** authorizes exactly ONE named self-host
//!   operation (RABS building/upgrading itself) to run without
//!   re-interception. It is minted by the edge with the installation
//!   key; a forged tag, a replay against a different operation, or any
//!   malformation is a typed refusal and the wrapper intercepts
//!   normally.
//!
//! The MAC is SipHash-2-4 — a published keyed PRF designed for exactly
//! this short-message authentication — implemented here from the
//! reference specification (this crate is deliberately
//! zero-dependency) and pinned against the reference test vectors from
//! the SipHash repository.

/// Maximum wrapper re-entry depth before the loop breaks.
pub const MAX_WRAPPER_DEPTH: u32 = 4;

const SIPROUNDS_COMPRESS: usize = 2;
const SIPROUNDS_FINALIZE: usize = 4;

#[inline]
const fn sipround(mut v: [u64; 4]) -> [u64; 4] {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
    v
}

/// SipHash-2-4 per the reference specification (Aumasson/Bernstein).
#[must_use]
pub fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));
    let mut v = [
        0x736f_6d65_7073_6575 ^ k0,
        0x646f_7261_6e64_6f6d ^ k1,
        0x6c79_6765_6e65_7261 ^ k0,
        0x7465_6462_7974_6573 ^ k1,
    ];
    let (blocks, tail) = data.as_chunks::<8>();
    for chunk in blocks {
        let m = u64::from_le_bytes(*chunk);
        v[3] ^= m;
        for _ in 0..SIPROUNDS_COMPRESS {
            v = sipround(v);
        }
        v[0] ^= m;
    }
    let mut last = [0_u8; 8];
    last[..tail.len()].copy_from_slice(tail);
    last[7] = (data.len() & 0xff) as u8;
    let m = u64::from_le_bytes(last);
    v[3] ^= m;
    for _ in 0..SIPROUNDS_COMPRESS {
        v = sipround(v);
    }
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..SIPROUNDS_FINALIZE {
        v = sipround(v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

fn chain_tag(key: &[u8; 16], depth: u32) -> u64 {
    let mut claims = Vec::with_capacity(32);
    claims.extend_from_slice(b"rabs.wrapper-chain.v1");
    claims.extend_from_slice(&depth.to_be_bytes());
    siphash24(key, &claims)
}

fn bypass_tag(key: &[u8; 16], operation: u64, issued_depth: u32) -> u64 {
    let mut claims = Vec::with_capacity(48);
    claims.extend_from_slice(b"rabs.self-host-bypass.v1");
    claims.extend_from_slice(&operation.to_be_bytes());
    claims.extend_from_slice(&issued_depth.to_be_bytes());
    siphash24(key, &claims)
}

/// Mint the chain marker a wrapper passes to its children.
#[must_use]
pub fn mint_chain_marker(key: &[u8; 16], depth: u32) -> String {
    format!("rabs-chain v1 {depth} {:016x}", chain_tag(key, depth))
}

/// Authenticated chain state decoded from the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainState {
    /// No marker present: a fresh chain at depth 0.
    Fresh,
    /// Authenticated marker at this depth.
    Valid {
        /// The authenticated re-entry depth.
        depth: u32,
    },
    /// A marker was present but malformed or forged. For depth purposes
    /// this counts as fresh (tampering never reduces interception), and
    /// the state is distinguishable so the wrapper can report it.
    Invalid,
}

/// Decode + authenticate a chain marker (`None` = variable absent).
#[must_use]
pub fn validate_chain_marker(key: &[u8; 16], marker: Option<&str>) -> ChainState {
    let Some(marker) = marker else {
        return ChainState::Fresh;
    };
    let mut parts = marker.split(' ');
    let (Some("rabs-chain"), Some("v1"), Some(depth), Some(tag), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return ChainState::Invalid;
    };
    let Ok(depth) = depth.parse::<u32>() else {
        return ChainState::Invalid;
    };
    let Ok(tag) = u64::from_str_radix(tag, 16) else {
        return ChainState::Invalid;
    };
    if tag != chain_tag(key, depth) {
        return ChainState::Invalid;
    }
    ChainState::Valid { depth }
}

/// Mint a bypass marker authorizing ONE self-host operation.
#[must_use]
pub fn mint_bypass_marker(key: &[u8; 16], operation: u64, issued_depth: u32) -> String {
    format!(
        "rabs-bypass v1 {operation:016x} {issued_depth} {:016x}",
        bypass_tag(key, operation, issued_depth)
    )
}

/// Typed bypass validation outcome. Every non-`Authorized` outcome
/// means the wrapper intercepts NORMALLY — a refused marker never
/// changes policy silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassVerdict {
    /// Authenticated marker for the expected operation.
    Authorized,
    /// Structurally not a marker.
    RefusedMalformed,
    /// Structure fine, tag does not authenticate (forgery/tamper).
    RefusedForged,
    /// Authenticated, but for a DIFFERENT self-host operation (replay).
    RefusedWrongOperation,
}

/// Validate a bypass marker against the expected self-host operation.
#[must_use]
pub fn validate_bypass_marker(
    key: &[u8; 16],
    marker: &str,
    expected_operation: u64,
) -> BypassVerdict {
    let mut parts = marker.split(' ');
    let (Some("rabs-bypass"), Some("v1"), Some(operation), Some(depth), Some(tag), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return BypassVerdict::RefusedMalformed;
    };
    let Ok(operation) = u64::from_str_radix(operation, 16) else {
        return BypassVerdict::RefusedMalformed;
    };
    let Ok(depth) = depth.parse::<u32>() else {
        return BypassVerdict::RefusedMalformed;
    };
    let Ok(tag) = u64::from_str_radix(tag, 16) else {
        return BypassVerdict::RefusedMalformed;
    };
    if tag != bypass_tag(key, operation, depth) {
        return BypassVerdict::RefusedForged;
    }
    if operation != expected_operation {
        return BypassVerdict::RefusedWrongOperation;
    }
    BypassVerdict::Authorized
}

/// What the wrapper does after evaluating both markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperAction {
    /// Intercept normally; children receive a chain marker at this
    /// depth.
    InterceptAtDepth {
        /// Depth to mint for children.
        child_depth: u32,
    },
    /// Authenticated self-host bypass: run the original chain without
    /// re-interception.
    RunOriginalSelfHost,
    /// Re-entry depth reached the bound: break the loop by running the
    /// original chain, and REPORT the loop.
    RunOriginalLoopBreak {
        /// The depth at which the detector fired.
        depth: u32,
    },
}

/// Combine the authenticated chain state and an optional bypass marker
/// into the wrapper's action. Precedence: an authenticated bypass wins;
/// then the depth bound; then normal interception.
#[must_use]
pub fn wrapper_action(
    key: &[u8; 16],
    chain_marker: Option<&str>,
    bypass_marker: Option<&str>,
    expected_operation: u64,
) -> WrapperAction {
    if let Some(marker) = bypass_marker
        && validate_bypass_marker(key, marker, expected_operation) == BypassVerdict::Authorized
    {
        return WrapperAction::RunOriginalSelfHost;
    }
    let depth = match validate_chain_marker(key, chain_marker) {
        ChainState::Fresh | ChainState::Invalid => 0,
        ChainState::Valid { depth } => depth,
    };
    if depth >= MAX_WRAPPER_DEPTH {
        WrapperAction::RunOriginalLoopBreak { depth }
    } else {
        WrapperAction::InterceptAtDepth {
            child_depth: depth + 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [42; 16];

    #[test]
    fn siphash24_matches_the_reference_vectors() {
        // First ten vectors from the SipHash reference repository
        // (veorq/SipHash, vectors.h, vectors_sip64): key = 00..0f,
        // input row i = the first i bytes of 00 01 02 ...; outputs are
        // the little-endian bytes of the returned u64.
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let expected: [[u8; 8]; 10] = [
            [0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72],
            [0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74],
            [0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d],
            [0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85],
            [0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf],
            [0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18],
            [0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb],
            [0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab],
            [0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93],
            [0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e],
        ];
        let input: Vec<u8> = (0..10).map(|i| i as u8).collect();
        for (len, want) in expected.iter().enumerate() {
            let got = siphash24(&key, &input[..len]).to_le_bytes();
            assert_eq!(&got, want, "reference vector {len} diverged");
        }
    }

    #[test]
    fn recursion_detector_fires_in_a_loop_fixture() {
        // Simulate a re-entry loop: each level validates its parent's
        // marker and mints the child's. The detector must fire at the
        // bound, and the loop-breaking action names the depth.
        let mut marker: Option<String> = None;
        let mut intercepted = 0_u32;
        loop {
            match wrapper_action(&KEY, marker.as_deref(), None, 0) {
                WrapperAction::InterceptAtDepth { child_depth } => {
                    intercepted += 1;
                    marker = Some(mint_chain_marker(&KEY, child_depth));
                }
                WrapperAction::RunOriginalLoopBreak { depth } => {
                    assert_eq!(depth, MAX_WRAPPER_DEPTH);
                    break;
                }
                WrapperAction::RunOriginalSelfHost => unreachable!("no bypass marker"),
            }
            assert!(intercepted <= MAX_WRAPPER_DEPTH, "detector never fired");
        }
        assert_eq!(intercepted, MAX_WRAPPER_DEPTH);
    }

    #[test]
    fn forged_markers_never_reduce_interception() {
        // A forged chain depth (user picked a huge depth without the
        // key) authenticates nothing: fresh chain, normal interception.
        let forged_chain = "rabs-chain v1 4 deadbeefdeadbeef";
        assert_eq!(
            validate_chain_marker(&KEY, Some(forged_chain)),
            ChainState::Invalid
        );
        assert_eq!(
            wrapper_action(&KEY, Some(forged_chain), None, 0),
            WrapperAction::InterceptAtDepth { child_depth: 1 }
        );
        // Tampering with an AUTHENTIC marker's depth also invalidates.
        let genuine = mint_chain_marker(&KEY, 1);
        let tampered = genuine.replace(" 1 ", " 4 ");
        assert_eq!(
            validate_chain_marker(&KEY, Some(tampered.as_str())),
            ChainState::Invalid
        );
        // Garbage is Invalid, absent is Fresh — both intercept.
        assert_eq!(
            validate_chain_marker(&KEY, Some("not a marker")),
            ChainState::Invalid
        );
        assert_eq!(validate_chain_marker(&KEY, None), ChainState::Fresh);
    }

    #[test]
    fn forged_bypass_markers_are_rejected_typed() {
        let genuine = mint_bypass_marker(&KEY, 77, 0);
        assert_eq!(
            validate_bypass_marker(&KEY, &genuine, 77),
            BypassVerdict::Authorized
        );
        // Wrong key (an attacker without the installation secret).
        let other_key = [9; 16];
        assert_eq!(
            validate_bypass_marker(&other_key, &genuine, 77),
            BypassVerdict::RefusedForged
        );
        // Tampered operation field.
        let tampered =
            mint_bypass_marker(&KEY, 77, 0).replace("000000000000004d", "000000000000004e");
        assert_eq!(
            validate_bypass_marker(&KEY, &tampered, 78),
            BypassVerdict::RefusedForged
        );
        // Authentic marker replayed against a DIFFERENT operation.
        assert_eq!(
            validate_bypass_marker(&KEY, &genuine, 78),
            BypassVerdict::RefusedWrongOperation
        );
        // Malformation.
        assert_eq!(
            validate_bypass_marker(&KEY, "rabs-bypass v1 zz 0 00", 77),
            BypassVerdict::RefusedMalformed
        );
        // A refused bypass falls through to NORMAL interception —
        // policy is never silently disabled.
        assert_eq!(
            wrapper_action(&KEY, None, Some(&genuine), 78),
            WrapperAction::InterceptAtDepth { child_depth: 1 }
        );
    }

    #[test]
    fn authentic_self_host_bypass_runs_the_original_chain() {
        // The self-build path: the edge mints a marker for its own
        // build operation; the wrapper validates and steps aside, even
        // mid-chain.
        let marker = mint_bypass_marker(&KEY, 501, 2);
        let chain = mint_chain_marker(&KEY, 2);
        assert_eq!(
            wrapper_action(&KEY, Some(&chain), Some(&marker), 501),
            WrapperAction::RunOriginalSelfHost
        );
    }

    #[test]
    fn marker_round_trips_are_stable() {
        for depth in [0, 1, MAX_WRAPPER_DEPTH, u32::MAX] {
            let marker = mint_chain_marker(&KEY, depth);
            assert_eq!(
                validate_chain_marker(&KEY, Some(&marker)),
                ChainState::Valid { depth }
            );
        }
        let bypass = mint_bypass_marker(&KEY, u64::MAX, u32::MAX);
        assert_eq!(
            validate_bypass_marker(&KEY, &bypass, u64::MAX),
            BypassVerdict::Authorized
        );
    }
}
