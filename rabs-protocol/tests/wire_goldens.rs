//! Golden wire fixtures per message family (bead J003; plan §87;
//! risk R10's drift arm).
//!
//! Every wire-encoded family gets a COMMITTED golden byte string:
//! drift in any encoder fails CI here before it breaks a fleet.
//! The suite is the message CATALOG — each entry names its family,
//! builds the canonical value, and pins the exact bytes; new families
//! join by adding an entry (and the catalog-count assertion forces the
//! addition to be deliberate).
//!
//! N/N-1 coverage: the J002 negotiation fixture pins that an N-1 peer
//! agreeing on the older version still decodes the frame family (the
//! frame layout is transport-stable across the negotiated range).

use rabs_protocol::frame_extensions::{decode_extensions, encode_extensions};
use rabs_protocol::framing::{Decoded, FrameCodec};
use rabs_protocol::version_negotiation::{Negotiation, VersionHello, VersionRange, negotiate};

/// One catalog entry: family name + produced bytes + golden bytes.
struct GoldenEntry {
    family: &'static str,
    produced: Vec<u8>,
    golden: Vec<u8>,
}

/// Build the full wire catalog (every family with an encoder today).
fn catalog() -> Vec<GoldenEntry> {
    let codec = FrameCodec::default();
    // Family: frame — length-prefixed payload.
    let frame = GoldenEntry {
        family: "frame.v1",
        produced: codec.encode(b"rabs").unwrap(),
        golden: [4u32.to_le_bytes().as_slice(), b"rabs"].concat(),
    };
    // Family: frame with empty payload (the degenerate golden).
    let empty_frame = GoldenEntry {
        family: "frame.v1/empty",
        produced: codec.encode(b"").unwrap(),
        golden: 0u32.to_le_bytes().to_vec(),
    };
    // Family: extensions — canonical sorted key/value block (J001).
    let extensions = GoldenEntry {
        family: "extensions.v1",
        produced: encode_extensions(&[(7, b"lease".to_vec()), (1, b"op".to_vec())]).unwrap(),
        golden: [
            2u64.to_le_bytes().as_slice(),
            &1u32.to_le_bytes(),
            &2u64.to_le_bytes(),
            b"op",
            &7u32.to_le_bytes(),
            &5u64.to_le_bytes(),
            b"lease",
        ]
        .concat(),
    };
    // Family: framed extensions — the composed carrier (extensions
    // block travelling as a frame payload).
    let composed_payload = encode_extensions(&[(42, vec![0xFF])]).unwrap();
    let framed_extensions = GoldenEntry {
        family: "frame.v1+extensions.v1",
        produced: codec.encode(&composed_payload).unwrap(),
        golden: {
            let inner = [
                1u64.to_le_bytes().as_slice(),
                &42u32.to_le_bytes(),
                &1u64.to_le_bytes(),
                &[0xFF],
            ]
            .concat();
            [(inner.len() as u32).to_le_bytes().as_slice(), &inner].concat()
        },
    };
    vec![frame, empty_frame, extensions, framed_extensions]
}

#[test]
fn every_family_matches_its_committed_golden() {
    // THE acceptance: drift in any encoder fails HERE.
    let entries = catalog();
    assert_eq!(
        entries.len(),
        4,
        "the catalog count is deliberate — a new family must be added \
         consciously with its golden"
    );
    for entry in &entries {
        assert_eq!(
            entry.produced, entry.golden,
            "family `{}` drifted from its golden bytes",
            entry.family
        );
    }
}

#[test]
fn goldens_decode_back_differentially() {
    // Differential encoder/decoder coverage: the GOLDEN bytes (not the
    // freshly produced ones) decode to the expected values — a decoder
    // regression cannot hide behind a matching encoder regression.
    let codec = FrameCodec::default();
    let golden_frame = [4u32.to_le_bytes().as_slice(), b"rabs"].concat();
    let Decoded::Frame { payload, consumed } = codec.decode(&golden_frame).unwrap() else {
        panic!("golden frame must decode");
    };
    assert_eq!(payload, b"rabs");
    assert_eq!(consumed, 8);
    let golden_extensions = [
        2u64.to_le_bytes().as_slice(),
        &1u32.to_le_bytes(),
        &2u64.to_le_bytes(),
        b"op",
        &7u32.to_le_bytes(),
        &5u64.to_le_bytes(),
        b"lease",
    ]
    .concat();
    assert_eq!(
        decode_extensions(&golden_extensions).unwrap(),
        vec![(1, b"op".to_vec()), (7, b"lease".to_vec())]
    );
}

#[test]
fn n_minus_1_negotiated_sessions_still_decode_the_frame_family() {
    // N/N-1 coverage: the frame layout is transport-stable across the
    // negotiated range — an N node speaking to an N-1 node agrees on
    // the older application version, and the SAME golden frame bytes
    // decode on both.
    let n = VersionHello {
        transport: VersionRange {
            minimum_compatible: 2,
            current: 3,
        },
        application: VersionRange {
            minimum_compatible: 6,
            current: 7,
        },
    };
    let n_minus_1 = VersionHello {
        transport: VersionRange {
            minimum_compatible: 1,
            current: 2,
        },
        application: VersionRange {
            minimum_compatible: 5,
            current: 6,
        },
    };
    let Negotiation::Agreed {
        transport,
        application,
    } = negotiate(&n, &n_minus_1)
    else {
        panic!("N/N-1 must negotiate");
    };
    assert_eq!((transport, application), (2, 6));
    // The golden frame decodes identically under the negotiated
    // session (framing is version-independent across the range).
    let codec = FrameCodec::default();
    let golden = [4u32.to_le_bytes().as_slice(), b"rabs"].concat();
    assert!(matches!(
        codec.decode(&golden),
        Ok(Decoded::Frame {
            payload: b"rabs",
            ..
        })
    ));
}
