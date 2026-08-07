//! Non-UTF8 argv/path/env round-trip fixtures — capture, keys, and
//! display escaping (bead T026; risk R89; A019 contract).
//!
//! On Unix these are arbitrary byte strings. The fixtures prove the
//! bytes survive capture and keying EXACTLY, that lossy-decode twins
//! never merge, and that the presentation escape is injective — the
//! storage/materialization half of T026 lives in
//! `rabs-cas/tests/non_utf8_fs.rs`.

use rabs_key::canonical::CanonicalEncoder;
use rabs_key::typed_digest::compute;
use rabs_protocol::raw_bytes::RawBytes;

/// The classic lossy-decode twins: UTF-8 "café" vs Latin-1 "café".
const CAFE_UTF8: &[u8] = b"caf\xC3\xA9";
const CAFE_LATIN1: &[u8] = b"caf\xE9";

#[test]
fn capture_preserves_exact_bytes_and_twins_stay_distinct() {
    // Capture: the exact OS bytes, nothing normalized.
    let utf8 = RawBytes::new(CAFE_UTF8.to_vec());
    let latin1 = RawBytes::new(CAFE_LATIN1.to_vec());
    assert_eq!(utf8.as_bytes(), CAFE_UTF8);
    assert_eq!(latin1.as_bytes(), CAFE_LATIN1);
    assert_ne!(utf8, latin1, "lossy-decode twins are different inputs");
    // The Latin-1 spelling is not UTF-8 — and that is a presentation
    // fact, not a capture failure.
    assert!(latin1.as_utf8().is_none());
    assert_eq!(utf8.as_utf8(), Some("café"));
}

#[test]
fn non_utf8_argv_env_and_paths_key_byte_for_byte() {
    // Keys consume the raw bytes: the twins fork the digest, and an
    // argv/env/path spelling difference of ONE byte forks it.
    let key = |argv: &[u8], env_val: &[u8], path: &[u8]| {
        let mut enc = CanonicalEncoder::new();
        enc.bytes(argv).bytes(env_val).bytes(path);
        compute("rabs.t026.fixture", &enc.finish())
    };
    let base = key(CAFE_UTF8, b"LC_ALL=C", b"/__rabs/ws/caf\xC3\xA9.rs");
    assert_ne!(
        base,
        key(CAFE_LATIN1, b"LC_ALL=C", b"/__rabs/ws/caf\xC3\xA9.rs"),
        "argv twin forks"
    );
    assert_ne!(
        base,
        key(CAFE_UTF8, b"LC_ALL=C\xFF", b"/__rabs/ws/caf\xC3\xA9.rs"),
        "env byte forks"
    );
    assert_ne!(
        base,
        key(CAFE_UTF8, b"LC_ALL=C", b"/__rabs/ws/caf\xE9.rs"),
        "path twin forks"
    );
    // And recomputation is bit-exact (round-trip control).
    assert_eq!(
        base,
        key(CAFE_UTF8, b"LC_ALL=C", b"/__rabs/ws/caf\xC3\xA9.rs")
    );
}

#[test]
fn length_framing_keeps_adjacent_raw_fields_apart() {
    // Two spellings that concatenate identically must not collide:
    // ("ab", "c") vs ("a", "bc") with high bytes in the mix.
    let pair = |a: &[u8], b: &[u8]| {
        let mut enc = CanonicalEncoder::new();
        enc.bytes(a).bytes(b);
        compute("rabs.t026.frame", &enc.finish())
    };
    assert_ne!(pair(b"a\xFF", b"\xFEz"), pair(b"a\xFF\xFE", b"z"));
    assert_ne!(pair(b"", b"\x00\x00"), pair(b"\x00", b"\x00"));
}

#[test]
fn display_escaping_is_injective_on_the_nasty_pairs() {
    // The pairs a naive escape merges: literal backslash-x sequences
    // vs the raw byte they'd render, and the twins.
    let nasty: [&[u8]; 5] = [
        b"a\\xff", // literal chars: 'a' '\' 'x' 'f' 'f'
        b"a\xFF",  // 'a' + raw 0xFF
        CAFE_UTF8,
        CAFE_LATIN1,
        b"tab\tnul\0end",
    ];
    let rendered: Vec<String> = nasty
        .iter()
        .map(|b| RawBytes::new(b.to_vec()).escaped())
        .collect();
    for (i, x) in rendered.iter().enumerate() {
        for (j, y) in rendered.iter().enumerate() {
            if i != j {
                assert_ne!(x, y, "escape must render distinct bytes distinctly");
            }
        }
    }
    // Pin the two headline renderings.
    assert_eq!(rendered[0], "a\\\\xff", "the literal backslash escapes");
    assert_eq!(rendered[1], "a\\xff", "the raw byte hex-escapes");
}
