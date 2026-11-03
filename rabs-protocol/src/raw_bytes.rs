//! Byte-preserving path/argv/environment types with escaped presentation
//! (bead A019; invariant I38; risk R89).
//!
//! On Unix, paths, argv elements, environment keys/values, and symlink
//! targets are **arbitrary byte strings**. RABS therefore keys, stores, and
//! transmits the raw bytes; UTF-8 is a *presentation* concern. A lossy
//! conversion is never a semantic key input: `b"caf\xC3\xA9"` and
//! `b"caf\xE9"` are different inputs even though a lossy decode renders
//! both as "café"-ish text.
//!
//! Presentation uses a deterministic, **injective** escape (distinct byte
//! strings always render distinctly), so displays are unambiguous — but the
//! escaped form is for humans/JSON only and never re-enters key
//! construction. Windows gets a separately versioned native encoding
//! contract (not this type).

use std::fmt;

/// Encode arbitrary wire bytes as canonical lowercase hexadecimal, without a prefix.
///
/// Source, toolchain, artifact and diagnostic transfers already bound their
/// input chunks. Reserve the complete output once instead of allocating a
/// temporary formatted string for every input byte. This changes neither the
/// wire representation nor the caller's size limits.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// A canonical byte string: the exact bytes the OS handed us.
///
/// Ordering/equality are plain byte comparisons, which is exactly what
/// canonical serialization needs (sorted sets of raw names, F001).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RawBytes(Vec<u8>);

impl RawBytes {
    /// Wrap raw bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The exact bytes. These — and only these — are what keys and wire
    /// codecs consume.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow as UTF-8 if (and only if) the bytes happen to be valid UTF-8.
    /// Presentation convenience; never a semantic requirement.
    #[must_use]
    pub fn as_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Number of raw bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the byte string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Deterministic, injective escape for presentation:
    /// printable ASCII except backslash passes through; backslash becomes
    /// `\\`; every other byte becomes `\xNN` (lowercase hex).
    ///
    /// Injectivity: the only way to produce `\` in the output is via an
    /// escape, so distinct inputs render distinctly and displays are
    /// unambiguous. The escaped form is presentation-only and must never
    /// feed key construction.
    #[must_use]
    pub fn escaped(&self) -> String {
        let mut out = String::with_capacity(self.0.len());
        for &b in &self.0 {
            match b {
                b'\\' => out.push_str("\\\\"),
                0x20..=0x7E => out.push(char::from(b)),
                _ => {
                    out.push_str("\\x");
                    let hex = |n: u8| char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 });
                    out.push(hex(b >> 4));
                    out.push(hex(b & 0x0F));
                }
            }
        }
        out
    }
}

impl From<&[u8]> for RawBytes {
    fn from(b: &[u8]) -> Self {
        Self(b.to_vec())
    }
}

impl From<&str> for RawBytes {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl fmt::Display for RawBytes {
    /// Displays the escaped presentation form (never raw bytes).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.escaped())
    }
}

/// A byte-preserving filesystem path (Unix: exact `OsStr` bytes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RawPath(pub RawBytes);

/// A byte-preserving argv element.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RawArg(pub RawBytes);

/// A byte-preserving environment pair. Presence/absence semantics live in
/// `PresentedEnvironment` (bead F006); this is just the byte carrier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawEnvPair {
    /// Exact variable-name bytes.
    pub name: RawBytes,
    /// Exact value bytes.
    pub value: RawBytes,
}

/// A byte-preserving symlink target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RawSymlinkTarget(pub RawBytes);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes_every_byte_with_canonical_lowercase_digits() {
        let bytes: Vec<_> = (0_u8..=255).collect();
        let expected = concat!(
            "000102030405060708090a0b0c0d0e0f",
            "101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f",
            "303132333435363738393a3b3c3d3e3f",
            "404142434445464748494a4b4c4d4e4f",
            "505152535455565758595a5b5c5d5e5f",
            "606162636465666768696a6b6c6d6e6f",
            "707172737475767778797a7b7c7d7e7f",
            "808182838485868788898a8b8c8d8e8f",
            "909192939495969798999a9b9c9d9e9f",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        assert_eq!(encode_hex(&bytes), expected);
        assert_eq!(encode_hex(&[]), "");
        assert_eq!(encode_hex(b"\0\n\xff"), "000aff");
    }

    #[test]
    fn hex_matches_existing_wire_format_across_transfer_chunk_boundaries() {
        for len in [0, 1, 2, 31, 32, 255, 256, 65_535, 65_536, 65_537, 131_073] {
            let bytes: Vec<_> = (0_u8..=255).cycle().take(len).collect();
            // Keep the independent incumbent formatter as the wire oracle.
            let expected: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(encode_hex(&bytes), expected, "payload length {len}");
            let chunked: String = bytes.chunks(64 * 1024).map(encode_hex).collect();
            assert_eq!(chunked, expected, "chunked payload length {len}");
        }
    }

    #[test]
    fn non_utf8_bytes_round_trip_exactly() {
        // Latin-1 "café" — NOT valid UTF-8; must survive byte-exact (R89).
        let latin1: &[u8] = b"caf\xE9";
        let raw = RawBytes::from(latin1);
        assert_eq!(raw.as_bytes(), latin1);
        assert!(raw.as_utf8().is_none(), "must not pretend this is UTF-8");
        // The UTF-8 spelling is a DIFFERENT byte string.
        let utf8 = RawBytes::from("café");
        assert_ne!(raw, utf8, "lossy-equivalent spellings must stay distinct");
    }

    #[test]
    fn escape_is_deterministic_and_readable_for_ascii() {
        let raw = RawBytes::from("cargo build --release");
        assert_eq!(raw.escaped(), "cargo build --release");
        assert_eq!(raw.escaped(), raw.escaped());
    }

    #[test]
    fn escape_is_injective_on_tricky_pairs() {
        // The classic ambiguity: a literal backslash-x sequence versus an
        // escaped byte must render differently.
        let literal = RawBytes::from(r"a\xe9");
        let byte = RawBytes::from(&b"a\xE9"[..]);
        assert_ne!(literal.escaped(), byte.escaped());
        assert_eq!(literal.escaped(), r"a\\xe9");
        assert_eq!(byte.escaped(), r"a\xe9");
        // Newlines/controls are escaped, not printed.
        assert_eq!(RawBytes::from("a\nb").escaped(), r"a\x0ab");
    }

    #[test]
    fn ordering_is_byte_ordering() {
        // Canonical serialization sorts by raw bytes, not by rendered text.
        let a = RawBytes::from(&b"\x01"[..]);
        let b = RawBytes::from(&b"A"[..]);
        assert!(a < b);
    }

    #[test]
    fn display_uses_the_escaped_form() {
        let raw = RawBytes::from(&b"x\xFFy"[..]);
        assert_eq!(format!("{raw}"), r"x\xffy");
    }

    #[test]
    fn env_pair_preserves_both_sides() {
        let pair = RawEnvPair {
            name: RawBytes::from("RUSTFLAGS"),
            value: RawBytes::from(&b"-C\xFFweird"[..]),
        };
        assert_eq!(pair.name.as_utf8(), Some("RUSTFLAGS"));
        assert_eq!(pair.value.as_bytes(), b"-C\xFFweird");
    }
}
