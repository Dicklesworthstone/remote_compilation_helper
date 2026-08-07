//! Canonical serialization for key components (bead F001; plan §51).
//!
//! Two logically identical values MUST produce identical bytes, forever,
//! across versions and implementations — because these bytes feed the
//! typed SHA-256 action-key digests (F034). The encoding is deliberately
//! tiny and total:
//!
//! - **length-delimited byte strings**: `u64-LE length || bytes` — no
//!   escaping, no terminators, byte-preserving (A019);
//! - **integers**: fixed-width little-endian (`u32`/`u64`);
//! - **booleans**: one byte, `0`/`1`;
//! - **options**: presence byte (`0`/`1`) then the value — an absent value
//!   is distinct from any present value including empty;
//! - **sequences**: `u64-LE count` then elements — `["ab","c"]` and
//!   `["a","bc"]` differ by construction;
//! - **sets/maps**: caller sorts by raw-byte order first (`sorted_bytes`
//!   helper) — insertion order can never rename a set (mirrors the
//!   evidence-set rule, A020);
//! - **field order**: struct encoders write fields in declaration order,
//!   fixed by the component schema version; there are no optional/skipped
//!   fields, no maps with unordered iteration, and no
//!   architecture-dependent layout (the wire format is NOT Rust `repr`,
//!   serde output, or an incidental enum layout).
//!
//! Golden fixtures pin the exact bytes; a change to any rule is a new
//! schema version and a cold key namespace (F002 epoch doctrine).

/// Canonical byte encoder. Append-only; the produced buffer is the exact
/// digest input.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CanonicalEncoder {
    buf: Vec<u8>,
}

impl CanonicalEncoder {
    /// New empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// The canonical bytes so far.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Length-delimited raw bytes.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(&(b.len() as u64).to_le_bytes());
        self.buf.extend_from_slice(b);
        self
    }

    /// UTF-8 string as length-delimited bytes (no distinct string type on
    /// the wire; strings are just bytes that happen to be UTF-8).
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// Fixed-width `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Fixed-width `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Boolean as one byte.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(u8::from(v));
        self
    }

    /// Option: presence byte then the value via `f`.
    pub fn option<T>(&mut self, v: Option<&T>, f: impl FnOnce(&mut Self, &T)) -> &mut Self {
        match v {
            None => {
                self.buf.push(0);
            }
            Some(t) => {
                self.buf.push(1);
                f(self, t);
            }
        }
        self
    }

    /// Sequence: count then elements via `f` (order is semantic).
    pub fn seq<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) -> &mut Self {
        self.buf
            .extend_from_slice(&(items.len() as u64).to_le_bytes());
        for it in items {
            f(self, it);
        }
        self
    }
}

/// Sort a set of byte strings into canonical (raw-byte) order, removing
/// duplicates: the mandatory step before encoding any semantic SET so
/// insertion order can never produce two names for one set.
#[must_use]
pub fn sorted_bytes(mut items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    items.sort_unstable();
    items.dedup();
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GOLDEN: the exact bytes for a representative composite value. Any
    /// rule change breaks this fixture and is therefore a deliberate,
    /// versioned decision (new schema version + cold namespace, F002).
    #[test]
    fn golden_composite_encoding_is_pinned() {
        let mut e = CanonicalEncoder::new();
        e.u32(7)
            .str("ab")
            .bool(true)
            .option(Some(&5u64), |e, v| {
                e.u64(*v);
            })
            .option(None::<&u64>, |e, v| {
                e.u64(*v);
            })
            .seq(&["x", "yz"], |e, s| {
                e.str(s);
            });
        let got = e.finish();
        let expect: Vec<u8> = [
            &7u32.to_le_bytes()[..], // u32 7
            &2u64.to_le_bytes()[..], // len("ab")
            b"ab",                   // bytes
            &[1u8][..],              // bool true
            &[1u8][..],              // Some
            &5u64.to_le_bytes()[..], // 5u64
            &[0u8][..],              // None
            &2u64.to_le_bytes()[..], // seq count
            &1u64.to_le_bytes()[..], // len("x")
            b"x",
            &2u64.to_le_bytes()[..], // len("yz")
            b"yz",
        ]
        .concat();
        assert_eq!(
            got, expect,
            "canonical encoding drifted: that is a new \
                                 schema version, not an edit"
        );
    }

    #[test]
    fn length_delimiting_preserves_element_boundaries() {
        let mut a = CanonicalEncoder::new();
        a.seq(&["ab", "c"], |e, s| {
            e.str(s);
        });
        let mut b = CanonicalEncoder::new();
        b.seq(&["a", "bc"], |e, s| {
            e.str(s);
        });
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn absent_is_distinct_from_present_empty() {
        let mut none = CanonicalEncoder::new();
        none.option(None::<&Vec<u8>>, |e, v| {
            e.bytes(v);
        });
        let mut some_empty = CanonicalEncoder::new();
        some_empty.option(Some(&Vec::new()), |e, v: &Vec<u8>| {
            e.bytes(v);
        });
        assert_ne!(
            none.finish(),
            some_empty.finish(),
            "absent env var vs present-empty is a semantic distinction (F006)"
        );
    }

    #[test]
    fn set_encoding_is_insertion_order_free() {
        let a = sorted_bytes(vec![b"beta".to_vec(), b"alpha".to_vec(), b"beta".to_vec()]);
        let b = sorted_bytes(vec![b"alpha".to_vec(), b"beta".to_vec()]);
        assert_eq!(a, b);
        let mut ea = CanonicalEncoder::new();
        ea.seq(&a, |e, v| {
            e.bytes(v);
        });
        let mut eb = CanonicalEncoder::new();
        eb.seq(&b, |e, v| {
            e.bytes(v);
        });
        assert_eq!(ea.finish(), eb.finish());
    }

    #[test]
    fn determinism_across_repeated_encodings() {
        let encode = || {
            let mut e = CanonicalEncoder::new();
            e.str("same").u64(99).bool(false);
            e.finish()
        };
        assert_eq!(encode(), encode());
    }

    #[test]
    fn non_utf8_bytes_encode_verbatim() {
        let raw: &[u8] = b"caf\xE9";
        let mut e = CanonicalEncoder::new();
        e.bytes(raw);
        let out = e.finish();
        assert_eq!(&out[8..], raw, "bytes are preserved exactly (A019)");
    }
}
