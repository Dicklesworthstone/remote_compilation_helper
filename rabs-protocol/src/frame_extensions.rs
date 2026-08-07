//! Canonical ATP frame-extension encoding (bead J001; Asupersync
//! blocker 44.1; risk R10's wire arm).
//!
//! ATP frames carry an extension map (numeric key → bytes). A
//! non-canonical encoding — hash-map iteration order, insertion order —
//! produces DIFFERENT bytes for the SAME logical frame, which breaks
//! replay comparison, signatures, and transcript hashing silently.
//! This module owns the one canonical encoding:
//!
//! - extensions sort by numeric key, strictly ascending (duplicate
//!   keys are a typed error, not last-writer-wins);
//! - `u32`-LE key, `u64`-LE length, raw value bytes — no map type's
//!   iteration order can reach the wire;
//! - golden fixtures pin exact bytes so an implementation change that
//!   moves ANY byte fails loudly here before it breaks replay.

/// Encoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    /// The same key appeared twice with (any) values.
    DuplicateKey(u32),
}

/// Canonically encode an extension set: sorted by key, length-framed.
///
/// Input order is IRRELEVANT by construction — entries are sorted
/// before any byte is written.
///
/// # Errors
/// [`ExtensionError::DuplicateKey`] when one key appears twice.
pub fn encode_extensions(extensions: &[(u32, Vec<u8>)]) -> Result<Vec<u8>, ExtensionError> {
    let mut sorted: Vec<&(u32, Vec<u8>)> = extensions.iter().collect();
    sorted.sort_by_key(|(key, _)| *key);
    for window in sorted.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(ExtensionError::DuplicateKey(window[0].0));
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(sorted.len() as u64).to_le_bytes());
    for (key, value) in sorted {
        out.extend_from_slice(&key.to_le_bytes());
        out.extend_from_slice(&(value.len() as u64).to_le_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// Decode a canonical extension block, VERIFYING canonicality: keys
/// must be strictly ascending (a decoder that accepted unsorted input
/// would let two spellings of one frame coexist).
///
/// # Errors
/// A static description of the malformation.
pub fn decode_extensions(bytes: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, &'static str> {
    let mut cursor = 0usize;
    let take = |cursor: &mut usize, n: usize| -> Result<&[u8], &'static str> {
        let end = cursor.checked_add(n).ok_or("length overflow")?;
        if end > bytes.len() {
            return Err("truncated extension block");
        }
        let slice = &bytes[*cursor..end];
        *cursor = end;
        Ok(slice)
    };
    let count_bytes: [u8; 8] = take(&mut cursor, 8)?.try_into().expect("8 bytes");
    let count = u64::from_le_bytes(count_bytes);
    let mut out = Vec::new();
    let mut last_key: Option<u32> = None;
    for _ in 0..count {
        let key_bytes: [u8; 4] = take(&mut cursor, 4)?.try_into().expect("4 bytes");
        let key = u32::from_le_bytes(key_bytes);
        if let Some(prior) = last_key
            && key <= prior
        {
            return Err("extension keys must be strictly ascending (canonical form)");
        }
        last_key = Some(key);
        let len_bytes: [u8; 8] = take(&mut cursor, 8)?.try_into().expect("8 bytes");
        let len = usize::try_from(u64::from_le_bytes(len_bytes)).map_err(|_| "length overflow")?;
        let value = take(&mut cursor, len)?.to_vec();
        out.push((key, value));
    }
    if cursor != bytes.len() {
        return Err("trailing bytes after extensions");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_set() -> Vec<(u32, Vec<u8>)> {
        vec![
            (7, b"lease".to_vec()),
            (1, b"op".to_vec()),
            (42, vec![0xFF, 0x00]),
        ]
    }

    #[test]
    fn permuted_insertion_orders_encode_byte_identically() {
        // THE acceptance: every permutation of the same set produces
        // one byte string.
        let base = encode_extensions(&fixture_set()).unwrap();
        let permutations: [Vec<usize>; 5] = [
            vec![0, 2, 1],
            vec![1, 0, 2],
            vec![1, 2, 0],
            vec![2, 0, 1],
            vec![2, 1, 0],
        ];
        let set = fixture_set();
        for perm in permutations {
            let reordered: Vec<(u32, Vec<u8>)> = perm.iter().map(|i| set[*i].clone()).collect();
            assert_eq!(
                encode_extensions(&reordered).unwrap(),
                base,
                "insertion order {perm:?} must not reach the wire"
            );
        }
    }

    #[test]
    fn golden_fixture_pins_exact_bytes() {
        // The committed golden: 3 entries, keys 1 < 7 < 42. Any
        // implementation change that moves a byte fails HERE before it
        // breaks replay/signatures/transcript hashing in the field.
        let encoded = encode_extensions(&fixture_set()).unwrap();
        let golden: Vec<u8> = [
            3u64.to_le_bytes().as_slice(), // count
            &1u32.to_le_bytes(),           // key 1
            &2u64.to_le_bytes(),           // len 2
            b"op",                         //
            &7u32.to_le_bytes(),           // key 7
            &5u64.to_le_bytes(),           // len 5
            b"lease",                      //
            &42u32.to_le_bytes(),          // key 42
            &2u64.to_le_bytes(),           // len 2
            &[0xFF, 0x00],                 //
        ]
        .concat();
        assert_eq!(encoded, golden);
    }

    #[test]
    fn round_trip_and_duplicate_rejection() {
        let encoded = encode_extensions(&fixture_set()).unwrap();
        let decoded = decode_extensions(&encoded).unwrap();
        assert_eq!(
            decoded,
            vec![
                (1, b"op".to_vec()),
                (7, b"lease".to_vec()),
                (42, vec![0xFF, 0x00]),
            ]
        );
        // Duplicate keys: typed error, never last-writer-wins.
        assert_eq!(
            encode_extensions(&[(1, b"a".to_vec()), (1, b"b".to_vec())]),
            Err(ExtensionError::DuplicateKey(1))
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_and_malformed_input() {
        // Hand-build an UNSORTED block: two spellings of one frame
        // must not both decode.
        let mut unsorted = Vec::new();
        unsorted.extend_from_slice(&2u64.to_le_bytes());
        unsorted.extend_from_slice(&7u32.to_le_bytes());
        unsorted.extend_from_slice(&0u64.to_le_bytes());
        unsorted.extend_from_slice(&1u32.to_le_bytes());
        unsorted.extend_from_slice(&0u64.to_le_bytes());
        assert!(decode_extensions(&unsorted).is_err());
        // Truncation and trailing garbage reject.
        let good = encode_extensions(&fixture_set()).unwrap();
        assert!(decode_extensions(&good[..good.len() - 1]).is_err());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(decode_extensions(&trailing).is_err());
        // Empty set is canonical.
        let empty = encode_extensions(&[]).unwrap();
        assert_eq!(decode_extensions(&empty).unwrap(), vec![]);
    }
}
