//! Deterministic content-defined chunking (bead H004; plan §90; risk
//! R95).
//!
//! FastCDC-style gear-hash chunking with VERSIONED parameters:
//!
//! - a chunking profile (gear table seed, min/avg/max sizes, mask
//!   bits) is identified by `profile_version`; every manifest records
//!   the version it was cut under, and an old manifest is NEVER
//!   reinterpreted with new settings — reassembly needs only the chunk
//!   list, so old manifests stay valid forever while new objects cut
//!   under the new profile;
//! - chunk boundaries are TRANSPORT/STORAGE layout; the whole-object
//!   digest remains the correctness identity (H001's rule) — two
//!   different profiles chunking one object agree on the object and
//!   differ only in manifests;
//! - the algorithm is pure and deterministic: same bytes + same
//!   profile ⇒ identical boundaries on every host, byte-shift-local
//!   (an insertion resynchronizes within a few chunks — the dedup
//!   property fixtures pin).

/// One chunking profile (versioned; parameters never change in place).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkingProfile {
    /// Profile version recorded in every manifest cut under it.
    pub profile_version: u32,
    /// Minimum chunk size (bytes).
    pub min_size: usize,
    /// Mask bits for the cut condition (avg ≈ 2^mask_bits).
    pub mask_bits: u32,
    /// Maximum chunk size (bytes).
    pub max_size: usize,
    /// Gear-table seed (versioned with the profile).
    pub gear_seed: u64,
}

/// The v1 profile: 16 KiB min / ~64 KiB avg / 256 KiB max.
pub const PROFILE_V1: ChunkingProfile = ChunkingProfile {
    profile_version: 1,
    min_size: 16 * 1024,
    mask_bits: 16,
    max_size: 256 * 1024,
    gear_seed: 0x9e37_79b9_7f4a_7c15,
};

/// One cut chunk (offset + length into the source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpan {
    /// Byte offset.
    pub offset: usize,
    /// Byte length.
    pub length: usize,
}

/// A chunk manifest: which profile cut it, and the spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkManifest {
    /// The profile version the spans were cut under. Reassembly never
    /// needs the profile — the field exists so tooling can tell WHICH
    /// settings produced the layout, never to reinterpret it.
    pub profile_version: u32,
    /// The spans, covering the object exactly.
    pub spans: Vec<ChunkSpan>,
}

/// Deterministic gear table derived from the profile seed
/// (splitmix64 — pure, no external crates).
fn gear_table(seed: u64) -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut state = seed;
    for entry in &mut table {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *entry = z ^ (z >> 31);
    }
    table
}

/// Cut `data` into chunks under `profile`.
#[must_use]
pub fn chunk(data: &[u8], profile: &ChunkingProfile) -> ChunkManifest {
    let table = gear_table(profile.gear_seed);
    let mask: u64 = (1u64 << profile.mask_bits) - 1;
    let mut spans = Vec::new();
    let mut start = 0usize;
    while start < data.len() {
        let remaining = data.len() - start;
        if remaining <= profile.min_size {
            spans.push(ChunkSpan {
                offset: start,
                length: remaining,
            });
            break;
        }
        let mut hash: u64 = 0;
        let mut cut = remaining.min(profile.max_size);
        let window_end = remaining.min(profile.max_size);
        for (i, byte) in data[start..start + window_end].iter().enumerate() {
            hash = (hash << 1).wrapping_add(table[*byte as usize]);
            if i >= profile.min_size && (hash & mask) == 0 {
                cut = i + 1;
                break;
            }
        }
        spans.push(ChunkSpan {
            offset: start,
            length: cut,
        });
        start += cut;
    }
    ChunkManifest {
        profile_version: profile.profile_version,
        spans,
    }
}

/// Reassemble an object from its spans (validates exact coverage).
///
/// # Errors
/// A static description if the spans do not tile the object exactly.
pub fn validate_coverage(manifest: &ChunkManifest, object_len: usize) -> Result<(), &'static str> {
    let mut expected = 0usize;
    for span in &manifest.spans {
        if span.offset != expected {
            return Err("spans must tile the object contiguously");
        }
        if span.length == 0 {
            return Err("zero-length span");
        }
        expected += span.length;
    }
    if expected != object_len {
        return Err("spans do not cover the object length");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random test bytes (no RNG in tests).
    fn bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 56) as u8
            })
            .collect()
    }

    #[test]
    fn chunking_is_deterministic_and_bounded() {
        let data = bytes(2 * 1024 * 1024, 7);
        let a = chunk(&data, &PROFILE_V1);
        let b = chunk(&data, &PROFILE_V1);
        assert_eq!(a, b, "same bytes + same profile = identical layout");
        assert!(validate_coverage(&a, data.len()).is_ok());
        for span in &a.spans[..a.spans.len() - 1] {
            assert!(span.length >= PROFILE_V1.min_size, "min bound");
            assert!(span.length <= PROFILE_V1.max_size, "max bound");
        }
        assert!(a.spans.len() > 4, "2 MiB must cut into several chunks");
    }

    #[test]
    fn an_insertion_resynchronizes_locally() {
        // The dedup property: insert bytes near the front; boundaries
        // AFTER resynchronization line up again, so most chunk CONTENT
        // (not offsets) is shared.
        let original = bytes(1024 * 1024, 9);
        let mut edited = original.clone();
        edited.splice(10_000..10_000, bytes(64, 11));
        let a = chunk(&original, &PROFILE_V1);
        let b = chunk(&edited, &PROFILE_V1);
        let content = |data: &[u8], m: &ChunkManifest| -> Vec<Vec<u8>> {
            m.spans
                .iter()
                .map(|s| data[s.offset..s.offset + s.length].to_vec())
                .collect()
        };
        let ca = content(&original, &a);
        let cb = content(&edited, &b);
        let shared = ca.iter().filter(|c| cb.contains(c)).count();
        assert!(
            shared * 2 > ca.len(),
            "majority of chunks must survive a 64-byte insertion \
             ({shared}/{} shared)",
            ca.len()
        );
    }

    #[test]
    fn parameter_version_bump_creates_new_manifests_without_invalidating_old() {
        // THE acceptance: a v2 profile cuts differently, but the OLD
        // manifest remains exactly valid — reassembly needs only its
        // spans, and nothing reinterprets them under v2 settings.
        let data = bytes(512 * 1024, 3);
        let old_manifest = chunk(&data, &PROFILE_V1);
        let v2 = ChunkingProfile {
            profile_version: 2,
            mask_bits: 14, // ~16 KiB average: different layout
            min_size: 4 * 1024,
            ..PROFILE_V1
        };
        let new_manifest = chunk(&data, &v2);
        assert_ne!(old_manifest.spans, new_manifest.spans);
        assert_eq!(old_manifest.profile_version, 1);
        assert_eq!(new_manifest.profile_version, 2);
        // Both manifests remain valid over the SAME object — chunking
        // is storage, the whole-object identity is the correctness
        // anchor (H001).
        assert!(validate_coverage(&old_manifest, data.len()).is_ok());
        assert!(validate_coverage(&new_manifest, data.len()).is_ok());
    }

    #[test]
    fn degenerate_objects_chunk_sanely() {
        // Empty object: empty manifest.
        let empty = chunk(&[], &PROFILE_V1);
        assert!(empty.spans.is_empty());
        assert!(validate_coverage(&empty, 0).is_ok());
        // Tiny object: one chunk.
        let tiny = chunk(&[1, 2, 3], &PROFILE_V1);
        assert_eq!(tiny.spans.len(), 1);
        assert!(validate_coverage(&tiny, 3).is_ok());
        // Coverage validator catches tears.
        let torn = ChunkManifest {
            profile_version: 1,
            spans: vec![ChunkSpan {
                offset: 0,
                length: 2,
            }],
        };
        assert!(validate_coverage(&torn, 3).is_err());
    }
}
