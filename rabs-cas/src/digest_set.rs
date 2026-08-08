//! H002 — streaming ATP content ID, BLAKE3 fingerprints, optional raw
//! SHA-256 (plan §90; builds on H001's object model and F034's typed
//! digest discipline).
//!
//! Three digest roles with STRUCTURALLY distinct types, so a value can
//! never be presented in the wrong role:
//!
//! - **ATP content id** — the native object/manifest identity: domain-
//!   separated SHA-256 as a [`TypedDigest`] under
//!   [`ATP_OBJECT_CONTENT_DOMAIN`]. This is the only member of the set
//!   that authoritative metadata may store.
//! - **BLAKE3 fingerprint** — fast local fingerprints, chunk prechecks,
//!   internal indexes. Deliberately its own type
//!   ([`Blake3Fingerprint`]), NOT a [`TypedDigest`]: the metadata
//!   store's algorithm tagging only admits SHA-256 V1, so a BLAKE3
//!   value cannot masquerade as object identity even by mistake.
//! - **raw SHA-256** — un-domain-separated, computed ONLY when an
//!   external gateway/store requires interop ([`RawSha256`], also its
//!   own type; carrying no domain is exactly why it must never be an
//!   internal identity).
//!
//! [`StreamingObjectWriter`] computes every requested digest in ONE
//! pass while bytes are written, counts logical size, and verifies an
//! expected size at [`StreamingObjectWriter::finish`] — a short or long
//! write is a typed error, never a silently mis-sized digest.
//!
//! Storage encoding is applied SEPARATELY from identity: digests here
//! are always over LOGICAL bytes; how a copy is stored (raw, zstd,
//! packed) is location evidence recorded via the metadata store's
//! `add_location(encoding)` (H010) and never changes any digest in the
//! set. Hashing compressed bytes yields a different content id by
//! construction — the tests pin that a compressed representation can
//! never masquerade as the uncompressed identity.

use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use sha2::{Digest, Sha256};

/// Domain of the native ATP object/manifest content identity (the same
/// domain the rest of the CAS uses for object ids).
pub const ATP_OBJECT_CONTENT_DOMAIN: &str = "rabs.object.sha256.v1";

/// Domain prefix mixed into BLAKE3 fingerprints (versioned like every
/// digest domain).
pub const BLAKE3_FINGERPRINT_DOMAIN: &str = "rabs.fingerprint.blake3.v1";

/// A BLAKE3 local fingerprint. Not a [`TypedDigest`] on purpose: fast
/// fingerprints never enter authoritative metadata as identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Blake3Fingerprint {
    /// The versioned fingerprint domain mixed into the hash.
    pub domain: &'static str,
    /// The 32-byte BLAKE3 output.
    pub bytes: [u8; 32],
}

/// A raw, un-domain-separated SHA-256 for external interop only. Its
/// own type: having NO domain is exactly why it can never be used as an
/// internal identity digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RawSha256(pub [u8; 32]);

/// The digest set computed for one logical object (H002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestSet {
    /// Native identity: domain-separated SHA-256 typed digest.
    pub atp_content_id: TypedDigest,
    /// Fast local fingerprint, when requested.
    pub blake3: Option<Blake3Fingerprint>,
    /// External-interop raw SHA-256, when requested.
    pub raw_sha256: Option<RawSha256>,
    /// Logical (uncompressed) byte count actually hashed.
    pub logical_size: u64,
}

/// Which optional digests to compute alongside the mandatory content
/// id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DigestRequest {
    /// Compute the BLAKE3 local fingerprint.
    pub blake3: bool,
    /// Compute the raw SHA-256 (external gateway interop only).
    pub raw_sha256: bool,
}

/// Typed streaming-digest failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// The finished byte count differs from the declared logical size.
    LogicalSizeMismatch {
        /// Bytes the writer was told to expect.
        expected: u64,
        /// Bytes actually written.
        actual: u64,
    },
    /// More bytes written than fit in the logical-size counter.
    SizeOverflow,
}

/// Mix a digest domain into a hasher as a length-delimited prefix (the
/// F034 framing rule: `len(u64 be) || domain`; the object content is
/// the trailing field, so streaming needs no length up front and no
/// concatenation ambiguity exists).
fn domain_prefix(domain: &str) -> ([u8; 8], &[u8]) {
    ((domain.len() as u64).to_be_bytes(), domain.as_bytes())
}

/// One-pass streaming writer: feeds every requested hasher and counts
/// logical bytes as they stream through.
pub struct StreamingObjectWriter {
    content: Sha256,
    blake3: Option<blake3::Hasher>,
    raw: Option<Sha256>,
    expected_size: Option<u64>,
    written: u64,
}

impl StreamingObjectWriter {
    /// Start a writer. `expected_size` (when known, e.g. from a
    /// manifest or transfer header) is verified at finish.
    #[must_use]
    pub fn new(request: DigestRequest, expected_size: Option<u64>) -> Self {
        let mut content = Sha256::new();
        let (len, domain) = domain_prefix(ATP_OBJECT_CONTENT_DOMAIN);
        content.update(len);
        content.update(domain);
        let blake3 = request.blake3.then(|| {
            let mut hasher = blake3::Hasher::new();
            let (len, domain) = domain_prefix(BLAKE3_FINGERPRINT_DOMAIN);
            hasher.update(&len);
            hasher.update(domain);
            hasher
        });
        let raw = request.raw_sha256.then(Sha256::new);
        Self {
            content,
            blake3,
            raw,
            expected_size,
            written: 0,
        }
    }

    /// Stream one chunk of LOGICAL object bytes. Chunk boundaries are
    /// arbitrary: any split of the same bytes produces the same set.
    ///
    /// # Errors
    /// [`DigestError::SizeOverflow`] when the counter would overflow.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), DigestError> {
        self.written = self
            .written
            .checked_add(chunk.len() as u64)
            .ok_or(DigestError::SizeOverflow)?;
        self.content.update(chunk);
        if let Some(hasher) = &mut self.blake3 {
            hasher.update(chunk);
        }
        if let Some(hasher) = &mut self.raw {
            hasher.update(chunk);
        }
        Ok(())
    }

    /// Finish: verify the expected logical size (when declared) and
    /// produce the tagged digest set.
    ///
    /// # Errors
    /// [`DigestError::LogicalSizeMismatch`] on a short or long write.
    pub fn finish(self) -> Result<DigestSet, DigestError> {
        if let Some(expected) = self.expected_size
            && expected != self.written
        {
            return Err(DigestError::LogicalSizeMismatch {
                expected,
                actual: self.written,
            });
        }
        Ok(DigestSet {
            atp_content_id: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: ATP_OBJECT_CONTENT_DOMAIN,
                bytes: self.content.finalize().into(),
            },
            blake3: self.blake3.map(|hasher| Blake3Fingerprint {
                domain: BLAKE3_FINGERPRINT_DOMAIN,
                bytes: *hasher.finalize().as_bytes(),
            }),
            raw_sha256: self.raw.map(|hasher| RawSha256(hasher.finalize().into())),
            logical_size: self.written,
        })
    }
}

/// One-shot convenience over [`StreamingObjectWriter`].
///
/// # Errors
/// [`DigestError`] exactly as the streaming path.
pub fn digest_set(
    bytes: &[u8],
    request: DigestRequest,
    expected_size: Option<u64>,
) -> Result<DigestSet, DigestError> {
    let mut writer = StreamingObjectWriter::new(request, expected_size);
    writer.write(bytes)?;
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: DigestRequest = DigestRequest {
        blake3: true,
        raw_sha256: true,
    };

    #[test]
    fn h002_streaming_equals_oneshot_under_arbitrary_chunking() {
        // Acceptance: streaming digest correctness under chunked writes
        // — every split of the same bytes yields the identical set.
        let bytes: Vec<u8> = (0..u8::MAX).cycle().take(70_001).collect();
        let oneshot = digest_set(&bytes, ALL, Some(bytes.len() as u64)).unwrap();
        for splits in [
            vec![0usize],
            vec![1, 2, 3],
            vec![70_000],
            vec![16 * 1024, 40_000, 69_999, 70_000],
        ] {
            let mut writer = StreamingObjectWriter::new(ALL, Some(bytes.len() as u64));
            let mut last = 0;
            for split in splits {
                writer.write(&bytes[last..split]).unwrap();
                last = split;
            }
            writer.write(&bytes[last..]).unwrap();
            assert_eq!(writer.finish().unwrap(), oneshot);
        }
        assert_eq!(oneshot.logical_size, 70_001);
    }

    #[test]
    fn h002_tags_bind_algorithm_and_domain_per_role() {
        // Acceptance: tag enforcement. The content id is a TYPED digest
        // under the object domain; BLAKE3 and raw SHA-256 are their own
        // types (they cannot be passed where a TypedDigest is required
        // — enforced at compile time) and their values differ from the
        // content id and from each other.
        let set = digest_set(b"tag enforcement", ALL, None).unwrap();
        assert_eq!(set.atp_content_id.algorithm, DigestAlgorithm::Sha256V1);
        assert_eq!(set.atp_content_id.domain, ATP_OBJECT_CONTENT_DOMAIN);
        let blake = set.blake3.unwrap();
        assert_eq!(blake.domain, BLAKE3_FINGERPRINT_DOMAIN);
        let raw = set.raw_sha256.unwrap();
        // Same input, three roles, three DIFFERENT values: the domain
        // separation is real.
        assert_ne!(set.atp_content_id.bytes, blake.bytes);
        assert_ne!(set.atp_content_id.bytes, raw.0);
        assert_ne!(blake.bytes, raw.0);

        // Each digest matches its primitive computed independently with
        // the documented framing.
        let mut reference = Sha256::new();
        reference.update((ATP_OBJECT_CONTENT_DOMAIN.len() as u64).to_be_bytes());
        reference.update(ATP_OBJECT_CONTENT_DOMAIN.as_bytes());
        reference.update(b"tag enforcement");
        assert_eq!(
            set.atp_content_id.bytes,
            <[u8; 32]>::from(reference.finalize())
        );

        let mut reference = blake3::Hasher::new();
        reference.update(&(BLAKE3_FINGERPRINT_DOMAIN.len() as u64).to_be_bytes());
        reference.update(BLAKE3_FINGERPRINT_DOMAIN.as_bytes());
        reference.update(b"tag enforcement");
        assert_eq!(blake.bytes, *reference.finalize().as_bytes());

        let mut reference = Sha256::new();
        reference.update(b"tag enforcement");
        assert_eq!(raw.0, <[u8; 32]>::from(reference.finalize()));
    }

    #[test]
    fn h002_raw_sha256_matches_published_sha2_test_vector() {
        // The raw digest exists for EXTERNAL interop, so pin it to the
        // canonical FIPS 180 "abc" vector rather than to our own code.
        let set = digest_set(
            b"abc",
            DigestRequest {
                blake3: false,
                raw_sha256: true,
            },
            None,
        )
        .unwrap();
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(set.raw_sha256.unwrap().0, expected);
        assert!(set.blake3.is_none(), "unrequested digests are not computed");
    }

    #[test]
    fn h002_logical_size_verification_refuses_short_and_long_writes() {
        let mut writer = StreamingObjectWriter::new(DigestRequest::default(), Some(4));
        writer.write(b"abc").unwrap();
        assert_eq!(
            writer.finish(),
            Err(DigestError::LogicalSizeMismatch {
                expected: 4,
                actual: 3
            })
        );
        let mut writer = StreamingObjectWriter::new(DigestRequest::default(), Some(2));
        writer.write(b"abc").unwrap();
        assert_eq!(
            writer.finish(),
            Err(DigestError::LogicalSizeMismatch {
                expected: 2,
                actual: 3
            })
        );
        // Exact size passes and reports it.
        let mut writer = StreamingObjectWriter::new(DigestRequest::default(), Some(3));
        writer.write(b"abc").unwrap();
        assert_eq!(writer.finish().unwrap().logical_size, 3);
    }

    #[test]
    fn h002_encoding_is_separate_from_identity() {
        // Storage encoding never changes identity: the digest set is
        // over LOGICAL bytes, and hashing an encoded representation
        // produces a DIFFERENT content id — so a compressed copy cannot
        // masquerade as the uncompressed object. Encoding is recorded
        // as location evidence (H010's add_location `encoding`), never
        // in the digest.
        let logical = b"logical object bytes, eminently compressible aaaaaaaaaaaaaaaa";
        let pretend_zstd: Vec<u8> = logical.iter().rev().copied().collect();
        let logical_set = digest_set(logical, DigestRequest::default(), None).unwrap();
        let encoded_set = digest_set(&pretend_zstd, DigestRequest::default(), None).unwrap();
        assert_ne!(logical_set.atp_content_id, encoded_set.atp_content_id);
        // Same domain, same algorithm — the VALUE differs, so the
        // separation lives in the bytes hashed, not in a retyped tag.
        assert_eq!(
            logical_set.atp_content_id.domain,
            encoded_set.atp_content_id.domain
        );
    }
}
