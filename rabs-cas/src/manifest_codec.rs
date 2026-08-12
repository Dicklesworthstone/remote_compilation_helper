//! Canonical byte encoding for [`CanonicalActionResultManifest`] (bead
//! bd-h8sp5).
//!
//! A committed manifest is a CAS OBJECT: the worker uploads its bytes,
//! the publication row names its object id. Until this module existed
//! nothing could turn those bytes back into a manifest, so the
//! coordinator could only classify a same-key divergence against
//! manifests it happened to still hold in memory from THIS incarnation
//! — a restart silently degraded A018 classification into a
//! `CommittedManifestUnavailable` refusal, and serving a hit (which must
//! read the committed manifest to know what to materialize) was not
//! reachable at all.
//!
//! Three properties this encoding is built for:
//!
//! - **Deterministic.** Outputs are emitted in the same canonical order
//!   the semantic projection uses ((role tag, virtual path)), so one
//!   manifest has exactly one encoding and therefore exactly one object
//!   id.
//! - **Identity-preserving.** A decoded manifest re-derives the SAME
//!   semantic and observable projection digests as the original. That is
//!   the safety property divergence classification rests on: if a reload
//!   could perturb a digest, the coordinator would invent divergences.
//! - **Fail-closed.** Every field is validated on the way in: a wrong
//!   magic, an unknown version, an unexpected digest domain, an unknown
//!   role/result-kind tag, a truncated buffer, or trailing bytes is a
//!   typed refusal. Domains are matched against the `'static` constants
//!   this crate holds and never re-typed from stored text (R121, the
//!   same rule the metadata store's domain interning enforces).

use rabs_key::logical_output_map::DOMAIN_ARTIFACT_BUNDLE_ROOT;
use rabs_key::typed_digest::{DOMAIN_ACTION_KEY, DOMAIN_DESCRIPTOR};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{
    CanonicalActionResultManifest, DigestAlgorithm, LogicalOutput, ObjectId, OutputRole,
    ResultKind, TypedDigest,
};

use crate::digest_set::ATP_OBJECT_CONTENT_DOMAIN;
use crate::publication::{OBSERVABLE_PROJECTION_DOMAIN, SEMANTIC_PROJECTION_DOMAIN};

/// Format magic; the trailing digit is the format generation.
const MAGIC: &[u8; 4] = b"RMF1";
/// Encoding version inside that generation.
const VERSION: u8 = 1;
/// The only digest algorithm this encoding admits.
const ALGO_SHA256_V1: u8 = 1;

/// Why a manifest could not be decoded. Every variant means "this is not
/// a manifest I can be sure of" — never a partially trusted result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestCodecError {
    /// The buffer does not start with the format magic.
    BadMagic,
    /// A format version this build does not implement.
    UnsupportedVersion(u8),
    /// The buffer ended in the middle of a field.
    Truncated {
        /// Which field ran out of bytes.
        field: &'static str,
    },
    /// Bytes remain after a complete manifest was read.
    TrailingBytes(usize),
    /// A digest field carried a domain other than the one that field is
    /// defined to hold.
    UnexpectedDomain {
        /// The field being decoded.
        field: &'static str,
        /// The domain the field must carry.
        expected: &'static str,
        /// What the bytes actually said.
        found: String,
    },
    /// A digest algorithm tag this build does not know.
    UnknownAlgorithm(u8),
    /// A result-kind tag this build does not know.
    UnknownResultKind(u8),
    /// An output-role tag this build does not know.
    UnknownOutputRole(u8),
    /// A length field exceeds what the remaining buffer can hold.
    LengthOverflow {
        /// Which field declared it.
        field: &'static str,
    },
}

impl std::fmt::Display for ManifestCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a canonical manifest (bad magic)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported manifest version {v}"),
            Self::Truncated { field } => write!(f, "truncated at {field}"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after the manifest"),
            Self::UnexpectedDomain {
                field,
                expected,
                found,
            } => write!(f, "{field}: expected domain {expected}, found {found:?}"),
            Self::UnknownAlgorithm(t) => write!(f, "unknown digest algorithm tag {t}"),
            Self::UnknownResultKind(t) => write!(f, "unknown result kind tag {t}"),
            Self::UnknownOutputRole(t) => write!(f, "unknown output role tag {t}"),
            Self::LengthOverflow { field } => write!(f, "{field}: length exceeds the buffer"),
        }
    }
}

const fn result_kind_tag(kind: ResultKind) -> u8 {
    match kind {
        ResultKind::Success => 0,
        ResultKind::DeterministicFailure => 1,
    }
}

const fn result_kind_from_tag(tag: u8) -> Option<ResultKind> {
    match tag {
        0 => Some(ResultKind::Success),
        1 => Some(ResultKind::DeterministicFailure),
        _ => None,
    }
}

const fn output_role_tag(role: OutputRole) -> u8 {
    match role {
        OutputRole::Materializable => 0,
        OutputRole::DepInfo => 1,
        OutputRole::ProvisionalMetadata => 2,
        OutputRole::BuildScriptMetadata => 3,
        OutputRole::TestSideEffect => 4,
    }
}

const fn output_role_from_tag(tag: u8) -> Option<OutputRole> {
    match tag {
        0 => Some(OutputRole::Materializable),
        1 => Some(OutputRole::DepInfo),
        2 => Some(OutputRole::ProvisionalMetadata),
        3 => Some(OutputRole::BuildScriptMetadata),
        4 => Some(OutputRole::TestSideEffect),
        _ => None,
    }
}

/// Outputs in the ONE canonical order (role tag, then virtual path) the
/// semantic projection also uses, so encoding is a function of the
/// manifest's value and not of how its vector happened to be built.
fn canonical_outputs(manifest: &CanonicalActionResultManifest) -> Vec<&LogicalOutput> {
    let mut outputs: Vec<&LogicalOutput> = manifest.logical_outputs.iter().collect();
    outputs.sort_by(|a, b| {
        (output_role_tag(a.role), a.virtual_path.as_bytes())
            .cmp(&(output_role_tag(b.role), b.virtual_path.as_bytes()))
    });
    outputs
}

fn put_digest(out: &mut Vec<u8>, digest: &TypedDigest) {
    let algo = match digest.algorithm {
        DigestAlgorithm::Sha256V1 => ALGO_SHA256_V1,
    };
    out.push(algo);
    let domain = digest.domain.as_bytes();
    // A domain longer than u16::MAX is unrepresentable by construction:
    // every domain is a compile-time constant in this workspace.
    out.extend_from_slice(
        &u16::try_from(domain.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(domain);
    out.extend_from_slice(&digest.bytes);
}

/// The canonical bytes of `manifest`. Deterministic: equal manifests
/// encode to equal bytes, so the object id is a function of the value.
#[must_use]
pub fn encode_manifest_v1(manifest: &CanonicalActionResultManifest) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    put_digest(&mut out, &manifest.action_key);
    put_digest(&mut out, &manifest.canonical_descriptor_digest);
    out.extend_from_slice(&manifest.key_epoch.to_be_bytes());
    out.extend_from_slice(&manifest.projection_epoch.to_be_bytes());
    out.push(result_kind_tag(manifest.result_kind));
    match &manifest.artifact_bundle_root {
        None => out.push(0),
        Some(root) => {
            out.push(1);
            put_digest(&mut out, &root.0);
        }
    }
    let outputs = canonical_outputs(manifest);
    // Count fits u32 by construction (a manifest with 4 billion outputs
    // cannot be built); saturate rather than panic in a `must_use` path.
    out.extend_from_slice(
        &u32::try_from(outputs.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for output in outputs {
        out.push(output_role_tag(output.role));
        let path = output.virtual_path.as_bytes();
        out.extend_from_slice(&u32::try_from(path.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(path);
        put_digest(&mut out, &output.object.0);
    }
    put_digest(&mut out, &manifest.semantic_result_digest);
    put_digest(&mut out, &manifest.observable_result_digest);
    out
}

/// A cursor that refuses rather than panics at the end of the buffer.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], ManifestCodecError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(ManifestCodecError::LengthOverflow { field })?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(ManifestCodecError::Truncated { field })?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, ManifestCodecError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, ManifestCodecError> {
        let bytes: [u8; 2] = self.take(2, field)?.try_into().unwrap_or([0; 2]);
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, ManifestCodecError> {
        let bytes: [u8; 4] = self.take(4, field)?.try_into().unwrap_or([0; 4]);
        Ok(u32::from_be_bytes(bytes))
    }

    /// A digest whose domain MUST be `expected` — the `'static` domain
    /// comes from this build, never from the stored text (R121).
    fn digest(
        &mut self,
        field: &'static str,
        expected: &'static str,
    ) -> Result<TypedDigest, ManifestCodecError> {
        let algo = self.u8(field)?;
        if algo != ALGO_SHA256_V1 {
            return Err(ManifestCodecError::UnknownAlgorithm(algo));
        }
        let len = self.u16(field)? as usize;
        let domain = self.take(len, field)?;
        if domain != expected.as_bytes() {
            return Err(ManifestCodecError::UnexpectedDomain {
                field,
                expected,
                found: String::from_utf8_lossy(domain).into_owned(),
            });
        }
        let bytes: [u8; 32] = self
            .take(32, field)?
            .try_into()
            .map_err(|_| ManifestCodecError::Truncated { field })?;
        Ok(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: expected,
            bytes,
        })
    }
}

/// Decode canonical manifest bytes.
///
/// # Errors
/// A typed [`ManifestCodecError`] naming the first violated rule; a
/// partially decoded manifest is never returned.
pub fn decode_manifest_v1(
    bytes: &[u8],
) -> Result<CanonicalActionResultManifest, ManifestCodecError> {
    let mut reader = Reader::new(bytes);
    if reader.take(4, "magic")? != MAGIC {
        return Err(ManifestCodecError::BadMagic);
    }
    let version = reader.u8("version")?;
    if version != VERSION {
        return Err(ManifestCodecError::UnsupportedVersion(version));
    }
    let action_key = reader.digest("action_key", DOMAIN_ACTION_KEY)?;
    let canonical_descriptor_digest = reader.digest("descriptor", DOMAIN_DESCRIPTOR)?;
    let key_epoch = reader.u32("key_epoch")?;
    let projection_epoch = reader.u32("projection_epoch")?;
    let kind_tag = reader.u8("result_kind")?;
    let result_kind =
        result_kind_from_tag(kind_tag).ok_or(ManifestCodecError::UnknownResultKind(kind_tag))?;
    let artifact_bundle_root = match reader.u8("bundle_root_present")? {
        0 => None,
        // The bundle root is NOT a content id: F035 derives it from the
        // role-tagged output map under its own domain.
        1 => Some(ObjectId(
            reader.digest("bundle_root", DOMAIN_ARTIFACT_BUNDLE_ROOT)?,
        )),
        other => return Err(ManifestCodecError::UnknownResultKind(other)),
    };
    let count = reader.u32("output_count")? as usize;
    let mut logical_outputs = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let role_tag = reader.u8("output_role")?;
        let role = output_role_from_tag(role_tag)
            .ok_or(ManifestCodecError::UnknownOutputRole(role_tag))?;
        let path_len = reader.u32("output_path_len")? as usize;
        let path = reader.take(path_len, "output_path")?.to_vec();
        let object = ObjectId(reader.digest("output_object", ATP_OBJECT_CONTENT_DOMAIN)?);
        logical_outputs.push(LogicalOutput {
            role,
            virtual_path: RawBytes::new(path),
            object,
        });
    }
    let semantic_result_digest = reader.digest("semantic_digest", SEMANTIC_PROJECTION_DOMAIN)?;
    let observable_result_digest =
        reader.digest("observable_digest", OBSERVABLE_PROJECTION_DOMAIN)?;
    if reader.at != bytes.len() {
        return Err(ManifestCodecError::TrailingBytes(bytes.len() - reader.at));
    }
    Ok(CanonicalActionResultManifest {
        action_key,
        canonical_descriptor_digest,
        key_epoch,
        projection_epoch,
        result_kind,
        artifact_bundle_root,
        logical_outputs,
        semantic_result_digest,
        observable_result_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publication::{observable_result_digest_v1, semantic_result_digest_v1};

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn object(tag: u8) -> ObjectId {
        ObjectId(digest(ATP_OBJECT_CONTENT_DOMAIN, tag))
    }

    fn output(role: OutputRole, path: &[u8], tag: u8) -> LogicalOutput {
        LogicalOutput {
            role,
            virtual_path: RawBytes::new(path.to_vec()),
            object: object(tag),
        }
    }

    fn manifest() -> CanonicalActionResultManifest {
        let mut manifest = CanonicalActionResultManifest {
            action_key: digest(DOMAIN_ACTION_KEY, 7),
            canonical_descriptor_digest: digest(DOMAIN_DESCRIPTOR, 8),
            key_epoch: 3,
            projection_epoch: 4,
            result_kind: ResultKind::Success,
            // Derived under F035's own domain, not a content id.
            artifact_bundle_root: Some(ObjectId(digest(DOMAIN_ARTIFACT_BUNDLE_ROOT, 40))),
            logical_outputs: vec![
                output(OutputRole::Materializable, b"out/lib.rlib", 41),
                output(OutputRole::DepInfo, b"out/lib.d", 42),
            ],
            semantic_result_digest: digest(SEMANTIC_PROJECTION_DOMAIN, 0),
            observable_result_digest: digest(OBSERVABLE_PROJECTION_DOMAIN, 0),
        };
        manifest.semantic_result_digest = semantic_result_digest_v1(&manifest);
        manifest.observable_result_digest =
            observable_result_digest_v1(&manifest, &digest("rabs.observation-stream.sha256.v1", 9));
        manifest
    }

    #[test]
    fn round_trip_preserves_the_manifest_and_its_identity() {
        let original = manifest();
        let decoded = decode_manifest_v1(&encode_manifest_v1(&original)).expect("decode");
        assert_eq!(decoded, original);
        // THE property divergence classification rests on: a reloaded
        // manifest re-derives the same projections, so a restart can
        // never turn one result into an apparent second one.
        assert_eq!(
            semantic_result_digest_v1(&decoded),
            original.semantic_result_digest
        );
        assert_eq!(
            observable_result_digest_v1(&decoded, &digest("rabs.observation-stream.sha256.v1", 9)),
            original.observable_result_digest
        );
    }

    #[test]
    fn encoding_is_canonical_under_output_reordering() {
        let a = manifest();
        let mut b = a.clone();
        b.logical_outputs.reverse();
        assert_eq!(
            encode_manifest_v1(&a),
            encode_manifest_v1(&b),
            "output order must not change the bytes (or the object id)"
        );
    }

    #[test]
    fn a_manifest_with_no_outputs_and_no_bundle_root_round_trips() {
        let mut empty = manifest();
        empty.logical_outputs.clear();
        empty.artifact_bundle_root = None;
        empty.semantic_result_digest = semantic_result_digest_v1(&empty);
        let decoded = decode_manifest_v1(&encode_manifest_v1(&empty)).expect("decode");
        assert_eq!(decoded, empty);
    }

    #[test]
    fn every_truncation_is_a_typed_refusal_never_a_partial_manifest() {
        let bytes = encode_manifest_v1(&manifest());
        for cut in 0..bytes.len() {
            let outcome = decode_manifest_v1(&bytes[..cut]);
            assert!(
                outcome.is_err(),
                "a {cut}-byte prefix must not decode as a manifest"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = encode_manifest_v1(&manifest());
        bytes.push(0);
        assert_eq!(
            decode_manifest_v1(&bytes),
            Err(ManifestCodecError::TrailingBytes(1))
        );
    }

    #[test]
    fn bad_magic_and_unknown_version_are_refused() {
        assert_eq!(
            decode_manifest_v1(b"XXXX\x01"),
            Err(ManifestCodecError::BadMagic)
        );
        let mut bytes = encode_manifest_v1(&manifest());
        bytes[4] = 9;
        assert_eq!(
            decode_manifest_v1(&bytes),
            Err(ManifestCodecError::UnsupportedVersion(9))
        );
    }

    #[test]
    fn a_domain_this_build_does_not_expect_is_refused_not_retyped() {
        // Rewrite the action-key domain in the encoded bytes to a
        // plausible-looking neighbour of the same length.
        let bytes = encode_manifest_v1(&manifest());
        let needle = DOMAIN_ACTION_KEY.as_bytes();
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("domain present in the encoding");
        let mut tampered = bytes.clone();
        tampered[at..at + needle.len()].copy_from_slice(b"rabs.action-key.sha256.v2");
        match decode_manifest_v1(&tampered) {
            Err(ManifestCodecError::UnexpectedDomain { field, found, .. }) => {
                assert_eq!(field, "action_key");
                assert_eq!(found, "rabs.action-key.sha256.v2");
            }
            other => panic!("an unknown domain must be refused, got {other:?}"),
        }
    }

    #[test]
    fn unknown_role_and_result_kind_tags_are_refused() {
        let digest_len = |domain: &str| 1 + 2 + domain.len() + 32;
        // magic + version + action key + descriptor + both epochs.
        let kind_at = 4 + 1 + digest_len(DOMAIN_ACTION_KEY) + digest_len(DOMAIN_DESCRIPTOR) + 4 + 4;
        let bytes = encode_manifest_v1(&manifest());
        let mut tampered = bytes.clone();
        tampered[kind_at] = 7;
        assert_eq!(
            decode_manifest_v1(&tampered),
            Err(ManifestCodecError::UnknownResultKind(7))
        );

        // The first output's role tag: after the bundle-root flag, its
        // digest, and the u32 output count.
        let role_at = kind_at + 1 + 1 + digest_len(DOMAIN_ARTIFACT_BUNDLE_ROOT) + 4;
        let mut tampered = bytes;
        tampered[role_at] = 9;
        assert_eq!(
            decode_manifest_v1(&tampered),
            Err(ManifestCodecError::UnknownOutputRole(9))
        );
    }
}
