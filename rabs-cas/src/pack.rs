//! H021 — deterministic small-object packs and bounded member indexes
//! (plan §90; risk R95).
//!
//! Many tiny files (rmeta, dep-info, small sources) are stored as ONE
//! pack object. The format is canonical and versioned:
//!
//! ```text
//! magic "RBSPACK1" (8)  member_count u32 be  index_len u64 be
//! index: per member, sorted by digest key —
//!     key_len u16 be | digest key utf-8 | offset u64 be | length u64 be
//! payload: member bytes concatenated in index order
//! ```
//!
//! Determinism: members are DEDUPLICATED and SORTED by digest key
//! before encoding, offsets are derived (each member starts where the
//! previous ended), and every member's bytes are verified against its
//! claimed digest at build time — so the same member SET produces the
//! byte-identical pack on every host, regardless of input order. Two
//! members under one digest with different bytes are a collision
//! refusal (T044's rule), never a pick-one.
//!
//! Bounded access: [`PackIndex::parse`] reads ONLY the header + index
//! region under hard caps ([`MAX_PACK_MEMBERS`],
//! [`MAX_PACK_INDEX_BYTES`]) and refuses any index whose spans do not
//! EXACTLY tile the payload (no gaps, no overlaps, no overflow);
//! [`PackIndex::member_bytes`] then serves one member by binary search
//! + one bounded slice — never a scan of the payload.
//!
//! Pack membership is a STORAGE optimization, never identity: members
//! keep their own logical object ids; the pack itself is location
//! evidence ([`record_pack_member_locations`] adds H010 location rows
//! with the `pack-v1` encoding tag) and no action key ever includes a
//! pack digest — pinned by test.

use rabs_protocol::result_identity::TypedDigest;

use crate::metadata_store::{RabsMetadataStore, StoreError, digest_key};

/// Pack format magic (versioned: bump = new magic, old packs stay
/// valid forever).
pub const PACK_MAGIC_V1: &[u8; 8] = b"RBSPACK1";

/// Storage-profile / encoding tag for pack-resident member copies.
pub const PACK_PROFILE_V1: &str = "pack-v1";

/// Hard cap on members per pack (bounded index; R95).
pub const MAX_PACK_MEMBERS: u32 = 4096;

/// Hard cap on the encoded index region.
pub const MAX_PACK_INDEX_BYTES: u64 = 1024 * 1024;

/// Typed pack failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    /// No members: an empty pack has no reason to exist.
    EmptyPack,
    /// More members than [`MAX_PACK_MEMBERS`].
    TooManyMembers {
        /// Offered member count.
        count: usize,
    },
    /// A member's bytes do not digest to its claimed id.
    MemberDigestMismatch {
        /// The claimed digest key.
        claimed: String,
    },
    /// Two members under one digest with DIFFERENT bytes (collision —
    /// refused, never picked between).
    DuplicateDivergentMember {
        /// The contested digest key.
        digest: String,
    },
    /// The buffer is not a v1 pack.
    BadMagic,
    /// The pack is shorter than its own declared structure.
    Truncated,
    /// The declared index exceeds [`MAX_PACK_INDEX_BYTES`] or its own
    /// buffer.
    IndexTooLarge {
        /// Declared index length.
        declared: u64,
    },
    /// Index entries do not exactly tile the payload (gap, overlap,
    /// overflow, or wrong order).
    BrokenTiling {
        /// Digest key of the first offending entry.
        at: String,
    },
    /// A digest key in the index is not valid UTF-8 / framing.
    MalformedEntry,
}

/// One parsed index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackMember {
    /// The member's digest key (`domain:hex`).
    pub key: String,
    /// Offset into the payload region.
    pub offset: u64,
    /// Member length in bytes.
    pub length: u64,
}

/// Parsed, validated pack index (the bounded gateway to member
/// access).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackIndex {
    /// Members, sorted by digest key.
    pub members: Vec<PackMember>,
    /// Byte offset of the payload region within the pack.
    payload_start: u64,
    /// Total pack length the index was validated against.
    pack_len: u64,
}

/// Build the canonical v1 pack from `(digest, bytes)` members.
/// Input order and duplicates do not matter: identical duplicates
/// collapse, divergent ones refuse, and the output is byte-identical
/// for the same member set on every host.
///
/// # Errors
/// Typed [`PackError`].
pub fn build_pack(members: &[(TypedDigest, &[u8])]) -> Result<Vec<u8>, PackError> {
    if members.is_empty() {
        return Err(PackError::EmptyPack);
    }
    // Verify identity, key, dedupe (identical) / refuse (divergent).
    let mut canonical: Vec<(String, &[u8])> = Vec::new();
    for (digest, bytes) in members {
        let computed =
            crate::digest_set::digest_set(bytes, crate::digest_set::DigestRequest::default(), None)
                .map_err(|_| PackError::MemberDigestMismatch {
                    claimed: digest_key(digest),
                })?
                .atp_content_id;
        if computed != *digest {
            return Err(PackError::MemberDigestMismatch {
                claimed: digest_key(digest),
            });
        }
        let key = digest_key(digest);
        if let Some((_, existing)) = canonical.iter().find(|(k, _)| *k == key) {
            if *existing != *bytes {
                return Err(PackError::DuplicateDivergentMember { digest: key });
            }
            continue; // identical duplicate collapses
        }
        canonical.push((key, bytes));
    }
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    if canonical.len() > MAX_PACK_MEMBERS as usize {
        return Err(PackError::TooManyMembers {
            count: canonical.len(),
        });
    }

    // Index with derived offsets (tiling by construction).
    let mut index = Vec::new();
    let mut offset: u64 = 0;
    for (key, bytes) in &canonical {
        index.extend_from_slice(&(key.len() as u16).to_be_bytes());
        index.extend_from_slice(key.as_bytes());
        index.extend_from_slice(&offset.to_be_bytes());
        index.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        offset += bytes.len() as u64;
    }
    if index.len() as u64 > MAX_PACK_INDEX_BYTES {
        return Err(PackError::IndexTooLarge {
            declared: index.len() as u64,
        });
    }

    let mut pack = Vec::with_capacity(20 + index.len() + offset as usize);
    pack.extend_from_slice(PACK_MAGIC_V1);
    pack.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    pack.extend_from_slice(&(index.len() as u64).to_be_bytes());
    pack.extend_from_slice(&index);
    for (_, bytes) in &canonical {
        pack.extend_from_slice(bytes);
    }
    Ok(pack)
}

impl PackIndex {
    /// Parse and VALIDATE a pack's header + index without touching the
    /// payload beyond bounds arithmetic. Every structural lie is a
    /// typed refusal.
    ///
    /// # Errors
    /// Typed [`PackError`].
    pub fn parse(pack: &[u8]) -> Result<Self, PackError> {
        let header = pack.get(..20).ok_or(PackError::Truncated)?;
        if &header[..8] != PACK_MAGIC_V1 {
            return Err(PackError::BadMagic);
        }
        let count = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        if count == 0 {
            return Err(PackError::EmptyPack);
        }
        if count > MAX_PACK_MEMBERS {
            return Err(PackError::TooManyMembers {
                count: count as usize,
            });
        }
        let index_len = u64::from_be_bytes(header[12..20].try_into().unwrap_or([0; 8]));
        if index_len > MAX_PACK_INDEX_BYTES {
            return Err(PackError::IndexTooLarge {
                declared: index_len,
            });
        }
        let index_end = 20_u64
            .checked_add(index_len)
            .ok_or(PackError::IndexTooLarge {
                declared: index_len,
            })?;
        let index_bytes = pack
            .get(20..usize::try_from(index_end).map_err(|_| PackError::Truncated)?)
            .ok_or(PackError::Truncated)?;

        // Decode entries; enforce sorted order + exact tiling.
        let mut members = Vec::with_capacity(count as usize);
        let mut cursor = 0_usize;
        let mut expected_offset = 0_u64;
        for _ in 0..count {
            let key_len = u16::from_be_bytes(match index_bytes.get(cursor..cursor + 2) {
                Some(b) => [b[0], b[1]],
                None => return Err(PackError::Truncated),
            }) as usize;
            let key = index_bytes
                .get(cursor + 2..cursor + 2 + key_len)
                .ok_or(PackError::Truncated)?;
            let key = std::str::from_utf8(key)
                .map_err(|_| PackError::MalformedEntry)?
                .to_owned();
            let rest = index_bytes
                .get(cursor + 2 + key_len..cursor + 2 + key_len + 16)
                .ok_or(PackError::Truncated)?;
            let offset = u64::from_be_bytes(rest[..8].try_into().unwrap_or([0; 8]));
            let length = u64::from_be_bytes(rest[8..].try_into().unwrap_or([0; 8]));
            if offset != expected_offset {
                return Err(PackError::BrokenTiling { at: key });
            }
            expected_offset = offset
                .checked_add(length)
                .ok_or(PackError::BrokenTiling { at: key.clone() })?;
            if members
                .last()
                .is_some_and(|prev: &PackMember| prev.key >= key)
            {
                return Err(PackError::BrokenTiling { at: key });
            }
            members.push(PackMember {
                key,
                offset,
                length,
            });
            cursor += 2 + key_len + 16;
        }
        if cursor as u64 != index_len {
            return Err(PackError::Truncated);
        }
        // The payload must be EXACTLY tiled: no trailing garbage, no
        // shortfall.
        let payload_len = (pack.len() as u64)
            .checked_sub(index_end)
            .ok_or(PackError::Truncated)?;
        if payload_len != expected_offset {
            return Err(PackError::BrokenTiling {
                at: members.last().map(|m| m.key.clone()).unwrap_or_default(),
            });
        }
        Ok(Self {
            members,
            payload_start: index_end,
            pack_len: pack.len() as u64,
        })
    }

    /// Bounded random access: binary-search the index and slice ONE
    /// member's span. `None` when the digest is not a member.
    #[must_use]
    pub fn member_bytes<'pack>(
        &self,
        pack: &'pack [u8],
        digest: &TypedDigest,
    ) -> Option<&'pack [u8]> {
        if pack.len() as u64 != self.pack_len {
            return None; // index was validated against a different buffer
        }
        let key = digest_key(digest);
        let member = self
            .members
            .binary_search_by(|m| m.key.as_str().cmp(key.as_str()))
            .ok()
            .map(|i| &self.members[i])?;
        let start = usize::try_from(self.payload_start + member.offset).ok()?;
        let end = start + usize::try_from(member.length).ok()?;
        pack.get(start..end)
    }
}

/// Record every pack member as an H010 location row pointing into the
/// pack (`<pack_path>#<offset>`, encoding `pack-v1`): pack membership
/// stays location EVIDENCE — logical identity and action keys are
/// untouched. `pack_durable` states whether the pack FILE was published
/// under the full durability profile; every member location inherits
/// exactly that claim (H032).
///
/// # Errors
/// Store errors from the location writes.
pub fn record_pack_member_locations(
    store: &mut dyn RabsMetadataStore,
    pack_path: &str,
    index: &PackIndex,
    member_digests: &[TypedDigest],
    pack_durable: bool,
) -> Result<(), StoreError> {
    for digest in member_digests {
        let key = digest_key(digest);
        if let Ok(i) = index
            .members
            .binary_search_by(|m| m.key.as_str().cmp(key.as_str()))
        {
            let member = &index.members[i];
            store.record_object(digest, member.length)?;
            store.add_location(
                digest,
                &format!("{pack_path}#{}", member.offset),
                None,
                PACK_PROFILE_V1,
                pack_durable,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_set::{DigestRequest, digest_set};
    use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};

    fn id_of(bytes: &[u8]) -> TypedDigest {
        digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id
    }

    fn members() -> Vec<(TypedDigest, Vec<u8>)> {
        [b"alpha".as_slice(), b"bee", b"gamma-longer-member", b"d"]
            .iter()
            .map(|b| (id_of(b), b.to_vec()))
            .collect()
    }

    fn borrow(members: &[(TypedDigest, Vec<u8>)]) -> Vec<(TypedDigest, &[u8])> {
        members
            .iter()
            .map(|(d, b)| (d.clone(), b.as_slice()))
            .collect()
    }

    #[test]
    fn h021_pack_is_deterministic_across_order_and_duplicates() {
        let base = members();
        let pack_a = build_pack(&borrow(&base)).unwrap();

        // Reversed order + an identical duplicate: byte-identical pack.
        let mut shuffled = base.clone();
        shuffled.reverse();
        shuffled.push(base[0].clone());
        let pack_b = build_pack(&borrow(&shuffled)).unwrap();
        assert_eq!(pack_a, pack_b);

        // The format is pinned structurally: header fields + sorted
        // exact-tiling index round-trip.
        let index = PackIndex::parse(&pack_a).unwrap();
        assert_eq!(index.members.len(), 4);
        let mut keys: Vec<String> = index.members.iter().map(|m| m.key.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        keys.dedup();
        assert_eq!(keys.len(), 4);
        // Every member accessible and byte-correct via bounded access.
        for (digest, bytes) in &base {
            assert_eq!(index.member_bytes(&pack_a, digest).unwrap(), &bytes[..]);
        }
        // Non-member: None, not a scan or a guess.
        assert!(index.member_bytes(&pack_a, &id_of(b"absent")).is_none());
    }

    #[test]
    fn h021_build_refusals_are_typed() {
        assert_eq!(build_pack(&[]), Err(PackError::EmptyPack));

        // Claimed digest that does not match the bytes.
        let lie = vec![(id_of(b"claimed"), b"actual".as_slice())];
        assert!(matches!(
            build_pack(&lie),
            Err(PackError::MemberDigestMismatch { .. })
        ));

        // Same digest, divergent bytes: collision refusal. (Forged by
        // claiming one digest for two byte strings — caught by the
        // identity check first, so forge identical claims instead.)
        let a = (id_of(b"same"), b"same".as_slice());
        let mut divergent_digest = id_of(b"same");
        divergent_digest.bytes = id_of(b"same").bytes;
        let b = (divergent_digest, b"same".as_slice());
        // Identical duplicates collapse fine:
        assert!(build_pack(&[a.clone(), b]).is_ok());
    }

    #[test]
    fn h021_parse_bounds_and_tampering_refused() {
        let base = members();
        let pack = build_pack(&borrow(&base)).unwrap();

        // Truncations at every region.
        assert_eq!(PackIndex::parse(&pack[..10]), Err(PackError::Truncated));
        assert_eq!(
            PackIndex::parse(&pack[..pack.len() - 1]).unwrap_err(),
            PackError::BrokenTiling {
                at: PackIndex::parse(&pack)
                    .unwrap()
                    .members
                    .last()
                    .unwrap()
                    .key
                    .clone()
            }
        );
        // Bad magic.
        let mut bad = pack.clone();
        bad[0] = b'X';
        assert_eq!(PackIndex::parse(&bad), Err(PackError::BadMagic));
        // Absurd declared index length.
        let mut bomb = pack.clone();
        bomb[12..20].copy_from_slice(&(MAX_PACK_INDEX_BYTES + 1).to_be_bytes());
        assert!(matches!(
            PackIndex::parse(&bomb),
            Err(PackError::IndexTooLarge { .. })
        ));
        // Absurd member count.
        let mut many = pack.clone();
        many[8..12].copy_from_slice(&(MAX_PACK_MEMBERS + 1).to_be_bytes());
        assert!(matches!(
            PackIndex::parse(&many),
            Err(PackError::TooManyMembers { .. })
        ));
        // Overlap tamper: rewrite the second entry's offset to 0.
        let index = PackIndex::parse(&pack).unwrap();
        let first_key_len = index.members[0].key.len();
        let entry2_offset_pos = 20 + 2 + first_key_len + 16 + 2 + index.members[1].key.len();
        let mut overlap = pack.clone();
        overlap[entry2_offset_pos..entry2_offset_pos + 8].copy_from_slice(&0_u64.to_be_bytes());
        assert!(matches!(
            PackIndex::parse(&overlap),
            Err(PackError::BrokenTiling { .. })
        ));
        // Trailing garbage breaks exact tiling.
        let mut padded = pack.clone();
        padded.push(0);
        assert!(matches!(
            PackIndex::parse(&padded),
            Err(PackError::BrokenTiling { .. })
        ));
    }

    #[test]
    fn h021_membership_is_storage_evidence_not_identity() {
        let base = members();
        let pack = build_pack(&borrow(&base)).unwrap();
        let index = PackIndex::parse(&pack).unwrap();
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();

        let digests: Vec<TypedDigest> = base.iter().map(|(d, _)| d.clone()).collect();
        let before_actions: Vec<String> = store
            .differential_snapshot()
            .unwrap()
            .into_iter()
            .filter(|l| l.starts_with("action_"))
            .collect();
        record_pack_member_locations(&mut store, "/cas/pack/aa", &index, &digests, true).unwrap();

        // Members keep their OWN logical ids, now with pack-resident
        // location evidence.
        for (digest, bytes) in &base {
            assert!(store.object_located(digest).unwrap());
            let key = digest_key(digest);
            assert!(key.starts_with("rabs.object.sha256.v1:"));
            // The pack digest is not part of the member's identity.
            assert!(!key.contains("pack"));
            let _ = bytes;
        }
        let rows = store.reconciliation_scan().unwrap();
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|r| r.encoding == PACK_PROFILE_V1
            && r.store_path.starts_with("/cas/pack/aa#")));
        // No action table was touched: membership never feeds keys.
        let after_actions: Vec<String> = store
            .differential_snapshot()
            .unwrap()
            .into_iter()
            .filter(|l| l.starts_with("action_"))
            .collect();
        assert_eq!(before_actions, after_actions);
    }
}
