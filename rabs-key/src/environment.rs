//! Exact minimal environment construction + hashing (bead F006; plan
//! §64; risks R5/R56/R122).
//!
//! The presented environment is CONSTRUCTED, never inherited: every
//! variable the compiler will see is placed deliberately into one of the
//! seven categories, and the digest covers presence, absence, and value
//! semantics per category. Rules with teeth:
//!
//! - **Absence is a keyed fact.** `ScrubbedAbsent` variables key on
//!   their scrubbed-ness; an env where `RUSTC_BOOTSTRAP` was scrubbed
//!   and one where it was never mentioned are different constructions
//!   and different keys.
//! - **PATH is not a string.** It keys as the canonical ordered tool
//!   manifest — which tool names resolved to which content identities,
//!   AND which lookups failed (a failed `cc` probe is a semantic fact:
//!   a host where it later succeeds must miss).
//! - **Secrets never appear.** An output-affecting secret contributes a
//!   trusted opaque digest computed over (value, version, scope) by the
//!   secret authority — or forces the action non-cacheable. A bare
//!   capability ID is structurally unrepresentable as a key input
//!   (R56): the only constructor takes the opaque digest.
//! - **Raw bytes, not lossy UTF-8.** Values are `Vec<u8>`; a value that
//!   fails UTF-8 still keys exactly (R122's lossy-conversion aliasing
//!   is impossible by type).
//! - **Jobserver descriptors are excluded and reconstructed per host** —
//!   they are transport, not semantics (`VolatileRefusal` names them so
//!   their presence in a construction is a policy refusal, not a key).

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the presented-environment dataset.
pub const DOMAIN_ENVIRONMENT: &str = "rabs.presented-environment.v1";

/// How one variable participates in semantics (plan §64 categories).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvDisposition {
    /// Fixed to a constant presented value (locale, TZ, HOME, user,
    /// hostname where enforceable). The constant bytes key.
    SemanticConstant(Vec<u8>),
    /// Passed through with full value hashing (RUSTFLAGS,
    /// CARGO_ENCODED_RUSTFLAGS, deployment targets, feature/cfg vars).
    SemanticHashed(Vec<u8>),
    /// Passed through after a named normalization; both the normalizer
    /// identity and the normalized bytes key.
    SemanticNormalized {
        /// Which normalizer ran (versioned name).
        normalizer: String,
        /// The post-normalization bytes.
        normalized: Vec<u8>,
    },
    /// Deliberately removed; the scrubbing itself is the keyed fact.
    ScrubbedAbsent,
    /// Output-affecting secret: ONLY the authority-computed opaque
    /// digest over (value, version, scope) — never the value, never a
    /// bare capability ID (R56).
    SecretOpaqueDigest(TypedDigest),
    /// Present in the source env but refused as inherently volatile
    /// (jobserver descriptors, socket paths, request IDs). Refusals are
    /// policy outcomes, not key inputs — see [`PresentedEnvironment`].
    VolatileRefusal,
    /// Presentation-only (color/width hints): reconstructed per
    /// subscriber, never keyed.
    PresentationOnly,
}

/// Make/cargo descriptor-AUTH variables (bead I003, risk R7): their
/// values are host-local transport (fds, fifo paths) — never semantics,
/// never valid from a client request. The worker reconstructs them per
/// host; a construction that recorded one is a policy refusal.
pub const DESCRIPTOR_AUTH_VARS: &[&[u8]] = &[b"MAKEFLAGS", b"MFLAGS", b"CARGO_MAKEFLAGS"];

/// The canonical logical-capacity variable the WORKER authors from the
/// execution grant. A CLIENT-supplied value is a capacity CLAIM — also
/// volatile (it says nothing about the host that will run the action);
/// only the worker-authored value keys, via
/// [`canonical_capacity_disposition`].
pub const CANONICAL_CAPACITY_VAR: &[u8] = b"NUM_JOBS";

/// Disposition for a client-presented coordination/capacity variable:
/// `Some(VolatileRefusal)` for every name this bead strips from remote
/// requests, `None` when the name is none of ours (caller classifies).
#[must_use]
pub fn client_coordination_disposition(name: &[u8]) -> Option<EnvDisposition> {
    if DESCRIPTOR_AUTH_VARS.contains(&name) || name == CANONICAL_CAPACITY_VAR {
        Some(EnvDisposition::VolatileRefusal)
    } else {
        None
    }
}

/// Disposition of the WORKER-authored canonical capacity value: it can
/// affect build behavior, so it keys — as a named normalization (the
/// normalizer identity + decimal bytes), not raw passthrough.
#[must_use]
pub fn canonical_capacity_disposition(slots: u32) -> EnvDisposition {
    EnvDisposition::SemanticNormalized {
        normalizer: "i003.canonical-capacity.v1".to_string(),
        normalized: slots.to_string().into_bytes(),
    }
}

/// One PATH lookup result in canonical resolution order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathToolEntry {
    /// The tool name resolved to this content identity.
    Resolved {
        /// Tool name looked up.
        name: String,
        /// Content digest of the resolved binary.
        binary_digest: TypedDigest,
    },
    /// The lookup failed — a semantic fact that must key (a host where
    /// it succeeds later has a different environment).
    LookupFailed {
        /// Tool name looked up.
        name: String,
    },
}

/// The constructed environment for one action.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PresentedEnvironment {
    /// Variable name (raw bytes) → disposition, in construction order.
    /// Hashing sorts by name so construction order never forks keys.
    pub variables: Vec<(Vec<u8>, EnvDisposition)>,
    /// PATH as the canonical ordered tool manifest (order preserved —
    /// resolution order IS the semantics of PATH).
    pub path_manifest: Vec<PathToolEntry>,
}

/// Why an environment cannot be keyed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvKeyError {
    /// A secret affects output but no authority digest was available:
    /// the action must run non-cacheable rather than key on a bare
    /// capability ID (R56).
    SecretWithoutDigest {
        /// The variable concerned.
        name: Vec<u8>,
    },
    /// Duplicate variable name in the construction — ambiguous.
    DuplicateVariable {
        /// The duplicated name.
        name: Vec<u8>,
    },
}

impl PresentedEnvironment {
    /// Canonical bytes. Sorted by variable name (construction order is
    /// not semantics); PATH manifest order preserved (it is).
    ///
    /// # Errors
    /// [`EnvKeyError::DuplicateVariable`] on ambiguous construction.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EnvKeyError> {
        let mut vars: Vec<&(Vec<u8>, EnvDisposition)> = self.variables.iter().collect();
        vars.sort_by(|a, b| a.0.cmp(&b.0));
        for w in vars.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(EnvKeyError::DuplicateVariable {
                    name: w[0].0.clone(),
                });
            }
        }
        let mut enc = CanonicalEncoder::new();
        // Only key-participating dispositions enter the bytes; the
        // discriminant tags keep categories from aliasing each other.
        let keyed: Vec<_> = vars
            .iter()
            .filter(|(_, d)| {
                !matches!(
                    d,
                    EnvDisposition::VolatileRefusal | EnvDisposition::PresentationOnly
                )
            })
            .collect();
        enc.u64(keyed.len() as u64);
        for (name, disp) in keyed {
            enc.bytes(name);
            match disp {
                EnvDisposition::SemanticConstant(v) => {
                    enc.u32(1).bytes(v);
                }
                EnvDisposition::SemanticHashed(v) => {
                    enc.u32(2).bytes(v);
                }
                EnvDisposition::SemanticNormalized {
                    normalizer,
                    normalized,
                } => {
                    enc.u32(3).str(normalizer).bytes(normalized);
                }
                EnvDisposition::ScrubbedAbsent => {
                    enc.u32(4);
                }
                EnvDisposition::SecretOpaqueDigest(d) => {
                    enc.u32(5).str(d.domain).bytes(&d.bytes);
                }
                EnvDisposition::VolatileRefusal | EnvDisposition::PresentationOnly => {
                    unreachable!("filtered above")
                }
            }
        }
        enc.u64(self.path_manifest.len() as u64);
        for entry in &self.path_manifest {
            match entry {
                PathToolEntry::Resolved {
                    name,
                    binary_digest,
                } => {
                    enc.u32(1)
                        .str(name)
                        .str(binary_digest.domain)
                        .bytes(&binary_digest.bytes);
                }
                PathToolEntry::LookupFailed { name } => {
                    enc.u32(2).str(name);
                }
            }
        }
        Ok(enc.finish())
    }

    /// The environment dataset digest — the descriptor's `environment`
    /// slot.
    ///
    /// # Errors
    /// Propagates [`EnvKeyError`] from canonicalization.
    pub fn dataset_digest(&self) -> Result<TypedDigest, EnvKeyError> {
        Ok(compute(DOMAIN_ENVIRONMENT, &self.canonical_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn base() -> PresentedEnvironment {
        PresentedEnvironment {
            variables: vec![
                (
                    b"RUSTFLAGS".to_vec(),
                    EnvDisposition::SemanticHashed(b"-Cdebuginfo=1".to_vec()),
                ),
                (
                    b"TZ".to_vec(),
                    EnvDisposition::SemanticConstant(b"UTC".to_vec()),
                ),
                (b"RUSTC_BOOTSTRAP".to_vec(), EnvDisposition::ScrubbedAbsent),
                (
                    b"CARGO_TERM_COLOR".to_vec(),
                    EnvDisposition::PresentationOnly,
                ),
                (b"CARGO_MAKEFLAGS".to_vec(), EnvDisposition::VolatileRefusal),
            ],
            path_manifest: vec![
                PathToolEntry::Resolved {
                    name: "rustc".into(),
                    binary_digest: d("rabs.tool-binary.v1", 1),
                },
                PathToolEntry::LookupFailed { name: "cc".into() },
            ],
        }
    }

    fn digest_of(e: &PresentedEnvironment) -> TypedDigest {
        e.dataset_digest().unwrap()
    }

    #[test]
    fn every_semantic_var_changes_the_key() {
        let baseline = digest_of(&base());
        // Value change.
        let mut m = base();
        m.variables[0].1 = EnvDisposition::SemanticHashed(b"-Cdebuginfo=2".to_vec());
        assert_ne!(baseline, digest_of(&m), "RUSTFLAGS value");
        // Constant change.
        let mut m = base();
        m.variables[1].1 = EnvDisposition::SemanticConstant(b"America/New_York".to_vec());
        assert_ne!(baseline, digest_of(&m), "constant value");
        // ABSENCE change: removing the scrub record is a different
        // construction (the acceptance's absence-changes-key case).
        let mut m = base();
        m.variables.remove(2);
        assert_ne!(baseline, digest_of(&m), "scrubbed-absence is keyed");
        // Secret version change moves the key without any value present.
        let mut with_secret = base();
        with_secret.variables.push((
            b"SECRET_SIGNING_KEY".to_vec(),
            EnvDisposition::SecretOpaqueDigest(d("rabs.secret-version.v1", 7)),
        ));
        let mut rotated = base();
        rotated.variables.push((
            b"SECRET_SIGNING_KEY".to_vec(),
            EnvDisposition::SecretOpaqueDigest(d("rabs.secret-version.v1", 8)),
        ));
        assert_ne!(digest_of(&with_secret), digest_of(&rotated));
        // And the raw secret bytes are nowhere: the canonical bytes of
        // the secret-bearing env contain only the opaque digest.
        let bytes = with_secret.canonical_bytes().unwrap();
        assert!(
            !bytes.windows(b"hunter2".len()).any(|w| w == b"hunter2"),
            "no raw secret value can appear (none was ever representable)"
        );
    }

    #[test]
    fn presentation_and_volatile_vars_never_move_the_key() {
        let baseline = digest_of(&base());
        // Different presentation value / dropped entirely: same key.
        let mut m = base();
        m.variables.retain(|(n, _)| n != b"CARGO_TERM_COLOR");
        assert_eq!(baseline, digest_of(&m));
        // Jobserver descriptor refusal present vs absent: same key —
        // descriptors are reconstructed per host, never semantics.
        let mut m = base();
        m.variables.retain(|(n, _)| n != b"CARGO_MAKEFLAGS");
        assert_eq!(baseline, digest_of(&m));
    }

    #[test]
    fn path_is_an_ordered_tool_manifest_including_failures() {
        let baseline = digest_of(&base());
        // A failed lookup succeeding later is a key change.
        let mut m = base();
        m.path_manifest[1] = PathToolEntry::Resolved {
            name: "cc".into(),
            binary_digest: d("rabs.tool-binary.v1", 2),
        };
        assert_ne!(baseline, digest_of(&m), "lookup failure is semantic");
        // Resolution ORDER is semantic.
        let mut m = base();
        m.path_manifest.reverse();
        assert_ne!(baseline, digest_of(&m), "PATH order is semantics");
        // The PATH string spelling is unrepresentable: only the manifest
        // exists, so /usr/bin:/bin vs /bin:/usr/bin with identical
        // resolutions is literally the same value.
    }

    #[test]
    fn construction_order_never_forks_keys_but_duplicates_are_ambiguous() {
        let mut reordered = base();
        reordered.variables.swap(0, 1);
        assert_eq!(digest_of(&base()), digest_of(&reordered));
        let mut dup = base();
        dup.variables.push((
            b"RUSTFLAGS".to_vec(),
            EnvDisposition::SemanticHashed(b"other".to_vec()),
        ));
        assert!(matches!(
            dup.canonical_bytes(),
            Err(EnvKeyError::DuplicateVariable { .. })
        ));
    }

    #[test]
    fn non_utf8_values_key_exactly() {
        // R122: invalid UTF-8 must key on exact bytes, not on a lossy
        // replacement that would alias distinct values.
        let mut a = base();
        a.variables.push((
            b"WEIRD".to_vec(),
            EnvDisposition::SemanticHashed(vec![0xFF, 0xFE, 0x01]),
        ));
        let mut b = base();
        b.variables.push((
            b"WEIRD".to_vec(),
            EnvDisposition::SemanticHashed(vec![0xFF, 0xFD, 0x01]),
        ));
        // Both would lossy-convert to the SAME replacement string; the
        // raw-byte model keeps them distinct.
        assert_ne!(digest_of(&a), digest_of(&b));
    }

    #[test]
    fn category_tags_prevent_cross_category_aliasing() {
        // The same bytes under different dispositions are different
        // semantics (a constant "1" vs a hashed passthrough "1").
        let mut a = base();
        a.variables.push((
            b"X".to_vec(),
            EnvDisposition::SemanticConstant(b"1".to_vec()),
        ));
        let mut b = base();
        b.variables
            .push((b"X".to_vec(), EnvDisposition::SemanticHashed(b"1".to_vec())));
        assert_ne!(digest_of(&a), digest_of(&b));
    }
    #[test]
    fn i003_descriptor_auth_vars_are_volatile_and_never_move_the_key() {
        let baseline = digest_of(&base());
        // Every descriptor-auth var: refused, and its presence/absence
        // never forks the key (transport is reconstructed per host).
        for name in ["MAKEFLAGS", "MFLAGS"] {
            let mut with = base();
            with.variables
                .push((name.as_bytes().to_vec(), EnvDisposition::VolatileRefusal));
            assert_eq!(
                baseline,
                digest_of(&with),
                "{name} refusal is key-invariant"
            );
            assert!(client_coordination_disposition(name.as_bytes()).is_some());
        }
        assert_eq!(
            client_coordination_disposition(b"CARGO_MAKEFLAGS"),
            Some(EnvDisposition::VolatileRefusal)
        );
        // Not one of ours: caller classifies.
        assert_eq!(client_coordination_disposition(b"RUSTFLAGS"), None);
    }

    #[test]
    fn i003_canonical_capacity_is_semantic_and_keys_on_value() {
        // The worker-authored NUM_JOBS keys as a named normalization.
        let mut a = base();
        a.variables
            .push((b"NUM_JOBS".to_vec(), canonical_capacity_disposition(6)));
        let mut b = base();
        b.variables
            .push((b"NUM_JOBS".to_vec(), canonical_capacity_disposition(12)));
        assert_ne!(
            digest_of(&a),
            digest_of(&b),
            "capacity value can affect behavior: it must key"
        );
        // Same slots via a different normalizer identity = different
        // construction (the normalization itself is part of semantics).
        let mut c = base();
        c.variables.push((
            b"NUM_JOBS".to_vec(),
            EnvDisposition::SemanticNormalized {
                normalizer: "i003.canonical-capacity.v0".to_string(),
                normalized: b"6".to_vec(),
            },
        ));
        assert_ne!(digest_of(&a), digest_of(&c), "normalizer identity keys");
        // A client capacity CLAIM (never worker-authored) refuses.
        assert_eq!(
            client_coordination_disposition(b"NUM_JOBS"),
            Some(EnvDisposition::VolatileRefusal)
        );
    }
}
