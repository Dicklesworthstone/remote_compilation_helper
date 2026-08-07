//! Canonical-descriptor byte-verification on every hit (bead F024; plan
//! §75; risks R28/R121).
//!
//! An index hit is a CLAIM, not a fact. Before serving, the stored
//! entry is re-proven three ways:
//!
//! 1. the canonical descriptor bytes reloaded from storage must equal
//!    the bytes the entry was committed with (detects storage/index
//!    corruption and torn writes);
//! 2. the independent descriptor digest — computed under its OWN domain,
//!    not the action-key domain — must match a recomputation over the
//!    reloaded bytes (detects serialization drift between writer and
//!    reader versions, and makes a SHA-256 collision on one digest
//!    insufficient: an attack or accident must collide two
//!    independently-domained hashes simultaneously);
//! 3. the action key recomputed from the descriptor must equal the key
//!    the entry is indexed under (detects key-assembly bugs and index
//!    cross-linking).
//!
//! Any failure refuses the hit with a `STORAGE_*`/`KEY_*` reason code
//! (registered in the F026 registry) — a corrupted entry is never
//! served on the strength of its index position.

use rabs_protocol::descriptor::ActionDescriptor;
use rabs_protocol::result_identity::TypedDigest;

use crate::action_key::{action_class_tag, compute_action_key};
use crate::canonical::CanonicalEncoder;
use crate::typed_digest::{DOMAIN_DESCRIPTOR, compute};

/// Reason code for byte/digest mismatches (storage integrity family).
pub const STORAGE_DESCRIPTOR_BYTES_MISMATCH: &str = "STORAGE_DESCRIPTOR_BYTES_MISMATCH";
/// Reason code for action-key recomputation mismatches.
pub const KEY_RECOMPUTATION_MISMATCH: &str = "KEY_RECOMPUTATION_MISMATCH";
/// Reason code for a validated hit (already registered by F026).
pub const CACHE_HIT_VALIDATED: &str = "CACHE_HIT_VALIDATED";

/// Canonical byte serialization of a descriptor (epochs + class tag +
/// the ordered key-input components).
#[must_use]
pub fn descriptor_canonical_bytes(descriptor: &ActionDescriptor) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new();
    enc.u32(descriptor.key_epoch)
        .u32(descriptor.projection_epoch)
        .u32(action_class_tag(descriptor.action_class));
    let components = descriptor.key_input_components();
    enc.u64(components.len() as u64);
    for (name, digest) in components {
        enc.str(name).str(digest.domain).bytes(&digest.bytes);
    }
    enc.finish()
}

/// The independent descriptor digest (its own domain — NOT the
/// action-key domain).
#[must_use]
pub fn descriptor_digest(bytes: &[u8]) -> TypedDigest {
    compute(DOMAIN_DESCRIPTOR, bytes)
}

/// What the index stored at commit time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDescriptorEntry {
    /// Canonical descriptor bytes as committed.
    pub canonical_descriptor_bytes: Vec<u8>,
    /// Independent digest over those bytes (DOMAIN_DESCRIPTOR).
    pub descriptor_digest: TypedDigest,
    /// The action key the entry is indexed under.
    pub action_key: TypedDigest,
}

impl StoredDescriptorEntry {
    /// Build the entry a commit stores (the only constructor — the
    /// three values can never be assembled inconsistently by hand).
    #[must_use]
    pub fn commit(descriptor: &ActionDescriptor) -> Self {
        let bytes = descriptor_canonical_bytes(descriptor);
        let digest = descriptor_digest(&bytes);
        let key = compute_action_key(descriptor).final_key;
        Self {
            canonical_descriptor_bytes: bytes,
            descriptor_digest: digest,
            action_key: key,
        }
    }
}

/// Hit-verification outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HitVerification {
    /// All three proofs held; serve (CACHE_HIT_VALIDATED).
    Validated,
    /// Refused before serving, with the registered reason code.
    Refused {
        /// `STORAGE_*` / `KEY_*` reason code.
        reason_code: &'static str,
    },
}

/// Verify a hit: `reloaded_bytes` are the descriptor bytes read back
/// from storage NOW; `descriptor` is the deserialized form the server
/// would act on; `entry` is what the index claims.
#[must_use]
pub fn verify_hit(
    entry: &StoredDescriptorEntry,
    reloaded_bytes: &[u8],
    descriptor: &ActionDescriptor,
) -> HitVerification {
    // 1. Byte-compare the reloaded canonical descriptor.
    if reloaded_bytes != entry.canonical_descriptor_bytes {
        return HitVerification::Refused {
            reason_code: STORAGE_DESCRIPTOR_BYTES_MISMATCH,
        };
    }
    // 2. Independent digest recomputation over the reloaded bytes, and
    //    the deserialized form must re-serialize to those bytes.
    if descriptor_digest(reloaded_bytes) != entry.descriptor_digest
        || descriptor_canonical_bytes(descriptor) != entry.canonical_descriptor_bytes
    {
        return HitVerification::Refused {
            reason_code: STORAGE_DESCRIPTOR_BYTES_MISMATCH,
        };
    }
    // 3. Action-key recomputation from the descriptor.
    if compute_action_key(descriptor).final_key != entry.action_key {
        return HitVerification::Refused {
            reason_code: KEY_RECOMPUTATION_MISMATCH,
        };
    }
    HitVerification::Validated
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::descriptor::ActionClass;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn descriptor() -> ActionDescriptor {
        ActionDescriptor {
            key_epoch: 1,
            projection_epoch: 1,
            action_class: ActionClass::RustcDependencyCompile,
            normalized_invocation: d("rabs.invocation.v1", 1),
            virtual_working_directory: d("rabs.cwd.v1", 2),
            action_inputs: d("rabs.inputs.v1", 3),
            negative_dependencies: d("rabs.negdeps.v1", 4),
            dependency_inputs: d("rabs.deps.v1", 5),
            toolchain: d("rabs.toolchain-contract.v1", 6),
            output_platform: d("rabs.output-platform.v1", 7),
            environment: d("rabs.env.v1", 8),
            sandbox_semantic_policy: d("rabs.sandbox-policy.v1", 9),
            build_path_semantic_policy: d("rabs.path-policy.v1", 10),
            execution_semantics: d("rabs.exec-semantics.v1", 11),
            output_declarations: d("rabs.outputs.v1", 12),
        }
    }

    #[test]
    fn intact_entries_validate_and_serve() {
        let desc = descriptor();
        let entry = StoredDescriptorEntry::commit(&desc);
        assert_eq!(
            verify_hit(&entry, &entry.canonical_descriptor_bytes.clone(), &desc),
            HitVerification::Validated
        );
    }

    #[test]
    fn corrupted_descriptor_bytes_refuse_with_storage_reason() {
        // THE acceptance fixture: flip one stored byte; the hit must
        // refuse with a STORAGE_* code, never serve.
        let desc = descriptor();
        let entry = StoredDescriptorEntry::commit(&desc);
        let mut corrupted = entry.canonical_descriptor_bytes.clone();
        corrupted[10] ^= 0xFF;
        let HitVerification::Refused { reason_code } = verify_hit(&entry, &corrupted, &desc) else {
            panic!("corrupted bytes must refuse");
        };
        assert!(reason_code.starts_with("STORAGE_"), "{reason_code}");
    }

    #[test]
    fn serialization_drift_refuses_with_storage_reason() {
        // Reader deserialized a DIFFERENT descriptor than the bytes
        // claim (writer/reader version skew): step 2 catches it even
        // though the reloaded bytes are intact.
        let desc = descriptor();
        let entry = StoredDescriptorEntry::commit(&desc);
        let mut drifted = descriptor();
        drifted.environment = d("rabs.env.v1", 99);
        let HitVerification::Refused { reason_code } =
            verify_hit(&entry, &entry.canonical_descriptor_bytes.clone(), &drifted)
        else {
            panic!("drift must refuse");
        };
        assert!(reason_code.starts_with("STORAGE_"), "{reason_code}");
    }

    #[test]
    fn index_cross_link_refuses_with_key_reason() {
        // Entry indexed under the WRONG key (index corruption or a
        // key-assembly bug): bytes and digest verify, key does not.
        let desc = descriptor();
        let mut entry = StoredDescriptorEntry::commit(&desc);
        entry.action_key = d("rabs.action-key.sha256.v1", 42);
        let HitVerification::Refused { reason_code } =
            verify_hit(&entry, &entry.canonical_descriptor_bytes.clone(), &desc)
        else {
            panic!("cross-link must refuse");
        };
        assert!(reason_code.starts_with("KEY_"), "{reason_code}");
    }

    #[test]
    fn independent_digest_uses_its_own_domain() {
        // The two digests over related bytes live in different domains:
        // colliding one cannot satisfy the other.
        let desc = descriptor();
        let entry = StoredDescriptorEntry::commit(&desc);
        assert_eq!(entry.descriptor_digest.domain, DOMAIN_DESCRIPTOR);
        assert_ne!(entry.descriptor_digest.domain, entry.action_key.domain);
        assert_ne!(entry.descriptor_digest.bytes, entry.action_key.bytes);
    }
}
