//! Object/chunk/manifest/artifact-bundle schemas (bead H001; plan §90;
//! risks R25/R125): the ATP object concepts mapped to build profiles.
//!
//! Every stored thing is one of eight object kinds, and every kind
//! carries an EXPLICIT metadata policy — what participates in logical
//! identity and what is deliberately excluded. The rule with teeth:
//!
//! - **timestamps are excluded from logical identity ONLY where a
//!   kind's policy declares it AND the exclusion is proven
//!   nonsemantic** for that kind (a source snapshot's mtimes are build
//!   noise; a stream archive's event times are the payload);
//! - permissions, symlinks, exec bits, and xattrs enter identity
//!   through the kind's named metadata profile, never ad hoc — two
//!   encoders of one kind cannot disagree about what to hash.

/// The eight object kinds (wire-stable tags via [`object_kind_tag`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// A single file blob (source, rmeta, rlib, object file,
    /// executable, diagnostic blob).
    FileObject,
    /// A directory tree with entry metadata per profile.
    DirectoryObject,
    /// A full snapshot (source tree or execroot form).
    SnapshotObject,
    /// A dataset (toolchain, sysroot, registry set, native SDK).
    DatasetObject,
    /// The complete output set of one action result.
    ArtifactBundle,
    /// Incremental state image (sparse; attempt auxiliary only).
    SparseImage,
    /// Event archives (compiler event streams, transcripts).
    StreamObject,
    /// Application-defined records (results, provenance, receipts,
    /// failure bundles).
    ApplicationDefinedObject,
}

impl ObjectKind {
    /// All kinds, for exhaustiveness checks.
    pub const ALL: [Self; 8] = [
        Self::FileObject,
        Self::DirectoryObject,
        Self::SnapshotObject,
        Self::DatasetObject,
        Self::ArtifactBundle,
        Self::SparseImage,
        Self::StreamObject,
        Self::ApplicationDefinedObject,
    ];
}

/// Wire-stable kind tag.
#[must_use]
pub const fn object_kind_tag(kind: ObjectKind) -> u32 {
    match kind {
        ObjectKind::FileObject => 1,
        ObjectKind::DirectoryObject => 2,
        ObjectKind::SnapshotObject => 3,
        ObjectKind::DatasetObject => 4,
        ObjectKind::ArtifactBundle => 5,
        ObjectKind::SparseImage => 6,
        ObjectKind::StreamObject => 7,
        ObjectKind::ApplicationDefinedObject => 8,
    }
}

/// How one metadata dimension participates in logical identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataRule {
    /// Participates in logical identity.
    Identity,
    /// Excluded, with the declared proof of nonsemantic status.
    ExcludedNonsemantic {
        /// Why exclusion is sound for this kind.
        proof: &'static str,
    },
    /// Not applicable to this kind.
    NotApplicable,
}

/// The per-kind metadata policy (the named profile every encoder of
/// the kind must follow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataPolicy {
    /// The kind this policy governs.
    pub kind: ObjectKind,
    /// Timestamps (mtime/ctime/birth).
    pub timestamps: MetadataRule,
    /// Permission bits beyond the exec bit.
    pub permissions: MetadataRule,
    /// Executable bit.
    pub exec_bit: MetadataRule,
    /// Symlink targets.
    pub symlinks: MetadataRule,
    /// Extended attributes.
    pub xattrs: MetadataRule,
}

/// The object-manifest registry: one metadata policy per kind.
pub const OBJECT_METADATA_REGISTRY: &[MetadataPolicy] = &[
    MetadataPolicy {
        kind: ObjectKind::FileObject,
        timestamps: MetadataRule::ExcludedNonsemantic {
            proof: "file identity is content bytes; compilers key on content, not mtime",
        },
        permissions: MetadataRule::ExcludedNonsemantic {
            proof: "non-exec permission bits do not alter tool reads under the presented profile",
        },
        exec_bit: MetadataRule::Identity,
        symlinks: MetadataRule::NotApplicable,
        xattrs: MetadataRule::ExcludedNonsemantic {
            proof: "xattrs are not presented inside the sandbox filesystem view",
        },
    },
    MetadataPolicy {
        kind: ObjectKind::DirectoryObject,
        timestamps: MetadataRule::ExcludedNonsemantic {
            proof: "directory mtimes churn on every materialization; listings are the semantics",
        },
        permissions: MetadataRule::ExcludedNonsemantic {
            proof: "presented profile normalizes directory modes",
        },
        exec_bit: MetadataRule::Identity,
        symlinks: MetadataRule::Identity,
        xattrs: MetadataRule::ExcludedNonsemantic {
            proof: "xattrs are not presented inside the sandbox filesystem view",
        },
    },
    MetadataPolicy {
        kind: ObjectKind::SnapshotObject,
        timestamps: MetadataRule::ExcludedNonsemantic {
            proof: "snapshot mtimes vary per checkout; content+structure is the identity",
        },
        permissions: MetadataRule::ExcludedNonsemantic {
            proof: "presented profile normalizes modes at materialization",
        },
        exec_bit: MetadataRule::Identity,
        symlinks: MetadataRule::Identity,
        xattrs: MetadataRule::ExcludedNonsemantic {
            proof: "xattrs are not presented inside the sandbox filesystem view",
        },
    },
    MetadataPolicy {
        kind: ObjectKind::DatasetObject,
        timestamps: MetadataRule::ExcludedNonsemantic {
            proof: "toolchain/sysroot install times vary per host; bytes are identity",
        },
        permissions: MetadataRule::Identity, // SDK tools ship meaningful modes
        exec_bit: MetadataRule::Identity,
        symlinks: MetadataRule::Identity, // sysroots use symlink farms
        xattrs: MetadataRule::ExcludedNonsemantic {
            proof: "xattrs are not presented inside the sandbox filesystem view",
        },
    },
    MetadataPolicy {
        kind: ObjectKind::ArtifactBundle,
        timestamps: MetadataRule::ExcludedNonsemantic {
            proof: "output mtimes are materialization artifacts; F035 root covers content",
        },
        permissions: MetadataRule::ExcludedNonsemantic {
            proof: "outputs re-materialize under the subscriber's umask policy",
        },
        exec_bit: MetadataRule::Identity,
        symlinks: MetadataRule::Identity,
        xattrs: MetadataRule::NotApplicable,
    },
    MetadataPolicy {
        // Sparse images are attempt auxiliaries: NEVER result identity
        // (I4), so their internal metadata all rides along verbatim.
        kind: ObjectKind::SparseImage,
        timestamps: MetadataRule::Identity, // incremental state IS time-laden
        permissions: MetadataRule::Identity,
        exec_bit: MetadataRule::Identity,
        symlinks: MetadataRule::Identity,
        xattrs: MetadataRule::Identity,
    },
    MetadataPolicy {
        kind: ObjectKind::StreamObject,
        timestamps: MetadataRule::Identity, // event times ARE the payload
        permissions: MetadataRule::NotApplicable,
        exec_bit: MetadataRule::NotApplicable,
        symlinks: MetadataRule::NotApplicable,
        xattrs: MetadataRule::NotApplicable,
    },
    MetadataPolicy {
        kind: ObjectKind::ApplicationDefinedObject,
        timestamps: MetadataRule::Identity, // records carry their own time fields
        permissions: MetadataRule::NotApplicable,
        exec_bit: MetadataRule::NotApplicable,
        symlinks: MetadataRule::NotApplicable,
        xattrs: MetadataRule::NotApplicable,
    },
];

/// Look up the metadata policy for a kind (total; test-enforced).
#[must_use]
pub fn metadata_policy(kind: ObjectKind) -> &'static MetadataPolicy {
    OBJECT_METADATA_REGISTRY
        .iter()
        .find(|p| p.kind == kind)
        .expect("registry totality is test-enforced")
}

/// One chunk of a large object's content (content-defined chunking;
/// chunk boundaries are storage, never identity — the object digest is
/// over the WHOLE content).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    /// Chunk content digest.
    pub chunk_digest: crate::result_identity::TypedDigest,
    /// Byte length of the chunk.
    pub length: u64,
}

/// Manifest for one stored object: kind, whole-content identity, and
/// the chunk list that reassembles it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectManifest {
    /// The kind (its metadata policy governs the encoder).
    pub kind: ObjectKind,
    /// Whole-object logical identity.
    pub object: crate::result_identity::ObjectId,
    /// Ordered chunks reassembling the content.
    pub chunks: Vec<ChunkRef>,
    /// Total content length (must equal the chunk-length sum).
    pub total_length: u64,
}

impl ObjectManifest {
    /// Structural validity: chunk lengths sum to the total.
    ///
    /// # Errors
    /// A static description of the violated rule.
    pub fn validate(&self) -> Result<(), &'static str> {
        let sum: u64 = self.chunks.iter().map(|c| c.length).sum();
        if sum != self.total_length {
            return Err("chunk lengths do not sum to total_length");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};

    fn digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    #[test]
    fn registry_is_total_and_tags_are_stable() {
        for kind in ObjectKind::ALL {
            let count = OBJECT_METADATA_REGISTRY
                .iter()
                .filter(|p| p.kind == kind)
                .count();
            assert_eq!(count, 1, "{kind:?} needs exactly one policy");
        }
        let tags: Vec<u32> = ObjectKind::ALL
            .iter()
            .map(|k| object_kind_tag(*k))
            .collect();
        assert_eq!(tags, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn every_timestamp_exclusion_names_its_proof() {
        // THE acceptance rule: timestamps leave logical identity ONLY
        // where declared + proven nonsemantic. Every exclusion carries
        // a non-empty proof string; kinds whose times ARE payload
        // (streams, sparse images, app records) keep them as identity.
        for policy in OBJECT_METADATA_REGISTRY {
            match policy.timestamps {
                MetadataRule::ExcludedNonsemantic { proof } => {
                    assert!(!proof.is_empty(), "{:?}", policy.kind);
                }
                MetadataRule::Identity => {
                    assert!(
                        matches!(
                            policy.kind,
                            ObjectKind::StreamObject
                                | ObjectKind::SparseImage
                                | ObjectKind::ApplicationDefinedObject
                        ),
                        "{:?}: timestamp-as-identity needs payload semantics",
                        policy.kind
                    );
                }
                MetadataRule::NotApplicable => {
                    panic!("{:?}: timestamps always exist on stored data", policy.kind);
                }
            }
        }
    }

    #[test]
    fn exec_bits_are_identity_wherever_files_exist() {
        // An exec-bit flip changes what a build can DO with an output;
        // no filesystem-shaped kind may exclude it.
        for policy in OBJECT_METADATA_REGISTRY {
            if matches!(
                policy.kind,
                ObjectKind::FileObject
                    | ObjectKind::DirectoryObject
                    | ObjectKind::SnapshotObject
                    | ObjectKind::DatasetObject
                    | ObjectKind::ArtifactBundle
                    | ObjectKind::SparseImage
            ) {
                assert_eq!(
                    policy.exec_bit,
                    MetadataRule::Identity,
                    "{:?}: exec bit is semantic",
                    policy.kind
                );
            }
        }
    }

    #[test]
    fn chunking_is_storage_never_identity() {
        // Two manifests chunking the SAME object differently share the
        // object identity — the digest is over whole content; chunk
        // boundaries are transport/storage layout.
        let object = ObjectId(digest(1));
        let one_chunk = ObjectManifest {
            kind: ObjectKind::FileObject,
            object: object.clone(),
            chunks: vec![ChunkRef {
                chunk_digest: digest(10),
                length: 100,
            }],
            total_length: 100,
        };
        let two_chunks = ObjectManifest {
            kind: ObjectKind::FileObject,
            object: object.clone(),
            chunks: vec![
                ChunkRef {
                    chunk_digest: digest(11),
                    length: 60,
                },
                ChunkRef {
                    chunk_digest: digest(12),
                    length: 40,
                },
            ],
            total_length: 100,
        };
        assert!(one_chunk.validate().is_ok());
        assert!(two_chunks.validate().is_ok());
        assert_eq!(one_chunk.object, two_chunks.object);
        // Length mismatch is structural corruption.
        let torn = ObjectManifest {
            total_length: 99,
            ..one_chunk
        };
        assert!(torn.validate().is_err());
    }

    #[test]
    fn h018_and_h025_cold_store_l4_round_trip_and_namespace_acl_encryption_at_rest() {
        let mut cold_store = ColdStoreL4Adapter::default();
        let obj_id = ObjectId(digest(0x41));
        let manifest = ObjectManifest {
            kind: ObjectKind::DatasetObject,
            object: obj_id.clone(),
            chunks: vec![ChunkRef {
                chunk_digest: digest(0x42),
                length: 6,
            }],
            total_length: 6,
        };
        let plaintext = b"secret".to_vec();
        let key_material = [0x5A_u8; 32];

        let acl_alpha = ProjectNamespaceProfile {
            namespace_id: "proj/alpha-restricted".into(),
            classification: NamespaceAccessClassification::RestrictedSensitive,
            require_encryption_at_rest: true,
            authorized_projects: vec!["proj/alpha-restricted".into()],
        };

        // 1. H025: Attempting to store a RestrictedSensitive object without encryption fails closed!
        assert_eq!(
            cold_store.put_cold_object(
                &acl_alpha,
                manifest.clone(),
                &plaintext,
                None,
                true, // local representation evicted, manifest retained cold
            ),
            Err(ColdStoreAndAclError::EncryptionAtRestRequired)
        );

        // 2. H018 + H025: Encrypted-at-rest round-trip through L4 cold store succeeds,
        //    even after local L1/L2 representation eviction.
        cold_store
            .put_cold_object(
                &acl_alpha,
                manifest.clone(),
                &plaintext,
                Some(&key_material),
                true,
            )
            .expect("store encrypted object in L4 cold tier");

        // Cross-namespace access from "proj/beta" is DENIED (H025 acceptance).
        assert_eq!(
            cold_store.get_cold_object(&obj_id, "proj/beta", Some(&key_material)),
            Err(ColdStoreAndAclError::CrossNamespaceAccessDenied {
                requested_by: "proj/beta".into(),
                owner_namespace: "proj/alpha-restricted".into(),
            })
        );

        // Wrong decryption key is rejected via integrity tag check.
        let wrong_key = [0x11_u8; 32];
        assert_eq!(
            cold_store.get_cold_object(&obj_id, "proj/alpha-restricted", Some(&wrong_key)),
            Err(ColdStoreAndAclError::IntegrityOrDecryptionFailed)
        );

        // Authorized project with matching key material round-trips both manifest and bytes.
        let (restored_manifest, restored_bytes) = cold_store
            .get_cold_object(&obj_id, "proj/alpha-restricted", Some(&key_material))
            .expect("round-trip from L4 cold store");
        assert_eq!(restored_manifest, manifest);
        assert_eq!(restored_bytes, plaintext);
    }

    #[test]
    fn h019_coordinator_directed_peer_seeding_improves_locality_verifies_receipt_and_browns_out() {
        let toolchain_obj = ObjectId(digest(0x71));
        let payload = b"rustc-toolchain-layer-bytes";
        let expected_digest = compute_seeding_digest(payload);

        let public_ns = ProjectNamespaceProfile {
            namespace_id: "fleet/shared-toolchains".into(),
            classification: NamespaceAccessClassification::SharedImmutable,
            require_encryption_at_rest: false,
            authorized_projects: vec!["*".into()],
        };
        let restricted_ns = ProjectNamespaceProfile {
            namespace_id: "proj/secret-enclave".into(),
            classification: NamespaceAccessClassification::RestrictedSensitive,
            require_encryption_at_rest: true,
            authorized_projects: vec!["proj/secret-enclave".into()],
        };

        // 1. Restricted/secret namespaces are NEVER seeded outside access policy!
        assert_eq!(
            evaluate_coordinator_peer_seeding(
                &restricted_ns,
                &toolchain_obj,
                expected_digest,
                payload,
                false, // not under pressure
                1,
            ),
            PeerSeedingOutcome::RefusedRestrictedNamespace
        );

        // 2. Seeding is optional work that browns out under pressure!
        assert_eq!(
            evaluate_coordinator_peer_seeding(
                &public_ns,
                &toolchain_obj,
                expected_digest,
                payload,
                true, // pressure brownout active!
                1,
            ),
            PeerSeedingOutcome::SkippedUnderPressureBrownout
        );

        // 3. Corrupted payload fails independent verification on receipt!
        assert_eq!(
            evaluate_coordinator_peer_seeding(
                &public_ns,
                &toolchain_obj,
                expected_digest,
                b"corrupted-bytes",
                false,
                1,
            ),
            PeerSeedingOutcome::RejectedDigestVerificationFailed
        );

        // 4. Valid seeding improves placement locality (replica count 1 -> 2).
        assert_eq!(
            evaluate_coordinator_peer_seeding(
                &public_ns,
                &toolchain_obj,
                expected_digest,
                payload,
                false,
                1,
            ),
            PeerSeedingOutcome::SeededAndVerified {
                new_placement_locality_replicas: 2,
            }
        );
    }

    #[test]
    fn h020_storage_value_model_ranks_retention_and_feeds_gc_eviction() {
        // Compare three unpinned objects under a 100 KB GC budget:
        // - `heavy_link`: 40 KB, Link class (high recompute cost: 60_000 ms, 5 hits)
        // - `dep_compile`: 40 KB, RustcDependencyCompile (40_000 ms, 10 hits)
        // - `cheap_archive`: 40 KB, NativeArchive (500 ms, 1 hit)
        let candidates = vec![
            StorageValueCandidate {
                object_id: ObjectId(digest(1)),
                action_class: crate::descriptor::ActionClass::NativeArchive,
                recompute_cost_ms: 500,
                recent_hit_count: 1,
                size_bytes: 40_000,
                pinned_or_leased: false,
            },
            StorageValueCandidate {
                object_id: ObjectId(digest(2)),
                action_class: crate::descriptor::ActionClass::Link,
                recompute_cost_ms: 60_000,
                recent_hit_count: 5,
                size_bytes: 40_000,
                pinned_or_leased: false,
            },
            StorageValueCandidate {
                object_id: ObjectId(digest(3)),
                action_class: crate::descriptor::ActionClass::RustcDependencyCompile,
                recompute_cost_ms: 40_000,
                recent_hit_count: 10,
                size_bytes: 40_000,
                pinned_or_leased: false,
            },
        ];

        let plan = plan_value_ranked_gc(&candidates, 80_000);
        // Total is 120_000 bytes; target is 80_000 bytes -> must evict 40_000 bytes.
        // `cheap_archive` (object 1) has the lowest compiler-seconds-per-byte score and is evicted first!
        assert_eq!(plan.evicted_objects, vec![ObjectId(digest(1))]);
        assert_eq!(
            plan.retained_ranked_high_to_low,
            vec![ObjectId(digest(3)), ObjectId(digest(2))]
        );
    }
}

/// Access classification for a project/object namespace (beads H019/H025).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceAccessClassification {
    /// Immutable toolchains or public registry dependencies shareable across projects in the V1 domain.
    SharedImmutable,
    /// Project-scoped build artifacts and workspace sources.
    ProjectScoped,
    /// Sensitive/secret-bearing or compliance-restricted namespace: never peer-seeded and
    /// requires at-rest encryption when configured.
    RestrictedSensitive,
}

/// Project namespace ACL and encryption-at-rest profile (bead H025).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectNamespaceProfile {
    /// Canonical namespace identifier (e.g. `"proj/alpha"`).
    pub namespace_id: String,
    /// Access classification.
    pub classification: NamespaceAccessClassification,
    /// Whether objects in this namespace must be encrypted at rest.
    pub require_encryption_at_rest: bool,
    /// Project identities authorized to read from this namespace (`"*"` for shared immutable).
    pub authorized_projects: Vec<String>,
}

impl ProjectNamespaceProfile {
    /// Whether `requester_project` is authorized to read objects in this namespace.
    #[must_use]
    pub fn permits_read(&self, requester_project: &str) -> bool {
        self.authorized_projects
            .iter()
            .any(|p| p == "*" || p == requester_project)
    }
}

/// Stored entry in the L4 cold object tier (bead H018).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ColdStoreEntry {
    profile: ProjectNamespaceProfile,
    manifest: ObjectManifest,
    ciphertext_or_bytes: Vec<u8>,
    encrypted: bool,
    integrity_tag: u64,
    local_representation_evicted: bool,
}

/// Errors from L4 cold-store and H025 namespace ACL / encryption operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdStoreAndAclError {
    /// Namespace profile requires encryption at rest, but no key material was supplied.
    EncryptionAtRestRequired,
    /// Requester project is not authorized by the namespace ACL.
    CrossNamespaceAccessDenied {
        /// Requesting project identity.
        requested_by: String,
        /// Owning namespace.
        owner_namespace: String,
    },
    /// Object not found in the L4 cold store.
    ObjectNotFound,
    /// Ciphertext integrity tag or decryption key check failed.
    IntegrityOrDecryptionFailed,
}

/// Optional L4 encrypted cold-store adapter behind the storage abstraction (beads H018/H025).
#[derive(Debug, Clone, Default)]
pub struct ColdStoreL4Adapter {
    entries: Vec<ColdStoreEntry>,
}

impl ColdStoreL4Adapter {
    /// Store an object manifest and payload in the L4 cold store, applying the namespace's
    /// encryption-at-rest policy (beads H018/H025).
    ///
    /// # Errors
    /// Returns [`ColdStoreAndAclError::EncryptionAtRestRequired`] if the namespace requires
    /// encryption and `encryption_key` is `None`.
    pub fn put_cold_object(
        &mut self,
        profile: &ProjectNamespaceProfile,
        manifest: ObjectManifest,
        plaintext: &[u8],
        encryption_key: Option<&[u8; 32]>,
        local_representation_evicted: bool,
    ) -> Result<(), ColdStoreAndAclError> {
        if profile.require_encryption_at_rest && encryption_key.is_none() {
            return Err(ColdStoreAndAclError::EncryptionAtRestRequired);
        }
        let (ciphertext_or_bytes, encrypted, integrity_tag) = match encryption_key {
            Some(key) => {
                let mut buf = Vec::with_capacity(plaintext.len());
                for (i, b) in plaintext.iter().enumerate() {
                    buf.push(b ^ key[i % 32] ^ ((i as u8).wrapping_mul(17)));
                }
                let tag = compute_keyed_tag(key, plaintext);
                (buf, true, tag)
            }
            None => (plaintext.to_vec(), false, compute_seeding_digest(plaintext)),
        };

        self.entries.push(ColdStoreEntry {
            profile: profile.clone(),
            manifest,
            ciphertext_or_bytes,
            encrypted,
            integrity_tag,
            local_representation_evicted,
        });
        Ok(())
    }

    /// Retrieve and decrypt an object + manifest from the L4 cold store after enforcing
    /// the H025 project namespace ACL.
    ///
    /// # Errors
    /// Returns [`ColdStoreAndAclError`] on cross-namespace access denial, missing object,
    /// or failed decryption/integrity verification.
    pub fn get_cold_object(
        &self,
        object_id: &crate::result_identity::ObjectId,
        requester_project: &str,
        decryption_key: Option<&[u8; 32]>,
    ) -> Result<(ObjectManifest, Vec<u8>), ColdStoreAndAclError> {
        let entry = self
            .entries
            .iter()
            .find(|e| &e.manifest.object == object_id)
            .ok_or(ColdStoreAndAclError::ObjectNotFound)?;

        if !entry.profile.permits_read(requester_project) {
            return Err(ColdStoreAndAclError::CrossNamespaceAccessDenied {
                requested_by: requester_project.into(),
                owner_namespace: entry.profile.namespace_id.clone(),
            });
        }

        if entry.encrypted {
            let key = decryption_key.ok_or(ColdStoreAndAclError::IntegrityOrDecryptionFailed)?;
            let mut plain = Vec::with_capacity(entry.ciphertext_or_bytes.len());
            for (i, b) in entry.ciphertext_or_bytes.iter().enumerate() {
                plain.push(b ^ key[i % 32] ^ ((i as u8).wrapping_mul(17)));
            }
            if compute_keyed_tag(key, &plain) != entry.integrity_tag {
                return Err(ColdStoreAndAclError::IntegrityOrDecryptionFailed);
            }
            Ok((entry.manifest.clone(), plain))
        } else {
            if compute_seeding_digest(&entry.ciphertext_or_bytes) != entry.integrity_tag {
                return Err(ColdStoreAndAclError::IntegrityOrDecryptionFailed);
            }
            Ok((entry.manifest.clone(), entry.ciphertext_or_bytes.clone()))
        }
    }
}

fn compute_keyed_tag(key: &[u8; 32], bytes: &[u8]) -> u64 {
    let mut acc: u64 = 0xCBF2_9CE4_8422_2325;
    for b in key.iter().chain(bytes.iter()) {
        acc ^= u64::from(*b);
        acc = acc.wrapping_mul(0x0100_0000_01B3);
    }
    acc
}

/// Compute a deterministic 64-bit verification digest for seeding fixtures (bead H019).
#[must_use]
pub fn compute_seeding_digest(bytes: &[u8]) -> u64 {
    compute_keyed_tag(&[0xA5; 32], bytes)
}

/// Outcome of coordinator-directed peer object seeding (bead H019).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSeedingOutcome {
    /// Object verified on receipt and added to the target worker's placement table.
    SeededAndVerified {
        /// Updated replica count across the fleet.
        new_placement_locality_replicas: u32,
    },
    /// Optional seeding work skipped because the sender or receiver is in pressure brownout.
    SkippedUnderPressureBrownout,
    /// Refused because secret/restricted namespaces may never be peer-seeded outside policy.
    RefusedRestrictedNamespace,
    /// Target worker rejected the seeded object because independent digest verification failed.
    RejectedDigestVerificationFailed,
}

/// Evaluate coordinator-directed worker-to-worker seeding of a hot immutable object (bead H019).
#[must_use]
pub fn evaluate_coordinator_peer_seeding(
    namespace: &ProjectNamespaceProfile,
    _object_id: &crate::result_identity::ObjectId,
    expected_digest: u64,
    received_bytes: &[u8],
    pressure_brownout_active: bool,
    existing_replicas: u32,
) -> PeerSeedingOutcome {
    if matches!(
        namespace.classification,
        NamespaceAccessClassification::RestrictedSensitive
    ) {
        return PeerSeedingOutcome::RefusedRestrictedNamespace;
    }
    if pressure_brownout_active {
        return PeerSeedingOutcome::SkippedUnderPressureBrownout;
    }
    if compute_seeding_digest(received_bytes) != expected_digest {
        return PeerSeedingOutcome::RejectedDigestVerificationFailed;
    }
    PeerSeedingOutcome::SeededAndVerified {
        new_placement_locality_replicas: existing_replicas.saturating_add(1),
    }
}

/// Input candidate for the H020 storage-value retention model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageValueCandidate {
    /// Object identifier.
    pub object_id: crate::result_identity::ObjectId,
    /// Action class that produced or consumes this object.
    pub action_class: crate::descriptor::ActionClass,
    /// Compiler milliseconds saved per cache hit.
    pub recompute_cost_ms: u64,
    /// Recent hit count.
    pub recent_hit_count: u32,
    /// Storage footprint in bytes.
    pub size_bytes: u64,
    /// Whether an active pin or lease protects this object from GC.
    pub pinned_or_leased: bool,
}

impl StorageValueCandidate {
    /// Compute the retention value score (compiler-ms saved × class weight × hit factor per KiB).
    #[must_use]
    pub const fn retention_score(&self) -> u64 {
        let class_multiplier: u64 = match self.action_class {
            crate::descriptor::ActionClass::RustcDependencyCompile
            | crate::descriptor::ActionClass::Link => 4,
            crate::descriptor::ActionClass::RustcWorkspaceCompile
            | crate::descriptor::ActionClass::BuildScriptRun => 3,
            _ => 1,
        };
        let hits = (self.recent_hit_count as u64).saturating_add(1);
        let total_value = self
            .recompute_cost_ms
            .saturating_mul(class_multiplier)
            .saturating_mul(hits)
            .saturating_mul(1024);
        let denom = if self.size_bytes == 0 {
            1
        } else {
            self.size_bytes
        };
        total_value / denom
    }
}

/// Output of the H020 value-ranked GC planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueRankedGcPlan {
    /// Retained objects ordered from highest retention score to lowest.
    pub retained_ranked_high_to_low: Vec<crate::result_identity::ObjectId>,
    /// Objects selected for eviction (lowest retention score first, excluding pinned/leased).
    pub evicted_objects: Vec<crate::result_identity::ObjectId>,
}

/// Rank stored objects by storage value (recomputation cost vs byte size) and select
/// the lowest-value unpinned objects for GC eviction to fit `target_bytes` (bead H020).
#[must_use]
pub fn plan_value_ranked_gc(
    candidates: &[StorageValueCandidate],
    target_bytes: u64,
) -> ValueRankedGcPlan {
    let mut indexed: Vec<&StorageValueCandidate> = candidates.iter().collect();
    // Sort ascending by retention_score so lowest-value unpinned entries are evicted first.
    indexed.sort_by_key(|c| c.retention_score());

    let mut current_bytes: u64 = candidates.iter().map(|c| c.size_bytes).sum();
    let mut evicted_objects = Vec::new();
    let mut retained = Vec::new();

    for c in indexed {
        if !c.pinned_or_leased && current_bytes > target_bytes {
            current_bytes = current_bytes.saturating_sub(c.size_bytes);
            evicted_objects.push(c.object_id.clone());
        } else {
            retained.push(c);
        }
    }

    retained.sort_by_key(|c| core::cmp::Reverse(c.retention_score()));
    let retained_ranked_high_to_low = retained.into_iter().map(|c| c.object_id.clone()).collect();

    ValueRankedGcPlan {
        retained_ranked_high_to_low,
        evicted_objects,
    }
}
