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
}
