//! Dependency source snapshot manifests (bead K002; plan §95; risk
//! R84).
//!
//! Registry and git packages materialize from CHECKSUMMED immutable
//! source manifests: one manifest per (source, checksum) identity
//! (K001), listing every member file with its content digest. The
//! manifest serves two masters with one artifact — materialization
//! (workers reconstruct the tree) and key inputs (the manifest digest
//! is the source identity's proof) — and it is validated against
//! Cargo's OWN checksum for the package: a mismatch between what Cargo
//! resolved and what the manifest claims REFUSES materialization
//! outright (a poisoned mirror or torn unpack must never silently
//! substitute source bytes).

use rabs_protocol::result_identity::TypedDigest;

/// One member file of a dependency source tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMember {
    /// Path relative to the package root.
    pub relative_path: String,
    /// Content digest of the file.
    pub content_digest: TypedDigest,
    /// Executable bit (the H001 FileObject policy keeps it identity).
    pub executable: bool,
}

/// The checksummed immutable source manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencySourceManifest {
    /// The K001 immutable-source checksum this manifest embodies
    /// (registry unpack checksum or git revision).
    pub source_checksum: String,
    /// Cargo's own checksum for the package (lockfile `checksum` field
    /// for registry packages; revision hash for git).
    pub cargo_checksum: String,
    /// Members sorted by relative path.
    pub members: Vec<SnapshotMember>,
}

/// Validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// The manifest's checksum does not match what Cargo resolved.
    CargoChecksumMismatch {
        /// What the manifest claims.
        manifest: String,
        /// What Cargo resolved.
        resolved: String,
    },
    /// Members not sorted / duplicated (non-canonical manifest).
    NonCanonicalMemberOrder(String),
}

impl DependencySourceManifest {
    /// Validate against Cargo's resolved checksum and canonical form.
    ///
    /// # Errors
    /// [`SnapshotError`] on mismatch or malformation.
    pub fn validate(&self, cargo_resolved_checksum: &str) -> Result<(), SnapshotError> {
        if self.cargo_checksum != cargo_resolved_checksum {
            return Err(SnapshotError::CargoChecksumMismatch {
                manifest: self.cargo_checksum.clone(),
                resolved: cargo_resolved_checksum.to_owned(),
            });
        }
        for window in self.members.windows(2) {
            if window[0].relative_path >= window[1].relative_path {
                return Err(SnapshotError::NonCanonicalMemberOrder(
                    window[1].relative_path.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Serialize to the canonical line format (round-trip anchor).
    #[must_use]
    pub fn to_canonical_lines(&self) -> String {
        let mut out = format!(
            "source-checksum {}\ncargo-checksum {}\n",
            self.source_checksum, self.cargo_checksum
        );
        for member in &self.members {
            let mut hex = String::with_capacity(64);
            for byte in &member.content_digest.bytes {
                hex.push_str(&format!("{byte:02x}"));
            }
            out.push_str(&format!(
                "member {} {} {} {}\n",
                member.relative_path,
                member.content_digest.domain,
                hex,
                u8::from(member.executable),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    fn manifest() -> DependencySourceManifest {
        DependencySourceManifest {
            source_checksum: "9f86d081884c7d65".into(),
            cargo_checksum: "cargo-sum-abc123".into(),
            members: vec![
                SnapshotMember {
                    relative_path: "Cargo.toml".into(),
                    content_digest: d(1),
                    executable: false,
                },
                SnapshotMember {
                    relative_path: "src/lib.rs".into(),
                    content_digest: d(2),
                    executable: false,
                },
                SnapshotMember {
                    relative_path: "tools/gen.sh".into(),
                    content_digest: d(3),
                    executable: true,
                },
            ],
        }
    }

    #[test]
    fn manifests_round_trip_deterministically() {
        // THE acceptance: the canonical serialization is stable — two
        // renders of one manifest are byte-identical, and every field
        // (paths, digests, exec bits, both checksums) appears.
        let a = manifest().to_canonical_lines();
        let b = manifest().to_canonical_lines();
        assert_eq!(a, b);
        assert!(a.contains("source-checksum 9f86d081884c7d65"));
        assert!(a.contains("cargo-checksum cargo-sum-abc123"));
        assert!(a.contains("member tools/gen.sh rabs.object.v1"));
        assert!(a.lines().last().unwrap().ends_with(" 1"), "exec bit");
        // A changed member changes the render (identity-bearing).
        let mut changed = manifest();
        changed.members[1].content_digest = d(9);
        assert_ne!(a, changed.to_canonical_lines());
    }

    #[test]
    fn cargo_checksum_mismatch_refuses() {
        // THE acceptance: a manifest whose checksum differs from what
        // Cargo resolved (poisoned mirror, torn unpack) refuses.
        let m = manifest();
        assert_eq!(m.validate("cargo-sum-abc123"), Ok(()));
        assert_eq!(
            m.validate("cargo-sum-EVIL"),
            Err(SnapshotError::CargoChecksumMismatch {
                manifest: "cargo-sum-abc123".into(),
                resolved: "cargo-sum-EVIL".into(),
            })
        );
    }

    #[test]
    fn non_canonical_member_order_refuses() {
        let mut unsorted = manifest();
        unsorted.members.swap(0, 2);
        assert!(matches!(
            unsorted.validate("cargo-sum-abc123"),
            Err(SnapshotError::NonCanonicalMemberOrder(_))
        ));
        // Duplicates are non-canonical too (>= comparison).
        let mut dup = manifest();
        dup.members[1].relative_path = "Cargo.toml".into();
        dup.members.swap(0, 1); // keep "sorted" shape with equal keys
        assert!(matches!(
            dup.validate("cargo-sum-abc123"),
            Err(SnapshotError::NonCanonicalMemberOrder(_))
        ));
    }
}
