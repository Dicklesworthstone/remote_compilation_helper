//! Filesystem semantic classes, defined and keyed (bead D022; plan
//! §65; risk R71).
//!
//! Two filesystems that answer namespace questions differently can make
//! one compile produce different results: a case-insensitive volume
//! resolves `Lib.rs` where a sensitive one errors; an NFD-normalizing
//! volume aliases two Unicode spellings; symlink/hardlink and
//! permission behavior diverge similarly. The semantic class captures
//! exactly the observable dimensions and keys them into
//! `OutputPlatformContract.filesystem_semantic_class` (F008) BY
//! DEFAULT:
//!
//! - **class equality is required** for any action that can observe
//!   namespace behavior;
//! - **omission requires proof** the action cannot distinguish — the
//!   canonical serialization has no "skip" arm without a named proof,
//!   so silently dropping the class from the key is unrepresentable.

use crate::canonical::CanonicalEncoder;

/// Case sensitivity of the presented filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum CaseSensitivity {
    Sensitive,
    InsensitivePreserving,
    InsensitiveFolding,
}

/// Unicode normalization behavior of path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum UnicodeNormalization {
    /// Bytes stored as given.
    BytePreserving,
    /// Names normalized (e.g. APFS/HFS+ NFD variants).
    Normalizing,
}

/// Symlink behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum SymlinkSemantics {
    FullPosix,
    /// Restricted (no symlink creation inside the view).
    Restricted,
}

/// Hardlink behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum HardlinkSemantics {
    FullPosix,
    Unsupported,
}

/// Permission/exec-bit behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PermissionSemantics {
    PosixFull,
    /// Exec bit honored, other mode bits normalized by the profile.
    ExecBitOnly,
}

/// Exposed xattr/ACL policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum XattrExposure {
    Hidden,
    Exposed,
}

/// The full filesystem semantic class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemSemanticClass {
    /// Case sensitivity.
    pub case: CaseSensitivity,
    /// Unicode normalization.
    pub unicode: UnicodeNormalization,
    /// Symlink semantics.
    pub symlinks: SymlinkSemantics,
    /// Hardlink semantics.
    pub hardlinks: HardlinkSemantics,
    /// Permission behavior.
    pub permissions: PermissionSemantics,
    /// xattr/ACL exposure.
    pub xattrs: XattrExposure,
}

impl FilesystemSemanticClass {
    /// The strict-hermetic Linux presentation class (the fleet default:
    /// sandboxes PRESENT this class regardless of backing store, which
    /// is what makes cross-worker sharing sound).
    pub const STRICT_LINUX_PRESENTED: Self = Self {
        case: CaseSensitivity::Sensitive,
        unicode: UnicodeNormalization::BytePreserving,
        symlinks: SymlinkSemantics::FullPosix,
        hardlinks: HardlinkSemantics::FullPosix,
        permissions: PermissionSemantics::ExecBitOnly,
        xattrs: XattrExposure::Hidden,
    };

    /// Canonical keying string for the F008
    /// `filesystem_semantic_class` slot.
    #[must_use]
    pub fn keying_string(&self) -> String {
        format!(
            "case-{}.unicode-{}.symlink-{}.hardlink-{}.perm-{}.xattr-{}",
            match self.case {
                CaseSensitivity::Sensitive => "sensitive",
                CaseSensitivity::InsensitivePreserving => "ins-preserving",
                CaseSensitivity::InsensitiveFolding => "ins-folding",
            },
            match self.unicode {
                UnicodeNormalization::BytePreserving => "bytes",
                UnicodeNormalization::Normalizing => "normalizing",
            },
            match self.symlinks {
                SymlinkSemantics::FullPosix => "posix",
                SymlinkSemantics::Restricted => "restricted",
            },
            match self.hardlinks {
                HardlinkSemantics::FullPosix => "posix",
                HardlinkSemantics::Unsupported => "none",
            },
            match self.permissions {
                PermissionSemantics::PosixFull => "posix",
                PermissionSemantics::ExecBitOnly => "execbit",
            },
            match self.xattrs {
                XattrExposure::Hidden => "hidden",
                XattrExposure::Exposed => "exposed",
            },
        )
    }
}

/// How the class enters the key for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassKeying {
    /// Default: the class keys (equality required for sharing).
    Keyed(FilesystemSemanticClass),
    /// Omitted UNDER A NAMED PROOF that this action class cannot
    /// observe namespace behavior. No proof, no omission.
    OmittedWithProof {
        /// The registered proof identity.
        proof: &'static str,
    },
}

impl ClassKeying {
    /// Canonical bytes for the descriptor slot.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut enc = CanonicalEncoder::new();
        match self {
            Self::Keyed(class) => {
                enc.u32(1).str(&class.keying_string());
            }
            Self::OmittedWithProof { proof } => {
                enc.u32(2).str(proof);
            }
        }
        enc.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn differential_case_unicode_symlink_fixtures_fork_the_class() {
        // THE acceptance fixtures: each observable dimension changed in
        // isolation produces a different keying string.
        let base = FilesystemSemanticClass::STRICT_LINUX_PRESENTED;
        let mut case_differs = base;
        case_differs.case = CaseSensitivity::InsensitivePreserving;
        assert_ne!(base.keying_string(), case_differs.keying_string());
        let mut unicode_differs = base;
        unicode_differs.unicode = UnicodeNormalization::Normalizing;
        assert_ne!(base.keying_string(), unicode_differs.keying_string());
        let mut symlink_differs = base;
        symlink_differs.symlinks = SymlinkSemantics::Restricted;
        assert_ne!(base.keying_string(), symlink_differs.keying_string());
        let mut hardlink_differs = base;
        hardlink_differs.hardlinks = HardlinkSemantics::Unsupported;
        assert_ne!(base.keying_string(), hardlink_differs.keying_string());
        let mut perm_differs = base;
        perm_differs.permissions = PermissionSemantics::PosixFull;
        assert_ne!(base.keying_string(), perm_differs.keying_string());
        let mut xattr_differs = base;
        xattr_differs.xattrs = XattrExposure::Exposed;
        assert_ne!(base.keying_string(), xattr_differs.keying_string());
    }

    #[test]
    fn keyed_by_default_and_omission_needs_a_named_proof() {
        // The default arm keys the class; the ONLY other arm requires a
        // proof identity — an unproven omission is unrepresentable.
        let keyed = ClassKeying::Keyed(FilesystemSemanticClass::STRICT_LINUX_PRESENTED);
        let omitted = ClassKeying::OmittedWithProof {
            proof: "rabs-proof.toolchain-probe-no-namespace-observation.v1",
        };
        assert_ne!(keyed.canonical_bytes(), omitted.canonical_bytes());
        // Discriminant tags: an omission proof string can never collide
        // with a keyed class string.
        let sneaky = ClassKeying::OmittedWithProof {
            proof: "case-sensitive.unicode-bytes.symlink-posix.hardlink-posix.perm-execbit.xattr-hidden",
        };
        assert_ne!(keyed.canonical_bytes(), sneaky.canonical_bytes());
    }

    #[test]
    fn presented_class_is_the_sharing_contract() {
        // Two workers with DIFFERENT backing stores presenting the same
        // strict class key identically — presentation, not the host
        // filesystem, is the contract (what makes sharing sound).
        let worker_a = FilesystemSemanticClass::STRICT_LINUX_PRESENTED;
        let worker_b = FilesystemSemanticClass::STRICT_LINUX_PRESENTED;
        assert_eq!(worker_a.keying_string(), worker_b.keying_string());
        assert_eq!(
            worker_a.keying_string(),
            "case-sensitive.unicode-bytes.symlink-posix.hardlink-posix.perm-execbit.xattr-hidden"
        );
    }
}
