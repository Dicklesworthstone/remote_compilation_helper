//! Pluggable linker profile detection (bead L005; plan §97).
//!
//! RABS supports three linker families through one pluggable profile
//! shape: **Wild** (the preferred upstream bet), **lld** (fallback),
//! and the **system linker** (supported, least featureful). Detection
//! is CONTENT-FIRST: the version line the linker binary REPORTS
//! classifies the family, and the profile identity that enters the
//! F007 toolchain contract is the (family, version-line, binary
//! digest) triple — a family label alone is never identity (two lld
//! builds are two profiles).

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for linker profile identity.
pub const DOMAIN_LINKER_PROFILE: &str = "rabs.linker-profile.v1";

/// The supported linker families (preference order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum LinkerFamily {
    Wild,
    Lld,
    System,
}

impl LinkerFamily {
    /// Fleet preference order: Wild first, lld fallback, system last.
    pub const PREFERENCE: [Self; 3] = [Self::Wild, Self::Lld, Self::System];
}

/// One detected linker profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkerProfile {
    /// The family.
    pub family: LinkerFamily,
    /// The version line the binary reported.
    pub version_line: String,
    /// The binary's content digest.
    pub binary_digest: TypedDigest,
}

impl LinkerProfile {
    /// The profile identity that enters the F007 toolchain contract.
    #[must_use]
    pub fn profile_identity(&self) -> TypedDigest {
        let mut enc = CanonicalEncoder::new();
        enc.u32(match self.family {
            LinkerFamily::Wild => 1,
            LinkerFamily::Lld => 2,
            LinkerFamily::System => 3,
        });
        enc.str(&self.version_line)
            .str(self.binary_digest.domain)
            .bytes(&self.binary_digest.bytes);
        compute(DOMAIN_LINKER_PROFILE, &enc.finish())
    }
}

/// Classify a linker's `--version` output line into its family.
/// Unknown output classifies `System` (the least-assuming profile).
#[must_use]
pub fn detect_family(version_line: &str) -> LinkerFamily {
    let lower = version_line.to_lowercase();
    if lower.contains("wild") {
        LinkerFamily::Wild
    } else if lower.contains("lld") {
        LinkerFamily::Lld
    } else {
        LinkerFamily::System
    }
}

/// Build the profile from probe results.
#[must_use]
pub fn detect_profile(version_line: &str, binary_digest: TypedDigest) -> LinkerProfile {
    LinkerProfile {
        family: detect_family(version_line),
        version_line: version_line.to_owned(),
        binary_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.tool-binary.v1",
            bytes: [tag; 32],
        }
    }

    #[test]
    fn detection_fixtures_per_linker() {
        // THE acceptance: one fixture per family's real version-line
        // shape.
        assert_eq!(detect_family("Wild version 0.3.0"), LinkerFamily::Wild);
        assert_eq!(
            detect_family("LLD 17.0.6 (compatible with GNU linkers)"),
            LinkerFamily::Lld
        );
        assert_eq!(detect_family("Ubuntu ld.lld 17.0.6"), LinkerFamily::Lld);
        assert_eq!(
            detect_family("GNU ld (GNU Binutils for Ubuntu) 2.42"),
            LinkerFamily::System
        );
        assert_eq!(
            detect_family("@(#)PROGRAM:ld PROJECT:ld64-951.9"),
            LinkerFamily::System,
            "unknown/apple output classifies as the least-assuming profile"
        );
    }

    #[test]
    fn profile_identity_is_the_triple_not_the_family_label() {
        // Two lld BUILDS are two profiles: identical family + version
        // line but different binary digests fork the identity.
        let a = detect_profile("LLD 17.0.6", d(1)).profile_identity();
        let b = detect_profile("LLD 17.0.6", d(2)).profile_identity();
        assert_ne!(a, b, "binary digest participates");
        // Version line participates.
        let c = detect_profile("LLD 18.1.0", d(1)).profile_identity();
        assert_ne!(a, c);
        // Family participates (a hypothetical collision of version
        // lines across families cannot alias).
        let wild = detect_profile("Wild version 0.3.0", d(1)).profile_identity();
        let system = LinkerProfile {
            family: LinkerFamily::System,
            version_line: "Wild version 0.3.0".into(), // adversarial line
            binary_digest: d(1),
        }
        .profile_identity();
        assert_ne!(wild, system);
    }

    #[test]
    fn preference_order_is_wild_lld_system() {
        assert_eq!(
            LinkerFamily::PREFERENCE,
            [LinkerFamily::Wild, LinkerFamily::Lld, LinkerFamily::System]
        );
    }
}
