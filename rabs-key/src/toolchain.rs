//! `ToolchainContract` and the toolchain dataset digest (bead F007; plan
//! §63; risks R4/R43).
//!
//! Toolchain identity for the action key is CONTENT identity, never a
//! version string: two nightlies with equal `rustc --version` output but
//! different commits (or locally patched compilers with identical
//! versions) must produce different keys. The contract therefore keys on:
//!
//! - the compiler **binary digest** AND the `-vV` commit identity (both:
//!   the binary digest catches patched/relinked compilers the commit
//!   hash misses; the commit identity survives equal-bytes distribution
//!   differences in reverse);
//! - LLVM/backend identity, the sysroot object-tree root digest, target
//!   specification digest, unstable-feature profile;
//! - Cargo identity — participating ONLY for canonical-Cargo /
//!   whole-command action classes (per-crate rustc actions must not
//!   fragment on a Cargo point release that cannot touch rustc output);
//! - rustdoc/clippy component identity where the action class uses them
//!   (same conditional logic);
//! - linker and native-tool identities, allocator/runtime libraries
//!   where output-sensitive;
//! - the **RABS semantic-adapter epoch** — the version of RABS's
//!   *interpretation* of toolchain semantics, deliberately NOT the RABS
//!   binary version (a RABS bugfix release that does not change
//!   normalization semantics must not cold-start every cache in the
//!   fleet; a semantics change must — the epoch is the honest lever).

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the toolchain dataset.
pub const DOMAIN_TOOLCHAIN_CONTRACT: &str = "rabs.toolchain-contract.v1";

/// One named tool identity (linker, ar, native cc, …): content digest
/// plus the identity string the probe reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolIdentity {
    /// Role name (`"linker"`, `"ar"`, `"cc"`, …) — part of the bytes so
    /// swapping two tools' digests cannot alias.
    pub role: String,
    /// Content digest of the tool binary.
    pub binary_digest: TypedDigest,
    /// Probed identity/version line (canonical bytes, not for display).
    pub identity_line: String,
}

/// The full toolchain contract for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainContract {
    /// Content digest of the rustc binary actually resolved.
    pub compiler_binary_digest: TypedDigest,
    /// `rustc -vV` commit-hash line (empty string if the channel omits
    /// it — the binary digest still anchors identity).
    pub commit_identity: String,
    /// LLVM/backend identity line from `-vV`.
    pub backend_identity: String,
    /// Root digest of the sysroot object tree (F004-mapped paths).
    pub sysroot_root_digest: TypedDigest,
    /// Target specification digest (built-in triple spec or custom
    /// target JSON content).
    pub target_spec_digest: TypedDigest,
    /// Sorted unstable-feature profile (`-Z` gates active fleet-wide
    /// policy, `RUSTC_BOOTSTRAP` posture, …).
    pub unstable_feature_profile: Vec<String>,
    /// Cargo identity — REQUIRED for canonical-Cargo/whole-command
    /// classes, `None` for per-crate rustc actions (which must not
    /// fragment on Cargo releases).
    pub cargo_identity: Option<ToolIdentity>,
    /// rustdoc/clippy component identity when the class uses one.
    pub component_identity: Option<ToolIdentity>,
    /// Linker + native tool identities in role order.
    pub native_tools: Vec<ToolIdentity>,
    /// Allocator/runtime library digests where output-sensitive.
    pub runtime_libraries: Vec<TypedDigest>,
    /// The RABS semantic-adapter epoch (NOT the RABS binary version).
    pub semantic_adapter_epoch: u32,
}

fn encode_tool(enc: &mut CanonicalEncoder, t: &ToolIdentity) {
    enc.str(&t.role)
        .str(t.binary_digest.domain)
        .bytes(&t.binary_digest.bytes)
        .str(&t.identity_line);
}

impl ToolchainContract {
    /// Canonical bytes of the contract.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut enc = CanonicalEncoder::new();
        enc.str(self.compiler_binary_digest.domain)
            .bytes(&self.compiler_binary_digest.bytes)
            .str(&self.commit_identity)
            .str(&self.backend_identity)
            .str(self.sysroot_root_digest.domain)
            .bytes(&self.sysroot_root_digest.bytes)
            .str(self.target_spec_digest.domain)
            .bytes(&self.target_spec_digest.bytes);
        // Unstable profile is a SET: sorted so probe order cannot fork keys.
        let mut profile = self.unstable_feature_profile.clone();
        profile.sort_unstable();
        enc.u64(profile.len() as u64);
        for p in &profile {
            enc.str(p);
        }
        match &self.cargo_identity {
            None => {
                enc.u64(0);
            }
            Some(t) => {
                enc.u64(1);
                encode_tool(&mut enc, t);
            }
        }
        match &self.component_identity {
            None => {
                enc.u64(0);
            }
            Some(t) => {
                enc.u64(1);
                encode_tool(&mut enc, t);
            }
        }
        // Native tools preserve role order (link order can matter).
        enc.u64(self.native_tools.len() as u64);
        for t in &self.native_tools {
            encode_tool(&mut enc, t);
        }
        enc.u64(self.runtime_libraries.len() as u64);
        for d in &self.runtime_libraries {
            enc.str(d.domain).bytes(&d.bytes);
        }
        enc.u32(self.semantic_adapter_epoch);
        enc.finish()
    }

    /// The toolchain dataset digest — the descriptor's `toolchain` slot.
    #[must_use]
    pub fn dataset_digest(&self) -> TypedDigest {
        compute(DOMAIN_TOOLCHAIN_CONTRACT, &self.canonical_bytes())
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

    fn contract() -> ToolchainContract {
        ToolchainContract {
            compiler_binary_digest: d("rabs.tool-binary.v1", 1),
            commit_identity: "commit-hash: 9b00956e56009bab2aa15d7bff10916599e3d6d6".into(),
            backend_identity: "LLVM version: 17.0.6".into(),
            sysroot_root_digest: d("rabs.sysroot.v1", 2),
            target_spec_digest: d("rabs.target-spec.v1", 3),
            unstable_feature_profile: vec!["share-generics=off".into()],
            cargo_identity: None,
            component_identity: None,
            native_tools: vec![ToolIdentity {
                role: "linker".into(),
                binary_digest: d("rabs.tool-binary.v1", 4),
                identity_line: "mold 2.4.0".into(),
            }],
            runtime_libraries: vec![],
            semantic_adapter_epoch: 1,
        }
    }

    #[test]
    fn same_version_different_commit_changes_keys() {
        // The F007 acceptance case: two toolchains that REPORT the same
        // version but were built from different commits (vendor rebuild,
        // local patch) must not share a dataset digest — via either the
        // commit line or the binary digest.
        let a = contract();
        let mut commit_differs = contract();
        commit_differs.commit_identity =
            "commit-hash: 0000000000000000000000000000000000000000".into();
        assert_ne!(a.dataset_digest(), commit_differs.dataset_digest());
        // Identical -vV output, patched binary bytes: still distinct.
        let mut binary_differs = contract();
        binary_differs.compiler_binary_digest = d("rabs.tool-binary.v1", 99);
        assert_ne!(a.dataset_digest(), binary_differs.dataset_digest());
    }

    #[test]
    fn adapter_epoch_bump_invalidates_as_designed() {
        let a = contract();
        let mut bumped = contract();
        bumped.semantic_adapter_epoch = 2;
        assert_ne!(
            a.dataset_digest(),
            bumped.dataset_digest(),
            "the semantic-adapter epoch is the deliberate invalidation lever"
        );
    }

    #[test]
    fn cargo_identity_participates_only_when_present() {
        // Per-crate rustc contracts carry None: a Cargo point release
        // (different cargo binary) leaves their digest untouched because
        // the field simply is not there. Whole-command contracts carry
        // Some and DO move.
        let per_crate = contract();
        assert_eq!(per_crate.dataset_digest(), contract().dataset_digest());
        let mut whole_cmd = contract();
        whole_cmd.cargo_identity = Some(ToolIdentity {
            role: "cargo".into(),
            binary_digest: d("rabs.tool-binary.v1", 10),
            identity_line: "cargo 1.85.0".into(),
        });
        let mut whole_cmd2 = whole_cmd.clone();
        whole_cmd2.cargo_identity.as_mut().unwrap().binary_digest = d("rabs.tool-binary.v1", 11);
        assert_ne!(per_crate.dataset_digest(), whole_cmd.dataset_digest());
        assert_ne!(whole_cmd.dataset_digest(), whole_cmd2.dataset_digest());
    }

    #[test]
    fn unstable_profile_is_order_insensitive_but_content_sensitive() {
        let mut a = contract();
        a.unstable_feature_profile = vec!["b-gate".into(), "a-gate".into()];
        let mut b = contract();
        b.unstable_feature_profile = vec!["a-gate".into(), "b-gate".into()];
        assert_eq!(a.dataset_digest(), b.dataset_digest(), "probe order");
        let mut c = contract();
        c.unstable_feature_profile = vec!["a-gate".into()];
        assert_ne!(a.dataset_digest(), c.dataset_digest());
    }

    #[test]
    fn every_field_participates_in_the_digest() {
        // Mutation sweep: each remaining field moves the digest.
        let base = contract().dataset_digest();
        let mut m = contract();
        m.backend_identity = "LLVM version: 18.1.0".into();
        assert_ne!(base, m.dataset_digest());
        let mut m = contract();
        m.sysroot_root_digest = d("rabs.sysroot.v1", 9);
        assert_ne!(base, m.dataset_digest());
        let mut m = contract();
        m.target_spec_digest = d("rabs.target-spec.v1", 9);
        assert_ne!(base, m.dataset_digest());
        let mut m = contract();
        m.native_tools[0].identity_line = "mold 2.5.0".into();
        assert_ne!(base, m.dataset_digest());
        let mut m = contract();
        m.native_tools[0].role = "ar".into();
        assert_ne!(base, m.dataset_digest(), "role participates (no aliasing)");
        let mut m = contract();
        m.runtime_libraries = vec![d("rabs.runtime-lib.v1", 5)];
        assert_ne!(base, m.dataset_digest());
        let mut m = contract();
        m.component_identity = Some(ToolIdentity {
            role: "clippy-driver".into(),
            binary_digest: d("rabs.tool-binary.v1", 6),
            identity_line: "clippy 0.1.85".into(),
        });
        assert_ne!(base, m.dataset_digest());
    }
}
