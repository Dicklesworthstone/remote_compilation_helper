//! Materialization modes: writable CAS hardlinks prohibited (bead
//! D023; invariant I33; risk R65).
//!
//! A writable hardlink to an immutable CAS inode is the classic cache
//! corruption: the "copy" IS the original, and one `cargo` touching
//! its output rewrites the shared bytes for the whole fleet. The rule
//! is structural here:
//!
//! - [`MaterializationMode`] has NO writable-hardlink variant — the
//!   forbidden mode is unrepresentable, not discouraged;
//! - mutable destinations (target/OUT_DIR/temp/incremental) get
//!   [`MaterializationMode::PrivateCopy`] or a CoW reflink whose
//!   isolation was VERIFIED on this filesystem; an unverified reflink
//!   implementation falls back to copy;
//! - immutable views use read-only binds;
//! - mtime adjustments apply only to private materializations (the
//!   mode carries the permission).

/// How a CAS object may be materialized. There is deliberately no
/// writable-hardlink variant (I33).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationMode {
    /// Full private copy: mutation and mtime changes permitted.
    PrivateCopy,
    /// Copy-on-write reflink VERIFIED isolated on this filesystem:
    /// mutation permitted (the write is redirected), mtime permitted.
    VerifiedCowReflink,
    /// Read-only bind of the CAS bytes: no mutation, no mtime change.
    ReadOnlyBind,
}

impl MaterializationMode {
    /// Whether the materialized path may be mutated.
    #[must_use]
    pub const fn mutation_permitted(self) -> bool {
        matches!(self, Self::PrivateCopy | Self::VerifiedCowReflink)
    }

    /// Whether mtime adjustments are permitted (private forms only).
    #[must_use]
    pub const fn mtime_permitted(self) -> bool {
        self.mutation_permitted()
    }
}

/// Choose the materialization mode for a destination.
///
/// `reflink_isolation_verified` — whether THIS filesystem's reflink
/// was differentially proven to isolate content AND metadata; an
/// unsupported/unverified implementation falls back to copy.
#[must_use]
pub const fn decide_materialization(
    destination_mutable: bool,
    reflink_available: bool,
    reflink_isolation_verified: bool,
) -> MaterializationMode {
    if !destination_mutable {
        return MaterializationMode::ReadOnlyBind;
    }
    if reflink_available && reflink_isolation_verified {
        return MaterializationMode::VerifiedCowReflink;
    }
    // Unverified reflink or none: PRIVATE COPY, never a hardlink.
    MaterializationMode::PrivateCopy
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Simple content fingerprint for the corruption tests (FNV-1a —
    /// test-local; real CAS identity uses typed SHA-256 digests).
    fn fingerprint(path: &PathBuf) -> u64 {
        let bytes = fs::read(path).unwrap();
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("rabs-d023-tests")
            .join(format!("{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writable_hardlinks_are_unrepresentable_and_fallbacks_apply() {
        // Structural: exhaustive match — no hardlink variant exists.
        for mode in [
            MaterializationMode::PrivateCopy,
            MaterializationMode::VerifiedCowReflink,
            MaterializationMode::ReadOnlyBind,
        ] {
            match mode {
                MaterializationMode::PrivateCopy
                | MaterializationMode::VerifiedCowReflink
                | MaterializationMode::ReadOnlyBind => {}
            }
        }
        // Decision table: immutable -> read-only bind; mutable with
        // UNVERIFIED reflink -> private copy (the fallback rule);
        // verified reflink -> CoW.
        assert_eq!(
            decide_materialization(false, true, true),
            MaterializationMode::ReadOnlyBind
        );
        assert_eq!(
            decide_materialization(true, true, false),
            MaterializationMode::PrivateCopy,
            "unverified reflink implementations fall back to copy"
        );
        assert_eq!(
            decide_materialization(true, false, false),
            MaterializationMode::PrivateCopy
        );
        assert_eq!(
            decide_materialization(true, true, true),
            MaterializationMode::VerifiedCowReflink
        );
    }

    #[test]
    fn private_copy_mutation_never_changes_cas_bytes() {
        // THE acceptance: materialize via private copy, mutate the
        // materialization aggressively — the CAS object's fingerprint
        // is unchanged.
        let dir = scratch_dir("private-copy");
        let cas_object = dir.join("cas-object.rlib");
        fs::write(&cas_object, b"immutable cas bytes").unwrap();
        let before = fingerprint(&cas_object);

        let materialized = dir.join("target-out.rlib");
        fs::copy(&cas_object, &materialized).unwrap();
        // Mutate the materialization (what cargo/rustc might do).
        fs::write(&materialized, b"locally rewritten output").unwrap();

        assert_eq!(
            fingerprint(&cas_object),
            before,
            "CAS digest must never change after materialization mutation"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_forbidden_hardlink_mode_demonstrably_corrupts() {
        // The negative control: WHY the variant does not exist. A
        // writable hardlink aliases the inode — mutating through the
        // alias changes the CAS bytes. This test documents the hazard
        // the policy kills (and doubles as the inode-alias corruption
        // probe for filesystems under test).
        let dir = scratch_dir("hardlink-hazard");
        let cas_object = dir.join("cas-object.rlib");
        fs::write(&cas_object, b"immutable cas bytes").unwrap();
        let before = fingerprint(&cas_object);

        let alias = dir.join("aliased-out.rlib");
        fs::hard_link(&cas_object, &alias).unwrap();
        fs::write(&alias, b"corrupted through the alias").unwrap();

        assert_ne!(
            fingerprint(&cas_object),
            before,
            "the hazard is real: alias mutation rewrites CAS bytes — \
             which is exactly why no writable-hardlink mode exists"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
