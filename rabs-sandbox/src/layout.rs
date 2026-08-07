//! Canonical visible path layout + hidden backing-path policy (bead
//! D002; invariants I1/I20; plan §55; risk R42).
//!
//! Two path worlds, never mixed:
//!
//! - the **visible** layout is what every action sees, byte-identical
//!   on every host: fixed roots under `/__rabs/…` plus the secret-slot
//!   mount under `/run/rabs-secrets/…`;
//! - the **hidden physical backing** directories MAY carry operation/
//!   action/attempt/snapshot IDs and random staging names — the mount
//!   namespace/chroot/VM hides them — but they must NEVER surface in
//!   any program-visible channel: `CARGO_MANIFEST_DIR`, `OUT_DIR`,
//!   `TMPDIR`, compiler args, generated source, dep-info, debuginfo,
//!   or any path a program can read back (R42: one leak poisons
//!   portable authority for everything it touched).
//!
//! This module is the layout SPEC as constants plus the leak-check
//! primitive; the D012 scanner enforces the policy over real surfaces.

/// The primary workspace (D001).
pub const WORKSPACE: &str = "/__rabs/workspace";
/// Additional path-dependency repositories (D001 logical IDs).
pub const REPOS: &str = "/__rabs/repos";
/// Checksummed registry unpacks (`/__rabs/registry/<checksum>`).
pub const REGISTRY: &str = "/__rabs/registry";
/// Pinned git checkouts (`/__rabs/git/<checksum>`).
pub const GIT: &str = "/__rabs/git";
/// Mounted toolchain root.
pub const TOOLCHAIN: &str = "/__rabs/toolchain";
/// Stable cargo home.
pub const CARGO_HOME: &str = "/__rabs/cargo-home";
/// Per-unit primary output dir (`/__rabs/out/<unit>`).
pub const OUT: &str = "/__rabs/out";
/// Per-unit build-script out dir (`/__rabs/build/<unit>/out`).
pub const BUILD: &str = "/__rabs/build";
/// Per-unit incremental dir.
pub const INCREMENTAL: &str = "/__rabs/incremental";
/// Temp dir presented as TMPDIR.
pub const TMP: &str = "/__rabs/tmp";
/// Stable HOME.
pub const HOME: &str = "/__rabs/home";
/// Secret-slot mount root (`/run/rabs-secrets/<slot>`).
pub const SECRETS: &str = "/run/rabs-secrets";

/// Every visible root, for exhaustive policy checks.
pub const VISIBLE_ROOTS: [&str; 12] = [
    WORKSPACE,
    REPOS,
    REGISTRY,
    GIT,
    TOOLCHAIN,
    CARGO_HOME,
    OUT,
    BUILD,
    INCREMENTAL,
    TMP,
    HOME,
    SECRETS,
];

/// Program-visible surfaces where a hidden backing path must never
/// appear (the R42 enforcement surface list; D012 scans them all).
pub const PROGRAM_VISIBLE_SURFACES: [&str; 8] = [
    "CARGO_MANIFEST_DIR",
    "OUT_DIR",
    "TMPDIR",
    "compiler-args",
    "generated-source",
    "dep-info",
    "debuginfo",
    "readback-paths",
];

/// Whether `value` (a program-visible string) leaks any of the hidden
/// physical backing roots. Pure primitive for the D012 scanner: a
/// backing root's PREFIX appearing anywhere in a visible value is a
/// leak — substring match, because paths embed in flags, JSON, and
/// debuginfo alike.
#[must_use]
pub fn leaks_backing_path(value: &[u8], hidden_backing_roots: &[&str]) -> bool {
    hidden_backing_roots.iter().any(|root| {
        !root.is_empty()
            && value
                .windows(root.len())
                .any(|window| window == root.as_bytes())
    })
}

/// Whether a path string is inside the visible layout.
#[must_use]
pub fn is_visible_path(path: &str) -> bool {
    VISIBLE_ROOTS
        .iter()
        .any(|root| path == *root || path.starts_with(&format!("{root}/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_layout_matches_the_spec_verbatim() {
        // The bead's enumeration, pinned: /__rabs/{workspace, repos,
        // registry, git, toolchain, cargo-home, out, build,
        // incremental, tmp, home} + /run/rabs-secrets.
        assert_eq!(
            VISIBLE_ROOTS,
            [
                "/__rabs/workspace",
                "/__rabs/repos",
                "/__rabs/registry",
                "/__rabs/git",
                "/__rabs/toolchain",
                "/__rabs/cargo-home",
                "/__rabs/out",
                "/__rabs/build",
                "/__rabs/incremental",
                "/__rabs/tmp",
                "/__rabs/home",
                "/run/rabs-secrets",
            ]
        );
        for root in VISIBLE_ROOTS {
            assert!(
                root.starts_with("/__rabs/") || root.starts_with("/run/rabs-secrets"),
                "{root}: visible roots live in exactly two namespaces"
            );
        }
    }

    #[test]
    fn hidden_backing_paths_are_caught_in_any_embedding() {
        // A physical staging root with attempt IDs, embedded the ways
        // R42 fears: env value, compiler flag, JSON, debuginfo-ish.
        let backing = ["/var/rabs/staging/attempt-8f2c1a", "/tmp/rabs-op-1234"];
        for visible in [
            b"/var/rabs/staging/attempt-8f2c1a/out".as_slice(),
            b"--remap-path-prefix=/var/rabs/staging/attempt-8f2c1a=/__rabs/workspace".as_slice(),
            br#"{"out_dir":"/tmp/rabs-op-1234/build/serde/out"}"#.as_slice(),
        ] {
            assert!(
                leaks_backing_path(visible, &backing),
                "must catch: {}",
                String::from_utf8_lossy(visible)
            );
        }
        // Clean canonical values pass.
        assert!(!leaks_backing_path(b"/__rabs/build/serde-1/out", &backing));
    }

    #[test]
    fn program_visible_surface_list_covers_the_bead_enumeration() {
        for surface in [
            "CARGO_MANIFEST_DIR",
            "OUT_DIR",
            "TMPDIR",
            "compiler-args",
            "generated-source",
            "dep-info",
            "debuginfo",
        ] {
            assert!(
                PROGRAM_VISIBLE_SURFACES.contains(&surface),
                "{surface} missing from the enforcement surface list"
            );
        }
    }

    #[test]
    fn visibility_check_is_prefix_correct() {
        assert!(is_visible_path("/__rabs/workspace/src/lib.rs"));
        assert!(is_visible_path("/run/rabs-secrets/slot-1"));
        assert!(!is_visible_path("/__rabs-evil/workspace"));
        assert!(!is_visible_path("/__rabs/workspacex"), "prefix, not glob");
        assert!(!is_visible_path("/var/rabs/staging/x"));
    }
}
