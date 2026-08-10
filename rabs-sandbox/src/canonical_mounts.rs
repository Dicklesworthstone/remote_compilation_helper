//! Canonical toolchain / sysroot / registry / git / output / temp mounts
//! (bead D005; invariants I1/I20; plan §55).
//!
//! D003 gave the canonical namespace and a spec you hand raw [`Bind`]s. This
//! module is the TYPED mount plan a scheduler assembles: named roots —
//! toolchain, registry unpacks by checksum, git checkouts by checksum,
//! path-dependency repos by logical id, output/incremental/build units,
//! cargo-home, home, workspace — each landing at its stable visible
//! [`layout`] path, compiled with [`CanonicalMountPlan::to_spec`] into the
//! exact [`CanonicalNamespaceSpec`] D003 executes.
//!
//! ## Two identity rules this module enforces (why it exists)
//!
//! 1. **Toolchains mount at a STABLE path, never a digest-bearing one.** The
//!    toolchain is an immutable ATP DatasetObject, but its *visible* path is
//!    fixed `/__rabs/toolchain` — a digest in the path would fragment cache
//!    keys and leak build identity into `rustc -vV` / `--print sysroot` /
//!    every embedded `--sysroot` flag. rustc computes its sysroot relative
//!    to its own binary, so binding the toolchain at the fixed path makes
//!    `rustc --print sysroot` report `/__rabs/toolchain` verbatim.
//! 2. **Immutable content sources DO carry their checksum in the path** —
//!    `/__rabs/registry/<checksum>`, `/__rabs/git/<checksum>` — because that
//!    IS their identity and Cargo addresses them that way. Checksums are
//!    validated as safe path components before they touch the argv.
//!
//! The plan also emits the canonical environment (`CARGO_HOME`, `PATH` into
//! the toolchain bin, `TMPDIR`, `HOME`, `RUSTUP_HOME` pointed at nothing so
//! no host rustup is consulted) so the presented env and the mounts agree by
//! construction.

use crate::canonical_namespace::{Bind, CanonicalNamespaceSpec};
use crate::layout;
use std::path::PathBuf;

/// A checksum-addressed immutable content mount (registry unpack or git
/// checkout). The checksum is the visible-path leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumMount {
    /// Content checksum — the visible leaf under `/__rabs/registry` or
    /// `/__rabs/git`. Validated as a safe path component.
    pub checksum: String,
    /// Hidden physical backing directory holding the unpacked content.
    pub backing: PathBuf,
}

impl ChecksumMount {
    /// Convenience constructor.
    pub fn new(checksum: impl Into<String>, backing: impl Into<PathBuf>) -> Self {
        Self {
            checksum: checksum.into(),
            backing: backing.into(),
        }
    }
}

/// A path-dependency repository mounted by its stable LOGICAL id (D001) —
/// never its mutable git URL / checkout path / branch / commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoMount {
    /// Stable logical repo id (the visible leaf under `/__rabs/repos`).
    pub logical_id: String,
    /// Hidden physical backing directory.
    pub backing: PathBuf,
    /// Whether the repo is writable (a workspace-member path dep under
    /// active edit) or read-only (a pinned closure dependency).
    pub writable: bool,
}

/// A named per-unit output mount (`out`, `build/<unit>/out`, or
/// `incremental`). Writable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitMount {
    /// The unit id (visible leaf).
    pub unit: String,
    /// Hidden physical backing directory.
    pub backing: PathBuf,
}

/// Typed refusal from plan validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPlanError {
    /// A checksum / logical id / unit token is not a safe path component.
    UnsafeToken {
        /// Which field carried the bad token.
        field: &'static str,
        /// The offending value.
        value: String,
    },
    /// The required toolchain backing is missing.
    MissingToolchain,
}

impl std::fmt::Display for MountPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeToken { field, value } => {
                write!(f, "unsafe path token in {field}: {value:?}")
            }
            Self::MissingToolchain => write!(f, "canonical mount plan requires a toolchain root"),
        }
    }
}

impl std::error::Error for MountPlanError {}

/// A complete typed canonical mount plan for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalMountPlan {
    /// Immutable toolchain root → `/__rabs/toolchain` (stable, non-digest).
    pub toolchain_backing: PathBuf,
    /// Writable primary workspace → `/__rabs/workspace`.
    pub workspace_backing: PathBuf,
    /// cargo-home → `/__rabs/cargo-home` (writable: caches/locks live here).
    pub cargo_home_backing: PathBuf,
    /// HOME → `/__rabs/home` (writable).
    pub home_backing: PathBuf,
    /// Registry unpacks → `/__rabs/registry/<checksum>` (read-only).
    pub registry: Vec<ChecksumMount>,
    /// Git checkouts → `/__rabs/git/<checksum>` (read-only).
    pub git: Vec<ChecksumMount>,
    /// Path-dependency repos → `/__rabs/repos/<logical_id>`.
    pub repos: Vec<RepoMount>,
    /// Primary output units → `/__rabs/out/<unit>` (writable).
    pub out_units: Vec<UnitMount>,
    /// Incremental units → `/__rabs/incremental/<unit>` (writable).
    pub incremental_units: Vec<UnitMount>,
    /// Extra explicitly-declared env pairs (merged over the canonical base;
    /// the plan's own keys win to keep mounts and env consistent).
    pub extra_env: Vec<(String, String)>,
    /// Network default-deny unless a fetch lane explicitly opts in.
    pub allow_network: bool,
}

impl CanonicalMountPlan {
    /// A minimal plan: toolchain + workspace + cargo-home + home, everything
    /// else empty. Callers add registry/git/repos/units.
    pub fn new(
        toolchain_backing: impl Into<PathBuf>,
        workspace_backing: impl Into<PathBuf>,
        cargo_home_backing: impl Into<PathBuf>,
        home_backing: impl Into<PathBuf>,
    ) -> Self {
        Self {
            toolchain_backing: toolchain_backing.into(),
            workspace_backing: workspace_backing.into(),
            cargo_home_backing: cargo_home_backing.into(),
            home_backing: home_backing.into(),
            registry: Vec::new(),
            git: Vec::new(),
            repos: Vec::new(),
            out_units: Vec::new(),
            incremental_units: Vec::new(),
            extra_env: Vec::new(),
            allow_network: false,
        }
    }

    /// The canonical environment the plan implies, before `extra_env` is
    /// layered on. Deterministic and name-sorted downstream in the argv.
    fn canonical_env(&self) -> Vec<(String, String)> {
        vec![
            (
                "PATH".to_string(),
                format!("{}/bin:/usr/bin:/bin", layout::TOOLCHAIN),
            ),
            ("HOME".to_string(), layout::HOME.to_string()),
            ("TMPDIR".to_string(), layout::TMP.to_string()),
            ("CARGO_HOME".to_string(), layout::CARGO_HOME.to_string()),
            // Point rustup at nothing: the toolchain is mounted directly, so
            // no host rustup proxy must ever intercept and re-resolve it.
            ("RUSTUP_HOME".to_string(), "/nonexistent-rustup".to_string()),
            (
                "RUSTUP_TOOLCHAIN".to_string(),
                "/nonexistent-rustup".to_string(),
            ),
        ]
    }

    /// Compile the plan into the [`CanonicalNamespaceSpec`] D003 executes.
    /// Validates every checksum / logical id / unit token as a safe path
    /// component first — an unsafe token is a typed refusal, never an argv
    /// that could escape its intended visible path.
    pub fn to_spec(&self) -> Result<CanonicalNamespaceSpec, MountPlanError> {
        if self.toolchain_backing.as_os_str().is_empty() {
            return Err(MountPlanError::MissingToolchain);
        }

        let mut ro: Vec<Bind> = Vec::new();
        let mut rw: Vec<Bind> = Vec::new();

        // Toolchain: STABLE path, read-only immutable dataset.
        ro.push(Bind::new(&self.toolchain_backing, layout::TOOLCHAIN));

        // Writable core surfaces.
        rw.push(Bind::new(&self.workspace_backing, layout::WORKSPACE));
        rw.push(Bind::new(&self.cargo_home_backing, layout::CARGO_HOME));
        rw.push(Bind::new(&self.home_backing, layout::HOME));

        // Checksum-addressed immutable content: the checksum IS the leaf.
        for entry in &self.registry {
            validate_token("registry.checksum", &entry.checksum)?;
            ro.push(Bind::new(
                &entry.backing,
                format!("{}/{}", layout::REGISTRY, entry.checksum),
            ));
        }
        for entry in &self.git {
            validate_token("git.checksum", &entry.checksum)?;
            ro.push(Bind::new(
                &entry.backing,
                format!("{}/{}", layout::GIT, entry.checksum),
            ));
        }

        // Path-dependency repos by logical id.
        for repo in &self.repos {
            validate_token("repos.logical_id", &repo.logical_id)?;
            let visible = format!("{}/{}", layout::REPOS, repo.logical_id);
            if repo.writable {
                rw.push(Bind::new(&repo.backing, visible));
            } else {
                ro.push(Bind::new(&repo.backing, visible));
            }
        }

        // Per-unit output / incremental (writable).
        for unit in &self.out_units {
            validate_token("out_units.unit", &unit.unit)?;
            rw.push(Bind::new(
                &unit.backing,
                format!("{}/{}", layout::OUT, unit.unit),
            ));
        }
        for unit in &self.incremental_units {
            validate_token("incremental_units.unit", &unit.unit)?;
            rw.push(Bind::new(
                &unit.backing,
                format!("{}/{}", layout::INCREMENTAL, unit.unit),
            ));
        }

        // Env: canonical base, then explicit extras (extras never override a
        // canonical key — mounts and env must stay consistent).
        let mut env = self.canonical_env();
        let canonical_keys: std::collections::BTreeSet<&str> =
            env.iter().map(|(k, _)| k.as_str()).collect();
        for (k, v) in &self.extra_env {
            if !canonical_keys.contains(k.as_str()) {
                env.push((k.clone(), v.clone()));
            }
        }

        let mut spec = CanonicalNamespaceSpec::new();
        spec.ro_binds = ro;
        spec.rw_binds = rw;
        spec.env = env;
        spec.allow_network = self.allow_network;
        Ok(spec)
    }
}

/// Whether `token` is a safe single visible-path component: non-empty, not
/// `.`/`..`, no `/` or NUL, only `[A-Za-z0-9._-]`, bounded length. Same
/// character class the reap-path guard uses — inputs embed into a generated
/// argv, so anything that could traverse or inject is refused.
fn validate_token(field: &'static str, token: &str) -> Result<(), MountPlanError> {
    let ok = !token.is_empty()
        && token != "."
        && token != ".."
        && token.len() <= 255
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(MountPlanError::UnsafeToken {
            field,
            value: token.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_plan() -> CanonicalMountPlan {
        CanonicalMountPlan::new(
            "/backing/toolchains/nightly-2026",
            "/backing/attempt-9/ws",
            "/backing/attempt-9/cargo-home",
            "/backing/attempt-9/home",
        )
    }

    fn visible_of(binds: &[Bind], needle: &str) -> Vec<String> {
        binds
            .iter()
            .filter(|b| b.visible.to_string_lossy().contains(needle))
            .map(|b| b.visible.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn toolchain_mounts_at_stable_non_digest_path_read_only() {
        let spec = base_plan().to_spec().unwrap();
        let tc: Vec<_> = spec
            .ro_binds
            .iter()
            .filter(|b| b.visible == PathBuf::from(layout::TOOLCHAIN))
            .collect();
        assert_eq!(tc.len(), 1, "toolchain is a single read-only bind");
        assert_eq!(tc[0].backing, PathBuf::from("/backing/toolchains/nightly-2026"));
        // The visible path carries NO digest.
        assert_eq!(tc[0].visible.to_string_lossy(), "/__rabs/toolchain");
    }

    #[test]
    fn checksum_sources_carry_their_checksum_in_the_visible_path() {
        let mut plan = base_plan();
        plan.registry
            .push(ChecksumMount::new("abc123def", "/backing/reg/serde-1.0"));
        plan.git
            .push(ChecksumMount::new("deadbeef00", "/backing/git/foo"));
        let spec = plan.to_spec().unwrap();
        assert_eq!(
            visible_of(&spec.ro_binds, "/registry/"),
            vec!["/__rabs/registry/abc123def".to_string()]
        );
        assert_eq!(
            visible_of(&spec.ro_binds, "/git/"),
            vec!["/__rabs/git/deadbeef00".to_string()]
        );
    }

    #[test]
    fn canonical_env_points_rustc_and_cargo_at_canonical_paths() {
        let spec = base_plan().to_spec().unwrap();
        let env: std::collections::BTreeMap<_, _> = spec.env.into_iter().collect();
        assert_eq!(env["CARGO_HOME"], "/__rabs/cargo-home");
        assert_eq!(env["HOME"], "/__rabs/home");
        assert_eq!(env["TMPDIR"], "/__rabs/tmp");
        assert!(env["PATH"].starts_with("/__rabs/toolchain/bin"));
        assert_eq!(env["RUSTUP_HOME"], "/nonexistent-rustup");
    }

    #[test]
    fn extra_env_cannot_override_canonical_keys() {
        let mut plan = base_plan();
        plan.extra_env
            .push(("CARGO_HOME".into(), "/evil".into()));
        plan.extra_env
            .push(("RUST_LOG".into(), "debug".into()));
        let spec = plan.to_spec().unwrap();
        let env: std::collections::BTreeMap<_, _> = spec.env.into_iter().collect();
        assert_eq!(env["CARGO_HOME"], "/__rabs/cargo-home", "canonical key wins");
        assert_eq!(env["RUST_LOG"], "debug", "non-canonical extra passes through");
    }

    #[test]
    fn writable_repo_is_rw_and_pinned_repo_is_ro() {
        let mut plan = base_plan();
        plan.repos.push(RepoMount {
            logical_id: "member-a".into(),
            backing: "/backing/repos/a".into(),
            writable: true,
        });
        plan.repos.push(RepoMount {
            logical_id: "dep-b".into(),
            backing: "/backing/repos/b".into(),
            writable: false,
        });
        let spec = plan.to_spec().unwrap();
        assert!(
            spec.rw_binds
                .iter()
                .any(|b| b.visible == PathBuf::from("/__rabs/repos/member-a"))
        );
        assert!(
            spec.ro_binds
                .iter()
                .any(|b| b.visible == PathBuf::from("/__rabs/repos/dep-b"))
        );
    }

    #[test]
    fn output_and_incremental_units_are_writable_under_their_roots() {
        let mut plan = base_plan();
        plan.out_units
            .push(UnitMount { unit: "u1".into(), backing: "/b/out1".into() });
        plan.incremental_units
            .push(UnitMount { unit: "u1".into(), backing: "/b/inc1".into() });
        let spec = plan.to_spec().unwrap();
        assert!(
            spec.rw_binds
                .iter()
                .any(|b| b.visible == PathBuf::from("/__rabs/out/u1"))
        );
        assert!(
            spec.rw_binds
                .iter()
                .any(|b| b.visible == PathBuf::from("/__rabs/incremental/u1"))
        );
    }

    #[test]
    fn unsafe_checksum_token_is_refused() {
        let mut plan = base_plan();
        plan.registry
            .push(ChecksumMount::new("../../etc", "/backing/x"));
        let err = plan.to_spec().unwrap_err();
        assert!(matches!(
            err,
            MountPlanError::UnsafeToken {
                field: "registry.checksum",
                ..
            }
        ));
    }

    #[test]
    fn traversal_and_slash_tokens_are_refused() {
        for bad in ["..", ".", "a/b", "a\0b", ""] {
            let mut plan = base_plan();
            plan.git.push(ChecksumMount::new(bad, "/backing/x"));
            assert!(plan.to_spec().is_err(), "token {bad:?} must be refused");
        }
    }

    #[test]
    fn plan_compiles_through_d003_builder_to_a_strict_argv() {
        use crate::canonical_namespace::{HostIsolationSupport, build_canonical_argv};
        let support = HostIsolationSupport {
            bubblewrap: Some("bubblewrap 0.11.1".into()),
            unprivileged_userns: true,
            overlayfs: true,
            cgroup_v2: true,
            landlock: true,
        };
        let spec = base_plan().to_spec().unwrap();
        let launch =
            build_canonical_argv(&spec, &support, "cargo", &["build".into()]).unwrap();
        assert!(launch.boundary.satisfies_strict_hermetic_linux());
    }
}
