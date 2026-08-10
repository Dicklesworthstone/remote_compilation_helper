//! Path-remap flag injection by toolchain capability (bead D007;
//! plan §27; invariants I1/I20).
//!
//! Remapping SUPPLEMENTS canonical execution — it is never a substitute,
//! because remap flags cannot fix Cargo-side unit identity or
//! runtime-visible paths (plan §27: "remapping is a supplement to
//! canonical execution rather than a substitute"). What it buys, on
//! toolchains that support it, is the `ProjectRelativeRemapped` semantic
//! lane: debuginfo (notably `DW_AT_comp_dir`, which embeds the compile
//! CWD) stops carrying even the *canonical* absolute workspace root and
//! instead carries stable project-relative form — the same thing a
//! developer's local `trim-paths` build would embed, so a runtime-visible
//! canonical string never becomes observable program semantics.
//!
//! ## Capability model
//!
//! Detection is a pure function over `rustc -vV` output so it can be
//! probed per mounted toolchain (inside the canonical namespace, against
//! `/__rabs/toolchain/bin/rustc`) and unit-tested without a toolchain:
//!
//! - `--remap-path-prefix` is stable rustc since 1.26 — supported on any
//!   toolchain whose reported release parses to ≥ 1.26.
//! - `trim-paths` (RFC 3127, `-Ztrim-paths`) is nightly-channel Cargo
//!   only — supported only when the release string carries a
//!   `-nightly`/`-dev` channel.
//!
//! An unparseable version report yields NO capabilities: remap is applied
//! only where support is affirmatively detected, never assumed.
//!
//! ## Safety invariants
//!
//! Remap sources must be canonical visible paths ([`layout`]) — a hidden
//! backing path appearing in a remap flag would itself be the R42 leak
//! this whole subsystem exists to prevent, so it is refused, not
//! remapped. Sources must not contain `=` (rustc splits the flag on its
//! first `=` after the prefix) and neither side may contain NUL.

use crate::canonical_mounts::CanonicalMountPlan;
use crate::layout;

/// `--remap-path-prefix` became stable in this rustc minor version.
const REMAP_PATH_PREFIX_STABLE_MINOR: u32 = 26;

/// What the probed toolchain supports, detected from `rustc -vV`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RemapCapability {
    /// `--remap-path-prefix=FROM=TO` is accepted by rustc.
    pub remap_path_prefix: bool,
    /// `-Ztrim-paths` / profile `trim-paths` is accepted by Cargo
    /// (nightly channel only).
    pub trim_paths: bool,
}

impl RemapCapability {
    /// Detect capabilities from the verbatim output of `rustc -vV`. Pure:
    /// callers run the probe (against the canonical toolchain path) and
    /// hand the text here. Anything unparseable detects as unsupported.
    #[must_use]
    pub fn detect(rustc_verbose_version: &str) -> Self {
        let Some(release) = rustc_verbose_version
            .lines()
            .find_map(|line| line.strip_prefix("release: "))
            .map(str::trim)
        else {
            return Self::default();
        };
        let version = release.split('-').next().unwrap_or_default();
        let mut parts = version.split('.');
        let (Some(major), Some(minor)) = (
            parts.next().and_then(|p| p.parse::<u32>().ok()),
            parts.next().and_then(|p| p.parse::<u32>().ok()),
        ) else {
            return Self::default();
        };
        let remap_path_prefix =
            major > 1 || (major == 1 && minor >= REMAP_PATH_PREFIX_STABLE_MINOR);
        let channel_is_nightly = release.contains("-nightly") || release.contains("-dev");
        Self {
            remap_path_prefix,
            trim_paths: remap_path_prefix && channel_is_nightly,
        }
    }
}

/// One remap source→target pair, compiled into
/// `--remap-path-prefix=<from>=<to>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemapEntry {
    /// Canonical visible path prefix to replace. MUST be a [`layout`]
    /// visible path (a backing path here would be the R42 leak).
    pub from: String,
    /// Stable replacement (project-relative form, e.g. `.`).
    pub to: String,
}

impl RemapEntry {
    /// Convenience constructor.
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }
}

/// Typed refusal from remap-flag construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemapError {
    /// A remap source is not a canonical visible path — remapping a
    /// hidden backing path is itself the leak (R42), so it is refused.
    NonCanonicalSource {
        /// The offending source path.
        from: String,
    },
    /// A remap side contains a character that cannot embed in the flag
    /// (`=` in the source, or NUL anywhere).
    UnsafeFlagToken {
        /// The offending value.
        value: String,
    },
}

impl std::fmt::Display for RemapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalSource { from } => write!(
                f,
                "remap source {from:?} is not a canonical visible path; \
                 remapping a hidden backing path is the leak, not the fix"
            ),
            Self::UnsafeFlagToken { value } => {
                write!(f, "remap value {value:?} cannot embed in a compiler flag")
            }
        }
    }
}

impl std::error::Error for RemapError {}

/// The default entry set for the `ProjectRelativeRemapped` lane: the
/// workspace root maps to `.`, so `DW_AT_comp_dir` and any other
/// debuginfo embedding of the compile dir becomes project-relative —
/// matching what a local `trim-paths` build embeds. Other canonical
/// roots are NOT remapped by default: they are already host-stable by
/// construction, and their checksum-bearing forms (registry/git) are
/// their Cargo identity.
#[must_use]
pub fn project_relative_entries() -> Vec<RemapEntry> {
    vec![RemapEntry::new(layout::WORKSPACE, ".")]
}

/// Compile entries into `--remap-path-prefix` rustc flags, applied ONLY
/// where the toolchain affirmatively supports them: an unsupported
/// toolchain yields an empty flag list (the canonical namespace still
/// provides full path stability — remap is supplement, not substitute).
/// Entry order is preserved; rustc applies the LAST matching mapping, so
/// callers order general→specific.
pub fn rustc_remap_flags(
    capability: RemapCapability,
    entries: &[RemapEntry],
) -> Result<Vec<String>, RemapError> {
    if !capability.remap_path_prefix {
        return Ok(Vec::new());
    }
    let mut flags = Vec::with_capacity(entries.len());
    for entry in entries {
        if !layout::is_visible_path(&entry.from) {
            return Err(RemapError::NonCanonicalSource {
                from: entry.from.clone(),
            });
        }
        if entry.from.contains('=') || entry.from.contains('\0') {
            return Err(RemapError::UnsafeFlagToken {
                value: entry.from.clone(),
            });
        }
        if entry.to.contains('\0') {
            return Err(RemapError::UnsafeFlagToken {
                value: entry.to.clone(),
            });
        }
        flags.push(format!("--remap-path-prefix={}={}", entry.from, entry.to));
    }
    Ok(flags)
}

/// Extra Cargo argv for the trim-paths lane, applied ONLY on toolchains
/// whose channel supports it (nightly). Profile-level `trim-paths`
/// configuration remains the caller's policy decision; this is the
/// unstable-feature gate flag itself.
#[must_use]
pub fn cargo_trim_paths_args(capability: RemapCapability) -> Vec<String> {
    if capability.trim_paths {
        vec!["-Ztrim-paths".to_string()]
    } else {
        Vec::new()
    }
}

/// Inject the remap flags into a [`CanonicalMountPlan`] by appending to
/// its `RUSTFLAGS` extra-env entry (merging with any flags already
/// declared there — Cargo reads RUSTFLAGS as one space-separated list).
/// Returns whether anything was injected: `false` means the toolchain
/// does not support remapping (or no entries were given) and the plan is
/// intentionally unchanged — canonical execution alone carries the
/// path-stability guarantee.
pub fn inject_remap_into_plan(
    plan: &mut CanonicalMountPlan,
    capability: RemapCapability,
    entries: &[RemapEntry],
) -> Result<bool, RemapError> {
    let flags = rustc_remap_flags(capability, entries)?;
    if flags.is_empty() {
        return Ok(false);
    }
    let addition = flags.join(" ");
    if let Some((_, existing)) = plan
        .extra_env
        .iter_mut()
        .find(|(name, _)| name == "RUSTFLAGS")
    {
        existing.push(' ');
        existing.push_str(&addition);
    } else {
        plan.extra_env.push(("RUSTFLAGS".to_string(), addition));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NIGHTLY_VV: &str = "rustc 1.99.0-nightly (09ee43b2d 2026-07-27)\n\
        binary: rustc\n\
        commit-hash: 09ee43b2d\n\
        release: 1.99.0-nightly\n\
        host: x86_64-unknown-linux-gnu\n\
        LLVM version: 21.0.0\n";

    const STABLE_VV: &str = "rustc 1.85.0 (4d91de4e4 2025-02-17)\nrelease: 1.85.0\n";

    #[test]
    fn nightly_detects_both_capabilities() {
        let cap = RemapCapability::detect(NIGHTLY_VV);
        assert!(cap.remap_path_prefix);
        assert!(cap.trim_paths, "trim-paths is available on nightly");
    }

    #[test]
    fn stable_detects_remap_but_not_trim_paths() {
        let cap = RemapCapability::detect(STABLE_VV);
        assert!(cap.remap_path_prefix);
        assert!(!cap.trim_paths, "trim-paths is nightly-only");
    }

    #[test]
    fn ancient_and_unparseable_toolchains_detect_nothing() {
        for vv in [
            "release: 1.25.0\n",      // pre-stabilization
            "release: garbage\n",     // unparseable version
            "no release line at all", // missing report
            "",                       // empty
            "release: -nightly\n",    // channel without version
        ] {
            let cap = RemapCapability::detect(vv);
            assert_eq!(cap, RemapCapability::default(), "input {vv:?}");
        }
    }

    #[test]
    fn old_nightly_before_stabilization_gets_nothing() {
        let cap = RemapCapability::detect("release: 1.20.0-nightly\n");
        assert!(!cap.remap_path_prefix);
        assert!(!cap.trim_paths, "trim-paths requires a remap-capable base");
    }

    #[test]
    fn flags_are_emitted_only_where_supported() {
        let entries = project_relative_entries();
        let none = rustc_remap_flags(RemapCapability::default(), &entries).unwrap();
        assert!(none.is_empty(), "unsupported toolchain: no flags, no error");
        let flags = rustc_remap_flags(RemapCapability::detect(STABLE_VV), &entries).unwrap();
        assert_eq!(flags, vec!["--remap-path-prefix=/__rabs/workspace=."]);
    }

    #[test]
    fn trim_paths_args_are_nightly_only() {
        assert!(cargo_trim_paths_args(RemapCapability::detect(STABLE_VV)).is_empty());
        assert_eq!(
            cargo_trim_paths_args(RemapCapability::detect(NIGHTLY_VV)),
            vec!["-Ztrim-paths".to_string()]
        );
    }

    #[test]
    fn backing_path_source_is_refused_as_the_leak_it_is() {
        let cap = RemapCapability::detect(NIGHTLY_VV);
        let entries = [RemapEntry::new("/var/rabs/staging/attempt-8f2c1a", ".")];
        let err = rustc_remap_flags(cap, &entries).unwrap_err();
        assert!(matches!(err, RemapError::NonCanonicalSource { .. }));
    }

    #[test]
    fn flag_breaking_characters_are_refused() {
        let cap = RemapCapability::detect(NIGHTLY_VV);
        for (from, to) in [
            ("/__rabs/workspace/a=b", "."),
            ("/__rabs/workspace/a\0b", "."),
            ("/__rabs/workspace", ".\0x"),
        ] {
            let err = rustc_remap_flags(cap, &[RemapEntry::new(from, to)]).unwrap_err();
            assert!(
                matches!(err, RemapError::UnsafeFlagToken { .. }),
                "{from:?}={to:?} must be refused"
            );
        }
    }

    #[test]
    fn injection_appends_to_existing_rustflags_and_reports_application() {
        let mut plan = CanonicalMountPlan::new("/b/tc", "/b/ws", "/b/ch", "/b/home");
        plan.extra_env
            .push(("RUSTFLAGS".to_string(), "-Copt-level=2".to_string()));
        let cap = RemapCapability::detect(STABLE_VV);
        let applied = inject_remap_into_plan(&mut plan, cap, &project_relative_entries()).unwrap();
        assert!(applied);
        let rustflags = &plan
            .extra_env
            .iter()
            .find(|(n, _)| n == "RUSTFLAGS")
            .unwrap()
            .1;
        assert_eq!(
            rustflags,
            "-Copt-level=2 --remap-path-prefix=/__rabs/workspace=."
        );
    }

    #[test]
    fn injection_on_unsupported_toolchain_is_a_clean_no_op() {
        let mut plan = CanonicalMountPlan::new("/b/tc", "/b/ws", "/b/ch", "/b/home");
        let applied = inject_remap_into_plan(
            &mut plan,
            RemapCapability::default(),
            &project_relative_entries(),
        )
        .unwrap();
        assert!(!applied);
        assert!(plan.extra_env.is_empty(), "plan intentionally unchanged");
    }

    #[test]
    fn injected_plan_still_compiles_to_a_spec_with_rustflags_present() {
        let mut plan = CanonicalMountPlan::new("/b/tc", "/b/ws", "/b/ch", "/b/home");
        inject_remap_into_plan(
            &mut plan,
            RemapCapability::detect(NIGHTLY_VV),
            &project_relative_entries(),
        )
        .unwrap();
        let spec = plan.to_spec().unwrap();
        assert!(
            spec.env
                .iter()
                .any(|(n, v)| n == "RUSTFLAGS" && v.contains("--remap-path-prefix")),
            "RUSTFLAGS flows through as non-canonical extra env"
        );
    }
}
