//! Stable logical OUT_DIR / incremental / temp / home / secret-slot
//! mappings (bead D006; plan §28; invariants I1/I20).
//!
//! The rule that keeps unit identity honest: **Cargo's exact requested
//! `OUT_DIR` is authoritative.** The canonical driver configures Cargo
//! (target dir, env) BEFORE planning so that Cargo itself selects
//! `/__rabs/build/<unit>/out`; the mapping layer then backs that exact
//! path with hidden private storage. A wrapper may NOT substitute a
//! different `OUT_DIR` after Cargo has already selected unit hashes and
//! fingerprint paths — that substitution is precisely how "same build"
//! silently becomes two different builds (plan §28: "the Cargo-generated
//! visible path is authoritative").
//!
//! Logical unit IDs are stable across equivalent worktrees: derived
//! from the package coordinate (name, version, target kind, profile) —
//! never from the worktree path (canonicalized away by D003) and never
//! from current source content (source identity lives in the D018
//! snapshot digest; baking it into the UNIT id would fragment
//! incremental/OUT_DIR reuse on every edit, which is exactly what
//! Cargo's own semantics do not do).
//!
//! The stable per-namespace surfaces this module pins:
//! `TMPDIR=/__rabs/tmp`, `HOME=/__rabs/home` (the D005 canonical env
//! already emits both; tests here hold that contract), and secrets at
//! `/run/rabs-secrets/<slot>` — slot names validated, mounted read-only,
//! never under `/__rabs` (they must not look like build inputs).

use crate::layout;

/// A logical unit coordinate — everything the stable ID derives from.
/// Deliberately NO worktree path and NO source digest (see module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitCoordinate {
    /// Package name (as Cargo knows it).
    pub package: String,
    /// Package version.
    pub version: String,
    /// Target kind (`lib`, `bin:<name>`, `build-script-build`, …).
    pub target_kind: String,
    /// Compilation profile (`debug`, `release`, custom).
    pub profile: String,
}

/// Typed refusal from mapping validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    /// A coordinate/slot component is not a safe path token.
    UnsafeToken {
        /// Which field carried the bad token.
        field: &'static str,
        /// The offending value.
        value: String,
    },
    /// Cargo requested an `OUT_DIR` the plan did not pre-configure —
    /// substituting a different one after unit-hash selection is
    /// forbidden, so the mapping refuses instead.
    WrapperMayNotSubstitute {
        /// What Cargo actually requested.
        requested: String,
        /// The canonical path the plan expected.
        canonical: String,
    },
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeToken { field, value } => {
                write!(f, "unsafe token in {field}: {value:?}")
            }
            Self::WrapperMayNotSubstitute {
                requested,
                canonical,
            } => write!(
                f,
                "Cargo requested OUT_DIR {requested:?} but the plan canonicalized \
                 {canonical:?}; a wrapper may not substitute OUT_DIR after Cargo \
                 selected unit hashes — reconfigure the driver and re-plan"
            ),
        }
    }
}

impl std::error::Error for MappingError {}

fn validate_component(field: &'static str, value: &str) -> Result<(), MappingError> {
    let ok = !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'));
    if ok {
        Ok(())
    } else {
        Err(MappingError::UnsafeToken {
            field,
            value: value.to_string(),
        })
    }
}

/// The stable logical unit ID for a coordinate. Same coordinate ⇒ same
/// ID on every host and every equivalent worktree; different profile or
/// target kind ⇒ different ID. The `:` of `bin:<name>` flattens to `-`
/// so the ID is a single safe path token.
pub fn logical_unit_id(coordinate: &UnitCoordinate) -> Result<String, MappingError> {
    validate_component("package", &coordinate.package)?;
    validate_component("version", &coordinate.version)?;
    validate_component("target_kind", &coordinate.target_kind)?;
    validate_component("profile", &coordinate.profile)?;
    Ok(format!(
        "{}-{}-{}-{}",
        coordinate.package,
        coordinate.version,
        coordinate.target_kind.replace(':', "-"),
        coordinate.profile
    ))
}

/// The canonical `OUT_DIR` for a unit: `/__rabs/build/<unit>/out`.
pub fn canonical_out_dir(unit_id: &str) -> Result<String, MappingError> {
    validate_component("unit_id", unit_id)?;
    Ok(format!("{}/{}/out", layout::BUILD, unit_id))
}

/// The canonical incremental dir for a unit: `/__rabs/incremental/<unit>`.
pub fn canonical_incremental_dir(unit_id: &str) -> Result<String, MappingError> {
    validate_component("unit_id", unit_id)?;
    Ok(format!("{}/{}", layout::INCREMENTAL, unit_id))
}

/// The canonical secret-slot path: `/run/rabs-secrets/<slot>` — outside
/// `/__rabs` on purpose (a secret must never look like a build input).
pub fn secret_slot_path(slot: &str) -> Result<String, MappingError> {
    validate_component("slot", slot)?;
    Ok(format!("{}/{}", layout::SECRETS, slot))
}

/// Authorize Cargo's ACTUAL requested `OUT_DIR` against the plan.
///
/// Valid only when the request is byte-identical to the canonical path
/// the driver configured before planning. Anything else — a host path,
/// a re-rooted variant, a trailing-slash cousin — is a typed refusal:
/// the wrapper may not substitute, it must re-plan.
pub fn authorize_requested_out_dir(
    cargo_requested: &str,
    unit_id: &str,
) -> Result<(), MappingError> {
    let canonical = canonical_out_dir(unit_id)?;
    if cargo_requested == canonical {
        Ok(())
    } else {
        Err(MappingError::WrapperMayNotSubstitute {
            requested: cargo_requested.to_string(),
            canonical,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coord(package: &str, kind: &str, profile: &str) -> UnitCoordinate {
        UnitCoordinate {
            package: package.into(),
            version: "1.2.3".into(),
            target_kind: kind.into(),
            profile: profile.into(),
        }
    }

    #[test]
    fn unit_ids_are_stable_and_worktree_free_by_construction() {
        // The coordinate has no worktree/source field to vary: two
        // "worktrees" of the same package coordinate get the SAME id.
        let a = logical_unit_id(&coord("serde", "lib", "debug")).unwrap();
        let b = logical_unit_id(&coord("serde", "lib", "debug")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, "serde-1.2.3-lib-debug");
        // Profile and kind DO split identity.
        assert_ne!(
            a,
            logical_unit_id(&coord("serde", "lib", "release")).unwrap()
        );
        assert_ne!(
            a,
            logical_unit_id(&coord("serde", "bin:serde", "debug")).unwrap()
        );
    }

    #[test]
    fn canonical_paths_land_under_their_layout_roots() {
        let unit = logical_unit_id(&coord("fx", "build-script-build", "debug")).unwrap();
        assert_eq!(
            canonical_out_dir(&unit).unwrap(),
            "/__rabs/build/fx-1.2.3-build-script-build-debug/out"
        );
        assert_eq!(
            canonical_incremental_dir(&unit).unwrap(),
            "/__rabs/incremental/fx-1.2.3-build-script-build-debug"
        );
        assert_eq!(
            secret_slot_path("signing-key").unwrap(),
            "/run/rabs-secrets/signing-key"
        );
    }

    #[test]
    fn secret_slots_live_outside_the_rabs_tree() {
        let path = secret_slot_path("s1").unwrap();
        assert!(
            !path.starts_with("/__rabs"),
            "secrets must never look like build inputs: {path}"
        );
        assert!(layout::is_visible_path(&path), "but still a visible root");
    }

    #[test]
    fn cargo_requested_out_dir_is_authoritative_and_exact() {
        let unit = "fx-1.2.3-lib-debug";
        let canonical = canonical_out_dir(unit).unwrap();
        assert!(authorize_requested_out_dir(&canonical, unit).is_ok());
        // A wrapper may NOT substitute: host path, re-root, or even a
        // near-miss trailing slash all refuse.
        for requested in [
            "/home/user/proj/target/debug/build/fx-abc/out",
            "/__rabs/out/fx/debug/build/fx-abc/out",
            "/__rabs/build/fx-1.2.3-lib-debug/out/",
        ] {
            let err = authorize_requested_out_dir(requested, unit).unwrap_err();
            assert!(
                matches!(err, MappingError::WrapperMayNotSubstitute { .. }),
                "{requested} must refuse"
            );
        }
    }

    #[test]
    fn hostile_tokens_are_refused_everywhere() {
        for bad in ["", ".", "..", "a/b", "a\0b", "a b"] {
            assert!(canonical_out_dir(bad).is_err(), "{bad:?}");
            assert!(secret_slot_path(bad).is_err(), "{bad:?}");
            assert!(
                logical_unit_id(&UnitCoordinate {
                    package: bad.into(),
                    version: "1".into(),
                    target_kind: "lib".into(),
                    profile: "debug".into(),
                })
                .is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn tmp_and_home_contracts_match_the_d005_canonical_env() {
        // D006 pins TMPDIR=/__rabs/tmp and HOME=/__rabs/home per
        // namespace; the D005 plan env is where they are emitted —
        // hold that contract here so a drift breaks THIS bead's test.
        use crate::canonical_mounts::CanonicalMountPlan;
        let spec = CanonicalMountPlan::new("/b/tc", "/b/ws", "/b/ch", "/b/home")
            .to_spec()
            .unwrap();
        let env: std::collections::BTreeMap<_, _> = spec.env.into_iter().collect();
        assert_eq!(env["TMPDIR"], layout::TMP);
        assert_eq!(env["HOME"], layout::HOME);
    }
}
