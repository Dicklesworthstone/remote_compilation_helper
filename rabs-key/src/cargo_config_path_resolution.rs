//! Origin-relative path resolution for canonical planning (bead K019;
//! plan Epic K; consumes the K015 provenance contract).
//!
//! Cargo resolves a RELATIVE path in configuration against a base that
//! depends on WHERE the value was declared — the exact origins K015
//! captures. Canonical planning must reproduce that resolution
//! EXACTLY, then spell the result in the canonical namespace, or two
//! hosts whose only difference is `/dp` vs `/data/projects` spelling
//! would key differently for identical reality.
//!
//! The base-selection law below is EMPIRICAL (probed against stock
//! Cargo 1.100 nightly on 2026-08-24; fixtures cite the probe):
//!
//! | Value declared in                    | Relative-path base            |
//! |--------------------------------------|-------------------------------|
//! | `<dir>/.cargo/config.toml`           | `<dir>` (parent of `.cargo`)  |
//! | `$CARGO_HOME/config.toml`            | `$CARGO_HOME`                 |
//! | `--config` CLI argument              | invocation CWD                |
//! | `CARGO_*` env override               | invocation CWD                |
//! | `[source.X] directory = ...`         | parent of `.cargo`            |
//! | `[env] NAME = { relative = true }`   | parent of `.cargo`            |
//!
//! Two subtleties the probes also pinned:
//!
//! 1. Cargo emits the JOIN unnormalized (`ws/../shared-target` stays
//!    spelled with `..`). Canonical planning therefore owns
//!    normalization: lexical only — `.`/`..` segments and duplicate
//!    separators collapsed — never symlink resolution, which would be
//!    host state smuggled into identity.
//! 2. After normalization the path is mapped from the alias root
//!    (`/dp`) onto the canonical root (`/data/projects` by default;
//!    both configurable fleet-side) and REQUIRED to live inside the
//!    canonical namespace. A value that escapes it refuses fail-closed
//!    — the same law as the D026 working-directory rule — because an
//!    action planned against host-local state cannot be keyed honestly.
//!
//! Pure over observed values: no filesystem access; the caller supplies
//! every base directory as an OBSERVED canonical fact.
//!
//! # Dependency rules
//!
//! Same as the crate: no Tokio, no Asupersync; no allocation beyond the
//! output buffer where avoidable.

/// Which base directory Cargo would resolve this declaration against,
/// derived from the K015 [`crate::cargo_config_provenance::ConfigOrigin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathBase {
    /// Parent of the declaring file's `.cargo` directory (workspace /
    /// ancestor config tables, source-replacement `directory`,
    /// `[env] relative = true`).
    ConfigParent {
        /// The parent-of-`.cargo` directory, canonical absolute.
        dir: Vec<u8>,
    },
    /// `$CARGO_HOME` itself (values declared in the home config).
    CargoHome {
        /// The CARGO_HOME directory, canonical absolute.
        home: Vec<u8>,
    },
    /// The invocation working directory (CLI `--config` arguments and
    /// `CARGO_*` environment overrides). Must already be spelled
    /// canonically — the D026 working-directory rule applies upstream.
    InvocationCwd {
        /// Canonical absolute cwd bytes.
        cwd: Vec<u8>,
    },
}

impl PathBase {
    /// Derive the base for a config FILE location
    /// (`<dir>/.cargo/<file>`): the parent of the `.cargo` directory.
    /// Refuses anything not shaped `<canonical>/<.cargo>/<file>`.
    ///
    /// # Errors
    /// [`PathResolutionError::NonCanonicalBase`] when the config path
    /// does not end in `/.cargo/<file>` or is not absolutely spelled.
    pub fn from_config_file(config_file_path: &[u8]) -> Result<Self, PathResolutionError> {
        const DOT_CARGO: &[u8] = b"/.cargo/";
        let Some(idx) = find(config_file_path, DOT_CARGO) else {
            return Err(PathResolutionError::NonCanonicalBase {
                raw: String::from_utf8_lossy(config_file_path).into_owned(),
            });
        };
        if idx == 0 || config_file_path.ends_with(DOT_CARGO) {
            return Err(PathResolutionError::NonCanonicalBase {
                raw: String::from_utf8_lossy(config_file_path).into_owned(),
            });
        }
        Ok(Self::ConfigParent {
            dir: config_file_path[..idx].to_vec(),
        })
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Canonical-namespace roots (mirrors RCH's configurable topology).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRoots {
    /// The canonical spelling projects are planned under.
    pub canonical_root: Vec<u8>,
    /// A well-known alias spelling that MUST map onto the canonical
    /// root (RCH convention: canonical `/data/projects`, alias `/dp`).
    /// Set equal to `canonical_root` when no alias exists.
    pub alias_root: Vec<u8>,
}

impl CanonicalRoots {
    /// The default RCH topology: canonical `/data/projects`, alias `/dp`.
    #[must_use]
    pub fn rch_default() -> Self {
        Self {
            canonical_root: b"/data/projects".to_vec(),
            alias_root: b"/dp".to_vec(),
        }
    }
}

/// Why an origin-relative value could not be resolved honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathResolutionError {
    /// The raw value was empty or only separators: ambiguous between
    /// unset and set-but-empty.
    EmptyPath,
    /// A base directory was not a canonical absolute spelling.
    NonCanonicalBase {
        /// Offending bytes.
        raw: String,
    },
    /// The resolved path left the canonical namespace (after alias
    /// mapping): planning cannot key host-local escapes honestly.
    EscapesCanonicalNamespace {
        /// The normalized, pre-mapping spelling that escaped.
        resolved: String,
    },
}

/// Resolve one origin-relative path spelling into its canonical
/// absolute form, reproducing Cargo's base selection exactly and then
/// normalizing + namespace-mapping for planning.
///
/// Absolute spellings skip the join but still normalize and map.
///
/// # Errors
/// [`PathResolutionError::EmptyPath`] on empty values;
/// [`PathResolutionError::NonCanonicalBase`] when a base is not a
/// canonical absolute path;
/// [`PathResolutionError::EscapesCanonicalNamespace`] when the resolved
/// path leaves the canonical root.
pub fn resolve_origin_relative(
    raw: &[u8],
    base: &PathBase,
    roots: &CanonicalRoots,
) -> Result<Vec<u8>, PathResolutionError> {
    if raw.is_empty() || trim_separators(raw).is_empty() {
        return Err(PathResolutionError::EmptyPath);
    }
    let base_dir = match base {
        PathBase::ConfigParent { dir } => dir,
        PathBase::CargoHome { home } => home,
        PathBase::InvocationCwd { cwd } => cwd,
    };
    validate_base(base_dir)?;
    let joined: Vec<u8> = if raw.first() == Some(&b'/') {
        raw.to_vec()
    } else {
        let mut j = Vec::with_capacity(base_dir.len() + 1 + raw.len());
        j.extend_from_slice(base_dir);
        j.push(b'/');
        j.extend_from_slice(raw);
        j
    };
    let normalized = lexically_normalize(&joined);
    let mapped = map_alias_prefix(&normalized, roots);
    if !mapped.starts_with(roots.canonical_root.as_slice())
        || mapped.get(roots.canonical_root.len()) != Some(&b'/')
    {
        return Err(PathResolutionError::EscapesCanonicalNamespace {
            resolved: String::from_utf8_lossy(&mapped).into_owned(),
        });
    }
    Ok(mapped)
}

fn trim_separators(raw: &[u8]) -> &[u8] {
    let mut s = raw;
    while let Some((f, rest)) = s.split_first() {
        if *f == b'/' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn validate_base(base: &[u8]) -> Result<(), PathResolutionError> {
    if base.first() != Some(&b'/') || base.last() == Some(&b'/') {
        return Err(PathResolutionError::NonCanonicalBase {
            raw: String::from_utf8_lossy(base).into_owned(),
        });
    }
    if !base
        .split(|&b| b == b'/')
        .skip(1)
        .all(|seg| !seg.is_empty() && seg != b"." && seg != b"..")
    {
        return Err(PathResolutionError::NonCanonicalBase {
            raw: String::from_utf8_lossy(base).into_owned(),
        });
    }
    Ok(())
}

/// Lexical normalization: collapse duplicate separators, drop `.` and
/// `..` segments (with their parent), drop trailing separators. Purely
/// textual — no symlink/host state.
fn lexically_normalize(path: &[u8]) -> Vec<u8> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for seg in path.split(|&b| b == b'/').filter(|s| !s.is_empty()) {
        match seg {
            b"." => {}
            b".." => {
                out.pop();
            }
            _ => out.push(seg.to_vec()),
        }
    }
    let mut joined = Vec::with_capacity(path.len());
    for seg in &out {
        joined.push(b'/');
        joined.extend_from_slice(seg);
    }
    joined
}

fn map_alias_prefix(path: &[u8], roots: &CanonicalRoots) -> Vec<u8> {
    let alias = roots.alias_root.as_slice();
    let canonical = roots.canonical_root.as_slice();
    if alias == canonical || path == alias {
        return path.to_vec();
    }
    let matches_prefix = path.starts_with(alias)
        && (path.len() == alias.len() || path.get(alias.len()) == Some(&b'/'));
    if matches_prefix && path.len() > alias.len() {
        let mut mapped = canonical.to_vec();
        mapped.extend_from_slice(&path[alias.len()..]);
        mapped
    } else {
        path.to_vec()
    }
}

// ---------------------------------------------------------------------
// Tests — K019 acceptance: origin-relative fixtures behave identically
// canonical vs stock. Each fixture cites the stock-Cargo probe it pins.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ws_base(ws: &[u8]) -> PathBase {
        PathBase::ConfigParent { dir: ws.to_vec() }
    }

    #[test]
    fn p1_workspace_config_target_dir_fixture() {
        // Stock probe P1: at /tmp/k19/ws with `.cargo/config.toml`
        // `target-dir = "../shared-target"`, cargo metadata reports
        // `/tmp/k19/ws/../shared-target` (unnormalized join against
        // parent-of-.cargo). Canonical planning spells it normalized.
        let roots = CanonicalRoots::rch_default();
        let r = resolve_origin_relative(
            b"../shared-target",
            &ws_base(b"/data/projects/acme"),
            &roots,
        )
        .expect("resolves");
        assert_eq!(r, b"/data/projects/shared-target");
    }

    #[test]
    fn p2_ancestor_config_fixture() {
        // Stock probe P2: ancestor `$ROOT/.cargo/config.toml` with
        // `anc-target` for a project under `$ROOT/proj` resolved
        // against `$ROOT`.
        let roots = CanonicalRoots::rch_default();
        let r = resolve_origin_relative(b"anc-target", &ws_base(b"/data/projects"), &roots)
            .expect("resolves");
        assert_eq!(r, b"/data/projects/anc-target");
    }

    #[test]
    fn p3_cargo_home_config_fixture() {
        // Stock probe P3redo: `$CARGO_HOME/config.toml`
        // `home-target` resolved against $CARGO_HOME itself.
        let roots = CanonicalRoots::rch_default();
        let home = PathBase::CargoHome {
            home: b"/data/projects/.cargo-home".to_vec(),
        };
        let r = resolve_origin_relative(b"home-target", &home, &roots).expect("resolves");
        assert_eq!(r, b"/data/projects/.cargo-home/home-target");
    }

    #[test]
    fn p4_p5_env_and_cli_resolve_against_invocation_cwd() {
        // Stock probes P4a/b + P5/P5b: CARGO_TARGET_DIR env override
        // AND --config CLI values resolve relative to the INVOCATION
        // cwd (verified from two different cwds).
        let roots = CanonicalRoots::rch_default();
        let cwd = PathBase::InvocationCwd {
            cwd: b"/data/projects/acme".to_vec(),
        };
        assert_eq!(
            resolve_origin_relative(b"env-rel", &cwd, &roots).expect("ok"),
            b"/data/projects/acme/env-rel"
        );
        assert_eq!(
            resolve_origin_relative(b"cli-rel", &cwd, &roots).expect("ok"),
            b"/data/projects/acme/cli-rel"
        );
    }

    #[test]
    fn p7_source_replacement_directory_fixture() {
        // Stock probe P7: [source.vend] directory = "vendor-tree"
        // resolved to <parent-of-.cargo>/vendor-tree (error message
        // named the joined path verbatim).
        let roots = CanonicalRoots::rch_default();
        let r =
            resolve_origin_relative(b"vendor-tree", &ws_base(b"/data/projects/vendorws"), &roots)
                .expect("resolves");
        assert_eq!(r, b"/data/projects/vendorws/vendor-tree");
    }

    #[test]
    fn env_section_relative_uses_config_parent_law() {
        // [env] NAME = { value = "sub/from-env", relative = true } uses
        // the same ConfigRelativePath rule (Cargo config docs; the
        // rule empirically pinned by P1/P2/P7 for config-declared
        // relative paths).
        let roots = CanonicalRoots::rch_default();
        assert_eq!(
            resolve_origin_relative(
                b"sub/from-env",
                &ws_base(b"/data/projects/envprobe"),
                &roots,
            )
            .expect("ok"),
            b"/data/projects/envprobe/sub/from-env"
        );
    }

    #[test]
    fn stock_unnormalized_output_normalizes_lexically() {
        // Stock cargo emits `ws/../shared-target` UNNORMALIZED; feeding
        // that observed spelling back must normalize lexically.
        let roots = CanonicalRoots::rch_default();
        let r = resolve_origin_relative(
            b"/data/projects/acme/../shared-target",
            &PathBase::InvocationCwd {
                cwd: b"/data/projects".to_vec(),
            },
            &roots,
        )
        .expect("resolves");
        assert_eq!(r, b"/data/projects/shared-target");
    }

    #[test]
    fn alias_root_spelling_maps_onto_canonical_root() {
        // The whole point: /dp/acme/target IS /data/projects/acme/target.
        let roots = CanonicalRoots::rch_default();
        let r = resolve_origin_relative(
            b"/dp/acme/shared-target",
            &PathBase::InvocationCwd {
                cwd: b"/data/projects".to_vec(),
            },
            &roots,
        )
        .expect("resolves");
        assert_eq!(r, b"/data/projects/acme/shared-target");
        // Prefix collisions must NOT map: /dpX stays /dpX (and then
        // escapes the namespace, refused).
        assert!(matches!(
            resolve_origin_relative(
                b"/dpX/acme/target",
                &PathBase::InvocationCwd {
                    cwd: b"/data/projects".to_vec(),
                },
                &roots,
            ),
            Err(PathResolutionError::EscapesCanonicalNamespace { .. })
        ));
    }

    #[test]
    fn namespace_escapes_refuse_fail_closed() {
        let roots = CanonicalRoots::rch_default();
        // .. traversal out of the workspace still lands IN the
        // namespace here (P1 shape); escape needs enough depth.
        assert!(matches!(
            resolve_origin_relative(
                b"../../../etc/passwd",
                &ws_base(b"/data/projects/acme"),
                &roots,
            ),
            Err(PathResolutionError::EscapesCanonicalNamespace { .. })
        ));
        // Absolute host-local spelling likewise.
        assert!(matches!(
            resolve_origin_relative(
                b"/var/tmp/host-only",
                &ws_base(b"/data/projects/acme"),
                &roots,
            ),
            Err(PathResolutionError::EscapesCanonicalNamespace { .. })
        ));
    }

    #[test]
    fn malformed_inputs_refuse() {
        let roots = CanonicalRoots::rch_default();
        assert_eq!(
            resolve_origin_relative(b"", &ws_base(b"/data/projects/a"), &roots),
            Err(PathResolutionError::EmptyPath)
        );
        assert_eq!(
            resolve_origin_relative(b"//", &ws_base(b"/data/projects/a"), &roots),
            Err(PathResolutionError::EmptyPath)
        );
        assert!(matches!(
            PathBase::from_config_file(b"/data/projects/acme/config.toml"),
            Err(PathResolutionError::NonCanonicalBase { .. })
        ));
        assert!(matches!(
            PathBase::from_config_file(b"/data/projects/acme/.cargo/"),
            Err(PathResolutionError::NonCanonicalBase { .. })
        ));
    }

    #[test]
    fn from_config_file_extracts_parent_of_dot_cargo() {
        assert_eq!(
            PathBase::from_config_file(b"/data/projects/acme/.cargo/config.toml").expect("ok"),
            ws_base(b"/data/projects/acme")
        );
        // Ancestor configs derive their own parent.
        assert_eq!(
            PathBase::from_config_file(b"/data/projects/.cargo/config.toml").expect("ok"),
            ws_base(b"/data/projects")
        );
    }

    #[test]
    fn deep_join_stays_exact_against_stock_shape() {
        // Multi-level relative spelling with interior dots.
        let roots = CanonicalRoots::rch_default();
        assert_eq!(
            resolve_origin_relative(
                b"./target/./x/../y",
                &ws_base(b"/data/projects/acme"),
                &roots,
            )
            .expect("ok"),
            b"/data/projects/acme/target/y"
        );
    }
}
