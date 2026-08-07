//! Immutable dependency-action identification (bead K001; plan §95;
//! risk R84).
//!
//! The dependency fast lane (`DependencyImmutableFastPath` isolation)
//! is admitted only for compiles whose EVERY source root is provably
//! immutable:
//!
//! - `/__rabs/registry/<checksum>/…` — checksummed registry unpacks;
//! - `/__rabs/git/<checksum>/…` — pinned git checkouts at an exact
//!   revision.
//!
//! Identity is the EXACT resolved (source kind, checksum) pair — never
//! a `name-version` string: two registries can serve different bytes
//! for one `serde-1.0.200`, and a `[patch]`-ed or vendored crate keeps
//! its name+version while changing content entirely. Anything not
//! under an immutable root — workspace paths, `[patch]` overrides,
//! vendored trees, path deps — REFUSES the fast path and takes the
//! ordinary full-identity lane. Refusal is the sound default; the fast
//! path must be earned by every root.

/// The exact immutable source identity (never name+version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImmutableSource {
    /// A checksummed registry unpack.
    Registry {
        /// The unpack checksum from the canonical path.
        checksum: String,
    },
    /// A pinned git checkout.
    Git {
        /// The revision checksum from the canonical path.
        checksum: String,
    },
}

/// Classification of one compile's source roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyLane {
    /// Every source root is immutable: fast path admitted, keyed by
    /// the exact source identities.
    ImmutableFastPath {
        /// The immutable identities, in first-seen order.
        sources: Vec<ImmutableSource>,
    },
    /// At least one root is not provably immutable: ordinary lane,
    /// with the offending path named.
    RefuseOrdinaryLane {
        /// The first path that broke immutability.
        first_mutable_path: String,
    },
}

/// Parse one canonical path's immutable identity, if any.
fn immutable_root(path: &str) -> Option<ImmutableSource> {
    if let Some(rest) = path.strip_prefix("/__rabs/registry/") {
        let checksum = rest.split('/').next().unwrap_or("");
        // A checksum segment must be a plausible hex digest — an empty
        // or non-hex segment is NOT an identity, and ambiguity refuses.
        if checksum.len() >= 32 && checksum.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(ImmutableSource::Registry {
                checksum: checksum.to_owned(),
            });
        }
        return None;
    }
    if let Some(rest) = path.strip_prefix("/__rabs/git/") {
        let checksum = rest.split('/').next().unwrap_or("");
        if checksum.len() >= 32 && checksum.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(ImmutableSource::Git {
                checksum: checksum.to_owned(),
            });
        }
        return None;
    }
    None
}

/// Classify a compile by its source paths (the F003 source plus every
/// path-bearing input the action reads from source roots).
#[must_use]
pub fn classify_dependency_lane(source_paths: &[String]) -> DependencyLane {
    let mut sources: Vec<ImmutableSource> = Vec::new();
    for path in source_paths {
        match immutable_root(path) {
            Some(source) => {
                if !sources.contains(&source) {
                    sources.push(source);
                }
            }
            None => {
                return DependencyLane::RefuseOrdinaryLane {
                    first_mutable_path: path.clone(),
                };
            }
        }
    }
    if sources.is_empty() {
        // No sources at all: nothing proves immutability — refuse.
        return DependencyLane::RefuseOrdinaryLane {
            first_mutable_path: String::new(),
        };
    }
    DependencyLane::ImmutableFastPath { sources }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REG: &str =
        "/__rabs/registry/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const GIT: &str = "/__rabs/git/62d398ea17519d7e80cbdb32e062d70647cd58a4aabbccdd";

    fn paths(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn registry_and_git_roots_classify_with_exact_checksums() {
        let lane = classify_dependency_lane(&paths(&[
            &format!("{REG}/serde-1.0.200/src/lib.rs"),
            &format!("{REG}/serde-1.0.200/src/de.rs"),
            &format!("{GIT}/asupersync/src/lib.rs"),
        ]));
        let DependencyLane::ImmutableFastPath { sources } = lane else {
            panic!("expected fast path");
        };
        assert_eq!(sources.len(), 2, "one identity per root, deduplicated");
        assert!(matches!(
            &sources[0],
            ImmutableSource::Registry { checksum } if checksum.starts_with("9f86d081")
        ));
        assert!(matches!(
            &sources[1],
            ImmutableSource::Git { checksum } if checksum.starts_with("62d398ea")
        ));
    }

    #[test]
    fn identity_is_checksum_never_name_version() {
        // Two different checksums serving the SAME name-version are
        // different identities (the [patch]/mirror hazard).
        let a = classify_dependency_lane(&paths(&[&format!("{REG}/serde-1.0.200/src/lib.rs")]));
        let other =
            "/__rabs/registry/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = classify_dependency_lane(&paths(&[&format!("{other}/serde-1.0.200/src/lib.rs")]));
        assert_ne!(a, b, "same name+version, different bytes: distinct");
    }

    #[test]
    fn patched_vendored_and_workspace_sources_refuse_the_fast_path() {
        // Patched: a [patch] override lives under the workspace.
        for mutable in [
            "/__rabs/ws/patched/serde/src/lib.rs",
            "/__rabs/ws/vendor/serde/src/lib.rs",
            "/__rabs/ws/src/main.rs",
            "/home/u/absolute/elsewhere.rs",
        ] {
            let lane = classify_dependency_lane(&paths(&[
                &format!("{REG}/other-1.0.0/src/lib.rs"),
                mutable,
            ]));
            assert_eq!(
                lane,
                DependencyLane::RefuseOrdinaryLane {
                    first_mutable_path: mutable.to_owned()
                },
                "{mutable} must refuse"
            );
        }
    }

    #[test]
    fn ambiguity_refuses_the_fast_path() {
        // Malformed checksum segments are ambiguity, not identity:
        // empty, too short, or non-hex all refuse.
        for ambiguous in [
            "/__rabs/registry//serde/src/lib.rs",
            "/__rabs/registry/abc123/src/lib.rs",
            "/__rabs/git/not-a-checksum-at-all-but-long-enough-yes/src/lib.rs",
        ] {
            assert!(
                matches!(
                    classify_dependency_lane(&paths(&[ambiguous])),
                    DependencyLane::RefuseOrdinaryLane { .. }
                ),
                "{ambiguous} must refuse"
            );
        }
        // And an EMPTY source list proves nothing: refuse.
        assert!(matches!(
            classify_dependency_lane(&[]),
            DependencyLane::RefuseOrdinaryLane { .. }
        ));
    }
}
