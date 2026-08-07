//! `--extern` path → content-identity resolution (bead F004; plan §62;
//! risks R3/R9).
//!
//! An `--extern name=path` argument names a LOCAL FILE; the action key
//! must depend on what the compiler will actually READ, never on the
//! local path spelling. Resolution maps each extern to the
//! **conservative dependency-artifact identity** of the supplied file:
//!
//! - the artifact kind matters (`rmeta` vs `rlib` vs `dylib`): rustc
//!   consumes different bytes from each, and a pipelined `.rmeta` and
//!   the final `.rlib` for the same crate are different dependency
//!   artifacts with different downstream effects;
//! - a **missing extern is a hard error**, never a silent omission — an
//!   extern the resolver cannot identify would otherwise vanish from
//!   the key while still failing (or worse, succeeding differently) at
//!   execution time;
//! - `--extern name` without a path (the `noprelude`-style /
//!   sysroot-provided form) resolves through the toolchain contract
//!   (F007) rather than a file identity, and keys as exactly that.
//!
//! The resolver is pure: file content identity arrives through a caller
//! supplied lookup (the daemon wires the real CAS/stat layer; tests wire
//! fixtures), keeping this crate effect-free per the A002 dependency
//! rules.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the resolved-extern set.
pub const DOMAIN_RESOLVED_EXTERNS: &str = "rabs.resolved-externs.v1";

/// Dependency-artifact kinds rustc consumes (wire-stable tags below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Plan vocabulary.
pub enum DependencyArtifactKind {
    Rmeta,
    Rlib,
    Dylib,
    ProcMacroDylib,
}

/// Wire-stable kind tag.
#[must_use]
pub const fn kind_tag(kind: DependencyArtifactKind) -> u32 {
    match kind {
        DependencyArtifactKind::Rmeta => 1,
        DependencyArtifactKind::Rlib => 2,
        DependencyArtifactKind::Dylib => 3,
        DependencyArtifactKind::ProcMacroDylib => 4,
    }
}

/// The identity of one file actually supplied to the compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyArtifactIdentity {
    /// What kind of artifact the file is.
    pub kind: DependencyArtifactKind,
    /// Content digest of the file bytes.
    pub content_digest: TypedDigest,
}

/// One resolved extern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedExtern {
    /// `--extern name=path`: the file's conservative identity.
    File {
        /// Crate name as given.
        name: String,
        /// Identity of the file actually supplied.
        identity: DependencyArtifactIdentity,
    },
    /// `--extern name` (no path): satisfied by the toolchain/sysroot;
    /// keys as that fact — the toolchain digest (F007) carries the
    /// actual bytes' identity.
    ToolchainProvided {
        /// Crate name as given.
        name: String,
    },
}

/// Resolution failure — always hard, never an omission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternResolutionError {
    /// The supplied path could not be identified (missing file,
    /// unreadable, or the provider has no identity for it).
    MissingExtern {
        /// Crate name.
        name: String,
        /// The path that failed to resolve.
        path: String,
    },
    /// Two externs share a crate name with different identities.
    ConflictingExtern {
        /// Crate name.
        name: String,
    },
}

/// Resolve `(name, Option<path>)` extern pairs (exactly the F003
/// `externs` field shape) into identities via `lookup`.
///
/// `lookup` returns the identity of the file at a path, or `None` if it
/// cannot — which is a HARD error here.
///
/// # Errors
/// [`ExternResolutionError::MissingExtern`] on any unresolvable path;
/// [`ExternResolutionError::ConflictingExtern`] when one crate name maps
/// to two different identities.
pub fn resolve_externs(
    externs: &[(String, Option<String>)],
    lookup: impl Fn(&str) -> Option<DependencyArtifactIdentity>,
) -> Result<Vec<ResolvedExtern>, ExternResolutionError> {
    let mut resolved: Vec<ResolvedExtern> = Vec::with_capacity(externs.len());
    for (name, path) in externs {
        let entry = match path {
            None => ResolvedExtern::ToolchainProvided { name: name.clone() },
            Some(p) => match lookup(p) {
                None => {
                    return Err(ExternResolutionError::MissingExtern {
                        name: name.clone(),
                        path: p.clone(),
                    });
                }
                Some(identity) => ResolvedExtern::File {
                    name: name.clone(),
                    identity,
                },
            },
        };
        // Duplicate crate names: identical resolution is a benign
        // repeat; different resolutions are ambiguous.
        let existing = resolved.iter().find(|r| {
            let n = match r {
                ResolvedExtern::File { name, .. } | ResolvedExtern::ToolchainProvided { name } => {
                    name
                }
            };
            n == name
        });
        match existing {
            Some(prev) if *prev != entry => {
                return Err(ExternResolutionError::ConflictingExtern { name: name.clone() });
            }
            Some(_) => {}
            None => resolved.push(entry),
        }
    }
    Ok(resolved)
}

/// Canonical digest over a resolved-extern set (sorted by crate name —
/// extern order is not semantics once identities are resolved).
#[must_use]
pub fn resolved_externs_digest(resolved: &[ResolvedExtern]) -> TypedDigest {
    let mut sorted: Vec<&ResolvedExtern> = resolved.iter().collect();
    sorted.sort_by_key(|r| match r {
        ResolvedExtern::File { name, .. } | ResolvedExtern::ToolchainProvided { name } => {
            name.clone()
        }
    });
    let mut enc = CanonicalEncoder::new();
    enc.u64(sorted.len() as u64);
    for r in sorted {
        match r {
            ResolvedExtern::File { name, identity } => {
                enc.u32(1)
                    .str(name)
                    .u32(kind_tag(identity.kind))
                    .str(identity.content_digest.domain)
                    .bytes(&identity.content_digest.bytes);
            }
            ResolvedExtern::ToolchainProvided { name } => {
                enc.u32(2).str(name);
            }
        }
    }
    compute(DOMAIN_RESOLVED_EXTERNS, &enc.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn identity(kind: DependencyArtifactKind, tag: u8) -> DependencyArtifactIdentity {
        DependencyArtifactIdentity {
            kind,
            content_digest: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: "rabs.dep-artifact.v1",
                bytes: [tag; 32],
            },
        }
    }

    /// Fixture provider: rmeta/rlib/dylib files with distinct contents.
    fn provider(path: &str) -> Option<DependencyArtifactIdentity> {
        match path {
            "/deps/libserde.rmeta" => Some(identity(DependencyArtifactKind::Rmeta, 1)),
            "/deps/libserde.rlib" => Some(identity(DependencyArtifactKind::Rlib, 2)),
            "/deps/libmacros.so" => Some(identity(DependencyArtifactKind::ProcMacroDylib, 3)),
            "/deps/libshared.so" => Some(identity(DependencyArtifactKind::Dylib, 4)),
            _ => None,
        }
    }

    fn e(name: &str, path: Option<&str>) -> (String, Option<String>) {
        (name.to_owned(), path.map(str::to_owned))
    }

    #[test]
    fn rmeta_rlib_dylib_fixtures_resolve_to_correct_identities() {
        let resolved = resolve_externs(
            &[
                e("serde", Some("/deps/libserde.rlib")),
                e("macros", Some("/deps/libmacros.so")),
                e("shared", Some("/deps/libshared.so")),
                e("core", None),
            ],
            provider,
        )
        .unwrap();
        assert_eq!(resolved.len(), 4);
        let ResolvedExtern::File {
            identity: serde, ..
        } = &resolved[0]
        else {
            panic!("expected file extern");
        };
        assert_eq!(serde.kind, DependencyArtifactKind::Rlib);
        assert!(matches!(
            &resolved[3],
            ResolvedExtern::ToolchainProvided { name } if name == "core"
        ));
    }

    #[test]
    fn pipelined_rmeta_and_final_rlib_are_different_identities() {
        // Same crate compiled, two supply modes: the .rmeta handed to a
        // pipelined downstream vs the final .rlib. Different files,
        // different kinds, different keys.
        let via_rmeta =
            resolve_externs(&[e("serde", Some("/deps/libserde.rmeta"))], provider).unwrap();
        let via_rlib =
            resolve_externs(&[e("serde", Some("/deps/libserde.rlib"))], provider).unwrap();
        assert_ne!(
            resolved_externs_digest(&via_rmeta),
            resolved_externs_digest(&via_rlib)
        );
    }

    #[test]
    fn missing_extern_is_a_hard_error_not_a_silent_omission() {
        let err = resolve_externs(
            &[
                e("serde", Some("/deps/libserde.rlib")),
                e("ghost", Some("/deps/libghost.rlib")),
            ],
            provider,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ExternResolutionError::MissingExtern {
                name: "ghost".into(),
                path: "/deps/libghost.rlib".into(),
            }
        );
    }

    #[test]
    fn conflicting_duplicates_error_and_identical_duplicates_collapse() {
        // rustc accepts repeated --extern; identical repeats are benign.
        let ok = resolve_externs(
            &[
                e("serde", Some("/deps/libserde.rlib")),
                e("serde", Some("/deps/libserde.rlib")),
            ],
            provider,
        )
        .unwrap();
        assert_eq!(ok.len(), 1);
        // One name, two different files: ambiguous — typed error.
        let err = resolve_externs(
            &[
                e("serde", Some("/deps/libserde.rlib")),
                e("serde", Some("/deps/libserde.rmeta")),
            ],
            provider,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ExternResolutionError::ConflictingExtern {
                name: "serde".into()
            }
        );
    }

    #[test]
    fn identity_keys_on_content_never_on_path_spelling() {
        // Two different path spellings supplying byte-identical files
        // produce equal digests; same path with changed contents forks.
        let by_content = |path: &str| match path {
            "/a/libx.rlib" | "/b/libx.rlib" => Some(identity(DependencyArtifactKind::Rlib, 9)),
            "/a/libx-changed.rlib" => Some(identity(DependencyArtifactKind::Rlib, 10)),
            _ => None,
        };
        let a = resolve_externs(&[e("x", Some("/a/libx.rlib"))], by_content).unwrap();
        let b = resolve_externs(&[e("x", Some("/b/libx.rlib"))], by_content).unwrap();
        assert_eq!(resolved_externs_digest(&a), resolved_externs_digest(&b));
        let c = resolve_externs(&[e("x", Some("/a/libx-changed.rlib"))], by_content).unwrap();
        assert_ne!(resolved_externs_digest(&a), resolved_externs_digest(&c));
    }
}
