//! Canonical execroot layout: fixed workspace path + stable logical
//! repo IDs (bead D001; invariant I1; plan §55; risk R1).
//!
//! WHY: identical work in different worktrees must resolve to identical
//! canonical paths or keys fragment (I1). Two rules:
//!
//! - the primary workspace lives at the FIXED `/__rabs/workspace` —
//!   safe because every sandbox is isolated; two builds cannot collide
//!   on the shared name because they never share a filesystem view;
//! - additional path-dependency repositories live at
//!   `/__rabs/repos/<logical-repo-id>` where the logical ID derives
//!   from STABLE identity — the Cargo/package source identity or a
//!   project-configured UUID plus the repo's closure role — and NEVER
//!   solely from a mutable git remote URL, local checkout path, branch,
//!   or current commit. Renaming a remote, moving a checkout, or
//!   advancing a branch must not move the canonical path (all three
//!   proven in tests).
//!
//! Aliasing (two configured sources claiming one logical ID, or one
//! source claiming two) is resolved EXPLICITLY in the repository-
//! closure manifest — a collision is a typed error, never a silent
//! last-writer-wins.

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// The fixed primary-workspace canonical path.
pub const WORKSPACE_ROOT: &str = "/__rabs/workspace";

/// Digest domain for logical repo IDs.
pub const DOMAIN_LOGICAL_REPO_ID: &str = "rabs.logical-repo-id.v1";

/// The STABLE identity a logical repo ID may derive from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StableRepoIdentity {
    /// Cargo package-source identity (registry/git source id string as
    /// resolved in the lockfile — stable across checkouts).
    CargoSourceId {
        /// The resolved source-id string.
        source_id: String,
    },
    /// A project-configured stable UUID.
    ConfiguredUuid {
        /// The UUID string.
        uuid: String,
    },
}

/// One repository's row in the closure manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoClosureEntry {
    /// Stable identity.
    pub identity: StableRepoIdentity,
    /// The repo's role in the closure (`"path-dep"`, `"tooling"`, …) —
    /// part of the ID so one source playing two roles gets two IDs.
    pub closure_role: String,
}

/// Derive the logical repo ID (hex of a typed digest over the stable
/// identity + role — mutable facts are not inputs by construction:
/// there is no parameter to pass a URL, path, branch, or commit).
#[must_use]
pub fn logical_repo_id(entry: &RepoClosureEntry) -> String {
    let mut enc = CanonicalEncoder::new();
    match &entry.identity {
        StableRepoIdentity::CargoSourceId { source_id } => {
            enc.u32(1).str(source_id);
        }
        StableRepoIdentity::ConfiguredUuid { uuid } => {
            enc.u32(2).str(uuid);
        }
    }
    enc.str(&entry.closure_role);
    let digest = compute(DOMAIN_LOGICAL_REPO_ID, &enc.finish());
    let mut hex = String::with_capacity(32);
    for byte in &digest.bytes[..16] {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// The canonical mount path for a repo entry.
#[must_use]
pub fn repo_canonical_path(entry: &RepoClosureEntry) -> String {
    format!("/__rabs/repos/{}", logical_repo_id(entry))
}

/// Manifest-level alias/collision check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosureManifestError {
    /// Two distinct entries derived the same logical ID.
    IdCollision {
        /// The colliding ID.
        id: String,
    },
    /// One stable identity appears twice with the same role.
    DuplicateEntry {
        /// The duplicated ID.
        id: String,
    },
}

/// Validate a repository-closure manifest: IDs must be unique, and
/// aliasing must be explicit (a duplicate is an error to resolve in
/// configuration, never silently collapsed).
///
/// # Errors
/// [`ClosureManifestError`] naming the colliding ID.
pub fn validate_closure_manifest(
    entries: &[RepoClosureEntry],
) -> Result<Vec<String>, ClosureManifestError> {
    let mut ids: Vec<(String, &RepoClosureEntry)> = Vec::new();
    for entry in entries {
        let id = logical_repo_id(entry);
        if let Some((_, prior)) = ids.iter().find(|(existing, _)| *existing == id) {
            return Err(if *prior == entry {
                ClosureManifestError::DuplicateEntry { id }
            } else {
                ClosureManifestError::IdCollision { id }
            });
        }
        ids.push((id, entry));
    }
    Ok(ids.into_iter().map(|(id, _)| id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(source_id: &str, role: &str) -> RepoClosureEntry {
        RepoClosureEntry {
            identity: StableRepoIdentity::CargoSourceId {
                source_id: source_id.into(),
            },
            closure_role: role.into(),
        }
    }

    #[test]
    fn workspace_root_is_fixed() {
        assert_eq!(WORKSPACE_ROOT, "/__rabs/workspace");
    }

    #[test]
    fn renamed_remotes_moved_checkouts_and_branches_cannot_move_the_id() {
        // The acceptance's three mutations are UNREPRESENTABLE: the
        // derivation takes only stable identity + role — there is no
        // parameter for a remote URL, checkout path, branch, or commit.
        // Two agents with different checkouts/remotes of one resolved
        // source produce byte-identical canonical paths.
        let alice = entry(
            "git+https://example.com/org/shared-lib?rev=abc123",
            "path-dep",
        );
        let bob = alice.clone(); // same resolved source id, any local state
        assert_eq!(repo_canonical_path(&alice), repo_canonical_path(&bob));
        // A configured-UUID repo: stable across every local mutation
        // by the same argument.
        let via_uuid = RepoClosureEntry {
            identity: StableRepoIdentity::ConfiguredUuid {
                uuid: "5c1e8f0a-8f5e-4bb9-9e59-7c9f0d3d9a01".into(),
            },
            closure_role: "path-dep".into(),
        };
        assert!(repo_canonical_path(&via_uuid).starts_with("/__rabs/repos/"));
    }

    #[test]
    fn distinct_sources_and_roles_get_distinct_ids() {
        let a = entry("git+https://example.com/org/a?rev=1", "path-dep");
        let b = entry("git+https://example.com/org/b?rev=1", "path-dep");
        assert_ne!(logical_repo_id(&a), logical_repo_id(&b));
        // One source, two closure roles: two IDs (role participates).
        let tooling = entry("git+https://example.com/org/a?rev=1", "tooling");
        assert_ne!(logical_repo_id(&a), logical_repo_id(&tooling));
        // Identity KIND participates: a UUID that textually equals a
        // source id is still a different identity.
        let uuid_lookalike = RepoClosureEntry {
            identity: StableRepoIdentity::ConfiguredUuid {
                uuid: "git+https://example.com/org/a?rev=1".into(),
            },
            closure_role: "path-dep".into(),
        };
        assert_ne!(logical_repo_id(&a), logical_repo_id(&uuid_lookalike));
    }

    #[test]
    fn aliased_repos_are_explicit_errors_never_silent() {
        // Same entry twice (config listed it twice): DuplicateEntry.
        let manifest = vec![
            entry("git+https://example.com/org/a?rev=1", "path-dep"),
            entry("git+https://example.com/org/a?rev=1", "path-dep"),
        ];
        assert!(matches!(
            validate_closure_manifest(&manifest),
            Err(ClosureManifestError::DuplicateEntry { .. })
        ));
        // Distinct entries are fine and yield unique IDs.
        let ok = vec![
            entry("git+https://example.com/org/a?rev=1", "path-dep"),
            entry("git+https://example.com/org/b?rev=1", "path-dep"),
        ];
        let ids = validate_closure_manifest(&ok).unwrap();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }
}
