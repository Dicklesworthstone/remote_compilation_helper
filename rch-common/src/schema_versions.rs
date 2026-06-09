//! Central registry of schema versions across the workspace.
//!
//! Why this exists: before this module, the four schema-version constants
//! lived independently in their owning crates. They all happened to be
//! `"1.0.0"`, which masked a real bug — a comparison that should have
//! checked compatibility between two of them silently passed because the
//! values coincided. (Fixed in commit `68fcb7c`.)
//!
//! Going forward, every schema-version constant in the workspace is
//! sourced from this registry. The pinned-snapshot test in this module
//! is the gate: bumping a version requires intentionally updating the
//! snapshot table, which surfaces the change in code review.
//!
//! # Components covered
//!
//! | `SchemaComponent` variant      | Owning surface                              |
//! |--------------------------------|---------------------------------------------|
//! | `DoctorReliability`            | `rch doctor --reliability` JSON envelope    |
//! | `Status`                       | `rch status --json` envelope                |
//! | `RepoUpdaterContract`          | repo-updater protocol over the wire         |
//! | `ProcessTriageContract`        | process-triage protocol over the wire       |
//!
//! # Bump policy
//!
//! See bead `remote_compilation_helper-62u24.11` "Schema-version bump
//! policy + migration playbook" for the canonical procedure. In short:
//! - MAJOR: removal or rename (breaking)
//! - MINOR: new field or new enum variant (additive)
//! - PATCH: serialization-order change or doc-only change affecting
//!   golden tests
//!
//! When you bump, ALSO update [`tests::test_schema_versions_match_snapshot`].
//! Reviewers see the snapshot delta and confirm the rationale.

use serde::{Deserialize, Serialize};

/// Stable identifier for each component that exposes a versioned schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaComponent {
    /// `rch doctor --reliability` response envelope.
    DoctorReliability,
    /// `rch status --json` response envelope.
    Status,
    /// Repo-updater wire contract.
    RepoUpdaterContract,
    /// Process-triage wire contract.
    ProcessTriageContract,
    /// Incident event schema (shared remediation reason-code ledger).
    IncidentLedger,
}

/// The canonical version string for a given component.
///
/// `const fn` so callers can use the result in `pub const` declarations
/// (preserves the existing call sites that read into compile-time
/// constants).
#[must_use]
pub const fn current_version(component: SchemaComponent) -> &'static str {
    match component {
        SchemaComponent::DoctorReliability => "1.0.0",
        SchemaComponent::Status => "1.0.0",
        SchemaComponent::RepoUpdaterContract => "1.0.0",
        SchemaComponent::ProcessTriageContract => "1.0.0",
        SchemaComponent::IncidentLedger => "1.0.0",
    }
}

/// Every component, paired with its current version. Iterable in tests
/// and at runtime.
pub const ALL_COMPONENTS: &[(SchemaComponent, &str)] = &[
    (
        SchemaComponent::DoctorReliability,
        current_version(SchemaComponent::DoctorReliability),
    ),
    (
        SchemaComponent::Status,
        current_version(SchemaComponent::Status),
    ),
    (
        SchemaComponent::RepoUpdaterContract,
        current_version(SchemaComponent::RepoUpdaterContract),
    ),
    (
        SchemaComponent::ProcessTriageContract,
        current_version(SchemaComponent::ProcessTriageContract),
    ),
    (
        SchemaComponent::IncidentLedger,
        current_version(SchemaComponent::IncidentLedger),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned snapshot of every component's version. Bumping a version
    /// in [`current_version`] without updating this table fails the test —
    /// the failure is the code-review trigger.
    ///
    /// Order matters: tests assert this list matches [`ALL_COMPONENTS`] in
    /// both content AND order, so a refactor that reshuffles the constant
    /// surfaces immediately.
    const PINNED_SNAPSHOT: &[(SchemaComponent, &str)] = &[
        (SchemaComponent::DoctorReliability, "1.0.0"),
        (SchemaComponent::Status, "1.0.0"),
        (SchemaComponent::RepoUpdaterContract, "1.0.0"),
        (SchemaComponent::ProcessTriageContract, "1.0.0"),
        (SchemaComponent::IncidentLedger, "1.0.0"),
    ];

    #[test]
    fn test_schema_versions_match_snapshot() {
        assert_eq!(
            ALL_COMPONENTS.len(),
            PINNED_SNAPSHOT.len(),
            "Number of components changed without snapshot update. \
             Either add the missing entry to PINNED_SNAPSHOT or remove the unused entry from ALL_COMPONENTS."
        );
        for (i, ((c1, v1), (c2, v2))) in ALL_COMPONENTS
            .iter()
            .zip(PINNED_SNAPSHOT.iter())
            .enumerate()
        {
            assert_eq!(
                (c1, *v1),
                (c2, *v2),
                "Mismatch at position {i}: ALL_COMPONENTS has ({c1:?}, {v1}); \
                 PINNED_SNAPSHOT has ({c2:?}, {v2}). \
                 Bump procedure: edit current_version() AND PINNED_SNAPSHOT in the same commit."
            );
        }
    }

    #[test]
    fn test_current_version_is_const_eval_friendly() {
        // Call current_version() in a const-eval context. The compiler will
        // refuse if it ever stops being a `const fn`.
        const _DR: &str = current_version(SchemaComponent::DoctorReliability);
        const _ST: &str = current_version(SchemaComponent::Status);
        const _RU: &str = current_version(SchemaComponent::RepoUpdaterContract);
        const _PT: &str = current_version(SchemaComponent::ProcessTriageContract);
    }

    #[test]
    fn test_versions_match_semver_shape() {
        for &(_, version) in ALL_COMPONENTS {
            let parts: Vec<&str> = version.split('.').collect();
            assert_eq!(
                parts.len(),
                3,
                "version {version} must be MAJOR.MINOR.PATCH (got {} parts)",
                parts.len()
            );
            for p in parts {
                assert!(
                    p.chars().all(|ch| ch.is_ascii_digit()),
                    "version {version} contains non-numeric component {p}"
                );
            }
        }
    }

    #[test]
    fn test_all_components_unique() {
        use std::collections::HashSet;
        let set: HashSet<_> = ALL_COMPONENTS.iter().map(|(c, _)| *c).collect();
        assert_eq!(
            set.len(),
            ALL_COMPONENTS.len(),
            "duplicate SchemaComponent in ALL_COMPONENTS"
        );
    }
}
