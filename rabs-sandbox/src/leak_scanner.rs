//! Path leak scanner for outputs and metadata (bead D012; invariant
//! I20; plan §58; risk R42; builds on the D002 primitive).
//!
//! Every surface an action produces — artifacts, metadata, compiler
//! events, generated source, dep-info — is scanned for hidden-world
//! strings: real worktree roots, user homes, worker temp/CAS roots,
//! hidden operation/attempt/snapshot staging paths, hostnames,
//! usernames, actual target/build dirs, secret mount backing paths.
//! Findings CLASSIFY (the response differs radically by class):
//!
//! - `AdmittedCanonical` — the path is a sanctioned canonical form
//!   under the family's BuildPathSemanticPolicy: no leak;
//! - `PresentationOnlyTranslated` — appears only in a
//!   subscriber-translated presentation surface: renderable away;
//! - `RemappableDebugMetadata` — debug-section-only reference:
//!   remappable, artifact still shareable after remap;
//! - `KeyRelevantSemanticLeakage` — a hidden value reached a
//!   key-participating surface: the key itself is suspect;
//! - `OutputSemanticPathSensitivity` — LOADABLE/runtime-visible bytes
//!   embed the path: output semantics depend on it;
//! - `PrivacySecretIncident` — a secret backing path or username
//!   escaped: incident, never just a cache decision;
//! - `NonCanonicalLaunchEvidence` — divergent Cargo metadata hashes
//!   prove Cargo did not actually run canonically.
//!
//! **Ambiguous loadable-data leakage loses portable authority**: the
//! disposition routes to the D030 path-preserving lane, never to a
//! canonical shared hit.

use crate::layout::leaks_backing_path;

/// The surface a finding was seen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Surface {
    LoadableArtifact,
    DebugMetadata,
    CompilerEvents,
    GeneratedSource,
    DepInfo,
    PresentationTranscript,
    CargoMetadataHash,
}

/// The hidden-world pattern classes the scanner hunts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenWorld {
    /// Real worktree roots (per-agent checkouts).
    pub worktree_roots: Vec<String>,
    /// User home directories.
    pub user_homes: Vec<String>,
    /// Worker temp/CAS/staging roots (attempt/operation dirs).
    pub staging_roots: Vec<String>,
    /// Host/user names.
    pub identities: Vec<String>,
    /// Secret mount BACKING paths (never the /run/rabs-secrets view).
    pub secret_backing_roots: Vec<String>,
}

/// Finding classification (the bead's seven classes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum LeakClass {
    AdmittedCanonical,
    PresentationOnlyTranslated,
    RemappableDebugMetadata,
    KeyRelevantSemanticLeakage,
    OutputSemanticPathSensitivity,
    PrivacySecretIncident,
    NonCanonicalLaunchEvidence,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakFinding {
    /// Which surface.
    pub surface: Surface,
    /// The classification.
    pub class: LeakClass,
    /// The matched hidden value.
    pub matched: String,
}

/// Disposition after scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDisposition {
    /// Clean (or admitted/translatable only): canonical authority holds.
    CanonicalAuthorityHolds,
    /// Remap required first; shareable after.
    RemapThenShare,
    /// Portable authority LOST: route to the path-preserving lane.
    PathPreservingLane,
    /// Incident: secrets/privacy escaped — quarantine + report.
    Incident,
}

/// Scan one surface's bytes against the hidden world.
#[must_use]
pub fn scan_surface(
    surface: Surface,
    bytes: &[u8],
    hidden: &HiddenWorld,
    canonical_launch_verified: bool,
) -> Vec<LeakFinding> {
    let mut findings = Vec::new();
    let mut check = |patterns: &[String], class_for: &dyn Fn(Surface) -> LeakClass| {
        for pattern in patterns {
            let roots = [pattern.as_str()];
            if leaks_backing_path(bytes, &roots) {
                findings.push(LeakFinding {
                    surface,
                    class: class_for(surface),
                    matched: pattern.clone(),
                });
            }
        }
    };
    // Secret backing paths: ALWAYS an incident, any surface.
    check(&hidden.secret_backing_roots, &|_| {
        LeakClass::PrivacySecretIncident
    });
    // Identities (host/user names): privacy incident on loadable
    // surfaces, remappable in debug metadata, presentation-only in
    // transcripts.
    check(&hidden.identities, &|s| match s {
        Surface::DebugMetadata => LeakClass::RemappableDebugMetadata,
        Surface::PresentationTranscript => LeakClass::PresentationOnlyTranslated,
        _ => LeakClass::PrivacySecretIncident,
    });
    // Worktree/home/staging paths: class depends on the surface.
    for patterns in [
        &hidden.worktree_roots,
        &hidden.user_homes,
        &hidden.staging_roots,
    ] {
        check(patterns, &|s| match s {
            Surface::LoadableArtifact => LeakClass::OutputSemanticPathSensitivity,
            Surface::DebugMetadata => LeakClass::RemappableDebugMetadata,
            Surface::PresentationTranscript => LeakClass::PresentationOnlyTranslated,
            Surface::DepInfo | Surface::GeneratedSource | Surface::CompilerEvents => {
                LeakClass::KeyRelevantSemanticLeakage
            }
            Surface::CargoMetadataHash => LeakClass::NonCanonicalLaunchEvidence,
        });
    }
    // Divergent Cargo metadata hashes: evidence Cargo was not launched
    // canonically, independent of pattern matches.
    if surface == Surface::CargoMetadataHash && !canonical_launch_verified {
        findings.push(LeakFinding {
            surface,
            class: LeakClass::NonCanonicalLaunchEvidence,
            matched: "metadata-hash-divergence".into(),
        });
    }
    findings
}

/// Fold findings into the action's disposition. Worst class wins;
/// ambiguity (any loadable/key-relevant leak) loses portable authority.
#[must_use]
pub fn disposition(findings: &[LeakFinding]) -> ScanDisposition {
    if findings
        .iter()
        .any(|f| f.class == LeakClass::PrivacySecretIncident)
    {
        return ScanDisposition::Incident;
    }
    if findings.iter().any(|f| {
        matches!(
            f.class,
            LeakClass::OutputSemanticPathSensitivity
                | LeakClass::KeyRelevantSemanticLeakage
                | LeakClass::NonCanonicalLaunchEvidence
        )
    }) {
        return ScanDisposition::PathPreservingLane;
    }
    if findings
        .iter()
        .any(|f| f.class == LeakClass::RemappableDebugMetadata)
    {
        return ScanDisposition::RemapThenShare;
    }
    ScanDisposition::CanonicalAuthorityHolds
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hidden() -> HiddenWorld {
        HiddenWorld {
            worktree_roots: vec!["/srv/checkouts/w1".into()],
            user_homes: vec!["/home/devhome".into()],
            staging_roots: vec!["/var/rabs/staging/attempt-8f2c".into()],
            identities: vec!["build-user-9".into(), "buildhost-42".into()],
            secret_backing_roots: vec!["/var/rabs/secret-backing".into()],
        }
    }

    #[test]
    fn seeded_leaks_of_every_class_are_caught() {
        // THE acceptance: one seeded leak per class.
        let cases: Vec<(Surface, &[u8], LeakClass, bool)> = vec![
            (
                Surface::LoadableArtifact,
                b"embedded: /srv/checkouts/w1/src/lib.rs",
                LeakClass::OutputSemanticPathSensitivity,
                true,
            ),
            (
                Surface::DebugMetadata,
                b"DW_AT_comp_dir /srv/checkouts/w1",
                LeakClass::RemappableDebugMetadata,
                true,
            ),
            (
                Surface::DepInfo,
                b"t: /var/rabs/staging/attempt-8f2c/src.rs",
                LeakClass::KeyRelevantSemanticLeakage,
                true,
            ),
            (
                Surface::PresentationTranscript,
                b"error at /srv/checkouts/w1/src/lib.rs:3",
                LeakClass::PresentationOnlyTranslated,
                true,
            ),
            (
                Surface::GeneratedSource,
                b"const P: &str = \"/home/devhome\";",
                LeakClass::KeyRelevantSemanticLeakage,
                true,
            ),
            (
                Surface::LoadableArtifact,
                b"/var/rabs/secret-backing/slot1",
                LeakClass::PrivacySecretIncident,
                true,
            ),
            (
                Surface::CargoMetadataHash,
                b"-Cmetadata=abc123",
                LeakClass::NonCanonicalLaunchEvidence,
                false, // canonical launch NOT verified
            ),
        ];
        for (surface, bytes, expected, canonical) in cases {
            let findings = scan_surface(surface, bytes, &hidden(), canonical);
            assert!(
                findings.iter().any(|f| f.class == expected),
                "{surface:?}: expected {expected:?}, got {findings:?}"
            );
        }
        // Clean canonical bytes on every surface: no findings.
        for surface in [
            Surface::LoadableArtifact,
            Surface::DebugMetadata,
            Surface::DepInfo,
        ] {
            assert!(
                scan_surface(surface, b"/__rabs/workspace/src/lib.rs", &hidden(), true).is_empty()
            );
        }
    }

    #[test]
    fn ambiguous_loadable_leakage_loses_portable_authority() {
        // THE routing rule: loadable/key-relevant leakage -> the
        // path-preserving lane, never a canonical hit.
        let loadable = scan_surface(
            Surface::LoadableArtifact,
            b"/srv/checkouts/w1/data",
            &hidden(),
            true,
        );
        assert_eq!(disposition(&loadable), ScanDisposition::PathPreservingLane);
        // Debug-only: remap then share.
        let debug = scan_surface(
            Surface::DebugMetadata,
            b"/srv/checkouts/w1",
            &hidden(),
            true,
        );
        assert_eq!(disposition(&debug), ScanDisposition::RemapThenShare);
        // Presentation-only: canonical authority holds.
        let transcript = scan_surface(
            Surface::PresentationTranscript,
            b"/srv/checkouts/w1/src/lib.rs:3",
            &hidden(),
            true,
        );
        assert_eq!(
            disposition(&transcript),
            ScanDisposition::CanonicalAuthorityHolds
        );
        // Secrets: incident dominates everything.
        let mixed = [
            scan_surface(
                Surface::DebugMetadata,
                b"/srv/checkouts/w1",
                &hidden(),
                true,
            ),
            scan_surface(
                Surface::LoadableArtifact,
                b"/var/rabs/secret-backing/slot1",
                &hidden(),
                true,
            ),
        ]
        .concat();
        assert_eq!(disposition(&mixed), ScanDisposition::Incident);
    }

    #[test]
    fn username_leaks_classify_by_surface() {
        // A username in loadable bytes is privacy; in debug metadata
        // it is remappable; in a transcript it is presentation.
        let loadable = scan_surface(
            Surface::LoadableArtifact,
            b"user=build-user-9",
            &hidden(),
            true,
        );
        assert!(
            loadable
                .iter()
                .any(|f| f.class == LeakClass::PrivacySecretIncident)
        );
        let debug = scan_surface(
            Surface::DebugMetadata,
            b"built by build-user-9",
            &hidden(),
            true,
        );
        assert!(
            debug
                .iter()
                .any(|f| f.class == LeakClass::RemappableDebugMetadata)
        );
    }
}
