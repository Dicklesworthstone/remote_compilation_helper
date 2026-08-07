//! Binary dep-info integration (bead E007; plan §72; extends E006).
//!
//! Nightly rustc can emit BINARY dependency info
//! (`-Zbinary-dep-depinfo`): the dep-info file then also names the
//! compiled artifacts the build consumed — rlibs, proc-macro dylibs,
//! host tools — not just source files. That is exactly the extra
//! evidence the proc-macro/host-tool closure needs (a macro dylib the
//! textual dep-info never mentions shows up here). Rules:
//!
//! - binary entries MERGE into the E006 evidence, classified by
//!   artifact kind so the observed-input cross-checks (E011) can
//!   distinguish source reads from artifact consumption;
//! - **absence is graceful**: on toolchains without the flag the merge
//!   is a no-op with an explicit `BinaryDepInfoSupport::NotEmitted`
//!   marker — never an error, never a fabricated claim that binary
//!   coverage exists when it does not.

use crate::dep_info::{DepInfoError, DepInfoEvidence, parse_dep_info};

/// Whether the toolchain emitted binary dep-info for this action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryDepInfoSupport {
    /// The toolchain emitted binary entries (they are in the merge).
    Emitted,
    /// Not supported/enabled: the merge is textual-only, and the
    /// evidence says so — no claim of binary coverage exists.
    NotEmitted,
}

/// Classification of one merged entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// Source file (textual dep-info).
    Source,
    /// Compiled artifact (binary dep-info: rlib/rmeta/dylib/tool).
    BinaryArtifact,
}

/// One merged evidence entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedEntry {
    /// Canonical virtual path.
    pub virtual_path: String,
    /// Object identity.
    pub object: rabs_protocol::result_identity::ObjectId,
    /// Which stream it came from.
    pub kind: EvidenceKind,
}

/// The merged evidence with its support marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedDepInfo {
    /// Whether binary coverage exists.
    pub support: BinaryDepInfoSupport,
    /// All entries, source first then binary, deduplicated by path
    /// (a path in both streams keeps the BinaryArtifact class — the
    /// stronger fact).
    pub entries: Vec<MergedEntry>,
}

/// Classify a path as artifact-shaped (binary dep-info names compiled
/// outputs; extension is a heuristic for the CLASS tag only — identity
/// always comes from content digests).
fn artifact_shaped(path: &str) -> bool {
    [".rlib", ".rmeta", ".so", ".dylib", ".dll", ".a"]
        .iter()
        .any(|ext| path.ends_with(ext))
}

/// Merge textual evidence with an optional binary dep-info file.
///
/// `binary_content` is `None` on toolchains without the flag — the
/// graceful-absence path.
///
/// # Errors
/// Propagates [`DepInfoError`] from parsing either stream.
pub fn merge_dep_info(
    textual: &DepInfoEvidence,
    binary_content: Option<&str>,
    virtualize: impl Fn(&str) -> Option<String>,
    identify: impl Fn(&str) -> Option<rabs_protocol::result_identity::ObjectId>,
) -> Result<MergedDepInfo, DepInfoError> {
    let mut entries: Vec<MergedEntry> = textual
        .entries
        .iter()
        .map(|e| MergedEntry {
            virtual_path: e.virtual_path.clone(),
            object: e.object.clone(),
            kind: EvidenceKind::Source,
        })
        .collect();
    let support = match binary_content {
        None => BinaryDepInfoSupport::NotEmitted,
        Some(content) => {
            let binary = parse_dep_info(content, virtualize, identify)?;
            for entry in binary.entries {
                let kind = if artifact_shaped(&entry.virtual_path) {
                    EvidenceKind::BinaryArtifact
                } else {
                    EvidenceKind::Source
                };
                match entries
                    .iter_mut()
                    .find(|e| e.virtual_path == entry.virtual_path)
                {
                    Some(existing) => {
                        // The binary stream's artifact fact is stronger.
                        if kind == EvidenceKind::BinaryArtifact {
                            existing.kind = EvidenceKind::BinaryArtifact;
                        }
                    }
                    None => entries.push(MergedEntry {
                        virtual_path: entry.virtual_path,
                        object: entry.object,
                        kind,
                    }),
                }
            }
            BinaryDepInfoSupport::Emitted
        }
    };
    Ok(MergedDepInfo { support, entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};

    fn object(tag: u8) -> ObjectId {
        ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        })
    }

    fn virtualize(path: &str) -> Option<String> {
        path.strip_prefix("/w/")
            .map(|rest| format!("/__rabs/ws/{rest}"))
    }

    fn identify(vpath: &str) -> Option<ObjectId> {
        match vpath {
            "/__rabs/ws/src/lib.rs" => Some(object(1)),
            "/__rabs/ws/deps/libserde.rlib" => Some(object(2)),
            "/__rabs/ws/deps/libmacros.so" => Some(object(3)),
            _ => None,
        }
    }

    fn textual() -> DepInfoEvidence {
        crate::dep_info::parse_dep_info("t: /w/src/lib.rs\n", virtualize, identify).unwrap()
    }

    #[test]
    fn binary_entries_merge_as_artifact_evidence() {
        // THE acceptance: binary dep-info adds the proc-macro dylib and
        // rlib the textual stream never mentions, classified as
        // artifacts.
        let binary = "t: /w/src/lib.rs /w/deps/libserde.rlib /w/deps/libmacros.so\n";
        let merged = merge_dep_info(&textual(), Some(binary), virtualize, identify).unwrap();
        assert_eq!(merged.support, BinaryDepInfoSupport::Emitted);
        assert_eq!(merged.entries.len(), 3, "deduplicated by path");
        let kinds: Vec<(&str, EvidenceKind)> = merged
            .entries
            .iter()
            .map(|e| (e.virtual_path.as_str(), e.kind))
            .collect();
        assert!(kinds.contains(&("/__rabs/ws/src/lib.rs", EvidenceKind::Source)));
        assert!(kinds.contains(&(
            "/__rabs/ws/deps/libserde.rlib",
            EvidenceKind::BinaryArtifact
        )));
        assert!(kinds.contains(&("/__rabs/ws/deps/libmacros.so", EvidenceKind::BinaryArtifact)));
    }

    #[test]
    fn absence_is_graceful_and_makes_no_coverage_claim() {
        // THE acceptance's second half: no binary dep-info — merge is
        // the textual evidence with an EXPLICIT NotEmitted marker; no
        // error, and nothing claims binary coverage exists.
        let merged = merge_dep_info(&textual(), None, virtualize, identify).unwrap();
        assert_eq!(merged.support, BinaryDepInfoSupport::NotEmitted);
        assert_eq!(merged.entries.len(), 1);
        assert_eq!(merged.entries[0].kind, EvidenceKind::Source);
    }

    #[test]
    fn parse_errors_in_the_binary_stream_propagate() {
        // A binary stream naming an unidentifiable artifact is a HARD
        // error (same E006 rule — no silent drops).
        let bad = "t: /w/deps/libghost.rlib\n";
        assert!(merge_dep_info(&textual(), Some(bad), virtualize, identify).is_err());
    }
}
