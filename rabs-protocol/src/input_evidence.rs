//! Positive-input / negative-dependency / isolation-evidence schemas
//! (bead E010; invariant I3's input closure; F027's single-owner rule;
//! plan §72; risks R12/R13).
//!
//! Three input categories, DISJOINT by construction:
//!
//! - [`ActionInputManifest`] — POSITIVE facts only: what the action
//!   read, with object identities. No "absent" entry is representable
//!   here.
//! - [`NegativeDependencySet`] — absences and misses: failed opens,
//!   missing paths, listing/glob results (whose future change must
//!   invalidate), PATH lookup misses, dangling symlink targets. No
//!   object identity is representable here — an absence HAS no bytes.
//! - Environment presence/absence lives in F006's
//!   `PresentedEnvironment` ONLY (the F027 single-owner rule): neither
//!   set here has any env-variable field, so duplicating env facts
//!   into filesystem sets is a compile error, not a review comment.
//!
//! [`IsolationEvidenceRecord`] is the fourth schema: what the sandbox
//! ACTUALLY enforced — profiles record enforcement, never aspiration
//! (a requested-but-unenforced control is a `NotEnforced` entry, and
//! the record says so out loud).

use crate::raw_bytes::RawBytes;
use crate::result_identity::ObjectId;

/// Schema version for all four records in this module.
pub const INPUT_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// File type of a positive input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum InputFileType {
    Regular,
    Directory,
    Symlink,
}

/// One positive input: a path that WAS read, with identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositiveInput {
    /// Canonical virtual path (byte-preserving).
    pub virtual_path: RawBytes,
    /// The object actually read.
    pub object: ObjectId,
    /// File type.
    pub file_type: InputFileType,
    /// Executable bit (semantic on unix).
    pub executable: bool,
    /// Symlink target + full resolution chain when `file_type` is
    /// `Symlink` (each hop is itself a semantic fact).
    pub symlink_resolution: Vec<RawBytes>,
}

/// A declared directory with its enumeration RESULT (the listing seen;
/// a later change to the listing invalidates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEnumeration {
    /// The directory path.
    pub virtual_path: RawBytes,
    /// Sorted entry names observed.
    pub entries: Vec<RawBytes>,
}

/// The positive input manifest (versioned).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActionInputManifest {
    /// Schema version.
    pub schema_version: u32,
    /// Files/symlinks actually read.
    pub inputs: Vec<PositiveInput>,
    /// Directories enumerated, with results.
    pub directory_enumerations: Vec<DirectoryEnumeration>,
    /// Approved generated/toolchain-provided objects consumed.
    pub approved_generated_objects: Vec<ObjectId>,
}

/// One negative dependency: an absence whose future presence must miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegativeDependency {
    /// An open() that failed.
    FailedOpen {
        /// The path.
        virtual_path: RawBytes,
    },
    /// A stat/exists probe that found nothing.
    MissingPath {
        /// The path.
        virtual_path: RawBytes,
    },
    /// A glob/listing whose (possibly empty) result set is the fact.
    GlobResult {
        /// The pattern.
        pattern: RawBytes,
        /// Sorted matched names (empty = matched nothing).
        matches: Vec<RawBytes>,
    },
    /// A PATH lookup that missed everywhere, or resolved to a LATER
    /// entry than some missing earlier candidate (the selected
    /// executable is recorded positively in F006's PATH manifest; the
    /// MISSES are the negative facts).
    PathLookupMiss {
        /// The tool name.
        tool: RawBytes,
        /// Directories probed and found not containing it, in order.
        probed_absent: Vec<RawBytes>,
    },
    /// A symlink whose target was missing.
    MissingSymlinkTarget {
        /// The symlink path.
        symlink: RawBytes,
        /// The dangling target.
        target: RawBytes,
    },
}

/// The negative dependency set (versioned).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegativeDependencySet {
    /// Schema version.
    pub schema_version: u32,
    /// The absences.
    pub entries: Vec<NegativeDependency>,
}

/// One isolation control's ACTUAL enforcement state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementState {
    /// Enforced with the named mechanism.
    Enforced {
        /// The mechanism (`"user-ns"`, `"seccomp"`, `"sandbox-exec"`, …).
        mechanism: &'static str,
    },
    /// Requested but NOT enforced (host limitation, permission,
    /// unsupported profile) — recorded loudly, never silently dropped.
    NotEnforced {
        /// Why enforcement failed.
        reason: &'static str,
    },
}

/// What the sandbox actually did (never what it aspired to).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationEvidenceRecord {
    /// Schema version.
    pub schema_version: u32,
    /// Profile name that was REQUESTED.
    pub requested_profile: RawBytes,
    /// Per-control enforcement facts (control name → state).
    pub controls: Vec<(RawBytes, EnforcementState)>,
}

impl IsolationEvidenceRecord {
    /// Whether every control was enforced (full-fidelity isolation).
    #[must_use]
    pub fn fully_enforced(&self) -> bool {
        self.controls
            .iter()
            .all(|(_, s)| matches!(s, EnforcementState::Enforced { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::{DigestAlgorithm, TypedDigest};

    fn object(tag: u8) -> ObjectId {
        ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        })
    }

    fn path(s: &str) -> RawBytes {
        RawBytes::new(s.as_bytes().to_vec())
    }

    #[test]
    fn positive_entries_always_carry_identity_and_negatives_never_can() {
        // The disjointness property, structurally: exhaustively
        // destructure both schemas — every positive row has an ObjectId
        // field; NO negative variant has one (an absence has no bytes).
        let positive = PositiveInput {
            virtual_path: path("/__rabs/src/lib.rs"),
            object: object(1),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: vec![],
        };
        let PositiveInput {
            virtual_path: _,
            object: _, // identity: present by construction
            file_type: _,
            executable: _,
            symlink_resolution: _,
        } = positive;
        // Negative variants: the match proves no ObjectId anywhere.
        let negatives = [
            NegativeDependency::FailedOpen {
                virtual_path: path("/__rabs/cfg.toml"),
            },
            NegativeDependency::MissingPath {
                virtual_path: path("/__rabs/opt.rs"),
            },
            NegativeDependency::GlobResult {
                pattern: path("/__rabs/src/*.rs"),
                matches: vec![path("/__rabs/src/lib.rs")],
            },
            NegativeDependency::PathLookupMiss {
                tool: path("cc"),
                probed_absent: vec![path("/usr/bin"), path("/bin")],
            },
            NegativeDependency::MissingSymlinkTarget {
                symlink: path("/__rabs/link"),
                target: path("/__rabs/gone"),
            },
        ];
        for n in &negatives {
            match n {
                NegativeDependency::FailedOpen { virtual_path: _ }
                | NegativeDependency::MissingPath { virtual_path: _ } => {}
                NegativeDependency::GlobResult {
                    pattern: _,
                    matches: _,
                } => {}
                NegativeDependency::PathLookupMiss {
                    tool: _,
                    probed_absent: _,
                } => {}
                NegativeDependency::MissingSymlinkTarget {
                    symlink: _,
                    target: _,
                } => {}
            }
        }
    }

    #[test]
    fn environment_is_unrepresentable_in_filesystem_sets() {
        // F027 single-owner proof: ActionInputManifest and
        // NegativeDependencySet have no env-variable field of any kind;
        // exhaustive destructure trips on any future addition, forcing
        // the F027 decision instead of silent duplication.
        let ActionInputManifest {
            schema_version: _,
            inputs: _,
            directory_enumerations: _,
            approved_generated_objects: _,
        } = ActionInputManifest::default();
        let NegativeDependencySet {
            schema_version: _,
            entries: _,
        } = NegativeDependencySet::default();
        // PresentedEnvironment (rabs-key F006) is the sole owner of env
        // presence/absence — its own tests prove absence-keying there.
    }

    #[test]
    fn empty_glob_results_are_facts_not_omissions() {
        // A glob matching nothing is a NEGATIVE fact whose future match
        // must invalidate — representable and distinct from not having
        // globbed at all.
        let empty = NegativeDependency::GlobResult {
            pattern: path("/__rabs/benches/*.rs"),
            matches: vec![],
        };
        let one = NegativeDependency::GlobResult {
            pattern: path("/__rabs/benches/*.rs"),
            matches: vec![path("/__rabs/benches/a.rs")],
        };
        assert_ne!(empty, one);
    }

    #[test]
    fn isolation_evidence_records_enforcement_not_aspiration() {
        let record = IsolationEvidenceRecord {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            requested_profile: path("strict-hermetic-linux"),
            controls: vec![
                (
                    path("network-deny"),
                    EnforcementState::Enforced { mechanism: "netns" },
                ),
                (
                    path("cgroup-memory"),
                    EnforcementState::NotEnforced {
                        reason: "cgroup v2 delegation unavailable",
                    },
                ),
            ],
        };
        // The requested profile is present, but fidelity is judged on
        // the per-control FACTS: one unenforced control = not fully
        // enforced, loudly.
        assert!(!record.fully_enforced());
        let full = IsolationEvidenceRecord {
            controls: vec![(
                path("network-deny"),
                EnforcementState::Enforced { mechanism: "netns" },
            )],
            ..record
        };
        assert!(full.fully_enforced());
    }

    #[test]
    fn schemas_are_versioned() {
        assert_eq!(INPUT_EVIDENCE_SCHEMA_VERSION, 1);
        let m = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            ..Default::default()
        };
        assert_eq!(m.schema_version, 1);
    }
}
