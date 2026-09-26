//! Manifest path/type/case/symlink validation (bead H027; plan §92;
//! risk R75; fuzz family T021).
//!
//! A manifest is attacker-shaped data: it may arrive from any worker
//! and will be MATERIALIZED onto real filesystems. Validation runs
//! BEFORE storage and again before materialization, and the default is
//! rejection — every admitted shape is an explicit rule:
//!
//! - member paths must be relative, canonical, NUL-free, non-empty;
//! - duplicates reject, including PLATFORM-EQUIVALENT collisions: two
//!   members differing only by ASCII case or by Unicode NFC/NFD
//!   spelling collide on case-insensitive/normalizing filesystems and
//!   would silently overwrite each other (the D022 class says which
//!   hosts — validation rejects the manifest for ALL of them, because
//!   a manifest that materializes differently per host is not one
//!   object);
//! - symlink targets must stay inside the manifest root (no absolute
//!   targets, no `..` escapes);
//! - implicit directories participate in collision checks, and no member
//!   may be installed beneath a file, hardlink, or symlink;
//! - hardlinks only to DECLARED earlier regular files or hardlink chains
//!   already proven to terminate at a regular file;
//! - device/socket/FIFO/special nodes reject unless the action class
//!   explicitly defined safe handling (none do today).

use std::collections::BTreeMap;

/// Member kinds a manifest may declare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestMemberKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symlink with its target as given.
    Symlink {
        /// Link target string.
        target: String,
    },
    /// Hardlink to an earlier member path.
    Hardlink {
        /// The earlier member this links to.
        to: String,
    },
    /// Device/socket/FIFO/other special node.
    SpecialNode,
}

/// One manifest member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestMember {
    /// Member path (must be relative, clean).
    pub path: String,
    /// Kind.
    pub kind: ManifestMemberKind,
}

/// Rejection causes (each names the R75 rule that fired).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ManifestViolation {
    AbsolutePath(String),
    DotDotComponent(String),
    NulByte(String),
    EmptyPath,
    NonCanonicalPath(String),
    NonPortablePath(String),
    DuplicatePath(String),
    CaseEquivalentCollision(String, String),
    UnicodeEquivalentCollision(String, String),
    SymlinkEscape { link: String, target: String },
    InvalidSymlinkTarget { link: String, target: String },
    UndeclaredHardlinkTarget { link: String, to: String },
    InvalidHardlinkTarget { link: String, to: String },
    NonDirectoryAncestor { ancestor: String, member: String },
    SpecialNodeRejected(String),
}

/// Case/Unicode-equivalence key: ASCII-lowercased, NFC/NFD-insensitive
/// (approximated here by stripping combining marks after lowercase —
/// conservative: two paths that MIGHT collide on some platform
/// collide here).
fn equivalence_key(path: &str) -> String {
    /// Latin-1/Latin-Extended precomposed letters fold to their ASCII
    /// base so NFC spellings meet their NFD twins (which lose their
    /// combining marks below) on one key.
    fn fold_base(c: char) -> char {
        match c {
            '\u{e0}'..='\u{e5}' | '\u{101}' | '\u{103}' | '\u{105}' => 'a',
            '\u{e7}' | '\u{107}' | '\u{10d}' => 'c',
            '\u{e8}'..='\u{eb}' | '\u{113}' | '\u{117}' | '\u{119}' => 'e',
            '\u{ec}'..='\u{ef}' | '\u{12b}' | '\u{131}' => 'i',
            '\u{f1}' | '\u{144}' => 'n',
            '\u{f2}'..='\u{f6}' | '\u{14d}' | '\u{151}' => 'o',
            '\u{f9}'..='\u{fc}' | '\u{16b}' | '\u{171}' => 'u',
            '\u{fd}' | '\u{ff}' => 'y',
            '\u{17a}' | '\u{17c}' | '\u{17e}' => 'z',
            '\u{15b}' | '\u{161}' => 's',
            other => other,
        }
    }
    path.chars()
        .filter(|c| {
            // Drop combining diacritical marks (U+0300..U+036F): NFD
            // spellings reduce to their base sequence.
            !('\u{0300}'..='\u{036F}').contains(c)
        })
        .flat_map(char::to_lowercase)
        .map(fold_base)
        .collect()
}

/// Whether a symlink target escapes the manifest root.
fn symlink_escapes(member_path: &str, target: &str) -> bool {
    if target.starts_with('/') {
        return true;
    }
    // Resolve the target relative to the member's parent directory,
    // counting depth; going below the root is an escape.
    let mut depth: i64 = member_path.split('/').count() as i64 - 1;
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// Reject aliases rather than normalizing attacker-controlled paths. In
/// particular, normalization must not hide which filesystem name is written.
fn validate_member_path(path: &str) -> Result<(), ManifestViolation> {
    if path.is_empty() {
        return Err(ManifestViolation::EmptyPath);
    }
    if path.starts_with('/') {
        return Err(ManifestViolation::AbsolutePath(path.into()));
    }
    if path.contains('\0') {
        return Err(ManifestViolation::NulByte(path.into()));
    }
    if path.split('/').any(|component| component == "..") {
        return Err(ManifestViolation::DotDotComponent(path.into()));
    }
    if path.split('/').any(|component| component.is_empty() || component == ".") {
        return Err(ManifestViolation::NonCanonicalPath(path.into()));
    }
    // The wire namespace uses slash separators, never host-specific drive,
    // alternate-data-stream, UNC, or backslash traversal syntax.
    if path.contains(['\\', ':']) {
        return Err(ManifestViolation::NonPortablePath(path.into()));
    }
    Ok(())
}

fn equivalent_collision(prior: &str, path: &str) -> ManifestViolation {
    if prior.eq_ignore_ascii_case(path) {
        ManifestViolation::CaseEquivalentCollision(prior.into(), path.into())
    } else {
        ManifestViolation::UnicodeEquivalentCollision(prior.into(), path.into())
    }
}

/// Validate a manifest member list. First violation rejects.
///
/// Directory declarations need not precede their children. The complete
/// namespace is checked before returning, including directories implied by
/// a child's path. Hardlink targets, unlike directories, must precede the link.
///
/// # Errors
/// The first [`ManifestViolation`] encountered.
pub fn validate_manifest(members: &[ManifestMember]) -> Result<(), ManifestViolation> {
    let mut seen_exact: BTreeMap<&str, &ManifestMemberKind> = BTreeMap::new();
    let mut seen_equivalent: BTreeMap<String, &str> = BTreeMap::new();
    for member in members {
        let path = member.path.as_str();
        validate_member_path(path)?;
        if seen_exact.contains_key(path) {
            return Err(ManifestViolation::DuplicatePath(path.into()));
        }
        // Include every implied directory. Merely comparing full paths
        // misses `Out/a` versus `out/b`, whose directory topology differs
        // between case-sensitive and case-insensitive filesystems.
        for end in path.match_indices('/').map(|(at, _)| at).chain([path.len()]) {
            let prefix = &path[..end];
            let key = equivalence_key(prefix);
            if let Some(prior) = seen_equivalent.get(&key) {
                if *prior != prefix {
                    return Err(equivalent_collision(prior, prefix));
                }
            } else {
                seen_equivalent.insert(key, prefix);
            }
        }
        match &member.kind {
            ManifestMemberKind::File | ManifestMemberKind::Directory => {}
            ManifestMemberKind::Symlink { target } => {
                if target.is_empty() || target.contains(['\0', '\\', ':']) {
                    return Err(ManifestViolation::InvalidSymlinkTarget {
                        link: path.into(),
                        target: target.clone(),
                    });
                }
                if target.starts_with('/') || symlink_escapes(path, target) {
                    return Err(ManifestViolation::SymlinkEscape {
                        link: path.into(),
                        target: target.clone(),
                    });
                }
            }
            ManifestMemberKind::Hardlink { to } => {
                match seen_exact.get(to.as_str()).copied() {
                    // Each earlier hardlink has already passed this check,
                    // so a chain always terminates at a regular file.
                    Some(ManifestMemberKind::File | ManifestMemberKind::Hardlink { .. }) => {}
                    Some(_) => {
                        return Err(ManifestViolation::InvalidHardlinkTarget {
                            link: path.into(),
                            to: to.clone(),
                        });
                    }
                    None => {
                        return Err(ManifestViolation::UndeclaredHardlinkTarget {
                            link: path.into(),
                            to: to.clone(),
                        });
                    }
                }
            }
            ManifestMemberKind::SpecialNode => {
                // No action class defines safe handling today.
                return Err(ManifestViolation::SpecialNodeRejected(path.into()));
            }
        }
        seen_exact.insert(path, &member.kind);
    }
    // Check after collecting ALL members, so reversing declaration order
    // cannot hide a file or symlink that is also somebody else's parent.
    for member in members {
        for (end, _) in member.path.match_indices('/') {
            let ancestor = &member.path[..end];
            if let Some(kind) = seen_exact.get(ancestor).copied()
                && !matches!(kind, ManifestMemberKind::Directory)
            {
                return Err(ManifestViolation::NonDirectoryAncestor {
                    ancestor: ancestor.into(),
                    member: member.path.clone(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> ManifestMember {
        ManifestMember {
            path: path.into(),
            kind: ManifestMemberKind::File,
        }
    }

    fn directory(path: &str) -> ManifestMember {
        ManifestMember {
            path: path.into(),
            kind: ManifestMemberKind::Directory,
        }
    }

    fn symlink(path: &str, target: &str) -> ManifestMember {
        ManifestMember {
            path: path.into(),
            kind: ManifestMemberKind::Symlink { target: target.into() },
        }
    }

    fn hardlink(path: &str, to: &str) -> ManifestMember {
        ManifestMember {
            path: path.into(),
            kind: ManifestMemberKind::Hardlink { to: to.into() },
        }
    }

    #[test]
    fn noncanonical_member_names_cannot_alias_filesystem_paths() {
        for path in [".", "./out", "out/.", "out/./lib", "out//lib", "out/"] {
            assert_eq!(
                validate_manifest(&[file(path)]),
                Err(ManifestViolation::NonCanonicalPath(path.into())),
                "accepted ambiguous member {path:?}"
            );
        }
    }

    #[test]
    fn host_specific_member_names_are_not_wire_paths() {
        for path in ["C:/escape", "C:escape", "out/stream:data", "out\\..\\escape", "\\\\host\\share"] {
            assert_eq!(
                validate_manifest(&[file(path)]),
                Err(ManifestViolation::NonPortablePath(path.into())),
                "accepted host-specific member {path:?}"
            );
        }
    }

    #[test]
    fn empty_nul_and_host_specific_symlink_targets_are_refused() {
        for target in ["", "a\0b", "C:/outside", "C:outside", "..\\outside"] {
            assert_eq!(
                validate_manifest(&[symlink("link", target)]),
                Err(ManifestViolation::InvalidSymlinkTarget {
                    link: "link".into(),
                    target: target.into(),
                }),
            );
        }
    }

    #[test]
    fn implicit_directory_aliases_are_rejected_even_with_different_leaf_names() {
        assert_eq!(
            validate_manifest(&[file("Out/a"), file("out/b")]),
            Err(ManifestViolation::CaseEquivalentCollision("Out".into(), "out".into())),
        );
        assert_eq!(
            validate_manifest(&[file("caf\u{e9}/a"), file("cafe\u{301}/b")]),
            Err(ManifestViolation::UnicodeEquivalentCollision(
                "caf\u{e9}".into(), "cafe\u{301}".into(),
            )),
        );
        assert!(matches!(
            validate_manifest(&[file("Out/a"), directory("out")]),
            Err(ManifestViolation::CaseEquivalentCollision(_, _))
        ));
    }

    #[test]
    fn members_cannot_be_written_through_non_directory_ancestors_in_either_order() {
        for parent in [file("out"), symlink("out", "other")] {
            for members in [
                vec![parent.clone(), file("out/nested/artifact")],
                vec![file("out/nested/artifact"), parent.clone()],
            ] {
                assert_eq!(
                    validate_manifest(&members),
                    Err(ManifestViolation::NonDirectoryAncestor {
                        ancestor: "out".into(),
                        member: "out/nested/artifact".into(),
                    }),
                );
            }
        }
        assert!(matches!(
            validate_manifest(&[file("source"), hardlink("out", "source"), file("out/child")]),
            Err(ManifestViolation::NonDirectoryAncestor { .. })
        ));
    }

    #[test]
    fn explicit_directories_may_follow_their_children() {
        assert_eq!(
            validate_manifest(&[
                file("out/a/artifact"),
                directory("out/a"),
                directory("out"),
                file("output"),
            ]),
            Ok(())
        );
    }

    #[test]
    fn hardlinks_require_an_earlier_regular_file_or_a_validated_chain() {
        assert_eq!(
            validate_manifest(&[
                file("original"),
                hardlink("alias", "original"),
                hardlink("alias2", "alias"),
            ]),
            Ok(())
        );
        for target in [directory("target"), symlink("target", "missing")] {
            assert_eq!(
                validate_manifest(&[target, hardlink("alias", "target")]),
                Err(ManifestViolation::InvalidHardlinkTarget {
                    link: "alias".into(), to: "target".into(),
                }),
            );
        }
        assert!(matches!(
            validate_manifest(&[hardlink("alias", "later"), file("later")]),
            Err(ManifestViolation::UndeclaredHardlinkTarget { .. })
        ));
    }

    #[test]
    fn large_flat_manifests_validate_without_pairwise_member_scans() {
        let members: Vec<_> = (0..10_000)
            .map(|index| file(&format!("out/artifact_{index}")))
            .collect();
        assert_eq!(validate_manifest(&members), Ok(()));
    }

    #[test]
    fn clean_manifests_validate() {
        let ok = vec![
            ManifestMember {
                path: "out".into(),
                kind: ManifestMemberKind::Directory,
            },
            file("out/libx.rlib"),
            ManifestMember {
                path: "out/alias.rlib".into(),
                kind: ManifestMemberKind::Hardlink {
                    to: "out/libx.rlib".into(),
                },
            },
            ManifestMember {
                path: "out/link".into(),
                kind: ManifestMemberKind::Symlink {
                    target: "libx.rlib".into(),
                },
            },
        ];
        assert_eq!(validate_manifest(&ok), Ok(()));
    }

    type ExpectedViolation = fn(&ManifestViolation) -> bool;

    #[test]
    fn malicious_manifest_corpus_fully_rejected() {
        // THE T021 corpus: every hostile shape from the bead list.
        let cases: Vec<(ManifestMember, ExpectedViolation)> = vec![
            (file("/etc/passwd"), |v| {
                matches!(v, ManifestViolation::AbsolutePath(_))
            }),
            (file("out/../../escape"), |v| {
                matches!(v, ManifestViolation::DotDotComponent(_))
            }),
            (file("out/nul\0byte"), |v| {
                matches!(v, ManifestViolation::NulByte(_))
            }),
            (file(""), |v| matches!(v, ManifestViolation::EmptyPath)),
            (
                ManifestMember {
                    path: "dev/null".into(),
                    kind: ManifestMemberKind::SpecialNode,
                },
                |v| matches!(v, ManifestViolation::SpecialNodeRejected(_)),
            ),
            (
                ManifestMember {
                    path: "out/evil".into(),
                    kind: ManifestMemberKind::Symlink {
                        target: "/etc/passwd".into(),
                    },
                },
                |v| matches!(v, ManifestViolation::SymlinkEscape { .. }),
            ),
            (
                ManifestMember {
                    path: "out/evil".into(),
                    kind: ManifestMemberKind::Symlink {
                        target: "../../outside".into(),
                    },
                },
                |v| matches!(v, ManifestViolation::SymlinkEscape { .. }),
            ),
            (
                ManifestMember {
                    path: "out/link".into(),
                    kind: ManifestMemberKind::Hardlink {
                        to: "never/declared".into(),
                    },
                },
                |v| matches!(v, ManifestViolation::UndeclaredHardlinkTarget { .. }),
            ),
        ];
        for (hostile, expect) in cases {
            let err = validate_manifest(std::slice::from_ref(&hostile)).unwrap_err();
            assert!(expect(&err), "{hostile:?} produced {err:?}");
        }
    }

    #[test]
    fn duplicate_and_platform_equivalent_collisions_reject() {
        // Exact duplicate.
        assert!(matches!(
            validate_manifest(&[file("out/a"), file("out/a")]),
            Err(ManifestViolation::DuplicatePath(_))
        ));
        // ASCII case twins: collide on case-insensitive hosts.
        assert!(matches!(
            validate_manifest(&[file("out/Lib.rs"), file("out/lib.rs")]),
            Err(ManifestViolation::CaseEquivalentCollision(_, _))
        ));
        // Unicode NFC vs NFD twins: e-acute composed vs decomposed.
        assert!(matches!(
            validate_manifest(&[file("out/caf\u{e9}"), file("out/cafe\u{301}")]),
            Err(ManifestViolation::UnicodeEquivalentCollision(_, _))
        ));
    }

    #[test]
    fn symlinks_may_navigate_within_but_never_below_the_root() {
        // In-tree relative navigation is fine.
        let ok = vec![ManifestMember {
            path: "a/b/link".into(),
            kind: ManifestMemberKind::Symlink {
                target: "../../top.txt".into(),
            },
        }];
        assert_eq!(validate_manifest(&ok), Ok(()));
        // One level deeper than the root: escape.
        let escape = vec![ManifestMember {
            path: "a/link".into(),
            kind: ManifestMemberKind::Symlink {
                target: "../../outside".into(),
            },
        }];
        assert!(matches!(
            validate_manifest(&escape),
            Err(ManifestViolation::SymlinkEscape { .. })
        ));
    }
}
