//! Manifest path/type/case/symlink validation (bead H027; plan §92;
//! risk R75; fuzz family T021).
//!
//! A manifest is attacker-shaped data: it may arrive from any worker
//! and will be MATERIALIZED onto real filesystems. Validation runs
//! BEFORE storage and again before materialization, and the default is
//! rejection — every admitted shape is an explicit rule:
//!
//! - member paths must be relative, `..`-free, NUL-free, non-empty;
//! - duplicates reject, including PLATFORM-EQUIVALENT collisions: two
//!   members differing only by ASCII case or by Unicode NFC/NFD
//!   spelling collide on case-insensitive/normalizing filesystems and
//!   would silently overwrite each other (the D022 class says which
//!   hosts — validation rejects the manifest for ALL of them, because
//!   a manifest that materializes differently per host is not one
//!   object);
//! - symlink targets must stay inside the manifest root (no absolute
//!   targets, no `..` escapes);
//! - hardlinks only to DECLARED earlier members;
//! - device/socket/FIFO/special nodes reject unless the action class
//!   explicitly defined safe handling (none do today).

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
    DuplicatePath(String),
    CaseEquivalentCollision(String, String),
    UnicodeEquivalentCollision(String, String),
    SymlinkEscape { link: String, target: String },
    UndeclaredHardlinkTarget { link: String, to: String },
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

/// Validate a manifest member list. First violation rejects.
///
/// # Errors
/// The first [`ManifestViolation`] encountered.
pub fn validate_manifest(members: &[ManifestMember]) -> Result<(), ManifestViolation> {
    let mut seen_exact: Vec<&str> = Vec::new();
    let mut seen_equivalent: Vec<(String, &str)> = Vec::new();
    for member in members {
        let path = member.path.as_str();
        if path.is_empty() {
            return Err(ManifestViolation::EmptyPath);
        }
        if path.starts_with('/') {
            return Err(ManifestViolation::AbsolutePath(path.into()));
        }
        if path.contains('\0') {
            return Err(ManifestViolation::NulByte(path.into()));
        }
        if path.split('/').any(|c| c == "..") {
            return Err(ManifestViolation::DotDotComponent(path.into()));
        }
        if seen_exact.contains(&path) {
            return Err(ManifestViolation::DuplicatePath(path.into()));
        }
        let key = equivalence_key(path);
        if let Some((_, prior)) = seen_equivalent.iter().find(|(k, _)| *k == key) {
            // Distinguish the diagnosis: pure-ASCII case twins vs
            // Unicode-normalization twins.
            return Err(if prior.eq_ignore_ascii_case(path) {
                ManifestViolation::CaseEquivalentCollision((*prior).into(), path.into())
            } else {
                ManifestViolation::UnicodeEquivalentCollision((*prior).into(), path.into())
            });
        }
        match &member.kind {
            ManifestMemberKind::File | ManifestMemberKind::Directory => {}
            ManifestMemberKind::Symlink { target } => {
                if target.starts_with('/') || symlink_escapes(path, target) {
                    return Err(ManifestViolation::SymlinkEscape {
                        link: path.into(),
                        target: target.clone(),
                    });
                }
            }
            ManifestMemberKind::Hardlink { to } => {
                if !seen_exact.contains(&to.as_str()) {
                    return Err(ManifestViolation::UndeclaredHardlinkTarget {
                        link: path.into(),
                        to: to.clone(),
                    });
                }
            }
            ManifestMemberKind::SpecialNode => {
                // No action class defines safe handling today.
                return Err(ManifestViolation::SpecialNodeRejected(path.into()));
            }
        }
        seen_exact.push(path);
        seen_equivalent.push((key, path));
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
