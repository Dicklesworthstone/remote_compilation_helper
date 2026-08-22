//! Generated output manifest schema (bead N003; plan §196 Epic N;
//! consumes the C007/K006 capture surface's run layout).
//!
//! One build-script run produces TWO durable file surfaces:
//!
//! - **OUT_DIR** (`<run>/out/`): everything the script generated;
//! - **Cargo output cache** (`output`, `stderr`, `root-output`,
//!   `invoked.timestamp` at the run root — vintage spellings vary; see
//!   `rabs-wrap/tests/n001_contract.rs` for the measured table).
//!
//! [`OutputTreeManifest`] records both as SORTED, path-unique entry
//! lists. This crate defines the SCHEMA and the tombstone diff; walking
//! real filesystems stays with callers (no fs effects here — same
//! dependency-direction law as every module in this crate).
//!
//! ## Tombstones and the deletion case
//!
//! Cargo does NOT manage OUT_DIR contents: a file a later observation
//! no longer sees is genuinely GONE (deleted by tooling, or never
//! restored after a crash). [`diff_manifests`] therefore treats any
//! before-present/after-absent path as an explicit
//! [`OutputEntryKind::Tombstone`] — deletions are first-class rows, not
//! silent absences (N010's failed-run parity policy consumes this).
//!
//! ## Content identity boundary
//!
//! V1 entries carry path + length only. Byte-level equality binding
//! (content digests) lands where hashing lives — the CAS/storage layer
//! hashes each file under its own domain and extends entries there;
//! presence-diff semantics here are already complete for the
//! deletion/tombstone acceptance.

/// Schema version for the output tree manifest.
pub const OUTPUT_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Upper bound on manifest entries per section.
pub const MAX_OUTPUT_ENTRIES: usize = 16384;

/// One recorded path in a tree section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputEntry {
    /// Relative path, `/`-separated, canonical byte form (never a
    /// platform separator; `..` components are unrepresentable by
    /// construction of the walker contract).
    pub path: Vec<u8>,
    /// File length in bytes at capture time.
    pub len: u64,
}

impl OutputEntry {
    /// Build one entry.
    #[must_use]
    pub fn new(path: impl Into<Vec<u8>>, len: u64) -> Self {
        Self {
            path: path.into(),
            len,
        }
    }
}

/// Which section an entry came from / belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputSection {
    /// The build script's OUT_DIR tree.
    OutDir,
    /// Cargo's own output-cache files at the run root.
    OutputCache,
}

/// A manifest presence state used by diffs: present rows carry their
/// capture-time length; removed paths become explicit tombstones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputEntryKind {
    /// Present at capture time.
    Present,
    /// Absent in the newer manifest relative to an older one.
    Tombstone,
}

/// The complete post-run output manifest for one build-script run:
/// OUT_DIR tree plus cargo's output-cache files, each section sorted by
/// path, paths unique within the section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputTreeManifest {
    /// Schema version ([`OUTPUT_MANIFEST_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// OUT_DIR entries, ascending by path.
    pub out_dir_entries: Vec<OutputEntry>,
    /// Output-cache entries, ascending by path (paths are the cache
    /// file names, e.g. `output`, `run/stdout`, `invoked.timestamp`).
    pub cache_entries: Vec<OutputEntry>,
}

/// Typed validation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestValidationError {
    /// Entries must ascend by path.
    UnsortedEntries(OutputSection),
    /// Duplicate paths within one section.
    DuplicatePath(OutputSection),
    /// Bounded-envelope overflow.
    TooManyEntries(OutputSection),
}

impl OutputTreeManifest {
    /// Construct + validate a manifest from caller-walked sections (the
    /// caller owns filesystem traversal; this owns structural law).
    ///
    /// # Errors
    /// [`ManifestValidationError`] naming the offending section.
    pub fn new(
        out_dir_entries: Vec<OutputEntry>,
        cache_entries: Vec<OutputEntry>,
    ) -> Result<Self, ManifestValidationError> {
        validate_section(&out_dir_entries, OutputSection::OutDir)?;
        validate_section(&cache_entries, OutputSection::OutputCache)?;
        Ok(Self {
            schema_version: OUTPUT_MANIFEST_SCHEMA_VERSION,
            out_dir_entries,
            cache_entries,
        })
    }

    /// All paths of one section, ascending (already validated).
    #[must_use]
    pub fn section(&self, section: OutputSection) -> &[OutputEntry] {
        match section {
            OutputSection::OutDir => &self.out_dir_entries,
            OutputSection::OutputCache => &self.cache_entries,
        }
    }
}

fn validate_section(
    entries: &[OutputEntry],
    section: OutputSection,
) -> Result<(), ManifestValidationError> {
    if entries.len() > MAX_OUTPUT_ENTRIES {
        return Err(ManifestValidationError::TooManyEntries(section));
    }
    for pair in entries.windows(2) {
        match pair[0].path.cmp(&pair[1].path) {
            std::cmp::Ordering::Greater => {
                return Err(ManifestValidationError::UnsortedEntries(section));
            }
            std::cmp::Ordering::Equal => {
                return Err(ManifestValidationError::DuplicatePath(section));
            }
            std::cmp::Ordering::Less => {}
        }
    }
    Ok(())
}

/// One row of a between-manifests diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeDeltaRow {
    /// Path appeared in the newer manifest.
    Added {
        /// The new entry.
        entry: OutputEntry,
        /// Which section changed.
        section: OutputSection,
    },
    /// Path vanished: FIRST-CLASS TOMBSTONE (deletions are recorded,
    /// never implied).
    Removed {
        /// The old entry (last observed length).
        last_entry: OutputEntry,
        /// Which section lost it.
        section: OutputSection,
    },
    /// Same path, different length on the newer capture. (Byte-level
    /// equality needs content digests — storage-layer extension; length
    /// change is the V1 observable.)
    LengthChanged {
        /// The new entry.
        new_entry: OutputEntry,
        /// The previous length.
        previous_len: u64,
        /// Which section changed.
        section: OutputSection,
    },
}

/// Structural delta between two captures of the SAME run's surfaces.
///
/// Deterministic and order-stable: rows are emitted section-by-section
/// (OutDir first), each section's rows sorted by path — Added/Modified
/// interleaved by path order, then all Removed tombstones. Nothing is
/// inferred beyond presence and length: absence of a row means the path
/// was present in both manifests with equal length.
///
/// # Errors
/// Propagates section validation from either side — diffing corrupt
/// manifests would silently misreport deletions.
pub fn diff_manifests(
    before: &OutputTreeManifest,
    after: &OutputTreeManifest,
) -> Result<Vec<TreeDeltaRow>, ManifestValidationError> {
    // Re-validate both sides so a corrupted input cannot fabricate
    // phantom additions or hide real tombstones.
    validate_section(&before.out_dir_entries, OutputSection::OutDir)?;
    validate_section(&before.cache_entries, OutputSection::OutputCache)?;
    validate_section(&after.out_dir_entries, OutputSection::OutDir)?;
    validate_section(&after.cache_entries, OutputSection::OutputCache)?;

    let mut rows = Vec::new();
    for (section, old, new) in [
        (
            OutputSection::OutDir,
            &before.out_dir_entries,
            &after.out_dir_entries,
        ),
        (
            OutputSection::OutputCache,
            &before.cache_entries,
            &after.cache_entries,
        ),
    ] {
        let mut i = 0usize;
        let mut j = 0usize;
        while i < old.len() || j < new.len() {
            match (old.get(i), new.get(j)) {
                (Some(o), Some(n)) => match o.path.cmp(&n.path) {
                    std::cmp::Ordering::Less => {
                        rows.push(TreeDeltaRow::Removed {
                            last_entry: o.clone(),
                            section,
                        });
                        i += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        rows.push(TreeDeltaRow::Added {
                            entry: n.clone(),
                            section,
                        });
                        j += 1;
                    }
                    std::cmp::Ordering::Equal => {
                        if o.len != n.len {
                            rows.push(TreeDeltaRow::LengthChanged {
                                new_entry: n.clone(),
                                previous_len: o.len,
                                section,
                            });
                        }
                        i += 1;
                        j += 1;
                    }
                },
                (Some(o), None) => {
                    rows.push(TreeDeltaRow::Removed {
                        last_entry: o.clone(),
                        section,
                    });
                    i += 1;
                }
                (None, Some(n)) => {
                    rows.push(TreeDeltaRow::Added {
                        entry: n.clone(),
                        section,
                    });
                    j += 1;
                }
                (None, None) => break,
            }
        }
    }
    Ok(rows)
}

/// Whether a delta contains ANY tombstone (deletion happened).
#[must_use]
pub fn has_tombstones(rows: &[TreeDeltaRow]) -> bool {
    rows.iter()
        .any(|r| matches!(r, TreeDeltaRow::Removed { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(path: &str, len: u64) -> OutputEntry {
        OutputEntry::new(path, len)
    }

    fn manifest(
        out: &[(&str, u64)],
        cache: &[(&str, u64)],
    ) -> Result<OutputTreeManifest, ManifestValidationError> {
        OutputTreeManifest::new(
            out.iter().map(|(p, l)| e(p, *l)).collect(),
            cache.iter().map(|(p, l)| e(p, *l)).collect(),
        )
    }

    #[test]
    fn n003_validation_enforces_sorted_unique_bounded_sections() {
        assert!(manifest(&[("a", 1), ("b", 2)], &[("output", 10), ("stderr", 0)]).is_ok());
        // Unsorted.
        assert_eq!(
            manifest(&[("b", 2), ("a", 1)], &[]),
            Err(ManifestValidationError::UnsortedEntries(
                OutputSection::OutDir
            ))
        );
        // Duplicate.
        assert_eq!(
            manifest(&[("a", 1), ("a", 2)], &[]),
            Err(ManifestValidationError::DuplicatePath(
                OutputSection::OutDir
            ))
        );
        // Cache-section errors name THEIR section.
        assert_eq!(
            manifest(&[], &[("z", 1), ("a", 2)]),
            Err(ManifestValidationError::UnsortedEntries(
                OutputSection::OutputCache
            ))
        );
    }

    #[test]
    fn n003_deletions_surface_as_explicit_tombstones() {
        let before =
            manifest(&[("gen.rs", 24), ("sub/nested.bin", 7)], &[("output", 100)]).expect("valid");
        let after = manifest(&[("gen.rs", 30)], &[("output", 100)]).expect("valid");
        let rows = diff_manifests(&before, &after).expect("valid inputs");
        assert!(has_tombstones(&rows));
        assert!(rows.contains(&TreeDeltaRow::Removed {
            last_entry: e("sub/nested.bin", 7),
            section: OutputSection::OutDir,
        }));
        assert!(rows.contains(&TreeDeltaRow::LengthChanged {
            new_entry: e("gen.rs", 30),
            previous_len: 24,
            section: OutputSection::OutDir,
        }));
        // Identical cache section yields NO rows: absence of a row means
        // present-with-equal-length on both sides.
        assert!(!rows.iter().any(|r| matches!(
            r,
            TreeDeltaRow::Added {
                section: OutputSection::OutputCache,
                ..
            } | TreeDeltaRow::LengthChanged {
                section: OutputSection::OutputCache,
                ..
            }
        )));
    }

    #[test]
    fn n003_additions_and_multi_section_diffs_are_order_stable() {
        let before = manifest(&[("gone.bin", 9), ("keep.rs", 5)], &[("output", 1)]).expect("v1");
        let after = manifest(
            &[("added.rs", 3), ("keep.rs", 5)],
            &[("output", 2), ("root-output", 4)],
        )
        .expect("v2");
        let rows = diff_manifests(&before, &after).expect("valid");
        // OutDir rows first (sorted by path), then cache rows.
        let summary: Vec<String> = rows
            .iter()
            .map(|r| match r {
                TreeDeltaRow::Added { entry, .. } => {
                    format!("+{}", String::from_utf8_lossy(&entry.path))
                }
                TreeDeltaRow::Removed { last_entry, .. } => {
                    format!("-{}", String::from_utf8_lossy(&last_entry.path))
                }
                TreeDeltaRow::LengthChanged { new_entry, .. } => {
                    format!("~{}", String::from_utf8_lossy(&new_entry.path))
                }
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                "+added.rs".to_owned(), // OutDir adds, path-sorted
                "-gone.bin".to_owned(), // OutDir tombstone
                "~output".to_owned(),   // cache length change
                "+root-output".to_owned(),
            ]
        );
        assert!(has_tombstones(&rows));
    }

    #[test]
    fn n003_identical_manifests_yield_zero_rows() {
        let m = manifest(&[("a", 1)], &[("output", 2)]).expect("valid");
        assert!(diff_manifests(&m, &m).expect("valid").is_empty());
    }

    #[test]
    fn n003_corrupted_either_side_refuses_rather_than_misdiffering() {
        // A duplicate path in BEFORE would make the merge walk report a
        // phantom add/remove pair; refuse instead.
        let bad_before = OutputTreeManifest {
            schema_version: OUTPUT_MANIFEST_SCHEMA_VERSION,
            out_dir_entries: vec![e("dup", 1), e("dup", 1)],
            cache_entries: Vec::new(),
        };
        let good = manifest(&[("x", 1)], &[]).expect("valid");
        assert_eq!(
            diff_manifests(&bad_before, &good),
            Err(ManifestValidationError::DuplicatePath(
                OutputSection::OutDir
            ))
        );
        assert_eq!(
            diff_manifests(&good, &bad_before),
            Err(ManifestValidationError::DuplicatePath(
                OutputSection::OutDir
            ))
        );
    }
}
