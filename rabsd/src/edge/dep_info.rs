//! Dep-info rewriting + materialization for Cargo freshness (bead
//! D009; plan §27/§28).
//!
//! When a served hit materializes into a subscriber's real target tree,
//! the dep-info Cargo will read must speak the subscriber's LIVE path
//! model — canonical `/__rabs` paths would make every listed input
//! "missing" and trigger a full rebuild. Rewriting reuses the D008
//! subscriber mapping and its completeness rule: any canonical residue
//! is a typed bypass (serve nothing rather than serve dep-info that
//! lies about where inputs live).
//!
//! The mtime side has one hard rule: **RABS never mutates immutable CAS
//! inodes to adjust mtimes.** Cargo's freshness comparison is "output
//! at least as new as every input", so materialization computes an
//! output mtime floor from the live input mtimes and then either
//! hardlinks (only when the CAS inode's mtime already satisfies the
//! floor — sharing is free) or writes a NEW inode stamped at the floor.
//! There is deliberately no "touch the CAS inode" variant to reach for.

use super::diagnostic_rewrite::{SubscriberMapping, TranslationOutcome};

/// Rewrite one dep-info file (makefile-style rustc `.d` content) to a
/// subscriber's live path model. Same completeness rule as D008: any
/// surviving canonical marker is a bypass, listing the offending lines.
#[must_use]
pub fn rewrite_dep_info(mapping: &SubscriberMapping, content: &str) -> TranslationOutcome {
    // Dep-info is a text surface (rule lines + env-dep comments);
    // prefix rewriting with the rendered-surface completeness rule is
    // exactly the semantics wanted here.
    super::diagnostic_rewrite::translate_rendered(mapping, content)
}

/// The output mtime floor for a served hit: at least as new as every
/// live input (Cargo's dirtiness rule is "output older than an input").
/// No inputs ⇒ no constraint (floor 0).
#[must_use]
pub fn output_mtime_floor_ns(input_mtimes_ns: &[u128]) -> u128 {
    input_mtimes_ns.iter().copied().max().unwrap_or(0)
}

/// How one artifact reaches the subscriber's target tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationStep {
    /// Hardlink the immutable CAS inode — permitted ONLY because its
    /// existing mtime already satisfies the floor; the inode is shared
    /// and therefore never touched.
    HardlinkSharedInode,
    /// Write a fresh private inode stamped at the floor. The CAS copy
    /// stays byte- and mtime-immutable.
    WriteNewInodeAt {
        /// The mtime (ns) the new inode is stamped with.
        mtime_ns: u128,
    },
}

/// Decide the materialization step for one artifact. `cas_mtime_ns` is
/// the immutable CAS inode's mtime; `floor_ns` from
/// [`output_mtime_floor_ns`]. The decision NEVER mutates the CAS inode:
/// an insufficient CAS mtime always yields a new-inode write.
#[must_use]
pub fn materialization_step(cas_mtime_ns: u128, floor_ns: u128) -> MaterializationStep {
    if cas_mtime_ns >= floor_ns {
        MaterializationStep::HardlinkSharedInode
    } else {
        MaterializationStep::WriteNewInodeAt { mtime_ns: floor_ns }
    }
}

// ---------------------------------------------------------------------
// D028: canonical dep-info storage + byte-correct subscriber derivation
// (invariant I39; risk R85). The SHARED result stores CANONICAL
// dep-info; each edge derives the subscriber-specific file under a
// versioned derivation contract with exact Makefile escaping semantics,
// records the derivation, and installs it privately. The derived
// real-path file is NEVER the canonical CAS object nor a semantic
// dependency artifact — its record carries the canonical digest as
// identity and the derived digest only as install verification.
// Anything whose lossless rewriting cannot be PROVEN (unknown escapes,
// line continuations, embedded newlines) bypasses the hit.
// ---------------------------------------------------------------------

/// The derivation contract version (bumped on any semantic change to
/// parsing/escaping/rendering below).
pub const DEP_INFO_DERIVATION_CONTRACT: u32 = 1;

/// One parsed dep-info line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepInfoLine {
    /// `target: dep dep …` (tokens are raw bytes — non-UTF8 safe).
    Rule {
        /// The target path token (unescaped bytes).
        target: Vec<u8>,
        /// Dependency path tokens (unescaped bytes).
        deps: Vec<Vec<u8>>,
    },
    /// A comment line (`# env-dep:…` and friends), byte-verbatim.
    Comment(Vec<u8>),
    /// A blank line.
    Blank,
}

/// A parsed dep-info file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DepInfoFile {
    /// Lines in order.
    pub lines: Vec<DepInfoLine>,
}

/// Typed refusal: the format cannot be losslessly round-tripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedDepInfo {
    /// Why the derivation bypasses.
    pub reason: String,
}

/// Unescape one Makefile path token; `None` on unknown escapes.
fn parse_line_tokens(line: &[u8]) -> Result<DepInfoLine, UnsupportedDepInfo> {
    if line.is_empty() {
        return Ok(DepInfoLine::Blank);
    }
    if line[0] == b'#' {
        return Ok(DepInfoLine::Comment(line.to_vec()));
    }
    if line.last() == Some(&b'\\') {
        return Err(UnsupportedDepInfo {
            reason: "line continuation cannot be proven lossless".to_string(),
        });
    }
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut target: Option<Vec<u8>> = None;
    let mut bytes = line.iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        match byte {
            b'\\' => match bytes.next() {
                Some(escaped @ (b' ' | b'\\' | b'#')) => current.push(escaped),
                other => {
                    return Err(UnsupportedDepInfo {
                        reason: format!("unknown escape \\{:?}", other.map(char::from)),
                    });
                }
            },
            b':' if target.is_none() => {
                target = Some(std::mem::take(&mut current));
            }
            b' ' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    match target {
        Some(target) => Ok(DepInfoLine::Rule {
            target,
            deps: tokens,
        }),
        None => Err(UnsupportedDepInfo {
            reason: "rule line without a target colon".to_string(),
        }),
    }
}

/// Parse canonical dep-info bytes; unsupported constructs refuse.
pub fn parse_dep_info(content: &[u8]) -> Result<DepInfoFile, UnsupportedDepInfo> {
    let mut file = DepInfoFile::default();
    for line in content.split(|b| *b == b'\n') {
        // A trailing newline yields one final empty segment; split
        // artifacts and true blanks both parse as Blank.
        file.lines.push(parse_line_tokens(line)?);
    }
    // Drop the artifact of a trailing newline so render() reproduces it.
    if file.lines.last() == Some(&DepInfoLine::Blank) {
        file.lines.pop();
    }
    Ok(file)
}

/// Escape one path token with exact Makefile semantics.
fn escape_token(token: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(token.len());
    for byte in token {
        if matches!(byte, b' ' | b'\\' | b'#') {
            out.push(b'\\');
        }
        out.push(*byte);
    }
    out
}

/// Render a dep-info file back to bytes (exact escaping; ends with a
/// trailing newline as rustc emits).
#[must_use]
pub fn render_dep_info(file: &DepInfoFile) -> Vec<u8> {
    let mut out = Vec::new();
    for line in &file.lines {
        match line {
            DepInfoLine::Rule { target, deps } => {
                out.extend_from_slice(&escape_token(target));
                out.push(b':');
                for dep in deps {
                    out.push(b' ');
                    out.extend_from_slice(&escape_token(dep));
                }
            }
            DepInfoLine::Comment(text) => out.extend_from_slice(text),
            DepInfoLine::Blank => {}
        }
        out.push(b'\n');
    }
    out
}

/// The recorded derivation: canonical digest is the IDENTITY; the
/// derived digest exists only to verify the private install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepInfoDerivation {
    /// Contract version this derivation was produced under.
    pub contract: u32,
    /// SHA-256 of the canonical dep-info (the CAS/semantic identity).
    pub canonical_sha256: [u8; 32],
    /// SHA-256 of the derived subscriber bytes (install verification
    /// ONLY — never a semantic identity).
    pub derived_sha256: [u8; 32],
}

/// A derived subscriber-specific dep-info file plus its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedDepInfo {
    /// The bytes to install privately for this subscriber.
    pub bytes: Vec<u8>,
    /// The derivation record.
    pub derivation: DepInfoDerivation,
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Replace canonical prefixes in one raw token (byte-level, so non-UTF8
/// path bytes survive untouched around the replaced prefix).
fn rewrite_token(token: &[u8], entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    for (canonical, worktree) in entries {
        if token.starts_with(canonical.as_slice()) {
            let mut out = worktree.clone();
            out.extend_from_slice(&token[canonical.len()..]);
            return out;
        }
    }
    token.to_vec()
}

/// Derive the subscriber-specific dep-info from canonical bytes under
/// the versioned contract. Structure-aware (parses, rewrites path
/// tokens, re-renders with exact escaping) — and BYPASSES on anything
/// unprovable: unsupported format, or a canonical marker surviving in
/// any token after rewrite.
pub fn derive_subscriber_dep_info(
    canonical: &[u8],
    entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<DerivedDepInfo, UnsupportedDepInfo> {
    let parsed = parse_dep_info(canonical)?;
    let mut derived = DepInfoFile::default();
    let marker: &[u8] = b"/__rabs";
    let check = |token: &[u8]| -> Result<(), UnsupportedDepInfo> {
        if token.windows(marker.len()).any(|window| window == marker) {
            Err(UnsupportedDepInfo {
                reason: format!(
                    "unmapped canonical path in dep-info: {}",
                    String::from_utf8_lossy(token)
                ),
            })
        } else {
            Ok(())
        }
    };
    for line in &parsed.lines {
        derived.lines.push(match line {
            DepInfoLine::Rule { target, deps } => {
                let target = rewrite_token(target, entries);
                check(&target)?;
                let deps = deps
                    .iter()
                    .map(|dep| {
                        let rewritten = rewrite_token(dep, entries);
                        check(&rewritten)?;
                        Ok(rewritten)
                    })
                    .collect::<Result<Vec<_>, UnsupportedDepInfo>>()?;
                DepInfoLine::Rule { target, deps }
            }
            other => other.clone(),
        });
    }
    let bytes = render_dep_info(&derived);
    Ok(DerivedDepInfo {
        derivation: DepInfoDerivation {
            contract: DEP_INFO_DERIVATION_CONTRACT,
            canonical_sha256: sha256_bytes(canonical),
            derived_sha256: sha256_bytes(&bytes),
        },
        bytes,
    })
}

/// The deterministic mtime for snapshot-materialized SOURCE files:
/// 2000-01-01T00:00:00Z, far in the past so every real output clears it.
///
/// Why it exists (observed live on hz2 during D009 bring-up): Cargo's
/// package fingerprint hashes source file MTIMES, so two worktrees of
/// byte-identical content whose files were written at different moments
/// fingerprint differently — `cargo build -vv` reports "the
/// precalculated components changed" and spuriously rebuilds. Snapshot
/// materialization therefore stamps every source with this constant:
/// same content ⇒ same mtimes ⇒ the fingerprint converges across
/// worktrees. Outputs keep real mtimes (≥ the D009 floor), so
/// input-older-than-output always holds.
#[must_use]
pub fn snapshot_source_epoch() -> std::time::SystemTime {
    // 946_684_800 seconds after the Unix epoch = 2000-01-01T00:00:00Z.
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(946_684_800)
}

/// Stamp every regular file under `root` with the snapshot source
/// epoch (the materializer's mtime choreography; symlinks untouched).
pub fn apply_snapshot_source_epoch(root: &std::path::Path) -> std::io::Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let file = std::fs::File::options().write(true).open(entry.path())?;
                file.set_modified(snapshot_source_epoch())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::diagnostic_rewrite::MappingEntry;
    use super::*;

    fn mapping() -> SubscriberMapping {
        SubscriberMapping::new(vec![
            MappingEntry {
                canonical: "/__rabs/workspace".into(),
                worktree: "/home/alice/proj".into(),
            },
            MappingEntry {
                canonical: "/__rabs/out/fixture".into(),
                worktree: "/home/alice/proj/target".into(),
            },
        ])
        .unwrap()
    }

    const DEP_INFO: &str = "/__rabs/out/fixture/debug/deps/fx-abc: \
                            /__rabs/workspace/src/main.rs /__rabs/workspace/build.rs\n\n\
                            /__rabs/workspace/src/main.rs:\n/__rabs/workspace/build.rs:\n";

    #[test]
    fn dep_info_rewrites_to_the_subscribers_live_path_model() {
        let TranslationOutcome::Translated(out) = rewrite_dep_info(&mapping(), DEP_INFO) else {
            panic!("expected full translation");
        };
        assert!(out.contains("/home/alice/proj/target/debug/deps/fx-abc:"));
        assert!(out.contains("/home/alice/proj/src/main.rs"));
        assert!(!out.contains("/__rabs"), "no canonical residue");
    }

    #[test]
    fn unmapped_canonical_input_bypasses_rather_than_lying() {
        let content = "/__rabs/out/fixture/debug/deps/fx-abc: /__rabs/registry/abc/serde/lib.rs\n";
        let TranslationOutcome::Bypass { untranslated } = rewrite_dep_info(&mapping(), content)
        else {
            panic!("expected bypass");
        };
        assert!(untranslated[0].contains("/__rabs/registry/abc"));
    }

    #[test]
    fn output_floor_is_the_newest_input() {
        assert_eq!(output_mtime_floor_ns(&[5, 9, 3]), 9);
        assert_eq!(output_mtime_floor_ns(&[]), 0);
    }

    #[test]
    fn escaping_edge_cases_round_trip_byte_exactly() {
        // THE D028 acceptance: spaces, colons-in-deps, hashes,
        // backslashes, and non-UTF8 bytes survive parse→render exactly.
        let canonical: &[u8] = b"/__rabs/out/f/debug/deps/fx-abc: \
/__rabs/workspace/src/with\\ space.rs \
/__rabs/workspace/src/with:colon.rs \
/__rabs/workspace/src/with\\#hash.rs \
/__rabs/workspace/src/back\\\\slash.rs\n\n# env-dep:CARGO_PKG_NAME=fx\n";
        let parsed = parse_dep_info(canonical).unwrap();
        assert_eq!(
            render_dep_info(&parsed),
            canonical.to_vec(),
            "byte-exact round-trip"
        );
        // Structure is right: the escaped tokens unescaped correctly.
        let DepInfoLine::Rule { deps, .. } = &parsed.lines[0] else {
            panic!("first line is the rule");
        };
        assert_eq!(deps[0], b"/__rabs/workspace/src/with space.rs".to_vec());
        assert_eq!(deps[1], b"/__rabs/workspace/src/with:colon.rs".to_vec());
        assert_eq!(deps[2], b"/__rabs/workspace/src/with#hash.rs".to_vec());
        assert_eq!(deps[3], b"/__rabs/workspace/src/back\\slash.rs".to_vec());

        // Non-UTF8 path bytes round-trip too.
        let raw: &[u8] = b"/__rabs/out/x: /__rabs/workspace/src/nom\xFF\xFEutf8.rs\n";
        let parsed = parse_dep_info(raw).unwrap();
        assert_eq!(render_dep_info(&parsed), raw.to_vec());
    }

    #[test]
    fn subscriber_derivation_is_byte_correct_and_records_the_contract() {
        let canonical: &[u8] =
            b"/__rabs/out/f/debug/deps/fx-abc: /__rabs/workspace/src/with\\ space.rs\n";
        let entries = vec![
            (b"/__rabs/workspace".to_vec(), b"/home/al ice/proj".to_vec()),
            (
                b"/__rabs/out/f".to_vec(),
                b"/home/al ice/proj/target".to_vec(),
            ),
        ];
        let derived = derive_subscriber_dep_info(canonical, &entries).unwrap();
        // The worktree path itself contains a space: exact escaping in
        // the derived bytes is what "byte-correct" means.
        assert_eq!(
            derived.bytes,
            b"/home/al\\ ice/proj/target/debug/deps/fx-abc: \
/home/al\\ ice/proj/src/with\\ space.rs\n"
                .to_vec()
        );
        assert_eq!(derived.derivation.contract, DEP_INFO_DERIVATION_CONTRACT);
        // Canonical digest is the identity; derived digest differs and
        // is install-verification only.
        assert_eq!(derived.derivation.canonical_sha256, {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(canonical);
            <[u8; 32]>::from(h.finalize())
        });
        assert_ne!(
            derived.derivation.canonical_sha256,
            derived.derivation.derived_sha256
        );
    }

    #[test]
    fn unsupported_formats_bypass_instead_of_guessing() {
        // Line continuation: unprovable lossless — bypass.
        assert!(parse_dep_info(b"a: b \\\nc\n").is_err());
        // Unknown escape: bypass.
        assert!(parse_dep_info(b"a: b\\qweird\n").is_err());
        // Rule without a colon: bypass.
        assert!(parse_dep_info(b"just some tokens\n").is_err());
        // Unmapped canonical path after rewrite: bypass, named.
        let err = derive_subscriber_dep_info(
            b"/__rabs/out/f/x: /__rabs/registry/abc/lib.rs\n",
            &[(b"/__rabs/out/f".to_vec(), b"/t".to_vec())],
        )
        .unwrap_err();
        assert!(err.reason.contains("/__rabs/registry/abc"));
    }

    #[test]
    fn cas_inodes_are_never_touched_only_shared_or_copied() {
        // CAS mtime already satisfies the floor: share the inode.
        assert_eq!(
            materialization_step(100, 90),
            MaterializationStep::HardlinkSharedInode
        );
        // CAS mtime too old: a NEW inode is written at the floor — the
        // enum has no touch-the-CAS variant to even express the
        // forbidden operation.
        assert_eq!(
            materialization_step(50, 90),
            MaterializationStep::WriteNewInodeAt { mtime_ns: 90 }
        );
        match materialization_step(0, 1) {
            MaterializationStep::HardlinkSharedInode
            | MaterializationStep::WriteNewInodeAt { .. } => {}
        }
    }
}
