//! rustc dep-info → canonical input identities (bead E006; plan §72;
//! risk R12).
//!
//! rustc's `--emit=dep-info` writes a Makefile-shaped file naming the
//! source paths a compile read. This parser turns it into canonical
//! evidence — virtual paths plus object identities — with two rules:
//!
//! - **dep-info is EVIDENCE, not a security boundary**: proc macros and
//!   build scripts read files dep-info never mentions, so these
//!   entries feed the observed-input report and cross-checks (E011),
//!   never a claim of completeness. The type is named
//!   [`DepInfoEvidence`] to keep anyone from mistaking it for a
//!   closure.
//! - Paths map through the caller's canonical-layout virtualizer and
//!   content-identity lookup (pure, like F004): a dep-info path that
//!   cannot be virtualized or identified is a typed hard error, never
//!   a silent drop.
//!
//! Escaping (the rustc emitter's rules): `\ ` space, `\#` hash,
//! `\\` backslash, `$$` dollar; a trailing `\` continues the line.

use rabs_protocol::result_identity::ObjectId;

/// One canonical dep-info entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepInfoEntry {
    /// Canonical virtual path.
    pub virtual_path: String,
    /// Content identity of the file.
    pub object: ObjectId,
}

/// Parsed dep-info: evidence only, never an input closure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DepInfoEvidence {
    /// Entries in file order, deduplicated.
    pub entries: Vec<DepInfoEntry>,
}

/// Parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepInfoError {
    /// A mentioned path could not be mapped to the canonical layout.
    UnmappablePath(String),
    /// A mapped path has no content identity (missing/unreadable).
    UnidentifiablePath(String),
}

/// Unescape one dep-info token (rustc emitter rules).
fn unescape(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some(' ') | Some('#') | Some('\\') => {
                    out.push(chars.next().expect("peeked"));
                }
                _ => out.push('\\'),
            },
            '$' if chars.peek() == Some(&'$') => {
                chars.next();
                out.push('$');
            }
            _ => out.push(c),
        }
    }
    out
}

/// Split a dependency list on UNESCAPED spaces.
fn split_deps(list: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = list.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if matches!(chars.peek(), Some(' ') | Some('#') | Some('\\')) => {
                current.push('\\');
                current.push(chars.next().expect("peeked"));
            }
            ' ' | '\t' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens.into_iter().map(|t| unescape(&t)).collect()
}

/// Parse dep-info content into canonical evidence.
///
/// `virtualize` maps a raw path to its canonical virtual form;
/// `identify` maps a virtual path to its content identity. Both are
/// caller-supplied (the daemon wires the layout table and CAS; tests
/// wire fixtures) so the parser stays pure.
///
/// # Errors
/// [`DepInfoError`] on any unmappable or unidentifiable path.
pub fn parse_dep_info(
    content: &str,
    virtualize: impl Fn(&str) -> Option<String>,
    identify: impl Fn(&str) -> Option<ObjectId>,
) -> Result<DepInfoEvidence, DepInfoError> {
    // Join continuation lines (trailing backslash), then take each
    // `target: deps` line's right-hand side.
    let joined = content.replace("\\\n", " ");
    let mut evidence = DepInfoEvidence::default();
    for line in joined.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Rule lines only; `path: deps...`. Split at the LAST ": "
        // boundary that is not escaped — rustc targets never contain
        // unescaped ": " so the first occurrence is the separator.
        let Some((_, deps)) = line.split_once(": ").or_else(|| {
            line.ends_with(':')
                .then(|| (line.trim_end_matches(':'), ""))
        }) else {
            continue; // e.g. `path:` phony lines without deps
        };
        for raw in split_deps(deps) {
            let virtual_path =
                virtualize(&raw).ok_or_else(|| DepInfoError::UnmappablePath(raw.clone()))?;
            let object = identify(&virtual_path)
                .ok_or_else(|| DepInfoError::UnidentifiablePath(virtual_path.clone()))?;
            if !evidence
                .entries
                .iter()
                .any(|e| e.virtual_path == virtual_path)
            {
                evidence.entries.push(DepInfoEntry {
                    virtual_path,
                    object,
                });
            }
        }
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

    fn object(tag: u8) -> ObjectId {
        ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        })
    }

    fn virtualize(path: &str) -> Option<String> {
        path.strip_prefix("/home/u/w/")
            .map(|rest| format!("/__rabs/ws/{rest}"))
    }

    fn identify(vpath: &str) -> Option<ObjectId> {
        match vpath {
            "/__rabs/ws/src/lib.rs" => Some(object(1)),
            "/__rabs/ws/src/util with space.rs" => Some(object(2)),
            "/__rabs/ws/src/hash#tag.rs" => Some(object(3)),
            "/__rabs/ws/src/back\\slash.rs" => Some(object(4)),
            "/__rabs/ws/src/dollar$file.rs" => Some(object(5)),
            "/__rabs/ws/src/next.rs" => Some(object(6)),
            _ => None,
        }
    }

    #[test]
    fn escaping_edge_cases_round_trip() {
        // THE acceptance surface: spaces, hashes, backslashes, dollars,
        // and a continuation line — all as the rustc emitter writes them.
        let dep = "target/debug/lib.rmeta: /home/u/w/src/lib.rs \
/home/u/w/src/util\\ with\\ space.rs /home/u/w/src/hash\\#tag.rs \
/home/u/w/src/back\\\\slash.rs /home/u/w/src/dollar$$file.rs \\\n /home/u/w/src/next.rs\n";
        let parsed = parse_dep_info(dep, virtualize, identify).unwrap();
        let paths: Vec<&str> = parsed
            .entries
            .iter()
            .map(|e| e.virtual_path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "/__rabs/ws/src/lib.rs",
                "/__rabs/ws/src/util with space.rs",
                "/__rabs/ws/src/hash#tag.rs",
                "/__rabs/ws/src/back\\slash.rs",
                "/__rabs/ws/src/dollar$file.rs",
                "/__rabs/ws/src/next.rs",
            ]
        );
        assert_eq!(parsed.entries[1].object, object(2));
    }

    #[test]
    fn phony_targets_and_duplicates_are_handled() {
        // rustc emits per-source phony lines (`src/lib.rs:`) and the
        // same dep across multiple rule lines: phony lines contribute
        // nothing; duplicates collapse.
        let dep = "\
target/debug/lib.d: /home/u/w/src/lib.rs\n\
target/debug/lib.rmeta: /home/u/w/src/lib.rs\n\
/home/u/w/src/lib.rs:\n";
        let parsed = parse_dep_info(dep, virtualize, identify).unwrap();
        assert_eq!(parsed.entries.len(), 1);
    }

    #[test]
    fn unmappable_and_unidentifiable_paths_are_hard_errors() {
        let outside = "t: /etc/passwd\n";
        assert_eq!(
            parse_dep_info(outside, virtualize, identify),
            Err(DepInfoError::UnmappablePath("/etc/passwd".into()))
        );
        let ghost = "t: /home/u/w/src/ghost.rs\n";
        assert_eq!(
            parse_dep_info(ghost, virtualize, identify),
            Err(DepInfoError::UnidentifiablePath(
                "/__rabs/ws/src/ghost.rs".into()
            ))
        );
    }

    #[test]
    fn evidence_is_not_a_closure_by_name_and_docs() {
        // The type is DepInfoEvidence, not DepInfoClosure: dep-info
        // feeds cross-checks (E011); proc macros/build scripts read
        // files it never mentions. This test pins the name so a rename
        // toward "closure"/"manifest" is a reviewed decision.
        let e: DepInfoEvidence = DepInfoEvidence::default();
        assert!(e.entries.is_empty());
    }
}
