//! Select a frozen Node workspace root from already selected source bytes.
//!
//! This is an authority decision, unlike the preparer's deliberately broad
//! fingerprint discovery. It performs no filesystem reads, follows no links,
//! and never promotes an implicit pnpm default into declared membership.
//! Callers must obtain every document from their exact selected source and
//! independently verify its bytes before using the returned relative root.
//! Supported patterns are literal paths, component `*`/`?`, and recursive
//! `**`. npm positives must precede exclusions. Yarn exclusion semantics vary
//! across supported versions, so those declarations cannot authorize ascent.
//! Non-ASCII `?` matches also require manager-specific character-width evidence.

use crate::pnpm_workspace;
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_DECLARATION_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DECLARATION_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DEPTH: usize = 128;
const MAX_PATTERNS: usize = 128;
const MAX_MATCH_STEPS: usize = 4_000_000;

fn relative_path(path: &str, empty: bool) -> Result<(), String> {
    if path.is_empty() {
        return if empty {
            Ok(())
        } else {
            Err("empty workspace member path".to_owned())
        };
    }
    if path.len() > MAX_PATH_BYTES
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').count() > MAX_DEPTH
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(
            "workspace path must be a bounded literal path inside selected source".to_owned(),
        );
    }
    Ok(())
}

fn join(root: &str, name: &str) -> String {
    if root.is_empty() {
        name.to_owned()
    } else {
        format!("{root}/{name}")
    }
}

fn parent(path: &str) -> Option<&str> {
    if path.is_empty() {
        None
    } else {
        Some(path.rsplit_once('/').map_or("", |(parent, _)| parent))
    }
}

/// The only document names needed to decide an invocation's preparation root.
/// The empty invocation denotes the selected source root, never its parent.
pub fn declaration_paths(invocation: &str) -> Result<BTreeSet<String>, String> {
    relative_path(invocation, true)?;
    let mut paths = BTreeSet::new();
    let mut directory = Some(invocation);
    while let Some(root) = directory {
        for name in ["package.json", pnpm_workspace::FILE_NAME] {
            let path = join(root, name);
            if path.len() > MAX_PATH_BYTES {
                return Err("workspace declaration path exceeds byte limit".to_owned());
            }
            paths.insert(path);
        }
        directory = parent(root);
    }
    Ok(paths)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Manager {
    Bun,
    Npm,
    Pnpm,
    Yarn,
}

fn locked_manager(root: &str, selected: &BTreeSet<String>) -> Result<Option<Manager>, String> {
    let families: &[(Manager, &[&str])] = &[
        (Manager::Bun, &["bun.lock", "bun.lockb"]),
        (Manager::Pnpm, &["pnpm-lock.yaml"]),
        (Manager::Yarn, &["yarn.lock"]),
        (Manager::Npm, &["package-lock.json", "npm-shrinkwrap.json"]),
    ];
    let mut manager = None;
    for (candidate, locks) in families {
        if locks
            .iter()
            .any(|lock| selected.contains(&join(root, lock)))
        {
            if manager.is_some() {
                return Err(format!("conflicting package-manager lockfiles at {root:?}"));
            }
            manager = Some(*candidate);
        }
    }
    Ok(manager)
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    workspaces: Option<Workspaces>,
}

struct Workspaces(Vec<String>);
struct PatternArray(Workspaces);

fn read_patterns<'de, S: SeqAccess<'de>>(mut sequence: S) -> Result<Workspaces, S::Error> {
    let mut patterns = Vec::new();
    while let Some(pattern) = sequence.next_element::<String>()? {
        if patterns.len() == MAX_PATTERNS {
            return Err(de::Error::custom("too many workspace patterns"));
        }
        if pattern.is_empty() || pattern.len() > MAX_PATH_BYTES {
            return Err(de::Error::custom(
                "workspace pattern is empty or exceeds byte limit",
            ));
        }
        patterns.push(pattern);
    }
    Ok(Workspaces(patterns))
}

impl<'de> Deserialize<'de> for PatternArray {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ArrayVisitor;
        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = PatternArray;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an array of workspace paths")
            }

            fn visit_seq<S: SeqAccess<'de>>(self, sequence: S) -> Result<PatternArray, S::Error> {
                read_patterns(sequence).map(PatternArray)
            }
        }
        deserializer.deserialize_seq(ArrayVisitor)
    }
}

impl<'de> Deserialize<'de> for Workspaces {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct WorkspaceVisitor;
        impl<'de> Visitor<'de> for WorkspaceVisitor {
            type Value = Workspaces;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("workspace paths or an object with a packages array")
            }

            fn visit_seq<S: SeqAccess<'de>>(self, sequence: S) -> Result<Workspaces, S::Error> {
                read_patterns(sequence)
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Workspaces, M::Error> {
                let mut packages = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "packages" {
                        if packages.is_some() {
                            return Err(de::Error::duplicate_field("packages"));
                        }
                        // A packages value is an array, never another object.
                        packages = Some(map.next_value::<PatternArray>()?.0);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                packages.ok_or_else(|| de::Error::missing_field("packages"))
            }
        }
        deserializer.deserialize_any(WorkspaceVisitor)
    }
}

fn manifest(bytes: &[u8]) -> Result<Manifest, String> {
    serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid workspace package.json: {error}"))
}

struct Pattern {
    text: String,
    components: Vec<Vec<char>>,
    literal: bool,
    excluded: bool,
}

impl Pattern {
    fn parse(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty()
            || pattern.len() > MAX_PATH_BYTES
            || pattern.chars().any(char::is_control)
            || pattern.contains(['{', '}', '[', ']', '(', ')', '\\', ':'])
        {
            return Err("unsupported workspace pattern; use literal paths or */**/?".to_owned());
        }
        let (excluded, pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern), |p| (true, p));
        if pattern.starts_with(['/', '!']) {
            return Err(
                "workspace patterns must remain inside selected source without repeated negation"
                    .to_owned(),
            );
        }
        let parts = pattern
            .split('/')
            .filter(|part| !matches!(*part, "" | "."))
            .collect::<Vec<_>>();
        if parts.is_empty()
            || parts.len() > MAX_DEPTH
            || parts.iter().any(|part| {
                matches!(*part, ".." | "node_modules" | ".git")
                    || (part.contains("**") && *part != "**")
            })
        {
            return Err(
                "workspace pattern escapes source or uses an unsupported recursive wildcard"
                    .to_owned(),
            );
        }
        Ok(Self {
            text: parts.join("/"),
            components: parts.iter().map(|part| part.chars().collect()).collect(),
            literal: !pattern.contains(['*', '?']),
            excluded,
        })
    }

    fn matches(&self, path: &str, match_hidden: bool, budget: &mut usize) -> Result<bool, String> {
        let parts = path.split('/').collect::<Vec<_>>();
        let mut previous = vec![false; parts.len() + 1];
        previous[0] = true;
        for pattern in &self.components {
            let mut current = vec![false; parts.len() + 1];
            if pattern.as_slice() == ['*', '*'] {
                for index in 0..=parts.len() {
                    spend(budget)?;
                    current[index] = previous[index]
                        || (index > 0
                            && current[index - 1]
                            && (match_hidden || !parts[index - 1].starts_with('.')));
                }
            } else {
                for index in 0..parts.len() {
                    spend(budget)?;
                    if previous[index]
                        && segment_matches(pattern, parts[index], match_hidden, budget)?
                    {
                        current[index + 1] = true;
                    }
                }
            }
            previous = current;
        }
        Ok(previous[parts.len()])
    }
}

fn spend(budget: &mut usize) -> Result<(), String> {
    *budget = budget
        .checked_sub(1)
        .ok_or("workspace pattern matching exceeds work limit")?;
    Ok(())
}

fn segment_matches(
    pattern: &[char],
    value: &str,
    match_hidden: bool,
    budget: &mut usize,
) -> Result<bool, String> {
    if !match_hidden && value.starts_with('.') && pattern.first() != Some(&'.') {
        return Ok(false);
    }
    let value = value.chars().collect::<Vec<_>>();
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star, mut retry) = (None, 0);
    while value_index < value.len() {
        spend(budget)?;
        if pattern.get(pattern_index) == Some(&'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            retry = value_index;
        } else if pattern
            .get(pattern_index)
            .is_some_and(|p| *p == '?' || *p == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if let Some(star) = star {
            retry += 1;
            value_index = retry;
            pattern_index = star + 1;
        } else {
            return Ok(false);
        }
    }
    while pattern.get(pattern_index) == Some(&'*') {
        spend(budget)?;
        pattern_index += 1;
    }
    Ok(pattern_index == pattern.len())
}

fn declares_member(manager: Manager, patterns: Vec<String>, member: &str) -> Result<bool, String> {
    if patterns.len() > MAX_PATTERNS {
        return Err("too many workspace patterns".to_owned());
    }
    let patterns = patterns
        .iter()
        .map(|pattern| Pattern::parse(pattern))
        .collect::<Result<Vec<_>, _>>()?;
    // npm's JS matcher counts UTF-16 code units (`??` matches one emoji),
    // while native managers may count Unicode scalars or UTF-8 bytes. Never
    // turn the Rust scalar matcher into authority for an ambiguous `?` case.
    // Unicode literal and `*` patterns do not depend on character width.
    if patterns.iter().any(|pattern| {
        pattern.text.contains('?') && (!member.is_ascii() || !pattern.text.is_ascii())
    }) {
        return Err(
            "non-ASCII workspace question-mark matching requires package-manager-specific evidence"
                .to_owned(),
        );
    }
    let mut saw_exclusion = false;
    for pattern in &patterns {
        if pattern.excluded {
            if manager == Manager::Yarn {
                return Err(
                    "Yarn workspace exclusions require version-specific membership evidence"
                        .to_owned(),
                );
            }
            saw_exclusion = true;
        } else if manager == Manager::Npm && saw_exclusion {
            return Err("npm workspace re-inclusion after an exclusion is unsupported".to_owned());
        }
    }
    let mut budget = MAX_MATCH_STEPS;
    // Bun explicitly listed directories survive negative glob patterns.
    if manager == Manager::Bun
        && patterns
            .iter()
            .any(|p| !p.excluded && p.literal && p.text == member)
    {
        return Ok(true);
    }
    // Bun's workspace glob walker always ignores this build directory, even
    // in a pattern that names it. Explicit literal entries above bypass the
    // walker and retain their documented precedence.
    if manager == Manager::Bun && member.split('/').any(|part| part == "CMakeFiles") {
        return Ok(false);
    }
    // pnpm excludes its legacy dependency directory even for literal entries.
    if manager == Manager::Pnpm && member.split('/').any(|part| part == "bower_components") {
        return Ok(false);
    }
    let mut included = false;
    for pattern in patterns.iter().filter(|pattern| !pattern.excluded) {
        // npm's minimatch pass treats a leading '#' as a comment, including
        // after its initial './' normalization. Such a pattern never owns a
        // literal hash-prefixed directory.
        if manager == Manager::Npm && pattern.text.starts_with('#') {
            continue;
        }
        let mut removed = false;
        if manager == Manager::Npm {
            // npm removes positive pattern strings matched by its final ignore
            // patterns before globbing. Matching only the final member path
            // would grant membership npm never installs (e.g. '*' vs '!?' ).
            for negative in patterns.iter().filter(|pattern| pattern.excluded) {
                if negative.matches(&pattern.text, false, &mut budget)? {
                    removed = true;
                    break;
                }
            }
        }
        if !removed && pattern.matches(member, false, &mut budget)? {
            included = true;
        }
    }
    if !included {
        return Ok(false);
    }
    for negative in patterns.iter().filter(|pattern| pattern.excluded) {
        // npm's glob ignores, Bun's negative matcher, and pnpm's explicit
        // exclusions include dot components that positive walks hide.
        if negative.matches(member, true, &mut budget)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Resolve within the selected root, preserving a nearer independent project.
///
/// An invocation's own frozen lockfile wins. Otherwise the nearest selected
/// ancestor with a lockfile must explicitly declare this member; an excluded,
/// independent, or implicit workspace is a boundary, not permission to search
/// further upward. Unsupported declarations fail before an installer starts.
pub fn resolve_preparation_root(
    invocation: &str,
    selected_regular: &BTreeSet<String>,
    declarations: &BTreeMap<String, Vec<u8>>,
) -> Result<String, String> {
    let requested = declaration_paths(invocation)?;
    let mut total = 0_usize;
    for (path, bytes) in declarations {
        if !requested.contains(path) || !selected_regular.contains(path) {
            return Err(
                "workspace declaration is not selected regular source on the invocation ancestry"
                    .to_owned(),
            );
        }
        total = total
            .checked_add(bytes.len())
            .ok_or("workspace declaration byte count overflow")?;
        if bytes.len() > MAX_DECLARATION_DOCUMENT_BYTES || total > MAX_DECLARATION_TOTAL_BYTES {
            return Err("workspace declarations exceed byte limit".to_owned());
        }
    }
    let document = |path: &str| -> Result<Option<&[u8]>, String> {
        if !selected_regular.contains(path) {
            return Ok(None);
        }
        declarations
            .get(path)
            .map(|bytes| Some(bytes.as_slice()))
            .ok_or_else(|| format!("selected workspace declaration bytes are missing: {path}"))
    };
    let invocation_manifest = manifest(
        document(&join(invocation, "package.json"))?
            .ok_or("invocation has no selected regular package.json")?,
    )?;
    if locked_manager(invocation, selected_regular)?.is_some() {
        return Ok(invocation.to_owned());
    }
    // Existing invocation-local preparation is not expanded through package
    // manager internals, even if a selected source happens to live there.
    if invocation
        .split('/')
        .any(|part| matches!(part, "node_modules" | ".git"))
    {
        return Ok(invocation.to_owned());
    }
    let mut ancestor = parent(invocation);
    while let Some(root) = ancestor {
        if let Some(manager) = locked_manager(root, selected_regular)? {
            let Some(bytes) = document(&join(root, "package.json"))? else {
                return Ok(invocation.to_owned());
            };
            let package = manifest(bytes)?;
            let patterns = if manager == Manager::Pnpm {
                match document(&join(root, pnpm_workspace::FILE_NAME))? {
                    Some(bytes) => {
                        pnpm_workspace::declared_package_patterns(bytes)?.unwrap_or_default()
                    }
                    None => Vec::new(),
                }
            } else {
                package
                    .workspaces
                    .map_or_else(Vec::new, |workspaces| workspaces.0)
            };
            let member = if root.is_empty() {
                invocation
            } else {
                invocation
                    .strip_prefix(root)
                    .and_then(|path| path.strip_prefix('/'))
                    .ok_or("workspace ancestor is not a literal parent")?
            };
            if declares_member(manager, patterns, member)?
                && (manager != Manager::Bun
                    || invocation_manifest
                        .name
                        .as_ref()
                        .is_some_and(|name| !name.is_empty()))
            {
                return Ok(root.to_owned());
            }
            return Ok(invocation.to_owned());
        }
        ancestor = parent(root);
    }
    Ok(invocation.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(entries: &[(&str, &str)]) -> (BTreeSet<String>, BTreeMap<String, Vec<u8>>) {
        let selected = entries.iter().map(|(path, _)| (*path).to_owned()).collect();
        let documents = entries
            .iter()
            .filter(|(path, _)| {
                path.ends_with("package.json") || path.ends_with(pnpm_workspace::FILE_NAME)
            })
            .map(|(path, bytes)| ((*path).to_owned(), bytes.as_bytes().to_vec()))
            .collect();
        (selected, documents)
    }

    fn resolve(invocation: &str, entries: &[(&str, &str)]) -> Result<String, String> {
        let (selected, mut documents) = source(entries);
        let wanted = declaration_paths(invocation)?;
        documents.retain(|path, _| wanted.contains(path));
        resolve_preparation_root(invocation, &selected, &documents)
    }

    #[test]
    fn declaration_names_stop_at_the_selected_root() {
        assert_eq!(
            declaration_paths("").unwrap(),
            BTreeSet::from(["package.json".to_owned(), "pnpm-workspace.yaml".to_owned()])
        );
        let paths = declaration_paths("packages/app").unwrap();
        assert_eq!(paths.len(), 6);
        assert!(paths.contains("packages/package.json"));
        assert!(paths.contains("packages/app/pnpm-workspace.yaml"));
        for invalid in ["/app", "../app", "a//b", "a/./b", "a/../b", "a\\b"] {
            assert!(declaration_paths(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn literal_glob_object_and_recursive_declarations_select_the_real_root() {
        for workspaces in [
            r#"["packages/app"]"#,
            r#"["packages/*"]"#,
            r#"{"packages":["packages/**"]}"#,
            r#"["packages/a??"]"#,
        ] {
            let package = format!(r#"{{"workspaces":{workspaces}}}"#);
            for lock in [
                "package-lock.json",
                "npm-shrinkwrap.json",
                "bun.lock",
                "yarn.lock",
            ] {
                assert_eq!(
                    resolve(
                        "packages/app",
                        &[
                            ("package.json", &package),
                            (lock, "lock"),
                            ("packages/app/package.json", r#"{"name":"app"}"#)
                        ]
                    )
                    .unwrap(),
                    ""
                );
            }
        }
        assert!(
            !declares_member(Manager::Npm, vec!["packages/*".into()], "packages/a/nested").unwrap()
        );
        assert!(
            declares_member(
                Manager::Npm,
                vec!["packages/**".into()],
                "packages/a/nested"
            )
            .unwrap()
        );
        assert!(
            !declares_member(Manager::Npm, vec!["packages/*".into()], "packages-old/app").unwrap()
        );
        assert!(
            !declares_member(Manager::Npm, vec!["packages/*".into()], "packages/.hidden").unwrap()
        );
        assert!(
            declares_member(
                Manager::Npm,
                vec!["packages/.hidden".into()],
                "packages/.hidden"
            )
            .unwrap()
        );
    }

    #[test]
    fn exclusions_and_package_manager_sources_cannot_enlarge_membership() {
        for manager in [Manager::Npm, Manager::Pnpm, Manager::Bun] {
            let patterns = vec!["packages/**".into(), "!packages/old/**".into()];
            assert!(declares_member(manager, patterns.clone(), "packages/new").unwrap());
            assert!(!declares_member(manager, patterns.clone(), "packages/old").unwrap());
            assert!(!declares_member(manager, patterns, "packages/old/nested").unwrap());
        }
        assert!(
            declares_member(
                Manager::Bun,
                vec!["packages/app".into(), "!packages/**".into()],
                "packages/app"
            )
            .unwrap()
        );
        assert!(
            !declares_member(
                Manager::Npm,
                vec!["packages/app".into(), "!packages/**".into()],
                "packages/app"
            )
            .unwrap()
        );
        assert!(
            !declares_member(
                Manager::Npm,
                vec!["packages/*".into(), "!packages/?".into()],
                "packages/long"
            )
            .unwrap()
        );
        assert!(
            declares_member(
                Manager::Npm,
                vec!["!packages/**".into(), "packages/app".into()],
                "packages/app"
            )
            .is_err()
        );
        for yaml in [
            "",
            "{}",
            "packages: null",
            "packages: []",
            "packages: ['!other/**']",
        ] {
            assert_eq!(
                resolve(
                    "packages/app",
                    &[
                        ("package.json", r#"{"workspaces":["packages/*"]}"#),
                        ("pnpm-lock.yaml", "lock"),
                        ("pnpm-workspace.yaml", yaml),
                        ("packages/app/package.json", "{}")
                    ]
                )
                .unwrap(),
                "packages/app"
            );
        }
        assert_eq!(
            resolve(
                "packages/app",
                &[
                    ("package.json", "{}"),
                    ("package-lock.json", "lock"),
                    ("pnpm-workspace.yaml", "packages: ['packages/*']"),
                    ("packages/app/package.json", "{}")
                ]
            )
            .unwrap(),
            "packages/app"
        );
        assert_eq!(
            resolve(
                "packages/app",
                &[
                    ("package.json", "{}"),
                    ("pnpm-lock.yaml", "lock"),
                    ("pnpm-workspace.yaml", "packages: ['packages/*']"),
                    ("packages/app/package.json", "{}")
                ]
            )
            .unwrap(),
            ""
        );
    }

    #[test]
    fn npm_membership_matches_the_installer_reader_at_glob_boundaries() {
        // These cases were also exercised through @npmcli/map-workspaces on
        // real package directories. In particular, '!dir' does not exclude
        // dir/child, whereas '!dir/**' does, and npm prunes '*' for '!?'.
        let members = [
            "packages/a",
            "packages/app",
            "packages/blocked",
            "packages/blocked/child",
            "packages/.hidden",
        ];
        let cases: &[(&[&str], &[usize])] = &[
            (&["packages/*"], &[0, 1, 2]),
            (&["packages/**"], &[0, 1, 2, 3]),
            (&["packages/*", "!packages/?"], &[]),
            (&["packages/**", "!packages/blocked"], &[0, 1, 3]),
            (&["packages/**", "!packages/blocked/**"], &[0, 1]),
            (&["packages/app", "!packages/**"], &[]),
            (&["./packages//a??"], &[1]),
            (&["packages/.hidden"], &[4]),
            (&["packages/.*"], &[4]),
            (&["packages/.*", "!packages/*"], &[]),
            (&["packages/.hidden", "!packages/*"], &[]),
            (&["packages/.*", "!packages/**"], &[]),
        ];
        for (patterns, included) in cases {
            for (index, member) in members.iter().enumerate() {
                assert_eq!(
                    declares_member(
                        Manager::Npm,
                        patterns
                            .iter()
                            .map(|pattern| (*pattern).to_owned())
                            .collect(),
                        member,
                    )
                    .unwrap(),
                    included.contains(&index),
                    "{patterns:?}: {member}",
                );
            }
        }
    }

    #[test]
    fn npm_comments_do_not_authorize_literal_hash_directories() {
        // Native @npmcli/map-workspaces returns no member for these leading
        // comment forms but does admit a hash within a later component.
        for pattern in ["#packages/*", "#packages/app", "./#packages/*"] {
            assert!(!declares_member(Manager::Npm, vec![pattern.into()], "#packages/app").unwrap());
        }
        assert!(
            declares_member(Manager::Npm, vec!["packages/#app".into()], "packages/#app").unwrap()
        );
    }

    #[test]
    fn bun_glob_exclusions_cover_hidden_names_and_ignored_build_directories() {
        // Bun's WorkspaceMap uses Dots::Hide for positive walks, whereas
        // NegatedWorkspaces uses Dots::Match. Its walker also ignores every
        // CMakeFiles component. Literal members bypass both glob mechanisms.
        for (patterns, member, expected) in [
            (vec!["packages/*"], "packages/.hidden", false),
            (vec!["packages/.*"], "packages/.hidden", true),
            (
                vec!["packages/.*", "!packages/*"],
                "packages/.hidden",
                false,
            ),
            (
                vec!["packages/.hidden", "!packages/*"],
                "packages/.hidden",
                true,
            ),
            (
                vec!["packages/.*/app", "!packages/**"],
                "packages/.hidden/app",
                false,
            ),
            (vec!["packages/*"], "packages/CMakeFiles", false),
            (vec!["packages/**"], "packages/CMakeFiles/app", false),
            (
                vec!["packages/CMakeFiles/*"],
                "packages/CMakeFiles/app",
                false,
            ),
            (vec!["packages/CMakeFiles"], "packages/CMakeFiles", true),
        ] {
            assert_eq!(
                declares_member(
                    Manager::Bun,
                    patterns
                        .iter()
                        .map(|pattern| (*pattern).to_owned())
                        .collect(),
                    member,
                )
                .unwrap(),
                expected,
                "{patterns:?}: {member}",
            );
        }
        assert!(
            !declares_member(
                Manager::Pnpm,
                vec!["packages/.*".into(), "!packages/*".into()],
                "packages/.hidden",
            )
            .unwrap()
        );
        assert!(
            !declares_member(
                Manager::Pnpm,
                vec!["packages/bower_components".into()],
                "packages/bower_components",
            )
            .unwrap()
        );
    }

    #[test]
    fn unicode_question_marks_cannot_grant_membership_with_the_wrong_character_width() {
        // Native npm map-workspaces admits é for '?' and 😀/𐀀 for '??'.
        // A scalar-based '?' would falsely admit the astral names. Reject
        // those ambiguous patterns rather than silently changing managers.
        for manager in [Manager::Bun, Manager::Npm, Manager::Pnpm, Manager::Yarn] {
            for member in [
                "packages/é",
                "packages/😀",
                "packages/𐀀",
                "packages/e\u{301}",
            ] {
                for pattern in ["packages/?", "packages/??", "packages/*?"] {
                    assert!(declares_member(manager, vec![pattern.into()], member).is_err());
                }
                assert!(declares_member(manager, vec!["packages/*".into()], member).unwrap());
                assert!(declares_member(manager, vec![member.to_owned()], member).unwrap());
            }
            assert!(declares_member(manager, vec!["packages/😀*".into()], "packages/😀a").unwrap());
            assert!(declares_member(manager, vec!["packages/*😀".into()], "packages/a😀").unwrap());
        }
    }

    #[test]
    fn changed_declarations_and_new_member_locks_resolve_again() {
        let entries = [
            ("package.json", r#"{"workspaces":["packages/*"]}"#),
            ("package-lock.json", "lock"),
            ("packages/app/package.json", "{}"),
        ];
        let (mut selected, mut documents) = source(&entries);
        assert_eq!(
            resolve_preparation_root("packages/app", &selected, &documents).unwrap(),
            ""
        );
        documents.insert(
            "package.json".into(),
            br#"{"workspaces":["packages/*","!packages/app"]}"#.to_vec(),
        );
        assert_eq!(
            resolve_preparation_root("packages/app", &selected, &documents).unwrap(),
            "packages/app"
        );
        documents.insert("package.json".into(), entries[0].1.as_bytes().to_vec());
        selected.insert("packages/app/package-lock.json".into());
        assert_eq!(
            resolve_preparation_root("packages/app", &selected, &documents).unwrap(),
            "packages/app"
        );
        selected.remove("packages/app/package-lock.json");
        selected.remove("package-lock.json");
        assert_eq!(
            resolve_preparation_root("packages/app", &selected, &documents).unwrap(),
            "packages/app"
        );
    }

    #[test]
    fn local_locks_and_nearer_independent_roots_are_boundaries() {
        let mut entries = vec![
            ("package.json", r#"{"workspaces":["packages/**"]}"#),
            ("package-lock.json", "lock"),
            ("packages/app/package.json", "{}"),
        ];
        entries.push(("packages/app/bun.lock", "own lock"));
        assert_eq!(resolve("packages/app", &entries).unwrap(), "packages/app");
        entries.pop();
        entries.extend([
            ("packages/package.json", r#"{"workspaces":["other"]}"#),
            ("packages/yarn.lock", "nearer lock"),
        ]);
        assert_eq!(resolve("packages/app", &entries).unwrap(), "packages/app");
        entries[3].1 = r#"{"workspaces":["app"]}"#;
        assert_eq!(resolve("packages/app", &entries).unwrap(), "packages");
        entries.push(("packages/pnpm-lock.yaml", "conflict"));
        assert!(resolve("packages/app", &entries).is_err());
    }

    #[test]
    fn unselected_missing_and_unnamed_member_evidence_cannot_authorize_ascent() {
        let entries = [
            ("package.json", r#"{"workspaces":["packages/*"]}"#),
            ("bun.lock", "lock"),
            ("packages/app/package.json", "{}"),
        ];
        assert_eq!(resolve("packages/app", &entries).unwrap(), "packages/app");
        let (mut selected, mut documents) = source(&entries);
        documents.remove("package.json");
        assert!(resolve_preparation_root("packages/app", &selected, &documents).is_err());
        documents.insert(
            "package.json".into(),
            br#"{"workspaces":["packages/*"]}"#.to_vec(),
        );
        selected.remove("package.json");
        assert!(resolve_preparation_root("packages/app", &selected, &documents).is_err());
    }

    #[test]
    fn unsupported_shapes_and_patterns_refuse_without_partial_authority() {
        for pattern in [
            "../outside",
            "/outside",
            "packages/[ab]",
            "packages/{a,b}",
            "packages/**suffix",
            "node_modules/*",
            "!!packages/*",
            "!../outside",
            "packages/$\n",
        ] {
            assert!(Pattern::parse(pattern).is_err(), "{pattern}");
        }
        for package in [
            r#"{"workspaces":42}"#,
            r#"{"workspaces":[1]}"#,
            r#"{"workspaces":{}}"#,
            r#"{"workspaces":{"packages":{"packages":[]}}}"#,
            r#"{"workspaces":[],"workspaces":["packages/*"]}"#,
        ] {
            assert!(manifest(package.as_bytes()).is_err(), "{package}");
        }
        let patterns = vec!["packages/*".to_owned(); MAX_PATTERNS + 1];
        assert!(declares_member(Manager::Npm, patterns, "packages/app").is_err());
        let mut empty_budget = 0;
        assert!(
            Pattern::parse("**")
                .unwrap()
                .matches("packages/app", false, &mut empty_budget)
                .is_err()
        );
        assert!(declaration_paths(&vec!["a"; MAX_DEPTH + 1].join("/")).is_err());
        assert!(declaration_paths(&"a".repeat(MAX_PATH_BYTES)).is_err());
        let mut budget = MAX_MATCH_STEPS;
        assert!(
            Pattern::parse("*a")
                .unwrap()
                .matches("*ba", false, &mut budget)
                .unwrap()
        );
    }
}
