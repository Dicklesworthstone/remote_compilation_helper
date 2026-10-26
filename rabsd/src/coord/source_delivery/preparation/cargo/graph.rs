//! Control files Cargo may read while resolving one captured workspace.
//!
//! Source capture remains whole-anchor and byte-exact. This traversal only
//! distinguishes Cargo inputs from unrelated fixture data before the bounded
//! metadata subprocess starts. It follows every local dependency, including
//! optional/target/build inputs, workspace-member dev inputs, inheritance,
//! members and patches.
//! Cargo remains the resolver: the returned paths grant no execution, cache or
//! publication authority, and metadata is still checked against the capture.

use super::{MAX_PACKAGES, OUTPUT_LIMIT, contained_relative, invalid, require};
use super::{validate_manifest_paths_with_cache, vendor::VendoredSources};
use rabs_sandbox::snapshot_capture::SealedSourceSnapshot;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, Path};
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct ControlInputs {
    /// Only the selected workspace's lockfile governs this resolution.
    pub(super) lock: String,
}

/// Reading workspace inheritance does not resolve that workspace's members.
/// Dependencies reached from a member may themselves join the selected
/// workspace; other dependencies never make their dev-dependencies live.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InputRole {
    Control,
    Dependency,
    MemberCandidate,
    Member,
}

fn enqueue(
    pending: &mut BTreeSet<String>,
    roles: &mut BTreeMap<String, InputRole>,
    path: String,
    role: InputRole,
) {
    let previous = roles.entry(path.clone()).or_insert(InputRole::Control);
    *previous = (*previous).max(role);
    pending.insert(path);
}

fn manifest_value(
    image: &SealedSourceSnapshot,
    path: &str,
    parsed: &mut BTreeMap<String, Arc<toml::Value>>,
) -> io::Result<Arc<toml::Value>> {
    if let Some(value) = parsed.get(path) {
        return Ok(Arc::clone(value));
    }
    require(
        parsed.len() < MAX_PACKAGES,
        "Cargo control graph exceeds its package bound",
    )?;
    let bytes = image
        .file_bytes("workspace", path)
        .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
        .ok_or_else(|| {
            invalid(&format!(
                "Cargo graph manifest is missing or oversized: {path}"
            ))
        })?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid("Cargo graph manifest is not UTF-8"))?;
    let value = Arc::new(
        toml::from_str(text)
            .map_err(|_| invalid(&format!("malformed Cargo graph manifest: {path}")))?,
    );
    parsed.insert(path.to_owned(), Arc::clone(&value));
    Ok(value)
}

fn manifest_path(directory: &Path) -> io::Result<String> {
    directory
        .join("Cargo.toml")
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("Cargo graph path is not UTF-8"))
}

impl ControlInputs {
    pub(super) fn discover(
        image: &SealedSourceSnapshot,
        selected: &str,
        vendor: Option<&VendoredSources>,
        cached_registry: bool,
    ) -> io::Result<Self> {
        let captured = image
            .manifest("workspace")
            .ok_or_else(|| invalid("missing captured Cargo anchor"))?;
        let candidates: Vec<_> = captured
            .members
            .keys()
            .filter(|path| {
                Path::new(path)
                    .file_name()
                    .is_some_and(|name| name == "Cargo.toml")
            })
            .cloned()
            .collect();
        let mut seen = BTreeMap::new();
        // Shared workspace manifests are read by every member's root search.
        // Parse each retained byte string once instead of repeating TOML work
        // for every edge in a large workspace.
        let mut parsed = BTreeMap::new();
        let mut pending = BTreeSet::from([selected.to_owned()]);
        let mut roles = BTreeMap::from([(selected.to_owned(), InputRole::Member)]);
        let mut selected_root = None;
        while let Some(path) = pending.pop_first() {
            let role = roles.get(&path).copied().unwrap_or(InputRole::Control);
            // A foreign workspace may first be needed only for inheritance,
            // then later be named as an actual path dependency. Upgrade that
            // role monotonically; never expand a workspace merely by reading it.
            if seen.get(&path).is_some_and(|previous| *previous >= role) {
                continue;
            }
            seen.insert(path.clone(), role);
            require(
                seen.len() <= MAX_PACKAGES,
                "Cargo control graph exceeds its package bound",
            )?;
            let value = manifest_value(image, &path, &mut parsed)?;
            let base = Path::new(&path)
                .parent()
                .ok_or_else(|| invalid("Cargo graph manifest parent missing"))?;
            validate_manifest_paths_with_cache(
                base,
                &value,
                vendor.map(|vendor| &vendor.sources),
                false,
                cached_registry,
            )?;
            if role == InputRole::Control {
                continue;
            }
            let root = workspace_root(image, &path, &value, &mut pending, &mut parsed)?;
            if path == selected {
                selected_root = Some(root.clone());
                enqueue(&mut pending, &mut roles, root.clone(), InputRole::Member);
            }
            pending.insert(root.clone());
            let member = role == InputRole::Member
                || (role == InputRole::MemberCandidate
                    && is_workspace_path_member(
                        image,
                        &path,
                        &root,
                        selected_root.as_deref().ok_or_else(|| {
                            invalid("Cargo selected workspace has not been discovered")
                        })?,
                        &mut parsed,
                    )?);
            let mut reached = BTreeSet::new();
            let mut inherited = BTreeSet::new();
            dependency_manifests(base, &value, member, &mut reached, &mut inherited)?;
            if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
                for target in targets.values() {
                    dependency_manifests(base, target, member, &mut reached, &mut inherited)?;
                }
            }
            if !inherited.is_empty() {
                let workspace = manifest_value(image, &root, &mut parsed)?;
                let entries = workspace
                    .get("workspace")
                    .and_then(|workspace| workspace.get("dependencies"));
                let root_base = Path::new(&root)
                    .parent()
                    .ok_or_else(|| invalid("Cargo workspace manifest parent"))?;
                for name in inherited {
                    let entry =
                        entries
                            .and_then(|entries| entries.get(&name))
                            .ok_or_else(|| {
                                invalid("inherited Cargo dependency is absent from its workspace")
                            })?;
                    dependency_path(root_base, entry, &mut reached)?;
                }
            }
            for dependency in reached {
                enqueue(
                    &mut pending,
                    &mut roles,
                    dependency,
                    if member {
                        InputRole::MemberCandidate
                    } else {
                        InputRole::Dependency
                    },
                );
            }
            if selected_root.as_deref() == Some(path.as_str()) {
                if let Some(workspace) = value.get("workspace") {
                    if path == selected {
                        // Cargo expands these patterns only for a root
                        // invocation. They add no members, but their raw glob
                        // traversal must still remain inside the capture.
                        let _ = workspace_patterns(base, workspace, "default-members")?;
                    }
                    let mut members = BTreeSet::new();
                    workspace_members(base, workspace, &candidates, &mut members)?;
                    for member in members {
                        enqueue(&mut pending, &mut roles, member, InputRole::Member);
                    }
                }
                let mut overrides = BTreeSet::new();
                if let Some(patches) = value.get("patch").and_then(toml::Value::as_table) {
                    for dependencies in patches.values() {
                        dependency_paths(base, dependencies, &mut overrides)?;
                    }
                }
                if let Some(replacements) = value.get("replace") {
                    dependency_paths(base, replacements, &mut overrides)?;
                }
                for replacement in overrides {
                    enqueue(&mut pending, &mut roles, replacement, InputRole::Dependency);
                }
            }
            require(
                pending.len() <= MAX_PACKAGES,
                "Cargo control graph exceeds its dependency bound",
            )?;
        }
        let root = selected_root.ok_or_else(|| invalid("Cargo selected workspace is missing"))?;
        let lock = Path::new(&root).with_file_name("Cargo.lock");
        Ok(Self {
            lock: lock
                .to_str()
                .ok_or_else(|| invalid("Cargo lock path is not UTF-8"))?
                .to_owned(),
        })
    }
}

fn is_workspace_path_member(
    image: &SealedSourceSnapshot,
    path: &str,
    package_root: &str,
    selected_root: &str,
    parsed: &mut BTreeMap<String, Arc<toml::Value>>,
) -> io::Result<bool> {
    let selected = manifest_value(image, selected_root, parsed)?;
    let Some(workspace) = selected.get("workspace") else {
        // A package without [workspace] has no automatic path members.
        return Ok(false);
    };
    let base = Path::new(selected_root)
        .parent()
        .ok_or_else(|| invalid("Cargo workspace manifest parent"))?;
    let package = Path::new(path)
        .parent()
        .ok_or_else(|| invalid("Cargo dependency manifest parent"))?;
    Ok((package.starts_with(base) || package_root == selected_root)
        && !workspace_excluded(base, workspace, Path::new(path))?)
}

/// An explicit workspace stops ancestor discovery. Otherwise Cargo may read
/// ancestor manifests while locating a workspace; validate those too, even if
/// they are only intermediate package manifests. An unrelated sibling is never
/// consulted. Explicit package.workspace paths stay inside the captured anchor.
fn workspace_root(
    image: &SealedSourceSnapshot,
    path: &str,
    value: &toml::Value,
    pending: &mut BTreeSet<String>,
    parsed: &mut BTreeMap<String, Arc<toml::Value>>,
) -> io::Result<String> {
    if value.get("workspace").is_some() {
        return Ok(path.to_owned());
    }
    let base = Path::new(path)
        .parent()
        .ok_or_else(|| invalid("Cargo manifest parent"))?;
    for package in ["package", "project"] {
        if let Some(workspace) = value
            .get(package)
            .and_then(|package| package.get("workspace"))
            .and_then(toml::Value::as_str)
        {
            return manifest_path(&contained_relative(base, workspace)?);
        }
    }
    for ancestor in base.ancestors().skip(1) {
        let candidate = manifest_path(ancestor)?;
        if image.file_bytes("workspace", &candidate).is_some() {
            let parent = manifest_value(image, &candidate, parsed)?;
            if let Some(workspace) = parent.get("workspace") {
                // Cargo skips an excluding workspace during ancestor search.
                // Exclusions are literal prefixes, with explicit literal
                // members taking precedence, NOT filesystem glob patterns.
                if workspace_excluded(ancestor, workspace, Path::new(path))? {
                    continue;
                }
                pending.insert(candidate.clone());
                return Ok(candidate);
            }
            pending.insert(candidate);
            for package in ["package", "project"] {
                if let Some(workspace) = parent
                    .get(package)
                    .and_then(|package| package.get("workspace"))
                    .and_then(toml::Value::as_str)
                {
                    return manifest_path(&contained_relative(ancestor, workspace)?);
                }
            }
        }
    }
    Ok(path.to_owned())
}

fn dependency_manifests(
    base: &Path,
    value: &toml::Value,
    member: bool,
    pending: &mut BTreeSet<String>,
    inherited: &mut BTreeSet<String>,
) -> io::Result<()> {
    for field in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "dev_dependencies",
        "build_dependencies",
    ] {
        if !member && matches!(field, "dev-dependencies" | "dev_dependencies") {
            continue;
        }
        if let Some(dependencies) = value.get(field) {
            dependency_paths(base, dependencies, pending)?;
            if let Some(dependencies) = dependencies.as_table() {
                for (name, dependency) in dependencies {
                    if dependency.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                        inherited.insert(name.clone());
                    }
                }
            }
        }
    }
    Ok(())
}

fn dependency_paths(
    base: &Path,
    dependencies: &toml::Value,
    pending: &mut BTreeSet<String>,
) -> io::Result<()> {
    if let Some(dependencies) = dependencies.as_table() {
        for dependency in dependencies.values() {
            dependency_path(base, dependency, pending)?;
        }
    }
    Ok(())
}

fn dependency_path(
    base: &Path,
    dependency: &toml::Value,
    pending: &mut BTreeSet<String>,
) -> io::Result<()> {
    if let Some(path) = dependency.get("path").and_then(toml::Value::as_str) {
        pending.insert(manifest_path(&contained_relative(base, path)?)?);
    }
    Ok(())
}

fn workspace_members(
    base: &Path,
    workspace: &toml::Value,
    candidates: &[String],
    pending: &mut BTreeSet<String>,
) -> io::Result<()> {
    // default-members only select from the already-resolved members; they do
    // not add manifests to the graph. Cargo also ignores default-members when
    // the invocation selected a member manifest rather than the workspace root.
    for pattern in workspace_patterns(base, workspace, "members")? {
        for manifest in candidates {
            let directory = Path::new(manifest)
                .parent()
                .ok_or_else(|| invalid("Cargo member parent"))?;
            if pattern.matches(directory)
                && !workspace_excluded(base, workspace, Path::new(manifest))?
            {
                pending.insert(manifest.clone());
            }
        }
    }
    Ok(())
}

/// Cargo's WorkspaceRootConfig::is_excluded compares literal joined prefixes.
/// In particular exclude=['crates/b*'] does not exclude crates/bad, and a
/// literal member entry overrides an otherwise matching exclusion. Treating
/// these as ordinary globs could omit a manifest the real planner will read.
fn workspace_excluded(base: &Path, workspace: &toml::Value, path: &Path) -> io::Result<bool> {
    let has_prefix = |field| -> io::Result<bool> {
        for prefix in workspace
            .get(field)
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
        {
            // Validate containment, but preserve Cargo's lexical prefix
            // comparison. It does not normalize `..` in member/exclude text
            // before starts_with; normalizing here could hide a live member.
            contained_relative(base, prefix)?;
            if path.starts_with(base.join(prefix)) {
                return Ok(true);
            }
        }
        Ok(false)
    };
    Ok(has_prefix("exclude")? && !has_prefix("members")?)
}

fn workspace_patterns(
    base: &Path,
    workspace: &toml::Value,
    field: &str,
) -> io::Result<Vec<PathPattern>> {
    workspace
        .get(field)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(|pattern| {
            // Cargo expands filesystem globs before traversing `..`. Lexical
            // normalization could turn `crates/**/../member` into a different
            // member set, hiding manifests the subprocess will actually read.
            let mut wildcard = false;
            for component in Path::new(pattern).components() {
                match component {
                    Component::ParentDir => require(
                        !wildcard,
                        "Cargo workspace glob followed by a parent path is unsupported",
                    )?,
                    Component::Normal(text) => {
                        wildcard |= text.to_string_lossy().contains(['*', '?', '[']);
                    }
                    _ => {}
                }
            }
            PathPattern::new(&contained_relative(base, pattern)?)
        })
        .collect()
}

/// Match Cargo's filesystem member patterns against captured names, never the
/// ambient filesystem. Whole-component ** traverses directories, ordinary * and
/// ? stay within a component, and bracket classes/ranges are character-aware.
/// Invalid patterns fail before Cargo runs rather than skipping an unknown edge.
struct PathPattern(Vec<PatternPart>);

enum PatternPart {
    Recursive,
    Component(Vec<PatternToken>),
}

enum PatternToken {
    Literal(char),
    Any,
    Star,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

impl PathPattern {
    fn new(path: &Path) -> io::Result<Self> {
        let mut parts = Vec::new();
        for component in path.components() {
            let text = component
                .as_os_str()
                .to_str()
                .ok_or_else(|| invalid("non-UTF-8 Cargo member pattern"))?;
            if text == "**" {
                parts.push(PatternPart::Recursive);
                continue;
            }
            require(
                !text.contains("**"),
                "Cargo recursive wildcard must occupy a whole path component",
            )?;
            let chars: Vec<char> = text.chars().collect();
            let mut tokens = Vec::new();
            let mut at = 0;
            while at < chars.len() {
                match chars[at] {
                    '*' => tokens.push(PatternToken::Star),
                    '?' => tokens.push(PatternToken::Any),
                    '[' => {
                        at += 1;
                        let negated = chars.get(at) == Some(&'!');
                        at += usize::from(negated);
                        let mut ranges = Vec::new();
                        // A leading ] is a literal member of the class.
                        if chars.get(at) == Some(&']') {
                            ranges.push((']', ']'));
                            at += 1;
                        }
                        while at < chars.len() && chars[at] != ']' {
                            let start = chars[at];
                            if chars.get(at + 1) == Some(&'-')
                                && chars.get(at + 2).is_some_and(|c| *c != ']')
                            {
                                let end = chars[at + 2];
                                require(start <= end, "invalid Cargo member character range")?;
                                ranges.push((start, end));
                                at += 3;
                            } else {
                                ranges.push((start, start));
                                at += 1;
                            }
                        }
                        require(
                            chars.get(at) == Some(&']') && !ranges.is_empty(),
                            "invalid Cargo member character class",
                        )?;
                        tokens.push(PatternToken::Class { negated, ranges });
                    }
                    character => tokens.push(PatternToken::Literal(character)),
                }
                at += 1;
            }
            parts.push(PatternPart::Component(tokens));
        }
        Ok(Self(parts))
    }

    fn matches(&self, path: &Path) -> bool {
        let names: Vec<_> = path
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect();
        let mut matched = vec![false; names.len() + 1];
        matched[0] = true;
        for part in &self.0 {
            let mut next = vec![false; names.len() + 1];
            match part {
                PatternPart::Recursive => {
                    next[0] = matched[0];
                    for at in 1..next.len() {
                        next[at] = matched[at] || next[at - 1];
                    }
                }
                PatternPart::Component(tokens) => {
                    for (at, name) in names.iter().enumerate() {
                        next[at + 1] = matched[at] && component_matches(tokens, name);
                    }
                }
            }
            matched = next;
        }
        matched[names.len()]
    }
}

fn component_matches(tokens: &[PatternToken], name: &str) -> bool {
    let chars: Vec<_> = name.chars().collect();
    let mut matched = vec![false; chars.len() + 1];
    matched[0] = true;
    for token in tokens {
        let mut next = vec![false; chars.len() + 1];
        if matches!(token, PatternToken::Star) {
            next[0] = matched[0];
            for at in 1..next.len() {
                next[at] = matched[at] || next[at - 1];
            }
        } else {
            for (at, character) in chars.iter().enumerate() {
                next[at + 1] = matched[at]
                    && match token {
                        PatternToken::Literal(expected) => character == expected,
                        PatternToken::Any => true,
                        PatternToken::Class { negated, ranges } => {
                            ranges
                                .iter()
                                .any(|(start, end)| start <= character && character <= end)
                                != *negated
                        }
                        PatternToken::Star => unreachable!(),
                    };
            }
        }
        matched = next;
    }
    matched[chars.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_sandbox::snapshot_capture::capture_sealed_source;
    use std::fs;

    fn image(files: &[(&str, &str)]) -> SealedSourceSnapshot {
        let directory = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let path = directory.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        capture_sealed_source(
            &[("workspace".into(), directory.path().to_owned())],
            false,
            2,
            1024 * 1024,
        )
        .unwrap()
    }

    #[test]
    fn unrelated_manifests_and_dependency_locks_are_data_until_selected() {
        let captured = image(&[
            ("Cargo.toml", "[workspace]\nmembers=['app','dep']\n"),
            ("Cargo.lock", "version=4\n"),
            (
                "app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\n[dependencies]\ndep={path='../dep'}\n",
            ),
            ("dep/Cargo.toml", "[package]\nname='dep'\nversion='0.1.0'\n"),
            ("dep/Cargo.lock", "not a lockfile ]\n"),
            ("fixtures/invalid/Cargo.toml", "not a manifest ]\n"),
            ("fixtures/invalid/Cargo.lock", "not a lockfile ]\n"),
        ]);
        let controls = ControlInputs::discover(&captured, "app/Cargo.toml", None, false).unwrap();
        assert_eq!(controls.lock, "Cargo.lock");
        assert!(
            ControlInputs::discover(&captured, "fixtures/invalid/Cargo.toml", None, false).is_err()
        );
    }

    #[test]
    fn every_local_dependency_kind_is_checked_before_cargo_can_follow_it() {
        const BAD: &str = "[package]\nname='bad'\nversion='0.1.0'\n[dependencies]\nescape={path='/rabs-outside-anchor'}\n";
        for (root_extra, app_extra) in [
            ("", "[dependencies]\nbad={path='../hidden'}\n"),
            ("", "[dependencies]\nbad={path='../hidden',optional=true}\n"),
            ("", "[dev-dependencies]\nbad={path='../hidden'}\n"),
            ("", "[build-dependencies]\nbad={path='../hidden'}\n"),
            (
                "",
                "[target.'cfg(windows)'.dependencies]\nbad={path='../hidden'}\n",
            ),
            (
                "",
                "[target.'cfg(windows)'.build-dependencies]\nbad={path='../hidden'}\n",
            ),
            (
                "",
                "[target.'cfg(windows)'.dev-dependencies]\nbad={path='../hidden'}\n",
            ),
            (
                "[workspace.dependencies]\nbad={path='hidden'}\n",
                "[dependencies]\nbad={workspace=true}\n",
            ),
            ("[patch.crates-io]\nbad={path='hidden'}\n", ""),
            ("[replace]\n'bad:0.1.0'={path='hidden'}\n", ""),
        ] {
            let root = format!("[workspace]\nmembers=['app']\n{root_extra}");
            let app = format!("[package]\nname='app'\nversion='0.1.0'\n{app_extra}");
            let captured = image(&[
                ("Cargo.toml", &root),
                ("app/Cargo.toml", &app),
                ("hidden/Cargo.toml", BAD),
            ]);
            let error =
                ControlInputs::discover(&captured, "app/Cargo.toml", None, false).unwrap_err();
            assert!(
                error.to_string().contains("absolute Cargo source paths"),
                "{root_extra} {app_extra}: {error}"
            );
        }
    }

    #[test]
    fn unused_workspace_dependencies_are_not_resolution_edges() {
        for inherited in [false, true] {
            let app = format!(
                "[package]\nname='app'\nversion='0.1.0'\n{}",
                if inherited {
                    "[dependencies]\nunused={workspace=true}\n"
                } else {
                    ""
                }
            );
            let captured = image(&[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=['app']\n[workspace.dependencies]\nunused={path='missing'}\n",
                ),
                ("app/Cargo.toml", &app),
            ]);
            assert_eq!(
                ControlInputs::discover(&captured, "app/Cargo.toml", None, false).is_ok(),
                !inherited
            );
        }
    }

    #[test]
    fn default_members_do_not_add_unrelated_manifests_to_resolution() {
        for default in ["fixture", "**/../fixture"] {
            let root = format!("[workspace]\nmembers=['app']\ndefault-members=['{default}']\n");
            let captured = image(&[
                ("Cargo.toml", &root),
                ("app/Cargo.toml", "[package]\nname='app'\nversion='0.1.0'\n"),
                ("fixture/Cargo.toml", "not a Cargo manifest ]\n"),
            ]);
            assert!(ControlInputs::discover(&captured, "app/Cargo.toml", None, false).is_ok());
            if default.contains('*') {
                assert!(ControlInputs::discover(&captured, "Cargo.toml", None, false).is_err());
            }
        }
    }

    #[test]
    fn foreign_workspace_inheritance_does_not_resolve_unrelated_members_or_root_dependencies() {
        let captured = image(&[
            (
                "app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\n[workspace]\n[dependencies]\nleaf={path='../foreign/leaf'}\n",
            ),
            (
                "foreign/Cargo.toml",
                "[package]\nname='foreign'\nversion='0.1.0'\n[dependencies]\nunused={path='missing'}\n[workspace]\nmembers=['leaf','bad']\n[workspace.package]\nversion='0.1.0'\n[workspace.dependencies]\nunused={path='also-missing'}\n[patch.crates-io]\nunused={path='another-missing'}\n",
            ),
            (
                "foreign/leaf/Cargo.toml",
                "[package]\nname='leaf'\nversion.workspace=true\n[dev-dependencies]\nunused={path='../missing-dev'}\n[target.'cfg(windows)'.dev-dependencies]\nother={path='../missing-target-dev'}\n",
            ),
            (
                "foreign/bad/Cargo.toml",
                "malformed member of an unrelated workspace ]\n",
            ),
        ]);
        assert_eq!(
            ControlInputs::discover(&captured, "app/Cargo.toml", None, false)
                .unwrap()
                .lock,
            "app/Cargo.lock"
        );
        assert!(ControlInputs::discover(&captured, "foreign/Cargo.toml", None, false).is_err());
    }

    #[test]
    fn dev_dependencies_are_resolved_for_workspace_members_only() {
        for (workspace, excluded, accepted) in [
            (false, false, true),
            (true, false, false),
            (true, true, true),
        ] {
            let root = format!(
                "[package]\nname='app'\nversion='0.1.0'\n[dependencies]\nleaf={{path='leaf'}}\n{}",
                if workspace {
                    if excluded {
                        "[workspace]\nexclude=['leaf']\n"
                    } else {
                        "[workspace]\n"
                    }
                } else {
                    ""
                }
            );
            let captured = image(&[
                ("app/Cargo.toml", &root),
                (
                    "app/leaf/Cargo.toml",
                    "[package]\nname='leaf'\nversion='0.1.0'\n[dev-dependencies]\nunused={path='missing'}\n",
                ),
            ]);
            assert_eq!(
                ControlInputs::discover(&captured, "app/Cargo.toml", None, false).is_ok(),
                accepted,
                "workspace={workspace}, excluded={excluded}"
            );
        }

        // An out-of-tree dependency explicitly joining this workspace also
        // becomes a member, so its missing development dependency is live.
        let captured = image(&[
            (
                "app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\n[workspace]\n[dependencies]\nleaf={path='../leaf'}\n",
            ),
            (
                "leaf/Cargo.toml",
                "[package]\nname='leaf'\nversion='0.1.0'\nworkspace='../app'\n[dev-dependencies]\nunused={path='missing'}\n",
            ),
        ]);
        assert!(ControlInputs::discover(&captured, "app/Cargo.toml", None, false).is_err());
    }

    #[test]
    fn workspace_member_globs_include_transitive_manifests_but_respect_exclusions() {
        for pattern in ["crates/*", "crates/[ab]*", "crates/**"] {
            for excluded in [false, true] {
                let root = format!(
                    "[workspace]\nmembers=['{pattern}']\nexclude={}\n",
                    if excluded { "['crates/bad']" } else { "[]" }
                );
                let captured = image(&[
                    ("Cargo.toml", &root),
                    (
                        "crates/app/Cargo.toml",
                        "[package]\nname='app'\nversion='0.1.0'\n",
                    ),
                    (
                        "crates/bad/Cargo.toml",
                        "malformed selected workspace member ]\n",
                    ),
                    ("fixtures/bad/Cargo.toml", "unrelated malformed fixture ]\n"),
                ]);
                let result = ControlInputs::discover(&captured, "Cargo.toml", None, false);
                assert_eq!(
                    result.is_ok(),
                    excluded,
                    "{pattern}, excluded={excluded}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn explicit_workspace_and_independent_workspace_stop_ancestor_discovery() {
        let captured = image(&[
            ("Cargo.toml", "unrelated malformed outer manifest ]\n"),
            ("project/Cargo.toml", "[workspace]\nmembers=['app']\n"),
            (
                "project/app/Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nworkspace='..'\n",
            ),
            ("project/Cargo.lock", "version=4\n"),
            (
                "standalone/Cargo.toml",
                "[package]\nname='standalone'\nversion='0.1.0'\n[workspace]\n",
            ),
        ]);
        assert_eq!(
            ControlInputs::discover(&captured, "project/app/Cargo.toml", None, false)
                .unwrap()
                .lock,
            "project/Cargo.lock"
        );
        assert_eq!(
            ControlInputs::discover(&captured, "standalone/Cargo.toml", None, false)
                .unwrap()
                .lock,
            "standalone/Cargo.lock"
        );
    }

    #[test]
    fn excluded_selected_package_owns_its_lock_without_resolving_parent_members() {
        let captured = image(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers=['bad']\nexclude=['standalone']\n",
            ),
            (
                "bad/Cargo.toml",
                "malformed member of another workspace ]\n",
            ),
            (
                "standalone/Cargo.toml",
                "[package]\nname='standalone'\nversion='0.1.0'\n",
            ),
        ]);
        assert_eq!(
            ControlInputs::discover(&captured, "standalone/Cargo.toml", None, false)
                .unwrap()
                .lock,
            "standalone/Cargo.lock"
        );
        assert!(ControlInputs::discover(&captured, "Cargo.toml", None, false).is_err());
    }

    #[test]
    fn workspace_exclusion_is_literal_and_explicit_members_take_precedence() {
        for (members, excluded, accepted) in [
            ("['crates/*']", "['crates/bad']", true),
            ("['crates/*']", "['crates/b*']", false),
            ("['crates/bad']", "['crates/bad']", false),
            ("['crates/bad']", "['crates']", false),
            ("['crates/*']", "['crates/../crates/bad']", false),
        ] {
            let root = format!("[workspace]\nmembers={members}\nexclude={excluded}\n");
            let captured = image(&[
                ("Cargo.toml", &root),
                (
                    "crates/bad/Cargo.toml",
                    "[package]\nname='bad'\nversion='0.1.0'\n[dependencies]\nescape={path='/rabs-must-not-read'}\n",
                ),
            ]);
            assert_eq!(
                ControlInputs::discover(&captured, "Cargo.toml", None, false).is_ok(),
                accepted,
                "{members} {excluded}"
            );
        }
        let root: toml::Value = toml::from_str("[workspace]\nexclude=['fixtures']\n").unwrap();
        assert!(
            workspace_excluded(
                Path::new(""),
                &root["workspace"],
                Path::new("fixtures/nested/package/Cargo.toml")
            )
            .unwrap()
        );
    }

    #[test]
    fn workspace_patterns_are_component_bounded_and_character_aware() {
        for (pattern, path, expected) in [
            ("crates/*", "crates/app", true),
            ("crates/*", "crates/app/nested", false),
            ("crates/**/app", "crates/app", true),
            ("crates/**/app", "crates/nested/deep/app", true),
            ("crates/[!ab]?", "crates/éx", true),
            ("crates/[!ab]?", "crates/ax", false),
            ("crates/[a-c]*", "crates/builder", true),
            ("crates/[a-c]*", "crates/driver", false),
            ("crates/[*]", "crates/*", true),
            ("crates/[]]", "crates/]", true),
        ] {
            assert_eq!(
                PathPattern::new(Path::new(pattern))
                    .unwrap()
                    .matches(Path::new(path)),
                expected,
                "{pattern} {path}"
            );
        }
        for pattern in ["crates/[", "crates/[]", "crates/[z-a]", "crates/a**"] {
            assert!(PathPattern::new(Path::new(pattern)).is_err(), "{pattern}");
        }

        for pattern in [
            "crates/**/../member",
            "crates/*/../member",
            "crates/[ab]/../member",
        ] {
            let value: toml::Value = toml::from_str(&format!("members=['{pattern}']")).unwrap();
            assert!(workspace_patterns(Path::new("root"), &value, "members").is_err());
        }
        let value: toml::Value = toml::from_str("members=['../crates/*']").unwrap();
        assert!(workspace_patterns(Path::new("root"), &value, "members").is_ok());
    }
}
