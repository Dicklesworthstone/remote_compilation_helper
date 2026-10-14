//! Bounded input discovery for package.json and pnpm workspaces.
//!
//! The package manager remains the authority on which packages to install.
//! For a glob we fingerprint every package manifest below its literal prefix,
//! including excluded packages: a conservative superset cannot hide a changed
//! workspace behind a root-only cache hit. We do not interpret globs as shell
//! commands or follow directory symlinks outside the owned project.

use super::{InputIdentity, InputObservation, MAX_INPUT_BYTES};
use anyhow::{Context, Result, bail, ensure};
use rch_common::pnpm_workspace;
use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_PATTERNS: usize = 128;
const MAX_DIRECTORIES: usize = 4096;
const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 48;
const MAX_MANIFESTS: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    modified: std::time::SystemTime,
    #[cfg(unix)]
    inode: (u64, u64, i64, i64),
}

impl DirectoryIdentity {
    fn of(metadata: &Metadata) -> Result<Self> {
        ensure!(
            metadata.file_type().is_dir(),
            "workspace path is not a real directory"
        );
        Ok(Self {
            modified: metadata.modified()?,
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
        })
    }
}

/// Names plus the directory membership and declaration evidence used to
/// discover them. Verify AFTER reading the named files, not before their read.
pub(super) struct Inventory {
    pub(super) names: Vec<String>,
    root_manifest: InputObservation,
    pnpm_path: PathBuf,
    pnpm_manifest: Option<InputObservation>,
    directories: Vec<(PathBuf, DirectoryIdentity)>,
}

impl Inventory {
    pub(super) fn verify(&self, root_manifest: &InputObservation) -> Result<()> {
        ensure!(
            self.root_manifest == *root_manifest,
            "package.json changed between workspace discovery and fingerprinting"
        );
        let current = read_pnpm_document(&self.pnpm_path)?.map(|(_, observed)| observed);
        ensure!(
            current == self.pnpm_manifest,
            "pnpm-workspace.yaml changed between workspace discovery and fingerprinting"
        );
        for (path, observed) in &self.directories {
            ensure!(
                DirectoryIdentity::of(&std::fs::symlink_metadata(path)?)? == *observed,
                "workspace directory membership changed during capture: {}",
                path.display()
            );
        }
        Ok(())
    }
}

/// Observe optional YAML without following a static link or blocking on a FIFO.
/// The complete raw document also enters DependencyInputs' shared byte budget.
fn read_pnpm_document(path: &Path) -> Result<Option<(Vec<u8>, InputObservation)>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect pnpm-workspace.yaml"),
    };
    let identity = InputIdentity::of(&metadata).context("inspect pnpm-workspace.yaml")?;
    ensure!(
        identity.len <= pnpm_workspace::MAX_DOCUMENT_BYTES as u64,
        "pnpm-workspace.yaml exceeds document byte limit"
    );
    let mut file = File::open(path).context("open pnpm-workspace.yaml")?;
    ensure!(
        InputIdentity::of(&file.metadata()?)? == identity,
        "pnpm-workspace.yaml changed before read"
    );
    let mut bytes = Vec::new();
    (&mut file).take(identity.len + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == identity.len
            && InputIdentity::of(&file.metadata()?)? == identity
            && InputIdentity::of(&std::fs::symlink_metadata(path)?)? == identity,
        "pnpm-workspace.yaml changed during read"
    );
    let observation = InputObservation {
        identity,
        digest: blake3::hash(&bytes),
    };
    Ok(Some((bytes, observation)))
}

#[derive(Debug, PartialEq, Eq)]
struct Prefix {
    components: Vec<String>,
    recursive: bool,
}

/// Deliberately support literal paths and */**/? patterns, not an incomplete
/// emulation of brace expansion, extglobs or platform-dependent path escapes.
/// An unsupported declaration is refused before an installer starts.
fn prefix(pattern: &str) -> Result<Option<Prefix>> {
    ensure!(
        !pattern.is_empty() && pattern.len() <= 4096 && !pattern.chars().any(char::is_control),
        "invalid workspace pattern"
    );
    ensure!(
        !pattern.contains(['{', '}', '[', ']', '(', ')', '\\', ':']),
        "unsupported workspace pattern {pattern:?}; use literal directories or */**/? patterns"
    );
    if pattern.starts_with('!') {
        // Exclusions never enlarge the install set. Retaining their manifests
        // in the fingerprint costs a possible cache miss, never a false hit.
        return Ok(None);
    }
    ensure!(
        !pattern.starts_with('/'),
        "workspace must stay inside the owned project"
    );
    let mut components = Vec::new();
    let mut recursive = false;
    for part in pattern.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        ensure!(part != "..", "workspace must stay inside the owned project");
        ensure!(
            !matches!(part, "node_modules" | ".git"),
            "workspace declaration names dependency or version-control internals"
        );
        if part.contains(['*', '?']) {
            recursive = true;
        }
        if !recursive {
            components.push(part.to_owned());
        }
    }
    ensure!(
        components.len() <= MAX_DEPTH,
        "workspace path exceeds depth limit"
    );
    Ok(Some(Prefix {
        components,
        recursive,
    }))
}

fn declarations(bytes: &[u8]) -> Result<Vec<Prefix>> {
    let manifest: serde_json::Value =
        serde_json::from_slice(bytes).context("parse package.json")?;
    let object = manifest
        .as_object()
        .context("package.json must be an object")?;
    let Some(workspaces) = object.get("workspaces") else {
        return Ok(Vec::new());
    };
    // Yarn's object form is also accepted by npm's workspace reader.
    let declarations = if workspaces.is_object() {
        workspaces
            .get("packages")
            .context("workspaces object is missing packages")?
    } else {
        workspaces
    };
    let declarations = declarations
        .as_array()
        .context("workspaces must be an array of paths")?;
    ensure!(
        declarations.len() <= MAX_PATTERNS,
        "too many workspace declarations"
    );
    let mut prefixes = Vec::new();
    for declaration in declarations {
        if let Some(prefix) = prefix(
            declaration
                .as_str()
                .context("workspace path must be a string")?,
        )? {
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
}

struct Walk {
    root: PathBuf,
    directories: Vec<(PathBuf, DirectoryIdentity)>,
    expanded: BTreeSet<PathBuf>,
    manifests: BTreeSet<String>,
    entries: usize,
}

impl Walk {
    fn observe_directory(&mut self, path: &Path) -> Result<bool> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| format!("inspect workspace {}", path.display()));
            }
        };
        // A declared directory must not be followed through a symlink. Its
        // canonical target could be outside the source ownership grant.
        let identity = DirectoryIdentity::of(&metadata)
            .with_context(|| format!("inspect workspace {}", path.display()))?;
        if let Some((_, previous)) = self.directories.iter().find(|(seen, _)| seen == path) {
            ensure!(
                *previous == identity,
                "workspace directory changed during discovery"
            );
        } else {
            ensure!(
                self.directories.len() < MAX_DIRECTORIES,
                "workspace directory limit exceeded"
            );
            self.directories.push((path.to_path_buf(), identity));
        }
        Ok(true)
    }

    fn manifest(&mut self, directory: &Path) -> Result<()> {
        let path = directory.join("package.json");
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure!(
                    metadata.file_type().is_file(),
                    "workspace package.json is not a regular file: {}",
                    path.display()
                );
                let relative = path
                    .strip_prefix(&self.root)
                    .context("workspace escaped project")?;
                // Slash-separated names are stable across filesystem backends.
                let mut pieces = Vec::new();
                for piece in relative.iter() {
                    pieces.push(piece.to_str().context("workspace path is not UTF-8")?);
                }
                let name = pieces.join("/");
                ensure!(name.len() <= 4096, "workspace manifest path exceeds limit");
                if name != "package.json" {
                    self.manifests.insert(name);
                    ensure!(
                        self.manifests.len() <= MAX_MANIFESTS,
                        "workspace manifest limit exceeded"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        }
        Ok(())
    }

    fn scan(&mut self, directory: PathBuf, depth: usize) -> Result<()> {
        ensure!(
            depth <= MAX_DEPTH,
            "workspace discovery exceeds depth limit"
        );
        if !self.observe_directory(&directory)? || !self.expanded.insert(directory.clone()) {
            return Ok(());
        }
        self.manifest(&directory)?;
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("read workspace {}", directory.display()))?
        {
            let entry = entry?;
            self.entries += 1;
            ensure!(
                self.entries <= MAX_ENTRIES,
                "workspace entry limit exceeded"
            );
            let name = entry.file_name();
            if name == "node_modules" || name == ".git" {
                continue;
            }
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                self.scan(entry.path(), depth + 1)?;
            } else if file_type.is_symlink() {
                // Conservatively refuse an uninspectable subtree rather than
                // silently omitting a possible workspace. Never follow it.
                bail!(
                    "workspace discovery encountered a symlink: {}",
                    entry.path().display()
                );
            }
        }
        Ok(())
    }
}

pub(super) fn discover(project: &Path, root_names: &[&str]) -> Result<Inventory> {
    let mut walk = Walk {
        root: project.to_path_buf(),
        directories: Vec::new(),
        expanded: BTreeSet::new(),
        manifests: BTreeSet::new(),
        entries: 0,
    };
    ensure!(
        walk.observe_directory(project)?,
        "workspace project is missing"
    );
    let path = project.join("package.json");
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("no package manifest found in {}", project.display()))?;
    let identity = InputIdentity::of(&metadata)?;
    ensure!(
        identity.len <= MAX_INPUT_BYTES,
        "dependency inputs exceed byte limit"
    );
    let mut file = File::open(&path)?;
    ensure!(
        InputIdentity::of(&file.metadata()?)? == identity,
        "package.json changed before workspace discovery"
    );
    let mut bytes = Vec::new();
    (&mut file).take(identity.len + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == identity.len
            && InputIdentity::of(&file.metadata()?)? == identity
            && InputIdentity::of(&std::fs::symlink_metadata(&path)?)? == identity,
        "package.json changed during workspace discovery"
    );
    let mut prefixes = declarations(&bytes)?;
    let root_manifest = InputObservation {
        identity,
        digest: blake3::hash(&bytes),
    };
    let pnpm_path = project.join(pnpm_workspace::FILE_NAME);
    let pnpm_document = read_pnpm_document(&pnpm_path)?;
    if let Some((bytes, _)) = &pnpm_document {
        // The existing installer selects pnpm only from this lockfile. Do not
        // silently bootstrap a YAML workspace with its npm/Bun default. This
        // refusal is before RUNNING, so adding the lock permits a normal retry.
        ensure!(
            std::fs::symlink_metadata(project.join("pnpm-lock.yaml"))
                .is_ok_and(|metadata| metadata.file_type().is_file()),
            "pnpm workspace preparation requires pnpm-lock.yaml; refusing an npm/Bun bootstrap"
        );
        for pattern in pnpm_workspace::package_patterns(bytes).map_err(anyhow::Error::msg)? {
            if let Some(prefix) = prefix(&pattern)? {
                prefixes.push(prefix);
            }
        }
    }
    // Both declaration sources share one traversal and its global limits.
    for prefix in prefixes {
        let mut directory = project.to_path_buf();
        let mut exists = true;
        for part in &prefix.components {
            directory.push(part);
            if !walk.observe_directory(&directory)? {
                exists = false;
                break;
            }
        }
        if exists {
            if prefix.recursive {
                walk.scan(directory, prefix.components.len())?;
            } else {
                walk.manifest(&directory)?;
            }
        }
    }
    let mut names: Vec<String> = root_names.iter().map(|name| (*name).to_owned()).collect();
    if !root_names.contains(&pnpm_workspace::FILE_NAME) {
        // Include absence too, just like the optional root lockfiles. Raw YAML
        // bytes, not parsed/re-serialized settings, invalidate prior stamps.
        names.push(pnpm_workspace::FILE_NAME.to_owned());
    }
    for manifest in walk.manifests {
        if pnpm_document.is_some() {
            // With sharedWorkspaceLockfile=false, members have independent
            // resolutions. Older pnpm also reads member .npmrc files. Track
            // their absence as well as their bytes through the same capture.
            let directory = manifest
                .strip_suffix("package.json")
                .context("workspace manifest name lost its package.json suffix")?;
            names.push(format!("{directory}pnpm-lock.yaml"));
            names.push(format!("{directory}.npmrc"));
        }
        names.push(manifest);
    }
    Ok(Inventory {
        names,
        root_manifest,
        pnpm_path,
        pnpm_manifest: pnpm_document.map(|(_, observed)| observed),
        directories: walk.directories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prepare::{DependencyInputs, PrepareAction};
    use rch_common::RequiredRuntime;

    fn project(workspaces: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            format!(r#"{{"workspaces":{workspaces}}}"#),
        )
        .unwrap();
        dir
    }

    fn member(root: &Path, name: &str, contents: &str) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), contents).unwrap();
    }

    #[test]
    fn discovers_literal_glob_recursive_and_object_workspaces_deterministically() {
        for workspaces in [
            r#"["packages/*","literal","packages/**","!packages/excluded"]"#,
            r#"{"packages":["packages/**","literal","packages/*"],"nohoist":["**"]}"#,
        ] {
            let dir = project(workspaces);
            member(dir.path(), "packages/z", "{}");
            member(dir.path(), "packages/a/nested", "{}");
            member(dir.path(), "packages/excluded", "{}");
            member(dir.path(), "literal", "{}");
            member(dir.path(), "outside", "{}");
            member(dir.path(), "packages/node_modules/generated", "{}");
            member(dir.path(), "packages/.git/generated", "{}");
            let inputs = DependencyInputs::capture(dir.path()).unwrap();
            assert_eq!(
                inputs.fingerprint.sources,
                [
                    "package.json",
                    "literal/package.json",
                    "packages/a/nested/package.json",
                    "packages/excluded/package.json",
                    "packages/z/package.json"
                ]
            );
            assert_eq!(
                inputs.fingerprint,
                DependencyInputs::capture(dir.path()).unwrap().fingerprint
            );
        }
    }

    #[test]
    fn member_edit_addition_and_removal_change_identity_and_refuse_mid_install_publication() {
        let dir = project(r#"["packages/*"]"#);
        member(dir.path(), "packages/a", r#"{"name":"first"}"#);
        let original = DependencyInputs::capture(dir.path()).unwrap();
        member(dir.path(), "packages/a", r#"{"name":"other"}"#);
        let edited = DependencyInputs::capture(dir.path()).unwrap();
        assert_ne!(original.fingerprint.hash, edited.fingerprint.hash);
        assert!(
            original
                .verify_after(&edited, RequiredRuntime::Node, PrepareAction::Installed)
                .is_err()
        );
        member(dir.path(), "packages/b", "{}");
        let added = DependencyInputs::capture(dir.path()).unwrap();
        assert_ne!(edited.fingerprint.hash, added.fingerprint.hash);
        assert!(
            edited
                .verify_after(&added, RequiredRuntime::Bun, PrepareAction::Installed)
                .is_err()
        );
        std::fs::rename(dir.path().join("packages/b"), dir.path().join("retained-b")).unwrap();
        let removed = DependencyInputs::capture(dir.path()).unwrap();
        assert_ne!(added.fingerprint.hash, removed.fingerprint.hash);
        assert!(
            added
                .verify_after(&removed, RequiredRuntime::Node, PrepareAction::Skipped)
                .is_err()
        );
    }

    #[test]
    fn generated_dependency_manifests_do_not_invalidate_a_workspace_stamp() {
        let dir = project(r#"["packages/*"]"#);
        member(dir.path(), "packages/a", "{}");
        let before = DependencyInputs::capture(dir.path()).unwrap();
        member(dir.path(), "node_modules/generated", "{}");
        member(dir.path(), "packages/a/node_modules/generated", "{}");
        member(dir.path(), "unrelated", "{}");
        let after = DependencyInputs::capture(dir.path()).unwrap();
        assert_eq!(before.fingerprint, after.fingerprint);
        before
            .verify_after(&after, RequiredRuntime::Node, PrepareAction::Skipped)
            .unwrap();
    }

    #[test]
    fn discovery_membership_is_rechecked_after_manifest_reads() {
        let dir = project(r#"["packages/*"]"#);
        member(dir.path(), "packages/a", "{}");
        let inventory = discover(dir.path(), super::super::install::INPUT_NAMES).unwrap();
        member(dir.path(), "packages/new", "{}");
        assert!(inventory.verify(&inventory.root_manifest).is_err());
    }

    #[test]
    fn escapes_unsupported_patterns_and_malformed_declarations_are_refused() {
        for declaration in [
            r#"["../outside"]"#,
            r#"["/outside"]"#,
            r#"["packages/../outside"]"#,
            r#"["packages/{a,b}"]"#,
            r#"["packages/[ab]"]"#,
            r#"["node_modules/*"]"#,
            r#"["C:\\outside"]"#,
            r#"[42]"#,
            "null",
            r#"{}"#,
            r#""packages/*""#,
        ] {
            let dir = project(declaration);
            assert!(
                DependencyInputs::capture(dir.path()).is_err(),
                "{declaration}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn workspace_symlinks_never_extend_source_authority() {
        let outside = tempfile::tempdir().unwrap();
        member(outside.path(), "private", "{}");
        for pattern in [r#"["packages/a"]"#, r#"["packages/*"]"#] {
            let dir = project(pattern);
            std::fs::create_dir(dir.path().join("packages")).unwrap();
            std::os::unix::fs::symlink(
                outside.path().join("private"),
                dir.path().join("packages/a"),
            )
            .unwrap();
            assert!(DependencyInputs::capture(dir.path()).is_err());
            assert_eq!(
                std::fs::read(outside.path().join("private/package.json")).unwrap(),
                b"{}"
            );
        }
    }

    #[test]
    fn literal_workspace_does_not_walk_unrelated_nested_projects() {
        let dir = project(r#"["packages/a"]"#);
        member(dir.path(), "packages/a", "{}");
        member(dir.path(), "packages/a/fixtures", "{}");
        let inputs = DependencyInputs::capture(dir.path()).unwrap();
        assert_eq!(
            inputs.fingerprint.sources,
            ["package.json", "packages/a/package.json"]
        );
    }

    #[test]
    fn manifest_and_depth_limits_refuse_instead_of_publishing_partial_inventories() {
        let dir = project(r#"["packages/*"]"#);
        for n in 0..=MAX_MANIFESTS {
            member(dir.path(), &format!("packages/p{n}"), "{}");
        }
        assert!(DependencyInputs::capture(dir.path()).is_err());
        let deep = project(r#"["packages/**"]"#);
        let nested = std::iter::repeat_n("d", MAX_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/");
        member(deep.path(), &format!("packages/{nested}"), "{}");
        assert!(DependencyInputs::capture(deep.path()).is_err());
    }

    fn pnpm_project(yaml: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("package.json"), b"{}").unwrap();
        std::fs::write(
            directory.path().join("pnpm-lock.yaml"),
            b"lockfileVersion: '9.0'\n",
        )
        .unwrap();
        std::fs::write(directory.path().join(pnpm_workspace::FILE_NAME), yaml).unwrap();
        directory
    }

    #[test]
    fn pnpm_only_workspace_and_entire_config_participate_in_the_same_fingerprint() {
        let dir = pnpm_project("packages: ['packages/*']\ncatalog:\n chalk: ^4.0.0\n");
        member(dir.path(), "packages/a", r#"{"name":"a"}"#);
        member(dir.path(), "unrelated", "{}");
        let first = DependencyInputs::capture(dir.path()).unwrap();
        assert_eq!(
            first.fingerprint.sources,
            [
                "package.json",
                "pnpm-lock.yaml",
                "pnpm-workspace.yaml",
                "packages/a/package.json"
            ]
        );
        first
            .verify_after(
                &DependencyInputs::capture(dir.path()).unwrap(),
                RequiredRuntime::Node,
                PrepareAction::Skipped,
            )
            .unwrap();
        std::fs::write(
            dir.path().join(pnpm_workspace::FILE_NAME),
            "packages: ['packages/*']\ncatalog:\n chalk: ^5.0.0\n",
        )
        .unwrap();
        let changed = DependencyInputs::capture(dir.path()).unwrap();
        assert_ne!(first.fingerprint.hash, changed.fingerprint.hash);
        assert!(
            first
                .verify_after(&changed, RequiredRuntime::Node, PrepareAction::Installed)
                .is_err()
        );
    }

    #[test]
    fn pnpm_member_changes_cannot_hide_behind_unchanged_yaml_and_lock() {
        let dir = pnpm_project("packages: ['packages/*']\n");
        member(dir.path(), "packages/a", r#"{"name":"a"}"#);
        let root_files = ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"];
        let original: Vec<_> = root_files
            .iter()
            .map(|name| std::fs::read(dir.path().join(name)).unwrap())
            .collect();
        let mut before = DependencyInputs::capture(dir.path()).unwrap();
        for operation in ["edit", "add", "remove"] {
            match operation {
                "edit" => member(dir.path(), "packages/a", r#"{"name":"changed"}"#),
                "add" => member(dir.path(), "packages/b", "{}"),
                _ => std::fs::rename(dir.path().join("packages/b"), dir.path().join("retained-b"))
                    .unwrap(),
            }
            let after = DependencyInputs::capture(dir.path()).unwrap();
            assert_ne!(
                before.fingerprint.hash, after.fingerprint.hash,
                "{operation}"
            );
            assert!(
                before
                    .verify_after(&after, RequiredRuntime::Bun, PrepareAction::Installed)
                    .is_err()
            );
            assert_eq!(
                original,
                root_files
                    .iter()
                    .map(|name| std::fs::read(dir.path().join(name)).unwrap())
                    .collect::<Vec<_>>()
            );
            before = after;
        }
    }

    #[test]
    fn pnpm_discovery_rechecks_declaration_presence_and_contents() {
        let dir = pnpm_project("packages: ['packages/*']\n");
        let inventory = discover(dir.path(), super::super::install::INPUT_NAMES).unwrap();
        std::fs::write(
            dir.path().join(pnpm_workspace::FILE_NAME),
            "packages: ['other/*']\n",
        )
        .unwrap();
        assert!(inventory.verify(&inventory.root_manifest).is_err());
        let inventory = discover(dir.path(), super::super::install::INPUT_NAMES).unwrap();
        std::fs::rename(
            dir.path().join(pnpm_workspace::FILE_NAME),
            dir.path().join("retained.yaml"),
        )
        .unwrap();
        assert!(inventory.verify(&inventory.root_manifest).is_err());
        let absent = discover(dir.path(), super::super::install::INPUT_NAMES).unwrap();
        std::fs::write(
            dir.path().join(pnpm_workspace::FILE_NAME),
            "packages: ['packages/*']\n",
        )
        .unwrap();
        assert!(absent.verify(&absent.root_manifest).is_err());
    }

    #[test]
    fn pnpm_defaults_and_json_declarations_share_a_bounded_union() {
        let dir = pnpm_project("catalog: {}\n");
        member(dir.path(), "packages/a", "{}");
        member(dir.path(), "node_modules/generated", "{}");
        let inputs = DependencyInputs::capture(dir.path()).unwrap();
        assert!(
            inputs
                .fingerprint
                .sources
                .contains(&"packages/a/package.json".to_owned())
        );
        assert!(
            !inputs
                .fingerprint
                .sources
                .iter()
                .any(|name| name.contains("node_modules"))
        );
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces":["other/*"]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join(pnpm_workspace::FILE_NAME),
            "packages: ['packages/*']\n",
        )
        .unwrap();
        member(dir.path(), "other/b", "{}");
        let inputs = DependencyInputs::capture(dir.path()).unwrap();
        assert!(
            inputs
                .fingerprint
                .sources
                .contains(&"other/b/package.json".to_owned())
        );
        assert!(
            inputs
                .fingerprint
                .sources
                .contains(&"packages/a/package.json".to_owned())
        );
    }

    #[test]
    fn pnpm_config_without_its_lock_never_selects_the_default_manager() {
        let dir = pnpm_project("packages: ['packages/*']\n");
        std::fs::rename(
            dir.path().join("pnpm-lock.yaml"),
            dir.path().join("retained-lock.yaml"),
        )
        .unwrap();
        let result = DependencyInputs::capture(dir.path());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("requires pnpm-lock.yaml")
        );
    }

    #[test]
    fn pnpm_member_lock_and_config_changes_invalidate_the_shared_observation() {
        for name in ["pnpm-lock.yaml", ".npmrc"] {
            let dir = pnpm_project("packages: ['packages/*']\nsharedWorkspaceLockfile: false\n");
            member(dir.path(), "packages/a", r#"{"name":"a"}"#);
            let path = dir.path().join("packages/a").join(name);
            let absent = DependencyInputs::capture(dir.path()).unwrap();
            std::fs::write(&path, b"first version\n").unwrap();
            let added = DependencyInputs::capture(dir.path()).unwrap();
            assert_ne!(absent.fingerprint.hash, added.fingerprint.hash);
            assert!(
                absent
                    .verify_after(&added, RequiredRuntime::Node, PrepareAction::Installed)
                    .is_err()
            );
            std::fs::write(&path, b"other version\n").unwrap();
            let edited = DependencyInputs::capture(dir.path()).unwrap();
            assert_ne!(added.fingerprint.hash, edited.fingerprint.hash);
            assert!(
                added
                    .verify_after(&edited, RequiredRuntime::Node, PrepareAction::Installed)
                    .is_err()
            );
            std::fs::rename(&path, dir.path().join("retained-member-input")).unwrap();
            let removed = DependencyInputs::capture(dir.path()).unwrap();
            assert_eq!(absent.fingerprint, removed.fingerprint);
            assert!(
                edited
                    .verify_after(&removed, RequiredRuntime::Node, PrepareAction::Skipped)
                    .is_err()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn pnpm_yaml_symlink_is_not_followed() {
        let dir = pnpm_project("packages: ['packages/*']\n");
        let retained = dir.path().join("retained.yaml");
        std::fs::rename(dir.path().join(pnpm_workspace::FILE_NAME), &retained).unwrap();
        std::os::unix::fs::symlink(&retained, dir.path().join(pnpm_workspace::FILE_NAME)).unwrap();
        assert!(DependencyInputs::capture(dir.path()).is_err());
        assert_eq!(
            std::fs::read(retained).unwrap(),
            b"packages: ['packages/*']\n"
        );
    }
}
