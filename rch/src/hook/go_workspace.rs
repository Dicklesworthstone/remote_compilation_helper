//! A closed source boundary for Go modules and workspaces.
//!
//! Go parses its own manifests. This module consumes `go {work,mod} edit
//! -json`, resolves only the local declarations that Go actually honors, and
//! binds the source control files that must survive transfer unchanged. The
//! caller must bind each JSON response to the same captured manifest bytes.

use anyhow::{Context, Result, ensure};
use rch_common::normalize_project_path_with_policy;
use rch_common::path_topology::PathTopologyPolicy;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_MODULES: usize = 64;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_ANCESTORS: usize = 128;

#[derive(Debug)]
pub(super) struct GoSourcePlan {
    pub(super) source_root: PathBuf,
    pub(super) selected_module: Option<PathBuf>,
    pub(super) workspace: Option<PathBuf>,
    pub(super) required_files: BTreeMap<PathBuf, String>,
    pub(super) absent_files: Vec<PathBuf>,
    pub(super) workspace_edit_args: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WorkspaceJson {
    #[serde(rename = "Use")]
    modules: Option<Vec<WorkspaceUse>>,
    replace: Option<Vec<Replacement>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WorkspaceUse {
    disk_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ModuleJson {
    module: ModuleVersion,
    replace: Option<Vec<Replacement>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Replacement {
    old: ModuleVersion,
    new: ModuleVersion,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ModuleVersion {
    path: String,
    #[serde(default)]
    version: String,
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    modified: std::time::SystemTime,
    inode: (u64, u64, i64, i64),
}

impl FileIdentity {
    fn read(metadata: &std::fs::Metadata) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.is_file(),
            "Go control input is not an ordinary file"
        );
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified()?,
            inode: (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        })
    }
}

fn checked_text(text: &str) -> Result<()> {
    ensure!(
        !text.is_empty() && !text.contains('\\') && !text.chars().any(char::is_control),
        "Go source declaration is empty or contains an unsupported path character"
    );
    Ok(())
}

/// Require real path components, including components that a later `..`
/// would discard. Canonicalization alone would accept `symlink/../module`.
fn checked_directory(path: &Path, topology: &PathTopologyPolicy) -> Result<PathBuf> {
    checked_text(path.to_str().context("non-UTF-8 Go source directory")?)?;
    let normalized = normalize_project_path_with_policy(path, topology)
        .context("Go source directory is outside the configured topology")?;
    ensure!(
        normalized.canonical_path() == path,
        "Go source directory must use its canonical topology path"
    );
    let relative = path
        .strip_prefix(normalized.canonical_root())
        .context("Go source directory escaped its canonical root")?;
    let mut current = normalized.canonical_root().to_owned();
    for component in std::iter::once(None).chain(relative.components().map(Some)) {
        if let Some(component) = component {
            let Component::Normal(name) = component else {
                anyhow::bail!("Go source directory is not normalized");
            };
            current.push(name);
        }
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("inspect Go source directory {}", current.display()))?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Go source directory contains a symlink or non-directory: {}",
            current.display()
        );
    }
    Ok(path.to_owned())
}

fn manifest_parent(file: &Path, topology: &PathTopologyPolicy) -> Result<PathBuf> {
    checked_text(file.to_str().context("non-UTF-8 Go manifest path")?)?;
    ensure!(
        file.is_absolute() && file.file_name().is_some(),
        "Go manifest must have an absolute file path"
    );
    let parent = checked_directory(
        file.parent().context("Go manifest has no parent")?,
        topology,
    )?;
    let metadata = std::fs::symlink_metadata(file).context("inspect selected Go manifest")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Go manifest must be an ordinary file"
    );
    Ok(parent)
}

fn local_directory(base: &Path, raw: &str, topology: &PathTopologyPolicy) -> Result<PathBuf> {
    checked_text(raw)?;
    ensure!(
        !Path::new(raw).is_absolute() && !raw.contains(':'),
        "Go local source declarations must be relative paths"
    );
    let mut current = base.to_owned();
    for (depth, component) in Path::new(raw).components().enumerate() {
        ensure!(
            depth < MAX_ANCESTORS,
            "Go source declaration exceeds its depth limit"
        );
        match component {
            Component::CurDir => {}
            Component::Normal(name) => current.push(name),
            Component::ParentDir => {
                ensure!(
                    current.pop(),
                    "Go source declaration escaped the filesystem root"
                );
            }
            _ => anyhow::bail!("Go local source declaration is not a relative path"),
        }
        checked_directory(&current, topology)?;
    }
    checked_directory(&current, topology)
}

fn parse_workspace(json: &[u8]) -> Result<WorkspaceJson> {
    ensure!(
        json.len() <= MAX_MANIFEST_BYTES,
        "Go workspace JSON exceeds its byte limit"
    );
    serde_json::from_slice(json).context("invalid Go workspace JSON")
}

pub(super) fn workspace_modules(
    workspace_file: &Path,
    json: &[u8],
    topology: &PathTopologyPolicy,
) -> Result<Vec<PathBuf>> {
    let root = manifest_parent(workspace_file, topology)?;
    let workspace = parse_workspace(json)?;
    let modules = workspace.modules.unwrap_or_default();
    ensure!(
        !modules.is_empty() && modules.len() <= MAX_MODULES,
        "Go workspace requires between one and {MAX_MODULES} modules"
    );
    let mut roots = BTreeSet::new();
    for module in modules {
        let directory = local_directory(&root, &module.disk_path, topology)?;
        ensure!(
            directory.starts_with(&root),
            "Go workspace module escapes its source root"
        );
        ensure!(
            roots.insert(directory),
            "Go workspace repeats a module directory"
        );
    }
    Ok(roots.into_iter().collect())
}

fn replacement_directories(
    base: &Path,
    replacements: &[Replacement],
    topology: &PathTopologyPolicy,
) -> Result<Vec<(PathBuf, String)>> {
    ensure!(
        replacements.len() <= MAX_MODULES,
        "Go replacement count exceeds its limit"
    );
    let mut directories = Vec::new();
    for replacement in replacements {
        checked_text(&replacement.old.path)?;
        ensure!(
            !replacement.old.path.contains(['@', '='])
                && !replacement.old.version.contains(['@', '=', '\\'])
                && !replacement.old.version.chars().any(char::is_control),
            "Go replacement has an invalid module identity"
        );
        if !replacement.new.version.is_empty() {
            // Versioned replacements are resolved in the external module
            // cache. Their spelling is never interpreted as a source path.
            continue;
        }
        ensure!(
            replacement.new.path == "."
                || replacement.new.path == ".."
                || replacement.new.path.starts_with("./")
                || replacement.new.path.starts_with("../"),
            "Go unversioned replacement must name a relative local directory"
        );
        let directory = local_directory(base, &replacement.new.path, topology)?;
        let identity = if replacement.old.version.is_empty() {
            replacement.old.path.clone()
        } else {
            format!("{}@{}", replacement.old.path, replacement.old.version)
        };
        directories.push((directory, identity));
    }
    Ok(directories)
}

fn enclosing_repository(module: &Path, topology: &PathTopologyPolicy) -> Result<PathBuf> {
    for (depth, ancestor) in module
        .ancestors()
        .take_while(|path| path.starts_with(topology.canonical_root()))
        .enumerate()
    {
        ensure!(
            depth < MAX_ANCESTORS,
            "Go repository ancestry exceeds its depth limit"
        );
        match std::fs::symlink_metadata(ancestor.join(".git")) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink() && (metadata.is_file() || metadata.is_dir()),
                    "Go repository boundary is not an ordinary Git directory or worktree file"
                );
                return checked_directory(ancestor, topology);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect Go repository boundary"),
        }
    }
    anyhow::bail!("Go local replacements outside the module require an enclosing Git repository")
}

fn capture_file(
    file: PathBuf,
    optional: bool,
    plan: &mut GoSourcePlan,
    total: &mut usize,
    topology: &PathTopologyPolicy,
) -> Result<()> {
    if plan.required_files.contains_key(&file) || plan.absent_files.contains(&file) {
        return Ok(());
    }
    ensure!(
        file.starts_with(&plan.source_root),
        "Go manifest escapes selected source"
    );
    checked_directory(
        file.parent().context("Go manifest has no parent")?,
        topology,
    )?;
    let identity = match std::fs::symlink_metadata(&file) {
        Ok(metadata) => {
            ensure!(
                !metadata.file_type().is_symlink(),
                "Go control input is a symlink: {}",
                file.display()
            );
            FileIdentity::read(&metadata)?
        }
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => {
            plan.absent_files.push(file);
            return Ok(());
        }
        Err(error) => return Err(error).context("inspect Go control input"),
    };
    let remaining = MAX_MANIFEST_BYTES.saturating_sub(*total);
    ensure!(
        identity.len <= remaining as u64,
        "Go control inputs exceed the aggregate byte limit"
    );
    // Walk from the configured root using directory descriptors. A source
    // directory exchanged for a symlink during planning must never redirect
    // a control-file read outside the admitted source namespace.
    let directory_flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::DIRECTORY;
    let mut descriptor = rustix::fs::open(
        topology.canonical_root(),
        directory_flags,
        rustix::fs::Mode::empty(),
    )
    .context("open Go source topology root")?;
    let relative = file
        .strip_prefix(topology.canonical_root())
        .context("Go control input escaped topology")?;
    let components: Vec<_> = relative.components().collect();
    for component in &components[..components.len().saturating_sub(1)] {
        let Component::Normal(name) = component else {
            anyhow::bail!("Go control input has a nonliteral path component");
        };
        descriptor = rustix::fs::openat(
            &descriptor,
            *name,
            directory_flags,
            rustix::fs::Mode::empty(),
        )
        .context("open Go control input parent without following symlinks")?;
    }
    let mut opened = std::fs::File::from(
        rustix::fs::openat(
            &descriptor,
            file.file_name()
                .context("Go control input has no filename")?,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .context("open Go control input without following symlinks")?,
    );
    ensure!(
        FileIdentity::read(&opened.metadata()?)? == identity,
        "Go control input changed before read"
    );
    let mut bytes = Vec::new();
    (&mut opened)
        .take(identity.len + 1)
        .read_to_end(&mut bytes)
        .context("read Go control input")?;
    let current = std::fs::symlink_metadata(&file).context("recheck Go control input")?;
    ensure!(
        bytes.len() as u64 == identity.len
            && FileIdentity::read(&opened.metadata()?)? == identity
            && !current.file_type().is_symlink()
            && FileIdentity::read(&current)? == identity,
        "Go control input changed during read"
    );
    checked_directory(
        file.parent().context("Go control input has no parent")?,
        topology,
    )?;
    *total += bytes.len();
    let content = String::from_utf8(bytes).context("Go control input is not UTF-8")?;
    plan.required_files.insert(file, content);
    Ok(())
}

fn capture_workspace_vendor(
    plan: &mut GoSourcePlan,
    total: &mut usize,
    topology: &PathTopologyPolicy,
) -> Result<()> {
    let vendor = plan.source_root.join("vendor");
    match std::fs::symlink_metadata(&vendor) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "Go workspace vendor root must be a real directory"
            );
            capture_file(vendor.join("modules.txt"), true, plan, total, topology)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            plan.absent_files.push(vendor.join("modules.txt"));
            Ok(())
        }
        Err(error) => Err(error).context("inspect Go workspace vendor root"),
    }
}

/// Capture one control file through the same topology and descriptor checks
/// as the final source plan, before asking Go to parse a private copy.
pub(super) fn read_control_file(path: &Path, topology: &PathTopologyPolicy) -> Result<Vec<u8>> {
    let source_root = manifest_parent(path, topology)?;
    let mut captured = GoSourcePlan {
        source_root,
        selected_module: None,
        workspace: None,
        required_files: BTreeMap::new(),
        absent_files: Vec::new(),
        workspace_edit_args: Vec::new(),
    };
    capture_file(path.to_owned(), false, &mut captured, &mut 0, topology)?;
    Ok(captured
        .required_files
        .remove(path)
        .context("Go control input disappeared during capture")?
        .into_bytes())
}

pub(super) fn plan(
    invocation: &Path,
    selected_module: Option<&Path>,
    selected_workspace: Option<&Path>,
    workspace_json: Option<&[u8]>,
    module_json: &BTreeMap<PathBuf, Vec<u8>>,
    topology: &PathTopologyPolicy,
) -> Result<GoSourcePlan> {
    checked_directory(invocation, topology)?;
    ensure!(
        selected_workspace.is_some() == workspace_json.is_some(),
        "Go workspace path and parsed declarations must be supplied together"
    );
    let selected_module_root = selected_module
        .map(|file| {
            ensure!(
                file.file_name().is_some_and(|name| name == "go.mod"),
                "Go module file is not go.mod"
            );
            manifest_parent(file, topology)
        })
        .transpose()?;
    let (source_root, main_modules) = if let Some(workspace) = selected_workspace {
        let root = manifest_parent(workspace, topology)?;
        let modules = workspace_modules(workspace, workspace_json.unwrap_or_default(), topology)?;
        ensure!(
            invocation.starts_with(&root),
            "Go invocation is outside its workspace source root"
        );
        if let Some(module) = &selected_module_root {
            ensure!(
                modules.contains(module),
                "Go selected module is not a workspace member"
            );
            ensure!(
                invocation.starts_with(module),
                "Go invocation is outside its selected module"
            );
        }
        (root, modules)
    } else {
        let root =
            selected_module_root.context("Go source planning requires a module or workspace")?;
        ensure!(
            invocation.starts_with(&root),
            "Go invocation is outside its selected module"
        );
        (root.clone(), vec![root])
    };
    ensure!(
        module_json.len() == main_modules.len()
            && main_modules
                .iter()
                .all(|root| module_json.contains_key(root)),
        "Go module declarations do not exactly cover the selected main modules"
    );
    let workspace_declarations = workspace_json.map(parse_workspace).transpose()?;
    let workspace_replacements = workspace_declarations
        .as_ref()
        .and_then(|workspace| workspace.replace.as_deref())
        .unwrap_or_default();
    let mut json_bytes = workspace_json.map_or(0, <[u8]>::len);
    let mut roots: BTreeSet<_> = main_modules.iter().cloned().collect();
    let mut has_local_replacements = false;
    for module in &main_modules {
        let json = &module_json[module];
        json_bytes = json_bytes
            .checked_add(json.len())
            .context("Go declaration size overflow")?;
        ensure!(
            json_bytes <= MAX_MANIFEST_BYTES,
            "Go declarations exceed their aggregate byte limit"
        );
        let parsed: ModuleJson = serde_json::from_slice(json).context("invalid Go module JSON")?;
        checked_text(&parsed.module.path)?;
        // A workspace replace overrides the same module/version from a main
        // module. An overridden directory may legitimately be absent or live
        // outside this workspace and is not part of the selected source.
        let effective: Vec<_> = parsed
            .replace
            .unwrap_or_default()
            .into_iter()
            .filter(|replacement| {
                !workspace_replacements.iter().any(|override_| {
                    override_.old.path == replacement.old.path
                        && (override_.old.version.is_empty()
                            || override_.old.version == replacement.old.version)
                })
            })
            .collect();
        for (directory, _) in replacement_directories(module, &effective, topology)? {
            has_local_replacements = true;
            roots.insert(directory);
            ensure!(
                roots.len() <= MAX_MODULES,
                "Go source closure exceeds its module limit"
            );
        }
    }
    let mut workspace_edit_args = Vec::new();
    if let Some(workspace) = selected_workspace {
        let parsed = parse_workspace(workspace_json.unwrap_or_default())?;
        for module in parsed.modules.unwrap_or_default() {
            let directory = local_directory(&source_root, &module.disk_path, topology)?;
            workspace_edit_args.push(format!("-dropuse={}", module.disk_path));
            workspace_edit_args.push(format!("-use={}", directory.display()));
        }
        for (directory, identity) in replacement_directories(
            workspace.parent().context("Go workspace has no parent")?,
            &parsed.replace.unwrap_or_default(),
            topology,
        )? {
            has_local_replacements = true;
            roots.insert(directory.clone());
            ensure!(
                roots.len() <= MAX_MODULES,
                "Go source closure exceeds its module limit"
            );
            workspace_edit_args.push(format!("-replace={identity}={}", directory.display()));
        }
    }
    let source_root = if roots.iter().all(|root| root.starts_with(&source_root)) {
        source_root
    } else {
        ensure!(
            selected_workspace.is_none(),
            "Go workspace local replacement escapes its source root"
        );
        enclosing_repository(&source_root, topology)?
    };
    ensure!(
        roots.iter().all(|root| root.starts_with(&source_root)),
        "Go local replacement escapes the selected repository source boundary"
    );
    let mut plan = GoSourcePlan {
        source_root,
        selected_module: selected_module.map(Path::to_owned),
        workspace: selected_workspace.map(Path::to_owned),
        required_files: BTreeMap::new(),
        absent_files: Vec::new(),
        workspace_edit_args,
    };
    let mut total = 0;
    for root in roots {
        capture_file(root.join("go.mod"), false, &mut plan, &mut total, topology)?;
        capture_file(root.join("go.sum"), true, &mut plan, &mut total, topology)?;
    }
    if let Some(workspace) = selected_workspace {
        capture_file(workspace.to_owned(), false, &mut plan, &mut total, topology)?;
        let mut sum = workspace.as_os_str().to_os_string();
        sum.push(".sum");
        capture_file(PathBuf::from(sum), true, &mut plan, &mut total, topology)?;
        capture_workspace_vendor(&mut plan, &mut total, topology)?;
        // Go compares vendored replacement spellings with paths relative to
        // the selected workfile. Relocating that workfile would change those
        // spellings while the read-only vendor metadata retains the originals.
        ensure!(
            !has_local_replacements
                || !plan
                    .required_files
                    .contains_key(&plan.source_root.join("vendor/modules.txt")),
            "Go workspace vendoring with local replacements requires a private vendor metadata projection"
        );
    }
    plan.absent_files.sort();
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (PathBuf, PathTopologyPolicy) {
        let directory = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
        let topology = PathTopologyPolicy::new(directory.clone(), directory.join("alias"));
        (directory, topology)
    }

    fn module(root: &Path, name: &str) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(
            root.join("go.mod"),
            format!("module example.invalid/{name}\n\ngo 1.22\n"),
        )
        .unwrap();
    }

    fn module_json(name: &str, replacements: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"Module": {"Path": format!("example.invalid/{name}")}, "Replace": replacements})).unwrap()
    }

    fn replacement(name: &str, path: &str) -> serde_json::Value {
        json!({"Old": {"Path": format!("example.invalid/{name}")}, "New": {"Path": path}})
    }

    #[test]
    fn workspace_closure_preserves_members_replacements_and_absent_sums() {
        let (root, topology) = fixture();
        let app = root.join("app");
        let library = root.join("library with spaces");
        let local = root.join("local");
        module(&app, "app");
        module(&library, "library");
        module(&local, "local");
        // Replacements in a dependency module do not participate in Go's
        // main-module resolution and must not cause a recursive traversal.
        std::fs::write(
            local.join("go.mod"),
            "module example.invalid/local\nreplace example.invalid/ignored => /outside/absent\n",
        )
        .unwrap();
        let invocation = app.join("cmd/server");
        std::fs::create_dir_all(&invocation).unwrap();
        let workspace = root.join("go.work");
        std::fs::write(
            &workspace,
            "go 1.22\nuse (\n ./app\n \"./library with spaces\"\n)\n",
        )
        .unwrap();
        std::fs::write(
            app.join("go.sum"),
            "example.invalid/remote v1.0.0 h1:fixture\n",
        )
        .unwrap();
        let work_json = serde_json::to_vec(
            &json!({"Use": [{"DiskPath": "./app"}, {"DiskPath": "./library with spaces"}]}),
        )
        .unwrap();
        let modules = BTreeMap::from([
            (
                app.clone(),
                module_json(
                    "app",
                    json!([replacement("library", "../library with spaces")]),
                ),
            ),
            (
                library.clone(),
                module_json("library", json!([replacement("local", "../local")])),
            ),
        ]);
        let planned = plan(
            &invocation,
            Some(&app.join("go.mod")),
            Some(&workspace),
            Some(&work_json),
            &modules,
            &topology,
        )
        .unwrap();
        assert_eq!(planned.source_root, root);
        assert_eq!(planned.selected_module.as_ref(), Some(&app.join("go.mod")));
        assert_eq!(planned.workspace.as_ref(), Some(&workspace));
        for file in [
            &workspace,
            &app.join("go.mod"),
            &app.join("go.sum"),
            &library.join("go.mod"),
            &local.join("go.mod"),
        ] {
            assert!(
                planned.required_files.contains_key(file),
                "{}",
                file.display()
            );
        }
        assert!(planned.absent_files.contains(&root.join("go.work.sum")));
        assert!(planned.absent_files.contains(&library.join("go.sum")));
        assert!(
            planned
                .absent_files
                .contains(&root.join("vendor/modules.txt"))
        );
        assert!(
            planned
                .workspace_edit_args
                .contains(&format!("-use={}", library.display()))
        );
    }

    #[test]
    fn workspace_override_ignores_unselected_missing_module_replace() {
        let (root, topology) = fixture();
        let app = root.join("app");
        let local = root.join("local");
        module(&app, "app");
        module(&local, "local");
        let workspace = root.join("selected.work");
        std::fs::write(
            &workspace,
            "go 1.22\nuse ./app\nreplace example.invalid/local => ./local\n",
        )
        .unwrap();
        std::fs::write(root.join("selected.work.sum"), "captured work sum\n").unwrap();
        let work_json = serde_json::to_vec(
            &json!({"Use": [{"DiskPath": "./app"}], "Replace": [replacement("local", "./local")]}),
        )
        .unwrap();
        let modules = BTreeMap::from([(
            app.clone(),
            module_json(
                "app",
                json!([replacement("local", "../../../outside/missing")]),
            ),
        )]);
        let planned = plan(
            &app,
            Some(&app.join("go.mod")),
            Some(&workspace),
            Some(&work_json),
            &modules,
            &topology,
        )
        .unwrap();
        assert!(planned.required_files.contains_key(&local.join("go.mod")));
        assert_eq!(
            planned.required_files[&root.join("selected.work.sum")],
            "captured work sum\n"
        );
        assert!(planned.workspace_edit_args.contains(&format!(
            "-replace=example.invalid/local={}",
            local.display()
        )));
    }

    #[test]
    fn standalone_relative_replacements_expand_only_to_nearest_git_root() {
        let (root, topology) = fixture();
        let repository = root.join("repo");
        let app = repository.join("app");
        let local = repository.join("local");
        module(&app, "app");
        module(&local, "local");
        std::fs::create_dir(repository.join(".git")).unwrap();
        let invocation = app.join("cmd");
        std::fs::create_dir(&invocation).unwrap();
        let modules = BTreeMap::from([(
            app.clone(),
            module_json("app", json!([replacement("local", "../local")])),
        )]);
        let planned = plan(
            &invocation,
            Some(&app.join("go.mod")),
            None,
            None,
            &modules,
            &topology,
        )
        .unwrap();
        assert_eq!(planned.source_root, repository);
        assert!(planned.required_files.contains_key(&local.join("go.mod")));
        // A nearer independent repository is an ownership boundary even when
        // an enclosing repository would contain the replacement directory.
        std::fs::write(app.join(".git"), "gitdir: /unrelated/worktree\n").unwrap();
        assert!(
            plan(
                &invocation,
                Some(&app.join("go.mod")),
                None,
                None,
                &modules,
                &topology
            )
            .is_err()
        );
    }

    #[test]
    fn standalone_without_local_replacements_keeps_module_root() {
        let (root, topology) = fixture();
        let app = root.join("app");
        module(&app, "app");
        std::fs::create_dir(root.join(".git")).unwrap();
        let modules = BTreeMap::from([(
            app.clone(),
            module_json(
                "app",
                json!([{"Old": {"Path": "example.invalid/remote"}, "New": {"Path": "example.invalid/fork", "Version": "v1.0.0"}}]),
            ),
        )]);
        let planned = plan(
            &app,
            Some(&app.join("go.mod")),
            None,
            None,
            &modules,
            &topology,
        )
        .unwrap();
        assert_eq!(planned.source_root, app);
        assert!(planned.workspace.is_none());
        assert!(planned.workspace_edit_args.is_empty());
        assert_eq!(planned.required_files.len(), 1);
    }

    #[test]
    fn workspace_refuses_absolute_outside_duplicate_and_symlink_members() {
        let (root, topology) = fixture();
        let workspace_root = root.join("work");
        let member = workspace_root.join("member");
        let outside = root.join("outside");
        module(&member, "member");
        module(&outside, "outside");
        std::os::unix::fs::symlink(&member, workspace_root.join("linked")).unwrap();
        let workspace = workspace_root.join("go.work");
        std::fs::write(&workspace, "go 1.22\n").unwrap();
        for uses in [
            json!([{ "DiskPath": member.display().to_string() }]),
            json!([{ "DiskPath": "../outside" }]),
            json!([{ "DiskPath": "./member" }, { "DiskPath": "member" }]),
            json!([{ "DiskPath": "./linked" }]),
            json!([{ "DiskPath": "./linked/../member" }]),
            json!([{ "DiskPath": "C:\\project" }]),
            json!([]),
            serde_json::Value::Null,
        ] {
            let json = serde_json::to_vec(&json!({"Use": uses})).unwrap();
            assert!(
                workspace_modules(&workspace, &json, &topology).is_err(),
                "{uses}"
            );
        }
    }

    #[test]
    fn exact_main_module_set_and_workspace_membership_are_required() {
        let (root, topology) = fixture();
        let app = root.join("app");
        let extra = root.join("extra");
        module(&app, "app");
        module(&extra, "extra");
        let workspace = root.join("go.work");
        std::fs::write(&workspace, "go 1.22\nuse ./app\n").unwrap();
        let work_json = serde_json::to_vec(&json!({"Use": [{"DiskPath": "./app"}]})).unwrap();
        let modules = BTreeMap::from([(app.clone(), module_json("app", serde_json::Value::Null))]);
        assert!(
            plan(
                &root,
                None,
                Some(&workspace),
                Some(&work_json),
                &modules,
                &topology
            )
            .is_ok()
        );
        assert!(
            plan(
                &extra,
                Some(&extra.join("go.mod")),
                Some(&workspace),
                Some(&work_json),
                &modules,
                &topology
            )
            .is_err()
        );
        assert!(
            plan(
                &app,
                Some(&app.join("go.mod")),
                Some(&workspace),
                Some(&work_json),
                &BTreeMap::new(),
                &topology
            )
            .is_err()
        );
        let mut extra_modules = modules.clone();
        extra_modules.insert(extra, module_json("extra", serde_json::Value::Null));
        assert!(
            plan(
                &app,
                Some(&app.join("go.mod")),
                Some(&workspace),
                Some(&work_json),
                &extra_modules,
                &topology
            )
            .is_err()
        );
    }

    #[test]
    fn workspace_binds_vendor_manifest_and_refuses_symlinked_inputs() {
        let (root, topology) = fixture();
        let app = root.join("app");
        module(&app, "app");
        let workspace = root.join("go.work");
        std::fs::write(&workspace, "go 1.22\nuse ./app\n").unwrap();
        std::fs::create_dir(root.join("vendor")).unwrap();
        std::fs::write(root.join("vendor/modules.txt"), "## workspace\n").unwrap();
        let work_json = serde_json::to_vec(&json!({"Use": [{"DiskPath": "./app"}]})).unwrap();
        let modules = BTreeMap::from([(app.clone(), module_json("app", serde_json::Value::Null))]);
        let planned = plan(
            &app,
            Some(&app.join("go.mod")),
            Some(&workspace),
            Some(&work_json),
            &modules,
            &topology,
        )
        .unwrap();
        assert_eq!(
            planned.required_files[&root.join("vendor/modules.txt")],
            "## workspace\n"
        );
        std::os::unix::fs::symlink(root.join("vendor/modules.txt"), app.join("go.sum")).unwrap();
        assert!(
            plan(
                &app,
                Some(&app.join("go.mod")),
                Some(&workspace),
                Some(&work_json),
                &modules,
                &topology
            )
            .is_err()
        );
    }

    #[test]
    fn control_files_and_declarations_have_aggregate_bounds() {
        let (root, topology) = fixture();
        let app = root.join("app");
        module(&app, "app");
        let modules = BTreeMap::from([(app.clone(), module_json("app", serde_json::Value::Null))]);
        std::fs::write(app.join("go.sum"), vec![b'a'; MAX_MANIFEST_BYTES]).unwrap();
        assert!(
            plan(
                &app,
                Some(&app.join("go.mod")),
                None,
                None,
                &modules,
                &topology
            )
            .is_err()
        );
        let too_large = BTreeMap::from([(app.clone(), vec![b' '; MAX_MANIFEST_BYTES + 1])]);
        assert!(
            plan(
                &app,
                Some(&app.join("go.mod")),
                None,
                None,
                &too_large,
                &topology
            )
            .is_err()
        );
    }
}
