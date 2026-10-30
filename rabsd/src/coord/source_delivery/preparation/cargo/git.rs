//! Capture locked Cargo Git commits without importing user configuration,
//! checkouts, refs, hooks, alternates or unrelated repository history.
//!
//! Git reads a private object view backed by retained no-follow descriptors.
//! Only selected commit/tree/blob closures are repacked and verified. Cargo
//! resolves those inputs offline; no action-cache authority is created here.

use super::registry::{MAX_ARCHIVE_MEMBERS, open_home, open_selected};
use super::vendor::GitSource;
use super::{
    MAX_PACKAGES, OUTPUT_LIMIT, PreparationControl, bounded_command_with_input, contained_relative,
    invalid, local_tool_controlled, require,
};
use rabs_sandbox::cargo_home::CAPTURED_GIT_CONFIG;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const MAX_DATABASES: usize = 64;
#[cfg(target_os = "linux")]
const MAX_OBJECT_FILES: usize = 512;
#[cfg(target_os = "linux")]
const MAX_OBJECT_STORE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(180);
type GitIdentity = (String, String, GitSource, String);
type CapturedFiles = BTreeMap<String, Vec<u8>>;

fn object_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(unix, test))]
fn namespace(value: &str) -> bool {
    value.len() <= 128
        && value.rsplit_once('-').is_some_and(|(name, suffix)| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
                && suffix.len() == 16
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Cargo's manifest selector remains part of the source identity, but the full
/// locked commit alone selects captured objects. Frozen metadata resolution must
/// reproduce that identity from the private cache without resolving moving refs.
/// Selector validation belongs to the lock/metadata boundary, where its encoding
/// is known; applying literal reference bounds here would reject encoded locks.
pub(super) fn locked_revision(source: &str) -> io::Result<&str> {
    require(
        source.len() <= 4096,
        "Git source identity exceeds its bound",
    )?;
    let (selector, revision) = source
        .strip_prefix("git+")
        .and_then(|source| source.rsplit_once('#'))
        .ok_or_else(|| invalid("cached Git source requires an exact locked commit"))?;
    require(
        object_id(revision),
        "cached Git source requires a canonical full locked commit",
    )?;
    let url = selector.split_once('?').map_or(selector, |(url, _)| url);
    validate_url(url)?;
    Ok(revision)
}

fn validate_url(url: &str) -> io::Result<()> {
    require(
        url.len() <= 4096
            && ["https://", "http://", "ssh://", "git://", "file:///"]
                .iter()
                .any(|scheme| url.starts_with(scheme))
            && !url.contains(['?', '#', '\\'])
            && !url.chars().any(char::is_control)
            && !url.split_once("://").is_some_and(|(_, tail)| {
                tail.split('/')
                    .next()
                    .is_some_and(|host| host.contains('@'))
            }),
        "cached Git source requires an ordinary URL without credentials",
    )
}

pub(super) fn validate_dependency(fields: &toml::map::Map<String, toml::Value>) -> io::Result<()> {
    GitSource::from_fields(fields)?;
    let url = fields
        .get("git")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| invalid("Git dependency URL must be a string"))?;
    require(
        !["path", "registry", "registry-index"]
            .iter()
            .any(|field| fields.contains_key(*field)),
        "cached Git dependency combines incompatible source selectors",
    )?;
    validate_url(url)
}

pub(super) fn has_locked_packages(lock: &toml::Value) -> bool {
    lock.get("package")
        .and_then(toml::Value::as_array)
        .is_some_and(|packages| {
            packages.iter().any(|package| {
                package
                    .get("source")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|source| source.starts_with("git+"))
            })
        })
}

fn locked_packages(lock: &toml::Value) -> io::Result<BTreeSet<GitIdentity>> {
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .filter(|packages| packages.len() <= MAX_PACKAGES)
        .ok_or_else(|| invalid("cached Git capture requires a bounded Cargo.lock package list"))?;
    let encoded = match lock.get("version") {
        None => false,
        Some(toml::Value::Integer(1..=3)) => false,
        Some(toml::Value::Integer(4)) => true,
        _ => {
            return Err(invalid(
                "unsupported Cargo.lock Git source encoding version",
            ));
        }
    };
    let mut result = BTreeSet::new();
    for package in packages {
        let Some(source) = package
            .get("source")
            .and_then(toml::Value::as_str)
            .filter(|source| source.starts_with("git+"))
        else {
            continue;
        };
        let revision = locked_revision(source)?;
        let identity = if encoded {
            GitSource::parse_encoded(source)?
        } else {
            GitSource::parse(source)?
        };
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid("locked Git package name missing"))?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid("locked Git package version missing"))?;
        require(
            package.get("checksum").is_none()
                && result.insert((name.into(), version.into(), identity, revision.into())),
            "invalid or duplicate locked Git package",
        )?;
    }
    Ok(result)
}

#[derive(Debug)]
struct GitMember {
    object: String,
    size: u64,
    #[cfg(unix)]
    executable: bool,
}

#[derive(Debug)]
struct CapturedCommit {
    members: BTreeMap<String, GitMember>,
}

#[derive(Debug)]
pub(super) struct GitCache {
    packages: BTreeSet<GitIdentity>,
    commits: BTreeMap<(String, String), CapturedCommit>,
    tool: GitTools,
    scratch: PathBuf,
}

#[derive(Debug)]
struct GitTools {
    git: PathBuf,
    prlimit: PathBuf,
}

fn git_command(tool: &GitTools, repository: &Path, scratch: &Path) -> Command {
    // A compressed object can advertise an enormous expansion before ls-tree
    // reports its size. Bound native Git's address space as well as the existing
    // process-group deadline and output limits; no unsafe child hook is needed.
    let mut command = Command::new(&tool.prlimit);
    command
        .args(["--as=2147483648", "--core=0", "--"])
        .arg(&tool.git)
        .env_clear()
        .current_dir(scratch)
        .env("HOME", scratch)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .args([
            "-c",
            "protocol.allow=never",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.multiPackIndex=false",
            "-c",
            "gc.auto=0",
            "-c",
            "pack.threads=1",
            "-c",
            "core.packedGitWindowSize=32m",
            "-c",
            "core.packedGitLimit=256m",
            "-c",
            "core.deltaBaseCacheLimit=32m",
        ])
        .arg("--git-dir")
        .arg(repository);
    for key in ["PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

fn run(
    command: Command,
    scratch: &Path,
    limit: u64,
    input: Option<&[u8]>,
    control: &PreparationControl<'_>,
) -> io::Result<Vec<u8>> {
    bounded_command_with_input(command, scratch, GIT_TIMEOUT, limit, input, control)
}

fn checkpoint(deadline: Instant, control: &PreparationControl<'_>) -> io::Result<()> {
    control.checkpoint()?;
    require(
        Instant::now() < deadline,
        "cached Git acquisition exceeded its runtime bound",
    )
}

fn minimal_repository(root: &Path, revisions: &BTreeSet<String>) -> io::Result<()> {
    let first = revisions
        .first()
        .ok_or_else(|| invalid("empty selected Git revision set"))?;
    fs::create_dir_all(root.join("objects/pack"))?;
    fs::create_dir_all(root.join("refs/heads"))?;
    fs::write(root.join("config"), CAPTURED_GIT_CONFIG)?;
    fs::write(root.join("HEAD"), format!("{first}\n"))?;
    // The fixed generated ref preserves Git's required refs directory through
    // regular-file-only delivery. No original ref enters the projection.
    fs::write(root.join("refs/heads/rabs-captured"), format!("{first}\n"))?;
    fs::write(
        root.join("shallow"),
        revisions
            .iter()
            .map(|revision| format!("{revision}\n"))
            .collect::<String>(),
    )?;
    Ok(())
}

#[cfg(unix)]
fn database_names(root: &File, control: &PreparationControl<'_>) -> io::Result<Vec<String>> {
    let directory = open_selected(root, "git/db", true)?;
    let mut names = BTreeSet::new();
    for (index, entry) in rustix::fs::Dir::read_from(&directory)?.enumerate() {
        control.checkpoint()?;
        require(
            index < 258,
            "Cargo Git database directory exceeds its scan bound",
        )?;
        let entry = entry?;
        if let Ok(name) = entry.file_name().to_str()
            && namespace(name)
        {
            names.insert(name.to_owned());
        }
    }
    require(
        !names.is_empty(),
        "approved Cargo home has no supported Git object database",
    )?;
    Ok(names.into_iter().collect())
}

#[cfg(not(unix))]
fn database_names(_root: &File, _control: &PreparationControl<'_>) -> io::Result<Vec<String>> {
    Err(invalid(
        "cached Git capture requires Linux descriptor-backed object access",
    ))
}

struct ObjectView {
    files: Vec<(File, Metadata)>,
}

impl ObjectView {
    fn verify_unchanged(&self, control: &PreparationControl<'_>) -> io::Result<()> {
        for (file, before) in &self.files {
            control.checkpoint()?;
            let after = file.metadata()?;
            require(
                before.len() == after.len(),
                "Git object storage changed during capture",
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                require(
                    before.dev() == after.dev()
                        && before.ino() == after.ino()
                        && before.mtime() == after.mtime()
                        && before.mtime_nsec() == after.mtime_nsec()
                        && before.ctime() == after.ctime()
                        && before.ctime_nsec() == after.ctime_nsec(),
                    "Git object storage changed during capture",
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn object_view(
    root: &File,
    name: &str,
    destination: &Path,
    control: &PreparationControl<'_>,
) -> io::Result<ObjectView> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::symlink;
    // /proc's visible PID can differ from getpid in a nested PID namespace.
    // Retained descriptors stay owned until the selected bytes are repacked.
    let proc_pid = fs::read_link("/proc/self")?;
    require(
        proc_pid.components().count() == 1
            && proc_pid.to_str().is_some_and(|pid| {
                !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit())
            }),
        "unavailable descriptor-backed Git object view",
    )?;
    let objects = open_selected(root, &format!("git/db/{name}/objects"), true)?;
    for forbidden in ["info/alternates", "info/http-alternates"] {
        match open_selected(&objects, forbidden, false) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => {
                return Err(invalid(
                    "cached Git object alternates are outside the approved source closure",
                ));
            }
        }
    }
    let mut view = ObjectView { files: Vec::new() };
    let mut total = 0_u64;
    let mut link = |path: &str| -> io::Result<()> {
        control.checkpoint()?;
        require(
            view.files.len() < MAX_OBJECT_FILES,
            "cached Git object storage exceeds its descriptor bound",
        )?;
        let file = open_selected(&objects, path, false)?;
        let metadata = file.metadata()?;
        total = total
            .checked_add(metadata.len())
            .filter(|total| *total <= MAX_OBJECT_STORE_BYTES)
            .ok_or_else(|| invalid("cached Git object storage exceeds its byte scan bound"))?;
        require(
            metadata.is_file(),
            "cached Git object must be an ordinary regular file",
        )?;
        let output = destination.join("objects").join(path);
        fs::create_dir_all(
            output
                .parent()
                .ok_or_else(|| invalid("Git object parent missing"))?,
        )?;
        symlink(
            Path::new("/proc")
                .join(&proc_pid)
                .join("fd")
                .join(file.as_raw_fd().to_string()),
            output,
        )?;
        view.files.push((file, metadata));
        Ok(())
    };
    for (index, entry) in rustix::fs::Dir::read_from(&objects)?.enumerate() {
        control.checkpoint()?;
        require(
            index < 260,
            "cached Git object directory exceeds its scan bound",
        )?;
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name == "pack" {
            let directory = open_selected(&objects, "pack", true)?;
            let mut packs = BTreeMap::<String, (bool, bool)>::new();
            for (index, entry) in rustix::fs::Dir::read_from(&directory)?.enumerate() {
                control.checkpoint()?;
                require(
                    index < 2048,
                    "cached Git pack directory exceeds its scan bound",
                )?;
                let entry = entry?;
                let Ok(file) = entry.file_name().to_str() else {
                    continue;
                };
                require(
                    !file.ends_with(".promisor"),
                    "partial Git clones require a fetch broker before source preparation",
                )?;
                let Some((stem, extension)) = file.rsplit_once('.') else {
                    continue;
                };
                let Some(digest) = stem
                    .strip_prefix("pack-")
                    .filter(|digest| object_id(digest))
                else {
                    continue;
                };
                if matches!(extension, "pack" | "idx") {
                    let pair = packs.entry(digest.into()).or_default();
                    if extension == "pack" {
                        pair.0 = true;
                    } else {
                        pair.1 = true;
                    }
                    link(&format!("pack/{file}"))?;
                }
            }
            require(
                packs.values().all(|pair| pair.0 && pair.1),
                "cached Git packs require paired index files",
            )?;
        } else if name.len() == 2
            && name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            let directory = open_selected(&objects, name, true)?;
            for (index, entry) in rustix::fs::Dir::read_from(&directory)?.enumerate() {
                control.checkpoint()?;
                require(
                    index < MAX_OBJECT_FILES + 2,
                    "cached loose Git objects exceed their scan bound",
                )?;
                let entry = entry?;
                let Ok(file) = entry.file_name().to_str() else {
                    continue;
                };
                if file.len() == 38 && object_id(&format!("{name}{file}")) {
                    link(&format!("{name}/{file}"))?;
                }
            }
        }
    }
    Ok(view)
}

#[cfg(not(target_os = "linux"))]
fn object_view(
    _root: &File,
    _name: &str,
    _destination: &Path,
    _control: &PreparationControl<'_>,
) -> io::Result<ObjectView> {
    Err(invalid(
        "cached Git capture requires Linux descriptor-backed object access",
    ))
}

#[cfg(test)]
fn parse_tree(bytes: &[u8], remaining: &mut u64, count: &mut usize) -> io::Result<CapturedCommit> {
    parse_tree_controlled(bytes, remaining, count, &PreparationControl::uncontrolled())
}

fn parse_tree_controlled(
    bytes: &[u8],
    remaining: &mut u64,
    count: &mut usize,
    control: &PreparationControl<'_>,
) -> io::Result<CapturedCommit> {
    require(
        bytes.last() == Some(&0),
        "Git tree listing is empty or truncated",
    )?;
    let mut members = BTreeMap::new();
    for row in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        control.checkpoint()?;
        let tab = row
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| invalid("invalid Git tree entry"))?;
        let fields = std::str::from_utf8(&row[..tab])
            .map_err(|_| invalid("invalid Git tree header"))?
            .split_whitespace()
            .collect::<Vec<_>>();
        require(
            fields.len() == 4
                && matches!(fields[0], "100644" | "100755")
                && fields[1] == "blob"
                && object_id(fields[2]),
            "captured Git sources support regular files only, not symlinks or submodules",
        )?;
        let path = std::str::from_utf8(&row[tab + 1..])
            .map_err(|_| invalid("Git source path is not UTF-8"))?;
        require(
            path.len() <= 4096
                && !path.contains(['\\', ':', '"'])
                && !path.chars().any(char::is_control)
                && path.split('/').all(|part| {
                    !part.is_empty() && !matches!(part, "." | ".." | ".git" | ".gitmodules")
                }),
            "Git source tree contains an unsafe path or unsupported submodule declaration",
        )?;
        let size = fields[3]
            .parse::<u64>()
            .map_err(|_| invalid("invalid Git blob size"))?;
        *remaining = remaining.checked_sub(size).ok_or_else(|| {
            invalid("Git and registry sources exceed their aggregate expanded byte budget")
        })?;
        *count = count
            .checked_add(1)
            .filter(|count| *count <= MAX_ARCHIVE_MEMBERS)
            .ok_or_else(|| {
                invalid("Git and registry sources exceed their aggregate expanded file bound")
            })?;
        require(
            members
                .insert(
                    path.into(),
                    GitMember {
                        object: fields[2].into(),
                        size,
                        #[cfg(unix)]
                        executable: fields[0] == "100755",
                    },
                )
                .is_none(),
            "duplicate Git tree path",
        )?;
    }
    Ok(CapturedCommit { members })
}

// Cargo discovers manifests recursively in a Git repository. Check path-bearing
// declarations before it runs, while leaving fixture/metadata tables alone.
fn validate_tree_manifest(base: &Path, value: &toml::Value) -> io::Result<()> {
    for section in ["package", "project", "lib"] {
        if let Some(fields) = value.get(section) {
            for name in ["workspace", "readme", "license-file", "build", "path"] {
                super::validate_path_field(base, fields, name)?;
            }
            if let Some(scripts) = fields.get("build").and_then(toml::Value::as_array) {
                for script in scripts.iter().filter_map(toml::Value::as_str) {
                    contained_relative(base, script)?;
                }
            }
            for field in ["default-target", "forced-target"] {
                if let Some(target) = fields.get(field).and_then(toml::Value::as_str) {
                    require(
                        !target.ends_with(".json")
                            && !target.contains(['/', '\\', ':'])
                            && !target.chars().any(char::is_control),
                        "Git package targets require named triples",
                    )?;
                }
            }
        }
    }
    for section in ["bin", "example", "test", "bench"] {
        if let Some(targets) = value.get(section).and_then(toml::Value::as_array) {
            for target in targets {
                super::validate_path_field(base, target, "path")?;
            }
        }
    }
    for section in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "dev_dependencies",
        "build_dependencies",
        "replace",
    ] {
        if let Some(dependencies) = value.get(section).and_then(toml::Value::as_table) {
            for dependency in dependencies.values() {
                super::validate_path_field(base, dependency, "path")?;
            }
        }
    }
    for section in ["target", "patch"] {
        if let Some(entries) = value.get(section).and_then(toml::Value::as_table) {
            for entry in entries.values() {
                if section == "target" {
                    validate_tree_manifest(base, entry)?;
                } else if let Some(dependencies) = entry.as_table() {
                    for dependency in dependencies.values() {
                        super::validate_path_field(base, dependency, "path")?;
                    }
                }
            }
        }
    }
    if let Some(workspace) = value.get("workspace") {
        validate_tree_manifest(base, workspace)?;
        for name in ["members", "default-members", "exclude"] {
            if let Some(paths) = workspace.get(name).and_then(toml::Value::as_array) {
                for path in paths.iter().filter_map(toml::Value::as_str) {
                    contained_relative(base, path)?;
                }
            }
        }
    }
    Ok(())
}

impl GitCache {
    pub(super) fn capture(
        root: &File,
        lock: &toml::Value,
        scratch: &Path,
        mut remaining: u64,
        expanded_remaining: &mut u64,
        expanded_members: &mut usize,
        control: &PreparationControl<'_>,
    ) -> io::Result<(Self, CapturedFiles)> {
        control.checkpoint()?;
        let packages = locked_packages(lock)?;
        let revisions = packages
            .iter()
            .map(|(_, _, _, revision)| revision.clone())
            .collect::<BTreeSet<_>>();
        require(
            !revisions.is_empty() && revisions.len() <= MAX_DATABASES,
            "cached Git revision set exceeds its bound",
        )?;
        let scratch = scratch.join("git-capture");
        fs::create_dir(&scratch)?;
        let tool = GitTools {
            git: local_tool_controlled("git", &scratch, control)?,
            prlimit: local_tool_controlled("prlimit", &scratch, control)?,
        };
        let mut captured = Self {
            packages,
            commits: BTreeMap::new(),
            tool,
            scratch,
        };
        let mut files = BTreeMap::new();
        let mut found = BTreeSet::new();
        let mut databases = 0_usize;
        let deadline = Instant::now() + CAPTURE_TIMEOUT;
        for name in database_names(root, control)? {
            checkpoint(deadline, control)?;
            let temporary = tempfile::Builder::new()
                .prefix("objects-")
                .tempdir_in(&captured.scratch)?;
            let repository = temporary.path().join("view");
            minimal_repository(&repository, &revisions)?;
            let view = object_view(root, &name, &repository, control)?;
            let mut probe = git_command(&captured.tool, &repository, &captured.scratch);
            probe.args(["cat-file", "--batch-check"]);
            let input = revisions
                .iter()
                .map(|revision| format!("{revision}\n"))
                .collect::<String>();
            let output = run(
                probe,
                &captured.scratch,
                OUTPUT_LIMIT,
                Some(input.as_bytes()),
                control,
            )?;
            let text =
                std::str::from_utf8(&output).map_err(|_| invalid("invalid Git commit probe"))?;
            let mut selected = BTreeSet::new();
            let rows = text.lines().collect::<Vec<_>>();
            require(
                rows.len() == revisions.len(),
                "Git commit probe returned an incomplete result",
            )?;
            for (revision, row) in revisions.iter().zip(rows) {
                if row == format!("{revision} missing") {
                    continue;
                }
                let fields = row.split_whitespace().collect::<Vec<_>>();
                require(
                    fields.len() == 3
                        && fields[0] == revision
                        && fields[1] == "commit"
                        && fields[2]
                            .parse::<u64>()
                            .is_ok_and(|size| size <= OUTPUT_LIMIT),
                    "locked Git revision is not a bounded commit object",
                )?;
                selected.insert(revision.clone());
            }
            if selected.is_empty() {
                view.verify_unchanged(control)?;
                continue;
            }
            databases += 1;
            require(
                databases <= MAX_DATABASES,
                "too many selected Cargo Git databases",
            )?;
            for revision in &selected {
                checkpoint(deadline, control)?;
                let mut command = git_command(&captured.tool, &repository, &captured.scratch);
                command.args(["ls-tree", "-r", "-l", "-z", revision]);
                let output = run(command, &captured.scratch, OUTPUT_LIMIT, None, control)?;
                let commit =
                    parse_tree_controlled(&output, expanded_remaining, expanded_members, control)?;
                for (path, member) in &commit.members {
                    control.checkpoint()?;
                    if Path::new(path)
                        .file_name()
                        .is_some_and(|name| name == "Cargo.toml")
                    {
                        checkpoint(deadline, control)?;
                        require(
                            member.size <= OUTPUT_LIMIT,
                            "Git Cargo manifest exceeds its bound",
                        )?;
                        let mut command =
                            git_command(&captured.tool, &repository, &captured.scratch);
                        command.args(["cat-file", "blob", &member.object]);
                        let bytes = run(command, &captured.scratch, OUTPUT_LIMIT, None, control)?;
                        if let Ok(text) = std::str::from_utf8(&bytes)
                            && let Ok(value) = toml::from_str::<toml::Value>(text)
                        {
                            validate_tree_manifest(
                                Path::new(path).parent().unwrap_or(Path::new("")),
                                &value,
                            )?;
                        }
                    }
                }
                captured
                    .commits
                    .insert((name.clone(), revision.clone()), commit);
                found.insert(revision.clone());
            }
            checkpoint(deadline, control)?;
            let mut enumerate = git_command(&captured.tool, &repository, &captured.scratch);
            enumerate
                .args([
                    "rev-list",
                    "--objects",
                    "--no-object-names",
                    "--no-walk=unsorted",
                ])
                .args(&selected);
            let output = run(enumerate, &captured.scratch, OUTPUT_LIMIT, None, control)?;
            let text = std::str::from_utf8(&output)
                .map_err(|_| invalid("invalid selected Git object list"))?;
            let objects = text.lines().collect::<BTreeSet<_>>();
            require(
                !objects.is_empty()
                    && objects.len() <= MAX_ARCHIVE_MEMBERS * 2
                    && objects.iter().all(|object| object_id(object)),
                "selected Git object closure exceeds its bound",
            )?;
            let input = objects
                .iter()
                .map(|object| format!("{object}\n"))
                .collect::<String>();
            let mut pack = git_command(&captured.tool, &repository, &captured.scratch);
            pack.args([
                "pack-objects",
                "--stdout",
                "--no-reuse-delta",
                "--no-reuse-object",
                "--window=0",
                "--threads=1",
            ]);
            checkpoint(deadline, control)?;
            let packed = run(
                pack,
                &captured.scratch,
                remaining,
                Some(input.as_bytes()),
                control,
            )?;
            let generated = temporary.path().join("captured");
            minimal_repository(&generated, &selected)?;
            let incoming = temporary.path().join("selected.pack");
            control.write_all(File::create(&incoming)?, &packed)?;
            let mut index = git_command(&captured.tool, &generated, &captured.scratch);
            index
                .args(["index-pack", "--strict", "--threads=1"])
                .arg(&incoming);
            checkpoint(deadline, control)?;
            let output = run(index, &captured.scratch, OUTPUT_LIMIT, None, control)?;
            let digest = std::str::from_utf8(&output)
                .map_err(|_| invalid("invalid generated Git pack identity"))?
                .trim();
            require(object_id(digest), "invalid generated Git pack identity")?;
            let stem = format!("objects/pack/pack-{digest}");
            fs::rename(&incoming, generated.join(format!("{stem}.pack")))?;
            fs::rename(
                incoming.with_extension("idx"),
                generated.join(format!("{stem}.idx")),
            )?;
            let mut verify = git_command(&captured.tool, &generated, &captured.scratch);
            verify.args(["fsck", "--full", "--strict", "--no-reflogs"]);
            checkpoint(deadline, control)?;
            run(verify, &captured.scratch, OUTPUT_LIMIT, None, control)?;
            view.verify_unchanged(control)?;
            let mut packed = Some(packed);
            for path in [
                "config".to_owned(),
                "HEAD".to_owned(),
                "shallow".to_owned(),
                "refs/heads/rabs-captured".to_owned(),
                format!("{stem}.pack"),
                format!("{stem}.idx"),
            ] {
                control.checkpoint()?;
                let bytes = if path.ends_with(".pack") {
                    packed
                        .take()
                        .ok_or_else(|| invalid("duplicate generated Git pack"))?
                } else {
                    control.read_bounded(
                        File::open(generated.join(&path))?,
                        remaining.saturating_add(1),
                    )?
                };
                remaining = remaining.checked_sub(bytes.len() as u64).ok_or_else(|| {
                    invalid("captured Git pack exceeds the aggregate source byte budget")
                })?;
                require(
                    files
                        .insert(format!("git/db/{name}/{path}"), bytes)
                        .is_none(),
                    "duplicate captured Git cache path",
                )?;
            }
        }
        checkpoint(deadline, control)?;
        require(
            found == revisions,
            "approved Cargo home is missing a locked Git commit; fetch the complete locked graph before preparing",
        )?;
        Ok((captured, files))
    }

    fn resolved_checkout<'a>(
        &'a self,
        home: &Path,
        package: &Value,
    ) -> io::Result<(PathBuf, &'a CapturedCommit)> {
        let source = package["source"]
            .as_str()
            .ok_or_else(|| invalid("resolved Git source missing"))?;
        let name = package["name"]
            .as_str()
            .ok_or_else(|| invalid("resolved Git package name missing"))?;
        let version = package["version"]
            .as_str()
            .ok_or_else(|| invalid("resolved Git package version missing"))?;
        let revision = locked_revision(source)?;
        require(
            self.packages.contains(&(
                name.into(),
                version.into(),
                GitSource::parse(source)?,
                revision.into(),
            )),
            "resolved Git package differs from its exact locked source identity",
        )?;
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or_else(|| invalid("resolved Git manifest missing"))?,
        );
        let checkouts = home.join("git/checkouts");
        let path = manifest
            .strip_prefix(&checkouts)
            .map_err(|_| invalid("resolved Git manifest escapes its private Cargo home"))?;
        let parts = path.components().collect::<Vec<_>>();
        require(
            parts.len() >= 3
                && parts
                    .iter()
                    .all(|part| matches!(part, Component::Normal(_))),
            "resolved Git checkout path is noncanonical",
        )?;
        let namespace = parts[0]
            .as_os_str()
            .to_str()
            .ok_or_else(|| invalid("invalid Git checkout namespace"))?;
        let prefix = parts[1]
            .as_os_str()
            .to_str()
            .ok_or_else(|| invalid("invalid Git checkout revision"))?;
        require(
            prefix.len() >= 7 && prefix.len() <= 40 && revision.starts_with(prefix),
            "resolved Git checkout revision differs from Cargo.lock",
        )?;
        let commit = self
            .commits
            .get(&(namespace.into(), revision.into()))
            .ok_or_else(|| {
                invalid("resolved Git namespace was not captured from the approved object store")
            })?;
        Ok((checkouts.join(namespace).join(prefix), commit))
    }

    pub(super) fn check_package(&self, home: &Path, package: &Value) -> io::Result<()> {
        let (checkout, commit) = self.resolved_checkout(home, package)?;
        let targets = package["targets"]
            .as_array()
            .filter(|targets| !targets.is_empty())
            .ok_or_else(|| invalid("resolved Git package has no target graph"))?;
        for path in std::iter::once(&package["manifest_path"])
            .chain(targets.iter().map(|target| &target["src_path"]))
        {
            let path = Path::new(
                path.as_str()
                    .ok_or_else(|| invalid("resolved Git package path missing"))?,
            );
            let relative = path
                .strip_prefix(&checkout)
                .ok()
                .and_then(Path::to_str)
                .ok_or_else(|| {
                    invalid("resolved Git package target escapes its captured repository")
                })?;
            require(
                commit.members.contains_key(relative),
                "resolved Git manifest or target is absent from the selected commit",
            )?;
        }
        Ok(())
    }

    pub(super) fn verify_checkouts(
        &self,
        home: &Path,
        packages: &[Value],
        control: &PreparationControl<'_>,
    ) -> io::Result<()> {
        let mut checked = BTreeSet::new();
        for package in packages.iter().filter(|package| {
            package["source"]
                .as_str()
                .is_some_and(|source| source.starts_with("git+"))
        }) {
            control.checkpoint()?;
            let (checkout, commit) = self.resolved_checkout(home, package)?;
            if !checked.insert(checkout.clone()) {
                continue;
            }
            let directory = open_home(&checkout)?;
            let mut paths = String::new();
            for (path, member) in &commit.members {
                control.checkpoint()?;
                let file = open_selected(&directory, path, false)?;
                let metadata = file.metadata()?;
                require(
                    metadata.is_file() && metadata.len() == member.size,
                    "Cargo Git checkout differs from the captured commit tree",
                )?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    require(
                        (metadata.permissions().mode() & 0o111 != 0) == member.executable,
                        "Cargo Git checkout changed a captured executable bit",
                    )?;
                }
                let path = checkout.join(path);
                paths.push_str(
                    path.to_str()
                        .ok_or_else(|| invalid("non-UTF-8 private Git checkout"))?,
                );
                paths.push('\n');
            }
            let namespace = checkout
                .parent()
                .and_then(Path::file_name)
                .ok_or_else(|| invalid("private Git checkout namespace missing"))?;
            let mut command = git_command(
                &self.tool,
                &home.join("git/db").join(namespace),
                &self.scratch,
            );
            command.args(["hash-object", "--stdin-paths", "--no-filters"]);
            let output = run(
                command,
                &self.scratch,
                OUTPUT_LIMIT,
                Some(paths.as_bytes()),
                control,
            )?;
            let text = std::str::from_utf8(&output)
                .map_err(|_| invalid("invalid Git checkout object verification"))?;
            require(
                text.lines()
                    .eq(commit.members.values().map(|member| member.object.as_str())),
                "Cargo Git checkout bytes differ from the verified selected objects",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_selectors_keep_full_locked_commit_authority_without_resolving_refs() {
        let revision = "0123456789abcdef0123456789abcdef01234567";
        for selector in [
            String::new(),
            format!("?rev={revision}"),
            "?branch=main".to_owned(),
            "?tag=release+%2F".to_owned(),
            "?rev=0123456".to_owned(),
        ] {
            let source = format!("git+https://example.invalid/repo.git{selector}#{revision}");
            assert_eq!(locked_revision(&source).unwrap(), revision, "{source}");
            GitSource::parse(&source).unwrap();
        }
        for source in [
            "git+https://example.invalid/repo.git".to_owned(),
            "git+https://example.invalid/repo.git#0123456".to_owned(),
            format!("git+https://example.invalid/repo.git?branch=#{revision}"),
            format!("git+https://example.invalid/repo.git?unknown=main#{revision}"),
            format!("git+https://example.invalid/repo.git?branch=bad\nref#{revision}"),
            format!("git+https://user:secret@example.invalid/repo.git?rev={revision}#{revision}"),
            format!("git+https://user@example.invalid/repo.git?branch=main#{revision}"),
            format!(
                "git+https://example.invalid/repo.git?rev={revision}#{}",
                "a".repeat(40)
            ),
        ] {
            assert!(
                locked_revision(&source).is_err() || GitSource::parse(&source).is_err(),
                "{source}"
            );
        }
        assert!(namespace("repo-0123456789abcdef"));
        assert!(!namespace("../repo-0123456789abcdef"));
    }

    #[test]
    fn cached_git_manifests_require_one_literal_selector_and_an_ordinary_url() {
        let base = "git='https://example.invalid/repo.git'";
        for reference in ["", ",rev='0123456'", ",branch='main'", ",tag='release+%2F'"] {
            let value: toml::Value = toml::from_str(&format!("dep={{{base}{reference}}}")).unwrap();
            validate_dependency(value["dep"].as_table().unwrap()).unwrap();
        }
        for reference in [
            ",branch='main',rev='0123456'",
            ",tag='release',branch='main'",
            ",branch=123",
            ",tag=''",
            ",path='../outside'",
            ",registry='private'",
        ] {
            let value: toml::Value = toml::from_str(&format!("dep={{{base}{reference}}}")).unwrap();
            assert!(validate_dependency(value["dep"].as_table().unwrap()).is_err());
        }
        let value: toml::Value =
            toml::from_str("dep={git='https://user:secret@example.invalid/repo',branch='main'}")
                .unwrap();
        assert!(validate_dependency(value["dep"].as_table().unwrap()).is_err());
    }

    #[test]
    fn lock_encoding_preserves_literal_metadata_refs_and_distinct_package_identities() {
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let url = "https://example.invalid/repo.git";
        let encoded = format!("git+{url}?tag=release%2B%252F%23%26name#{revision}");
        let literal = format!("git+{url}?tag=release+%2F#&name#{revision}");
        let lock = |version, source: &str| {
            toml::from_str::<toml::Value>(&format!(
                "version={version}\n[[package]]\nname='dep'\nversion='1.0.0'\nsource='{source}'\n"
            ))
            .unwrap()
        };
        let identity = locked_packages(&lock(4, &encoded)).unwrap();
        assert!(identity.contains(&(
            "dep".into(),
            "1.0.0".into(),
            GitSource::parse(&literal).unwrap(),
            revision.into(),
        )));
        assert_eq!(identity, locked_packages(&lock(3, &literal)).unwrap());
        let long_literal = format!("git+{url}?tag={}#{revision}", "%".repeat(400));
        let long_encoded = format!("git+{url}?tag={}#{revision}", "%25".repeat(400));
        assert_eq!(
            locked_packages(&lock(4, &long_encoded)).unwrap(),
            locked_packages(&lock(3, &long_literal)).unwrap(),
            "reference bounds apply after decoding the versioned lock spelling"
        );
        assert_ne!(
            identity,
            locked_packages(&lock(
                4,
                &format!("git+{url}?tag=release%2B%2F%23%26name#{revision}")
            ))
            .unwrap(),
            "a literal percent escape is not its decoded target"
        );
        for reference in ["bad%", "bad%GG", "bad%FF", "bad%00", "a&branch=b", "a#b"] {
            let source = format!("git+{url}?tag={reference}#{revision}");
            assert!(locked_packages(&lock(4, &source)).is_err(), "{source}");
        }
        let mut graph = lock(4, &encoded);
        let packages = graph["package"].as_array_mut().unwrap();
        let mut transitive = packages[0].clone();
        transitive["name"] = "transitive".into();
        packages.push(transitive);
        let mut other_source = packages[0].clone();
        other_source["source"] = format!("git+{url}?branch=main#{revision}").into();
        packages.push(other_source);
        assert_eq!(locked_packages(&graph).unwrap().len(), 3);
        let duplicate = graph["package"][0].clone();
        graph["package"].as_array_mut().unwrap().push(duplicate);
        assert!(locked_packages(&graph).is_err());
    }

    #[test]
    fn selected_tree_checks_modes_paths_and_shared_expansion_budget() {
        let oid = "0123456789abcdef0123456789abcdef01234567";
        let row = format!("100644 blob {oid} 3\tsrc/lib.rs\0");
        let tree = parse_tree(row.as_bytes(), &mut 3, &mut 0).unwrap();
        assert_eq!(tree.members["src/lib.rs"].size, 3);
        assert!(parse_tree(row.as_bytes(), &mut 2, &mut 0).is_err());
        for row in [
            format!("120000 blob {oid} 3\tlink\0"),
            format!("160000 commit {oid} -\tsubmodule\0"),
            format!("100644 blob {oid} 3\t../outside\0"),
            format!("100644 blob {oid} 3\t.git/config\0"),
            format!("100644 blob {oid} 3\t.gitmodules\0"),
        ] {
            assert!(parse_tree(row.as_bytes(), &mut 100, &mut 0).is_err());
        }
    }

    #[test]
    fn git_tree_manifest_paths_cannot_escape_before_cargo_discovery() {
        for manifest in [
            "[dependencies]\nx={path='../../outside'}",
            "[package]\nworkspace='/outside'",
            "[workspace]\nmembers=['../../outside']",
            "[[test]]\npath='/outside/test.rs'",
        ] {
            let value = toml::from_str(manifest).unwrap();
            assert!(validate_tree_manifest(Path::new("dep"), &value).is_err());
        }
        let value = toml::from_str(
            "[dependencies]\nx={path='../leaf'}\n[package.metadata.fixture]\npath='/irrelevant'",
        )
        .unwrap();
        validate_tree_manifest(Path::new("dep"), &value).unwrap();
    }
}
