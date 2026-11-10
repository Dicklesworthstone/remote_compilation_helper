//! Known package-manager environment inputs to dependency preparation.
//!
//! Keep raw values (including registry credentials) out of records and logs.
//! In addition to environment values, bind explicitly selected npm user/global
//! configuration files, the default home `.npmrc` candidate, and the project's
//! `.npmrc`, including their referenced environment values. This does not
//! discover npm's implicit global prefix or configuration-file redirects.
//! Unix launcher generations (including PATH candidates and shebang
//! interpreters) invalidate retained native dependencies after runtime or
//! manager upgrades without repeatedly hashing large Node/Bun binaries.
//! This is local generation identity, not a portable toolchain content digest
//! or the dependency closure of arbitrary wrappers and runtime libraries.
//! Berry separately binds its home/ancestor config
//! and effective auxiliary files through `capture_yarn`. Custom lifecycle
//! scripts may read other inputs; this is not a hermetic sandbox.

use anyhow::{Context, Result, ensure};
use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_ENVIRONMENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONFIGURATION_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CONFIGURATION_COMPONENTS: usize = 4096;
const MAX_CONFIGURATION_SYMLINKS: usize = 40;
const MAX_CONFIGURATION_REFERENCES: usize = 4096;
const MAX_CONFIGURATION_FILES: usize = 32;
const MAX_YARN_CONFIGURATION_ROOTS: usize = 128;
const MAX_YARN_CONFIGURATION_FILES: usize = 4096 + MAX_YARN_CONFIGURATION_ROOTS;
#[cfg(unix)]
const MAX_TOOLCHAIN_PATHS: usize = 1024;
#[cfg(unix)]
const MAX_TOOLCHAIN_SEARCH_DIRECTORIES: usize = 128;
#[cfg(unix)]
const MAX_SHEBANG_BYTES: u64 = 4096;

fn relevant(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    [b"npm_config_".as_slice(), b"pnpm_", b"yarn_", b"bun_"]
        .iter()
        .any(|prefix| {
            bytes
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        })
        || [
            "NODE_ENV",
            "NODE_OPTIONS",
            "NODE_PATH",
            "CI",
            "PATH",
            "PATHEXT",
            "HOME",
            "USERPROFILE",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "APPDATA",
            "LOCALAPPDATA",
        ]
        .iter()
        .any(|key| bytes.eq_ignore_ascii_case(key.as_bytes()))
}

fn fingerprint(values: impl IntoIterator<Item = (OsString, OsString)>) -> Result<blake3::Hash> {
    let mut values: Vec<_> = values
        .into_iter()
        .filter(|(name, _)| relevant(name))
        .collect();
    // Preserve exact key case and OS value bytes. Stable sorting also retains
    // the original order of any duplicate environment names.
    values.sort_by(|left, right| left.0.as_encoded_bytes().cmp(right.0.as_encoded_bytes()));
    let mut digest = blake3::Hasher::new();
    digest.update(b"rch-dependency-install-environment-v1\0");
    let mut budget = MAX_ENVIRONMENT_BYTES;
    for (name, value) in values {
        for bytes in [name.as_encoded_bytes(), value.as_encoded_bytes()] {
            ensure!(
                bytes.len() <= budget,
                "package-manager environment exceeds byte limit"
            );
            budget -= bytes.len();
            digest.update(&(bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        }
    }
    Ok(digest.finalize())
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct CapturedEnvironment {
    pub(super) digest: blake3::Hash,
    configurations: Vec<Configuration>,
}

impl CapturedEnvironment {
    pub(super) fn configuration_paths(&self) -> impl Iterator<Item = &Path> {
        self.configurations
            .iter()
            .map(|entry| entry.requested.as_path())
    }

    /// A fresh local PnP install may create the previously absent `.yarn`
    /// structural parent. Its authored input roots must remain absent, and
    /// every preexisting path observation must still match exactly. This is
    /// only for the post-install comparison, never an in-query coherence test.
    pub(super) fn same_after_yarn_parent_created(&self, after: &Self, project: &Path) -> bool {
        if self.digest != after.digest || self.configurations.len() != after.configurations.len() {
            return false;
        }
        let parent = project.join(".yarn");
        self.configurations
            .iter()
            .zip(&after.configurations)
            .all(|(before, after)| {
                if before == after {
                    return true;
                }
                if before.requested != after.requested
                    || before.contents.is_some()
                    || after.contents.is_some()
                    || before.resolution.file.is_some()
                    || after.resolution.file.is_some()
                    || before.requested.parent() != Some(parent.as_path())
                    || !matches!(
                        before.requested.file_name().and_then(OsStr::to_str),
                        Some("patches" | "plugins" | "releases")
                    )
                {
                    return false;
                }
                let Some((PathEntry::Missing(missing_before), preserved_before)) =
                    before.resolution.entries.split_last()
                else {
                    return false;
                };
                let Some((PathEntry::Missing(missing_after), prefix_after)) =
                    after.resolution.entries.split_last()
                else {
                    return false;
                };
                let Some((PathEntry::Directory(created, _), preserved_after)) =
                    prefix_after.split_last()
                else {
                    return false;
                };
                missing_before == &parent
                    && created == &parent
                    && missing_after == &before.requested
                    && preserved_before == preserved_after
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Configuration {
    requested: PathBuf,
    resolution: Resolution,
    contents: Option<blake3::Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    bytes: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    generation: (u64, u64, i64, i64, u32),
}

impl FileIdentity {
    fn of(metadata: &Metadata) -> Result<Self> {
        Ok(Self {
            bytes: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            generation: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                    metadata.mode(),
                )
            },
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    generation: (u64, u64),
    #[cfg(not(unix))]
    created: std::time::SystemTime,
}

impl DirectoryIdentity {
    fn of(metadata: &Metadata) -> Result<Self> {
        ensure!(
            metadata.is_dir(),
            "npm configuration parent is not a directory"
        );
        // npm may create cache/log entries under HOME during installation.
        // Their directory timestamps are not configuration substitutions.
        Ok(Self {
            #[cfg(unix)]
            generation: {
                use std::os::unix::fs::MetadataExt;
                (metadata.dev(), metadata.ino())
            },
            #[cfg(not(unix))]
            created: metadata.created()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PathEntry {
    Directory(PathBuf, DirectoryIdentity),
    Symlink(PathBuf, FileIdentity, PathBuf),
    Missing(PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
struct Resolution {
    entries: Vec<PathEntry>,
    file: Option<(PathBuf, FileIdentity)>,
}

/// Walk link targets as filesystem paths, including their intermediate
/// directories and missing components. `canonicalize` alone loses the identity
/// of a substituted link or parent, and cannot describe a dangling link.
fn resolve_configuration(path: &Path) -> Result<Resolution> {
    let mut remaining: VecDeque<_> = path
        .components()
        .take(MAX_CONFIGURATION_COMPONENTS + 1)
        .map(|part| part.as_os_str().to_owned())
        .collect();
    ensure!(
        remaining.len() <= MAX_CONFIGURATION_COMPONENTS,
        "npm configuration path exceeds component limit"
    );
    let mut current = PathBuf::new();
    let mut entries = Vec::new();
    let mut links = 0;
    let mut components = 0;
    while let Some(part) = remaining.pop_front() {
        components += 1;
        ensure!(
            components <= MAX_CONFIGURATION_COMPONENTS,
            "npm configuration path exceeds component limit"
        );
        match Path::new(&part).components().next() {
            Some(Component::CurDir) => continue,
            Some(Component::ParentDir) => {
                current.pop();
                continue;
            }
            Some(Component::Prefix(_)) => {
                current.push(part);
                continue;
            }
            _ => current.push(part),
        }
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                entries.push(PathEntry::Missing(current));
                return Ok(Resolution {
                    entries,
                    file: None,
                });
            }
            Err(error) => return Err(error).context("inspect npm configuration path"),
        };
        if metadata.file_type().is_symlink() {
            links += 1;
            ensure!(
                links <= MAX_CONFIGURATION_SYMLINKS,
                "npm configuration path exceeds symlink limit"
            );
            let before = FileIdentity::of(&metadata)?;
            let target = std::fs::read_link(&current).context("read npm configuration symlink")?;
            ensure!(
                FileIdentity::of(&std::fs::symlink_metadata(&current)?)? == before,
                "npm configuration symlink changed during capture"
            );
            entries.push(PathEntry::Symlink(current.clone(), before, target.clone()));
            current.pop();
            for component in target.components().rev() {
                ensure!(
                    remaining.len() < MAX_CONFIGURATION_COMPONENTS,
                    "npm configuration path exceeds component limit"
                );
                remaining.push_front(component.as_os_str().to_owned());
            }
        } else if remaining.is_empty() {
            ensure!(
                metadata.is_file(),
                "npm configuration is not a regular file"
            );
            return Ok(Resolution {
                entries,
                file: Some((current, FileIdentity::of(&metadata)?)),
            });
        } else {
            entries.push(PathEntry::Directory(
                current.clone(),
                DirectoryIdentity::of(&metadata)?,
            ));
        }
    }
    anyhow::bail!("npm configuration path does not name a regular file")
}

fn frame(digest: &mut blake3::Hasher, bytes: &[u8]) {
    digest.update(&(bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

#[cfg(unix)]
fn bind_file_generation(digest: &mut blake3::Hasher, identity: &FileIdentity) {
    let (device, inode, changed, changed_nanos, mode) = identity.generation;
    digest.update(&device.to_le_bytes());
    digest.update(&inode.to_le_bytes());
    digest.update(&changed.to_le_bytes());
    digest.update(&changed_nanos.to_le_bytes());
    digest.update(&mode.to_le_bytes());
    digest.update(&identity.bytes.to_le_bytes());
    let modified = match identity.modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => {
            digest.update(&[0]);
            duration
        }
        Err(error) => {
            digest.update(&[1]);
            error.duration()
        }
    };
    digest.update(&modified.as_secs().to_le_bytes());
    digest.update(&modified.subsec_nanos().to_le_bytes());
}

/// Include every executable candidate, not only the first mode-bit match:
/// ACLs and effective credentials can make execvp skip an earlier candidate.
/// Missing candidates remain an absence observation even if an installer
/// creates an otherwise unrelated node_modules/.bin parent during its run.
#[cfg(unix)]
fn toolchain_candidates(
    project: &Path,
    values: &[(OsString, OsString)],
    program: &str,
) -> Result<Vec<PathBuf>> {
    let project = if project.is_absolute() {
        project.to_owned()
    } else {
        std::env::current_dir()?.join(project)
    };
    if program.contains('/') {
        return Ok(vec![project.join(program)]);
    }
    // execvp uses the system search path when PATH is absent. Both supported
    // Unix platforms include these directories; extra candidates only cause
    // conservative misses, never reuse across a replaced executable.
    let path = environment_value(values, "PATH").unwrap_or_else(|| OsStr::new("/bin:/usr/bin"));
    let directories: Vec<_> = std::env::split_paths(path)
        .take(MAX_TOOLCHAIN_SEARCH_DIRECTORIES + 1)
        .collect();
    ensure!(
        directories.len() <= MAX_TOOLCHAIN_SEARCH_DIRECTORIES,
        "dependency toolchain PATH exceeds directory limit"
    );
    Ok(directories
        .into_iter()
        .map(|directory| project.join(directory).join(program))
        .collect())
}

#[cfg(unix)]
fn launcher_interpreters(path: &Path, before: &FileIdentity) -> Result<Vec<String>> {
    use rustix::fs::{Mode, OFlags};
    let mut file = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )?);
    let opened = file.metadata()?;
    ensure!(
        opened.is_file() && FileIdentity::of(&opened)? == *before,
        "dependency launcher changed before inspection"
    );
    let mut prefix = Vec::new();
    (&mut file)
        .take(MAX_SHEBANG_BYTES)
        .read_to_end(&mut prefix)?;
    ensure!(
        FileIdentity::of(&file.metadata()?)? == *before,
        "dependency launcher changed during inspection"
    );
    let Some(script) = prefix.strip_prefix(b"#!") else {
        return Ok(Vec::new());
    };
    let line = script
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let text = std::str::from_utf8(line).context("dependency shebang is not UTF-8")?;
    let mut words = text.split_ascii_whitespace();
    let interpreter = words.next().context("empty dependency shebang")?;
    // The kernel treats a shebang interpreter as a literal pathname relative
    // to the workload cwd, even when it contains no slash. Only env's command
    // below performs PATH lookup. Preserve that distinction in the resolver.
    let mut interpreters = vec![if interpreter.contains('/') {
        interpreter.to_owned()
    } else {
        format!("./{interpreter}")
    }];
    if Path::new(interpreter).file_name() == Some(OsStr::new("env")) {
        let argument = words.next().context("env shebang has no interpreter")?;
        let program = if matches!(argument, "-S" | "--split-string") {
            words
                .next()
                .context("env shebang has no split interpreter")?
        } else if let Some(program) = argument.strip_prefix("--split-string=") {
            program
        } else {
            argument
        };
        // Common env and env -S launchers have a literal first command word.
        // Do not guess at environment assignments, substitutions or quoting:
        // their actual executable search context could differ from this one.
        ensure!(
            !program.is_empty()
                && !program.starts_with('-')
                && !program.contains(['=', '$', '\\', '\'', '"']),
            "dependency env shebang requires a literal interpreter"
        );
        interpreters.push(program.to_owned());
    }
    Ok(interpreters)
}

#[cfg(unix)]
fn capture_toolchain(
    project: &Path,
    values: &[(OsString, OsString)],
) -> Result<std::collections::BTreeMap<PathBuf, Option<Resolution>>> {
    use std::os::unix::fs::PermissionsExt;
    let mut pending = BTreeSet::new();
    for program in ["node", "bun", "npm", "pnpm", "yarn", "corepack"] {
        pending.extend(toolchain_candidates(project, values, program)?);
    }
    let mut observations = std::collections::BTreeMap::new();
    while let Some(path) = pending.pop_first() {
        if observations.contains_key(&path) {
            continue;
        }
        ensure!(
            observations.len().saturating_add(pending.len()) < MAX_TOOLCHAIN_PATHS,
            "dependency toolchain exceeds path limit"
        );
        let executable = match std::fs::metadata(&path) {
            Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                false
            }
            Err(error) => return Err(error).context("inspect dependency launcher"),
        };
        let resolution = if executable {
            let resolution = resolve_configuration(&path)?;
            let (resolved, identity) = resolution
                .file
                .as_ref()
                .context("dependency launcher disappeared during inspection")?;
            for interpreter in launcher_interpreters(resolved, identity)? {
                for candidate in toolchain_candidates(project, values, &interpreter)? {
                    if candidate != path && !observations.contains_key(&candidate) {
                        pending.insert(candidate);
                    }
                }
                ensure!(
                    observations.len().saturating_add(pending.len()) < MAX_TOOLCHAIN_PATHS,
                    "dependency toolchain exceeds path limit"
                );
            }
            Some(resolution)
        } else {
            None
        };
        observations.insert(path, resolution);
    }
    Ok(observations)
}

#[cfg(unix)]
fn bind_toolchain(
    digest: &mut blake3::Hasher,
    observations: &std::collections::BTreeMap<PathBuf, Option<Resolution>>,
) {
    digest.update(b"rch-dependency-toolchain-generation-v1\0");
    digest.update(&(observations.len() as u64).to_le_bytes());
    for (path, resolution) in observations {
        frame(digest, path.as_os_str().as_encoded_bytes());
        let Some(resolution) = resolution else {
            digest.update(&[0]);
            continue;
        };
        digest.update(&[1]);
        digest.update(&(resolution.entries.len() as u64).to_le_bytes());
        for entry in &resolution.entries {
            match entry {
                PathEntry::Directory(path, identity) => {
                    digest.update(&[0]);
                    frame(digest, path.as_os_str().as_encoded_bytes());
                    digest.update(&identity.generation.0.to_le_bytes());
                    digest.update(&identity.generation.1.to_le_bytes());
                }
                PathEntry::Symlink(path, identity, target) => {
                    digest.update(&[1]);
                    frame(digest, path.as_os_str().as_encoded_bytes());
                    bind_file_generation(digest, identity);
                    frame(digest, target.as_os_str().as_encoded_bytes());
                }
                PathEntry::Missing(path) => {
                    digest.update(&[2]);
                    frame(digest, path.as_os_str().as_encoded_bytes());
                }
            }
        }
        if let Some((path, identity)) = &resolution.file {
            frame(digest, path.as_os_str().as_encoded_bytes());
            bind_file_generation(digest, identity);
        }
    }
}

fn capture_configuration(
    path: PathBuf,
    values: &[(OsString, OsString)],
    budget: &mut u64,
    digest: &mut blake3::Hasher,
) -> Result<Configuration> {
    let resolution = resolve_configuration(&path)?;
    frame(digest, path.as_os_str().as_encoded_bytes());
    // Path spelling and symlink destinations affect resolution. Inode/time
    // observations are coherence guards, not content-cache identity.
    let links = resolution
        .entries
        .iter()
        .filter(|entry| matches!(entry, PathEntry::Symlink(..)))
        .count();
    digest.update(&(links as u64).to_le_bytes());
    for entry in &resolution.entries {
        if let PathEntry::Symlink(name, _, target) = entry {
            frame(digest, name.as_os_str().as_encoded_bytes());
            frame(digest, target.as_os_str().as_encoded_bytes());
        }
    }
    let contents = if let Some((resolved, before)) = &resolution.file {
        *budget = budget
            .checked_sub(before.bytes)
            .context("npm configuration files exceed byte limit")?;
        #[cfg(unix)]
        let mut file = {
            use rustix::fs::{Mode, OFlags};
            // A file replaced with a FIFO after lstat must not block open.
            let flags = OFlags::RDONLY
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::NOCTTY;
            File::from(rustix::fs::open(resolved, flags, Mode::empty())?)
        };
        #[cfg(not(unix))]
        let mut file = File::open(resolved).context("open npm configuration")?;
        let opened = file.metadata()?;
        ensure!(
            opened.is_file() && FileIdentity::of(&opened)? == *before,
            "npm configuration changed before read"
        );
        let mut bytes = Vec::new();
        (&mut file).take(before.bytes + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == before.bytes && FileIdentity::of(&file.metadata()?)? == *before,
            "npm configuration changed during read"
        );
        digest.update(&[1]);
        frame(digest, resolved.as_os_str().as_encoded_bytes());
        frame(digest, &bytes);
        bind_configuration_references(digest, &bytes, values, budget)?;
        Some(blake3::hash(&bytes))
    } else {
        digest.update(&[0]);
        None
    };
    ensure!(
        resolve_configuration(&path)? == resolution,
        "npm configuration path changed during capture"
    );
    Ok(Configuration {
        requested: path,
        resolution,
        contents,
    })
}

fn collect_references(text: &str, references: &mut BTreeSet<String>) -> Result<()> {
    // Conservatively bind even commented/escaped references. INI unquoting
    // happens before npm's env-replace, so treating an escape as authoritative
    // here could omit a variable which the actual parser will expand.
    // Split first so malformed `${${...` without a closing brace stays linear.
    for segment in text.split("${").skip(1) {
        let Some((body, _)) = segment.split_once('}') else {
            continue;
        };
        let name = body.strip_suffix('?').unwrap_or(body);
        if !name.is_empty() && !name.contains(['$', '{', '?']) {
            ensure!(
                references.len() < MAX_CONFIGURATION_REFERENCES || references.contains(name),
                "npm configuration exceeds environment reference limit"
            );
            references.insert(name.to_owned());
        }
    }
    Ok(())
}

fn collect_yarn_references(text: &str, references: &mut BTreeSet<String>) -> Result<()> {
    for segment in text.split("${").skip(1) {
        let Some((body, _)) = segment.split_once('}') else {
            continue;
        };
        // Yarn supports both an unset fallback and an unset-or-empty fallback.
        // Bind the variable, not the literal fallback suffix. Conservatively
        // include commented references; they can only cause an extra miss.
        let name = body
            .split_once(":-")
            .or_else(|| body.split_once('-'))
            .map_or(body, |(name, _)| name);
        if !name.is_empty() && !name.contains(['$', '{', ':']) {
            ensure!(
                references.len() < MAX_CONFIGURATION_REFERENCES || references.contains(name),
                "Yarn configuration exceeds environment reference limit"
            );
            references.insert(name.to_owned());
        }
    }
    Ok(())
}

fn bind_configuration_references(
    digest: &mut blake3::Hasher,
    bytes: &[u8],
    values: &[(OsString, OsString)],
    budget: &mut u64,
) -> Result<()> {
    // npm reads UTF-8 INI text. Bind names found both in raw text and in JSON
    // quoted fields, whose escapes can spell a reference ("\u0024{NAME}").
    // This does not interpret settings or reproduce configuration precedence.
    let text = String::from_utf8_lossy(bytes);
    let mut references = BTreeSet::new();
    collect_references(&text, &mut references)?;
    collect_yarn_references(&text, &mut references)?;
    for line in text.split(['\r', '\n']) {
        for part in line.splitn(2, '=') {
            let field = trim_npm_text(part);
            let field = field
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
                .unwrap_or(field);
            if let Ok(decoded) = serde_json::from_str::<serde_json::Value>(field) {
                collect_json_references(&decoded, &mut references)?;
            }
        }
    }
    digest.update(&(references.len() as u64).to_le_bytes());
    for name in references {
        frame(digest, name.as_bytes());
        if let Some(value) = environment_value(values, &name) {
            let bytes = value.as_encoded_bytes();
            *budget = budget
                .checked_sub(bytes.len() as u64)
                .context("npm configuration environment exceeds byte limit")?;
            digest.update(&[1]);
            frame(digest, bytes);
        } else {
            digest.update(&[0]);
        }
    }
    Ok(())
}

fn collect_json_references(
    value: &serde_json::Value,
    references: &mut BTreeSet<String>,
) -> Result<()> {
    match value {
        serde_json::Value::String(text) => collect_references(text, references)?,
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_references(value, references)?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                collect_references(key, references)?;
                collect_json_references(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn environment_value<'a>(values: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsStr> {
    values.iter().rev().find_map(|(key, value)| {
        let matches = if cfg!(windows) {
            key.as_encoded_bytes().eq_ignore_ascii_case(name.as_bytes())
        } else {
            key == name
        };
        matches.then_some(value.as_os_str())
    })
}

/// npm normalizes option names case-insensitively and ignores empty entries.
/// Managed subprocesses can reorder the inherited environment, so bind every
/// nonempty spelling instead of predicting which case-alias npm will select.
fn config_overrides<'a>(values: &'a [(OsString, OsString)], option: &str) -> Vec<&'a OsStr> {
    values
        .iter()
        .filter_map(|(key, value)| {
            (key.as_encoded_bytes()
                .eq_ignore_ascii_case(option.as_bytes())
                && !value.is_empty())
            .then_some(value.as_os_str())
        })
        .collect()
}

fn append_path_text(output: &mut String, text: &str) -> Result<()> {
    ensure!(
        output.len().saturating_add(text.len()) <= MAX_ENVIRONMENT_BYTES,
        "expanded npm configuration path exceeds byte limit"
    );
    output.push_str(text);
    Ok(())
}

/// Match npm's ${NAME}, ${NAME?}, and backslash-escaped substitutions. Values
/// are used only for path resolution and hashing, never error/log formatting.
fn expand_path(value: &str, values: &[(OsString, OsString)]) -> Result<String> {
    let mut output = String::new();
    let bytes = value.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        let start = position;
        while bytes.get(position) == Some(&b'\\') {
            position += 1;
        }
        let escapes = position - start;
        let expression = value.get(position..).and_then(|rest| {
            let body = rest.strip_prefix("${")?;
            // Stop at invalid name characters so repeated malformed openings
            // cannot repeatedly scan the rest of a large configuration value.
            let end = body.find(['}', '$', '{', '?'])?;
            if end == 0 {
                return None;
            }
            match body.as_bytes()[end] {
                b'}' => Some((&body[..end], false, end + 3)),
                b'?' if body.as_bytes().get(end + 1) == Some(&b'}') => {
                    Some((&body[..end], true, end + 4))
                }
                _ => None,
            }
        });
        if let Some((name, optional, length)) = expression {
            append_path_text(&mut output, &value[start..start + escapes / 2])?;
            if escapes % 2 != 0 {
                append_path_text(&mut output, &value[position..position + length])?;
            } else if let Some(replacement) = environment_value(values, name) {
                append_path_text(
                    &mut output,
                    replacement
                        .to_str()
                        .context("npm configuration path is not UTF-8")?,
                )?;
            } else if !optional {
                append_path_text(&mut output, &value[position..position + length])?;
            }
            position += length;
        } else {
            append_path_text(&mut output, &value[start..position])?;
            if let Some(character) = value[position..].chars().next() {
                append_path_text(
                    &mut output,
                    &value[position..position + character.len_utf8()],
                )?;
                position += character.len_utf8();
            }
        }
    }
    Ok(output)
}

fn absolute_path(project: &Path, path: &Path) -> Result<PathBuf> {
    let project = if project.is_absolute() {
        project.to_owned()
    } else {
        std::env::current_dir()?.join(project)
    };
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        project.join(path)
    };
    ensure!(
        absolute.is_absolute(),
        "npm configuration needs an absolute project directory"
    );
    let mut normalized = PathBuf::new();
    for (index, component) in absolute.components().enumerate() {
        ensure!(
            index < MAX_CONFIGURATION_COMPONENTS,
            "npm configuration path exceeds component limit"
        );
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn configuration_path(
    project: &Path,
    value: &OsStr,
    values: &[(OsString, OsString)],
    home: Option<&Path>,
) -> Result<PathBuf> {
    let text = value
        .to_str()
        .context("npm configuration path is not UTF-8")?;
    let expanded = expand_path(trim_npm_text(text), values)?;
    let home_relative = expanded.strip_prefix("~/").or_else(|| {
        cfg!(windows)
            .then(|| expanded.strip_prefix("~\\"))
            .flatten()
    });
    if let (Some(home), Some(relative)) = (home, home_relative) {
        absolute_path(project, &home.join(relative))
    } else {
        absolute_path(project, Path::new(&expanded))
    }
}

fn trim_npm_text(text: &str) -> &str {
    // ECMAScript String.trim's whitespace set (not Rust's additional U+0085).
    text.trim_matches(|c: char| {
        matches!(c,
            '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' |
            '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' |
            '\u{205f}' | '\u{3000}' | '\u{feff}'
        )
    })
}

fn capture_with(project: &Path, values: Vec<(OsString, OsString)>) -> Result<CapturedEnvironment> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"rch-dependency-install-environment-v3\0");
    digest.update(fingerprint(values.iter().cloned())?.as_bytes());
    #[cfg(unix)]
    let toolchain = capture_toolchain(project, &values)?;
    #[cfg(unix)]
    bind_toolchain(&mut digest, &toolchain);
    let home = match environment_value(&values, "HOME") {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        // On Unix Node's os.homedir() preserves an explicitly empty HOME.
        // npm then leaves `~/` literal rather than substituting account HOME.
        Some(_) if cfg!(unix) => None,
        _ => dirs::home_dir(),
    };
    ensure!(
        home.as_ref().is_none_or(|path| path.to_str().is_some()),
        "npm configuration home is not UTF-8"
    );
    let mut paths = vec![(
        b"npm-project".as_slice(),
        absolute_path(project, Path::new(".npmrc"))?,
    )];
    for (role, option) in [
        (b"npm-user".as_slice(), "npm_config_userconfig"),
        (b"npm-global".as_slice(), "npm_config_globalconfig"),
    ] {
        let overrides = config_overrides(&values, option);
        ensure!(
            paths.len().saturating_add(overrides.len()) <= MAX_CONFIGURATION_FILES,
            "npm configuration exceeds file limit"
        );
        if overrides.is_empty() && option == "npm_config_userconfig" {
            paths.push((
                role,
                configuration_path(project, OsStr::new("~/.npmrc"), &values, home.as_deref())?,
            ));
        } else {
            for value in overrides {
                paths.push((
                    role,
                    configuration_path(project, value, &values, home.as_deref())?,
                ));
            }
        }
    }
    paths.sort();
    paths.dedup();
    let mut budget = MAX_CONFIGURATION_BYTES;
    let mut configurations = Vec::new();
    for (role, path) in paths {
        frame(&mut digest, role);
        configurations.push(capture_configuration(
            path,
            &values,
            &mut budget,
            &mut digest,
        )?);
    }
    // The first config must still describe the same generation after the last
    // one is read, including an absent file and every traversed symlink/parent.
    for configuration in &configurations {
        ensure!(
            resolve_configuration(&configuration.requested)? == configuration.resolution,
            "npm configuration changed during environment capture"
        );
    }
    #[cfg(unix)]
    ensure!(
        toolchain == capture_toolchain(project, &values)?,
        "dependency toolchain changed during environment capture"
    );
    Ok(CapturedEnvironment {
        digest: digest.finalize(),
        configurations,
    })
}

/// Bind Berry's home/ancestor configuration plus the effective files reported
/// by Yarn itself. This is separate from npm capture: a Node project without
/// a Yarn lock must not acquire unrelated Yarn configuration obligations.
pub(super) fn capture_yarn(project: &Path, additional: &[PathBuf]) -> Result<CapturedEnvironment> {
    capture_yarn_with(project, additional, std::env::vars_os().collect())
}

fn capture_yarn_with(
    project: &Path,
    additional: &[PathBuf],
    values: Vec<(OsString, OsString)>,
) -> Result<CapturedEnvironment> {
    let mut names = BTreeSet::from([".yarnrc.yml".to_owned()]);
    for (key, value) in &values {
        if key
            .as_encoded_bytes()
            .eq_ignore_ascii_case(b"YARN_RC_FILENAME")
        {
            let name = value
                .to_str()
                .context("Yarn configuration filename is not UTF-8")?;
            ensure!(
                !name.is_empty()
                    && name.len() <= 255
                    && !matches!(name, "." | "..")
                    && !name.contains(['/', '\\'])
                    && !name.chars().any(char::is_control),
                "Yarn configuration filename must be a literal filename"
            );
            names.insert(name.to_owned());
        }
    }
    let absolute = absolute_path(project, Path::new("."))?;
    let mut paths = BTreeSet::new();
    for ancestor in absolute.ancestors() {
        for name in &names {
            paths.insert(ancestor.join(name));
        }
        ensure!(
            paths.len() <= MAX_YARN_CONFIGURATION_ROOTS,
            "Yarn configuration exceeds file limit"
        );
    }
    let home = environment_value(&values, "HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir);
    if let Some(home) = home {
        // Berry always reads the default home filename, even with RC_FILENAME.
        paths.insert(absolute_path(project, &home.join(".yarnrc.yml"))?);
    }
    paths.extend(additional.iter().cloned());
    ensure!(
        paths.len() <= MAX_YARN_CONFIGURATION_FILES,
        "Yarn configuration exceeds file limit"
    );
    capture_paths(paths, &values)
}

fn capture_paths(
    paths: BTreeSet<PathBuf>,
    values: &[(OsString, OsString)],
) -> Result<CapturedEnvironment> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"rch-yarn-configuration-v1\0");
    let mut budget = MAX_CONFIGURATION_BYTES;
    let mut configurations = Vec::new();
    for path in paths {
        configurations.push(capture_configuration(
            path,
            values,
            &mut budget,
            &mut digest,
        )?);
    }
    for configuration in &configurations {
        ensure!(
            resolve_configuration(&configuration.requested)? == configuration.resolution,
            "Yarn configuration changed during capture"
        );
    }
    Ok(CapturedEnvironment {
        digest: digest.finalize(),
        configurations,
    })
}

pub(super) fn capture(project: &Path) -> Result<CapturedEnvironment> {
    capture_with(project, std::env::vars_os().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yarn_home_ancestor_override_and_environment_inputs_change_identity() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("parent/project");
        let home = directory.path().join("home");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir(&home).unwrap();
        let mut values = vec![(OsString::from("HOME"), home.as_os_str().to_owned())];
        let capture = |values: &Vec<(OsString, OsString)>| {
            capture_yarn_with(&project, &[], values.clone()).unwrap()
        };
        let absent = capture(&values);
        std::fs::write(home.join(".yarnrc.yml"), b"enableScripts: false\n").unwrap();
        let homed = capture(&values);
        assert_ne!(absent.digest, homed.digest);
        std::fs::write(
            directory.path().join("parent/.yarnrc.yml"),
            b"npmRegistryServer: '${CUSTOM_REGISTRY:-https://registry.yarnpkg.com}'\n",
        )
        .unwrap();
        let parent = capture(&values);
        assert_ne!(homed.digest, parent.digest);
        values.push((
            OsString::from("CUSTOM_REGISTRY"),
            OsString::from("https://registry.example"),
        ));
        assert_ne!(parent.digest, capture(&values).digest);
        values.push((
            OsString::from("YARN_RC_FILENAME"),
            OsString::from("custom.yml"),
        ));
        let custom_absent = capture(&values);
        std::fs::write(project.join("custom.yml"), b"nodeLinker: pnp\n").unwrap();
        assert_ne!(custom_absent.digest, capture(&values).digest);
        // A cache/log write changes directory timestamps, not config authority.
        let expected = capture(&values);
        std::fs::write(home.join("unrelated-log"), b"new log").unwrap();
        assert_eq!(expected, capture(&values));
    }

    #[test]
    fn yarn_extra_files_bind_absence_and_content() {
        let fixture = ConfigFixture::new();
        let extra = fixture.project.join(".env.yarn");
        let capture = || {
            capture_yarn_with(
                &fixture.project,
                std::slice::from_ref(&extra),
                fixture.values.clone(),
            )
            .unwrap()
        };
        let absent = capture();
        std::fs::write(&extra, b"MODE=development\n").unwrap();
        let initial = capture();
        assert_ne!(absent.digest, initial.digest);
        std::fs::write(&extra, b"MODE=production\n").unwrap();
        assert_ne!(initial.digest, capture().digest);
    }

    #[test]
    fn yarn_install_may_create_only_the_missing_structural_parent() {
        let fixture = ConfigFixture::new();
        let extra = fixture.project.join(".yarn/plugins");
        let capture = || {
            capture_yarn_with(
                &fixture.project,
                std::slice::from_ref(&extra),
                fixture.values.clone(),
            )
            .unwrap()
        };
        let before = capture();
        std::fs::create_dir(fixture.project.join(".yarn")).unwrap();
        let after = capture();
        assert_ne!(before, after);
        assert!(before.same_after_yarn_parent_created(&after, &fixture.project));
        assert!(!after.same_after_yarn_parent_created(&before, &fixture.project));

        // Once the directory exists, a later replacement is still refused.
        std::fs::rename(
            fixture.project.join(".yarn"),
            fixture.project.join("saved-yarn"),
        )
        .unwrap();
        std::fs::create_dir(fixture.project.join(".yarn")).unwrap();
        assert!(!after.same_after_yarn_parent_created(&capture(), &fixture.project));

        std::fs::write(&extra, b"new authored input").unwrap();
        assert!(!before.same_after_yarn_parent_created(&capture(), &fixture.project));
    }

    #[cfg(unix)]
    #[test]
    fn yarn_created_parent_cannot_be_a_symlink_or_an_unrelated_input_parent() {
        use std::os::unix::fs::symlink;

        let fixture = ConfigFixture::new();
        let target = fixture.project.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let capture = |extra: PathBuf| {
            capture_yarn_with(&fixture.project, &[extra], fixture.values.clone()).unwrap()
        };
        let extra = fixture.project.join(".yarn/releases");
        let before = capture(extra.clone());
        symlink(&target, fixture.project.join(".yarn")).unwrap();
        assert!(!before.same_after_yarn_parent_created(&capture(extra), &fixture.project));

        let extra = fixture.project.join("new-config/settings.yml");
        let before = capture(extra.clone());
        std::fs::create_dir(fixture.project.join("new-config")).unwrap();
        assert!(!before.same_after_yarn_parent_created(&capture(extra), &fixture.project));
    }

    struct ConfigFixture {
        _directory: tempfile::TempDir,
        project: PathBuf,
        home: PathBuf,
        values: Vec<(OsString, OsString)>,
    }

    impl ConfigFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let project = directory.path().join("project");
            let home = directory.path().join("home");
            std::fs::create_dir(&project).unwrap();
            std::fs::create_dir(&home).unwrap();
            let values = vec![(OsString::from("HOME"), home.as_os_str().to_owned())];
            Self {
                _directory: directory,
                project,
                home,
                values,
            }
        }

        fn set(&mut self, key: &str, value: impl AsRef<OsStr>) {
            self.values.retain(|(name, _)| name != key);
            self.values
                .push((OsString::from(key), value.as_ref().to_owned()));
        }

        fn capture(&self) -> Result<CapturedEnvironment> {
            capture_with(&self.project, self.values.clone())
        }
    }

    #[cfg(unix)]
    fn launcher(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn runtime_and_manager_generations_invalidate_without_hashing_large_binaries() {
        let mut fixture = ConfigFixture::new();
        let bin = fixture.project.join("tools");
        std::fs::create_dir(&bin).unwrap();
        fixture.set("PATH", &bin);
        let node = bin.join("node");
        // A large sparse native-looking executable still costs only a bounded
        // prefix read. No executable is launched to discover its identity.
        launcher(&node, b"\x7fELFfixture");
        File::options()
            .write(true)
            .open(&node)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();
        let initial = fixture.capture().unwrap();
        assert_eq!(initial, fixture.capture().unwrap());

        let before = std::fs::metadata(&node).unwrap().modified().unwrap();
        std::fs::rename(&node, bin.join("retained-node")).unwrap();
        launcher(&node, b"\x7fELFfixture");
        let file = File::options().write(true).open(&node).unwrap();
        file.set_len(1024 * 1024 * 1024).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(before))
            .unwrap();
        let replaced = fixture.capture().unwrap();
        assert_ne!(
            initial.digest, replaced.digest,
            "same size and mtime, new inode"
        );

        let npm = bin.join("npm");
        launcher(&npm, b"#!/bin/sh\nexit 0\n");
        let installed = fixture.capture().unwrap();
        let before = std::fs::metadata(&npm).unwrap().modified().unwrap();
        std::fs::write(&npm, b"#!/bin/sh\nexit 1\n").unwrap();
        File::options()
            .write(true)
            .open(&npm)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(before))
            .unwrap();
        assert_ne!(
            installed.digest,
            fixture.capture().unwrap().digest,
            "same-size manager rewrite with restored mtime changes ctime"
        );
    }

    #[cfg(unix)]
    #[test]
    fn launcher_symlink_parent_and_literal_env_interpreter_generations_are_bound() {
        use std::os::unix::fs::symlink;
        let mut fixture = ConfigFixture::new();
        let bin = fixture.project.join("tools");
        std::fs::create_dir(&bin).unwrap();
        fixture.set("PATH", &bin);
        let first = bin.join("runtime-first");
        let second = bin.join("runtime-second");
        launcher(&first, b"\x7fELFsame runtime");
        launcher(&second, b"\x7fELFsame runtime");
        let interpreter = bin.join("private-node");
        symlink(&first, &interpreter).unwrap();
        launcher(
            &bin.join("npm"),
            b"#!/usr/bin/env -S private-node --no-warnings\n",
        );
        let initial = fixture.capture().unwrap();
        std::fs::rename(&interpreter, bin.join("retained-interpreter-link")).unwrap();
        symlink(&second, &interpreter).unwrap();
        let retargeted = fixture.capture().unwrap();
        assert_ne!(initial.digest, retargeted.digest);

        // Rename the PATH directory and preserve the same executable inodes
        // via links. A new parent generation still cannot certify an old run.
        let retained = fixture.project.join("retained-tools");
        std::fs::rename(&bin, &retained).unwrap();
        symlink(&retained, &bin).unwrap();
        assert_ne!(retargeted.digest, fixture.capture().unwrap().digest);
    }

    #[cfg(unix)]
    #[test]
    fn absent_tool_candidates_ignore_new_empty_parents_but_notice_shadowing() {
        let mut fixture = ConfigFixture::new();
        let bin = fixture.project.join("tools");
        std::fs::create_dir(&bin).unwrap();
        launcher(&bin.join("node"), b"\x7fELFruntime");
        fixture.set("PATH", "node_modules/.bin:tools");
        let initial = fixture.capture().unwrap();
        let prepared = fixture.project.join("node_modules/.bin");
        std::fs::create_dir_all(&prepared).unwrap();
        std::fs::write(bin.join("unrelated-install-log"), b"log").unwrap();
        assert_eq!(initial, fixture.capture().unwrap());
        launcher(&prepared.join("node"), b"\x7fELFnew runtime");
        assert_ne!(initial.digest, fixture.capture().unwrap().digest);
    }

    #[cfg(unix)]
    #[test]
    fn relative_kernel_interpreter_is_bound_to_workload_cwd_not_path() {
        let mut fixture = ConfigFixture::new();
        let bin = fixture.project.join("tools");
        std::fs::create_dir(&bin).unwrap();
        fixture.set("PATH", &bin);
        launcher(&bin.join("npm"), b"#!private-node\n");
        launcher(&bin.join("private-node"), b"\x7fELFunused PATH runtime");
        let actual = fixture.project.join("private-node");
        launcher(&actual, b"\x7fELFactual cwd runtime");
        let before = fixture.capture().unwrap();
        std::fs::write(
            bin.join("private-node"),
            b"\x7fELFreplaced unused PATH runtime",
        )
        .unwrap();
        assert_eq!(before, fixture.capture().unwrap());
        std::fs::write(&actual, b"\x7fELFreplaced cwd runtime").unwrap();
        assert_ne!(before.digest, fixture.capture().unwrap().digest);
    }

    #[cfg(unix)]
    #[test]
    fn toolchain_bounds_and_ambiguous_env_launchers_refuse_without_execution() {
        let mut fixture = ConfigFixture::new();
        fixture.set("PATH", ":".repeat(MAX_TOOLCHAIN_SEARCH_DIRECTORIES));
        assert!(
            fixture
                .capture()
                .unwrap_err()
                .to_string()
                .contains("directory limit")
        );
        let bin = fixture.project.join("tools");
        std::fs::create_dir(&bin).unwrap();
        fixture.set("PATH", &bin);
        launcher(&bin.join("npm"), b"#!/usr/bin/env -S PATH=/other node\n");
        assert!(
            fixture
                .capture()
                .unwrap_err()
                .to_string()
                .contains("literal interpreter")
        );
    }

    fn digest(values: &[(&str, &str)]) -> blake3::Hash {
        fingerprint(
            values
                .iter()
                .map(|(key, value)| (OsString::from(*key), OsString::from(*value))),
        )
        .unwrap()
    }

    #[test]
    fn configuration_values_presence_and_exact_key_case_affect_identity() {
        for key in [
            "NODE_ENV",
            "NODE_OPTIONS",
            "NODE_PATH",
            "CI",
            "PATH",
            "HOME",
            "XDG_CONFIG_HOME",
            "npm_config_omit",
            "NPM_CONFIG_IGNORE_SCRIPTS",
            "PNPM_CONFIG_PRODUCTION",
            "YARN_ENABLE_SCRIPTS",
            "BUN_INSTALL",
        ] {
            assert_ne!(digest(&[]), digest(&[(key, "")]), "{key}");
            assert_ne!(
                digest(&[(key, "first")]),
                digest(&[(key, "second")]),
                "{key}"
            );
        }
        assert_ne!(
            digest(&[("NODE_ENV", "production")]),
            digest(&[("node_env", "production")])
        );
        assert_ne!(
            digest(&[("npm_config_omit", "dev")]),
            digest(&[("NPM_CONFIG_OMIT", "dev")])
        );
    }

    #[test]
    fn order_and_unrelated_attempt_environment_do_not_force_reinstalls() {
        let expected = digest(&[("NODE_ENV", "development"), ("npm_config_omit", "optional")]);
        assert_eq!(
            expected,
            digest(&[("npm_config_omit", "optional"), ("NODE_ENV", "development")])
        );
        assert_eq!(
            expected,
            digest(&[
                ("RCH_BUILD_ID", "new-attempt"),
                ("TMPDIR", "/another/temporary/root"),
                ("NODE_ENV", "development"),
                ("npm_config_omit", "optional"),
            ])
        );
        // Length framing separates a changed key from a changed value.
        assert_ne!(
            digest(&[("npm_config_a", "bc")]),
            digest(&[("npm_config_ab", "c")])
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_values_remain_distinct() {
        use std::os::unix::ffi::OsStringExt;
        let first = fingerprint([(
            OsString::from("npm_config_cache"),
            OsString::from_vec(vec![0xff]),
        )])
        .unwrap();
        let second = fingerprint([(
            OsString::from("npm_config_cache"),
            OsString::from_vec(vec![0xfe]),
        )])
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn default_user_config_binds_missing_empty_and_changed_contents() {
        let fixture = ConfigFixture::new();
        let missing = fixture.capture().unwrap();
        let path = fixture.home.join(".npmrc");
        std::fs::write(&path, b"").unwrap();
        let empty = fixture.capture().unwrap();
        assert_ne!(missing.digest, empty.digest);
        std::fs::write(&path, b"omit=dev\n").unwrap();
        let configured = fixture.capture().unwrap();
        assert_ne!(empty.digest, configured.digest);
        assert_eq!(configured, fixture.capture().unwrap());
        std::fs::write(&path, b"omit=optional\n").unwrap();
        assert_ne!(configured.digest, fixture.capture().unwrap().digest);
    }

    #[test]
    fn explicit_config_paths_bind_contents_without_disclosing_credentials() {
        let mut fixture = ConfigFixture::new();
        let user = fixture.project.join("user-settings");
        let global = fixture.project.join("global-settings");
        let secret = "private-registry-credential-must-not-appear";
        std::fs::write(&user, format!("//registry.example/:_authToken={secret}\n")).unwrap();
        std::fs::write(&global, "ignore-scripts=true\n").unwrap();
        fixture.set("npm_config_userconfig", &user);
        fixture.set("NPM_CONFIG_GLOBALCONFIG", &global);
        let before = fixture.capture().unwrap();
        assert!(!format!("{before:?}").contains(secret));
        std::fs::write(&global, "ignore-scripts=false\n").unwrap();
        assert_ne!(before.digest, fixture.capture().unwrap().digest);
        // An explicit userconfig overrides the default candidate completely.
        let after = fixture.capture().unwrap();
        std::fs::write(fixture.home.join(".npmrc"), "omit=dev\n").unwrap();
        assert_eq!(after, fixture.capture().unwrap());
    }

    #[test]
    fn config_aliases_are_bound_independently_of_child_environment_order() {
        let mut fixture = ConfigFixture::new();
        std::fs::write(fixture.project.join("lower"), "omit=dev\n").unwrap();
        std::fs::write(fixture.project.join("upper"), "omit=optional\n").unwrap();
        fixture.set("npm_config_userconfig", "lower");
        fixture.set("NPM_CONFIG_USERCONFIG", "upper");
        let upper = fixture.capture().unwrap();
        let original = fingerprint(fixture.values.clone()).unwrap();
        fixture.values.reverse();
        assert_eq!(original, fingerprint(fixture.values.clone()).unwrap());
        let lower = fixture.capture().unwrap();
        assert_eq!(
            upper, lower,
            "both case-alias paths are bound before child env normalization"
        );
        std::fs::write(fixture.project.join("lower"), "ignore-scripts=true\n").unwrap();
        assert_ne!(lower.digest, fixture.capture().unwrap().digest);
        fixture.set("NPM_CONFIG_USERCONFIG", "");
        let empty_alias = fixture.capture().unwrap();
        assert!(
            empty_alias
                .configurations
                .iter()
                .any(|config| config.requested == fixture.project.join("lower")),
            "empty aliases must not erase a preceding nonempty selection"
        );
        assert!(
            !empty_alias
                .configurations
                .iter()
                .any(|config| config.requested == fixture.project.join("upper"))
        );
    }

    #[test]
    fn config_paths_expand_against_the_project_and_selected_home() {
        let mut fixture = ConfigFixture::new();
        std::fs::write(fixture.project.join("settings file"), "omit=dev\n").unwrap();
        fixture.set("CONFIG_LOCATION", "./absent/../settings file");
        fixture.set("npm_config_userconfig", " \t${CONFIG_LOCATION}\n");
        let relative = fixture.capture().unwrap();
        assert!(
            relative
                .configurations
                .iter()
                .any(|config| config.requested == fixture.project.join("settings file"))
        );
        std::fs::write(fixture.home.join("custom"), "omit=optional\n").unwrap();
        fixture.set("npm_config_userconfig", "~/custom");
        assert!(
            fixture
                .capture()
                .unwrap()
                .configurations
                .iter()
                .any(|config| config.requested == fixture.home.join("custom"))
        );
        // An unbound path variable can select another file with unchanged
        // npm_config_userconfig spelling, and therefore changes identity.
        fixture.set("npm_config_userconfig", "${CONFIG_LOCATION}");
        fixture.set("CONFIG_LOCATION", fixture.home.join("custom"));
        assert_ne!(relative.digest, fixture.capture().unwrap().digest);
    }

    #[test]
    fn path_expansion_preserves_npm_optional_and_escape_semantics() {
        let values = vec![(OsString::from("NAME"), OsString::from("value"))];
        for (input, expected) in [
            ("${NAME}", "value"),
            ("${MISSING}", "${MISSING}"),
            ("${MISSING?}", ""),
            (r"\${NAME}", "${NAME}"),
            (r"\\${NAME}", r"\value"),
            (r"\\\${NAME}", r"\${NAME}"),
            ("a/${NAME}/λ", "a/value/λ"),
            (r"trailing\", r"trailing\"),
        ] {
            assert_eq!(expand_path(input, &values).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn config_references_bind_values_presence_and_ini_unquoting() {
        let mut fixture = ConfigFixture::new();
        let path = fixture.home.join(".npmrc");
        for text in [
            "omit=${DEPENDENCY_OMIT}\n",
            "omit=${DEPENDENCY_OMIT?}\n",
            "omit=\"\\u0024{DEPENDENCY_OMIT}\"\n",
            "omit='\"\\u0024{DEPENDENCY_OMIT}\"'\n",
            "omit='[\"\\u0024{DEPENDENCY_OMIT}\"]'\n",
            "unrelated=true\romit=\"\\u0024{DEPENDENCY_OMIT}\"\r",
            "omit=\u{feff}\"\\u0024{DEPENDENCY_OMIT}\"\n",
        ] {
            std::fs::write(&path, text).unwrap();
            fixture.values.retain(|(name, _)| name != "DEPENDENCY_OMIT");
            let absent = fixture.capture().unwrap();
            fixture.set("DEPENDENCY_OMIT", "");
            let empty = fixture.capture().unwrap();
            assert_ne!(absent.digest, empty.digest, "{text}");
            fixture.set("DEPENDENCY_OMIT", "dev");
            let dev = fixture.capture().unwrap();
            fixture.set("DEPENDENCY_OMIT", "optional");
            assert_ne!(dev.digest, fixture.capture().unwrap().digest, "{text}");
        }
    }

    #[test]
    fn project_config_references_are_bound_with_an_explicit_user_override() {
        let mut fixture = ConfigFixture::new();
        std::fs::write(fixture.project.join("user-config"), "").unwrap();
        std::fs::write(fixture.project.join(".npmrc"), "omit=${PROJECT_OMIT}\n").unwrap();
        fixture.set("npm_config_userconfig", "user-config");
        fixture.set("PROJECT_OMIT", "dev");
        let before = fixture.capture().unwrap();
        fixture.set("PROJECT_OMIT", "optional");
        assert_ne!(before.digest, fixture.capture().unwrap().digest);
    }

    #[cfg(unix)]
    #[test]
    fn explicitly_empty_home_keeps_npm_tilde_path_literal() {
        let mut fixture = ConfigFixture::new();
        fixture.set("HOME", "");
        std::fs::create_dir(fixture.project.join("~")).unwrap();
        let path = fixture.project.join("~/.npmrc");
        std::fs::write(&path, "omit=dev\n").unwrap();
        let before = fixture.capture().unwrap();
        assert!(
            before
                .configurations
                .iter()
                .any(|config| config.requested == path)
        );
        std::fs::write(&path, "omit=optional\n").unwrap();
        assert_ne!(before.digest, fixture.capture().unwrap().digest);
    }

    #[test]
    fn malformed_references_and_excessive_path_components_are_bounded() {
        let mut text = "${".repeat(64 * 1024);
        text.push_str("${ACTUAL}");
        let mut references = BTreeSet::new();
        collect_references(&text, &mut references).unwrap();
        assert_eq!(references, BTreeSet::from(["ACTUAL".to_string()]));
        let expanded = expand_path(
            &text,
            &[(OsString::from("ACTUAL"), OsString::from("value"))],
        )
        .unwrap();
        assert_eq!(expanded, format!("{}value", "${".repeat(64 * 1024)));
        let fixture = ConfigFixture::new();
        let excessive = "component/".repeat(MAX_CONFIGURATION_COMPONENTS + 1);
        assert!(
            absolute_path(&fixture.project, Path::new(&excessive))
                .unwrap_err()
                .to_string()
                .contains("component limit")
        );
    }

    #[test]
    fn unrelated_environment_and_npm_cache_writes_preserve_configuration_identity() {
        let mut fixture = ConfigFixture::new();
        std::fs::write(fixture.home.join(".npmrc"), "omit=dev\n").unwrap();
        let before = fixture.capture().unwrap();
        std::fs::create_dir(fixture.home.join(".npm")).unwrap();
        std::fs::write(fixture.home.join(".npm/log"), "installer diagnostics\n").unwrap();
        fixture.set("RCH_BUILD_ID", "another-build");
        assert_eq!(before, fixture.capture().unwrap());
    }

    #[test]
    fn config_file_size_and_reference_count_are_bounded() {
        let fixture = ConfigFixture::new();
        let path = fixture.home.join(".npmrc");
        File::create(&path)
            .unwrap()
            .set_len(MAX_CONFIGURATION_BYTES + 1)
            .unwrap();
        assert!(
            fixture
                .capture()
                .unwrap_err()
                .to_string()
                .contains("byte limit")
        );
        let text = (0..=MAX_CONFIGURATION_REFERENCES)
            .map(|index| format!("${{NAME_{index}}}\n"))
            .collect::<String>();
        let mut references = BTreeSet::new();
        assert!(collect_references(&text, &mut references).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_destinations_and_dangling_target_presence_are_bound() {
        use std::os::unix::fs::symlink;
        let fixture = ConfigFixture::new();
        let link = fixture.home.join(".npmrc");
        symlink("settings/first", &link).unwrap();
        let missing = fixture.capture().unwrap();
        std::fs::create_dir(fixture.home.join("settings")).unwrap();
        std::fs::write(fixture.home.join("settings/first"), "omit=dev\n").unwrap();
        std::fs::write(fixture.home.join("settings/second"), "omit=dev\n").unwrap();
        let first = fixture.capture().unwrap();
        assert_ne!(missing.digest, first.digest);
        std::fs::rename(&link, fixture.home.join("previous-link")).unwrap();
        symlink("settings/second", &link).unwrap();
        let second = fixture.capture().unwrap();
        assert_ne!(
            first.digest, second.digest,
            "same bytes at a different selected link target"
        );
        assert_eq!(second, fixture.capture().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn replaced_parent_is_detected_without_keying_directory_timestamps() {
        let mut fixture = ConfigFixture::new();
        let parent = fixture.project.join("settings");
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("npmrc"), "omit=dev\n").unwrap();
        fixture.set("npm_config_userconfig", "settings/npmrc");
        let before = fixture.capture().unwrap();
        std::fs::rename(&parent, fixture.project.join("retained-settings")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("npmrc"), "omit=dev\n").unwrap();
        let after = fixture.capture().unwrap();
        assert_eq!(
            before.digest, after.digest,
            "same content remains the same cache input"
        );
        assert_ne!(
            before, after,
            "a running installation cannot mix parent generations"
        );
    }

    #[cfg(unix)]
    #[test]
    fn special_files_and_symlink_loops_are_refused_before_read() {
        use std::os::unix::fs::symlink;
        let mut fixture = ConfigFixture::new();
        let fifo = fixture.project.join("configuration-fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        fixture.set("npm_config_userconfig", &fifo);
        assert!(
            fixture
                .capture()
                .unwrap_err()
                .to_string()
                .contains("not a regular file")
        );
        symlink("loop", fixture.project.join("loop")).unwrap();
        fixture.set("npm_config_userconfig", "loop");
        assert!(
            fixture
                .capture()
                .unwrap_err()
                .to_string()
                .contains("symlink limit")
        );
    }
}
