//! Exact ownership of dependency outputs for source-qualified execution.
//!
//! A fingerprint is install intent, not output provenance. Only a completed
//! frozen installer transaction can introduce a new output inventory. Later
//! attempts rehash that inventory before reuse; an unrecorded retained tree is
//! never promoted to trusted state by scanning it. Selected source remains a
//! separate exact obligation, including selected files below node_modules and
//! checked-in Yarn Plug'n'Play loaders or cache archives.

use crate::prepare::DependencyLayout;
use anyhow::Result;
use rch_common::prepared_dependencies::{
    PreparedDependencyAttestation, PreparedDependencyRequest, PreparedDependencyState,
};
use rch_common::types::RequiredRuntime;
use std::path::Path;

pub async fn proof_inspect(
    project: &Path,
    runtime: RequiredRuntime,
    request: &PreparedDependencyRequest,
) -> Result<Option<PreparedDependencyState>> {
    #[cfg(target_os = "linux")]
    {
        linux::inspect(project, runtime, request).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (project, runtime, request);
        anyhow::bail!("qualified dependency preparation requires Linux descendant completion")
    }
}

pub async fn proof_install(
    project: &Path,
    runtime: RequiredRuntime,
    request: &PreparedDependencyRequest,
) -> Result<PreparedDependencyAttestation> {
    #[cfg(target_os = "linux")]
    {
        linux::install(project, runtime, request).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (project, runtime, request);
        anyhow::bail!("qualified dependency preparation requires Linux descendant completion")
    }
}

pub async fn proof_verify(
    project: &Path,
    runtime: RequiredRuntime,
    expected_request_digest: &str,
    expected_attestation_digest: &str,
    invocation_project: Option<&Path>,
) -> Result<DependencyLayout> {
    #[cfg(target_os = "linux")]
    {
        linux::verify(
            project,
            runtime,
            expected_request_digest,
            expected_attestation_digest,
            invocation_project,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            project,
            runtime,
            expected_request_digest,
            expected_attestation_digest,
            invocation_project,
        );
        anyhow::bail!("qualified dependency preparation requires Linux descendant completion")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::prepare::{
        DependencyInputs, IDLE, InstallPlan, PrepareAction, PrepareTransaction, RUNNING,
        install as installer, preflight_cache_files, verified_fingerprint,
    };
    use anyhow::{Context, bail, ensure};
    use rch_common::node_workspace::{
        MAX_DECLARATION_DOCUMENT_BYTES, MAX_DECLARATION_TOTAL_BYTES, declaration_paths,
        resolve_preparation_root,
    };
    use rch_common::prepared_dependencies::{
        MAX_PREPARED_DEPENDENCY_BYTES, MAX_PREPARED_DEPENDENCY_DIRECTORIES,
        MAX_PREPARED_DEPENDENCY_FILES, MAX_PREPARED_DEPENDENCY_JSON_BYTES,
        PREPARED_DEPENDENCY_VERSION, PreparedDependencyDisposition, PreparedDependencyFile,
        PreparedDependencyFileKind, PreparedDependencyInventory, admitted_dependency_outputs,
        admitted_dependency_roots,
    };
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const READ_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY);
    const DIRECTORY_FLAGS: OFlags = READ_FLAGS.union(OFlags::DIRECTORY);
    const MAX_DEPTH: usize = 128;
    const MAX_COMPLETED_BYTES: usize = 2 * MAX_PREPARED_DEPENDENCY_JSON_BYTES + 1024;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Identity {
        device: u64,
        inode: u64,
        mode: u32,
        links: u64,
        uid: u32,
        bytes: u64,
        modified: (i64, u64),
        changed: (i64, u64),
    }

    impl Identity {
        // Linux's stat field widths vary between supported architectures.
        #[allow(clippy::unnecessary_cast)]
        fn of(info: &rustix::fs::Stat) -> Result<Self> {
            ensure!(info.st_size >= 0, "negative dependency entry length");
            Ok(Self {
                device: info.st_dev as u64,
                inode: info.st_ino as u64,
                mode: info.st_mode,
                links: info.st_nlink as u64,
                uid: info.st_uid,
                bytes: info.st_size as u64,
                modified: (info.st_mtime as i64, info.st_mtime_nsec as u64),
                changed: (info.st_ctime as i64, info.st_ctime_nsec as u64),
            })
        }

        fn held(file: &File) -> Result<Self> {
            Self::of(&rustix::fs::fstat(file)?)
        }

        fn at(parent: &File, name: &str) -> Result<Self> {
            Self::of(&rustix::fs::statat(
                parent,
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            )?)
        }

        fn kind(&self) -> FileType {
            FileType::from_raw_mode(self.mode)
        }

        fn same_inode(&self, other: &Self) -> bool {
            self.kind() == other.kind() && self.device == other.device && self.inode == other.inode
        }

        fn private_record(&self) -> Result<()> {
            ensure!(
                self.kind() == FileType::RegularFile
                    && self.links == 1
                    && self.uid == rustix::process::geteuid().as_raw()
                    && self.mode & 0o077 == 0,
                "prepared dependency record is not a private owned regular file"
            );
            Ok(())
        }
    }

    /// All reads descend from a held source-root descriptor. Revalidation
    /// checks every observed entry and ancestor after the last byte is read.
    /// NOFOLLOW and NONBLOCK also make replacement by a symlink/FIFO refuse
    /// instead of reading outside the tree or waiting on a special file.
    struct View {
        source_name: PathBuf,
        canonical_source: PathBuf,
        root: File,
        root_identity: Identity,
        observed: BTreeMap<String, Identity>,
        bytes_left: u64,
    }

    impl View {
        fn new(request: &PreparedDependencyRequest) -> Result<Self> {
            request.validate()?;
            let source_name = PathBuf::from(&request.source_root);
            let canonical_source = source_name.canonicalize()?;
            let root = File::from(rustix::fs::open(
                &canonical_source,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )?);
            let root_identity = Identity::held(&root)?;
            let view = Self {
                source_name,
                canonical_source,
                root,
                root_identity,
                observed: BTreeMap::new(),
                // The two independently bounded manifests may each contain
                // eight GiB. No file is read without debiting this budget.
                bytes_left: 2 * MAX_PREPARED_DEPENDENCY_BYTES,
            };
            view.verify_root()?;
            Ok(view)
        }

        fn verify_root(&self) -> Result<()> {
            ensure!(
                self.source_name.canonicalize()? == self.canonical_source,
                "prepared source-root alias changed"
            );
            let named = File::from(rustix::fs::open(
                &self.canonical_source,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )?);
            ensure!(
                Identity::held(&self.root)? == self.root_identity
                    && Identity::held(&named)? == self.root_identity,
                "prepared source root changed during inventory"
            );
            Ok(())
        }

        fn remember(&mut self, path: &str, identity: Identity) -> Result<()> {
            if let Some(previous) = self.observed.get(path) {
                ensure!(*previous == identity, "dependency entry changed: {path}");
            } else {
                ensure!(
                    self.observed.len()
                        < 2 * (MAX_PREPARED_DEPENDENCY_FILES + MAX_PREPARED_DEPENDENCY_DIRECTORIES)
                            + MAX_DEPTH,
                    "prepared dependency observation limit exceeded"
                );
                self.observed.insert(path.to_owned(), identity);
            }
            Ok(())
        }

        fn directory(&mut self, path: &str) -> Result<File> {
            self.optional_directory(path)?
                .with_context(|| format!("prepared directory does not exist: {path}"))
        }

        /// Missing generated ancestors are normal before the first install.
        /// Resolve them component by component without following a symlink or
        /// dropping the identity checks on the last existing parent.
        fn optional_directory(&mut self, path: &str) -> Result<Option<File>> {
            let mut current = self.root.try_clone()?;
            if path.is_empty() {
                return Ok(Some(current));
            }
            let mut prefix = String::new();
            ensure!(
                path.split('/').count() <= MAX_DEPTH,
                "prepared dependency directory depth exceeded"
            );
            for component in path.split('/') {
                ensure!(
                    !component.is_empty() && !matches!(component, "." | ".."),
                    "invalid prepared directory component"
                );
                let before =
                    match rustix::fs::statat(&current, component, AtFlags::SYMLINK_NOFOLLOW) {
                        Ok(info) => Identity::of(&info)?,
                        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
                        Err(error) => return Err(error).context("inspect dependency parent"),
                    };
                ensure!(
                    before.kind() == FileType::Directory,
                    "dependency parent is not a directory"
                );
                let child = File::from(rustix::fs::openat(
                    &current,
                    component,
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                )?);
                ensure!(
                    Identity::held(&child)? == before,
                    "dependency directory changed before open"
                );
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                self.remember(&prefix, before)?;
                current = child;
            }
            Ok(Some(current))
        }

        fn parent(&mut self, path: &str) -> Result<(File, String)> {
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            ensure!(
                !name.is_empty() && !matches!(name, "." | ".."),
                "invalid dependency filename"
            );
            Ok((self.directory(parent)?, name.to_owned()))
        }

        fn file(&mut self, path: &str) -> Result<PreparedDependencyFile> {
            self.file_with_contents(path, None).map(|(file, _)| file)
        }

        /// Retain declaration bytes during the same bounded descriptor read
        /// that verifies selected source, rather than reopening a named path
        /// later to decide whether an ancestor may own the installation.
        fn file_with_contents(
            &mut self,
            path: &str,
            content_limit: Option<usize>,
        ) -> Result<(PreparedDependencyFile, Option<Vec<u8>>)> {
            let (parent, name) = self.parent(path)?;
            let before = Identity::at(&parent, &name)?;
            let mut contents = if let Some(limit) = content_limit {
                ensure!(
                    before.kind() == FileType::RegularFile,
                    "workspace declaration is not a regular file: {path}"
                );
                ensure!(
                    before.bytes <= limit as u64,
                    "workspace declaration byte limit exceeded: {path}"
                );
                Some(Vec::with_capacity(before.bytes as usize))
            } else {
                None
            };
            self.bytes_left = self
                .bytes_left
                .checked_sub(before.bytes)
                .context("prepared dependency byte limit exceeded")?;
            let mut digest = Sha256::new();
            let (kind, executable, target) = match before.kind() {
                FileType::RegularFile => {
                    let mut file = File::from(rustix::fs::openat(
                        &parent,
                        name.as_str(),
                        READ_FLAGS,
                        Mode::empty(),
                    )?);
                    ensure!(
                        Identity::held(&file)? == before,
                        "dependency file changed before read: {path}"
                    );
                    let mut remaining = before.bytes;
                    let mut buffer = [0u8; 64 * 1024];
                    while remaining > 0 {
                        let limit = remaining.min(buffer.len() as u64) as usize;
                        let count = file.read(&mut buffer[..limit])?;
                        ensure!(count != 0, "dependency file shortened during read: {path}");
                        digest.update(&buffer[..count]);
                        if let Some(contents) = &mut contents {
                            contents.extend_from_slice(&buffer[..count]);
                        }
                        remaining -= count as u64;
                    }
                    ensure!(
                        file.read(&mut buffer[..1])? == 0,
                        "dependency file grew during read: {path}"
                    );
                    ensure!(
                        Identity::held(&file)? == before,
                        "dependency file changed during read: {path}"
                    );
                    (
                        PreparedDependencyFileKind::Regular,
                        before.mode & 0o111 != 0,
                        None,
                    )
                }
                FileType::Symlink => {
                    ensure!(
                        before.bytes <= 4096,
                        "dependency symlink exceeds path limit"
                    );
                    let target = rustix::fs::readlinkat(&parent, name.as_str(), Vec::new())?;
                    let target = target
                        .to_str()
                        .context("dependency symlink target is not UTF-8")?;
                    ensure!(
                        target.len() as u64 == before.bytes,
                        "dependency symlink length changed"
                    );
                    digest.update(target.as_bytes());
                    (
                        PreparedDependencyFileKind::Symlink,
                        false,
                        Some(target.to_owned()),
                    )
                }
                _ => bail!("unsupported dependency output type: {path}"),
            };
            ensure!(
                Identity::at(&parent, &name)? == before,
                "dependency path changed during read: {path}"
            );
            self.remember(path, before.clone())?;
            let mut sha256 = String::with_capacity(64);
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for byte in digest.finalize() {
                sha256.push(char::from(HEX[usize::from(byte >> 4)]));
                sha256.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
            Ok((
                PreparedDependencyFile {
                    path: path.to_owned(),
                    kind,
                    sha256,
                    byte_count: before.bytes,
                    executable,
                    symlink_target: target,
                },
                contents,
            ))
        }

        fn selected(
            &mut self,
            request: &PreparedDependencyRequest,
        ) -> Result<BTreeMap<String, Vec<u8>>> {
            let needed =
                declaration_paths(&request.project_relative).map_err(anyhow::Error::msg)?;
            let mut declarations = BTreeMap::new();
            let mut remaining = MAX_DECLARATION_TOTAL_BYTES;
            for directory in &request.directories {
                self.directory(directory)?;
            }
            for expected in &request.files {
                let capture = (expected.kind == PreparedDependencyFileKind::Regular
                    && needed.contains(&expected.path))
                .then_some(remaining.min(MAX_DECLARATION_DOCUMENT_BYTES));
                let (observed, contents) = self.file_with_contents(&expected.path, capture)?;
                ensure!(
                    observed == *expected,
                    "selected source changed before prepared execution: {}",
                    expected.path
                );
                if let Some(contents) = contents {
                    remaining -= contents.len();
                    declarations.insert(expected.path.clone(), contents);
                }
            }
            Ok(declarations)
        }

        fn walk(
            &mut self,
            path: &str,
            selected_files: &BTreeMap<&str, &PreparedDependencyFile>,
            selected_directories: &BTreeSet<&str>,
            inventory: &mut PreparedDependencyInventory,
        ) -> Result<()> {
            let directory = self.directory(path)?;
            if !selected_directories.contains(path) {
                ensure!(
                    inventory.directories.len() < MAX_PREPARED_DEPENDENCY_DIRECTORIES,
                    "prepared directory count exceeded"
                );
                inventory.directories.push(path.to_owned());
            }
            let mut entries = Vec::new();
            for entry in rustix::fs::Dir::read_from(&directory)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .to_str()
                    .context("dependency filename is not UTF-8")?;
                if matches!(name, "." | "..") {
                    continue;
                }
                ensure!(
                    entries.len()
                        < MAX_PREPARED_DEPENDENCY_FILES + MAX_PREPARED_DEPENDENCY_DIRECTORIES,
                    "dependency directory is too large"
                );
                entries.push(name.to_owned());
            }
            entries.sort();
            for name in entries {
                let child = format!("{path}/{name}");
                let identity = Identity::at(&directory, &name)?;
                if identity.kind() == FileType::Directory {
                    self.walk(&child, selected_files, selected_directories, inventory)?;
                } else if selected_files.contains_key(child.as_str()) {
                    // Already read above, but a package installer may not use
                    // the selected namespace as an exemption from provenance.
                    self.remember(&child, identity)?;
                } else {
                    ensure!(
                        inventory.files.len() < MAX_PREPARED_DEPENDENCY_FILES,
                        "prepared file count exceeded"
                    );
                    inventory.files.push(self.file(&child)?);
                }
            }
            Ok(())
        }

        fn finish(mut self) -> Result<()> {
            let observed = self.observed.clone();
            for (path, expected) in observed {
                let (parent, name) = self.parent(&path)?;
                ensure!(
                    Identity::at(&parent, &name)? == expected,
                    "prepared dependency changed during inventory: {path}"
                );
            }
            self.verify_root()
        }
    }

    struct Snapshot {
        inventory: PreparedDependencyInventory,
        source: Identity,
        project: Identity,
    }

    fn scan(
        project: &Path,
        request: &PreparedDependencyRequest,
        inputs: &DependencyInputs,
        invocation_project: Option<&Path>,
    ) -> Result<Snapshot> {
        let mut view = View::new(request)?;
        let preparation = request.preparation_relative();
        let held_project = view.directory(preparation)?;
        let project_identity = Identity::held(&held_project)?;
        ensure!(
            project.canonicalize()? == view.canonical_source.join(preparation),
            "prepared request names a different project"
        );
        view.directory(&request.project_relative)?;
        let expected_invocation = view.canonical_source.join(&request.project_relative);
        let verify_invocation = || -> Result<()> {
            if let Some(invocation) = invocation_project {
                ensure!(
                    invocation.canonicalize()? == expected_invocation,
                    "prepared execution invocation directory does not match its accepted request"
                );
            }
            Ok(())
        };
        verify_invocation()?;
        let selected_files: BTreeMap<_, _> = request
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();
        let selected_directories: BTreeSet<_> =
            request.directories.iter().map(String::as_str).collect();
        let mut roots = BTreeSet::new();
        for name in &inputs.fingerprint.sources {
            let relative = if preparation.is_empty() {
                name.clone()
            } else {
                format!("{preparation}/{name}")
            };
            ensure!(
                selected_files
                    .get(relative.as_str())
                    .is_some_and(|file| file.kind == PreparedDependencyFileKind::Regular),
                "dependency install input is not selected regular source: {relative}"
            );
            if name == "package.json" || name.ends_with("/package.json") {
                let parent = relative.rsplit_once('/').map_or("", |(parent, _)| parent);
                roots.insert(if parent.is_empty() {
                    "node_modules".to_owned()
                } else {
                    format!("{parent}/node_modules")
                });
            }
        }
        let allowed: BTreeSet<_> = admitted_dependency_roots(request)?.into_iter().collect();
        ensure!(
            roots.is_subset(&allowed),
            "dependency output roots exceed selected workspace namespace"
        );
        let outputs = admitted_dependency_outputs(request)?;
        // Common's package-manifest roots are only candidates. Keep the
        // narrower captured workspace membership above, while adding the
        // fixed Yarn trees separately from its exact files and parent dirs.
        roots.extend(
            outputs
                .subtree_roots
                .iter()
                .filter(|root| !allowed.contains(*root))
                .cloned(),
        );
        let declarations = view.selected(request)?;
        let regular_paths = request
            .files
            .iter()
            .filter(|file| file.kind == PreparedDependencyFileKind::Regular)
            .map(|file| file.path.clone())
            .collect();
        ensure!(
            resolve_preparation_root(&request.project_relative, &regular_paths, &declarations)
                .map_err(anyhow::Error::msg)?
                == preparation,
            "requested preparation root is not the declared workspace root for this invocation"
        );
        let mut inventory = PreparedDependencyInventory {
            files: Vec::new(),
            directories: Vec::new(),
        };
        for directory in outputs.structural_directories {
            if view.optional_directory(&directory)?.is_some()
                && !selected_directories.contains(directory.as_str())
            {
                ensure!(
                    inventory.directories.len() < MAX_PREPARED_DEPENDENCY_DIRECTORIES,
                    "prepared directory count exceeded"
                );
                inventory.directories.push(directory);
            }
        }
        for root in &roots {
            // A selected workspace may itself be below a generated tree.
            // Enumerate that namespace once, so inventories remain unique.
            if root
                .match_indices('/')
                .any(|(boundary, _)| roots.contains(&root[..boundary]))
            {
                continue;
            }
            let (parent_path, name) = root.rsplit_once('/').unwrap_or(("", root));
            let Some(parent) = view.optional_directory(parent_path)? else {
                continue;
            };
            match rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(info) => {
                    ensure!(
                        Identity::of(&info)?.kind() == FileType::Directory,
                        "dependency output root is not a real directory: {root}"
                    );
                    view.walk(root, &selected_files, &selected_directories, &mut inventory)?;
                }
                Err(error) if error == rustix::io::Errno::NOENT => {}
                Err(error) => return Err(error).context("inspect dependency output root"),
            }
        }
        for path in outputs.exact_files {
            let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", &path));
            let Some(parent) = view.optional_directory(parent_path)? else {
                continue;
            };
            let identity = match rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(info) => Identity::of(&info)?,
                Err(error) if error == rustix::io::Errno::NOENT => continue,
                Err(error) => return Err(error).context("inspect exact dependency output"),
            };
            ensure!(
                identity.kind() == FileType::RegularFile,
                "exact dependency output is not a real regular file: {path}"
            );
            if selected_files.contains_key(path.as_str()) {
                view.remember(&path, identity)?;
            } else {
                ensure!(
                    inventory.files.len() < MAX_PREPARED_DEPENDENCY_FILES,
                    "prepared file count exceeded"
                );
                inventory.files.push(view.file(&path)?);
            }
        }
        inventory
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        inventory.directories.sort();
        inventory.validate_for(request)?;
        let source = view.root_identity.clone();
        view.finish()?;
        verify_invocation()?;
        Ok(Snapshot {
            inventory,
            source,
            project: project_identity,
        })
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Completed {
        request: PreparedDependencyRequest,
        attestation: PreparedDependencyAttestation,
    }

    /// The journal lock serializes this one atomic completed envelope. A crash
    /// after its rename but before IDLE leaves the stable RUNNING fence; no
    /// reader may use the new state until that same transaction is settled.
    struct Store {
        directory: File,
        directory_path: PathBuf,
        directory_identity: Identity,
        name: String,
        previous: Option<Identity>,
    }

    impl Store {
        fn open(transaction: &PrepareTransaction) -> Result<Self> {
            transaction.verify_path()?;
            let directory_path = transaction
                .path
                .parent()
                .context("preparation journal has no parent")?
                .to_owned();
            let directory = File::from(rustix::fs::open(
                &directory_path,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )?);
            let directory_identity = Identity::held(&directory)?;
            ensure!(
                directory_identity.uid == rustix::process::geteuid().as_raw()
                    && directory_identity.mode & 0o077 == 0,
                "preparation state directory is not private and owned"
            );
            let name = format!(
                "{}.outputs-v1.json",
                transaction
                    .path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .context("invalid preparation journal filename")?
            );
            let store = Self {
                directory,
                directory_path,
                directory_identity,
                name,
                previous: None,
            };
            store.verify_directory()?;
            Ok(store)
        }

        fn verify_directory(&self) -> Result<()> {
            let named = File::from(rustix::fs::open(
                &self.directory_path,
                DIRECTORY_FLAGS,
                Mode::empty(),
            )?);
            ensure!(
                Identity::held(&self.directory)?.same_inode(&self.directory_identity)
                    && Identity::held(&named)?.same_inode(&self.directory_identity),
                "preparation state directory changed"
            );
            Ok(())
        }

        fn read(&mut self) -> Result<Option<Completed>> {
            let identity = match rustix::fs::statat(
                &self.directory,
                self.name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(info) => Identity::of(&info)?,
                Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
                Err(error) => return Err(error).context("inspect completed preparation"),
            };
            identity.private_record()?;
            ensure!(
                identity.bytes <= MAX_COMPLETED_BYTES as u64,
                "completed preparation exceeds byte limit"
            );
            let mut file = File::from(rustix::fs::openat(
                &self.directory,
                self.name.as_str(),
                READ_FLAGS,
                Mode::empty(),
            )?);
            ensure!(
                Identity::held(&file)? == identity,
                "completed preparation changed before read"
            );
            let mut bytes = Vec::new();
            (&mut file)
                .take(MAX_COMPLETED_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == identity.bytes
                    && Identity::held(&file)? == identity
                    && Identity::at(&self.directory, &self.name)? == identity,
                "completed preparation changed during read"
            );
            self.verify_directory()?;
            let completed: Completed =
                serde_json::from_slice(&bytes).context("invalid completed preparation record")?;
            completed.request.validate()?;
            completed.attestation.validate_for(&completed.request)?;
            ensure!(
                serde_json::to_vec(&completed.request)?.len() <= MAX_PREPARED_DEPENDENCY_JSON_BYTES
                    && serde_json::to_vec(&completed.attestation)?.len()
                        <= MAX_PREPARED_DEPENDENCY_JSON_BYTES,
                "completed preparation components exceed byte limit"
            );
            self.previous = Some(identity);
            Ok(Some(completed))
        }

        fn publish(&self, completed: &Completed) -> Result<()> {
            completed.attestation.validate_for(&completed.request)?;
            let bytes = serde_json::to_vec(completed)?;
            ensure!(
                bytes.len() <= MAX_COMPLETED_BYTES,
                "completed preparation exceeds byte limit"
            );
            ensure!(
                serde_json::to_vec(&completed.request)?.len() <= MAX_PREPARED_DEPENDENCY_JSON_BYTES
                    && serde_json::to_vec(&completed.attestation)?.len()
                        <= MAX_PREPARED_DEPENDENCY_JSON_BYTES,
                "completed preparation components exceed byte limit"
            );
            self.verify_directory()?;
            static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temporary = format!("{}.{}.{}.pending", self.name, std::process::id(), sequence);
            let mut file = File::from(rustix::fs::openat(
                &self.directory,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            file.write_all(&bytes)?;
            file.sync_all()?;
            let written = Identity::held(&file)?;
            written.private_record()?;
            ensure!(
                written.bytes == bytes.len() as u64
                    && Identity::at(&self.directory, &temporary)? == written,
                "prepared state staging file changed"
            );
            let current = match rustix::fs::statat(
                &self.directory,
                self.name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(info) => Some(Identity::of(&info)?),
                Err(error) if error == rustix::io::Errno::NOENT => None,
                Err(error) => return Err(error).context("revalidate completed preparation"),
            };
            ensure!(
                current == self.previous,
                "completed preparation was replaced during transaction"
            );
            self.verify_directory()?;
            rustix::fs::renameat(
                &self.directory,
                temporary.as_str(),
                &self.directory,
                self.name.as_str(),
            )?;
            self.directory.sync_all()?;
            ensure!(
                Identity::at(&self.directory, &self.name)?.same_inode(&written),
                "published prepared state inode changed"
            );
            self.verify_directory()
        }
    }

    fn check_runtime(runtime: RequiredRuntime) -> Result<()> {
        ensure!(
            matches!(runtime, RequiredRuntime::Node | RequiredRuntime::Bun),
            "qualified dependency preparation requires Node or Bun"
        );
        Ok(())
    }

    fn retained_inventory(
        request: &PreparedDependencyRequest,
        state: &PreparedDependencyState,
    ) -> Result<PreparedDependencyInventory> {
        state.validate_for(request)?;
        let selected_files: BTreeSet<_> = request
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        let selected_directories: BTreeSet<_> =
            request.directories.iter().map(String::as_str).collect();
        Ok(PreparedDependencyInventory {
            files: state
                .inventory
                .files
                .iter()
                .filter(|file| !selected_files.contains(file.path.as_str()))
                .cloned()
                .collect(),
            directories: state
                .inventory
                .directories
                .iter()
                .filter(|directory| !selected_directories.contains(directory.as_str()))
                .cloned()
                .collect(),
        })
    }

    fn verify_baseline(
        request: &PreparedDependencyRequest,
        snapshot: &Snapshot,
        previous: Option<&PreparedDependencyState>,
    ) -> Result<()> {
        match previous {
            Some(state) => {
                ensure!(
                    state.root_device == snapshot.project.device
                        && state.root_inode == snapshot.project.inode,
                    "retained preparation project inode changed"
                );
                ensure!(
                    snapshot.inventory == retained_inventory(request, state)?,
                    "retained dependency inventory changed or contains unregistered outputs"
                );
            }
            None => ensure!(
                snapshot.inventory.files.is_empty() && snapshot.inventory.directories.is_empty(),
                "retained dependency outputs have no completed ownership record"
            ),
        }
        Ok(())
    }

    pub(super) async fn inspect(
        project: &Path,
        runtime: RequiredRuntime,
        request: &PreparedDependencyRequest,
    ) -> Result<Option<PreparedDependencyState>> {
        check_runtime(runtime)?;
        request.validate()?;
        let mut transaction = PrepareTransaction::acquire(project).await?;
        let mut store = Store::open(&transaction)?;
        let completed = store.read()?;
        let inputs = DependencyInputs::capture_in_transaction(&mut transaction).await?;
        inputs.dependency_layout.verify_runtime(runtime)?;
        inputs.verify_invocation(&transaction.project, Path::new(&request.invocation_path()))?;
        let snapshot = scan(&transaction.project, request, &inputs, None)?;
        let state = completed.map(|completed| completed.attestation.state);
        verify_baseline(request, &snapshot, state.as_ref())?;
        transaction.verify_path()?;
        Ok(state)
    }

    pub(super) async fn install(
        project: &Path,
        runtime: RequiredRuntime,
        request: &PreparedDependencyRequest,
    ) -> Result<PreparedDependencyAttestation> {
        check_runtime(runtime)?;
        request.validate()?;
        let mut transaction = PrepareTransaction::acquire(project).await?;
        let mut store = Store::open(&transaction)?;
        let previous = store.read()?;
        preflight_cache_files(&transaction.project)?;
        let inputs = DependencyInputs::capture_in_transaction(&mut transaction).await?;
        inputs.dependency_layout.verify_runtime(runtime)?;
        inputs.verify_invocation(&transaction.project, Path::new(&request.invocation_path()))?;
        let plan = InstallPlan::for_sources(&inputs.fingerprint.sources, runtime)?;
        ensure!(
            plan.is_frozen(),
            "source-qualified dependency preparation requires a selected frozen lockfile"
        );
        let before = scan(&transaction.project, request, &inputs, None)?;
        let prior_state = previous
            .as_ref()
            .map(|completed| &completed.attestation.state);
        verify_baseline(request, &before, prior_state)?;
        // Frozen resolution does not close lifecycle-script inputs: an
        // installer can read any selected source file or directory. Reuse
        // requires that exact namespace, not only the manifest/lock stamp.
        // Keep attempt/build/owner identities out of this comparison so an
        // unchanged selection can still receive a fresh retained attestation.
        // The old inventory remains ownership evidence above even when these
        // inputs change; only a completed installer may publish its successor.
        let allow_cache_hit = previous.as_ref().is_some_and(|completed| {
            completed.request.files == request.files
                && completed.request.directories == request.directories
                && completed.attestation.state.input_fingerprint == inputs.fingerprint.hash
                && completed.attestation.state.package_manager == plan.manager_name()
        });
        transaction.record(RUNNING)?;
        let log_dir = transaction.project.join(".rch_prepare_logs");
        let report = installer::prepare_observed_node(
            &mut transaction,
            runtime,
            &log_dir,
            &inputs,
            allow_cache_hit,
            true,
        )
        .await?;
        ensure!(
            matches!(
                report.action,
                PrepareAction::Installed | PrepareAction::Skipped
            ),
            "qualified dependency installation did not complete: {:?}",
            report.action
        );
        ensure!(
            report.action != PrepareAction::Skipped || allow_cache_hit,
            "unproven dependency cache cannot be adopted"
        );
        let after_inputs = DependencyInputs::capture_in_transaction(&mut transaction).await?;
        inputs.verify_after(&after_inputs, runtime, report.action)?;
        ensure!(
            report.fingerprint.as_ref() == Some(&after_inputs.fingerprint),
            "qualified preparation fingerprint changed"
        );
        preflight_cache_files(&transaction.project)?;
        verified_fingerprint(&transaction.project, &report, &after_inputs)?;
        let after = scan(&transaction.project, request, &after_inputs, None)?;
        ensure!(
            before.source.same_inode(&after.source) && before.project.same_inode(&after.project),
            "prepared source/project root was replaced during installation"
        );
        if report.action == PrepareAction::Skipped {
            verify_baseline(request, &after, prior_state)?;
        }
        let state = PreparedDependencyState {
            version: PREPARED_DEPENDENCY_VERSION,
            project: request.preparation_path(),
            root_device: after.project.device,
            root_inode: after.project.inode,
            input_fingerprint: after_inputs.fingerprint.hash,
            package_manager: plan.manager_name().to_owned(),
            frozen: true,
            inventory_digest: after.inventory.digest()?,
            inventory: after.inventory,
        };
        let attestation = PreparedDependencyAttestation {
            version: PREPARED_DEPENDENCY_VERSION,
            request_digest: request.digest()?,
            state_digest: state.digest()?,
            state,
            disposition: if report.action == PrepareAction::Installed {
                PreparedDependencyDisposition::Fresh
            } else {
                PreparedDependencyDisposition::Retained
            },
        };
        attestation.validate_for(request)?;
        store.publish(&Completed {
            request: request.clone(),
            attestation: attestation.clone(),
        })?;
        transaction.record(IDLE)?;
        Ok(attestation)
    }

    pub(super) async fn verify(
        project: &Path,
        runtime: RequiredRuntime,
        expected_request_digest: &str,
        expected_attestation_digest: &str,
        invocation_project: Option<&Path>,
    ) -> Result<DependencyLayout> {
        check_runtime(runtime)?;
        let mut transaction = PrepareTransaction::acquire(project).await?;
        let mut store = Store::open(&transaction)?;
        let completed = store
            .read()?
            .context("prepared attempt has no completed attestation")?;
        ensure!(
            completed.request.digest()? == expected_request_digest
                && completed.attestation.request_digest == expected_request_digest
                && completed.attestation.digest()? == expected_attestation_digest,
            "prepared execution attempt does not match its accepted attestation"
        );
        ensure!(
            invocation_project.is_some()
                || completed.request.preparation_relative() == completed.request.project_relative,
            "workspace prepared verification requires --invocation-project"
        );
        let inputs = DependencyInputs::capture_in_transaction(&mut transaction).await?;
        inputs.dependency_layout.verify_runtime(runtime)?;
        inputs.verify_invocation(
            &transaction.project,
            Path::new(&completed.request.invocation_path()),
        )?;
        let plan = InstallPlan::for_sources(&inputs.fingerprint.sources, runtime)?;
        ensure!(
            plan.is_frozen()
                && plan.manager_name() == completed.attestation.state.package_manager
                && inputs.fingerprint.hash == completed.attestation.state.input_fingerprint,
            "prepared execution inputs changed after acceptance"
        );
        let snapshot = scan(
            &transaction.project,
            &completed.request,
            &inputs,
            invocation_project,
        )?;
        verify_baseline(
            &completed.request,
            &snapshot,
            Some(&completed.attestation.state),
        )?;
        transaction.verify_path()?;
        Ok(inputs.dependency_layout)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fmt::Write as _;
        use std::os::unix::fs::{PermissionsExt, symlink};

        fn project(source: &Path, relative: &str) -> PathBuf {
            let project = source.join(relative);
            std::fs::create_dir_all(&project).unwrap();
            std::fs::write(
                project.join("package.json"),
                br#"{"name":"pnp-fixture","private":true}"#,
            )
            .unwrap();
            std::fs::write(project.join("yarn.lock"), b"selected frozen resolution\n").unwrap();
            project
        }

        fn request(source: &Path, project: &Path, names: &[&str]) -> PreparedDependencyRequest {
            let mut directories = BTreeSet::new();
            let mut files = Vec::new();
            for name in names {
                let full = project.join(name);
                let relative = full.strip_prefix(source).unwrap();
                let path = relative.to_str().unwrap().to_owned();
                let contents = std::fs::read(&full).unwrap();
                let mut sha256 = String::with_capacity(64);
                for byte in Sha256::digest(&contents) {
                    write!(sha256, "{byte:02x}").unwrap();
                }
                files.push(PreparedDependencyFile {
                    path,
                    kind: PreparedDependencyFileKind::Regular,
                    sha256,
                    byte_count: contents.len() as u64,
                    executable: std::fs::metadata(&full).unwrap().permissions().mode() & 0o111 != 0,
                    symlink_target: None,
                });
                let mut parent = relative.parent().unwrap();
                while !parent.as_os_str().is_empty() {
                    directories.insert(parent.to_str().unwrap().to_owned());
                    parent = parent.parent().unwrap();
                }
            }
            files.sort_by(|left, right| left.path.cmp(&right.path));
            let request = PreparedDependencyRequest {
                schema_version: PREPARED_DEPENDENCY_VERSION,
                attempt_id: "pnp-scan-attempt".to_owned(),
                source_owner: "12345678-1234-1234-1234-123456789abc".to_owned(),
                build_id: "12345".to_owned(),
                command_sha256: "a".repeat(64),
                source_content_root: "b".repeat(64),
                source_root: source.canonicalize().unwrap().to_str().unwrap().to_owned(),
                project_relative: project
                    .strip_prefix(source)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
                preparation_relative: None,
                files,
                directories: directories.into_iter().collect(),
            };
            request.validate().unwrap();
            request
        }

        fn state(
            request: &PreparedDependencyRequest,
            inputs: &DependencyInputs,
            snapshot: &Snapshot,
        ) -> PreparedDependencyState {
            PreparedDependencyState {
                version: PREPARED_DEPENDENCY_VERSION,
                project: request.preparation_path(),
                root_device: snapshot.project.device,
                root_inode: snapshot.project.inode,
                input_fingerprint: inputs.fingerprint.hash.clone(),
                package_manager: "yarn".to_owned(),
                frozen: true,
                inventory: snapshot.inventory.clone(),
                inventory_digest: snapshot.inventory.digest().unwrap(),
            }
        }

        #[test]
        fn pnp_inventory_tracks_exact_files_trees_and_missing_structural_parent() {
            for relative in ["", "web"] {
                let source = tempfile::tempdir().unwrap();
                let project = project(source.path(), relative);
                let request = request(source.path(), &project, &["package.json", "yarn.lock"]);
                let inputs = DependencyInputs::capture(&project).unwrap();
                let before = scan(&project, &request, &inputs, None).unwrap();
                verify_baseline(&request, &before, None).unwrap();
                assert!(!project.join(".yarn").exists());

                std::fs::create_dir_all(project.join(".yarn/cache")).unwrap();
                std::fs::create_dir_all(project.join(".yarn/unplugged/pkg/empty")).unwrap();
                for name in [
                    ".pnp.cjs",
                    ".pnp.data.json",
                    ".pnp.loader.mjs",
                    ".yarn/install-state.gz",
                    ".yarn/cache/pkg.zip",
                    ".yarn/unplugged/pkg/index.js",
                ] {
                    std::fs::write(project.join(name), format!("completed {name}\n")).unwrap();
                }
                let after = scan(&project, &request, &inputs, None).unwrap();
                assert_eq!(after.inventory.files.len(), 6);
                let prefix = if relative.is_empty() { "" } else { "web/" };
                assert_eq!(
                    after.inventory.directories,
                    [
                        ".yarn",
                        ".yarn/cache",
                        ".yarn/unplugged",
                        ".yarn/unplugged/pkg",
                        ".yarn/unplugged/pkg/empty",
                    ]
                    .map(|path| format!("{prefix}{path}"))
                );
                assert!(verify_baseline(&request, &after, None).is_err());
                let completed = state(&request, &inputs, &after);
                verify_baseline(&request, &after, Some(&completed)).unwrap();
                std::fs::write(project.join(".yarn/cache/pkg.zip"), b"changed cache\n").unwrap();
                let tampered = scan(&project, &request, &inputs, None).unwrap();
                assert!(verify_baseline(&request, &tampered, Some(&completed)).is_err());
            }
        }

        #[test]
        fn pnp_zero_install_sources_are_not_adopted_and_yarn_neighbors_are_not_outputs() {
            let source = tempfile::tempdir().unwrap();
            let project = project(source.path(), "");
            std::fs::create_dir_all(project.join(".yarn/cache")).unwrap();
            std::fs::create_dir_all(project.join(".yarn/releases")).unwrap();
            for name in [
                ".pnp.cjs",
                ".yarn/cache/selected.zip",
                ".yarn/releases/yarn.cjs",
            ] {
                std::fs::write(project.join(name), format!("selected {name}\n")).unwrap();
            }
            let request = request(
                source.path(),
                &project,
                &[
                    "package.json",
                    "yarn.lock",
                    ".pnp.cjs",
                    ".yarn/cache/selected.zip",
                    ".yarn/releases/yarn.cjs",
                ],
            );
            let inputs = DependencyInputs::capture(&project).unwrap();
            let selected_only = scan(&project, &request, &inputs, None).unwrap();
            verify_baseline(&request, &selected_only, None).unwrap();
            std::fs::write(project.join(".yarn/install-state.gz"), b"new state\n").unwrap();
            std::fs::write(project.join(".yarn/unclaimed.txt"), b"unclaimed neighbor\n").unwrap();
            let after = scan(&project, &request, &inputs, None).unwrap();
            assert_eq!(after.inventory.files.len(), 1);
            assert_eq!(after.inventory.files[0].path, ".yarn/install-state.gz");
            assert!(after.inventory.directories.is_empty());
            // The full source namespace barrier rejects this extra neighbor.
            // The dependency proof must not give it generated-output authority.
            let mut forged = after.inventory.clone();
            let neighbor = View::new(&request)
                .unwrap()
                .file(".yarn/unclaimed.txt")
                .unwrap();
            forged.files.push(neighbor);
            assert!(forged.validate_for(&request).is_err());
            std::fs::write(project.join(".pnp.cjs"), b"changed selected loader\n").unwrap();
            assert!(scan(&project, &request, &inputs, None).is_err());
        }

        #[test]
        fn pnp_exact_outputs_and_generated_directories_reject_aliases() {
            for name in [".pnp.cjs", ".yarn", ".yarn/cache", ".yarn/unplugged"] {
                let source = tempfile::tempdir().unwrap();
                let outside = tempfile::tempdir().unwrap();
                let project = project(source.path(), "");
                let request = request(source.path(), &project, &["package.json", "yarn.lock"]);
                let inputs = DependencyInputs::capture(&project).unwrap();
                if name.starts_with(".yarn/") {
                    std::fs::create_dir(project.join(".yarn")).unwrap();
                }
                symlink(outside.path(), project.join(name)).unwrap();
                assert!(scan(&project, &request, &inputs, None).is_err(), "{name}");
                assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
            }
            let source = tempfile::tempdir().unwrap();
            let project = project(source.path(), "");
            let request = request(source.path(), &project, &["package.json", "yarn.lock"]);
            let inputs = DependencyInputs::capture(&project).unwrap();
            std::fs::create_dir(project.join(".pnp.cjs")).unwrap();
            assert!(scan(&project, &request, &inputs, None).is_err());
        }

        #[test]
        fn pnp_retained_inventory_rechecks_mode_presence_and_new_empty_directories() {
            for mutation in ["mode", "missing", "empty-directory"] {
                let source = tempfile::tempdir().unwrap();
                let project = project(source.path(), "");
                let request = request(source.path(), &project, &["package.json", "yarn.lock"]);
                let inputs = DependencyInputs::capture(&project).unwrap();
                std::fs::create_dir_all(project.join(".yarn/cache")).unwrap();
                let cache_file = project.join(".yarn/cache/pkg.zip");
                std::fs::write(&cache_file, b"retained cache bytes\n").unwrap();
                let before = scan(&project, &request, &inputs, None).unwrap();
                let completed = state(&request, &inputs, &before);
                match mutation {
                    "mode" => {
                        std::fs::set_permissions(
                            &cache_file,
                            std::fs::Permissions::from_mode(0o700),
                        )
                        .unwrap();
                    }
                    "missing" => {
                        std::fs::rename(&cache_file, project.join("unclaimed-cache.zip")).unwrap();
                    }
                    _ => {
                        std::fs::create_dir(project.join(".yarn/cache/unregistered-empty")).unwrap()
                    }
                }
                let after = scan(&project, &request, &inputs, None).unwrap();
                assert!(
                    verify_baseline(&request, &after, Some(&completed)).is_err(),
                    "{mutation}"
                );
            }
        }
    }
}
