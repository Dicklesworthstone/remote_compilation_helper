//! Negotiated request-bound source upload, before durable execution admission.
//!
//! The wire names a manifest and relative files, never the worker's staging
//! directory. A sealed owner is moved to the execution lifetime; reconnects
//! discard incomplete staging, not execution history. Completed result recovery
//! uses the ORIGINAL source-bearing request fingerprint and needs no reupload.
//! Optional source-byte reuse is explicit in source-begin. It saves transport,
//! never grants action-cache authority or skips the request's final source seal.

mod cache;

pub use cache::{DEFAULT_SOURCE_CACHE_BYTES, MAX_SOURCE_CACHE_BYTES, SourceCache};

#[cfg(test)]
use rabs_sandbox::cargo_home::CARGO_HOME_SOURCE_VERSION;
use rabs_sandbox::cargo_home::{CargoHomeProjection, PreparedCargoHome};
use rabs_sandbox::source_transfer::{
    MAX_SOURCE_CHUNK, MAX_SOURCE_FILES, SOURCE_TRANSFER, SourceFile, SourceManifest, SourceReceiver,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const UPLOAD_BUDGET: Duration = Duration::from_secs(5 * 60);

fn invalid(message: &str) -> String {
    message.to_owned()
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) {
        return Err(invalid("source upload cancelled"));
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2)
        || value.len() / 2 > maximum
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid bounded source hex"));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

fn digest(value: &Value) -> Result<[u8; 32], String> {
    decode_hex(value.as_str().ok_or("source digest must be a string")?, 32)?
        .try_into()
        .map_err(|_| invalid("source digest must contain 32 bytes"))
}

/// Interpret only the bounded source manifest. Other request fields remain
/// untouched so the journal fingerprints the exact original execution request.
pub fn parse_manifest(value: &Value) -> Result<SourceManifest, String> {
    if !value.as_object().is_some_and(|object| object.len() == 2) {
        return Err(invalid(
            "source manifest requires exactly files and manifest_sha256",
        ));
    }
    let rows = value["files"]
        .as_array()
        .filter(|rows| rows.len() <= MAX_SOURCE_FILES)
        .ok_or("invalid source file list")?;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        if !row.as_object().is_some_and(|object| object.len() == 4) {
            return Err(invalid("invalid source file fields"));
        }
        files.push(SourceFile {
            path: row["path"]
                .as_str()
                .ok_or("source path must be a string")?
                .to_owned(),
            len: row["bytes"]
                .as_u64()
                .ok_or("source length must be unsigned")?,
            sha256: digest(&row["sha256"])?,
            executable: row["executable"]
                .as_bool()
                .ok_or("source executable bit must be boolean")?,
        });
    }
    let manifest = SourceManifest::new(files).map_err(|error| error.to_string())?;
    if manifest.digest() != digest(&value["manifest_sha256"])? {
        return Err(invalid("source manifest digest mismatch"));
    }
    Ok(manifest)
}

/// The same declaration is carried by source-begin and the ORIGINAL execution
/// request. Decode only its shape here; sandbox policy owns relative-path and
/// registry-only selection. Never substitute a worker-local Cargo home pathname.
fn cargo_home_projection(
    value: &Value,
    manifest: &SourceManifest,
) -> Result<Option<CargoHomeProjection>, String> {
    let Some(home) = value.get("cargo_home") else {
        return Ok(None);
    };
    if !home.as_object().is_some_and(|object| object.len() == 2) {
        return Err(invalid(
            "cargo_home requires a supported version and prefix",
        ));
    }
    let prefix = home["prefix"]
        .as_str()
        .ok_or("cargo_home prefix must be a string")?;
    let version = home["version"]
        .as_str()
        .ok_or("cargo_home version must be a string")?;
    CargoHomeProjection::for_version(version, prefix, manifest)
        .map(Some)
        .map_err(|error| error.to_string())
}

pub fn request_manifest(request: &Value) -> Result<Option<SourceManifest>, String> {
    // These fields name local preparation intent, not executable source. Check
    // their PRESENCE before the worker-local fast path as well as uploaded input.
    // Ignoring them could admit a different workspace than the caller selected.
    // Never echo their host paths or values into protocol diagnostics.
    if request.get("source_files").is_some() || request.get("source_roots").is_some() {
        return Err(invalid(
            "unprepared source_files/source_roots; use --worker-prepare before execution",
        ));
    }
    match request.get("source_manifest") {
        None if request.get("cargo_home").is_some() => {
            Err(invalid("cargo_home requires an uploaded source_manifest"))
        }
        None => Ok(None),
        Some(value) => {
            if request.get("workspace_backing").is_some() {
                return Err(invalid(
                    "source manifest and worker workspace path are mutually exclusive",
                ));
            }
            let manifest = parse_manifest(value)?;
            cargo_home_projection(request, &manifest)?;
            Ok(Some(manifest))
        }
    }
}

pub fn selected(frame: &str) -> Result<bool, String> {
    let value: Value = serde_json::from_str(frame).map_err(|error| error.to_string())?;
    match value.get("source_transfer") {
        None => Ok(false),
        Some(value) if value.as_str() == Some(SOURCE_TRANSFER) => Ok(true),
        Some(_) => Err(invalid("unsupported source_transfer selection")),
    }
}

/// Keeps worker-owned source bytes alive until the process and all writers have
/// drained. It conveys no publication permission and is never reconstructed from
/// an arbitrary path supplied in a frame.
pub struct SourceOwner {
    receiver: SourceReceiver,
    _directory: tempfile::TempDir,
    request_id: u64,
    deadline: Instant,
    execution_owned: bool,
    allow_cached_files: bool,
    missing_files: Vec<String>,
    reused_bytes: u64,
    cache: Option<cache::SourceCache>,
    cache_write_error: Option<String>,
    source_failed: bool,
    cargo_home: Option<CargoHomeProjection>,
    prepared_cargo_home: Option<PreparedCargoHome>,
}

/// Exact input mountpoints inside one private writable output directory. The
/// underlying placeholders remain empty while the compiler sees separately
/// retained read-only input files mounted over them. After namespace teardown,
/// only these descriptor-verified names may be excluded from output capture.
#[derive(Debug)]
pub(crate) struct DependencyOutputInputs {
    backing: std::path::PathBuf,
    directory: std::fs::File,
    directory_metadata: std::fs::Metadata,
    files: std::collections::BTreeMap<String, DependencyOutputInput>,
}

#[derive(Debug)]
struct DependencyOutputInput {
    placeholder: std::fs::File,
    placeholder_metadata: std::fs::Metadata,
    retained_path: std::path::PathBuf,
    retained: std::fs::File,
    retained_metadata: std::fs::Metadata,
}

/// Holds the complete generated-input inventory across compiler execution and
/// capture. Files are rehashed against the source seal before this guard is
/// returned; held descriptors and exact directory membership fence later
/// replacement, mutation and newly introduced files.
#[derive(Debug)]
pub(crate) struct DependencyGeneratedInputs {
    backing: std::path::PathBuf,
    directory: std::fs::File,
    directory_metadata: std::fs::Metadata,
    directories: std::collections::BTreeMap<String, std::fs::Metadata>,
    files: std::collections::BTreeMap<String, (std::fs::File, std::fs::Metadata)>,
}

fn dependency_same_directory(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.is_dir()
            && right.is_dir()
            && dependency_same_identity(left, right)
            && left.nlink() == right.nlink()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

impl DependencyGeneratedInputs {
    fn capture(
        backing: std::path::PathBuf,
        files: &[&SourceFile],
        directories: &[String],
        prefix: &str,
    ) -> io::Result<Self> {
        use std::io::Read;

        rabs_sandbox::generated_source::validate_generated_directories(directories)?;
        let refuse = || io::Error::other("generated input differs from its sealed manifest");
        let directory_metadata = std::fs::symlink_metadata(&backing)?;
        if !directory_metadata.is_dir() || std::fs::canonicalize(&backing)? != backing {
            return Err(refuse());
        }
        let directory = std::fs::File::open(&backing)?;
        if !dependency_same_directory(&directory_metadata, &directory.metadata()?) {
            return Err(refuse());
        }
        let mut guard = Self {
            backing,
            directory,
            directory_metadata,
            directories: std::collections::BTreeMap::new(),
            files: std::collections::BTreeMap::new(),
        };
        for name in directories {
            let path = guard.backing.join(name);
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_dir() || std::fs::canonicalize(&path)? != path {
                return Err(refuse());
            }
            guard.directories.insert(name.clone(), metadata);
        }
        for expected in files {
            let name = expected.path.strip_prefix(prefix).ok_or_else(refuse)?;
            for (offset, _) in name.match_indices('/') {
                let parent = &name[..offset];
                if !guard.directories.contains_key(parent) {
                    return Err(refuse());
                }
            }
            if guard.directories.contains_key(name) {
                return Err(refuse());
            }
            let path = guard.backing.join(name);
            if std::fs::canonicalize(&path)? != path {
                return Err(refuse());
            }
            let mut file = rabs_sandbox::regular_input::open(&path)?;
            let metadata = file.metadata()?;
            if metadata.len() != expected.len
                || !dependency_same_file(&metadata, &std::fs::symlink_metadata(&path)?)
            {
                return Err(refuse());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if (metadata.permissions().mode() & 0o111 != 0) != expected.executable {
                    return Err(refuse());
                }
            }
            let mut remaining = expected.len;
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
            while remaining != 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count]);
                remaining -= count as u64;
            }
            if file.read(&mut buffer[..1])? != 0
                || <[u8; 32]>::from(hash.finalize()) != expected.sha256
                || !dependency_same_file(&metadata, &file.metadata()?)
            {
                return Err(refuse());
            }
            guard.files.insert(name.to_owned(), (file, metadata));
        }
        guard.verify()?;
        Ok(guard)
    }

    pub(crate) fn verify(&self) -> io::Result<()> {
        let refuse = || io::Error::other("generated input tree changed after preparation");
        if std::fs::canonicalize(&self.backing)? != self.backing
            || !dependency_same_directory(&self.directory_metadata, &self.directory.metadata()?)
            || !dependency_same_directory(
                &self.directory_metadata,
                &std::fs::symlink_metadata(&self.backing)?,
            )
        {
            return Err(refuse());
        }
        let mut found = std::collections::BTreeSet::new();
        for name in std::iter::once("").chain(self.directories.keys().map(String::as_str)) {
            let path = self.backing.join(name);
            if !name.is_empty()
                && (!dependency_same_directory(
                    &self.directories[name],
                    &std::fs::symlink_metadata(&path)?,
                ) || std::fs::canonicalize(&path)? != path)
            {
                return Err(refuse());
            }
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let basename = entry.file_name();
                let basename = basename.to_str().ok_or_else(refuse)?;
                let relative = if name.is_empty() {
                    basename.to_owned()
                } else {
                    format!("{name}/{basename}")
                };
                if (!self.files.contains_key(&relative)
                    && !self.directories.contains_key(&relative))
                    || !found.insert(relative)
                {
                    return Err(refuse());
                }
            }
        }
        if found.len() != self.files.len() + self.directories.len() {
            return Err(refuse());
        }
        for (name, (file, metadata)) in &self.files {
            let path = self.backing.join(name);
            if std::fs::canonicalize(&path)? != path
                || !dependency_same_file(metadata, &file.metadata()?)
                || !dependency_same_file(metadata, &std::fs::symlink_metadata(path)?)
            {
                return Err(refuse());
            }
        }
        Ok(())
    }
}

fn dependency_same_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino() && left.mode() == right.mode()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn dependency_same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.is_file()
            && right.is_file()
            && dependency_same_identity(left, right)
            && left.len() == right.len()
            && left.nlink() == 1
            && right.nlink() == 1
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

impl DependencyOutputInputs {
    fn new(backing: &std::path::Path) -> io::Result<Self> {
        let entry = std::fs::symlink_metadata(backing)?;
        if !backing.is_absolute() || !entry.is_dir() || std::fs::canonicalize(backing)? != backing {
            return Err(io::Error::other(
                "dependency output backing is not a real private root",
            ));
        }
        let directory = std::fs::File::open(backing)?;
        let directory_metadata = directory.metadata()?;
        if !dependency_same_identity(&entry, &directory_metadata) {
            return Err(io::Error::other(
                "dependency output root changed during acquisition",
            ));
        }
        Ok(Self {
            backing: backing.to_path_buf(),
            directory,
            directory_metadata,
            files: std::collections::BTreeMap::new(),
        })
    }

    /// Input basenames from the sealed manifest, never an arbitrary exclusion
    /// list supplied by a request. Capture must call verify on its own backing
    /// both before and after excluding these entries.
    pub(crate) fn relative_paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// Refuse replaced, changed, linked or missing placeholders and retained
    /// inputs. The directory's own mtime may change when rustc creates outputs;
    /// its held inode and every immutable file generation must remain unchanged.
    pub(crate) fn verify(&self, output_backing: &std::path::Path) -> io::Result<()> {
        let refuse = || io::Error::other("dependency input mountpoint or retained backing changed");
        if output_backing != self.backing
            || std::fs::canonicalize(output_backing)? != self.backing
            || !dependency_same_identity(&self.directory_metadata, &self.directory.metadata()?)
            || !dependency_same_identity(
                &self.directory_metadata,
                &std::fs::symlink_metadata(output_backing)?,
            )
        {
            return Err(refuse());
        }
        for (name, input) in &self.files {
            if input.placeholder_metadata.len() != 0
                || !dependency_same_file(
                    &input.placeholder_metadata,
                    &input.placeholder.metadata()?,
                )
                || !dependency_same_file(
                    &input.placeholder_metadata,
                    &std::fs::symlink_metadata(self.backing.join(name))?,
                )
                || std::fs::canonicalize(&input.retained_path)? != input.retained_path
                || !dependency_same_file(&input.retained_metadata, &input.retained.metadata()?)
                || !dependency_same_file(
                    &input.retained_metadata,
                    &std::fs::symlink_metadata(&input.retained_path)?,
                )
            {
                return Err(refuse());
            }
        }
        Ok(())
    }
}

impl SourceOwner {
    /// Exact file inventory of this owned upload. Execution validates native
    /// lookup against these declared members as well as the sealed bytes; a
    /// metadata-only compiler need not open a requested static archive itself.
    pub(crate) fn manifest(&self) -> &SourceManifest {
        self.receiver.manifest()
    }

    /// The transferred, verified package root for original-path dependency
    /// execution. Every other member must belong to an explicitly declared
    /// retained artifact or generated root; wire paths never select arbitrary
    /// host backings.
    pub(crate) fn dependency_root(
        &self,
        request_id: u64,
        context: &rabs_sandbox::dependency_context::DependencyExecContext,
    ) -> io::Result<std::path::PathBuf> {
        let refuse = |message: &str| io::Error::new(io::ErrorKind::InvalidData, message);
        if !self.execution_owned {
            self.within_budget().map_err(io::Error::other)?;
        }
        if self.source_failed || request_id != self.request_id || self.cargo_home.is_some() {
            return Err(refuse(
                "dependency source owner is not the admitted plain source tree",
            ));
        }
        let bundle = self
            .receiver
            .sealed_root()
            .ok_or_else(|| refuse("dependency execution source is not completely verified"))?;
        let mut package_present = false;
        let mut generated_present = false;
        let mut native_present = vec![false; context.native_roots().len()];
        let mut artifact_present = vec![false; context.artifact_roots().len()];
        for file in self.receiver.manifest().files() {
            if let Some(relative) = file.path.strip_prefix("package/") {
                if relative.is_empty() {
                    return Err(refuse("dependency package member has no relative path"));
                }
                if context.workspace_execution_only() {
                    let directories = context.source_directories();
                    if directories
                        .binary_search_by(|path| path.as_str().cmp(relative))
                        .is_ok()
                        || relative.match_indices('/').any(|(offset, _)| {
                            directories
                                .binary_search_by(|path| path.as_str().cmp(&relative[..offset]))
                                .is_err()
                        })
                    {
                        return Err(refuse(
                            "workspace file conflicts with its complete directory inventory",
                        ));
                    }
                }
                package_present = true;
                continue;
            }
            if let Some(relative) = file.path.strip_prefix("generated/") {
                if relative.is_empty() || context.generated_root().is_none() {
                    return Err(refuse("dependency generated member is not declared"));
                }
                let directories = context.generated_directories();
                if directories
                    .binary_search_by(|path| path.as_str().cmp(relative))
                    .is_ok()
                    || relative.match_indices('/').any(|(offset, _)| {
                        directories
                            .binary_search_by(|path| path.as_str().cmp(&relative[..offset]))
                            .is_err()
                    })
                {
                    return Err(refuse(
                        "generated file conflicts with its complete directory inventory",
                    ));
                }
                generated_present = true;
                continue;
            }
            let mut native_member = false;
            for (index, root) in context.native_roots().iter().enumerate() {
                let Some(relative) = file
                    .path
                    .strip_prefix(&root.prefix)
                    .and_then(|suffix| suffix.strip_prefix('/'))
                else {
                    continue;
                };
                if relative.is_empty()
                    || root
                        .directories
                        .binary_search_by(|path| path.as_str().cmp(relative))
                        .is_ok()
                    || relative.match_indices('/').any(|(offset, _)| {
                        root.directories
                            .binary_search_by(|path| path.as_str().cmp(&relative[..offset]))
                            .is_err()
                    })
                {
                    return Err(refuse(
                        "native file conflicts with its complete directory inventory",
                    ));
                }
                native_present[index] = true;
                native_member = true;
                break;
            }
            if native_member {
                continue;
            }
            let mut declared = false;
            for (index, root) in context.artifact_roots().iter().enumerate() {
                let Some(name) = file
                    .path
                    .strip_prefix(root.prefix.as_str())
                    .and_then(|suffix| suffix.strip_prefix('/'))
                else {
                    continue;
                };
                if name.is_empty()
                    || name.contains('/')
                    || !name.starts_with("lib")
                    || !(name.ends_with(".rmeta") || name.ends_with(".rlib"))
                    || file.executable
                {
                    return Err(refuse(
                        "dependency bundle contains an unsupported artifact member",
                    ));
                }
                artifact_present[index] = true;
                declared = true;
                break;
            }
            if !declared {
                return Err(refuse("dependency bundle contains an unmapped member"));
            }
        }
        if !package_present || artifact_present.iter().any(|present| !present) {
            return Err(refuse("dependency bundle is missing a declared input root"));
        }
        let package = bundle.join("package");
        for root in std::iter::once(package.clone())
            .chain(
                context
                    .artifact_roots()
                    .iter()
                    .map(|root| bundle.join(&root.prefix)),
            )
            .chain(generated_present.then(|| bundle.join("generated")))
            .chain(
                context
                    .native_roots()
                    .iter()
                    .zip(&native_present)
                    .filter(|(_, present)| **present)
                    .map(|(root, _)| bundle.join(&root.prefix)),
            )
        {
            if !std::fs::symlink_metadata(root)?.is_dir() {
                return Err(refuse(
                    "dependency bundle root is not a retained real directory",
                ));
            }
        }
        if !generated_present {
            match std::fs::symlink_metadata(bundle.join("generated")) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => return Err(refuse("undeclared generated tree in sealed bundle")),
            }
        }
        for (root, present) in context.native_roots().iter().zip(native_present) {
            if !present {
                match std::fs::symlink_metadata(bundle.join(&root.prefix)) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                    Ok(_) => return Err(refuse("undeclared native tree in sealed bundle")),
                }
            }
        }
        Ok(package)
    }

    /// Prepare the complete generated tree and retain its identity through
    /// execution. Every tree receives a private backing beside the sealed
    /// bundle so explicit empty directories never change SourceReceiver's
    /// file-only inventory. Files are bounded copies, never writable aliases
    /// of a transfer or cache inode.
    pub(crate) fn prepare_dependency_generated(
        &self,
        request_id: u64,
        context: &rabs_sandbox::dependency_context::DependencyExecContext,
        spec: &mut rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
    ) -> io::Result<Option<DependencyGeneratedInputs>> {
        self.prepare_dependency_tree(request_id, context, spec, false)
    }

    /// Reconstruct the complete selected workspace independently of the sealed
    /// file-only transfer. Empty directories and sibling packages are preserved;
    /// no compiler write can alias a retained transfer or reusable cache inode.
    pub(crate) fn prepare_dependency_source(
        &self,
        request_id: u64,
        context: &rabs_sandbox::dependency_context::DependencyExecContext,
        spec: &mut rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
    ) -> io::Result<Option<DependencyGeneratedInputs>> {
        if !context.workspace_execution_only() {
            return Ok(None);
        }
        self.prepare_dependency_tree(request_id, context, spec, true)
    }

    /// Give every additional native tree a private read-only backing. Empty
    /// trees still preserve their complete declared directory topology, and no
    /// copy aliases the retained source upload or a reusable cache inode.
    pub(crate) fn prepare_dependency_native(
        &self,
        request_id: u64,
        context: &rabs_sandbox::dependency_context::DependencyExecContext,
        spec: &mut rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
    ) -> io::Result<Vec<DependencyGeneratedInputs>> {
        let package = self.dependency_root(request_id, context)?;
        let mut inputs = Vec::with_capacity(context.native_roots().len());
        for (index, root) in context.native_roots().iter().enumerate() {
            inputs.push(
                self.prepare_dependency_tree_at(
                    &package,
                    spec,
                    &root.path,
                    &root.directories,
                    &format!("{}/", root.prefix),
                    self._directory
                        .path()
                        .join(format!("native-inputs-{index:04}")),
                )?,
            );
        }
        Ok(inputs)
    }

    fn prepare_dependency_tree(
        &self,
        request_id: u64,
        context: &rabs_sandbox::dependency_context::DependencyExecContext,
        spec: &mut rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
        workspace: bool,
    ) -> io::Result<Option<DependencyGeneratedInputs>> {
        let package = self.dependency_root(request_id, context)?;
        let (visible, directories, prefix, backing) = if workspace {
            (
                context.source_root(),
                context.source_directories(),
                "package/",
                self._directory.path().join("workspace-inputs/package"),
            )
        } else {
            let Some(visible) = context.generated_root() else {
                return Ok(None);
            };
            (
                visible,
                context.generated_directories(),
                "generated/",
                self._directory.path().join("generated-inputs"),
            )
        };
        if workspace {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(self._directory.path().join("workspace-inputs"))?;
        }
        self.prepare_dependency_tree_at(&package, spec, visible, directories, prefix, backing)
            .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_dependency_tree_at(
        &self,
        package: &std::path::Path,
        spec: &mut rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
        visible: &str,
        directories: &[String],
        prefix: &str,
        backing: std::path::PathBuf,
    ) -> io::Result<DependencyGeneratedInputs> {
        use std::io::Read;

        let bundle = package
            .parent()
            .ok_or_else(|| io::Error::other("missing dependency bundle"))?;
        let mut bindings = spec
            .ro_binds
            .iter_mut()
            .filter(|bind| bind.visible == std::path::Path::new(visible));
        let binding = bindings
            .next()
            .ok_or_else(|| io::Error::other("missing retained input read-only mount"))?;
        if bindings.next().is_some() || binding.backing != bundle.join(prefix.trim_end_matches('/'))
        {
            return Err(io::Error::other(
                "input mount differs from its declared bundle",
            ));
        }
        let files: Vec<_> = self
            .receiver
            .manifest()
            .files()
            .iter()
            .filter(|file| file.path.starts_with(prefix))
            .collect();
        // SourceReceiver creates only file parents. Hold that exact original
        // tree while copying; additional generated directories belong solely
        // to the request-bound execution context and its private backing.
        let source_guard = if files.is_empty() {
            None
        } else {
            let mut parents = std::collections::BTreeSet::new();
            for file in &files {
                let relative = file.path.strip_prefix(prefix).unwrap();
                for (offset, _) in relative.match_indices('/') {
                    parents.insert(relative[..offset].to_owned());
                }
            }
            Some(DependencyGeneratedInputs::capture(
                bundle.join(prefix.trim_end_matches('/')),
                &files,
                &parents.into_iter().collect::<Vec<_>>(),
                prefix,
            )?)
        };
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&backing)?;
        for directory in directories {
            builder.create(backing.join(directory))?;
        }
        for expected in &files {
            let relative = expected.path.strip_prefix(prefix).unwrap();
            let source = rabs_sandbox::regular_input::open(&bundle.join(&expected.path))?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut destination = options.open(backing.join(relative))?;
            if std::io::copy(&mut source.take(expected.len + 1), &mut destination)? != expected.len
            {
                return Err(io::Error::other(
                    "retained input changed length during preparation",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                destination.set_permissions(std::fs::Permissions::from_mode(
                    if expected.executable { 0o555 } else { 0o444 },
                ))?;
            }
        }
        if let Some(source_guard) = source_guard {
            source_guard.verify()?;
        }
        let guard = DependencyGeneratedInputs::capture(backing, &files, directories, prefix)?;
        binding.backing = guard.backing.clone();
        Ok(guard)
    }

    /// Install only this sealed bundle's shared output inputs. Mountpoints are
    /// exclusively created in the worker-owned output root; an existing output,
    /// directory, symlink or earlier placeholder is a collision, never reused.
    /// The returned guard must outlive execution, descendant drain and capture.
    pub(crate) fn prepare_dependency_output(
        &self,
        request_id: u64,
        context: &rabs_sandbox::dependency_context::DependencyExecContext,
        spec: &mut rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
    ) -> io::Result<DependencyOutputInputs> {
        use rabs_sandbox::canonical_namespace::Bind;
        use std::io::Read;
        use std::path::Path;

        let refuse = |message: &str| io::Error::new(io::ErrorKind::InvalidData, message);
        let package = self.dependency_root(request_id, context)?;
        let mut output = spec
            .rw_binds
            .iter()
            .filter(|bind| bind.visible == Path::new(context.out_dir()));
        let backing = output
            .next()
            .ok_or_else(|| refuse("dependency output lacks its writable mount"))?
            .backing
            .clone();
        if output.next().is_some() {
            return Err(refuse("dependency output has duplicate writable mounts"));
        }
        let mut inputs = DependencyOutputInputs::new(&backing)?;
        let Some(shared) = context
            .artifact_roots()
            .iter()
            .find(|root| root.path == context.out_dir())
        else {
            return Ok(inputs);
        };
        if spec
            .ro_binds
            .iter()
            .any(|bind| bind.visible.starts_with(context.out_dir()))
        {
            return Err(refuse(
                "dependency output already has read-only child mounts",
            ));
        }
        let bundle = package
            .parent()
            .ok_or_else(|| refuse("dependency bundle parent is missing"))?;
        for expected in self.receiver.manifest().files() {
            let Some(name) = expected
                .path
                .strip_prefix(shared.prefix.as_str())
                .and_then(|suffix| suffix.strip_prefix('/'))
            else {
                continue;
            };
            let retained_path = bundle.join(&expected.path);
            if std::fs::canonicalize(&retained_path)? != retained_path {
                return Err(refuse("retained dependency input has a filesystem alias"));
            }
            let mut retained = rabs_sandbox::regular_input::open(&retained_path)?;
            let retained_metadata = retained.metadata()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if retained_metadata.permissions().mode() & 0o111 != 0 {
                    return Err(refuse(
                        "retained dependency input became executable after its seal",
                    ));
                }
            }
            if retained_metadata.len() != expected.len
                || !dependency_same_file(
                    &retained_metadata,
                    &std::fs::symlink_metadata(&retained_path)?,
                )
            {
                return Err(refuse(
                    "retained dependency input differs from its sealed member",
                ));
            }
            let mut hasher = Sha256::new();
            let mut remaining = expected.len;
            let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
            while remaining != 0 {
                let count = usize::try_from(remaining.min(buffer.len() as u64))
                    .map_err(|_| refuse("retained dependency input exceeds a chunk"))?;
                retained.read_exact(&mut buffer[..count])?;
                hasher.update(&buffer[..count]);
                remaining -= count as u64;
            }
            match retained.read_exact(&mut buffer[..1]) {
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                Err(error) => return Err(error),
                Ok(()) => return Err(refuse("retained dependency input grew after its seal")),
            }
            let digest: [u8; 32] = hasher.finalize().into();
            if digest != expected.sha256
                || !dependency_same_file(&retained_metadata, &retained.metadata()?)
                || !dependency_same_file(
                    &retained_metadata,
                    &std::fs::symlink_metadata(&retained_path)?,
                )
            {
                return Err(refuse("retained dependency bytes changed after their seal"));
            }
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let placeholder = options.open(backing.join(name))?;
            let placeholder_metadata = placeholder.metadata()?;
            if placeholder_metadata.len() != 0
                || !dependency_same_file(
                    &placeholder_metadata,
                    &std::fs::symlink_metadata(backing.join(name))?,
                )
            {
                return Err(refuse(
                    "dependency input placeholder changed during creation",
                ));
            }
            inputs.files.insert(
                name.to_owned(),
                DependencyOutputInput {
                    placeholder,
                    placeholder_metadata,
                    retained_path: retained_path.clone(),
                    retained,
                    retained_metadata,
                },
            );
            spec.ro_binds.push(Bind::new(
                retained_path,
                Path::new(context.out_dir()).join(name),
            ));
        }
        inputs.verify(&backing)?;
        Ok(inputs)
    }

    /// Require the exact sealed package and artifact backings at their declared
    /// read-only aliases, with no writable physical alias into the bundle.
    pub(crate) fn protect_dependency(
        &self,
        request_id: u64,
        context: &rabs_sandbox::dependency_context::DependencyExecContext,
        spec: &rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
    ) -> io::Result<()> {
        use std::path::Path;
        let refuse = |message: &str| io::Error::new(io::ErrorKind::InvalidData, message);
        let root = self.dependency_root(request_id, context)?;
        let source_backing = if context.workspace_execution_only() {
            self._directory.path().join("workspace-inputs/package")
        } else {
            root.clone()
        };
        if !std::fs::symlink_metadata(&source_backing)?.is_dir()
            || std::fs::canonicalize(&source_backing)? != source_backing
        {
            return Err(refuse("source inputs lack their private real directory"));
        }
        let visible = Path::new(context.source_root());
        let overlap =
            |left: &Path, right: &Path| left.starts_with(right) || right.starts_with(left);
        let mut owned = 0;
        for bind in &spec.ro_binds {
            if bind.visible == visible && bind.backing == source_backing {
                owned += 1;
            } else if overlap(&bind.visible, visible) {
                return Err(refuse("mount shadows dependency source"));
            }
        }
        if owned != 1 {
            return Err(refuse(
                "dependency source lacks its retained read-only mount",
            ));
        }
        let bundle = root
            .parent()
            .ok_or_else(|| refuse("dependency bundle parent is missing"))?;
        let generated_backing = if let Some(generated) = context.generated_root() {
            let visible = Path::new(generated);
            let backing = self._directory.path().join("generated-inputs");
            let mut owned = 0;
            for bind in &spec.ro_binds {
                if bind.visible == visible && bind.backing == backing {
                    owned += 1;
                } else if overlap(&bind.visible, visible)
                    && !context.loader_dirs().iter().any(|loader| {
                        bind.visible == Path::new(loader)
                            && visible.starts_with(&bind.visible)
                            && visible != bind.visible
                    })
                {
                    return Err(refuse("mount shadows retained generated inputs"));
                }
            }
            if owned != 1
                || !std::fs::symlink_metadata(&backing)?.is_dir()
                || std::fs::canonicalize(&backing)? != backing
            {
                return Err(refuse(
                    "generated inputs lack their retained read-only mount",
                ));
            }
            Some(backing)
        } else {
            None
        };
        let mut native_backings = Vec::with_capacity(context.native_roots().len());
        for (index, root) in context.native_roots().iter().enumerate() {
            let visible = Path::new(&root.path);
            let backing = self
                ._directory
                .path()
                .join(format!("native-inputs-{index:04}"));
            let mut owned = 0;
            for bind in &spec.ro_binds {
                if bind.visible == visible && bind.backing == backing {
                    owned += 1;
                } else if overlap(&bind.visible, visible)
                    && !context.loader_dirs().iter().any(|loader| {
                        bind.visible == Path::new(loader)
                            && visible.starts_with(&bind.visible)
                            && visible != bind.visible
                    })
                {
                    return Err(refuse("mount shadows retained native inputs"));
                }
            }
            if owned != 1
                || !std::fs::symlink_metadata(&backing)?.is_dir()
                || std::fs::canonicalize(&backing)? != backing
            {
                return Err(refuse("native inputs lack their retained read-only mount"));
            }
            native_backings.push(backing);
        }
        for artifact in context.artifact_roots() {
            let visible = Path::new(&artifact.path);
            if artifact.path == context.out_dir() {
                let expected: std::collections::BTreeMap<_, _> = self
                    .receiver
                    .manifest()
                    .files()
                    .iter()
                    .filter_map(|file| {
                        file.path
                            .strip_prefix(artifact.prefix.as_str())
                            .and_then(|suffix| suffix.strip_prefix('/'))
                            .map(|name| (visible.join(name), bundle.join(&file.path)))
                    })
                    .collect();
                let mut found = std::collections::BTreeSet::new();
                for bind in &spec.ro_binds {
                    if bind.visible.starts_with(visible) {
                        if expected.get(&bind.visible) != Some(&bind.backing)
                            || !found.insert(bind.visible.clone())
                        {
                            return Err(refuse("mount changes the exact shared dependency inputs"));
                        }
                    } else if visible.starts_with(&bind.visible)
                        && !context
                            .loader_dirs()
                            .iter()
                            .any(|loader| bind.visible == Path::new(loader))
                    {
                        return Err(refuse("parent mount shadows shared dependency inputs"));
                    }
                }
                if expected.is_empty() || found.len() != expected.len() {
                    return Err(refuse(
                        "shared dependency inputs lack their exact file mounts",
                    ));
                }
                if spec
                    .rw_binds
                    .iter()
                    .filter(|bind| bind.visible == visible)
                    .count()
                    != 1
                {
                    return Err(refuse(
                        "shared dependency output lacks its single writable root",
                    ));
                }
                continue;
            }
            let backing = bundle.join(&artifact.prefix);
            let mut owned = 0;
            for bind in &spec.ro_binds {
                if bind.visible == visible && bind.backing == backing {
                    owned += 1;
                } else if bind.visible.starts_with(visible) {
                    return Err(refuse("mount shadows retained dependency artifacts"));
                }
            }
            if owned != 1 {
                return Err(refuse(
                    "dependency artifacts lack their retained read-only mount",
                ));
            }
        }
        let canonical_bundle = std::fs::canonicalize(bundle)?;
        for bind in &spec.rw_binds {
            if overlap(&bind.visible, visible)
                || context
                    .generated_root()
                    .is_some_and(|root| overlap(&bind.visible, Path::new(root)))
                || context
                    .native_roots()
                    .iter()
                    .any(|root| overlap(&bind.visible, Path::new(&root.path)))
                || context.artifact_roots().iter().any(|root| {
                    overlap(&bind.visible, Path::new(&root.path))
                        && !(root.path == context.out_dir()
                            && bind.visible == Path::new(context.out_dir()))
                })
                || overlap(&std::fs::canonicalize(&bind.backing)?, &canonical_bundle)
                || overlap(&std::fs::canonicalize(&bind.backing)?, &source_backing)
                || generated_backing.as_ref().is_some_and(|generated| {
                    std::fs::canonicalize(&bind.backing)
                        .map_or(true, |backing| overlap(&backing, generated))
                })
                || native_backings.iter().any(|native| {
                    std::fs::canonicalize(&bind.backing)
                        .map_or(true, |backing| overlap(&backing, native))
                })
            {
                return Err(refuse("writable mount aliases dependency input bundle"));
            }
        }
        Ok(())
    }

    /// Constrain the final namespace to the exact sealed workspace owned by
    /// this admission. File modes alone do not stop a compiler from changing
    /// its own input files or adding undeclared inputs. The workspace becomes
    /// read-only; explicitly imported registry bytes use independent writable
    /// Cargo-home scratch. HOME and declared outputs are unchanged.
    /// This is transport-source isolation, not action-key provenance.
    pub(crate) fn protect_workspace(
        &self,
        request_id: u64,
        spec: &mut rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
    ) -> io::Result<()> {
        use std::path::Path;
        let refuse = |message: &str| io::Error::new(io::ErrorKind::InvalidData, message);
        // A validated handoff ends the upload phase. Toolchain acquisition
        // before this mount check belongs to the execution timeout and lease;
        // it must not consume a second, already-retired upload budget.
        if !self.execution_owned {
            self.within_budget().map_err(io::Error::other)?;
        }
        if self.source_failed || request_id != self.request_id {
            return Err(refuse("source owner does not match execution admission"));
        }
        let root = self.workspace_root()?;
        let workspace = Path::new(rabs_sandbox::layout::WORKSPACE);
        let index = spec
            .rw_binds
            .iter()
            .position(|bind| bind.visible == workspace)
            .ok_or_else(|| refuse("execution lacks its owned workspace mount"))?;
        if spec.rw_binds[index].backing != root {
            return Err(refuse(
                "workspace mount differs from the sealed source owner",
            ));
        }
        let overlaps = |path: &Path| path.starts_with(workspace) || workspace.starts_with(path);
        if spec.ro_binds.iter().any(|bind| overlaps(&bind.visible)) {
            return Err(refuse("another mount shadows the owned workspace"));
        }
        for (other, bind) in spec.rw_binds.iter().enumerate() {
            if other == index {
                continue;
            }
            if overlaps(&bind.visible) {
                return Err(refuse("writable mount shadows the owned workspace"));
            }
            // Resolve host aliases before comparing. A read-only workspace
            // must not remain writable through HOME or another output mount.
            let backing = std::fs::canonicalize(&bind.backing)?;
            if backing.starts_with(root) || root.starts_with(&backing) {
                return Err(refuse("writable mount aliases the owned source tree"));
            }
        }
        // Build the whole change privately. Failure while validating the Cargo
        // home must not leave a partially modified source/runtime namespace.
        let mut prepared = spec.clone();
        let source = prepared.rw_binds.remove(index);
        prepared.ro_binds.push(source);
        if self.cargo_home.is_some() {
            self.prepared_cargo_home
                .as_ref()
                .ok_or_else(|| refuse("Cargo home preparation is incomplete"))?
                .apply_to(&mut prepared)?;
        }
        if !self.execution_owned {
            self.within_budget().map_err(io::Error::other)?;
        }
        *spec = prepared;
        Ok(())
    }

    fn within_budget(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline {
            return Err(invalid("source upload deadline exceeded"));
        }
        Ok(())
    }

    /// The exact negotiated compiler-visible tree. The sealed transfer tree
    /// remains retained but isolated cache transport never exposes its prefix
    /// through the execution request's physical workspace backing.
    fn workspace_root(&self) -> io::Result<&std::path::Path> {
        let source = self
            .receiver
            .sealed_root()
            .ok_or_else(|| io::Error::other("execution source is not completely verified"))?;
        if self.cargo_home.is_some() {
            let prepared = self.prepared_cargo_home.as_ref().ok_or_else(|| {
                io::Error::other("execution Cargo home is not completely prepared")
            })?;
            Ok(prepared.projected_workspace().unwrap_or(source))
        } else {
            Ok(source)
        }
    }

    /// The verified runtime workspace and complete transport identity for an
    /// optional worker-local Cargo target clone. This conveys no action-cache
    /// authority and never grants a caller-selected path access to the pool.
    pub(crate) fn target_cache_inputs(
        &self,
        request_id: u64,
    ) -> io::Result<crate::target_cache::WorkspaceInputs> {
        if self.source_failed || request_id != self.request_id || !self.execution_owned {
            return Err(io::Error::other(
                "target state requires an admitted source owner",
            ));
        }
        let root = self.workspace_root()?.to_path_buf();
        let source = self.receiver.manifest();
        if self
            .cargo_home
            .as_ref()
            .is_some_and(|home| home.source_digest() != source.digest())
        {
            return Err(io::Error::other(
                "target state Cargo home differs from the admitted source",
            ));
        }
        let manifest = self
            .cargo_home
            .as_ref()
            .and_then(CargoHomeProjection::workspace_manifest)
            .unwrap_or(source)
            .clone();
        Ok(crate::target_cache::WorkspaceInputs {
            root,
            manifest,
            full_source_digest: source.digest(),
            projection: self.cargo_home.clone().map(Arc::new),
            runtime_owner: None,
        })
    }

    /// Every readiness response uses the same post-I/O deadline frontier.
    /// Cached-file reuse and verification cannot renew the original budget.
    fn ready(&self) -> Result<Value, String> {
        self.within_budget()?;
        let mut reply = json!({"kind":"source-ready", "request_id":self.request_id,
            "manifest_sha256":hex(&self.receiver.manifest().digest()),
            "sealed":self.receiver.sealed_root().is_some() && !self.source_failed
                && (self.cargo_home.is_none() || self.prepared_cargo_home.is_some())});
        if let Some(home) = &self.cargo_home {
            // Exact echo is the extension's support negotiation. Old workers
            // omit it, letting senders refuse BEFORE any cache bytes are sent.
            reply["cargo_home"] = json!({"version":home.version(), "prefix":home.prefix()});
        }
        if self.allow_cached_files {
            // This is the frozen initial missing set, not a new cache lookup on
            // every retry. Reused bytes already belong to this private receiver.
            reply["missing_files"] = json!(self.missing_files);
            reply["source_reused_bytes"] = json!(self.reused_bytes);
            reply["cache_write_error"] = json!(self.cache_write_error);
        }
        Ok(reply)
    }
}

#[derive(Default)]
pub struct SourceTransferState {
    pending: Option<SourceOwner>,
    input_budget: Option<Duration>,
    cache: Option<SourceCache>,
    // Upload work observes this flag without a source-state lock. It is not
    // retained by an execution-owned SourceOwner after the admission handoff.
    cancelled: Arc<AtomicBool>,
}

impl SourceTransferState {
    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub(crate) fn with_cache(mut self, cache: Option<SourceCache>) -> Self {
        self.cache = cache;
        self
    }

    /// A selected full-toolchain upload follows the source upload before
    /// execution admission. Both inputs retain one fixed combined budget from
    /// source-begin; progress never renews it. Ordinary source-only sessions
    /// retain the existing five-minute bound.
    pub(crate) fn with_input_budget(input_budget: Duration) -> Self {
        Self {
            input_budget: Some(input_budget),
            ..Self::default()
        }
    }

    /// Handle only source-begin/chunk/seal after explicit session negotiation.
    /// Busy is computed by the execution driver, not asserted by the sender.
    pub fn handle(&mut self, value: &Value, enabled: bool, busy: bool) -> Result<Value, String> {
        if !enabled {
            return Err(invalid("source transfer not negotiated"));
        }
        if busy {
            return Err(invalid("worker-busy-or-result-pending"));
        }
        let cancelled = Arc::clone(&self.cancelled);
        check_cancelled(&cancelled)?;
        let id = value["request_id"]
            .as_u64()
            .ok_or("source request_id must be unsigned")?;
        if value["kind"] == "source-begin" {
            let manifest = parse_manifest(&value["manifest"])?;
            let cargo_home = cargo_home_projection(value, &manifest)?;
            let allow_cached_files = match value.get("allow_cached_files") {
                None => false,
                Some(value) => value
                    .as_bool()
                    .ok_or("allow_cached_files must be boolean")?,
            };
            if let Some(owner) = &self.pending {
                if owner.request_id != id
                    || owner.receiver.manifest() != &manifest
                    || owner.allow_cached_files != allow_cached_files
                    || owner.cargo_home != cargo_home
                {
                    return Err(invalid("another source transfer owns this session"));
                }
                if owner.source_failed {
                    return Err(invalid("execution source verification failed"));
                }
                let reply = owner.ready()?;
                check_cancelled(&cancelled)?;
                return Ok(reply);
            }
            let deadline = Instant::now() + self.input_budget.unwrap_or(UPLOAD_BUDGET);
            let cache = if allow_cached_files {
                self.cache.clone().map(|cache| {
                    cache
                        .before(deadline)
                        .with_cancellation(Arc::clone(&cancelled))
                })
            } else {
                None
            };
            let mut builder = tempfile::Builder::new();
            builder.prefix("rabs-source-");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                builder.permissions(std::fs::Permissions::from_mode(0o700));
            }
            let directory = builder.tempdir().map_err(|error| error.to_string())?;
            let mut receiver =
                SourceReceiver::create(&directory.path().join("workspace"), manifest)
                    .map_err(|error| error.to_string())?;
            let mut missing_files = Vec::new();
            let mut reused_bytes = 0;
            for file in receiver.manifest().files().to_vec() {
                check_cancelled(&cancelled)?;
                if Instant::now() >= deadline {
                    return Err(invalid("source upload deadline exceeded"));
                }
                if file.len == 0 {
                    continue;
                }
                if let Some(snapshot) = cache.as_ref().and_then(|cache| cache.load(&file)) {
                    // Lookup verifies a complete anonymous snapshot before any
                    // receiver write. Large archives use a fixed-size buffer,
                    // and later cache corruption cannot change this snapshot.
                    snapshot
                        .install(&mut receiver)
                        .map_err(|error| error.to_string())?;
                    reused_bytes += file.len;
                } else {
                    missing_files.push(file.path);
                }
            }
            // A cache lookup deliberately treats corrupt/unavailable bytes as
            // misses. Cancellation must not be converted into such a miss or
            // acknowledged as a fresh upload's readiness.
            check_cancelled(&cancelled)?;
            if Instant::now() >= deadline {
                return Err(invalid("source upload deadline exceeded"));
            }
            let owner = SourceOwner {
                receiver,
                _directory: directory,
                request_id: id,
                deadline,
                execution_owned: false,
                allow_cached_files,
                missing_files,
                reused_bytes,
                cache,
                cache_write_error: None,
                source_failed: false,
                cargo_home,
                prepared_cargo_home: None,
            };
            let reply = owner.ready()?;
            check_cancelled(&cancelled)?;
            self.pending = Some(owner);
            return Ok(reply);
        }
        let owner = self
            .pending
            .as_mut()
            .ok_or("no source transfer in this session")?;
        if owner.source_failed {
            return Err(invalid("execution source verification failed"));
        }
        if owner.request_id != id
            || owner.receiver.manifest().digest() != digest(&value["manifest_sha256"])?
        {
            return Err(invalid("source transfer identity mismatch"));
        }
        owner.within_budget()?;
        match value["kind"].as_str() {
            Some("source-chunk") => {
                let path = value["path"]
                    .as_str()
                    .ok_or("source chunk lacks a relative path")?;
                let offset = value["offset"]
                    .as_u64()
                    .ok_or("source chunk offset must be unsigned")?;
                let bytes = decode_hex(
                    value["data_hex"]
                        .as_str()
                        .ok_or("source chunk lacks data")?,
                    MAX_SOURCE_CHUNK,
                )?;
                let next = owner
                    .receiver
                    .write_chunk(path, offset, &bytes, digest(&value["chunk_sha256"])?)
                    .map_err(|error| error.to_string())?;
                // Accepted filesystem writes do not make an expired transfer
                // live again. Do not acknowledge progress after the deadline.
                owner.within_budget()?;
                check_cancelled(&cancelled)?;
                Ok(json!({"kind":"source-chunk-accepted", "request_id":id,
                    "manifest_sha256":hex(&owner.receiver.manifest().digest()),
                    "path":path, "next_offset":next}))
            }
            Some("source-seal") => {
                let deadline = owner.deadline;
                let sealed = owner.receiver.seal_cancellable(|| {
                    cancelled.load(Ordering::Acquire) || Instant::now() >= deadline
                });
                check_cancelled(&cancelled)?;
                sealed.map_err(|error| error.to_string())?;
                owner.within_budget()?;
                // Seed once, before execution owns the source. Optional cache
                // storage failure is not an execution failure; discovering a
                // changed source is, and remains fenced on subsequent frames.
                if let Some(cache) = owner.cache.take() {
                    match cache.remember(&owner.receiver) {
                        Ok(_) => {}
                        Err(cache::RememberError::Cache(error)) => {
                            owner.cache_write_error = Some(error.to_string())
                        }
                        Err(cache::RememberError::Source(error)) => {
                            owner.source_failed = true;
                            return Err(format!("sealed source verification failed: {error}"));
                        }
                    }
                }
                check_cancelled(&cancelled)?;
                owner.within_budget()?;
                if let Some(projection) = &owner.cargo_home
                    && owner.prepared_cargo_home.is_none()
                {
                    let deadline = owner.deadline;
                    match projection.prepare(
                        &owner.receiver,
                        &owner._directory.path().join("cargo-home-runtime"),
                        || cancelled.load(Ordering::Acquire) || Instant::now() >= deadline,
                    ) {
                        Ok(prepared) => owner.prepared_cargo_home = Some(prepared),
                        Err(error) => {
                            owner.source_failed = true;
                            return Err(format!("Cargo home preparation failed: {error}"));
                        }
                    }
                }
                let reply = owner.ready()?;
                check_cancelled(&cancelled)?;
                Ok(reply)
            }
            _ => Err(invalid("unknown source operation")),
        }
    }

    /// Resolve the private physical path WITHOUT changing the raw request. The
    /// caller does this before journal admission, then transfers ownership only
    /// after admission succeeds. Host paths never enter a source fingerprint.
    pub fn prepared_path(&self, request: &Value, enabled: bool) -> Result<Option<String>, String> {
        let Some(manifest) = request_manifest(request)? else {
            return Ok(None);
        };
        check_cancelled(&self.cancelled)?;
        if !enabled {
            return Err(invalid("source transfer not negotiated"));
        }
        let owner = self
            .pending
            .as_ref()
            .ok_or("execution source has not been uploaded")?;
        if owner.source_failed {
            return Err(invalid("execution source verification failed"));
        }
        if request["request_id"].as_u64() != Some(owner.request_id)
            || owner.receiver.manifest() != &manifest
            || cargo_home_projection(request, &manifest)? != owner.cargo_home
        {
            return Err(invalid(
                "execution differs from its uploaded source identity",
            ));
        }
        if owner.cargo_home.is_some() && owner.prepared_cargo_home.is_none() {
            return Err(invalid("execution Cargo home is not completely prepared"));
        }
        owner.within_budget()?;
        let path = owner.workspace_root().map_err(|error| error.to_string())?;
        path.to_str()
            .map(|path| Some(path.to_owned()))
            .ok_or_else(|| invalid("worker staging path is not UTF-8"))
    }

    /// Call only after prepared_path and successful durable admission, on the
    /// same session owner. Keeping this separate prevents an admission refusal
    /// from accidentally losing the already-verified input snapshot.
    pub fn take_prepared(&mut self, request: &Value) -> io::Result<Option<SourceOwner>> {
        if request_manifest(request)
            .map_err(io::Error::other)?
            .is_none()
        {
            return Ok(None);
        }
        self.prepared_path(request, true)
            .map_err(io::Error::other)?;
        Ok(self.pending.take().map(|mut owner| {
            // Only the same fully verified, unexpired owner can make this
            // transition. There is no public setter or alternate host path.
            // Upload cache controls belong to the retired transfer phase,
            // even if a future preparation path retains one after sealing.
            owner.cache = None;
            owner.execution_owned = true;
            owner
        }))
    }
}

#[cfg(all(test, unix))]
mod tests {
    mod cargo_home_tests;

    use super::*;
    use sha2::{Digest, Sha256};

    fn manifest() -> Value {
        let bytes = b"source\0\xff";
        let file = SourceFile {
            path: "src/lib.rs".to_owned(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        };
        let manifest = SourceManifest::new(vec![file]).unwrap();
        json!({"manifest_sha256":hex(&manifest.digest()), "files":[{
            "path":"src/lib.rs", "bytes":bytes.len(), "sha256":hex(&Sha256::digest(bytes)), "executable":false,
        }]})
    }

    #[test]
    fn source_negotiation_and_identity_precede_execution_ownership() {
        let manifest = manifest();
        let request = json!({"kind":"canonical-exec", "request_id":7, "source_manifest":manifest});
        let begin = json!({"kind":"source-begin", "request_id":7, "manifest":manifest});
        let mut state = SourceTransferState::default();
        assert!(state.handle(&begin, false, false).is_err());
        assert!(state.handle(&begin, true, true).is_err());
        assert!(state.prepared_path(&request, true).is_err());
        assert_eq!(state.handle(&begin, true, false).unwrap()["sealed"], false);
        assert!(state.prepared_path(&request, true).is_err());
        let identity = manifest["manifest_sha256"].clone();
        let chunk = json!({"kind":"source-chunk", "request_id":7, "manifest_sha256":identity,
            "path":"src/lib.rs", "offset":0, "data_hex":hex(b"source\0\xff"),
            "chunk_sha256":hex(&Sha256::digest(b"source\0\xff"))});
        let mut foreign = chunk.clone();
        foreign["request_id"] = json!(8);
        assert!(state.handle(&foreign, true, false).is_err());
        state.handle(&chunk, true, false).unwrap();
        state
            .handle(
                &json!({"kind":"source-seal", "request_id":7, "manifest_sha256":identity}),
                true,
                false,
            )
            .unwrap();
        assert!(state.prepared_path(&request, false).is_err());
        let path = state.prepared_path(&request, true).unwrap().unwrap();
        assert_eq!(
            std::fs::read(std::path::Path::new(&path).join("src/lib.rs")).unwrap(),
            b"source\0\xff"
        );
        let mut mixed = request.clone();
        mixed["workspace_backing"] = json!("/untrusted");
        assert!(state.prepared_path(&mixed, true).is_err());
        let owner = state.take_prepared(&request).unwrap().unwrap();
        assert!(state.prepared_path(&request, true).is_err());
        assert!(std::path::Path::new(&path).exists());
        drop(owner);
        assert!(!std::path::Path::new(&path).exists());
    }

    fn projection(files: &[(&str, &[u8], bool)]) -> Value {
        let manifest = SourceManifest::new(
            files
                .iter()
                .map(|(path, bytes, executable)| SourceFile {
                    path: (*path).into(),
                    len: bytes.len() as u64,
                    sha256: Sha256::digest(bytes).into(),
                    executable: *executable,
                })
                .collect(),
        )
        .unwrap();
        json!({"manifest_sha256":hex(&manifest.digest()), "files":manifest.files().iter().map(|file| {
            json!({"path":file.path, "bytes":file.len, "sha256":hex(&file.sha256), "executable":file.executable})
        }).collect::<Vec<_>>()})
    }

    fn cached_state(parent: &std::path::Path) -> SourceTransferState {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        SourceTransferState {
            cache: Some(SourceCache::open(parent, DEFAULT_SOURCE_CACHE_BYTES).unwrap()),
            ..SourceTransferState::default()
        }
    }

    fn begin(manifest: &Value, id: u64) -> Value {
        json!({"kind":"source-begin", "request_id":id, "manifest":manifest, "allow_cached_files":true})
    }

    fn seal(manifest: &Value, id: u64) -> Value {
        json!({"kind":"source-seal", "request_id":id, "manifest_sha256":manifest["manifest_sha256"]})
    }

    fn upload(
        state: &mut SourceTransferState,
        manifest: &Value,
        id: u64,
        path: &str,
        bytes: &[u8],
    ) {
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            state
                .handle(
                    &json!({"kind":"source-chunk", "request_id":id,
                "manifest_sha256":manifest["manifest_sha256"], "path":path,
                "offset":index * MAX_SOURCE_CHUNK, "data_hex":hex(chunk),
                "chunk_sha256":hex(&Sha256::digest(chunk))}),
                    true,
                    false,
                )
                .unwrap();
        }
    }

    fn uploaded_dependency_bundle(files: &[(&str, &[u8], bool)]) -> SourceOwner {
        let manifest = projection(files);
        let request = json!({
            "kind":"canonical-exec", "request_id":91, "source_manifest":manifest,
        });
        let mut state = SourceTransferState::default();
        state
            .handle(
                &json!({"kind":"source-begin", "request_id":91, "manifest":manifest}),
                true,
                false,
            )
            .unwrap();
        for (path, bytes, _) in files {
            upload(&mut state, &manifest, 91, path, bytes);
        }
        state.handle(&seal(&manifest, 91), true, false).unwrap();
        state.take_prepared(&request).unwrap().unwrap()
    }

    fn workspace_dependency_context(
        files: &[(&str, &[u8], bool)],
        source_directories: Vec<String>,
        generated_directories: Vec<String>,
    ) -> rabs_sandbox::dependency_context::DependencyExecContext {
        use rabs_sandbox::dependency_context::{
            DependencyArtifactRoot, DependencyExecContext, DependencyExecutionMode,
        };
        let output = "/__rabs/out/cargo/debug/deps";
        let generated = files
            .iter()
            .any(|(path, _, _)| path.starts_with("generated/"))
            .then_some("/__rabs/out/cargo/debug/build/member-123/out");
        let artifacts = files
            .iter()
            .any(|(path, _, _)| path.starts_with("dependencies/0000/"))
            .then(|| DependencyArtifactRoot {
                path: output.into(),
                prefix: "dependencies/0000".into(),
            })
            .into_iter()
            .collect();
        let mut env = vec![
            ("HOME".into(), "/__rabs/home".into()),
            ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
            (
                "CARGO_MANIFEST_DIR".into(),
                "/__rabs/workspace/member".into(),
            ),
            ("CARGO_PKG_NAME".into(), "member".into()),
            ("CARGO_PRIMARY_PACKAGE".into(), "1".into()),
        ];
        if let Some(root) = generated {
            env.push(("OUT_DIR".into(), root.into()));
        }
        DependencyExecContext::new_canonical_workspace_execution(
            DependencyExecutionMode::Metadata,
            "/__rabs/workspace/member".into(),
            output.into(),
            vec![output.into()],
            Vec::new(),
            artifacts,
            generated.map(str::to_owned),
            source_directories,
            generated_directories,
            env,
            [7; 32],
        )
        .unwrap()
    }

    fn workspace_source_directories() -> Vec<String> {
        ["member", "member/src", "shared", "shared/empty"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn workspace_dependency_fixture(
        files: &[(&str, &[u8], bool)],
        generated_directories: Vec<String>,
    ) -> (
        SourceOwner,
        rabs_sandbox::dependency_context::DependencyExecContext,
        rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
        tempfile::TempDir,
    ) {
        let owner = uploaded_dependency_bundle(files);
        let context = workspace_dependency_context(
            files,
            workspace_source_directories(),
            generated_directories,
        );
        let runtime = tempfile::tempdir().unwrap();
        for name in ["toolchain", "output", "empty", "home"] {
            std::fs::create_dir(runtime.path().join(name)).unwrap();
        }
        context
            .prepare_empty_backings(&runtime.path().join("empty"))
            .unwrap();
        let package = owner.dependency_root(91, &context).unwrap();
        let spec = context
            .namespace(
                &package,
                &runtime.path().join("toolchain"),
                &runtime.path().join("output"),
                &runtime.path().join("empty"),
                &runtime.path().join("home"),
            )
            .unwrap();
        (owner, context, spec, runtime)
    }

    /// Independently hash and retain the complete original transfer, including
    /// dependency artifacts. SourceReceiver's sealed flag alone is not a second
    /// content check; this guard also detects newly introduced empty directories.
    fn retained_transfer_guard(owner: &SourceOwner) -> DependencyGeneratedInputs {
        let files = owner.receiver.manifest().files().iter().collect::<Vec<_>>();
        let mut directories = std::collections::BTreeSet::new();
        for file in &files {
            for (offset, _) in file.path.match_indices('/') {
                directories.insert(file.path[..offset].to_owned());
            }
        }
        DependencyGeneratedInputs::capture(
            owner.receiver.sealed_root().unwrap().to_owned(),
            &files,
            &directories.into_iter().collect::<Vec<_>>(),
            "",
        )
        .unwrap()
    }

    #[test]
    fn workspace_projection_runs_real_member_rustc_with_sibling_and_generated_directory_inputs() {
        use std::os::unix::fs::MetadataExt;
        let files = [
            (
                "package/member/src/lib.rs",
                br#"
                pub const PRIMARY: &str = env!("CARGO_PRIMARY_PACKAGE");
                pub const SHARED: &str = include_str!("../../shared/empty/../value.txt");
                include!(concat!(env!("OUT_DIR"), "/nested/empty/../constants.rs"));
                pub fn value() -> (&'static str, &'static str) { (SHARED, GENERATED) }
            "#
                .as_slice(),
                false,
            ),
            (
                "package/shared/value.txt",
                b"captured sibling value".as_slice(),
                false,
            ),
            (
                "generated/nested/constants.rs",
                b"pub const GENERATED:&str=\"captured generated value\";".as_slice(),
                false,
            ),
            (
                "dependencies/0000/libleaf.rmeta",
                b"unchanged retained dependency candidate".as_slice(),
                false,
            ),
        ];
        let (owner, context, mut spec, runtime) =
            workspace_dependency_fixture(&files, vec!["nested".into(), "nested/empty".into()]);
        let original = retained_transfer_guard(&owner);
        let manifest_before = owner.receiver.manifest().clone();
        let workspace = owner
            .prepare_dependency_source(91, &context, &mut spec)
            .unwrap()
            .unwrap();
        let generated = owner
            .prepare_dependency_generated(91, &context, &mut spec)
            .unwrap()
            .unwrap();
        let candidates = owner
            .prepare_dependency_output(91, &context, &mut spec)
            .unwrap();
        owner.protect_dependency(91, &context, &spec).unwrap();
        original.verify().unwrap();
        assert_eq!(owner.receiver.manifest(), &manifest_before);
        assert!(!original.backing.join("package/shared/empty").exists());
        assert!(!original.backing.join("generated/nested/empty").exists());
        assert!(workspace.backing.join("shared/empty").is_dir());
        assert!(generated.backing.join("nested/empty").is_dir());
        assert!(!workspace.backing.join("dependencies").exists());
        for relative in ["member/src/lib.rs", "shared/value.txt"] {
            let sealed =
                std::fs::metadata(original.backing.join("package").join(relative)).unwrap();
            let copied = std::fs::metadata(workspace.backing.join(relative)).unwrap();
            assert_ne!((sealed.dev(), sealed.ino()), (copied.dev(), copied.ino()));
            assert_eq!(copied.nlink(), 1);
        }
        let compile = |emit: &str| {
            std::process::Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                .args([
                    "--crate-name=workspace_tree",
                    "--crate-type=lib",
                    "--edition=2021",
                    "--error-format=json",
                    "--json=artifacts",
                    "--emit",
                    emit,
                    "--out-dir",
                ])
                .arg(runtime.path().join("output"))
                .arg("src/lib.rs")
                .current_dir(workspace.backing.join("member"))
                .env("CARGO_PRIMARY_PACKAGE", "1")
                .env("OUT_DIR", &generated.backing)
                .output()
                .expect("run the actual Rust compiler against the retained workspace")
        };
        for emit in ["dep-info,metadata", "dep-info,metadata,link"] {
            let result = compile(emit);
            assert!(
                result.status.success(),
                "rustc could not read the complete workspace/generated trees: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(
                runtime
                    .path()
                    .join("output/libworkspace_tree.rmeta")
                    .is_file()
            );
            if emit.contains("link") {
                assert!(
                    runtime
                        .path()
                        .join("output/libworkspace_tree.rlib")
                        .is_file()
                );
            }
            workspace.verify().unwrap();
            generated.verify().unwrap();
            original.verify().unwrap();
            candidates.verify(&runtime.path().join("output")).unwrap();
        }
        std::fs::rename(
            workspace.backing.join("shared/empty"),
            runtime.path().join("held-empty"),
        )
        .unwrap();
        assert!(
            !compile("dep-info,metadata").status.success(),
            "the actual compiler must fail if the required empty source directory is omitted"
        );
        assert!(workspace.verify().is_err());
        original.verify().unwrap();
        assert_eq!(
            std::fs::read(original.backing.join("dependencies/0000/libleaf.rmeta")).unwrap(),
            files[3].1
        );
    }

    #[test]
    fn workspace_projection_rejects_missing_file_parents_directory_collisions_and_changed_seals() {
        use std::os::unix::fs::PermissionsExt;
        let files = [
            (
                "package/member/src/lib.rs",
                b"retained source".as_slice(),
                false,
            ),
            (
                "package/shared/value.txt",
                b"shared bytes".as_slice(),
                false,
            ),
        ];
        let (owner, _context, spec, _runtime) = workspace_dependency_fixture(&files, Vec::new());
        for directories in [
            vec!["member".into(), "shared".into(), "shared/empty".into()],
            vec![
                "member".into(),
                "member/src".into(),
                "member/src/lib.rs".into(),
                "shared".into(),
                "shared/empty".into(),
            ],
        ] {
            let context = workspace_dependency_context(&files, directories, Vec::new());
            assert!(owner.dependency_root(91, &context).is_err());
            assert!(
                owner
                    .prepare_dependency_source(91, &context, &mut spec.clone())
                    .is_err()
            );
        }
        for changed_membership in [false, true] {
            let (owner, context, mut spec, _runtime) =
                workspace_dependency_fixture(&files, Vec::new());
            let root = owner.dependency_root(91, &context).unwrap();
            if changed_membership {
                std::fs::create_dir(root.join("unobserved-empty-directory")).unwrap();
            } else {
                let source = root.join("member/src/lib.rs");
                std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
                std::fs::write(&source, b"modified source").unwrap();
                std::fs::set_permissions(source, std::fs::Permissions::from_mode(0o444)).unwrap();
            }
            assert!(
                owner
                    .prepare_dependency_source(91, &context, &mut spec)
                    .is_err(),
                "the sealed flag cannot substitute for rechecking original bytes and exact membership"
            );
        }
    }

    #[test]
    fn workspace_projection_guards_exact_membership_replacement_and_writable_aliases() {
        use rabs_sandbox::canonical_namespace::Bind;
        use std::os::unix::fs::{PermissionsExt, symlink};
        let files = [
            (
                "package/member/src/lib.rs",
                b"retained source".as_slice(),
                false,
            ),
            (
                "package/shared/value.txt",
                b"shared bytes".as_slice(),
                false,
            ),
        ];
        for mutation in [
            "bytes",
            "replacement",
            "hardlink",
            "empty-directory",
            "parent-symlink",
            "new-member",
        ] {
            let (owner, context, mut spec, runtime) =
                workspace_dependency_fixture(&files, Vec::new());
            let original = retained_transfer_guard(&owner);
            let guard = owner
                .prepare_dependency_source(91, &context, &mut spec)
                .unwrap()
                .unwrap();
            owner.protect_dependency(91, &context, &spec).unwrap();
            let source = guard.backing.join("member/src/lib.rs");
            match mutation {
                "bytes" => {
                    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                    std::fs::write(source, b"modified source").unwrap();
                }
                "replacement" => {
                    std::fs::rename(&source, runtime.path().join("held-source")).unwrap();
                    std::fs::write(source, files[0].1).unwrap();
                }
                "hardlink" => std::fs::hard_link(source, runtime.path().join("alias")).unwrap(),
                "empty-directory" => {
                    std::fs::rename(
                        guard.backing.join("shared/empty"),
                        runtime.path().join("held-empty"),
                    )
                    .unwrap();
                    std::fs::create_dir(guard.backing.join("shared/empty")).unwrap();
                }
                "parent-symlink" => {
                    let retained = runtime.path().join("held-parent");
                    std::fs::rename(guard.backing.join("member/src"), &retained).unwrap();
                    symlink(retained, guard.backing.join("member/src")).unwrap();
                }
                "new-member" => {
                    std::fs::write(guard.backing.join("unobserved"), b"extra bytes").unwrap()
                }
                _ => unreachable!(),
            }
            assert!(
                guard.verify().is_err(),
                "workspace mutation escaped its guard: {mutation}"
            );
            original.verify().unwrap();
        }
        let (owner, context, mut spec, runtime) = workspace_dependency_fixture(&files, Vec::new());
        let guard = owner
            .prepare_dependency_source(91, &context, &mut spec)
            .unwrap()
            .unwrap();
        let visible = std::path::Path::new(context.source_root());
        let alias = runtime.path().join("workspace-alias");
        symlink(&guard.backing, &alias).unwrap();
        for binding in [
            Bind::new(&guard.backing, "/scratch"),
            Bind::new(&alias, "/scratch"),
            Bind::new(guard.backing.parent().unwrap(), "/scratch"),
            Bind::new(runtime.path().join("output"), visible),
            Bind::new(runtime.path().join("output"), visible.join("member")),
        ] {
            let mut changed = spec.clone();
            changed.rw_binds.push(binding);
            assert!(owner.protect_dependency(91, &context, &changed).is_err());
        }
        let mut redirected = spec.clone();
        redirected
            .ro_binds
            .iter_mut()
            .find(|binding| binding.visible == visible)
            .unwrap()
            .backing = owner.dependency_root(91, &context).unwrap();
        assert!(owner.protect_dependency(91, &context, &redirected).is_err());
        let mut shadowed = spec.clone();
        shadowed.ro_binds.push(Bind::new(
            runtime.path().join("output"),
            visible.join("shared"),
        ));
        assert!(owner.protect_dependency(91, &context, &shadowed).is_err());
        assert!(
            owner
                .prepare_dependency_source(91, &context, &mut spec)
                .is_err(),
            "a prepared source image cannot be silently reconstructed or rebound a second time"
        );
        guard.verify().unwrap();
    }

    fn generated_dependency_fixture(
        files: &[(&str, &[u8], bool)],
    ) -> (
        SourceOwner,
        rabs_sandbox::dependency_context::DependencyExecContext,
        rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
        tempfile::TempDir,
    ) {
        generated_dependency_profile_fixture(files, false)
    }

    fn foreign_native_fixture() -> (
        SourceOwner,
        rabs_sandbox::dependency_context::DependencyExecContext,
        rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
        tempfile::TempDir,
    ) {
        use rabs_sandbox::dependency_context::{
            DependencyExecContext, DependencyExecutionMode, DependencyNativeRoot,
        };
        let owner = uploaded_dependency_bundle(&[
            ("package/src/lib.rs", b"source", false),
            (
                "native/0000/nested/libanswer.a",
                b"retained native archive",
                false,
            ),
        ]);
        let source = "/__rabs/cargo-home/registry/src/pinned/consumer-1.0.0";
        let context = DependencyExecContext::new_canonical_cargo(
            DependencyExecutionMode::Rlib,
            source.into(),
            source.into(),
            "/__rabs/out/cargo/debug/deps".into(),
            Vec::new(),
            vec!["/__rabs/out/cargo/debug".into()],
            Vec::new(),
            vec![
                ("HOME".into(), "/__rabs/home".into()),
                ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
                ("CARGO_MANIFEST_DIR".into(), source.into()),
            ],
            [7; 32],
        )
        .unwrap()
        .with_native_roots(vec![
            DependencyNativeRoot {
                path: "/__rabs/out/cargo/debug/build/a-hash/out".into(),
                prefix: "native/0000".into(),
                directories: vec!["empty".into(), "nested".into()],
            },
            DependencyNativeRoot {
                path: "/__rabs/out/cargo/debug/build/b-hash/out".into(),
                prefix: "native/0001".into(),
                directories: vec!["empty".into(), "empty/child".into()],
            },
        ])
        .unwrap();
        let runtime = tempfile::tempdir().unwrap();
        for name in ["toolchain", "output", "empty", "home"] {
            std::fs::create_dir(runtime.path().join(name)).unwrap();
        }
        context
            .prepare_empty_backings(&runtime.path().join("empty"))
            .unwrap();
        let package = owner.dependency_root(91, &context).unwrap();
        let spec = context
            .namespace(
                &package,
                &runtime.path().join("toolchain"),
                &runtime.path().join("output"),
                &runtime.path().join("empty"),
                &runtime.path().join("home"),
            )
            .unwrap();
        (owner, context, spec, runtime)
    }

    #[test]
    fn propagated_native_inputs_retain_bytes_empty_topology_and_private_ownership() {
        use std::os::unix::fs::MetadataExt;
        let (owner, context, mut spec, _runtime) = foreign_native_fixture();
        assert!(context.generated_root().is_none());
        let inputs = owner
            .prepare_dependency_native(91, &context, &mut spec)
            .unwrap();
        assert_eq!(inputs.len(), 2);
        owner.protect_dependency(91, &context, &spec).unwrap();
        for input in &inputs {
            input.verify().unwrap();
        }
        assert_eq!(
            std::fs::read(inputs[0].backing.join("nested/libanswer.a")).unwrap(),
            b"retained native archive"
        );
        assert!(inputs[0].backing.join("empty").is_dir());
        assert!(inputs[1].backing.join("empty/child").is_dir());
        let sealed = owner.receiver.sealed_root().unwrap();
        assert!(!sealed.join("native/0000/empty").exists());
        assert!(!sealed.join("native/0001").exists());
        let retained = std::fs::metadata(sealed.join("native/0000/nested/libanswer.a")).unwrap();
        let copied = std::fs::metadata(inputs[0].backing.join("nested/libanswer.a")).unwrap();
        assert_ne!(
            (retained.dev(), retained.ino()),
            (copied.dev(), copied.ino())
        );
        let absent = context.clone().with_native_roots(Vec::new()).unwrap();
        assert!(owner.dependency_root(91, &absent).is_err());
        let mut wrong = context.native_roots().to_vec();
        wrong[0].directories = vec!["empty".into()];
        assert!(
            owner
                .dependency_root(91, &context.with_native_roots(wrong).unwrap())
                .is_err()
        );
    }

    #[test]
    fn propagated_native_inputs_reject_shadow_mounts_writable_aliases_and_mutation() {
        use rabs_sandbox::canonical_namespace::Bind;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        let (owner, context, mut spec, runtime) = foreign_native_fixture();
        let inputs = owner
            .prepare_dependency_native(91, &context, &mut spec)
            .unwrap();
        owner.protect_dependency(91, &context, &spec).unwrap();
        let visible = Path::new(&context.native_roots()[0].path);
        let mut missing = spec.clone();
        missing.ro_binds.retain(|bind| bind.visible != visible);
        assert!(owner.protect_dependency(91, &context, &missing).is_err());
        for bind in [
            Bind::new(&inputs[0].backing, "/scratch"),
            Bind::new(runtime.path().join("output"), visible),
            Bind::new(runtime.path().join("output"), visible.join("child")),
        ] {
            let mut alias = spec.clone();
            alias.rw_binds.push(bind);
            assert!(owner.protect_dependency(91, &context, &alias).is_err());
        }
        let mut shadowed = spec;
        shadowed.ro_binds.push(Bind::new(
            runtime.path().join("output"),
            visible.join("nested"),
        ));
        assert!(owner.protect_dependency(91, &context, &shadowed).is_err());
        let archive = inputs[0].backing.join("nested/libanswer.a");
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&archive, b"changed native archive").unwrap();
        assert!(inputs[0].verify().is_err());
        std::fs::write(inputs[1].backing.join("unannounced"), b"new input").unwrap();
        assert!(inputs[1].verify().is_err());
    }

    fn generated_dependency_profile_fixture(
        files: &[(&str, &[u8], bool)],
        canonical: bool,
    ) -> (
        SourceOwner,
        rabs_sandbox::dependency_context::DependencyExecContext,
        rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
        tempfile::TempDir,
    ) {
        use rabs_sandbox::dependency_context::{DependencyExecContext, DependencyExecutionMode};
        let owner = uploaded_dependency_bundle(files);
        let mut directories = std::collections::BTreeSet::new();
        for (path, _, _) in files {
            if let Some(relative) = path.strip_prefix("generated/") {
                for (offset, _) in relative.match_indices('/') {
                    directories.insert(relative[..offset].to_owned());
                }
            }
        }
        let context = if canonical {
            let source = "/__rabs/workspace/vendor/package";
            let output = "/__rabs/out/cargo/debug/deps";
            let generated = "/__rabs/out/cargo/debug/build/package-123/out";
            DependencyExecContext::new_canonical_cargo_with_generated(
                DependencyExecutionMode::Metadata,
                source.into(),
                source.into(),
                output.into(),
                vec![output.into()],
                vec!["/__rabs/out/cargo/debug".into()],
                Vec::new(),
                Some(generated.into()),
                vec![
                    ("HOME".into(), "/__rabs/home".into()),
                    ("CARGO_HOME".into(), "/__rabs/cargo-home".into()),
                    ("CARGO_MANIFEST_DIR".into(), source.into()),
                    ("OUT_DIR".into(), generated.into()),
                ],
                [7; 32],
            )
        } else {
            let generated = "/target/build/unit/out";
            DependencyExecContext::new_with_generated_artifacts(
                "/source/package".to_owned(),
                "/source/package".to_owned(),
                "/toolchains/pinned".to_owned(),
                "/toolchains/pinned/bin/rustc".to_owned(),
                "/target/deps".to_owned(),
                vec!["/target/deps".to_owned()],
                vec!["/target".to_owned()],
                Vec::new(),
                Some(generated.to_owned()),
                vec![("OUT_DIR".to_owned(), generated.to_owned())],
                [7; 32],
            )
        }
        .unwrap()
        .with_generated_directories(directories.into_iter().collect())
        .unwrap();
        let runtime = tempfile::tempdir().unwrap();
        for name in ["toolchain", "output", "empty", "home"] {
            std::fs::create_dir(runtime.path().join(name)).unwrap();
        }
        context
            .prepare_empty_backings(&runtime.path().join("empty"))
            .unwrap();
        let package = owner.dependency_root(91, &context).unwrap();
        let spec = context
            .namespace(
                &package,
                &runtime.path().join("toolchain"),
                &runtime.path().join("output"),
                &runtime.path().join("empty"),
                &runtime.path().join("home"),
            )
            .unwrap();
        (owner, context, spec, runtime)
    }

    #[test]
    fn canonical_generated_inputs_use_exact_sealed_or_empty_read_only_owners() {
        use rabs_sandbox::canonical_namespace::Bind;
        use rabs_sandbox::dependency_context::DependencyExecutionMode;
        let package = ("package/src/lib.rs", b"source".as_slice(), false);
        let generated = (
            "generated/nested/input.rs",
            b"pub const VALUE:u32=73;".as_slice(),
            false,
        );
        let binary = (
            "generated/nested/data.bin",
            b"captured binary bytes\n\0\xff".as_slice(),
            false,
        );
        let executable = ("generated/helper", b"helper bytes".as_slice(), true);
        for mode in [
            DependencyExecutionMode::Metadata,
            DependencyExecutionMode::Rlib,
        ] {
            for files in [
                vec![package],
                vec![package, generated],
                vec![package, generated, binary, executable],
            ] {
                let (owner, context, mut spec, _runtime) =
                    generated_dependency_profile_fixture(&files, true);
                let context = context.with_execution_mode(mode);
                let original = spec.clone();
                let guard = owner
                    .prepare_dependency_generated(91, &context, &mut spec)
                    .unwrap()
                    .unwrap();
                assert_eq!(context.version(), "canonical-dependency-exec-v4");
                assert_eq!(guard.files.len(), files.len() - 1);
                owner.protect_dependency(91, &context, &spec).unwrap();
                guard.verify().unwrap();
                let visible = std::path::Path::new(context.generated_root().unwrap());
                assert_eq!(
                    spec.ro_binds
                        .iter()
                        .filter(|bind| bind.visible == visible)
                        .count(),
                    1
                );
                assert!(
                    spec.rw_binds
                        .iter()
                        .all(|bind| !bind.visible.starts_with(visible))
                );
                if files.len() == 1 {
                    assert_eq!(std::fs::read_dir(&guard.backing).unwrap().count(), 0);
                    assert!(
                        owner
                            .receiver
                            .sealed_root()
                            .unwrap()
                            .join("generated")
                            .symlink_metadata()
                            .is_err()
                    );
                    assert!(
                        owner
                            .prepare_dependency_generated(91, &context, &mut original.clone())
                            .is_err(),
                        "an empty generated owner cannot be silently reused"
                    );
                } else {
                    assert_eq!(
                        std::fs::read(guard.backing.join("nested/input.rs")).unwrap(),
                        generated.1
                    );
                }
                if files.len() == 4 {
                    assert_eq!(
                        std::fs::read(guard.backing.join("nested/data.bin")).unwrap(),
                        binary.1
                    );
                    assert_eq!(
                        std::fs::read(guard.backing.join("helper")).unwrap(),
                        executable.1
                    );
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        assert_ne!(
                            std::fs::metadata(guard.backing.join("helper"))
                                .unwrap()
                                .permissions()
                                .mode()
                                & 0o111,
                            0
                        );
                    }
                }
                let mut writable = spec.clone();
                writable
                    .rw_binds
                    .push(Bind::new(&guard.backing, "/__rabs/home/mutable-generated"));
                assert!(owner.protect_dependency(91, &context, &writable).is_err());
                let mut missing = spec;
                missing.ro_binds.retain(|bind| bind.visible != visible);
                assert!(owner.protect_dependency(91, &context, &missing).is_err());
            }
        }
    }

    #[test]
    fn generated_inputs_preserve_nested_binary_files_and_empty_tree_ownership() {
        let package = ("package/src/lib.rs", b"source".as_slice(), false);
        let generated = (
            "generated/nested/constants.rs",
            b"pub const VALUE: u8 = 42;\n\0\xff".as_slice(),
            false,
        );
        let executable = (
            "generated/helper",
            b"captured helper bytes".as_slice(),
            true,
        );
        for files in [vec![package], vec![package, generated, executable]] {
            let (owner, context, mut spec, _runtime) = generated_dependency_fixture(&files);
            let original = spec.clone();
            let guard = owner
                .prepare_dependency_generated(91, &context, &mut spec)
                .unwrap()
                .unwrap();
            guard.verify().unwrap();
            owner.protect_dependency(91, &context, &spec).unwrap();
            assert_eq!(guard.files.len(), files.len() - 1);
            let generated_bind = spec
                .ro_binds
                .iter()
                .find(|bind| Some(bind.visible.to_str().unwrap()) == context.generated_root())
                .unwrap();
            assert_eq!(generated_bind.backing, guard.backing);
            if files.len() == 1 {
                assert!(
                    owner
                        .receiver
                        .sealed_root()
                        .unwrap()
                        .join("generated")
                        .symlink_metadata()
                        .is_err()
                );
                assert_eq!(std::fs::read_dir(&guard.backing).unwrap().count(), 0);
                assert!(
                    owner
                        .prepare_dependency_generated(91, &context, &mut original.clone())
                        .is_err(),
                    "an already created empty input owner cannot be silently reused"
                );
            } else {
                assert_eq!(
                    std::fs::read(guard.backing.join("nested/constants.rs")).unwrap(),
                    generated.1
                );
                assert_eq!(
                    std::fs::read(guard.backing.join("helper")).unwrap(),
                    executable.1
                );
            }
        }
    }

    #[test]
    fn generated_directory_only_and_mixed_trees_preserve_exact_private_topology() {
        use rabs_sandbox::dependency_context::DependencyExecutionMode;
        use std::os::unix::fs::MetadataExt;
        let package = ("package/src/lib.rs", b"source".as_slice(), false);
        let generated = ("generated/value.rs", b"generated bytes".as_slice(), false);
        for canonical in [false, true] {
            for mode in [
                DependencyExecutionMode::Metadata,
                DependencyExecutionMode::Rlib,
            ] {
                for files in [vec![package], vec![package, generated]] {
                    let (owner, context, mut spec, runtime) =
                        generated_dependency_profile_fixture(&files, canonical);
                    let context = context
                        .with_execution_mode(mode)
                        .with_generated_directories(vec!["empty".into(), "empty/child".into()])
                        .unwrap();
                    let guard = owner
                        .prepare_dependency_generated(91, &context, &mut spec)
                        .unwrap()
                        .unwrap();
                    owner.protect_dependency(91, &context, &spec).unwrap();
                    guard.verify().unwrap();
                    assert_eq!(
                        guard
                            .directories
                            .keys()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                        ["empty", "empty/child"]
                    );
                    assert!(guard.backing.join("empty/child").is_dir());
                    assert_eq!(
                        std::fs::read_dir(guard.backing.join("empty/child"))
                            .unwrap()
                            .count(),
                        0
                    );
                    let sealed = owner.receiver.sealed_root().unwrap();
                    assert!(
                        !sealed.join("generated/empty").exists(),
                        "execution topology must not alter the sealed transfer"
                    );
                    if files.len() == 2 {
                        let original =
                            std::fs::metadata(sealed.join("generated/value.rs")).unwrap();
                        let copied = std::fs::metadata(guard.backing.join("value.rs")).unwrap();
                        assert_ne!(
                            (original.dev(), original.ino()),
                            (copied.dev(), copied.ino())
                        );
                        assert_eq!(
                            std::fs::read(guard.backing.join("value.rs")).unwrap(),
                            generated.1
                        );
                    }
                    std::fs::rename(
                        guard.backing.join("empty/child"),
                        runtime.path().join("retained-child"),
                    )
                    .unwrap();
                    std::fs::create_dir(guard.backing.join("empty/child")).unwrap();
                    assert!(
                        guard.verify().is_err(),
                        "same-name empty directory replacement must invalidate the guard"
                    );
                }
            }
        }
    }

    #[test]
    fn generated_directory_topology_allows_real_rustc_include_traversal() {
        let files = [
            ("package/src/lib.rs", b"pub const VALUE: &str = include_str!(concat!(env!(\"OUT_DIR\"), \"/empty/../value.rs\"));\n".as_slice(), false),
            ("generated/value.rs", b"retained generated value".as_slice(), false),
        ];
        let (owner, context, mut spec, runtime) = generated_dependency_fixture(&files);
        let context = context
            .with_generated_directories(vec!["empty".into()])
            .unwrap();
        let guard = owner
            .prepare_dependency_generated(91, &context, &mut spec)
            .unwrap()
            .unwrap();
        owner.protect_dependency(91, &context, &spec).unwrap();
        let source = owner
            .dependency_root(91, &context)
            .unwrap()
            .join("src/lib.rs");
        let compile = || {
            std::process::Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                .args([
                    "--crate-name=generated_tree",
                    "--crate-type=lib",
                    "--emit=metadata",
                    "--out-dir",
                ])
                .arg(runtime.path().join("output"))
                .arg(&source)
                .env("OUT_DIR", &guard.backing)
                .output()
                .expect("run the actual Rust compiler")
        };
        let result = compile();
        assert!(
            result.status.success(),
            "rustc could not read the preserved generated tree: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            runtime
                .path()
                .join("output/libgenerated_tree.rmeta")
                .is_file()
        );
        guard.verify().unwrap();
        std::fs::rename(
            guard.backing.join("empty"),
            runtime.path().join("retained-empty"),
        )
        .unwrap();
        assert!(
            !compile().status.success(),
            "negative control must fail when required empty directory is omitted"
        );
        assert!(guard.verify().is_err());
    }

    #[test]
    fn generated_file_manifest_requires_declared_parents_and_disjoint_directory_names() {
        let files = [
            ("package/src/lib.rs", b"source".as_slice(), false),
            ("generated/nested/value.rs", b"generated".as_slice(), false),
        ];
        let (owner, context, spec, _runtime) = generated_dependency_fixture(&files);
        for directories in [vec![], vec!["nested".into(), "nested/value.rs".into()]] {
            let invalid = context
                .clone()
                .with_generated_directories(directories)
                .unwrap();
            assert!(owner.dependency_root(91, &invalid).is_err());
            assert!(
                owner
                    .prepare_dependency_generated(91, &invalid, &mut spec.clone())
                    .is_err()
            );
        }
    }

    #[test]
    fn generated_input_guard_rejects_mutation_replacement_aliases_and_new_members() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let files = [
            ("package/src/lib.rs", b"source".as_slice(), false),
            (
                "generated/nested/input.rs",
                b"original generated bytes".as_slice(),
                false,
            ),
        ];
        for mutation in [
            "bytes",
            "file",
            "hardlink",
            "mode",
            "extra",
            "directory",
            "parent",
            "root",
        ] {
            let (owner, context, mut spec, runtime) = generated_dependency_fixture(&files);
            let guard = owner
                .prepare_dependency_generated(91, &context, &mut spec)
                .unwrap()
                .unwrap();
            let input = guard.backing.join("nested/input.rs");
            match mutation {
                "bytes" => {
                    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                    std::fs::write(&input, b"different generated data").unwrap();
                }
                "file" => {
                    std::fs::rename(&input, runtime.path().join("saved-input")).unwrap();
                    std::fs::write(&input, files[1].1).unwrap();
                }
                "hardlink" => std::fs::hard_link(&input, runtime.path().join("alias")).unwrap(),
                "mode" => std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o400))
                    .unwrap(),
                "extra" => std::fs::write(guard.backing.join("extra"), b"new input").unwrap(),
                "directory" => std::fs::create_dir(guard.backing.join("extra-directory")).unwrap(),
                "parent" => {
                    let original = runtime.path().join("saved-parent");
                    std::fs::rename(guard.backing.join("nested"), &original).unwrap();
                    symlink(original, guard.backing.join("nested")).unwrap();
                }
                "root" => {
                    std::fs::rename(&guard.backing, runtime.path().join("saved-root")).unwrap();
                    std::fs::create_dir(&guard.backing).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                guard.verify().is_err(),
                "mutation escaped generated guard: {mutation}"
            );
        }
        let (owner, context, mut spec, _runtime) = generated_dependency_fixture(&files[..1]);
        let guard = owner
            .prepare_dependency_generated(91, &context, &mut spec)
            .unwrap()
            .unwrap();
        std::fs::write(guard.backing.join("introduced"), b"previously absent").unwrap();
        assert!(
            guard.verify().is_err(),
            "an empty generated tree is an exact absence input"
        );
    }

    #[test]
    fn generated_preparation_rechecks_sealed_bytes_and_exact_inventory() {
        use std::os::unix::fs::PermissionsExt;
        let files = [
            ("package/src/lib.rs", b"source".as_slice(), false),
            ("generated/input.rs", b"good".as_slice(), false),
        ];
        for extra in [false, true] {
            let (owner, context, mut spec, _runtime) = generated_dependency_fixture(&files);
            let root = owner.receiver.sealed_root().unwrap().join("generated");
            if extra {
                std::fs::write(root.join("undeclared"), b"extra").unwrap();
            } else {
                let input = root.join("input.rs");
                std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
                std::fs::write(&input, b"evil").unwrap();
                std::fs::set_permissions(input, std::fs::Permissions::from_mode(0o444)).unwrap();
            }
            assert!(
                owner
                    .prepare_dependency_generated(91, &context, &mut spec)
                    .is_err()
            );
        }
    }

    #[test]
    fn generated_mounts_refuse_shadowing_redirection_and_writable_aliases() {
        assert_generated_mount_protection(false);
    }

    #[test]
    fn canonical_generated_mounts_refuse_shadowing_redirection_and_writable_aliases() {
        assert_generated_mount_protection(true);
    }

    fn assert_generated_mount_protection(canonical: bool) {
        use rabs_sandbox::canonical_namespace::Bind;
        use std::path::Path;
        for populated in [false, true] {
            let mut files = vec![("package/src/lib.rs", b"source".as_slice(), false)];
            if populated {
                files.push(("generated/input.rs", b"generated".as_slice(), false));
            }
            let (owner, context, mut spec, runtime) =
                generated_dependency_profile_fixture(&files, canonical);
            let guard = owner
                .prepare_dependency_generated(91, &context, &mut spec)
                .unwrap()
                .unwrap();
            owner.protect_dependency(91, &context, &spec).unwrap();
            let visible = Path::new(context.generated_root().unwrap());
            let mut missing = spec.clone();
            missing.ro_binds.retain(|bind| bind.visible != visible);
            assert!(owner.protect_dependency(91, &context, &missing).is_err());
            let mut redirected = spec.clone();
            redirected
                .ro_binds
                .iter_mut()
                .find(|bind| bind.visible == visible)
                .unwrap()
                .backing = runtime.path().join("output");
            assert!(owner.protect_dependency(91, &context, &redirected).is_err());
            for shadow in [
                visible.join("input.rs"),
                visible.parent().unwrap().parent().unwrap().to_path_buf(),
            ] {
                let mut changed = spec.clone();
                changed
                    .ro_binds
                    .push(Bind::new(runtime.path().join("output"), shadow));
                assert!(owner.protect_dependency(91, &context, &changed).is_err());
            }
            for bind in [
                Bind::new(&guard.backing, "/scratch"),
                Bind::new(runtime.path().join("output"), visible),
                Bind::new(runtime.path().join("output"), visible.join("child")),
                Bind::new(
                    runtime.path().join("output"),
                    visible.parent().unwrap().parent().unwrap(),
                ),
            ] {
                let mut changed = spec.clone();
                changed.rw_binds.push(bind);
                assert!(owner.protect_dependency(91, &context, &changed).is_err());
            }
        }
    }

    #[test]
    fn generated_bundle_members_require_the_matching_context() {
        use rabs_sandbox::dependency_context::DependencyExecContext;
        let owner = uploaded_dependency_bundle(&[
            ("package/src/lib.rs", b"source", false),
            ("generated/input.rs", b"generated", false),
        ]);
        let context = DependencyExecContext::new(
            "/source/package".to_owned(),
            "/source/package".to_owned(),
            "/toolchains/pinned".to_owned(),
            "/toolchains/pinned/bin/rustc".to_owned(),
            "/target/deps".to_owned(),
            Vec::new(),
            Vec::new(),
            [7; 32],
        )
        .unwrap();
        assert!(owner.dependency_root(91, &context).is_err());
    }

    struct SharedDependencyFixture {
        owner: SourceOwner,
        context: rabs_sandbox::dependency_context::DependencyExecContext,
        spec: rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec,
        output: tempfile::TempDir,
        _toolchain: tempfile::TempDir,
        _empty: tempfile::TempDir,
        _home: tempfile::TempDir,
    }

    impl SharedDependencyFixture {
        fn new() -> Self {
            use rabs_sandbox::dependency_context::{DependencyArtifactRoot, DependencyExecContext};

            let owner = uploaded_dependency_bundle(&[
                (
                    "package/src/lib.rs",
                    b"pub fn answer() -> u8 { 42 }\n",
                    false,
                ),
                (
                    "dependencies/0000/libleaf.rmeta",
                    b"retained metadata",
                    false,
                ),
                (
                    "dependencies/0000/libarchive.rlib",
                    b"retained full archive",
                    false,
                ),
                (
                    "dependencies/0001/libexternal.rmeta",
                    b"other directory input",
                    false,
                ),
            ]);
            let context = DependencyExecContext::new_with_artifacts(
                "/source/package".to_owned(),
                "/source/package".to_owned(),
                "/toolchains/pinned".to_owned(),
                "/toolchains/pinned/bin/rustc".to_owned(),
                "/target/deps".to_owned(),
                vec!["/target/deps".to_owned(), "/target/external".to_owned()],
                vec!["/target".to_owned()],
                vec![
                    DependencyArtifactRoot {
                        path: "/target/deps".to_owned(),
                        prefix: "dependencies/0000".to_owned(),
                    },
                    DependencyArtifactRoot {
                        path: "/target/external".to_owned(),
                        prefix: "dependencies/0001".to_owned(),
                    },
                ],
                Vec::new(),
                [7; 32],
            )
            .unwrap();
            let toolchain = tempfile::tempdir().unwrap();
            let output = tempfile::tempdir().unwrap();
            let empty = tempfile::tempdir().unwrap();
            let home = tempfile::tempdir().unwrap();
            context.prepare_empty_backings(empty.path()).unwrap();
            let package = owner.dependency_root(91, &context).unwrap();
            let spec = context
                .namespace(
                    &package,
                    toolchain.path(),
                    output.path(),
                    empty.path(),
                    home.path(),
                )
                .unwrap();
            Self {
                owner,
                context,
                spec,
                output,
                _toolchain: toolchain,
                _empty: empty,
                _home: home,
            }
        }

        fn prepare(&mut self) -> io::Result<DependencyOutputInputs> {
            self.owner
                .prepare_dependency_output(91, &self.context, &mut self.spec)
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_output_retains_exact_input_bytes_over_exclusive_empty_mountpoints() {
        use rabs_sandbox::dependency_context::{
            DependencyExecContext, DependencyExecutionMode, DependencyIsolationSupport,
            build_dependency_argv,
        };
        use std::path::Path;

        let mut fixture = SharedDependencyFixture::new();
        let retention_parent = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let runtime = rabs_sandbox::runtime_cohort::retain_runtime_cohort(
            &executable,
            executable.parent().unwrap(),
            &[],
            fixture.output.path(),
            retention_parent.path(),
            || false,
        )
        .unwrap();
        fixture.context = DependencyExecContext::new_with_artifacts(
            fixture.context.source_root().to_owned(),
            fixture.context.cwd().to_owned(),
            fixture.context.toolchain_root().to_owned(),
            fixture.context.compiler().to_owned(),
            fixture.context.out_dir().to_owned(),
            fixture.context.dependency_dirs().to_vec(),
            fixture.context.loader_dirs().to_vec(),
            fixture.context.artifact_roots().to_vec(),
            fixture.context.env().to_vec(),
            runtime.cohort().bytes,
        )
        .unwrap()
        .with_execution_mode(DependencyExecutionMode::Rlib);
        let guard = fixture.prepare().unwrap();
        assert_eq!(
            guard.relative_paths().collect::<Vec<_>>(),
            ["libarchive.rlib", "libleaf.rmeta"]
        );
        for (name, bytes) in [
            ("libarchive.rlib", b"retained full archive".as_slice()),
            ("libleaf.rmeta", b"retained metadata".as_slice()),
        ] {
            assert_eq!(
                std::fs::read(fixture.output.path().join(name)).unwrap(),
                b""
            );
            let visible = Path::new(fixture.context.out_dir()).join(name);
            let binding = fixture
                .spec
                .ro_binds
                .iter()
                .find(|bind| bind.visible == visible)
                .unwrap();
            assert_eq!(std::fs::read(&binding.backing).unwrap(), bytes);
        }
        fixture
            .owner
            .protect_dependency(91, &fixture.context, &fixture.spec)
            .unwrap();
        guard.verify(fixture.output.path()).unwrap();
        // New output entries are legitimate changes to the directory, but may
        // not alter any of the retained mountpoint identities.
        std::fs::write(
            fixture.output.path().join("libproduced.rmeta"),
            b"new output",
        )
        .unwrap();
        guard.verify(fixture.output.path()).unwrap();
        let unrelated = tempfile::tempdir().unwrap();
        assert!(guard.verify(unrelated.path()).is_err());

        let support = DependencyIsolationSupport::probe(fixture.context.execution_mode());
        if !support.is_supported() {
            eprintln!(
                "SKIP: namespace argv proof unavailable: {:?}",
                support.missing()
            );
            return;
        }
        let launch = build_dependency_argv(
            &fixture.context,
            &fixture.spec,
            &runtime,
            &support,
            fixture.context.compiler(),
            &[],
        )
        .unwrap();
        let args: Vec<_> = launch
            .argv
            .iter()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        let writable = args
            .windows(3)
            .position(|args| args[0] == "--bind" && args[2] == fixture.context.out_dir())
            .unwrap();
        for name in guard.relative_paths() {
            let visible = format!("{}/{name}", fixture.context.out_dir());
            let retained = args
                .windows(3)
                .position(|args| args[0] == "--ro-bind" && args[2] == visible)
                .unwrap();
            assert!(
                writable < retained,
                "input must cover the writable mountpoint"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn shared_input_guards_refuse_mutation_replacement_links_and_backing_changes() {
        use std::os::unix::fs::PermissionsExt;

        for mutation in [
            "bytes",
            "replacement",
            "hardlink",
            "permissions",
            "retained",
        ] {
            let mut fixture = SharedDependencyFixture::new();
            let guard = fixture.prepare().unwrap();
            let placeholder = fixture.output.path().join("libleaf.rmeta");
            match mutation {
                "bytes" => std::fs::write(&placeholder, b"untrusted output").unwrap(),
                "replacement" => {
                    std::fs::rename(&placeholder, fixture.output.path().join("saved-input"))
                        .unwrap();
                    std::fs::write(&placeholder, b"").unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&placeholder, fixture.output.path().join("linked-input"))
                        .unwrap();
                }
                "permissions" => {
                    std::fs::set_permissions(&placeholder, std::fs::Permissions::from_mode(0o400))
                        .unwrap();
                }
                "retained" => {
                    let binding = fixture
                        .spec
                        .ro_binds
                        .iter()
                        .find(|bind| {
                            bind.visible == std::path::Path::new("/target/deps/libleaf.rmeta")
                        })
                        .unwrap();
                    std::fs::set_permissions(
                        &binding.backing,
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                    std::fs::write(&binding.backing, b"changed metadata!").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(guard.verify(fixture.output.path()).is_err(), "{mutation}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn shared_output_preparation_never_reuses_a_file_directory_or_symlink() {
        for existing in ["file", "directory", "symlink"] {
            let mut fixture = SharedDependencyFixture::new();
            let collision = fixture.output.path().join("libarchive.rlib");
            match existing {
                "file" => std::fs::write(&collision, b"prior output").unwrap(),
                "directory" => std::fs::create_dir(&collision).unwrap(),
                "symlink" => std::os::unix::fs::symlink("missing-target", &collision).unwrap(),
                _ => unreachable!(),
            }
            assert!(fixture.prepare().is_err(), "{existing}");
            if existing == "file" {
                assert_eq!(std::fs::read(&collision).unwrap(), b"prior output");
            }
        }
        let mut fixture = SharedDependencyFixture::new();
        let _guard = fixture.prepare().unwrap();
        assert!(
            fixture.prepare().is_err(),
            "a prepared namespace cannot be reused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shared_output_preparation_rehashes_the_sealed_member_before_mounting() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = SharedDependencyFixture::new();
        let package = fixture.owner.dependency_root(91, &fixture.context).unwrap();
        let member = package
            .parent()
            .unwrap()
            .join("dependencies/0000/libarchive.rlib");
        std::fs::set_permissions(&member, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&member, b"changed full archive!").unwrap();
        assert!(fixture.prepare().is_err());
        assert!(
            std::fs::read_dir(fixture.output.path())
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn shared_output_guard_retains_the_directory_identity() {
        let mut fixture = SharedDependencyFixture::new();
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        std::fs::create_dir(&output).unwrap();
        fixture
            .spec
            .rw_binds
            .iter_mut()
            .find(|bind| bind.visible == std::path::Path::new(fixture.context.out_dir()))
            .unwrap()
            .backing = output.clone();
        let guard = fixture.prepare().unwrap();
        std::fs::rename(&output, root.path().join("retained-output")).unwrap();
        std::fs::create_dir(&output).unwrap();
        for name in guard.relative_paths() {
            std::fs::write(output.join(name), b"").unwrap();
        }
        assert!(guard.verify(&output).is_err());
    }

    #[test]
    fn shared_dependency_protection_requires_the_complete_unaliased_file_set() {
        use rabs_sandbox::canonical_namespace::Bind;
        use std::path::Path;

        let mut fixture = SharedDependencyFixture::new();
        let _guard = fixture.prepare().unwrap();
        fixture
            .owner
            .protect_dependency(91, &fixture.context, &fixture.spec)
            .unwrap();
        let input = Path::new("/target/deps/libleaf.rmeta");
        let original = fixture
            .spec
            .ro_binds
            .iter()
            .find(|bind| bind.visible == input)
            .unwrap();
        let mut missing = fixture.spec.clone();
        missing.ro_binds.retain(|bind| bind.visible != input);
        assert!(
            fixture
                .owner
                .protect_dependency(91, &fixture.context, &missing)
                .is_err()
        );
        for extra in [
            original.clone(),
            Bind::new(&original.backing, "/target/deps/libundeclared.rmeta"),
            Bind::new(&original.backing, "/target/deps/libleaf.rmeta/shadow"),
            Bind::new(&original.backing, "/target/deps"),
            Bind::new(&original.backing, "/"),
        ] {
            let mut shadowed = fixture.spec.clone();
            shadowed.ro_binds.push(extra);
            assert!(
                fixture
                    .owner
                    .protect_dependency(91, &fixture.context, &shadowed)
                    .is_err()
            );
        }
        let mut redirected = fixture.spec.clone();
        redirected
            .ro_binds
            .iter_mut()
            .find(|bind| bind.visible == input)
            .unwrap()
            .backing = fixture.output.path().join("libleaf.rmeta");
        assert!(
            fixture
                .owner
                .protect_dependency(91, &fixture.context, &redirected)
                .is_err()
        );
        let bundle = fixture
            .owner
            .dependency_root(91, &fixture.context)
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        for extra in [
            Bind::new(fixture.output.path(), input),
            Bind::new(&bundle, "/unrelated/alias"),
            Bind::new(fixture.output.path(), fixture.context.out_dir()),
        ] {
            let mut writable = fixture.spec.clone();
            writable.rw_binds.push(extra);
            assert!(
                fixture
                    .owner
                    .protect_dependency(91, &fixture.context, &writable)
                    .is_err()
            );
        }
    }

    #[test]
    fn dependency_bundle_projects_only_owned_package_and_exact_candidate_roots() {
        use rabs_sandbox::canonical_namespace::Bind;
        use rabs_sandbox::dependency_context::{DependencyArtifactRoot, DependencyExecContext};
        use std::path::Path;

        let owner = uploaded_dependency_bundle(&[
            (
                "package/src/lib.rs",
                b"pub fn answer() -> u8 { 42 }\n",
                false,
            ),
            (
                "dependencies/0000/libleaf.rmeta",
                b"retained metadata",
                false,
            ),
            (
                "dependencies/0001/libarchive.rlib",
                b"retained archive",
                false,
            ),
        ]);
        let context = DependencyExecContext::new_with_artifacts(
            "/source/package".to_owned(),
            "/source/package".to_owned(),
            "/toolchains/pinned".to_owned(),
            "/toolchains/pinned/bin/rustc".to_owned(),
            "/target/output".to_owned(),
            vec!["/target/z-first".to_owned(), "/target/a-second".to_owned()],
            vec!["/target".to_owned()],
            vec![
                DependencyArtifactRoot {
                    path: "/target/z-first".to_owned(),
                    prefix: "dependencies/0000".to_owned(),
                },
                DependencyArtifactRoot {
                    path: "/target/a-second".to_owned(),
                    prefix: "dependencies/0001".to_owned(),
                },
            ],
            Vec::new(),
            [7; 32],
        )
        .unwrap();
        let package = owner.dependency_root(91, &context).unwrap();
        assert_eq!(package.file_name().unwrap(), "package");
        assert_eq!(
            std::fs::read(package.join("src/lib.rs")).unwrap(),
            b"pub fn answer() -> u8 { 42 }\n"
        );
        let bundle = package.parent().unwrap();
        assert_eq!(
            std::fs::read(bundle.join("dependencies/0000/libleaf.rmeta")).unwrap(),
            b"retained metadata"
        );
        assert_eq!(
            std::fs::read(bundle.join("dependencies/0001/libarchive.rlib")).unwrap(),
            b"retained archive"
        );
        assert!(owner.dependency_root(92, &context).is_err());
        let toolchain = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let empty = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        context.prepare_empty_backings(empty.path()).unwrap();
        let mut spec = context
            .namespace(
                &package,
                toolchain.path(),
                output.path(),
                empty.path(),
                home.path(),
            )
            .unwrap();
        let guard = owner
            .prepare_dependency_output(91, &context, &mut spec)
            .unwrap();
        assert!(guard.relative_paths().next().is_none());
        guard.verify(output.path()).unwrap();
        std::fs::write(output.path().join("libproduced.rmeta"), b"new output").unwrap();
        guard.verify(output.path()).unwrap();
        owner.protect_dependency(91, &context, &spec).unwrap();
        for root in context.artifact_roots() {
            assert!(spec.ro_binds.iter().any(|bind| {
                bind.visible == Path::new(&root.path) && bind.backing == bundle.join(&root.prefix)
            }));
        }
        let other = tempfile::tempdir().unwrap();
        let mut redirected = spec.clone();
        redirected
            .ro_binds
            .iter_mut()
            .find(|bind| bind.visible == Path::new("/target/z-first"))
            .unwrap()
            .backing = other.path().to_path_buf();
        assert!(owner.protect_dependency(91, &context, &redirected).is_err());
        let mut writable = spec.clone();
        writable.rw_binds[0].backing = package.clone();
        assert!(owner.protect_dependency(91, &context, &writable).is_err());
        let mut visible_alias = spec.clone();
        visible_alias.rw_binds[0].visible = "/target/z-first".into();
        assert!(
            owner
                .protect_dependency(91, &context, &visible_alias)
                .is_err()
        );
        let mut shadowed = spec;
        shadowed
            .ro_binds
            .push(Bind::new(other.path(), "/target/z-first/shadow"));
        assert!(owner.protect_dependency(91, &context, &shadowed).is_err());
    }

    #[test]
    fn dependency_bundle_rejects_unmapped_missing_nested_or_executable_candidates() {
        use rabs_sandbox::dependency_context::{DependencyArtifactRoot, DependencyExecContext};

        let context = DependencyExecContext::new_with_artifacts(
            "/source/package".to_owned(),
            "/source/package".to_owned(),
            "/toolchains/pinned".to_owned(),
            "/toolchains/pinned/bin/rustc".to_owned(),
            "/target/output".to_owned(),
            vec!["/target/dependencies".to_owned()],
            Vec::new(),
            vec![DependencyArtifactRoot {
                path: "/target/dependencies".to_owned(),
                prefix: "dependencies/0000".to_owned(),
            }],
            Vec::new(),
            [7; 32],
        )
        .unwrap();
        let package: (&str, &[u8], bool) = ("package/src/lib.rs", b"source", false);
        let artifact: (&str, &[u8], bool) = ("dependencies/0000/libleaf.rmeta", b"metadata", false);
        let cases: Vec<Vec<(&str, &[u8], bool)>> = vec![
            vec![
                package,
                ("dependencies/0001/libleaf.rmeta", b"metadata", false),
            ],
            vec![
                package,
                ("dependencies/0000/nested/libleaf.rmeta", b"metadata", false),
            ],
            vec![package, ("dependencies/0000/libleaf.so", b"dynamic", false)],
            vec![
                package,
                ("dependencies/0000/libleaf.rmeta", b"metadata", true),
            ],
            vec![package],
            vec![artifact],
            vec![package, artifact, ("unmapped/extra", b"extra", false)],
            vec![
                package,
                ("dependencies/0000/leaf.rmeta", b"metadata", false),
            ],
        ];
        for files in cases {
            let owner = uploaded_dependency_bundle(&files);
            assert!(
                owner.dependency_root(91, &context).is_err(),
                "unsupported sealed input bundle: {files:?}"
            );
        }
    }

    #[test]
    fn full_input_budget_keeps_sealed_source_usable_during_toolchain_transfer() {
        let manifest = projection(&[("empty.rs", b"", false)]);
        let request = json!({"kind":"canonical-exec", "request_id":0, "source_manifest":manifest});
        let start = json!({"kind":"source-begin", "request_id":0, "manifest":manifest});
        for extended in [false, true] {
            let mut state = if extended {
                SourceTransferState::with_input_budget(
                    rabs_sandbox::toolchain_transfer::TOOLCHAIN_INPUT_BUDGET,
                )
            } else {
                SourceTransferState::default()
            };
            state.handle(&start, true, false).unwrap();
            state.handle(&seal(&manifest, 0), true, false).unwrap();
            // Simulate time spent transferring the full toolchain after the
            // source sealed, without sleeping or changing the wall clock.
            state.pending.as_mut().unwrap().deadline -= Duration::from_secs(6 * 60);
            let deadline = state.pending.as_ref().unwrap().deadline;
            assert_eq!(state.prepared_path(&request, true).is_ok(), extended);
            assert_eq!(state.handle(&start, true, false).is_ok(), extended);
            assert_eq!(state.pending.as_ref().unwrap().deadline, deadline);
            state.pending.as_mut().unwrap().deadline = Instant::now() - Duration::from_secs(1);
            assert!(state.prepared_path(&request, true).is_err());
            assert!(state.take_prepared(&request).is_err());
        }
    }

    #[test]
    fn large_archive_upload_then_reopened_cache_reuses_private_bytes_but_still_requires_seal() {
        use std::os::unix::fs::MetadataExt;
        let cache = tempfile::tempdir().unwrap();
        let bytes: Vec<_> = (0..5 * 1024 * 1024 + 7).map(|i| (i % 251) as u8).collect();
        let archive = "dependencies/0000/liblarge.rlib";
        let manifest = projection(&[(archive, &bytes, false), ("empty", b"", false)]);
        let mut cold = cached_state(cache.path());
        let reply = cold.handle(&begin(&manifest, 7), true, false).unwrap();
        assert_eq!(reply["missing_files"], json!([archive]));
        assert_eq!(reply["source_reused_bytes"], 0);
        assert!(cold.handle(&seal(&manifest, 7), true, false).is_err());
        upload(&mut cold, &manifest, 7, archive, &bytes);
        assert_eq!(
            cold.handle(&seal(&manifest, 7), true, false).unwrap()["sealed"],
            true
        );
        drop(cold); // A fresh session has no source owner; only verified cache objects survive.

        let mut warm = cached_state(cache.path());
        let reply = warm.handle(&begin(&manifest, 8), true, false).unwrap();
        assert_eq!(reply["missing_files"], json!([]));
        assert_eq!(reply["source_reused_bytes"], bytes.len());
        assert_eq!(reply["sealed"], false);
        let request = json!({"kind":"canonical-exec", "request_id":8, "source_manifest":manifest});
        assert!(warm.prepared_path(&request, true).is_err());
        let until = warm.pending.as_ref().unwrap().deadline;
        assert_eq!(
            warm.handle(&begin(&manifest, 8), true, false).unwrap(),
            reply
        );
        assert_eq!(warm.pending.as_ref().unwrap().deadline, until);
        warm.handle(&seal(&manifest, 8), true, false).unwrap();
        let root = std::path::PathBuf::from(warm.prepared_path(&request, true).unwrap().unwrap());
        assert_eq!(std::fs::read(root.join(archive)).unwrap(), bytes);
        assert_eq!(std::fs::read(root.join("empty")).unwrap(), b"");
        let cached = cache
            .path()
            .join("source-files-v1")
            .join(format!("{}.src", hex(&Sha256::digest(&bytes))));
        assert_ne!(
            std::fs::metadata(cached).unwrap().ino(),
            std::fs::metadata(root.join(archive)).unwrap().ino()
        );
        let owner = warm.take_prepared(&request).unwrap().unwrap();
        assert!(owner.cache.is_none());
        let cancelled = warm.cancellation_flag();
        cancelled.store(true, Ordering::Release);
        assert!(warm.prepared_path(&request, true).is_err());
        drop(warm);
        assert_eq!(
            Arc::strong_count(&cancelled),
            1,
            "execution retains no upload cancellation token"
        );
        assert_eq!(owner.target_cache_inputs(8).unwrap().root, root);
        assert!(root.exists());
        drop(owner);
    }

    #[test]
    fn corrupt_large_archive_is_a_clean_miss_before_any_receiver_write() {
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::PermissionsExt;
        let cache = tempfile::tempdir().unwrap();
        let bytes = vec![b'A'; 5 * 1024 * 1024 + 19];
        let archive = "dependencies/0000/liblarge.rlib";
        let manifest = projection(&[(archive, &bytes, false)]);
        let mut cold = cached_state(cache.path());
        cold.handle(&begin(&manifest, 31), true, false).unwrap();
        upload(&mut cold, &manifest, 31, archive, &bytes);
        cold.handle(&seal(&manifest, 31), true, false).unwrap();
        drop(cold);
        let path = cache
            .path()
            .join("source-files-v1")
            .join(format!("{}.src", hex(&Sha256::digest(&bytes))));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut corrupt = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        corrupt.seek(SeekFrom::End(-1)).unwrap();
        corrupt.write_all(b"B").unwrap();
        drop(corrupt);

        let mut next = cached_state(cache.path());
        let reply = next.handle(&begin(&manifest, 32), true, false).unwrap();
        assert_eq!(reply["missing_files"], json!([archive]));
        assert_eq!(reply["source_reused_bytes"], 0);
        let owner = next.pending.as_ref().unwrap();
        assert_eq!(
            std::fs::metadata(owner._directory.path().join("workspace").join(archive))
                .unwrap()
                .len(),
            0
        );
        // A late bad byte cannot poison the receiver: the entire correct upload
        // remains usable and replaces the corrupt cache object after sealing.
        upload(&mut next, &manifest, 32, archive, &bytes);
        assert_eq!(
            next.handle(&seal(&manifest, 32), true, false).unwrap()["sealed"],
            true
        );
        assert_eq!(
            cached_state(cache.path())
                .handle(&begin(&manifest, 33), true, false)
                .unwrap()["source_reused_bytes"],
            bytes.len()
        );
    }

    #[test]
    fn edited_files_miss_while_renamed_bytes_reuse_with_request_specific_modes() {
        use std::os::unix::fs::PermissionsExt;
        let cache = tempfile::tempdir().unwrap();
        let first = projection(&[("a", b"unchanged", false), ("b", b"before", false)]);
        let mut cold = cached_state(cache.path());
        cold.handle(&begin(&first, 1), true, false).unwrap();
        upload(&mut cold, &first, 1, "a", b"unchanged");
        upload(&mut cold, &first, 1, "b", b"before");
        cold.handle(&seal(&first, 1), true, false).unwrap();
        let next = projection(&[("renamed/a", b"unchanged", true), ("b", b"after", false)]);
        let mut warm = cached_state(cache.path());
        let start = begin(&next, 2);
        let reply = warm.handle(&start, true, false).unwrap();
        assert_eq!(reply["missing_files"], json!(["b"]));
        assert_eq!(reply["source_reused_bytes"], 9);
        assert!(warm.handle(&seal(&next, 2), true, false).is_err());
        upload(&mut warm, &next, 2, "b", b"after");
        // Retried begin reports the original missing set, not current file offsets.
        assert_eq!(warm.handle(&start, true, false).unwrap(), reply);
        warm.handle(&seal(&next, 2), true, false).unwrap();
        let request = json!({"request_id":2, "source_manifest":next});
        let root = std::path::PathBuf::from(warm.prepared_path(&request, true).unwrap().unwrap());
        assert_eq!(std::fs::read(root.join("b")).unwrap(), b"after");
        assert_eq!(
            std::fs::metadata(root.join("renamed/a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            std::fs::metadata(root.join("b"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        assert_ne!(first["manifest_sha256"], next["manifest_sha256"]);
    }

    #[test]
    fn corrupt_cached_content_requires_upload_and_can_be_repaired_without_reexecution() {
        use std::os::unix::fs::PermissionsExt;
        let cache = tempfile::tempdir().unwrap();
        let manifest = projection(&[("lib.rs", b"good", false)]);
        let mut state = cached_state(cache.path());
        state.handle(&begin(&manifest, 1), true, false).unwrap();
        upload(&mut state, &manifest, 1, "lib.rs", b"good");
        state.handle(&seal(&manifest, 1), true, false).unwrap();
        let cached = cache
            .path()
            .join("source-files-v1")
            .join(format!("{}.src", hex(&Sha256::digest(b"good"))));
        std::fs::set_permissions(&cached, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&cached, b"evil").unwrap();
        let mut next = cached_state(cache.path());
        assert_eq!(
            next.handle(&begin(&manifest, 2), true, false).unwrap()["missing_files"],
            json!(["lib.rs"])
        );
        assert!(next.handle(&seal(&manifest, 2), true, false).is_err());
        upload(&mut next, &manifest, 2, "lib.rs", b"good");
        next.handle(&seal(&manifest, 2), true, false).unwrap();
        assert_eq!(std::fs::read(cached).unwrap(), b"good");
        assert_eq!(
            cached_state(cache.path())
                .handle(&begin(&manifest, 3), true, false)
                .unwrap()["missing_files"],
            json!([])
        );
    }

    #[test]
    fn reuse_selection_is_explicit_immutable_and_does_not_renew_expired_ownership() {
        let cache = tempfile::tempdir().unwrap();
        let manifest = manifest();
        let mut state = cached_state(cache.path());
        let mut start = begin(&manifest, 7);
        start["allow_cached_files"] = json!("true");
        assert!(state.handle(&start, true, false).is_err());
        start["allow_cached_files"] = json!(true);
        assert!(state.handle(&start, false, false).is_err());
        assert!(state.handle(&start, true, true).is_err());
        state.handle(&start, true, false).unwrap();
        start["allow_cached_files"] = json!(false);
        assert!(state.handle(&start, true, false).is_err());
        let owner = state.pending.as_mut().unwrap();
        owner.deadline = Instant::now() - Duration::from_secs(1);
        let expired = owner.deadline;
        assert!(state.handle(&begin(&manifest, 7), true, false).is_err());
        assert!(state.handle(&seal(&manifest, 7), true, false).is_err());
        assert_eq!(state.pending.as_ref().unwrap().deadline, expired);
        let mut legacy = cached_state(cache.path());
        let reply = legacy
            .handle(
                &json!({"kind":"source-begin", "request_id":8, "manifest":manifest}),
                true,
                false,
            )
            .unwrap();
        assert!(reply.get("missing_files").is_none());
        assert!(legacy.pending.as_ref().unwrap().cache.is_none());
    }

    #[test]
    fn cache_storage_failure_is_optional_but_changed_execution_source_is_fenced() {
        let cache = tempfile::tempdir().unwrap();
        let manifest = projection(&[("lib.rs", b"good", false)]);
        let mut state = cached_state(cache.path());
        state.handle(&begin(&manifest, 1), true, false).unwrap();
        upload(&mut state, &manifest, 1, "lib.rs", b"good");
        // A foreign cache entry is never deleted and prevents only optional writes.
        std::fs::write(cache.path().join("source-files-v1/foreign"), b"preserve").unwrap();
        let reply = state.handle(&seal(&manifest, 1), true, false).unwrap();
        assert_eq!(reply["sealed"], true);
        assert!(reply["cache_write_error"].as_str().is_some());
        assert!(
            state
                .prepared_path(&json!({"request_id":1, "source_manifest":manifest}), true)
                .is_ok()
        );
        assert_eq!(
            std::fs::read(cache.path().join("source-files-v1/foreign")).unwrap(),
            b"preserve"
        );

        let clean_cache = tempfile::tempdir().unwrap();
        let mut changed = cached_state(clean_cache.path());
        changed.handle(&begin(&manifest, 2), true, false).unwrap();
        upload(&mut changed, &manifest, 2, "lib.rs", b"good");
        let source = changed
            .pending
            .as_ref()
            .unwrap()
            ._directory
            .path()
            .join("workspace/lib.rs");
        std::fs::write(source, b"evil").unwrap(); // Same length; metadata alone is not identity.
        assert!(changed.handle(&seal(&manifest, 2), true, false).is_err());
        let request = json!({"request_id":2, "source_manifest":manifest});
        assert!(changed.prepared_path(&request, true).is_err());
        assert!(changed.handle(&seal(&manifest, 2), true, false).is_err());
        assert!(changed.take_prepared(&request).is_err());
    }

    fn uploaded() -> (SourceTransferState, Value, Value, Value) {
        let manifest = manifest();
        let request = json!({"kind":"canonical-exec", "request_id":7,
            "source_manifest":manifest, "program":"rustc", "args":["src/lib.rs"]});
        let begin = json!({"kind":"source-begin", "request_id":7, "manifest":manifest});
        let chunk = json!({"kind":"source-chunk", "request_id":7,
            "manifest_sha256":manifest["manifest_sha256"], "path":"src/lib.rs", "offset":0,
            "data_hex":hex(b"source\0\xff"), "chunk_sha256":hex(&Sha256::digest(b"source\0\xff"))});
        let seal = json!({"kind":"source-seal", "request_id":7,
            "manifest_sha256":manifest["manifest_sha256"]});
        let mut state = SourceTransferState::default();
        assert_eq!(state.handle(&begin, true, false).unwrap()["sealed"], false);
        state.handle(&chunk, true, false).unwrap();
        (state, request, begin, seal)
    }

    fn namespace_for_source(
        owner: &SourceOwner,
        runtime: &std::path::Path,
    ) -> rabs_sandbox::canonical_namespace::CanonicalNamespaceSpec {
        use rabs_sandbox::canonical_namespace::{Bind, CanonicalNamespaceSpec};
        use rabs_sandbox::layout;
        let mut spec = CanonicalNamespaceSpec::new();
        spec.ro_binds
            .push(Bind::new("/toolchain", layout::TOOLCHAIN));
        let source = std::fs::canonicalize(owner._directory.path().join("workspace")).unwrap();
        spec.rw_binds.push(Bind::new(source, layout::WORKSPACE));
        for (name, visible) in [
            ("home", layout::HOME),
            ("cargo-home", layout::CARGO_HOME),
            ("output", "/__rabs/out/dep"),
        ] {
            let backing = runtime.join(name);
            std::fs::create_dir_all(&backing).unwrap();
            spec.rw_binds.push(Bind::new(backing, visible));
        }
        spec
    }

    #[test]
    fn source_owner_makes_only_its_workspace_read_only() {
        use rabs_sandbox::layout;
        let (mut state, request, _, seal) = uploaded();
        state.handle(&seal, true, false).unwrap();
        let owner = state.take_prepared(&request).unwrap().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let mut spec = namespace_for_source(&owner, runtime.path());
        let before = spec.clone();
        owner.protect_workspace(7, &mut spec).unwrap();
        assert_eq!(spec.rw_binds, before.rw_binds[1..]);
        assert_eq!(spec.ro_binds.len(), before.ro_binds.len() + 1);
        assert_eq!(spec.ro_binds.last(), before.rw_binds.first());
        assert!(
            spec.ro_binds
                .iter()
                .any(|bind| bind.visible == std::path::Path::new(layout::WORKSPACE))
        );
        assert_eq!(spec.env, before.env);
        assert_eq!(spec.cwd, before.cwd);
        assert!(!spec.allows_network());
        assert_eq!(
            std::fs::read(owner.receiver.sealed_root().unwrap().join("src/lib.rs")).unwrap(),
            b"source\0\xff"
        );
    }

    #[test]
    fn invalid_source_owner_never_changes_execution_mounts() {
        let (mut state, request, _, seal) = uploaded();
        let runtime = tempfile::tempdir().unwrap();
        let mut spec = namespace_for_source(state.pending.as_ref().unwrap(), runtime.path());
        let before = spec.clone();
        assert!(
            state
                .pending
                .as_ref()
                .unwrap()
                .protect_workspace(7, &mut spec)
                .is_err()
        );
        assert_eq!(
            spec, before,
            "an unsealed upload cannot configure execution"
        );
        state.handle(&seal, true, false).unwrap();
        let mut owner = state.take_prepared(&request).unwrap().unwrap();
        assert!(owner.protect_workspace(8, &mut spec).is_err());
        assert_eq!(spec, before);
        owner.source_failed = true;
        assert!(owner.protect_workspace(7, &mut spec).is_err());
        assert_eq!(spec, before);

        // Expiration still blocks a sealed owner which has not transferred
        // into execution, and refusal cannot silently change its ownership.
        let (mut expired, request, _, seal) = uploaded();
        expired.handle(&seal, true, false).unwrap();
        expired.pending.as_mut().unwrap().deadline = Instant::now() - Duration::from_secs(1);
        let mut spec = namespace_for_source(expired.pending.as_ref().unwrap(), runtime.path());
        let before = spec.clone();
        assert!(expired.prepared_path(&request, true).is_err());
        assert!(expired.take_prepared(&request).is_err());
        let owner = expired.pending.as_ref().unwrap();
        assert!(!owner.execution_owned);
        assert!(owner.protect_workspace(7, &mut spec).is_err());
        assert_eq!(spec, before);
    }

    #[test]
    fn handed_off_source_mount_outlives_upload_deadline_and_keeps_isolation() {
        use rabs_sandbox::layout;
        let (mut state, request, _, seal) = uploaded();
        state.handle(&seal, true, false).unwrap();
        assert!(!state.pending.as_ref().unwrap().execution_owned);
        let mut foreign = request.clone();
        foreign["request_id"] = json!(8);
        assert!(state.take_prepared(&foreign).is_err());
        assert!(!state.pending.as_ref().unwrap().execution_owned);

        let mut owner = state.take_prepared(&request).unwrap().unwrap();
        assert!(owner.execution_owned);
        assert!(state.pending.is_none());
        // Model time spent acquiring the compiler after successful admission
        // by expiring only this owner's already-retired upload timestamp.
        owner.deadline = Instant::now() - Duration::from_secs(1);
        let runtime = tempfile::tempdir().unwrap();
        let mut spec = namespace_for_source(&owner, runtime.path());
        let before = spec.clone();
        owner.protect_workspace(7, &mut spec).unwrap();
        assert_eq!(spec.rw_binds, before.rw_binds[1..]);
        assert_eq!(spec.ro_binds.last(), before.rw_binds.first());
        assert!(
            spec.rw_binds
                .iter()
                .all(|bind| bind.visible != std::path::Path::new(layout::WORKSPACE))
        );
        assert_eq!(spec.env, before.env);
        assert_eq!(spec.cwd, before.cwd);
        assert_eq!(
            std::fs::read(owner.receiver.sealed_root().unwrap().join("src/lib.rs")).unwrap(),
            b"source\0\xff"
        );
        let mut foreign_spec = before.clone();
        assert!(owner.protect_workspace(8, &mut foreign_spec).is_err());
        assert_eq!(foreign_spec, before);
    }

    #[test]
    fn source_mount_mismatch_shadowing_and_writable_aliases_refuse() {
        use rabs_sandbox::canonical_namespace::Bind;
        use std::os::unix::fs::symlink;
        let (mut state, request, _, seal) = uploaded();
        state.handle(&seal, true, false).unwrap();
        let owner = state.take_prepared(&request).unwrap().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let root = owner.receiver.sealed_root().unwrap();
        let alias = runtime.path().join("source-alias");
        symlink(root, &alias).unwrap();
        for variant in 0..7 {
            let mut spec = namespace_for_source(&owner, runtime.path());
            match variant {
                0 => spec.rw_binds[0].backing = runtime.path().to_path_buf(),
                1 => spec.rw_binds.push(spec.rw_binds[0].clone()),
                2 => spec.ro_binds.push(spec.rw_binds[0].clone()),
                3 => spec
                    .rw_binds
                    .push(Bind::new(runtime.path(), "/__rabs/workspace/src")),
                4 => spec.rw_binds[1].backing = root.to_path_buf(),
                5 => spec.rw_binds[1].backing = owner._directory.path().to_path_buf(),
                _ => spec.rw_binds[1].backing = alias.clone(),
            }
            let before = spec.clone();
            assert!(
                owner.protect_workspace(7, &mut spec).is_err(),
                "accepted variant {variant}"
            );
            assert_eq!(spec, before, "refusal changed variant {variant}");
        }
    }

    fn assert_not_admissible(state: &mut SourceTransferState, request: &Value, seal: &Value) {
        assert!(state.handle(seal, true, false).is_err());
        assert!(state.prepared_path(request, true).is_err());
        assert!(state.take_prepared(request).is_err());
        assert!(
            state.pending.is_some(),
            "failed input ownership remains with this session"
        );
    }

    #[test]
    fn changed_staged_bytes_never_become_an_execution_source() {
        let (mut state, request, begin, seal) = uploaded();
        let original = request.clone();
        let path = state
            .pending
            .as_ref()
            .unwrap()
            ._directory
            .path()
            .join("workspace/src/lib.rs");
        std::fs::write(&path, b"edited\0\xff").unwrap();
        assert_not_admissible(&mut state, &request, &seal);
        // The original identity cannot be reused to bless repaired or changed
        // bytes after a failed seal, nor does re-begin reset the poisoned stage.
        std::fs::write(&path, b"source\0\xff").unwrap();
        assert_eq!(state.handle(&begin, true, false).unwrap()["sealed"], false);
        assert_not_admissible(&mut state, &request, &seal);
        assert_eq!(
            request, original,
            "worker paths never rewrite the journal request"
        );
    }

    #[test]
    fn unrequested_cargo_configuration_and_empty_directories_refuse_admission() {
        for extra in [".cargo/config.toml", ".git/HEAD", "unrequested-directory"] {
            let (mut state, request, _, seal) = uploaded();
            let root = state
                .pending
                .as_ref()
                .unwrap()
                ._directory
                .path()
                .join("workspace");
            let path = root.join(extra);
            if extra == "unrequested-directory" {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, b"unrequested input").unwrap();
            }
            assert_not_admissible(&mut state, &request, &seal);
        }
    }

    #[test]
    fn a_redirected_source_directory_cannot_be_handed_to_the_executor() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (mut state, request, _, seal) = uploaded();
        let private = state
            .pending
            .as_ref()
            .unwrap()
            ._directory
            .path()
            .to_path_buf();
        let outside = private.join("outside");
        std::fs::rename(private.join("workspace/src"), &outside).unwrap();
        symlink(&outside, private.join("workspace/src")).unwrap();
        assert_not_admissible(&mut state, &request, &seal);
        let file = outside.join("lib.rs");
        assert_eq!(std::fs::read(&file).unwrap(), b"source\0\xff");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn verified_but_late_seal_never_acknowledges_readiness_or_transfers_ownership() {
        let (mut state, request, begin, seal) = uploaded();
        let owner = state.pending.as_mut().unwrap();
        // Drive the actual post-I/O readiness frontier with a completed seal
        // and an expired budget, without timing-dependent sleeps or fake IO.
        owner.receiver.seal().unwrap();
        owner.deadline = Instant::now() - Duration::from_secs(1);
        assert!(owner.ready().is_err());
        assert!(state.handle(&begin, true, false).is_err());
        assert_not_admissible(&mut state, &request, &seal);
    }

    #[test]
    fn successful_sealing_and_repeated_begin_never_renew_the_upload_budget() {
        let (mut state, request, begin, seal) = uploaded();
        let deadline = state.pending.as_ref().unwrap().deadline;
        assert_eq!(state.handle(&begin, true, false).unwrap()["sealed"], false);
        assert_eq!(state.pending.as_ref().unwrap().deadline, deadline);
        let ready = state.handle(&seal, true, false).unwrap();
        assert_eq!(ready["sealed"], true);
        assert_eq!(ready["request_id"], request["request_id"]);
        assert_eq!(
            ready["manifest_sha256"],
            request["source_manifest"]["manifest_sha256"]
        );
        assert_eq!(state.handle(&begin, true, false).unwrap(), ready);
        assert_eq!(state.pending.as_ref().unwrap().deadline, deadline);
        let path = state.prepared_path(&request, true).unwrap().unwrap();
        let owner = state.take_prepared(&request).unwrap().unwrap();
        assert!(state.pending.is_none());
        assert_eq!(owner.deadline, deadline);
        assert_eq!(
            std::fs::read(std::path::Path::new(&path).join("src/lib.rs")).unwrap(),
            b"source\0\xff"
        );
    }

    #[test]
    fn cached_bytes_do_not_authorize_extra_inputs_or_a_changed_private_copy() {
        let cache = tempfile::tempdir().unwrap();
        let manifest = projection(&[("lib.rs", b"good", false)]);
        let mut cold = cached_state(cache.path());
        cold.handle(&begin(&manifest, 1), true, false).unwrap();
        upload(&mut cold, &manifest, 1, "lib.rs", b"good");
        cold.handle(&seal(&manifest, 1), true, false).unwrap();
        for extra_file in [false, true] {
            let mut warm = cached_state(cache.path());
            let start = warm.handle(&begin(&manifest, 2), true, false).unwrap();
            assert_eq!(start["missing_files"], json!([]));
            assert_eq!(start["sealed"], false);
            let root = warm
                .pending
                .as_ref()
                .unwrap()
                ._directory
                .path()
                .join("workspace");
            if extra_file {
                std::fs::create_dir(root.join(".cargo")).unwrap();
                std::fs::write(root.join(".cargo/config.toml"), b"unexpected configuration")
                    .unwrap();
            } else {
                std::fs::write(root.join("lib.rs"), b"evil").unwrap();
            }
            let request =
                json!({"kind":"canonical-exec", "request_id":2, "source_manifest":manifest});
            assert_not_admissible(&mut warm, &request, &seal(&manifest, 2));
            let cached = cache
                .path()
                .join("source-files-v1")
                .join(format!("{}.src", hex(&Sha256::digest(b"good"))));
            assert_eq!(
                std::fs::read(cached).unwrap(),
                b"good",
                "a bad stage never reseeds the cache"
            );
        }
    }

    #[test]
    fn unprepared_source_fields_refuse_before_worker_local_or_uploaded_admission() {
        for field in ["source_files", "source_roots"] {
            for value in [
                Value::Null,
                json!([]),
                json!({"host":"private-local-marker"}),
            ] {
                for uploaded in [false, true] {
                    let mut request = json!({"kind":"canonical-exec", "request_id":7});
                    if uploaded {
                        request["source_manifest"] = manifest();
                    } else {
                        request["workspace_backing"] = json!("/worker/workspace");
                    }
                    request[field] = value.clone();
                    let before = request.clone();
                    let error = request_manifest(&request).unwrap_err();
                    assert!(error.contains("--worker-prepare"));
                    assert!(!error.contains("private-local-marker"));
                    let mut state = SourceTransferState::default();
                    for enabled in [false, true] {
                        assert!(state.prepared_path(&request, enabled).is_err());
                    }
                    assert!(state.take_prepared(&request).is_err());
                    assert!(state.pending.is_none());
                    assert_eq!(request, before);
                }
            }
        }
        let request = json!({"kind":"canonical-exec", "request_id":7, "workspace_backing":"/worker/workspace"});
        assert!(request_manifest(&request).unwrap().is_none());
        assert!(
            SourceTransferState::default()
                .take_prepared(&request)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejected_preparation_cannot_consume_an_existing_sealed_source_owner() {
        let (mut state, request, _, seal) = uploaded();
        state.handle(&seal, true, false).unwrap();
        let path = state.prepared_path(&request, true).unwrap();
        for field in ["source_files", "source_roots"] {
            let mut bad = request.clone();
            bad[field] = Value::Null;
            assert!(state.prepared_path(&bad, true).is_err());
            assert!(state.take_prepared(&bad).is_err());
            assert!(state.pending.is_some());
            assert_eq!(state.prepared_path(&request, true).unwrap(), path);
        }
        let owner = state.take_prepared(&request).unwrap().unwrap();
        assert_eq!(
            std::fs::read(owner.receiver.sealed_root().unwrap().join("src/lib.rs")).unwrap(),
            b"source\0\xff"
        );
        assert!(state.pending.is_none());
    }

    #[test]
    fn multi_repository_projection_uses_the_same_seal_and_read_only_owner() {
        let files: [(&str, &[u8], bool); 2] = [
            (
                "app/Cargo.toml",
                b"[dependencies]\ndep={path=\"../dep\"}\n",
                false,
            ),
            ("dep/src/lib.rs", b"pub fn answer() -> u32 { 42 }\n", false),
        ];
        let manifest = projection(&files);
        let request = json!({"kind":"canonical-exec", "request_id":17, "source_manifest":manifest});
        let mut state = SourceTransferState::default();
        state
            .handle(
                &json!({"kind":"source-begin", "request_id":17, "manifest":manifest}),
                true,
                false,
            )
            .unwrap();
        for (path, bytes, _) in files {
            upload(&mut state, &manifest, 17, path, bytes);
        }
        assert!(state.prepared_path(&request, true).is_err());
        state.handle(&seal(&manifest, 17), true, false).unwrap();
        let owner = state.take_prepared(&request).unwrap().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let mut spec = namespace_for_source(&owner, runtime.path());
        owner.protect_workspace(17, &mut spec).unwrap();
        let root = owner.receiver.sealed_root().unwrap();
        for (path, bytes, _) in files {
            assert_eq!(std::fs::read(root.join(path)).unwrap(), bytes);
        }
        assert!(
            spec.rw_binds
                .iter()
                .all(|bind| bind.visible != std::path::Path::new(rabs_sandbox::layout::WORKSPACE))
        );
        assert_eq!(request["source_manifest"], manifest);
    }
}
