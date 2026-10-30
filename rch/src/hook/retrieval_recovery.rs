//! Durable source ownership and identity-bound collection. Never replays a command.
use super::super::artifact_patterns::direct_compiler::{
    NativeOutputContract, native_output_contract,
};
use super::super::cargo_output_contract::{
    CargoCallerPaths, CargoOutputCapture, CargoOutputContract,
};
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

#[cfg(unix)]
#[path = "publication_copy.rs"]
mod publication_copy;
#[cfg(unix)]
use publication_copy::prepare_output_temporary;

#[path = "publication_runtime.rs"]
mod publication_runtime;
use publication_runtime::PublicationPoint;
#[cfg(all(test, unix))]
#[path = "publication_runtime_tests.rs"]
mod publication_runtime_tests;

#[path = "recovery_completion.rs"]
mod recovery_completion;
pub(crate) use recovery_completion::{daemon_absence_is_conclusive, unix_ms_now};
#[path = "recovery_owner.rs"]
pub(in crate::hook) mod recovery_owner;
#[path = "result_recovery.rs"]
mod result_recovery;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecoveryRecipe {
    version: u32,
    wrapper_id: String,
    build_id: u64,
    worker: WorkerConfig,
    identity: String,
    completion: String,
    source_roots: Vec<String>,
    /// Current admissions record this before any worker request. Legacy
    /// journals discover one exact registry and persist it before recovery
    /// mutates a claim, pair, source tree, or cancellation receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_authority_namespace: Option<SourceAuthorityNamespace>,
    pair: Option<(String, String)>,
    retire_root: Option<String>,
    /// An owned source pair retires by moving to this exact sibling. Persist
    /// both names before acquisition so recovery never invents new authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retained_root: Option<String>,
    /// True acknowledges a durable retained tree. False records preparation
    /// that never materialized source; it is not a retained-source receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retained_materialized: Option<bool>,
    transfer: TransferConfig,
    project_root: PathBuf,
    kind: Option<CompilationKind>,
    expected_triple: String,
    pinned_triple: Option<String>,
    allow_foreign: bool,
    package_archive: bool,
    /// Persisted before execution: a successful captured build cannot publish
    /// until its complete, same-attempt Cargo receipt supplies the output set.
    #[serde(default)]
    cargo_output_capture: Option<CargoOutputCapture>,
    /// Complete same-attempt stdout retained outside disposable staging trees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cargo_stdout: Option<RetainedCargoStdout>,
    /// Complete diagnostics retained before retirement can remove the log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cargo_stderr: Option<RetainedCargoStderr>,
    /// Persist the caller's output contract before execution so detached
    /// recovery cannot downgrade it to ordinary glob-only Cargo delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_json_policy: Option<PathBuf>,
    /// Persist the first caller-visible paths and bytes before worker release.
    /// Recovery must not project a later build's shared target files instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_delivery: Option<RetainedCargoDelivery>,
    phases: Vec<RecoveryPhase>,
    exit_code: Option<i32>,
    returned: Option<i32>,
    /// Daemon accounting may have completed earlier through cancellation.
    /// Preserve its outcome independently of command and artifact delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    daemon_exit_code: Option<i32>,
    /// The daemon had no record of a long-dead build when its recovery
    /// settled, so it held no reservation to release (bd-ey7fr).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    daemon_record_absent: bool,
    #[serde(default)]
    prepared: bool,
    #[serde(default)]
    execution_started: bool,
    #[serde(default)]
    preparation_cancelled: bool,
    /// Cancellation is not settled by a local terminal acknowledgement. False
    /// is persisted before worker cancellation; true follows an exact worker
    /// receipt under its activity and metadata locks. None also covers legacy
    /// preparation cancellations, which still need that reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_cancellation_settled: Option<bool>,
    #[serde(default)]
    sources_released: bool,
    #[serde(default)]
    tree_retired: bool,
    #[serde(default)]
    pair_released: bool,
    #[serde(default)]
    retired: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct RetainedCargoStdout {
    path: PathBuf,
    blake3: String,
    bytes: u64,
    remote_root: PathBuf,
    // Ordinary artifact evidence does not observe the physical source root.
    // Old caller-JSON receipts deserialize their existing path as Some(path).
    #[serde(default)]
    remote_project_root: Option<PathBuf>,
    exit_code: i32,
}

#[derive(Clone, Serialize, Deserialize)]
struct RetainedCargoStderr {
    path: PathBuf,
    blake3: String,
    bytes: u64,
    exit_code: i32,
}

impl RetainedCargoStderr {
    fn read(&self) -> anyhow::Result<Vec<u8>> {
        let limit = super::super::cargo_output_contract::MAX_CARGO_OUTPUT_RECEIPT_BYTES;
        anyhow::ensure!(
            self.bytes <= limit as u64,
            "retained Cargo stderr exceeds its bound"
        );
        let metadata = std::fs::symlink_metadata(&self.path)?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "retained Cargo stderr is not a regular file"
        );
        let mut file = File::open(&self.path)?.take(limit as u64 + 1);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 == self.bytes
                && blake3::hash(&bytes).to_hex().to_string() == self.blake3,
            "retained Cargo stderr failed its exact byte binding"
        );
        Ok(bytes)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RetainedCargoDelivery {
    path: PathBuf,
    blake3: String,
    bytes: u64,
    producer_blake3: String,
    output_root: PathBuf,
    files: BTreeMap<PathBuf, String>,
}

impl RetainedCargoDelivery {
    fn read(&self, producer: &RetainedCargoStdout) -> anyhow::Result<Vec<u8>> {
        // Re-read the real producer too. A stored hash string alone cannot
        // replace the immutable same-attempt receipt that authorized delivery.
        producer.read()?;
        anyhow::ensure!(
            self.producer_blake3 == producer.blake3 && producer.exit_code == 0,
            "caller Cargo delivery contradicts its producer receipt"
        );
        let limit = super::super::cargo_output_contract::MAX_CARGO_OUTPUT_RECEIPT_BYTES
            .checked_mul(2)
            .context("caller Cargo JSON size limit overflow")?;
        anyhow::ensure!(
            self.bytes <= limit as u64,
            "retained caller Cargo JSON exceeds its bound"
        );
        let metadata = std::fs::symlink_metadata(&self.path)?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "retained caller Cargo JSON is not a regular file"
        );
        let mut file = File::open(&self.path)?.take(limit as u64 + 1);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 == self.bytes
                && blake3::hash(&bytes).to_hex().to_string() == self.blake3,
            "retained caller Cargo JSON failed its exact byte binding"
        );
        CargoOutputContract {
            required_files: self.files.keys().cloned().collect(),
        }
        .verify_staged(&self.output_root)?;
        for (relative, expected) in &self.files {
            anyhow::ensure!(
                fingerprint(&self.output_root.join(relative))?.as_ref() == Some(expected),
                "retained caller Cargo output changed: {}",
                relative.display()
            );
        }
        Ok(bytes)
    }
}

fn retain_cargo_bytes(wrapper: &str, label: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    let path =
        default_job_lease_directory().join(format!("{wrapper}.{label}-{}", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .context("retained Cargo bytes have no parent")?,
    )?
    .sync_all()?;
    Ok(path)
}

impl RetainedCargoStdout {
    fn read(&self) -> anyhow::Result<Vec<u8>> {
        let limit = super::super::cargo_output_contract::MAX_CARGO_OUTPUT_RECEIPT_BYTES;
        anyhow::ensure!(
            self.bytes <= limit as u64,
            "retained Cargo stdout exceeds its receipt bound"
        );
        let metadata = std::fs::symlink_metadata(&self.path)
            .context("retained Cargo stdout producer metadata is unavailable")?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "retained Cargo stdout is not a regular file"
        );
        // The pathname check alone races a symlink/FIFO replacement. On Unix,
        // open the leaf without following it or blocking on a special file.
        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags};
            File::from(rustix::fs::open(
                &self.path,
                OFlags::RDONLY
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::empty(),
            )?)
        };
        #[cfg(not(unix))]
        let file = File::open(&self.path)?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "retained Cargo stdout is not a regular file"
        );
        let mut file = file.take(limit as u64 + 1);
        let mut stdout = Vec::new();
        file.read_to_end(&mut stdout)?;
        anyhow::ensure!(
            stdout.len() as u64 == self.bytes
                && blake3::hash(&stdout).to_hex().to_string() == self.blake3,
            "retained Cargo stdout bytes failed their exact invocation binding"
        );
        Ok(stdout)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RecoveryPhase {
    name: String,
    local: PathBuf,
    remote: String,
    patterns: Vec<String>,
    result_dir: Option<PathBuf>,
    custom_target: bool,
    output_gate: bool,
    #[serde(default)]
    cargo_outputs: Option<CargoOutputContract>,
    /// Exact native-driver files, known before execution and independent of
    /// Cargo's target directory or target-root output gate.
    #[serde(default)]
    native_outputs: Option<NativeOutputContract>,
    /// Predecessors observed under the publication lock. A pending rename
    /// keeps its predecessor until the published checkpoint is durable.
    baseline: BTreeMap<PathBuf, String>,
    published: BTreeMap<PathBuf, String>,
    #[serde(default)]
    pending: Option<(PathBuf, String)>,
    complete: bool,
    /// A failed delivery is terminal evidence, not a completed publication.
    #[serde(default)]
    missing_result: Option<result_recovery::MissingResult>,
}

pub(crate) struct RecoverySession {
    recipe: RecoveryRecipe,
    writer: DurableLeaseWriter,
}

/// An immutable, complete receipt cannot satisfy this invocation's contract.
/// Keep this separate from local journal I/O, which a collector may retry.
#[derive(Debug, thiserror::Error)]
#[error("invalid Cargo executable evidence: {0:#}")]
pub(super) struct CargoOutputContractRejected(anyhow::Error);

fn fingerprint(path: &Path) -> anyhow::Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "output is not a regular file: {}",
        path.display()
    );
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut bytes = [0u8; 65536];
    loop {
        publication_runtime::checkpoint()?;
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hasher.update(&bytes[..count]);
    }
    Ok(Some(hasher.finalize().to_hex().to_string()))
}

/// The caller may choose a symlinked root, but descendants must not redirect
/// either normal publication or a journaled pending output outside that root.
fn validate_output_ancestors(root: &Path, relative: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        !relative.as_os_str().is_empty()
            && relative
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
        "output publication requires a root-relative file path"
    );
    let destination = root.join(relative);
    let mut ancestor = destination.parent();
    while let Some(path) = ancestor {
        if path == root {
            break;
        }
        anyhow::ensure!(
            path.starts_with(root),
            "output ancestor escaped its phase root"
        );
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "output ancestor is a symlink: {}",
                    path.display()
                );
                anyhow::ensure!(
                    metadata.is_dir(),
                    "output ancestor is not a directory: {}",
                    path.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect output ancestor {}", path.display()));
            }
        }
        ancestor = path.parent();
    }
    Ok(())
}

fn copy_published_output(
    source_path: &Path,
    destination: &Path,
    expected: &str,
) -> anyhow::Result<File> {
    let mut source = File::open(source_path)?;
    let metadata = source.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "published Cargo output is not a regular file"
    );
    let length = metadata.len();
    let bound = length
        .checked_add(1)
        .context("published Cargo output length overflow")?;
    std::fs::create_dir_all(
        destination
            .parent()
            .context("caller Cargo output has no parent")?,
    )?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut copy = options.open(destination)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];
    let mut count_total = 0u64;
    let mut reader = (&mut source).take(bound);
    loop {
        publication_runtime::checkpoint()?;
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        count_total += count as u64;
        hasher.update(&buffer[..count]);
        copy.write_all(&buffer[..count])?;
    }
    anyhow::ensure!(
        count_total == length && hasher.finalize().to_hex().to_string() == expected,
        "published Cargo output changed before stdout delivery: {}",
        source_path.display()
    );
    copy.sync_all()?;
    copy.set_permissions(metadata.permissions())?;
    copy.sync_all()?;
    Ok(copy)
}

/// Keep the original directory and file alive through checkpoint publication.
/// Names are only accepted when they still identify these held descriptors.
struct PreparedOutput {
    file: File,
    directory: File,
    parent: PathBuf,
    temporary: PathBuf,
    expected_hash: String,
    length: u64,
    #[cfg(unix)]
    mode: u32,
}

impl PreparedOutput {
    fn existing(directory: File, temporary: &Path, expected: &str) -> anyhow::Result<Self> {
        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags};
            use std::os::fd::AsFd;
            File::from(rustix::fs::openat(
                directory.as_fd(),
                temporary
                    .file_name()
                    .context("output temporary has no name")?,
                OFlags::RDONLY
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::empty(),
            )?)
        };
        #[cfg(not(unix))]
        let file = File::open(temporary)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file(),
            "retained temporary is not a regular file"
        );
        let prepared = Self::hold(file, directory, temporary, expected)?;
        prepared.file.sync_all()?;
        Ok(prepared)
    }

    fn hold(file: File, directory: File, temporary: &Path, expected: &str) -> anyhow::Result<Self> {
        let length = file.metadata()?.len();
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::MetadataExt;
            file.metadata()?.mode() & 0o7777
        };
        let prepared = Self {
            file,
            directory,
            parent: temporary
                .parent()
                .context("output temporary has no parent")?
                .to_owned(),
            temporary: temporary.to_owned(),
            expected_hash: expected.to_owned(),
            length,
            #[cfg(unix)]
            mode,
        };
        prepared.verify_name(temporary)?;
        if let Err(error) = prepared.verify_content() {
            if error.is::<publication_runtime::PublicationCancelled>() {
                // A cancelled full-byte check must retain its private copy,
                // with the same best-effort salvage as interrupted writes.
                let _ = prepared.file.sync_all();
                let _ = prepared.directory.sync_all();
            }
            return Err(error);
        }
        Ok(prepared)
    }

    fn verify_content(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.file.metadata()?.len() == self.length,
            "prepared output length changed"
        );
        let bound = self
            .length
            .checked_add(1)
            .context("temporary output length overflow")?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 65536];
        let mut offset = 0u64;
        #[cfg(not(unix))]
        let mut reader = {
            use std::io::{Seek, SeekFrom};
            let mut reader = self.file.try_clone()?;
            reader.seek(SeekFrom::Start(0))?;
            reader
        };
        while offset < bound {
            publication_runtime::checkpoint()?;
            let size = (bound - offset).min(buffer.len() as u64) as usize;
            #[cfg(unix)]
            let count = {
                use std::os::unix::fs::FileExt;
                // Cloned file handles share their cursor. Positional reads
                // always hash the held bytes from zero without moving it.
                self.file.read_at(&mut buffer[..size], offset)?
            };
            #[cfg(not(unix))]
            let count = reader.read(&mut buffer[..size])?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            offset += count as u64;
        }
        anyhow::ensure!(
            offset == self.length
                && self.file.metadata()?.len() == self.length
                && hasher.finalize().to_hex().as_str() == self.expected_hash,
            "prepared output bytes changed: {}; publication unverified",
            self.temporary.display()
        );
        Ok(())
    }

    fn verify_name(&self, path: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(
            path.parent() == Some(self.parent.as_path()),
            "output publication parent changed"
        );
        anyhow::ensure!(
            self.file.metadata()?.is_file(),
            "prepared output is not a regular file"
        );
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags};
            use std::os::fd::AsFd;
            use std::os::unix::fs::MetadataExt;
            let held_directory = self.directory.metadata()?;
            // The caller may choose a symlinked output root; compare its
            // physical referent with the directory held before preparation.
            let named_directory = std::fs::metadata(&self.parent)?;
            anyhow::ensure!(
                held_directory.is_dir()
                    && named_directory.is_dir()
                    && held_directory.dev() == named_directory.dev()
                    && held_directory.ino() == named_directory.ino(),
                "output publication directory changed"
            );
            let named = File::from(rustix::fs::openat(
                self.directory.as_fd(),
                path.file_name().context("output publication has no name")?,
                OFlags::RDONLY
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::empty(),
            )?);
            let held = self.file.metadata()?;
            let named = named.metadata()?;
            anyhow::ensure!(
                held.is_file()
                    && named.is_file()
                    && held.dev() == named.dev()
                    && held.ino() == named.ino()
                    && held.nlink() == 1
                    && named.nlink() == 1
                    && held.mode() & 0o7777 == self.mode
                    && named.mode() & 0o7777 == self.mode,
                "prepared output identity, permissions or links changed"
            );
        }
        Ok(())
    }

    fn publish(&self, destination: &Path) -> anyhow::Result<()> {
        self.verify_name(&self.temporary)?;
        self.verify_content()?;
        publication_runtime::checkpoint()?;
        anyhow::ensure!(
            destination.parent() == Some(self.parent.as_path()),
            "output destination parent changed"
        );
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            rustix::fs::renameat(
                self.directory.as_fd(),
                self.temporary
                    .file_name()
                    .context("output temporary has no name")?,
                self.directory.as_fd(),
                destination
                    .file_name()
                    .context("output destination has no name")?,
            )?;
        }
        #[cfg(not(unix))]
        std::fs::rename(&self.temporary, destination)?;
        self.verify_name(destination)?;
        self.directory.sync_all()?;
        self.verify_name(destination)?;
        self.verify_content()
    }
}

/// A failed pending checkpoint can leave this wrapper's unjournaled copy.
/// Reuse only the exact staged bytes and permissions; never truncate a prior
/// temporary file or discard a conflicting/partial copy to force a retry.
#[cfg(not(unix))]
fn prepare_output_temporary(
    source: &Path,
    temporary: &Path,
    expected: &str,
) -> anyhow::Result<PreparedOutput> {
    let parent = temporary
        .parent()
        .context("output temporary has no parent")?;
    std::fs::create_dir_all(parent)?;
    let directory = File::open(parent)?;
    anyhow::ensure!(
        directory.metadata()?.is_dir(),
        "output parent is not a directory"
    );
    match std::fs::symlink_metadata(temporary) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = copy_published_output(source, temporary, expected)?;
            PreparedOutput::hold(file, directory, temporary, expected)
        }
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "retained output temporary is not a regular file: {}",
                temporary.display()
            );
            let source_metadata = std::fs::symlink_metadata(source)?;
            anyhow::ensure!(
                source_metadata.is_file(),
                "staged output is not a regular file"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.nlink() == 1
                        && metadata.mode() & 0o7777 == source_metadata.mode() & 0o7777,
                    "retained output temporary permissions or links changed: {}",
                    temporary.display()
                );
            }
            #[cfg(not(unix))]
            anyhow::ensure!(
                metadata.permissions().readonly() == source_metadata.permissions().readonly(),
                "retained output temporary permissions changed"
            );
            let prepared = PreparedOutput::existing(directory, temporary, expected)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                anyhow::ensure!(
                    prepared.mode == source_metadata.mode() & 0o7777,
                    "held retained temporary permissions differ from staged output"
                );
            }
            Ok(prepared)
        }
    }
}

// Unix publication reads the stage through `staged_inventory` instead.
#[cfg(any(not(unix), test))]
fn regular_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    fn visit(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        if !directory.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(directory)? {
            publication_runtime::checkpoint()?;
            let entry = entry?;
            let kind = entry.file_type()?;
            anyhow::ensure!(
                !kind.is_symlink(),
                "symlink in recovery output: {}",
                entry.path().display()
            );
            if kind.is_dir() {
                visit(root, &entry.path(), files)?;
            } else if kind.is_file() {
                files.push(entry.path().strip_prefix(root)?.to_owned());
            } else {
                anyhow::bail!("non-regular recovery output: {}", entry.path().display());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

/// How long a publication waits for another wrapper's publication into the
/// same local output root. Large artifact sets can take minutes to publish;
/// the bound turns a wedged holder into an error without blocking the executor.
const OUTPUT_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(600);

/// Different spellings of one output directory must share publication
/// ownership. Resolve existing prefixes without creating a fresh target tree;
/// missing suffixes keep the same identity after another job creates them.
/// Resolve a symlink before applying a following `..`, as the filesystem does.
fn output_lock_root_identity(root: &Path) -> anyhow::Result<PathBuf> {
    Ok(output_root_identity_and_existing_prefix(root)?.0)
}

fn output_root_identity_and_existing_prefix(root: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    use std::path::Component;

    let absolute = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir()?.join(root)
    };
    let mut resolved = PathBuf::new();
    let mut existing = PathBuf::new();
    let mut missing_suffix = false;
    for component in absolute.components() {
        match component {
            Component::Prefix(_) => anyhow::bail!(
                "output publication requires a Unix directory path: {}",
                root.display()
            ),
            Component::RootDir => {
                resolved.push(component.as_os_str());
                existing.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
                if missing_suffix && resolved.exists() {
                    let canonical = std::fs::canonicalize(&resolved)?;
                    anyhow::ensure!(
                        std::fs::metadata(&canonical)?.is_dir(),
                        "output publication root has a non-directory component: {}",
                        resolved.display()
                    );
                    resolved = canonical;
                    existing = resolved.clone();
                    missing_suffix = false;
                } else if !missing_suffix {
                    existing = resolved.clone();
                }
            }
            Component::Normal(name) => {
                resolved.push(name);
                match std::fs::canonicalize(&resolved) {
                    Ok(canonical) => {
                        anyhow::ensure!(
                            std::fs::metadata(&canonical)?.is_dir(),
                            "output publication root has a non-directory component: {}",
                            resolved.display()
                        );
                        resolved = canonical;
                        existing = resolved.clone();
                        missing_suffix = false;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        // A missing directory is allowed, but a dangling
                        // symlink is not an ordinary missing suffix: treating
                        // it as one would assign a different lock from its
                        // eventual target when that target appears.
                        match std::fs::symlink_metadata(&resolved) {
                            Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {
                                missing_suffix = true;
                            }
                            Ok(_) => {
                                return Err(error).with_context(|| {
                                    format!(
                                        "cannot resolve existing output root entry {}",
                                        resolved.display()
                                    )
                                });
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    anyhow::ensure!(
        !existing.as_os_str().is_empty(),
        "output publication root has no existing ancestor directory: {}",
        root.display()
    );
    Ok((resolved, existing))
}

/// Exclusive ownership of one local output root for the duration of a single
/// phase publication. It is deliberately NOT held across the remote build:
/// dispatchers share one CARGO_TARGET_DIR (and run concurrent jobs in one
/// project), and a job-long lock failed every overlapping build outright.
async fn lock_output_root(root: &Path) -> anyhow::Result<File> {
    let identity = output_lock_root_identity(root)?;
    let directory = default_job_lease_directory().join("output-locks");
    std::fs::create_dir_all(&directory)?;
    let name = blake3::hash(identity.as_os_str().as_encoded_bytes())
        .to_hex()
        .to_string();
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(name))?;
    let deadline = tokio::time::Instant::now() + OUTPUT_LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => {
                anyhow::ensure!(
                    output_lock_root_identity(root)? == identity,
                    "output root changed while waiting for publication ownership: {}; journal retained",
                    root.display()
                );
                return Ok(file);
            }
            Err(std::fs::TryLockError::WouldBlock) if tokio::time::Instant::now() < deadline => {
                // The CLI uses a current-thread runtime. Blocking here stalls
                // heartbeats and prevents the caller's recovery deadline or
                // cancellation from being polled for the whole lock budget.
                // No output or journal has been touched while waiting, so a
                // dropped waiter can safely retry this exact publication.
                let next_poll = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
                tokio::time::sleep_until(next_poll.min(deadline)).await;
            }
            Err(error) => anyhow::bail!(
                "output publication into {} is held by another wrapper: {error}",
                root.display()
            ),
        }
    }
}

fn validate_retained_source_intent(
    source_roots: &[String],
    pair: Option<&(String, String)>,
    retire_root: Option<&str>,
    retained_root: Option<&str>,
    identity: &str,
) -> anyhow::Result<()> {
    let Some(retained) = retained_root else {
        return Ok(());
    };
    let root = retire_root.context("retained source intent has no original source root")?;
    anyhow::ensure!(
        identity.len() == 32
            && identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "retained source identity must be 32 lowercase hexadecimal characters"
    );
    anyhow::ensure!(
        retained == format!("{root}.retained-{identity}")
            && source_roots.iter().any(|path| path == root)
            && source_roots.iter().any(|path| path == retained)
            && pair.is_some_and(|(pair_root, token)| pair_root == root && token == identity),
        "retained source intent must bind the exact pair and both sibling authorities"
    );
    super::super::ssh::validate_source_authority_intent(
        &[root.to_owned(), retained.to_owned()],
        identity,
    )
}

impl RecoverySession {
    /// Save the recovery identity before even a queued remote grant can exist.
    /// Until `starting_execution` is durable, recovery can drain transfers and
    /// cancel this exact preparation without replaying a compiler command.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin(
        writer: &DurableLeaseWriter,
        worker: &WorkerConfig,
        source_roots: Vec<String>,
        pair: Option<(String, String)>,
        retire_root: Option<String>,
        retained_root: Option<String>,
        transfer: TransferConfig,
        project_root: PathBuf,
        identity: String,
    ) -> anyhow::Result<()> {
        let lease = writer.snapshot();
        let build_id = lease
            .identity
            .remote_build_id
            .context("source ownership requires admitted build identity")?;
        anyhow::ensure!(
            lease.worker_id.as_deref() == Some(worker.id.as_str()) && lease.recovery.is_none(),
            "source ownership requires a fresh admitted lease; recover the previous attempt first"
        );
        super::super::ssh::validate_source_authority_intent(&source_roots, &identity)?;
        validate_retained_source_intent(
            &source_roots,
            pair.as_ref(),
            retire_root.as_deref(),
            retained_root.as_deref(),
            &identity,
        )?;
        let completion = format!(
            "{}/recovery-{}-{}.done",
            transfer.remote_base.trim_end_matches('/'),
            build_id,
            identity
        );
        let recipe = RecoveryRecipe {
            version: 2,
            wrapper_id: lease.identity.local_wrapper_id,
            build_id,
            worker: worker.clone(),
            identity,
            completion,
            source_roots,
            source_authority_namespace: Some(SourceAuthorityNamespace::Current),
            pair,
            retire_root,
            retained_root,
            retained_materialized: None,
            transfer,
            project_root,
            kind: None,
            expected_triple: String::new(),
            pinned_triple: None,
            allow_foreign: false,
            package_archive: false,
            cargo_output_capture: None,
            cargo_stdout: None,
            cargo_stderr: None,
            caller_json_policy: None,
            caller_delivery: None,
            phases: Vec::new(),
            exit_code: None,
            returned: None,
            daemon_exit_code: None,
            daemon_record_absent: false,
            prepared: false,
            execution_started: false,
            preparation_cancelled: false,
            source_cancellation_settled: None,
            sources_released: false,
            tree_retired: false,
            pair_released: false,
            retired: false,
        };
        writer.set_recovery(serde_json::to_value(recipe)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        writer: &DurableLeaseWriter,
        worker: &WorkerConfig,
        pipeline: &TransferPipeline,
        source_roots: Vec<String>,
        pair: Option<(String, String)>,
        retire_root: Option<String>,
        retained_root: Option<String>,
        transfer: TransferConfig,
        project_root: PathBuf,
        target: Option<&Path>,
        kind: Option<CompilationKind>,
        command: &str,
        result_dirs: &[PathBuf],
        identity: String,
    ) -> anyhow::Result<Self> {
        // Persist the output contract, not runtime-test policy: recovery is
        // collection-only and has no command to reparse after the wrapper dies.
        // The phase patterns below take the command's OWN kind, exactly as the
        // live retrieval does: from the delivery kind they lose the build-only
        // test/bench carve-out, and publication then skipped the very
        // executables the live retrieval fetched (bd-b7lot, seen live).
        let delivery_kind = artifact_delivery_kind(kind, Some(command));
        let lease = writer.snapshot();
        let intent: RecoveryRecipe = serde_json::from_value(
            lease
                .recovery
                .clone()
                .context("output preparation requires the persisted source intent")?,
        )?;
        anyhow::ensure!(
            intent.version == 2
                && intent.identity == identity
                && intent.source_authority_namespace == Some(SourceAuthorityNamespace::Current)
                && intent.wrapper_id == lease.identity.local_wrapper_id
                && Some(intent.build_id) == lease.identity.remote_build_id
                && intent.worker.id == worker.id
                && intent.source_roots == source_roots
                && intent.pair == pair
                && intent.retire_root == retire_root
                && intent.retained_root == retained_root
                && intent.retained_materialized.is_none()
                && !intent.tree_retired
                && !intent.execution_started
                && !intent.preparation_cancelled
                && !intent.retired,
            "output preparation cannot replace another source ownership intent"
        );
        let build_id = lease
            .identity
            .remote_build_id
            .context("recovery requires admitted build identity")?;
        let completion = format!(
            "{}/recovery-{}-{}.done",
            transfer.remote_base.trim_end_matches('/'),
            build_id,
            identity
        );
        let mut phases = Vec::new();
        let native_outputs = (!WorkerPlatform::from_worker(worker).is_windows())
            .then(|| native_output_contract(kind, command, true))
            .flatten();
        let project_patterns = match &native_outputs {
            Some(contract) => contract.patterns()?,
            None => get_project_artifact_patterns(kind, Some(command), target.is_some()),
        };
        let native_project_outputs = native_outputs.is_some();
        if !project_patterns.is_empty() {
            phases.push(RecoveryPhase {
                name: "project".into(),
                local: project_root.clone(),
                remote: pipeline.remote_path(),
                patterns: project_patterns,
                result_dir: None,
                custom_target: false,
                output_gate: target.is_none(),
                cargo_outputs: None,
                native_outputs,
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: false,
                missing_result: None,
            });
        }
        if let Some(target) = target.filter(|_| !native_project_outputs) {
            let patterns = get_custom_target_artifact_patterns(kind, Some(command));
            if !patterns.is_empty() {
                phases.push(RecoveryPhase {
                    name: "target".into(),
                    local: target.to_owned(),
                    remote: pipeline.remote_cargo_target_dir(),
                    patterns,
                    result_dir: None,
                    custom_target: true,
                    output_gate: true,
                    cargo_outputs: None,
                    native_outputs: None,
                    baseline: BTreeMap::new(),
                    published: BTreeMap::new(),
                    pending: None,
                    complete: false,
                    missing_result: None,
                });
            }
        }
        for dir in result_dirs {
            phases.push(RecoveryPhase {
                name: format!("result:{}", dir.display()),
                local: project_root.clone(),
                remote: pipeline.remote_path(),
                patterns: Vec::new(),
                result_dir: Some(dir.clone()),
                custom_target: false,
                output_gate: false,
                cargo_outputs: None,
                native_outputs: None,
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: false,
                missing_result: None,
            });
        }
        // No destination ownership is acquired during the remote build. An
        // eager glob/hash pass over a reused local target is both obsolete by
        // publication time and expensive to carry through every checkpoint.
        // Observe only the admitted staged set under the publication lock,
        // before its first write. Old journals still resolve pending renames
        // against their original predecessor before any baseline is refreshed.
        let cargo_output_capture = CargoOutputCapture::for_command(kind, command);
        anyhow::ensure!(
            cargo_output_capture.is_none()
                || phases.iter().filter(|phase| phase.output_gate).count() == 1,
            "captured Cargo execution requires exactly one artifact output root"
        );
        let pinned_triple = explicit_target_triple_for_command(command);
        let recipe = RecoveryRecipe {
            version: 2,
            wrapper_id: lease.identity.local_wrapper_id,
            build_id,
            worker: worker.clone(),
            identity,
            completion,
            source_roots,
            source_authority_namespace: Some(SourceAuthorityNamespace::Current),
            pair,
            retire_root,
            retained_root,
            retained_materialized: None,
            transfer,
            project_root,
            kind: delivery_kind,
            expected_triple: pinned_triple
                .clone()
                .unwrap_or_else(default_host_target_triple),
            pinned_triple,
            allow_foreign: foreign_artifact_gate_disabled(),
            package_archive: sync_back_verified_zero_package_archives(Some(0), command),
            cargo_output_capture,
            cargo_stdout: None,
            cargo_stderr: None,
            caller_json_policy: None,
            caller_delivery: None,
            phases,
            exit_code: None,
            returned: None,
            daemon_exit_code: None,
            daemon_record_absent: false,
            prepared: true,
            execution_started: false,
            preparation_cancelled: false,
            source_cancellation_settled: None,
            sources_released: false,
            tree_retired: false,
            pair_released: false,
            retired: false,
        };
        let session = Self {
            recipe,
            writer: writer.clone(),
        };
        session.persist()?;
        Ok(session)
    }

    fn persist(&self) -> anyhow::Result<()> {
        self.writer
            .set_recovery(serde_json::to_value(&self.recipe)?)
    }
    /// A failed journal publication must not install a successful lifecycle
    /// boundary in this session. Same-session retries use these exact flags.
    fn persist_next_recipe(&mut self, next_recipe: RecoveryRecipe) -> anyhow::Result<()> {
        self.writer
            .set_recovery(serde_json::to_value(&next_recipe)?)?;
        self.recipe = next_recipe;
        Ok(())
    }
    /// Output checkpoints touch only one phase. Keep their undo state small,
    /// but restore the last acknowledged session state on publication failure.
    /// Post-rename sync errors still require durable-state reconciliation.
    fn persist_pending_output(
        &mut self,
        index: usize,
        pending: Option<(PathBuf, String)>,
    ) -> anyhow::Result<()> {
        let previous = std::mem::replace(&mut self.recipe.phases[index].pending, pending);
        if let Err(error) = self.persist() {
            self.recipe.phases[index].pending = previous;
            return Err(error);
        }
        Ok(())
    }

    fn persist_published_output(
        &mut self,
        index: usize,
        relative: PathBuf,
        hash: String,
    ) -> anyhow::Result<()> {
        let phase = &mut self.recipe.phases[index];
        let previous_hash = phase.published.insert(relative.clone(), hash);
        let previous_pending = phase.pending.take();
        // A published receipt replaces the need to remember its predecessor.
        // Retire both in the SAME durable checkpoint, never before the rename
        // has been verified. A failed checkpoint restores all three fields.
        let previous_baseline = phase.baseline.remove(&relative);
        if let Err(error) = self.persist() {
            let phase = &mut self.recipe.phases[index];
            match previous_hash {
                Some(hash) => {
                    phase.published.insert(relative.clone(), hash);
                }
                None => {
                    phase.published.remove(&relative);
                }
            }
            if let Some(hash) = previous_baseline {
                phase.baseline.insert(relative, hash);
            }
            phase.pending = previous_pending;
            return Err(error);
        }
        Ok(())
    }

    /// Compact old preparation-wide baselines only after pending recovery and
    /// complete stage/policy validation, under the same publication lock.
    /// Keep the discarded entries as undo state until the refreshed baseline
    /// is durable. This removes obsolete hashes, not output files or receipts.
    fn persist_publication_baseline(
        &mut self,
        index: usize,
        files: &[PathBuf],
    ) -> anyhow::Result<()> {
        let phase = &mut self.recipe.phases[index];
        anyhow::ensure!(
            phase.pending.is_none(),
            "pending output must be reconciled before baseline compaction"
        );
        let selected: BTreeSet<_> = files.iter().collect();
        let mut discarded = BTreeMap::new();
        for (relative, hash) in std::mem::take(&mut phase.baseline) {
            if selected.contains(&relative) && !phase.published.contains_key(&relative) {
                phase.baseline.insert(relative, hash);
            } else {
                discarded.insert(relative, hash);
            }
        }
        if let Err(error) = self.persist_output_baseline(index, files) {
            // The inner transaction restored selected entries (or made no
            // changes on an inspection/cancellation failure). Restore the
            // pruned entries too, so the borrowed session keeps one epoch.
            self.recipe.phases[index].baseline.extend(discarded);
            return Err(error);
        }
        Ok(())
    }

    fn persist_output_baseline(&mut self, index: usize, files: &[PathBuf]) -> anyhow::Result<()> {
        // A failed fingerprint must not leave half of a new baseline installed.
        // Observe every path before changing any entry, then retain only the
        // entries actually changed as the undo state for a failed publication.
        let phase = &self.recipe.phases[index];
        let mut observations = Vec::new();
        for relative in files {
            publication_runtime::checkpoint()?;
            if !phase.published.contains_key(relative) {
                validate_output_ancestors(&phase.local, relative)?;
                observations.push((relative.clone(), fingerprint(&phase.local.join(relative))?));
            }
        }
        let phase = &mut self.recipe.phases[index];
        let mut previous = Vec::new();
        for (relative, hash) in observations {
            if phase.baseline.get(&relative) == hash.as_ref() {
                continue;
            }
            let old = match hash {
                Some(hash) => phase.baseline.insert(relative.clone(), hash),
                None => phase.baseline.remove(&relative),
            };
            previous.push((relative, old));
        }
        if let Err(error) = self.persist() {
            let phase = &mut self.recipe.phases[index];
            for (relative, hash) in previous.into_iter().rev() {
                match hash {
                    Some(hash) => {
                        phase.baseline.insert(relative, hash);
                    }
                    None => {
                        phase.baseline.remove(&relative);
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn needs_cargo_artifact_evidence(&self) -> bool {
        self.recipe.cargo_output_capture.is_some()
            && self
                .recipe
                .phases
                .iter()
                .any(|phase| phase.output_gate && phase.cargo_outputs.is_none())
    }

    pub(crate) fn request_caller_json(&mut self, remote_project_root: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.recipe.execution_started
                && self.recipe.exit_code.is_none()
                && self
                    .recipe
                    .cargo_output_capture
                    .as_ref()
                    .is_some_and(CargoOutputCapture::caller_json_supported)
                && remote_project_root.is_absolute()
                && !remote_project_root
                    .to_string_lossy()
                    .chars()
                    .any(char::is_control),
            "caller Cargo JSON requires a fresh admitted named-binary contract"
        );
        let mut next_recipe = self.recipe.clone();
        next_recipe.caller_json_policy = Some(remote_project_root.to_owned());
        self.persist_next_recipe(next_recipe)
    }

    /// Live collection and detached recovery share this exact entry point.
    pub(crate) fn install_complete_cargo_evidence(
        &mut self,
        evidence: &crate::transfer::CargoArtifactEvidence,
    ) -> anyhow::Result<()> {
        if self.recipe.caller_json_policy.is_some() {
            anyhow::ensure!(
                evidence.remote_project_root.is_some(),
                "caller Cargo JSON has no verified source root"
            );
        }
        // Preserve complete producer bytes for normal machine consumers too.
        // The optional physical source root is observed only by caller JSON;
        // neither retention nor recovery may invent it for ordinary builds.
        self.retain_cargo_stdout(
            &evidence.stdout,
            &evidence.remote_root,
            evidence.remote_project_root.as_deref(),
            0,
        )?;
        self.install_cargo_artifact_evidence(&evidence.stdout, &evidence.remote_root)
    }

    /// Return only the original completed invocation's retained producer bytes.
    /// A missing old receipt allows worker collection; a corrupt present receipt
    /// is an error, never permission to replace it with a new baseline.
    fn retained_cargo_artifact_evidence(
        &self,
    ) -> anyhow::Result<Option<crate::transfer::CargoArtifactEvidence>> {
        let Some(receipt) = self.recipe.cargo_stdout.as_ref() else {
            return Ok(None);
        };
        anyhow::ensure!(
            self.recipe.execution_started
                && self.recipe.exit_code == Some(0)
                && receipt.exit_code == 0
                && self.recipe.cargo_output_capture.is_some(),
            "retained Cargo artifact evidence contradicts the admitted completion"
        );
        Ok(Some(crate::transfer::CargoArtifactEvidence {
            stdout: receipt.read()?,
            remote_root: receipt.remote_root.clone(),
            remote_project_root: receipt.remote_project_root.clone(),
        }))
    }
    pub(crate) fn cargo_artifact_remote_root(&self) -> Option<&str> {
        self.recipe.cargo_output_capture.as_ref()?;
        self.recipe
            .phases
            .iter()
            .find(|phase| phase.output_gate)
            .map(|phase| phase.remote.as_str())
    }
    /// Complete Cargo evidence authorizes the selected binary executables that
    /// this exact invocation emitted. Persist the contract and transfer policy
    /// together, before either live collection or detached recovery begins.
    pub(crate) fn install_cargo_artifact_evidence(
        &mut self,
        stdout: &[u8],
        canonical_remote_root: &Path,
    ) -> anyhow::Result<()> {
        let prepared = (|| -> anyhow::Result<_> {
            anyhow::ensure!(
                self.recipe.execution_started && self.recipe.exit_code == Some(0),
                "Cargo output evidence requires a successful admitted execution"
            );
            let capture = self
                .recipe
                .cargo_output_capture
                .as_ref()
                .context("this execution did not request Cargo output evidence")?;
            let configured_root = self
                .cargo_artifact_remote_root()
                .context("captured Cargo execution has no artifact output root")?;
            // The transport proved this exact configured path resolves to the
            // canonical root. Cargo can report either spelling (or both); no
            // unrelated suffix/prefix inference can authorize an output.
            let mut contract = capture.parse_receipt_with_roots(
                stdout,
                &[Path::new(configured_root), canonical_remote_root],
            )?;
            if let Some(project) = self.recipe.caller_json_policy.as_deref() {
                let receipt = self.recipe.cargo_stdout.as_ref().context("caller Cargo output requires complete retained producer evidence before publication")?;
                anyhow::ensure!(receipt.exit_code == 0 && receipt.blake3 == blake3::hash(stdout).to_hex().to_string(), "caller Cargo output contradicts its retained producer receipt");
                let source_root = self.recipe.project_root.canonicalize()?;
                contract.required_files.extend(capture.validate_caller_metadata(
                    stdout,
                    &[Path::new(configured_root), canonical_remote_root],
                    &[project, receipt.remote_project_root.as_deref()
                        .context("caller Cargo output has no retained verified source root")?],
                    &source_root,
                )?);
            }
            let index = self
                .recipe
                .phases
                .iter()
                .position(|phase| phase.output_gate)
                .context("captured Cargo execution has no artifact output root")?;
            let phase = &self.recipe.phases[index];
            if let Some(existing) = &phase.cargo_outputs {
                anyhow::ensure!(
                    existing.required_files == contract.required_files,
                    "Cargo output evidence contradicts the persisted required output set"
                );
                return Ok(None);
            }
            anyhow::ensure!(
                !phase.complete && phase.pending.is_none() && phase.published.is_empty(),
                "Cargo output evidence must precede every artifact publication"
            );
            let mut exact_patterns = Vec::new();
            for relative in &contract.required_files {
                // A project-root collection must never promote a source file
                // through the priority include below. With a custom Cargo
                // target, the phase root already is the designated output
                // tree; otherwise outputs must remain beneath target/.
                anyhow::ensure!(
                    phase.custom_target
                        || (relative.starts_with("target") && relative.components().count() > 1),
                    "Cargo output is outside the project's target tree: {}",
                    relative.display()
                );
                let name = relative.to_str().context("non-UTF-8 Cargo output path")?;
                let mut literal = String::with_capacity(name.len());
                for character in name.chars() {
                    if matches!(character, '\\' | '*' | '?' | '[' | ']') {
                        literal.push('\\');
                    }
                    literal.push(character);
                }
                exact_patterns.push(format!("+ {literal}"));
            }
            exact_patterns.extend(phase.patterns.iter().cloned());
            Ok(Some((index, contract, exact_patterns)))
        })()
        .map_err(CargoOutputContractRejected)?;
        let Some((index, contract, patterns)) = prepared else {
            return Ok(());
        };
        let mut next_recipe = self.recipe.clone();
        let phase = &mut next_recipe.phases[index];
        phase.patterns = patterns;
        phase.cargo_outputs = Some(contract);
        self.writer
            .set_recovery(serde_json::to_value(&next_recipe)?)?;
        self.recipe = next_recipe;
        Ok(())
    }
    pub(crate) fn cargo_artifact_patterns(&self, name: &str) -> anyhow::Result<Vec<String>> {
        self.recipe
            .phases
            .iter()
            .find(|phase| phase.name == name)
            .map(|phase| phase.patterns.clone())
            .context("missing retrieval phase")
    }

    /// Preserve the exact producer log before any retirement can remove the
    /// supervisor's copy. A failed write stays retained; a recovery collector
    /// can create a fresh uniquely named copy without overwriting that evidence.
    pub(crate) fn retain_cargo_stdout<'a>(
        &mut self,
        stdout: &[u8],
        remote_root: &Path,
        remote_project_root: impl Into<Option<&'a Path>>,
        exit_code: i32,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recipe.execution_started
                && self.recipe.exit_code == Some(exit_code)
                && self.recipe.cargo_output_capture.is_some(),
            "Cargo stdout requires this admitted invocation's exact completion"
        );
        let remote_project_root = remote_project_root.into();
        anyhow::ensure!(
            self.recipe.caller_json_policy.is_none() || remote_project_root.is_some(),
            "caller Cargo stdout has no observed source root"
        );
        anyhow::ensure!(
            stdout.len() <= super::super::cargo_output_contract::MAX_CARGO_OUTPUT_RECEIPT_BYTES,
            "Cargo stdout exceeds the complete-receipt limit"
        );
        let digest = blake3::hash(stdout).to_hex().to_string();
        if let Some(receipt) = &self.recipe.cargo_stdout {
            anyhow::ensure!(
                receipt.blake3 == digest
                    && receipt.bytes == stdout.len() as u64
                    && receipt.remote_root == remote_root
                    && receipt.remote_project_root.as_deref() == remote_project_root
                    && receipt.exit_code == exit_code
                    && receipt.read()? == stdout,
                "retained Cargo stdout contradicts the completed invocation"
            );
            return Ok(());
        }
        let path = retain_cargo_bytes(&self.recipe.wrapper_id, "cargo-stdout", stdout)?;
        let mut next_recipe = self.recipe.clone();
        next_recipe.cargo_stdout = Some(RetainedCargoStdout {
            path,
            blake3: digest,
            bytes: stdout.len() as u64,
            remote_root: remote_root.to_owned(),
            remote_project_root: remote_project_root.map(Path::to_path_buf),
            exit_code,
        });
        self.writer
            .set_recovery(serde_json::to_value(&next_recipe)?)?;
        self.recipe = next_recipe;
        Ok(())
    }

    pub(crate) async fn collect_cargo_stderr(
        &mut self,
        pipeline: &TransferPipeline,
        worker: &WorkerConfig,
    ) -> anyhow::Result<()> {
        let Some(project) = self.recipe.caller_json_policy.clone() else {
            return Ok(());
        };
        let exit = self
            .recipe
            .exit_code
            .context("Cargo diagnostics have no exact completion")?;
        if let Some(receipt) = self.recipe.cargo_stderr.as_ref() {
            anyhow::ensure!(
                receipt.exit_code == exit,
                "Cargo stderr contradicts its completion"
            );
            receipt.read()?;
            return Ok(());
        }
        anyhow::ensure!(
            self.recipe.execution_started,
            "Cargo stderr has no admitted invocation"
        );
        let bytes = pipeline
            .clone()
            .with_remote_path_override(
                project
                    .to_str()
                    .context("persisted Cargo source root is not UTF-8")?,
            )
            .read_cargo_stderr_evidence(worker, exit)
            .await?;
        let path = retain_cargo_bytes(&self.recipe.wrapper_id, "cargo-stderr", &bytes)?;
        let receipt = RetainedCargoStderr {
            path,
            blake3: blake3::hash(&bytes).to_hex().to_string(),
            bytes: bytes.len() as u64,
            exit_code: exit,
        };
        receipt.read()?;
        let mut next_recipe = self.recipe.clone();
        next_recipe.cargo_stderr = Some(receipt);
        self.writer
            .set_recovery(serde_json::to_value(&next_recipe)?)?;
        self.recipe = next_recipe;
        Ok(())
    }

    /// A success record may reach compiler stdout only after actual delivery.
    /// Copy the original staged bytes against their publication fingerprints.
    /// A later build may already own the shared target; it cannot substitute
    /// its outputs for this invocation's first caller delivery.
    pub(crate) async fn caller_cargo_json(&mut self) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            self.recipe.returned == Some(0) && self.recipe.exit_code == Some(0),
            "caller Cargo JSON requires successful compilation and artifact delivery"
        );
        let receipt = self
            .recipe
            .cargo_stdout
            .as_ref()
            .context("complete retained Cargo stdout is unavailable")?;
        anyhow::ensure!(
            receipt.exit_code == 0,
            "retained Cargo stdout failed its invocation binding"
        );
        if let Some(delivery) = self.recipe.caller_delivery.as_ref() {
            return delivery.read(receipt);
        }
        let remote_project_root = self
            .recipe
            .caller_json_policy
            .as_deref()
            .context("caller Cargo JSON has no persisted source policy")?;
        let stdout = receipt.read()?;
        let (index, phase) = self
            .recipe
            .phases
            .iter()
            .enumerate()
            .find(|(_, phase)| phase.output_gate)
            .context("caller Cargo JSON has no output phase")?;
        anyhow::ensure!(
            phase.complete && phase.pending.is_none(),
            "caller Cargo JSON output phase is incomplete"
        );
        let _publication = lock_output_root(&phase.local).await?;
        let local_root = phase.local.canonicalize()?;
        let stage = self.stage(index);
        let delivery_source = match std::fs::symlink_metadata(&stage) {
            Ok(_) => stage,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Older ordinary jobs removed staging at phase completion.
                // Only actual absence permits their shared-output fallback;
                // dangling ancestors or a present invalid stage fail closed.
                let (resolved, existing) = output_root_identity_and_existing_prefix(&stage)?;
                anyhow::ensure!(
                    resolved != existing,
                    "caller Cargo staging appeared while selecting delivery inputs"
                );
                local_root.clone()
            }
            Err(error) => return Err(error).context("inspect caller Cargo staging"),
        };
        phase
            .cargo_outputs
            .as_ref()
            .context("caller Cargo JSON has no output contract")?
            .verify_staged(&delivery_source)?;
        let source_root = self.recipe.project_root.canonicalize()?;
        let capture = self
            .recipe
            .cargo_output_capture
            .as_ref()
            .context("caller Cargo JSON has no capture policy")?;
        // Other builds can legitimately replace shared outputs before or after
        // this lock is acquired. Give this invocation independent copies of
        // its staged inputs before advertising paths to an installer.
        let caller_parent = if phase.custom_target {
            local_root.clone()
        } else {
            local_root.join("target").canonicalize()?
        };
        anyhow::ensure!(
            caller_parent.starts_with(&local_root),
            "caller Cargo target root escapes its verified output phase"
        );
        let caller_root = caller_parent.join(format!(
            ".rch-delivered-{}-{}",
            self.recipe.wrapper_id,
            uuid::Uuid::new_v4(),
        ));
        std::fs::create_dir(&caller_root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&caller_root, std::fs::Permissions::from_mode(0o700))?;
        }
        let binding = serde_json::json!({
            "path": receipt.path,
            "blake3": receipt.blake3,
            "wrapper_id": self.recipe.wrapper_id,
            "build_id": self.recipe.build_id,
            "published_output_root": local_root,
            "caller_output_root": caller_root,
            "remote_project_root": receipt.remote_project_root,
            "stderr": self.recipe.cargo_stderr.as_ref()
                .context("caller Cargo delivery has no retained complete diagnostics")?,
        });
        let roots = [Path::new(&phase.remote), receipt.remote_root.as_path()];
        let source_roots = [
            remote_project_root,
            receipt
                .remote_project_root
                .as_deref()
                .context("caller Cargo delivery has no retained verified source root")?,
        ];
        let projected = capture.caller_json(
            &stdout,
            &CargoCallerPaths {
                remote_output_roots: &roots,
                local_output_root: &caller_root,
                remote_project_roots: &source_roots,
                local_project_root: &source_root,
                published: &phase.published,
                receipt_binding: &binding,
            },
        )?;
        CargoOutputContract {
            required_files: projected.files.clone(),
        }
        .verify_staged(&delivery_source)?;
        for relative in &projected.files {
            let expected = phase
                .published
                .get(relative)
                .context("caller Cargo filename lacks a publication fingerprint")?;
            copy_published_output(
                &delivery_source.join(relative),
                &caller_root.join(relative),
                expected,
            )?;
        }
        File::open(&caller_root)?.sync_all()?;
        File::open(&caller_parent)?.sync_all()?;
        CargoOutputContract {
            required_files: projected.files.clone(),
        }
        .verify_staged(&caller_root)?;
        let limit = super::super::cargo_output_contract::MAX_CARGO_OUTPUT_RECEIPT_BYTES
            .checked_mul(2)
            .context("caller Cargo JSON size limit overflow")?;
        anyhow::ensure!(
            projected.stdout.len() <= limit,
            "projected caller Cargo JSON exceeds its bound"
        );
        let path =
            retain_cargo_bytes(&self.recipe.wrapper_id, "cargo-delivery", &projected.stdout)?;
        let mut files = BTreeMap::new();
        for relative in &projected.files {
            files.insert(
                relative.clone(),
                phase
                    .published
                    .get(relative)
                    .context("caller Cargo output lacks its publication fingerprint")?
                    .clone(),
            );
        }
        let delivery = RetainedCargoDelivery {
            path,
            blake3: blake3::hash(&projected.stdout).to_hex().to_string(),
            bytes: projected.stdout.len() as u64,
            producer_blake3: receipt.blake3.clone(),
            output_root: caller_root,
            files,
        };
        delivery.read(receipt)?;
        let mut next_recipe = self.recipe.clone();
        next_recipe.caller_delivery = Some(delivery);
        self.writer
            .set_recovery(serde_json::to_value(&next_recipe)?)?;
        self.recipe = next_recipe;
        Ok(projected.stdout)
    }

    async fn prepare_caller_delivery(&mut self) -> anyhow::Result<()> {
        if self.recipe.caller_json_policy.is_some() && self.recipe.returned == Some(0) {
            self.caller_cargo_json().await?;
        }
        Ok(())
    }

    pub(crate) fn failed_cargo_stdout(&self) -> anyhow::Result<Vec<u8>> {
        let receipt = self
            .recipe
            .cargo_stdout
            .as_ref()
            .context("complete failed Cargo stdout is unavailable")?;
        anyhow::ensure!(
            receipt.exit_code != 0 && self.recipe.exit_code == Some(receipt.exit_code),
            "failed Cargo stdout requires the exact nonzero completion"
        );
        let stdout = receipt.read()?;
        // Telemetry follows the real workload's terminal output and is not
        // part of Cargo stdout. Keep every preceding byte, including failures.
        let marker = format!("\n{}\n", rch_telemetry::protocol::PIGGYBACK_MARKER);
        let end = if stdout.starts_with(&marker.as_bytes()[1..]) {
            0
        } else {
            stdout
                .windows(marker.len())
                .position(|window| window == marker.as_bytes())
                .map_or(stdout.len(), |index| index + 1)
        };
        Ok(stdout[..end].to_vec())
    }
    pub(crate) fn has_native_output_contract(&self) -> bool {
        self.recipe
            .phases
            .iter()
            .any(|phase| phase.native_outputs.is_some())
    }
    fn verify_native_outputs(&self, index: usize) -> anyhow::Result<()> {
        if let Some(contract) = &self.recipe.phases[index].native_outputs {
            contract.verify_staged(&self.stage(index))?;
        }
        Ok(())
    }
    fn verify_cargo_outputs(&self, index: usize) -> anyhow::Result<()> {
        let phase = &self.recipe.phases[index];
        if self.recipe.cargo_output_capture.is_none() || !phase.output_gate {
            return Ok(());
        }
        phase
            .cargo_outputs
            .as_ref()
            .context("complete Cargo output evidence is required before publication")?
            .verify_staged(&self.stage(index))
    }
    pub(crate) fn completion_pipeline(&self, pipeline: TransferPipeline) -> TransferPipeline {
        pipeline
            .with_recovery_completion(self.recipe.completion.clone(), self.recipe.identity.clone())
    }
    pub(crate) fn completed(&mut self, exit: i32) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recipe.execution_started,
            "completion requires an admitted execution attempt"
        );
        anyhow::ensure!(
            self.recipe
                .exit_code
                .is_none_or(|observed| observed == exit),
            "remote completion contradicts the recorded command outcome; ownership retained"
        );
        let mut next_recipe = self.recipe.clone();
        next_recipe.exit_code = Some(exit);
        self.persist_next_recipe(next_recipe)
    }
    /// Short-lived pre-execution suitability check of every local publication
    /// destination root. Reuses the output-root lock, canonical prefix/dangling
    /// symlink resolver, and exclusive `0600` ownership/UID probe before
    /// crossing the durable `starting_execution` boundary. Final publication
    /// revalidation remains unchanged.
    pub(crate) async fn verify_publication_suitability(&mut self) -> anyhow::Result<()> {
        #[cfg(unix)]
        let expected_uid = rustix::process::geteuid().as_raw();
        #[cfg(not(unix))]
        let expected_uid = 0;
        self.verify_publication_suitability_with(expected_uid, |_| Ok(()))
            .await
    }

    pub(super) async fn verify_publication_suitability_with<F>(
        &mut self,
        expected_uid: u32,
        observe: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&Path) -> anyhow::Result<()> + Send + 'static,
    {
        anyhow::ensure!(
            self.recipe.prepared
                && !self.recipe.execution_started
                && !self.recipe.preparation_cancelled
                && !self.recipe.sources_released
                && !self.recipe.pair_released
                && !self.recipe.tree_retired
                && !self.recipe.retired
                && self.recipe.exit_code.is_none()
                && self.recipe.returned.is_none()
                && self.recipe.phases.iter().all(|phase| {
                    !phase.complete
                        && phase.published.is_empty()
                        && phase.pending.is_none()
                        && phase.missing_result.is_none()
                }),
            "pre-execution publication suitability requires an unconsumed prepared session"
        );
        let mut roots = Vec::new();
        for phase in &self.recipe.phases {
            if !roots.contains(&phase.local) {
                roots.push(phase.local.clone());
            }
        }
        let observe = std::sync::Arc::new(std::sync::Mutex::new(observe));
        for root in roots {
            let publication = lock_output_root(&root).await?;
            let observe = std::sync::Arc::clone(&observe);
            publication_runtime::run(self, publication, move |session| {
                publication_runtime::checkpoint()?;
                let (identity, existing) = output_root_identity_and_existing_prefix(&root)?;
                #[cfg(unix)]
                publication_copy::probe_output_directory(
                    &existing,
                    &session.recipe.identity,
                    expected_uid,
                    |temporary| {
                        observe.lock().map_err(|_| {
                            anyhow::anyhow!("publication suitability observer poisoned")
                        })?(temporary)
                    },
                )?;
                #[cfg(not(unix))]
                let _ = (&existing, expected_uid, &observe);
                let (after_identity, after_existing) =
                    output_root_identity_and_existing_prefix(&root)?;
                anyhow::ensure!(
                    after_identity == identity && after_existing == existing,
                    "output publication root changed during suitability probe: {}",
                    root.display()
                );
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    pub(crate) fn starting_execution(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recipe.prepared
                && !self.recipe.execution_started
                && !self.recipe.preparation_cancelled
                && !self.recipe.sources_released,
            "execution requires an unconsumed prepared source grant"
        );
        let mut next_recipe = self.recipe.clone();
        next_recipe.execution_started = true;
        self.persist_next_recipe(next_recipe)
    }
    fn stage(&self, index: usize) -> PathBuf {
        self.recipe
            .transfer
            .retrieval_staging_dir
            .clone()
            .unwrap_or_else(|| default_job_lease_directory().join("retrieval"))
            .join(&self.recipe.identity)
            .join(index.to_string())
    }

    /// Apply operator recovery settings under the exclusive journal claim.
    /// Only extend the transfer budget; all output and source authority stays
    /// bound to the original recipe. Never move or delete an old staging tree.
    fn apply_retrieval_config(&mut self, current: &TransferConfig) -> anyhow::Result<()> {
        let mut next = self.recipe.clone();
        if let Some(timeout) = current.max_transfer_time_ms.filter(|value| *value > 0) {
            anyhow::ensure!(
                timeout <= 86_400_000,
                "recovery transfer timeout must not exceed 24 hours"
            );
            // Zero, like None, means adaptive timing in TransferPipeline.
            // Do not turn that sentinel into a hard ceiling or compare an
            // extension against zero instead of the persisted retry floor.
            let explicit = next
                .transfer
                .max_transfer_time_ms
                .filter(|value| *value > 0);
            let floor = explicit.unwrap_or(next.transfer.retry.total_timeout_ms);
            if timeout > floor {
                if explicit.is_some() {
                    next.transfer.max_transfer_time_ms = Some(timeout);
                } else {
                    // Preserve size-derived budgets: an extension of the
                    // base must not introduce a smaller hard ceiling for a
                    // large retained output set.
                    next.transfer.retry.total_timeout_ms = timeout;
                }
            }
        }
        if let Some(root) = &current.retrieval_staging_dir {
            anyhow::ensure!(
                root.is_absolute(),
                "transfer.retrieval_staging_dir must be absolute"
            );
            if next.transfer.retrieval_staging_dir.as_ref() != Some(root) {
                anyhow::ensure!(
                    !next.sources_released
                        && next.returned.is_none()
                        && next.phases.iter().all(|phase| !phase.complete
                            && phase.published.is_empty()
                            && phase.pending.is_none()),
                    "cannot change retrieval staging after publication began; retained staging and ownership are unchanged"
                );
                next.transfer.retrieval_staging_dir = Some(root.clone());
            }
        }
        next.transfer.retrieval_min_free_bytes = next
            .transfer
            .retrieval_min_free_bytes
            .max(current.retrieval_min_free_bytes);
        self.persist_next_recipe(next)
    }
    pub(crate) fn staging_pipeline(
        &self,
        name: &str,
        pipeline: &TransferPipeline,
    ) -> anyhow::Result<TransferPipeline> {
        let index = self
            .recipe
            .phases
            .iter()
            .position(|phase| phase.name == name)
            .context("missing retrieval phase")?;
        let stage = self.stage(index);
        anyhow::ensure!(
            stage.is_absolute(),
            "retrieval staging directory must be absolute"
        );
        std::fs::create_dir_all(&stage)?;
        Ok(pipeline
            .clone()
            .with_retrieval_reference_root(self.recipe.phases[index].local.clone())
            .with_local_root(stage))
    }
    pub(crate) async fn publish(&mut self, name: &str) -> anyhow::Result<()> {
        self.publish_with_observer(name, |_, _| Ok(())).await
    }

    async fn publish_with_observer(
        &mut self,
        name: &str,
        observe: impl FnMut(PublicationPoint, &Path) -> anyhow::Result<()> + Send + 'static,
    ) -> anyhow::Result<()> {
        let index = self
            .recipe
            .phases
            .iter()
            .position(|phase| phase.name == name)
            .context("missing retrieval phase")?;
        anyhow::ensure!(
            self.recipe.phases[index].missing_result.is_none(),
            "a missing required result cannot be published as complete"
        );
        if self.recipe.phases[index].complete {
            return Ok(());
        }
        // Keep the asynchronous, cancellable lock wait. The worker owns the
        // acquired descriptor until it stops, including on future cancellation.
        let publication = lock_output_root(&self.recipe.phases[index].local).await?;
        publication_runtime::run(self, publication, move |session| {
            session.publish_blocking(index, observe)
        })
        .await
    }

    fn publish_blocking(
        &mut self,
        index: usize,
        mut observe: impl FnMut(PublicationPoint, &Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        publication_runtime::checkpoint()?;
        // Validate the entire required set before the first journal/output
        // mutation. One executable or support library cannot satisfy another
        // selected Cargo target, and existing destination files are no proof.
        self.verify_cargo_outputs(index)?;
        publication_runtime::checkpoint()?;
        self.verify_native_outputs(index)?;
        publication_runtime::checkpoint()?;
        let stage = self.stage(index);
        #[cfg(unix)]
        let mut files = publication_copy::staged_regular_files(&stage)?;
        #[cfg(not(unix))]
        let mut files = regular_files(&stage)?;
        let phase = &self.recipe.phases[index];
        if let Some((relative, _)) = &phase.pending {
            // Check before the completed shortcut, policy fingerprint or
            // pending rename can observe a redirected descendant as ours.
            validate_output_ancestors(&phase.local, relative)?;
        }
        if phase.result_dir.is_some() {
            anyhow::ensure!(
                phase.pending.as_ref().is_none_or(|(relative, _)| {
                    !crate::transfer::is_internal_source_archive(relative)
                }),
                "internal source archive has a pending publication; retained evidence requires inspection"
            );
            files.retain(|relative| !crate::transfer::is_internal_source_archive(relative));
        } else {
            // A resumed transfer can retain files selected by an older
            // collector. Ownership fingerprints alone do not authorize a
            // source file as an artifact, so only staged files the artifact
            // policy admits are ever published. The rest (retained Cargo
            // metadata such as `.rustc_info.json`) stay private to the stage:
            // refusing the whole publication instead left the job forever
            // unrecoverable and its worker-side source claim stranded.
            let policy = TransferPipeline::new(
                phase.local.clone(),
                "recovery-publication".into(),
                self.recipe.identity.clone(),
                self.recipe.transfer.clone(),
            );
            let (admitted, outside) =
                policy.partition_staged_artifact_paths(&files, &phase.patterns)?;
            for path in &outside {
                publication_runtime::checkpoint()?;
                // Warn: a skip means collector and recipe disagree about the
                // policy (as in bd-3kskq); keep that skew visible.
                warn!(
                    "recovery skips staged file outside the artifact policy: {}",
                    path.display()
                );
            }
            files = admitted;
            if let Some((relative, hash)) = &phase.pending {
                // A journaled write already began renaming this path into
                // place. It must be in policy to be finished; never skip it.
                let completed = !phase.baseline.contains_key(relative)
                    && fingerprint(&phase.local.join(relative))?.as_ref() == Some(hash);
                if !completed {
                    policy.validate_staged_artifact_paths(
                        std::slice::from_ref(relative),
                        &phase.patterns,
                    )?;
                }
            }
        }
        publication_runtime::checkpoint()?;
        if let Some((relative, hash)) = self.recipe.phases[index].pending.clone() {
            let destination = self.recipe.phases[index].local.join(&relative);
            let parent = destination
                .parent()
                .context("pending output missing parent")?;
            let temporary = parent.join(format!(".rch-return-{}", self.recipe.identity));
            let current = fingerprint(&destination)?;
            if current.as_ref() != Some(&hash) {
                anyhow::ensure!(
                    current.as_ref() == self.recipe.phases[index].baseline.get(&relative),
                    "interrupted output publication cannot prove ownership at {}; refusing overwrite",
                    destination.display()
                );
                let prepared = PreparedOutput::existing(File::open(parent)?, &temporary, &hash)?;
                prepared.publish(&destination)?;
            }
            self.persist_published_output(index, relative, hash)?;
        }
        // Observe the predecessors of this admitted staged set while holding
        // publication ownership. Legacy preparation-wide hashes are pruned
        // in the same transaction. A journaled pending rename was reconciled
        // against its ORIGINAL predecessor above, never a refreshed baseline.
        self.persist_publication_baseline(index, &files)?;
        for relative in files {
            publication_runtime::checkpoint()?;
            let phase = &self.recipe.phases[index];
            if phase.published.contains_key(&relative) {
                continue;
            }
            let destination = phase.local.join(&relative);
            observe(PublicationPoint::BeforeFile, &destination)?;
            publication_runtime::checkpoint()?;
            validate_output_ancestors(&phase.local, &relative)?;
            let source = stage.join(&relative);
            let hash = fingerprint(&source)?.context("staged output disappeared")?;
            let current = fingerprint(&destination)?;
            anyhow::ensure!(
                current.as_ref() == phase.baseline.get(&relative),
                "output ownership changed at {}; refusing to overwrite",
                destination.display()
            );
            let parent = destination.parent().context("output missing parent")?;
            let temporary = parent.join(format!(".rch-return-{}", self.recipe.identity));
            let prepared = prepare_output_temporary(&source, &temporary, &hash)?;
            prepared.directory.sync_all()?;
            self.persist_pending_output(index, Some((relative.clone(), hash.clone())))?;
            observe(PublicationPoint::PendingDurable, &destination)?;
            publication_runtime::checkpoint()?;
            anyhow::ensure!(
                fingerprint(&destination)?.as_ref()
                    == self.recipe.phases[index].baseline.get(&relative),
                "output changed while publishing {}",
                destination.display()
            );
            prepared.publish(&destination)?;
            observe(PublicationPoint::Renamed, &destination)?;
            publication_runtime::checkpoint()?;
            self.persist_published_output(index, relative, hash)?;
            observe(PublicationPoint::PublishedDurable, &destination)?;
        }
        publication_runtime::checkpoint()?;
        let mut next_recipe = self.recipe.clone();
        next_recipe.phases[index].complete = true;
        self.persist_next_recipe(next_recipe)?;
        // First caller-JSON delivery still needs this invocation's original
        // bytes if another build replaces the shared outputs. Ordinary jobs
        // release these duplicates at their existing retirement boundary.
        // Retained-source intent also protects out-of-policy staging inputs.
        let caller_delivery_pending = self.recipe.caller_json_policy.is_some()
            && self.recipe.caller_delivery.is_none()
            && self.recipe.phases[index].output_gate;
        if !self.retain_source_lifecycle_evidence()
            && !caller_delivery_pending
            && publication_runtime::checkpoint().is_ok()
        {
            let _ = std::fs::remove_dir_all(&stage);
        }
        Ok(())
    }
    pub(crate) fn returned(&mut self, exit: i32) -> anyhow::Result<()> {
        anyhow::ensure!(
            exit != 0
                || self
                    .recipe
                    .phases
                    .iter()
                    .all(|phase| { phase.native_outputs.is_none() || phase.complete }),
            "native compilation cannot succeed before every required output is published"
        );
        anyhow::ensure!(
            !result_recovery::has_missing_results(&self.recipe)
                || exit == EXIT_ARTIFACT_TRANSFER_FAILED,
            "missing required outputs must remain a delivery failure"
        );
        anyhow::ensure!(
            exit != 0
                || self.recipe.cargo_output_capture.is_none()
                || self.recipe.phases.iter().all(|phase| {
                    !phase.output_gate || (phase.cargo_outputs.is_some() && phase.complete)
                }),
            "captured Cargo build cannot succeed before all required outputs are published"
        );
        let mut next_recipe = self.recipe.clone();
        next_recipe.returned = Some(exit);
        self.persist_next_recipe(next_recipe)
    }
    pub(crate) fn tree_retired(&mut self) -> anyhow::Result<()> {
        self.persist_tree_retirement(self.recipe.retained_materialized)
    }
    fn persist_tree_retirement(&mut self, materialized: Option<bool>) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recipe.retained_root.is_none() || materialized.is_some(),
            "retained source retirement has no durable filesystem acknowledgment"
        );
        anyhow::ensure!(
            materialized != Some(false)
                || (!self.recipe.execution_started && self.recipe.preparation_cancelled),
            "an executed source pair cannot retire as unmaterialized preparation"
        );
        anyhow::ensure!(
            materialized.is_none() || self.recipe.retained_root.is_some(),
            "retained source acknowledgment has no original destination"
        );
        let mut next_recipe = self.recipe.clone();
        next_recipe.retained_materialized = materialized;
        next_recipe.tree_retired = true;
        self.persist_next_recipe(next_recipe)
    }
    /// The caller holds the complete active or drained cleanup grant. A lost
    /// acknowledgment leaves the recipe pending; the identity-bound rename
    /// protocol verifies the exact retained sibling on the next attempt.
    pub(crate) async fn retire_source_tree(
        &mut self,
        pipeline: &TransferPipeline,
    ) -> anyhow::Result<()> {
        if self.recipe.tree_retired {
            return Ok(());
        }
        let mut materialized = None;
        if let Some(root) = self.recipe.retire_root.as_deref() {
            if let Some(retained) = self.recipe.retained_root.as_deref() {
                materialized = Some(
                    pipeline
                        .retain_remote_tree(
                            &self.recipe.worker,
                            root,
                            retained,
                            &self.recipe.identity,
                            !self.recipe.execution_started && self.recipe.preparation_cancelled,
                        )
                        .await?,
                );
            } else {
                pipeline.reap_remote_tree(&self.recipe.worker, root).await?;
            }
        }
        self.persist_tree_retirement(materialized)
    }
    pub(crate) fn pair_released(&mut self) -> anyhow::Result<()> {
        let mut next_recipe = self.recipe.clone();
        next_recipe.pair_released = true;
        self.persist_next_recipe(next_recipe)
    }
    pub(crate) fn sources_released(&mut self) -> anyhow::Result<()> {
        let mut next_recipe = self.recipe.clone();
        next_recipe.sources_released = true;
        self.persist_next_recipe(next_recipe)
    }

    async fn bind_source_namespace(&mut self) -> anyhow::Result<SourceAuthorityNamespace> {
        self.bind_source_namespace_with(async |worker, roots, identity| {
            super::super::ssh::locate_remote_source_authority_namespace(worker, roots, identity)
                .await
        })
        .await
    }

    async fn bind_source_namespace_with(
        &mut self,
        mut locate: impl AsyncFnMut(
            &WorkerConfig,
            &[String],
            &str,
        ) -> anyhow::Result<SourceAuthorityNamespace>,
    ) -> anyhow::Result<SourceAuthorityNamespace> {
        if let Some(namespace) = self.recipe.source_authority_namespace {
            return Ok(namespace);
        }
        anyhow::ensure!(
            !self.recipe.source_roots.is_empty(),
            "legacy source namespace has no complete source intent; refusing to guess from pair metadata"
        );
        let before = self.writer.snapshot();
        anyhow::ensure!(
            serde_json::to_value(load_recipe(&self.writer)?)?
                == serde_json::to_value(&self.recipe)?,
            "source recovery recipe changed before namespace discovery"
        );
        if let Some(owner) = &self.writer.recovery_ownership {
            owner.verify()?;
        }
        let namespace = locate(
            &self.recipe.worker,
            &self.recipe.source_roots,
            &self.recipe.identity,
        )
        .await?;
        let mut latest = self.writer.snapshot();
        latest.heartbeat_unix_ms = before.heartbeat_unix_ms;
        latest.phase.clone_from(&before.phase);
        anyhow::ensure!(
            latest == before,
            "journal changed during source namespace discovery"
        );
        if let Some(owner) = &self.writer.recovery_ownership {
            owner.verify()?;
        }
        // Add only the discovered binding. Preserve unknown legacy custody
        // fields and original path spellings rather than reserializing them.
        let mut recovery = before
            .recovery
            .context("source recovery recipe disappeared")?;
        recovery
            .as_object_mut()
            .context("source recovery recipe is not an object")?
            .insert(
                "source_authority_namespace".into(),
                serde_json::to_value(namespace)?,
            );
        self.writer.set_recovery(recovery)?;
        self.recipe.source_authority_namespace = Some(namespace);
        Ok(namespace)
    }

    async fn reconcile_source_cancellation(&mut self) -> anyhow::Result<()> {
        if self.recipe.source_cancellation_settled == Some(true)
            || (!self.recipe.preparation_cancelled
                && self.recipe.source_cancellation_settled.is_none())
        {
            return Ok(());
        }
        anyhow::ensure!(
            self.recipe.returned.is_some_and(|exit| exit != 0)
                && self.recipe.sources_released
                && self.recipe.tree_retired
                && self.recipe.pair_released,
            "source cancellation settlement requires durable failed delivery and complete resource retirement"
        );
        let namespace = if self.recipe.source_roots.is_empty() {
            SourceAuthorityNamespace::Current // No worker operation is performed.
        } else {
            self.bind_source_namespace().await?
        };
        self.reconcile_source_cancellation_with(async |worker, roots, identity| {
            super::super::ssh::settle_remote_source_cancellation(worker, roots, identity, namespace)
                .await
        })
        .await
    }

    /// Older executed cancellations could finish without recording either
    /// preparation_cancelled or the newer settlement obligation. Explicit
    /// recovery may discover that obligation from exact worker evidence only
    /// after the original journal proves complete retirement. This path never
    /// grants source access or reopens a source/pair tree.
    async fn discover_terminal_source_cancellation(&mut self) -> anyhow::Result<()> {
        self.discover_terminal_source_cancellation_with(
            async |worker, roots, identity, recorded_namespace| {
                let namespace = match recorded_namespace {
                    Some(namespace) => namespace,
                    None => {
                        let Some(namespace) =
                            super::super::ssh::discover_remote_source_authority_namespace(
                                worker, roots, identity,
                            )
                            .await?
                        else {
                            return Ok(None);
                        };
                        namespace
                    }
                };
                if super::super::ssh::remote_source_intent_has_cancellation(
                    worker, roots, identity, namespace,
                )
                .await?
                {
                    Ok(Some(namespace))
                } else {
                    Ok(None)
                }
            },
        )
        .await?;
        Ok(())
    }

    async fn discover_terminal_source_cancellation_with(
        &mut self,
        mut observe: impl AsyncFnMut(
            &WorkerConfig,
            &[String],
            &str,
            Option<SourceAuthorityNamespace>,
        ) -> anyhow::Result<Option<SourceAuthorityNamespace>>,
    ) -> anyhow::Result<bool> {
        if self.recipe.preparation_cancelled
            || self.recipe.source_cancellation_settled.is_some()
            || self.recipe.source_roots.is_empty()
            || self.recipe.returned == Some(0)
        {
            return Ok(false);
        }
        let ownership = self
            .writer
            .recovery_ownership
            .as_ref()
            .context("terminal cancellation discovery has no journal owner")?;
        ownership.verify()?;
        let before = self.writer.snapshot();
        anyhow::ensure!(
            before.terminal_acknowledged
                && before.state == rch_common::job_identity::JobLifecycleState::Finished
                && self.recipe.returned.is_some_and(|exit| exit != 0)
                && before.exit_code == self.recipe.returned
                && self.recipe.retired
                && self.recipe.sources_released
                && self.recipe.tree_retired
                && self.recipe.pair_released
                && serde_json::to_value(load_recipe(&self.writer)?)?
                    == serde_json::to_value(&self.recipe)?,
            "terminal cancellation discovery lacks exact failed delivery and complete retirement"
        );
        super::super::ssh::validate_source_authority_intent(
            &self.recipe.source_roots,
            &self.recipe.identity,
        )?;
        self.validate_cancellation_pair()?;
        let namespace = observe(
            &self.recipe.worker,
            &self.recipe.source_roots,
            &self.recipe.identity,
            self.recipe.source_authority_namespace,
        )
        .await?;
        ownership.verify()?;
        anyhow::ensure!(
            self.writer.snapshot() == before,
            "journal changed during terminal cancellation discovery; evidence retained"
        );
        let Some(namespace) = namespace else {
            return Ok(false);
        };
        anyhow::ensure!(
            self.recipe
                .source_authority_namespace
                .is_none_or(|recorded| recorded == namespace),
            "terminal cancellation discovery changed the source namespace"
        );
        // An absent observation writes nothing. A positive observation adds
        // only the namespace and outstanding obligation, preserving historical
        // spelling and unknown custody fields. Settlement remains a separate,
        // activity-drained worker acknowledgement, including after restart.
        let mut recovery = before
            .recovery
            .context("terminal recovery recipe disappeared")?;
        let object = recovery
            .as_object_mut()
            .context("terminal recovery recipe is not an object")?;
        object.insert(
            "source_authority_namespace".into(),
            serde_json::to_value(namespace)?,
        );
        object.insert(
            "source_cancellation_settled".into(),
            serde_json::json!(false),
        );
        self.writer.set_recovery(recovery)?;
        self.recipe.source_authority_namespace = Some(namespace);
        self.recipe.source_cancellation_settled = Some(false);
        Ok(true)
    }

    async fn reconcile_source_cancellation_with(
        &mut self,
        mut settle: impl AsyncFnMut(&WorkerConfig, &[String], &str) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        if self.recipe.source_cancellation_settled == Some(true)
            || (!self.recipe.preparation_cancelled
                && self.recipe.source_cancellation_settled.is_none())
        {
            return Ok(());
        }
        anyhow::ensure!(
            self.recipe.returned.is_some_and(|exit| exit != 0)
                && self.recipe.sources_released
                && self.recipe.tree_retired
                && self.recipe.pair_released,
            "source cancellation settlement requires durable failed delivery and complete resource retirement"
        );
        let before = self.writer.snapshot();
        anyhow::ensure!(
            serde_json::to_value(load_recipe(&self.writer)?)?
                == serde_json::to_value(&self.recipe)?,
            "source cancellation recipe changed before worker reconciliation"
        );
        if let Some(owner) = &self.writer.recovery_ownership {
            owner.verify()?;
        }
        if !self.recipe.source_roots.is_empty() {
            // This is metadata reconciliation only. The worker independently
            // drains activity, verifies the exact identity/closure and keeps
            // the anti-replay fence. No output or source path is reopened.
            settle(
                &self.recipe.worker,
                &self.recipe.source_roots,
                &self.recipe.identity,
            )
            .await?;
        }
        let mut latest = self.writer.snapshot();
        // The live heartbeat loop can have one spawn_blocking publication in
        // flight when cancellation begins. Its final phase/time observation
        // cannot change admission, result or recovery authority. Preserve it
        // when checkpointing instead of mistaking progress for a new owner.
        latest.heartbeat_unix_ms = before.heartbeat_unix_ms;
        latest.phase.clone_from(&before.phase);
        anyhow::ensure!(
            latest == before,
            "job journal changed during source cancellation settlement; acknowledgement refused"
        );
        // A terminal reconciliation adds one fact. Preserve the rest of the
        // original JSON, including legacy root spellings and unknown custody
        // fields; parsing defaults must not rewrite historical evidence.
        let mut recovery = before.recovery.context("cancellation recipe disappeared")?;
        recovery
            .as_object_mut()
            .context("cancellation recipe is not an object")?
            .insert(
                "source_cancellation_settled".into(),
                serde_json::json!(true),
            );
        self.writer.set_recovery(recovery)?;
        self.recipe.source_cancellation_settled = Some(true);
        Ok(())
    }

    /// A cancellation may use a pair only for this same identity and exact
    /// retirement root. Legacy non-retained recipes do not have the retained
    /// tree validator's stronger binding, so check before any cancellation
    /// checkpoint or RPC can select a cleanup pair for another source grant.
    fn validate_cancellation_pair(&self) -> anyhow::Result<()> {
        let Some((root, token)) = self.recipe.pair.as_ref() else {
            return Ok(());
        };
        super::super::ssh::validate_source_authority_intent(
            &self.recipe.source_roots,
            &self.recipe.identity,
        )?;
        let canonical_root = super::super::ssh::canonical_source_authority_root(root);
        super::super::ssh::validate_source_authority_intent(
            std::slice::from_ref(&canonical_root),
            token,
        )?;
        anyhow::ensure!(
            token == &self.recipe.identity
                && self.recipe.source_roots.contains(&canonical_root)
                && self
                    .recipe
                    .retire_root
                    .as_deref()
                    .map(super::super::ssh::canonical_source_authority_root)
                    .as_ref()
                    == Some(&canonical_root),
            "source-pair cancellation does not match its source identity and retirement root"
        );
        Ok(())
    }

    /// The caller has read this attempt's exact durable completion. Observe
    /// an old cancellation fence before normal recovery could reattach the
    /// grant, and checkpoint its outstanding cleanup before the first RPC.
    /// A fence is intent only: cancel_source_grant must still drain activity,
    /// acquire the actual cleanup grant, and retire every owned resource.
    async fn checkpoint_completed_source_cancellation_with(
        &mut self,
        exit: i32,
        mut has_cancellation: impl AsyncFnMut(&WorkerConfig, &[String], &str) -> anyhow::Result<bool>,
    ) -> anyhow::Result<bool> {
        let cancellation_started = self.recipe.source_cancellation_settled == Some(false);
        if !cancellation_started
            && self.recipe.pair.is_none()
            && self.recipe.source_roots.is_empty()
        {
            return Ok(false);
        }
        let ownership = self
            .writer
            .recovery_ownership
            .as_ref()
            .context("completed source cancellation has no journal owner")?;
        ownership.verify()?;
        let before = self.writer.snapshot();
        anyhow::ensure!(
            self.recipe.execution_started
                && self.recipe.returned.is_none()
                && !before.terminal_acknowledged
                && self.recipe.source_authority_namespace.is_some()
                && serde_json::to_value(load_recipe(&self.writer)?)?
                    == serde_json::to_value(&self.recipe)?,
            "completed source cancellation lacks its exact unfinished execution recipe"
        );
        self.validate_cancellation_pair()?;
        let cancellation = cancellation_started
            || has_cancellation(
                &self.recipe.worker,
                &self.recipe.source_roots,
                &self.recipe.identity,
            )
            .await?;
        ownership.verify()?;
        anyhow::ensure!(
            self.writer.snapshot() == before,
            "recovery journal changed during completed cancellation discovery"
        );
        if !cancellation {
            return Ok(false);
        }
        anyhow::ensure!(
            self.recipe
                .exit_code
                .is_none_or(|observed| observed == exit),
            "remote completion contradicts the recorded command outcome; ownership retained"
        );
        anyhow::ensure!(
            before.exit_code != Some(0),
            "source cancellation contradicts the recorded successful wrapper result"
        );
        let mut next = self.recipe.clone();
        next.exit_code = Some(exit);
        next.source_cancellation_settled = Some(false);
        self.persist_next_recipe(next)?;
        Ok(true)
    }

    /// Resume cancellation after the tree was durably retired, without
    /// reacquiring source access or reading pooled source contents. A crash can leave the
    /// pair released while finish-cancel, its reply, or the local checkpoint
    /// is still outstanding. Normal pair recovery must refuse that old owner.
    async fn resume_retired_source_pair_cancellation(&mut self) -> anyhow::Result<Option<i32>> {
        if self.recipe.pair.is_none()
            || self.recipe.source_roots.is_empty()
            || !self.recipe.execution_started
            || !self.recipe.tree_retired
            || self.recipe.returned.is_some()
        {
            return Ok(None);
        }
        let namespace = self.bind_source_namespace().await?;
        self.resume_retired_source_pair_cancellation_with(
            async |worker, roots, identity| {
                super::super::ssh::remote_source_intent_has_cancellation(
                    worker, roots, identity, namespace,
                )
                .await
            },
            async |worker, root, token| {
                super::super::ssh::clean_overlay_source_pair_was_released(
                    worker, root, token, namespace,
                )
                .await
            },
            async |worker, roots, identity| {
                // The local cancellation checkpoint precedes the first RPC.
                // Re-establish its fence if that RPC never arrived, or its
                // receipt if retention collected it. This helper consumes no
                // cleanup authority even when the active claim still exists.
                if super::super::ssh::cancel_remote_source_authority_intent(
                    worker, roots, identity, namespace,
                )
                .await?
                {
                    super::super::ssh::finish_cancel_remote_source_authority_intent(
                        worker, roots, identity, namespace,
                    )
                    .await?;
                }
                Ok(())
            },
            async |session| session.reconcile_source_cancellation().await,
        )
        .await
    }

    async fn resume_retired_source_pair_cancellation_with(
        &mut self,
        mut has_cancellation: impl AsyncFnMut(&WorkerConfig, &[String], &str) -> anyhow::Result<bool>,
        mut pair_was_released: impl AsyncFnMut(&WorkerConfig, &str, &str) -> anyhow::Result<bool>,
        mut finish: impl AsyncFnMut(&WorkerConfig, &[String], &str) -> anyhow::Result<()>,
        mut reconcile: impl AsyncFnMut(&mut RecoverySession) -> anyhow::Result<()>,
    ) -> anyhow::Result<Option<i32>> {
        let Some((root, token)) = self.recipe.pair.clone() else {
            return Ok(None);
        };
        if self.recipe.source_roots.is_empty()
            || !self.recipe.execution_started
            || !self.recipe.tree_retired
            || self.recipe.returned.is_some()
        {
            return Ok(None);
        }
        let ownership = self
            .writer
            .recovery_ownership
            .as_ref()
            .context("source-pair cancellation recovery has no journal owner")?;
        ownership.verify()?;
        anyhow::ensure!(
            self.recipe.source_authority_namespace.is_some()
                && serde_json::to_value(load_recipe(&self.writer)?)?
                    == serde_json::to_value(&self.recipe)?,
            "source-pair cancellation recovery lacks its exact bound recipe"
        );
        self.validate_cancellation_pair()?;
        let before = self.writer.snapshot();
        anyhow::ensure!(
            !before.terminal_acknowledged,
            "source-pair cancellation cannot replace an acknowledged result"
        );
        let cancellation_started = self.recipe.source_cancellation_settled == Some(false);
        if !cancellation_started {
            // Old journals did not persist the cancellation obligation. An
            // exact worker fence proves cancellation was requested even when
            // finish-cancel never ran or its receipt was collected. That
            // observation grants no cleanup or retirement: the durable tree
            // checkpoint and exact pair release below are still required.
            let cancellation = has_cancellation(
                &self.recipe.worker,
                &self.recipe.source_roots,
                &self.recipe.identity,
            )
            .await?;
            ownership.verify()?;
            anyhow::ensure!(
                self.writer.snapshot() == before,
                "source-pair recovery journal changed during cancellation discovery"
            );
            if !cancellation {
                return Ok(None);
            }
        }
        anyhow::ensure!(
            before.exit_code != Some(0),
            "source-pair cancellation contradicts the recorded successful wrapper result"
        );
        if !self.recipe.pair_released {
            let released = pair_was_released(&self.recipe.worker, &root, &token).await?;
            ownership.verify()?;
            anyhow::ensure!(
                self.writer.snapshot() == before,
                "source-pair recovery journal changed during pair reconciliation"
            );
            if !released {
                // The tree checkpoint can precede pair release, including in
                // a legacy journal without a cancellation-obligation field.
                // No retirement is proved here. Only the later execution-
                // complete or execution-lost path can resume cleanup with an
                // exact live pair guard; missing/changed owners still refuse.
                return Ok(None);
            }
        }
        ownership.verify()?;
        anyhow::ensure!(
            self.writer.snapshot() == before,
            "source-pair recovery journal changed before cancellation resumption"
        );
        let exit = if result_recovery::has_missing_results(&self.recipe) {
            EXIT_ARTIFACT_TRANSFER_FAILED
        } else {
            before.exit_code.unwrap_or(EXIT_BUILD_ERROR)
        };
        if !cancellation_started {
            let mut next = self.recipe.clone();
            next.source_cancellation_settled = Some(false);
            self.persist_next_recipe(next)?;
        }
        let cancellation_before = self.writer.snapshot();
        finish(
            &self.recipe.worker,
            &self.recipe.source_roots,
            &self.recipe.identity,
        )
        .await?;
        self.writer
            .recovery_ownership
            .as_ref()
            .context("source-pair cancellation recovery lost its journal owner")?
            .verify()?;
        anyhow::ensure!(
            self.writer.snapshot() == cancellation_before,
            "source-pair recovery journal changed during worker cancellation"
        );
        // No source or pair is reacquired. The tree checkpoint, exact pair
        // receipt and drained cancellation prove only these retirement facts.
        let mut next = self.recipe.clone();
        next.pair_released = true;
        next.sources_released = true;
        self.persist_next_recipe(next)?;
        self.returned(exit)?;
        reconcile(self).await?;
        self.retired()?;
        Ok(Some(exit))
    }

    pub(crate) fn retired(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.recipe.returned.is_some(),
            "cannot retire before output publication completes"
        );
        anyhow::ensure!(
            self.recipe.retire_root.is_none() || self.recipe.tree_retired,
            "remote tree retirement is outstanding"
        );
        anyhow::ensure!(
            self.recipe.pair.is_none() || self.recipe.pair_released,
            "source-pair release is outstanding"
        );
        anyhow::ensure!(
            self.recipe.source_roots.is_empty() || self.recipe.sources_released,
            "remote source release is outstanding"
        );
        anyhow::ensure!(
            self.recipe.source_cancellation_settled != Some(false)
                && (!self.recipe.preparation_cancelled
                    || self.recipe.source_roots.is_empty()
                    || self.recipe.source_cancellation_settled == Some(true)),
            "worker source cancellation settlement is outstanding"
        );
        let mut next_recipe = self.recipe.clone();
        next_recipe.retired = true;
        self.persist_next_recipe(next_recipe)?;
        // Whole-stage removal also discards unpublished collector inputs. The
        // owner decided (bd-ra5aw, 2026-10-30) that a retained-source job's
        // local stage is not custody once a successful delivery is complete:
        // the worker's retained tree stays and the caller holds the published
        // bytes. Failed or unfinished deliveries keep their stage as evidence.
        if (!self.retain_source_lifecycle_evidence() || self.successful_delivery_complete())
            && !self.retain_failed_delivery_evidence()
            && let Some(stages) = self.stage(0).parent()
        {
            let _ = std::fs::remove_dir_all(stages);
        }
        Ok(())
    }
    pub(crate) async fn retire_returned(&mut self) -> anyhow::Result<()> {
        if self.recipe.retired {
            self.reconcile_source_cancellation().await?;
            return Ok(());
        }
        anyhow::ensure!(
            self.recipe.returned.is_some(),
            "cannot retire outputs before durable return"
        );
        let namespace = if (!self.recipe.sources_released && !self.recipe.source_roots.is_empty())
            || (!self.recipe.pair_released && self.recipe.pair.is_some())
            || (!self.recipe.tree_retired && self.recipe.retire_root.is_some())
        {
            self.bind_source_namespace().await?
        } else {
            self.recipe
                .source_authority_namespace
                .unwrap_or(SourceAuthorityNamespace::Current)
        };
        let worker = self.recipe.worker.clone();
        let mut pair = if !self.recipe.pair_released {
            if let Some((root, token)) = self.recipe.pair.clone() {
                if super::super::ssh::clean_overlay_source_pair_was_released(
                    &worker, &root, &token, namespace,
                )
                .await?
                {
                    self.pair_released()?;
                    None
                } else {
                    Some(
                        super::super::ssh::recover_clean_overlay_source_pair(
                            &worker,
                            &root,
                            &token,
                            Duration::from_secs(15),
                            namespace,
                        )
                        .await?,
                    )
                }
            } else {
                None
            }
        } else {
            None
        };
        let mut sources = if self.recipe.sources_released || self.recipe.source_roots.is_empty() {
            None
        } else if super::super::ssh::remote_source_authority_was_released(
            &worker,
            &self.recipe.source_roots,
            &self.recipe.identity,
            namespace,
        )
        .await?
        {
            // A release receipt is only a terminal reconciliation fact. It can
            // never reopen paths which a later invocation may now be writing.
            anyhow::ensure!(
                self.recipe.tree_retired,
                "source release preceded durable tree retirement; refusing path access"
            );
            self.sources_released()?;
            None
        } else {
            Some(
                super::super::ssh::recover_remote_source_authority_lock(
                    &worker,
                    &self.recipe.source_roots,
                    pair.as_mut(),
                    &self.recipe.identity,
                    Duration::from_secs(15),
                    namespace,
                )
                .await?,
            )
        };
        if self.recipe.tree_retired {
            // Do not reopen released worker paths. Any first caller delivery
            // must already have enough retained local evidence to verify here.
            self.prepare_caller_delivery().await?;
        }
        if !self.recipe.tree_retired {
            let sources = sources
                .as_mut()
                .context("tree retirement requires the active source grant")?;
            sources.ensure_held()?;
            if let Some(pair) = pair.as_mut() {
                pair.ensure_held()?;
            }
            if self.recipe.caller_json_policy.is_some() {
                let pipeline = self.completion_pipeline(
                    TransferPipeline::new(
                        self.recipe.project_root.clone(),
                        "recovery".into(),
                        self.recipe.identity.clone(),
                        self.recipe.transfer.clone(),
                    )
                    .with_source_authority_in(self.recipe.identity.clone(), namespace)?,
                );
                self.collect_cargo_stderr(&pipeline, &worker).await?;
            }
            self.prepare_caller_delivery().await?;
            let pipeline = TransferPipeline::new(
                self.recipe.project_root.clone(),
                "recovery".into(),
                self.recipe.identity.clone(),
                self.recipe.transfer.clone(),
            )
            .with_source_authority_in(self.recipe.identity.clone(), namespace)?;
            self.retire_source_tree(&pipeline).await?;
        }
        if let Some(sources) = sources.take() {
            sources.release().await?;
            self.sources_released()?;
        }
        if let Some(pair) = pair.take() {
            pair.release().await?;
        }
        self.pair_released()?;
        self.reconcile_source_cancellation().await?;
        self.retired()?;
        self.discard_completion_receipts().await;
        Ok(())
    }
    /// Retained custody begins with the admitted intent, before a filesystem
    /// retirement acknowledgment. A pending or cancelled tree does not grant
    /// permission to discard the invocation's delivery/completion evidence.
    fn retain_source_lifecycle_evidence(&self) -> bool {
        self.recipe.retained_root.is_some()
    }

    /// A successful delivery that no longer needs its local stage: the command
    /// and the caller both saw exit 0, every phase is published with nothing
    /// pending or missing, and any first caller Cargo reply is prepared.
    fn successful_delivery_complete(&self) -> bool {
        self.recipe.exit_code == Some(0)
            && self.recipe.returned == Some(0)
            && !self.recipe.phases.is_empty()
            && self.recipe.phases.iter().all(|phase| {
                phase.complete && phase.pending.is_none() && phase.missing_result.is_none()
            })
            && (self.recipe.caller_json_policy.is_none() || self.recipe.caller_delivery.is_some())
    }

    fn retain_failed_delivery_evidence(&self) -> bool {
        result_recovery::has_missing_results(&self.recipe)
            || (self.recipe.exit_code == Some(0)
                && self
                    .recipe
                    .phases
                    .iter()
                    .any(|phase| phase.native_outputs.is_some() && !phase.complete))
            || (self.recipe.cargo_output_capture.is_some()
                && self.recipe.exit_code == Some(0)
                && self
                    .recipe
                    .phases
                    .iter()
                    .any(|phase| phase.output_gate && !phase.complete))
            || (self.recipe.exit_code == Some(0)
                && self.recipe.returned == Some(EXIT_ARTIFACT_TRANSFER_FAILED)
                && self.recipe.phases.iter().any(|phase| !phase.complete))
    }
    async fn discard_completion_receipts(&self) {
        // Retained source custody protects the original completion too. Keep
        // terminal required-output failure evidence under the existing policy.
        if self.retain_source_lifecycle_evidence() || self.retain_failed_delivery_evidence() {
            return;
        }
        let pipeline = self.completion_pipeline(TransferPipeline::new(
            self.recipe.project_root.clone(),
            "recovery".into(),
            self.recipe.identity.clone(),
            self.recipe.transfer.clone(),
        ));
        if let Err(error) = pipeline
            .discard_recovery_completion(&self.recipe.worker)
            .await
        {
            debug!(worker = %self.recipe.worker.id, %error, "completion receipt cleanup failed");
        }
    }
}

fn load_recipe(writer: &DurableLeaseWriter) -> anyhow::Result<RecoveryRecipe> {
    let lease = writer.snapshot();
    let mut recipe: RecoveryRecipe = serde_json::from_value(
        lease
            .recovery
            .context("job has no durable source/retrieval recipe")?,
    )?;
    // Leases written before bd-4d1hs may carry a trailing-slash root that the
    // source-authority lock plan refuses; recover them under the canonical
    // spelling instead of failing forever.
    for root in &mut recipe.source_roots {
        *root = super::super::ssh::canonical_source_authority_root(root);
    }
    anyhow::ensure!(
        recipe.version == 2
            && recipe.wrapper_id == lease.identity.local_wrapper_id
            && Some(recipe.build_id) == lease.identity.remote_build_id
            && lease.worker_id.as_deref() == Some(recipe.worker.id.as_str()),
        "recovery recipe identity mismatch or unsupported source ownership version"
    );
    anyhow::ensure!(
        recipe.source_cancellation_settled != Some(true)
            || (recipe.returned.is_some_and(|exit| exit != 0)
                && recipe.sources_released
                && recipe.tree_retired
                && recipe.pair_released),
        "source cancellation settlement contradicts failed delivery or resource retirement evidence"
    );
    validate_retained_source_intent(
        &recipe.source_roots,
        recipe.pair.as_ref(),
        recipe.retire_root.as_deref(),
        recipe.retained_root.as_deref(),
        &recipe.identity,
    )?;
    anyhow::ensure!(
        recipe
            .transfer
            .retrieval_staging_dir
            .as_ref()
            .is_none_or(|path| path.is_absolute()),
        "persisted retrieval staging directory must be absolute"
    );
    anyhow::ensure!(
        recipe.retained_materialized.is_none() || recipe.retained_root.is_some(),
        "retained source acknowledgment has no original destination"
    );
    if recipe.retained_root.is_some() {
        anyhow::ensure!(
            recipe.tree_retired == recipe.retained_materialized.is_some()
                && (!recipe.retired || recipe.tree_retired)
                && (recipe.retained_materialized != Some(false)
                    || (!recipe.execution_started && recipe.preparation_cancelled)),
            "retained source acknowledgment contradicts the execution or retirement boundary"
        );
    }
    anyhow::ensure!(
        recipe.cargo_output_capture.is_none()
            || (recipe.prepared
                && recipe
                    .phases
                    .iter()
                    .filter(|phase| phase.output_gate)
                    .count()
                    == 1),
        "captured Cargo recovery has an invalid output root contract"
    );
    anyhow::ensure!(
        recipe.phases.iter().all(|phase| {
            phase.cargo_outputs.is_none()
                || (recipe.cargo_output_capture.is_some() && phase.output_gate)
        }),
        "Cargo output evidence is attached to an unrelated recovery phase"
    );
    if let Some(project) = recipe.caller_json_policy.as_ref() {
        anyhow::ensure!(
            recipe.prepared
                && project.is_absolute()
                && !project.to_string_lossy().chars().any(char::is_control)
                && !WorkerPlatform::from_worker(&recipe.worker).is_windows()
                && recipe
                    .cargo_output_capture
                    .as_ref()
                    .is_some_and(CargoOutputCapture::caller_json_supported),
            "caller Cargo JSON recovery has an invalid admitted source/output policy"
        );
    } else {
        anyhow::ensure!(
            recipe.cargo_stderr.is_none() && recipe.caller_delivery.is_none(),
            "retained caller Cargo output has no original opt-in policy"
        );
    }
    if let Some(producer) = recipe.cargo_stdout.as_ref() {
        anyhow::ensure!(
            recipe.execution_started
                && recipe.exit_code == Some(producer.exit_code)
                && recipe.cargo_output_capture.is_some()
                && (recipe.caller_json_policy.is_some() || producer.exit_code == 0)
                && (recipe.caller_json_policy.is_none() || producer.remote_project_root.is_some())
                && producer.bytes
                    <= super::super::cargo_output_contract::MAX_CARGO_OUTPUT_RECEIPT_BYTES as u64,
            "retained Cargo producer contradicts the original completion"
        );
    }
    if let Some(diagnostics) = recipe.cargo_stderr.as_ref() {
        anyhow::ensure!(
            recipe.execution_started && recipe.exit_code == Some(diagnostics.exit_code),
            "retained Cargo diagnostics contradict the original completion"
        );
    }
    if recipe.caller_delivery.is_some() {
        anyhow::ensure!(
            recipe.exit_code == Some(0)
                && recipe.returned == Some(0)
                && recipe
                    .cargo_stdout
                    .as_ref()
                    .is_some_and(|producer| producer.exit_code == 0)
                && recipe
                    .phases
                    .iter()
                    .filter(|phase| phase.output_gate)
                    .all(|phase| phase.complete && phase.pending.is_none()),
            "retained caller Cargo delivery precedes successful publication"
        );
    }
    result_recovery::validate_missing_results(&recipe)?;
    for phase in &recipe.phases {
        if let Some(contract) = &phase.native_outputs {
            anyhow::ensure!(
                recipe.prepared
                    && phase.name == "project"
                    && phase.result_dir.is_none()
                    && !phase.custom_target
                    && phase.local == recipe.project_root
                    && !WorkerPlatform::from_worker(&recipe.worker).is_windows()
                    && contract.patterns()? == phase.patterns,
                "native output contract is attached to an unrelated recovery phase"
            );
        }
    }
    Ok(recipe)
}

/// Cancel only preparation. The remote activity fence drains surviving sync
/// processes and denies late arrivals before any root becomes writable again.
/// Once execution might have started, only its exact completion can retire it.
pub(crate) async fn cancel_preparation(writer: &DurableLeaseWriter) -> anyhow::Result<bool> {
    let recipe = load_recipe(writer)?;
    if recipe.retired {
        RecoverySession {
            recipe,
            writer: writer.clone(),
        }
        .reconcile_source_cancellation()
        .await?;
        return Ok(true);
    }
    if recipe.execution_started {
        return Ok(false);
    }
    let mut session = RecoverySession {
        recipe,
        writer: writer.clone(),
    };
    let mut next_recipe = session.recipe.clone();
    next_recipe.preparation_cancelled = true;
    session.persist_next_recipe(next_recipe)?;
    cancel_source_grant(session).await
}

/// Cancel the job's source grant (and pair), reap its remote tree, and retire
/// the recipe with a build-error exit. Callers must have proven that nothing
/// of the job can still run remotely: execution never started, its exact
/// completion was read, or `remote_execution_lost` found it gone.
async fn cancel_source_grant(mut session: RecoverySession) -> anyhow::Result<bool> {
    session.validate_cancellation_pair()?;
    // Preserve the obligation even when SSH loses the cancellation reply or
    // the wrapper dies after worker retirement. Executed-but-lost attempts use
    // this path too, so preparation_cancelled alone cannot identify it.
    let mut next_recipe = session.recipe.clone();
    next_recipe.source_cancellation_settled = Some(false);
    session.persist_next_recipe(next_recipe)?;
    let namespace = session.bind_source_namespace().await?;
    let worker = session.recipe.worker.clone();
    let owned = super::super::ssh::cancel_remote_source_authority_intent(
        &worker,
        &session.recipe.source_roots,
        &session.recipe.identity,
        namespace,
    )
    .await?;
    let mut pair = if let Some((root, token)) = session.recipe.pair.clone() {
        super::super::ssh::cancel_clean_overlay_source_pair_intent(
            &worker,
            &root,
            &token,
            Duration::from_secs(15),
            namespace,
        )
        .await?
    } else {
        None
    };
    anyhow::ensure!(
        owned || pair.is_none(),
        "cancelled intent without a source grant cannot acquire a source pair"
    );
    if let Some((root, token)) = &session.recipe.pair
        && pair.is_none()
        && (owned || session.recipe.execution_started)
    {
        anyhow::ensure!(
            session.recipe.tree_retired,
            "source cancellation cannot retire an unverified tree without its exact pair guard"
        );
        anyhow::ensure!(
            session.recipe.pair_released
                || super::super::ssh::clean_overlay_source_pair_was_released(
                    &worker, root, token, namespace,
                )
                .await?,
            "source cancellation has no exact pair release receipt; ownership retained"
        );
    }
    if owned {
        if let Some(pair) = pair.as_mut() {
            pair.ensure_held()?;
        }
        // The full durable grant still excludes every overlapping owner.
        // Cleanup activity survives its SSH client and is drained again
        // before final cancellation can make these paths writable.
        let pipeline = TransferPipeline::new(
            session.recipe.project_root.clone(),
            "recovery".into(),
            session.recipe.identity.clone(),
            session.recipe.transfer.clone(),
        )
        .with_source_authority_cleanup(session.recipe.identity.clone(), namespace)?;
        session.retire_source_tree(&pipeline).await?;
        if let Some(pair) = pair.take() {
            pair.release().await?;
        }
        super::super::ssh::finish_cancel_remote_source_authority_intent(
            &worker,
            &session.recipe.source_roots,
            &session.recipe.identity,
            namespace,
        )
        .await?;
    }
    // Without a full grant, cancellation only fences delayed acquisition and
    // abandons pair metadata. The paths may belong to another parent-root job.
    if !owned && session.recipe.retained_root.is_some() && !session.recipe.tree_retired {
        anyhow::ensure!(
            !session.recipe.execution_started && session.recipe.preparation_cancelled,
            "an executed source pair cannot be retired without its full source grant"
        );
        // No activity was admitted for this identity. Do not inspect paths
        // now owned by someone else or manufacture a retained tree receipt.
        session.persist_tree_retirement(Some(false))?;
    } else {
        session.tree_retired()?;
    }
    session.pair_released()?;
    session.sources_released()?;
    session.returned(EXIT_BUILD_ERROR)?;
    session.reconcile_source_cancellation().await?;
    session.retired()?;
    Ok(true)
}

/// Recollect the admitted command's outputs; no execution path is reachable.
pub(crate) async fn recover_job(
    writer: &DurableLeaseWriter,
) -> anyhow::Result<(i32, DurableLeaseWriter)> {
    let owned = recovery_owner::claim(writer).await?;
    let exit = Box::pin(recover_owned_job(&owned)).await?;
    owned
        .recovery_ownership
        .as_ref()
        .context("recovery has no journal owner")?
        .verify()?;
    Ok((exit, owned))
}

async fn recover_owned_job(writer: &DurableLeaseWriter) -> anyhow::Result<i32> {
    // The recipe is reloaded after claim. Persist extensions before collection
    // so a subsequent retry keeps them even without the invocation config.
    if !writer.snapshot().terminal_acknowledged {
        let config = crate::config::load_config()?;
        let mut session = RecoverySession {
            recipe: load_recipe(writer)?,
            writer: writer.clone(),
        };
        if session.recipe.returned.is_none() {
            session.apply_retrieval_config(&config.transfer)?;
        }
    }
    // Resolve lazily: an acknowledged cancellation reconciles worker metadata,
    // but does not need to reopen completed daemon accounting. Ordinary
    // acknowledged delivery remains a local operation.
    let mut socket = None;
    Box::pin(recover_owned_job_with_daemon(
        writer,
        async |command: &str| {
            if socket.is_none() {
                let config = crate::config::load_config()?;
                socket = Some(shellexpand::tilde(&config.general.socket_path).into_owned());
            }
            recovery_completion::request(socket.as_deref().expect("resolved socket"), command).await
        },
    ))
    .await
}

/// Recover only the original opt-in invocation, then return its durable stdout.
/// An ordinary job cannot acquire a Cargo output contract after execution.
pub(crate) async fn recover_job_cargo_json(
    writer: &DurableLeaseWriter,
) -> anyhow::Result<(i32, Option<Vec<u8>>, Vec<u8>)> {
    let owned = recovery_owner::claim(writer).await?;
    let writer = &owned;
    {
        let recipe = load_recipe(writer)?;
        anyhow::ensure!(
            recipe.execution_started
                && recipe.caller_json_policy.is_some()
                && recipe
                    .cargo_output_capture
                    .as_ref()
                    .is_some_and(CargoOutputCapture::caller_json_supported),
            "Cargo JSON recovery requires the original admitted opt-in named-binary invocation"
        );
    }
    let exit = Box::pin(recover_owned_job(writer)).await?;
    // Keep the same namespace and lock through acknowledgement and readback.
    let recipe = load_recipe(writer)?;
    let lease = writer.snapshot();
    anyhow::ensure!(
        lease.terminal_acknowledged
            && lease.exit_code == Some(exit)
            && recipe.returned == Some(exit)
            && recipe.retired
            && recipe.caller_json_policy.is_some(),
        "Cargo JSON recovery lacks its exact acknowledged delivery result"
    );
    let session = RecoverySession {
        recipe,
        writer: writer.clone(),
    };
    let stdout = if exit == 0 {
        anyhow::ensure!(
            session.recipe.exit_code == Some(0),
            "successful Cargo recovery contradicts its compiler completion"
        );
        let producer = session
            .recipe
            .cargo_stdout
            .as_ref()
            .context("successful Cargo recovery has no retained producer stdout")?;
        let delivery = session
            .recipe
            .caller_delivery
            .as_ref()
            .context("successful Cargo recovery has no retained caller delivery")?;
        Some(delivery.read(producer)?)
    } else if session
        .recipe
        .cargo_stdout
        .as_ref()
        .is_some_and(|receipt| receipt.exit_code != 0)
    {
        Some(session.failed_cargo_stdout()?)
    } else {
        // Compiler success with failed delivery must not advertise success.
        None
    };
    let diagnostics = session
        .recipe
        .cargo_stderr
        .as_ref()
        .context("Cargo recovery has no retained complete compiler stderr")?;
    anyhow::ensure!(
        session.recipe.exit_code == Some(diagnostics.exit_code),
        "recovered Cargo stderr contradicts its compiler completion"
    );
    let stderr = diagnostics.read()?;
    writer
        .recovery_ownership
        .as_ref()
        .context("recovery has no journal owner")?
        .verify()?;
    Ok((exit, stdout, stderr))
}

#[cfg(test)]
async fn recover_job_with_daemon(
    writer: &DurableLeaseWriter,
    daemon: impl AsyncFnMut(&str) -> anyhow::Result<String>,
) -> anyhow::Result<i32> {
    let owned = recovery_owner::claim(writer).await?;
    let exit = Box::pin(recover_owned_job_with_daemon(&owned, daemon)).await?;
    owned
        .recovery_ownership
        .as_ref()
        .context("recovery has no journal owner")?
        .verify()?;
    Ok(exit)
}

async fn retire_already_released_source_grant(
    session: &mut RecoverySession,
    writer: &DurableLeaseWriter,
    daemon: &mut impl AsyncFnMut(&str) -> anyhow::Result<String>,
    observed_exit: Option<i32>,
) -> anyhow::Result<i32> {
    retire_already_released_source_grant_with(
        session,
        writer,
        daemon,
        observed_exit,
        async |session| session.reconcile_source_cancellation().await,
    )
    .await
}

async fn retire_already_released_source_grant_with(
    session: &mut RecoverySession,
    writer: &DurableLeaseWriter,
    daemon: &mut impl AsyncFnMut(&str) -> anyhow::Result<String>,
    observed_exit: Option<i32>,
    mut reconcile: impl AsyncFnMut(&mut RecoverySession) -> anyhow::Result<()>,
) -> anyhow::Result<i32> {
    if let Some(exit) = observed_exit {
        session.completed(exit)?;
    }
    let retired_exit = if result_recovery::has_missing_results(&session.recipe) {
        EXIT_ARTIFACT_TRANSFER_FAILED
    } else if let Some(existing) = writer.snapshot().exit_code.filter(|code| *code != 0) {
        existing
    } else if observed_exit == Some(0) || session.recipe.exit_code == Some(0) {
        EXIT_ARTIFACT_TRANSFER_FAILED
    } else {
        observed_exit
            .or(session.recipe.exit_code)
            .unwrap_or(EXIT_BUILD_ERROR)
    };
    tracing::warn!(
        identity = %session.recipe.identity,
        worker = %session.recipe.worker.id,
        ?observed_exit,
        retired_exit,
        "source grant was already released before outputs were returned; retiring lease without reopening worker paths"
    );
    if !session.recipe.tree_retired {
        session.tree_retired()?;
    }
    if !session.recipe.pair_released {
        session.pair_released()?;
    }
    if !session.recipe.sources_released {
        session.sources_released()?;
    }
    session.returned(retired_exit)?;
    // Cancellation may have durably released the worker before the process
    // died between sources_released and returned. Complete its remaining
    // metadata obligation before the retirement/acknowledgement gates.
    reconcile(session).await?;
    session.retired()?;
    session.discard_completion_receipts().await;
    writer.record_exit(retired_exit)?;
    recovery_completion::finish(writer, daemon).await?;
    Ok(retired_exit)
}

async fn settle_already_released_source_grant(
    session: &mut RecoverySession,
    writer: &DurableLeaseWriter,
    daemon: &mut impl AsyncFnMut(&str) -> anyhow::Result<String>,
    observed_exit: Option<i32>,
) -> anyhow::Result<Option<i32>> {
    if session.recipe.returned.is_some()
        || session.recipe.source_roots.is_empty()
        || (session.recipe.retained_root.is_some() && !session.recipe.tree_retired)
    {
        return Ok(None);
    }
    let worker = session.recipe.worker.clone();
    let namespace = session.bind_source_namespace().await?;
    if !session.recipe.sources_released
        && !super::super::ssh::remote_source_authority_was_released(
            &worker,
            &session.recipe.source_roots,
            &session.recipe.identity,
            namespace,
        )
        .await?
    {
        return Ok(None);
    }
    if !session.recipe.pair_released
        && let Some((root, token)) = session.recipe.pair.clone()
        && !super::super::ssh::clean_overlay_source_pair_was_released(
            &worker, &root, &token, namespace,
        )
        .await?
    {
        return Ok(None);
    }
    retire_already_released_source_grant(session, writer, daemon, observed_exit)
        .await
        .map(Some)
}

/// Whether a local `session.publish` error in detached recovery (`recover_owned_job_with_daemon`)
/// is a permanent local output-tree / `.rch-return` refusal that cannot improve on retry.
///
/// Transient or environmental errors (cancellation, lock contention, alias race while waiting
/// for the lock, storage exhaustion, or journal write failures) return `false` so recovery
/// keeps the source claim and remains retryable. Permanent local output-tree refusals
/// (e.g. a dangling symlink in `phase.local`, a pre-`96ca9bf3` `0644` `.rch-return-<id>`
/// temporary, a symlinked ancestor inside the output root, or conflicting local ownership)
/// return `true` so `recover_owned_job_with_daemon` can retire the build as
/// `EXIT_ARTIFACT_TRANSFER_FAILED`, release the worker source claim, and retain the staged
/// outputs locally (`bd-7e3bt`).
fn publication_failure_is_terminal_in_recovery(error: &anyhow::Error) -> bool {
    if error.is::<publication_runtime::PublicationCancelled>() {
        return false;
    }
    let detail = format!("{error:#}");
    const TERMINAL_REFUSALS: &[&str] = &[
        "cannot resolve existing output root entry ",
        "output publication root has a non-directory component:",
        "output publication requires a Unix directory path:",
        "retained output is not a private partial copy or a complete correctly-permissioned copy",
        "retained publication copy is not the exact staged prefix",
        "publication copy identity, length, permissions or links changed",
        "publication copy directory changed",
        "retained publication prefix changed during validation",
        "publication copy changed before writable open",
        "retained temporary is not a regular file",
        "retained output temporary is not a regular file:",
        "retained output temporary permissions or links changed:",
        "retained output temporary permissions changed",
        "held retained temporary permissions differ from staged output",
        "prepared output is not a regular file",
        "prepared output identity, permissions or links changed",
        "prepared output bytes changed:",
        "prepared output length changed",
        "output ownership changed at ",
        "interrupted output publication cannot prove ownership at ",
        "output changed while publishing ",
        "output is not a regular file:",
        "output ancestor is a symlink:",
        "output ancestor is not a directory:",
        "output ancestor escaped its phase root",
        "output parent is not a directory",
        "output publication requires a root-relative file path",
        "internal source archive has a pending publication",
        "outside the artifact policy",
    ];
    TERMINAL_REFUSALS
        .iter()
        .any(|needle| detail.contains(needle))
}

async fn recover_owned_job_with_daemon(
    writer: &DurableLeaseWriter,
    mut daemon: impl AsyncFnMut(&str) -> anyhow::Result<String>,
) -> anyhow::Result<i32> {
    // Hold one journal owner across the ENTIRE detached recovery, including
    // worker probes, source release and final daemon reservation reconciliation.
    // claim reloads the latest disk state after acquisition and never mistakes
    // an unverified wrapper for a dead one.
    writer
        .recovery_ownership
        .as_ref()
        .context("recovery has no journal owner")?
        .verify()?;
    let recipe = load_recipe(writer)?;
    let mut session = RecoverySession {
        recipe,
        writer: writer.clone(),
    };
    // Validate present producer custody before successful terminal
    // shortcut. These branches may only use local original evidence: a
    // released worker path is never reopened and an absent legacy receipt
    // remains absent. Retain the same verified bytes for unfinished recovery.
    // A recorded failed delivery must still reconcile/release its ownership;
    // it advertises no successful artifact or SDK evidence to borrow.
    let retained_cargo_evidence = if session.recipe.exit_code == Some(0)
        && session.recipe.returned.is_none_or(|exit| exit == 0)
    {
        session.retained_cargo_artifact_evidence()?
    } else {
        None
    };
    let lease = writer.snapshot();
    if lease.terminal_acknowledged {
        let exit = session
            .recipe
            .returned
            .context("terminal recovery lacks a delivery result")?;
        anyhow::ensure!(
            session.recipe.retired
                && lease.state == rch_common::job_identity::JobLifecycleState::Finished
                && lease.exit_code == Some(exit)
                && (session.recipe.source_roots.is_empty() || session.recipe.sources_released)
                && (session.recipe.pair.is_none() || session.recipe.pair_released)
                && (session.recipe.retire_root.is_none() || session.recipe.tree_retired),
            "terminal recovery contradicts its retained delivery/retirement evidence"
        );
        session.discover_terminal_source_cancellation().await?;
        session.reconcile_source_cancellation().await?;
        return Ok(exit);
    }
    if !session.recipe.execution_started {
        cancel_preparation(writer).await?;
        writer.record_exit(EXIT_BUILD_ERROR)?;
        recovery_completion::finish(writer, &mut daemon).await?;
        return Ok(EXIT_BUILD_ERROR);
    }
    if let Some(exit) = session.recipe.returned {
        session.retire_returned().await?;
        writer.record_exit(exit)?;
        recovery_completion::finish(writer, &mut daemon).await?;
        return Ok(exit);
    }
    if let Some(exit) = session.resume_retired_source_pair_cancellation().await? {
        writer.record_exit(exit)?;
        recovery_completion::finish(writer, &mut daemon).await?;
        return Ok(exit);
    }
    if session.recipe.sources_released
        && (session.recipe.pair.is_none() || session.recipe.pair_released)
        && (session.recipe.retained_root.is_none() || session.recipe.tree_retired)
    {
        return retire_already_released_source_grant(&mut session, writer, &mut daemon, None).await;
    }
    let worker = session.recipe.worker.clone();
    let namespace = session.bind_source_namespace().await?;
    let base = TransferPipeline::new(
        session.recipe.project_root.clone(),
        "recovery".into(),
        session.recipe.identity.clone(),
        session.recipe.transfer.clone(),
    );
    let base = session.completion_pipeline(base);
    let Some(mut exit) = base.read_recovery_completion(&worker).await? else {
        // A supervisor that died without its receipt (worker reboot, OOM,
        // kill) never writes one, and waiting for it kept the lease's source
        // claim fencing the worker forever. When the probe proves the
        // execution is gone, retire it as a failed build: nothing is replayed.
        if !session.recipe.source_roots.is_empty()
            && super::super::ssh::remote_execution_lost(
                &worker,
                &session.recipe.identity,
                &session.recipe.completion,
                namespace,
            )
            .await?
        {
            if let Some(retired_exit) =
                settle_already_released_source_grant(&mut session, writer, &mut daemon, None)
                    .await?
            {
                return Ok(retired_exit);
            }
            tracing::warn!(
                identity = %session.recipe.identity,
                worker = %worker.id,
                "remote execution ended without a completion receipt; retiring it as failed"
            );
            cancel_source_grant(session).await?;
            writer.record_exit(EXIT_BUILD_ERROR)?;
            recovery_completion::finish(writer, &mut daemon).await?;
            return Ok(EXIT_BUILD_ERROR);
        }
        anyhow::bail!(
            "same-id remote execution has no durable completion yet; command was not replayed"
        );
    };
    // A legacy cancellation can stop before finish-cancel or lose its
    // completed receipt to retention. Its exact marker still denies normal
    // recovery. This completion proves the execution ended, but only the
    // drained cancellation protocol below can grant cleanup and retire it.
    if session
        .checkpoint_completed_source_cancellation_with(exit, async |worker, roots, identity| {
            super::super::ssh::remote_source_intent_has_cancellation(
                worker, roots, identity, namespace,
            )
            .await
        })
        .await?
    {
        tracing::warn!(
            identity = %session.recipe.identity,
            worker = %worker.id,
            remote_exit = exit,
            "resuming source cancellation after execution; retiring it as failed without collecting outputs"
        );
        cancel_source_grant(session).await?;
        writer.record_exit(EXIT_BUILD_ERROR)?;
        recovery_completion::finish(writer, &mut daemon).await?;
        return Ok(EXIT_BUILD_ERROR);
    }
    if let Some(retired_exit) =
        settle_already_released_source_grant(&mut session, writer, &mut daemon, Some(exit)).await?
    {
        return Ok(retired_exit);
    }
    let mut pair = if let Some((root, token)) = &session.recipe.pair {
        Some(
            super::super::ssh::recover_clean_overlay_source_pair(
                &worker,
                root,
                token,
                Duration::from_secs(15),
                namespace,
            )
            .await?,
        )
    } else {
        None
    };
    let mut sources = super::super::ssh::recover_remote_source_authority_lock(
        &worker,
        &session.recipe.source_roots,
        pair.as_mut(),
        &session.recipe.identity,
        Duration::from_secs(15),
        namespace,
    )
    .await?;
    let base = base.with_source_authority_in(session.recipe.identity.clone(), namespace)?;
    session.completed(exit)?;
    let command_exit = exit;
    session.collect_cargo_stderr(&base, &worker).await?;
    // A wrapper can disappear after Cargo finishes but before it records the
    // output set locally. Re-read the complete same-attempt receipt; never
    // rerun Cargo and never silently downgrade to the old glob-only policy.
    let mut rejected_cargo_evidence = false;
    if command_exit == 0 && session.needs_cargo_artifact_evidence() {
        let root = session
            .cargo_artifact_remote_root()
            .context("captured Cargo recovery has no output root")?
            .to_owned();
        // Transport failure remains retryable. A complete but invalid Cargo
        // receipt cannot improve by repeating collection, so retire that
        // attempt as a delivery failure while retaining its receipt/stage.
        let evidence = if let Some(retained) = retained_cargo_evidence {
            Ok(retained)
        } else if let Some(project) = session.recipe.caller_json_policy.as_ref() {
            // The generic recovery pipeline is not the executed source root.
            // Restore only the exact opt-in path persisted before execution.
            base.clone()
                .with_remote_path_override(
                    project
                        .to_str()
                        .context("persisted Cargo source root is not UTF-8")?,
                )
                .read_cargo_stdout_evidence(&worker, &root, 0)
                .await
        } else {
            base.read_cargo_artifact_evidence(&worker, &root).await
        };
        match evidence {
            Ok(evidence) => {
                if let Err(error) = session.install_complete_cargo_evidence(&evidence) {
                    if !error.is::<CargoOutputContractRejected>() {
                        return Err(error);
                    }
                    eprintln!(
                        "[RCH] recovered Cargo output evidence is invalid: {error:#}; \
                         no build artifacts published (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                    );
                    rejected_cargo_evidence = true;
                }
            }
            Err(error) if error.is::<crate::transfer::CargoArtifactEvidenceRejected>() => {
                eprintln!(
                    "[RCH] recovered Cargo output evidence was rejected: {error:#}; \
                     no build artifacts published (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                );
                rejected_cargo_evidence = true;
            }
            Err(error) if base.remote_path_absent(&worker, &root).await? => {
                eprintln!(
                    "[RCH] recovered Cargo output root is gone ({root}): {error:#}; \
                     no build artifacts published (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                );
                rejected_cargo_evidence = true;
            }
            Err(error) => return Err(error),
        }
        if rejected_cargo_evidence {
            exit = EXIT_ARTIFACT_TRANSFER_FAILED;
        }
    } else if let Some(retained) = retained_cargo_evidence {
        session.install_complete_cargo_evidence(&retained)?;
    }
    if command_exit != 0
        && let Some(project) = session.recipe.caller_json_policy.clone()
    {
        if session.recipe.cargo_stdout.is_none() {
            // Failed Cargo need not create a target tree. Use the executed
            // source root for physical-path proof, and preserve the complete
            // same-attempt nonzero stdout before retiring its supervisor log.
            let source = project
                .to_str()
                .context("persisted Cargo source root is not UTF-8")?;
            let evidence = base
                .clone()
                .with_remote_path_override(source)
                .read_cargo_stdout_evidence(&worker, source, command_exit)
                .await?;
            session.retain_cargo_stdout(
                &evidence.stdout,
                &evidence.remote_root,
                evidence
                    .remote_project_root
                    .as_deref()
                    .context("recovered Cargo stdout has no verified source root")?,
                command_exit,
            )?;
        } else {
            session.failed_cargo_stdout()?;
        }
    }
    for index in 0..session.recipe.phases.len() {
        let phase = session.recipe.phases[index].clone();
        if phase.complete
            || ((command_exit != 0 || rejected_cargo_evidence) && phase.result_dir.is_none())
        {
            continue;
        }
        sources.ensure_held()?;
        if let Some(pair) = pair.as_mut() {
            pair.ensure_held()?;
        }
        let pipeline = base
            .clone()
            .with_remote_path_override(phase.remote.clone())
            .with_retrieval_reference_root(phase.local.clone())
            .with_local_root(session.stage(index));
        std::fs::create_dir_all(session.stage(index))?;
        if phase.result_dir.is_some() {
            // The completion receipt and recovered source grant above fence
            // the producer. Absence is now a failed output contract, not an
            // endlessly retryable transfer. Still collect other result dirs.
            if !result_recovery::collect_result(&mut session, index, &pipeline, &worker).await? {
                exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                continue;
            }
        } else {
            if phase.output_gate
                && !session.recipe.allow_foreign
                && kind_has_enumerable_output_contract(session.recipe.kind)
            {
                let preflight = preflight_artifact_platform(
                    &pipeline,
                    &worker,
                    &phase.patterns,
                    phase.custom_target,
                    &session.recipe.expected_triple,
                    session.recipe.pinned_triple.as_deref(),
                )
                .await;
                match preflight {
                    Ok(Some(rejection)) => {
                        eprintln!("[RCH] {rejection}");
                        exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                        break;
                    }
                    Ok(None) => {}
                    Err(error) if pipeline.remote_path_absent(&worker, &phase.remote).await? => {
                        eprintln!(
                            "[RCH] recovered output root is gone before platform preflight: {error:#}"
                        );
                        exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            let retrieved = match pipeline.retrieve_artifacts(&worker, &phase.patterns).await {
                Ok(retrieved) => retrieved,
                // Outputs whose remote tree is gone (e.g. a GC'd target pool)
                // can never come back: failing here stranded the job and its
                // worker-side source claim on every retry. Like a rejected
                // output set, it is a terminal build failure.
                Err(error) if pipeline.remote_path_absent(&worker, &phase.remote).await? => {
                    eprintln!(
                        "[RCH] recovered outputs are gone from the worker ({}): {error:#}; \
                         treating the recovered build as failed (exit {EXIT_ARTIFACT_TRANSFER_FAILED})",
                        phase.remote
                    );
                    exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                    break;
                }
                Err(error) => return Err(error),
            };
            if let Err(error) = session.verify_native_outputs(index) {
                eprintln!(
                    "[RCH] recovered native outputs are incomplete: {error:#}; \
                     no build artifacts published (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                );
                exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                break;
            }
            if phase.output_gate {
                // A rejected output set is a terminal build failure, exactly
                // as on the live path, not a recovery error: the remote outputs
                // never change, so an error would strand source ownership on
                // every retry. Publish nothing further, then retire normally.
                let rejection = if let Err(error) = session.verify_cargo_outputs(index) {
                    Some(format!("recovered Cargo outputs are incomplete: {error:#}"))
                } else if sync_back_verified_zero_build_outputs(
                    &retrieved.manifest_regular_files,
                    retrieved.matched_regular_files,
                    session.recipe.kind,
                    phase.custom_target,
                ) || (session.recipe.package_archive
                    && retrieved.matched_regular_files == Some(0))
                {
                    Some("recovered transfer matched zero expected outputs".to_owned())
                } else if !session.recipe.allow_foreign
                    && kind_has_enumerable_output_contract(session.recipe.kind)
                {
                    let foreign = foreign_target_artifacts(
                        &session.stage(index),
                        &retrieved.manifest_regular_files,
                        phase.custom_target,
                        &session.recipe.expected_triple,
                        session.recipe.pinned_triple.as_deref(),
                    );
                    (!foreign.is_empty()).then(|| {
                        format!(
                            "recovered outputs target a foreign platform: {}",
                            describe_findings(&foreign)
                        )
                    })
                } else {
                    None
                };
                if let Some(rejection) = rejection {
                    eprintln!(
                        "[RCH] {rejection}; treating the recovered build as failed \
                         (exit {EXIT_ARTIFACT_TRANSFER_FAILED})"
                    );
                    exit = EXIT_ARTIFACT_TRANSFER_FAILED;
                    break;
                }
            }
        }
        if let Err(error) = session.publish(&phase.name).await {
            if !publication_failure_is_terminal_in_recovery(&error) {
                return Err(error);
            }
            eprintln!(
                "[RCH] recovered output publication refused ({}): {error:#}; \
                 treating the recovered build as failed (exit {EXIT_ARTIFACT_TRANSFER_FAILED})",
                phase.name
            );
            exit = EXIT_ARTIFACT_TRANSFER_FAILED;
            break;
        }
    }
    // Publication is the durable terminal boundary. Retirement can be retried
    // independently and must never cause a second output write.
    session.returned(exit)?;
    session.prepare_caller_delivery().await?;
    session.retire_source_tree(&base).await?;
    if let Some(pair) = pair.take() {
        pair.release().await?;
    }
    session.pair_released()?;
    sources.release().await?;
    session.sources_released()?;
    session.retired()?;
    session.discard_completion_receipts().await;
    writer.record_exit(exit)?;
    recovery_completion::finish(writer, &mut daemon).await?;
    Ok(exit)
}

/// Exercise the same durable publication boundary with real Cargo records from
/// the selector's owned fixture, without running Cargo a second time here.
#[cfg(test)]
pub(crate) async fn assert_cargo_fixture_publication(
    kind: CompilationKind,
    command: &str,
    stdout: &[u8],
    remote_root: &Path,
    custom_target: bool,
) {
    tests::assert_cargo_fixture_publication(kind, command, stdout, remote_root, custom_target)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    fn admitted_preparation_fixture() -> (tempfile::TempDir, DurableLeaseWriter, WorkerConfig) {
        // Retain construction failures too; calling keep only after setup
        // succeeds lets a panic delete evidence through TempDir's destructor.
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("source-recovery"),
            host: "unreachable.invalid".into(),
            user: "worker".into(),
            identity_file: "/unused/test-key".into(),
            total_slots: 1,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        };
        let writer = DurableLeaseWriter {
            path: directory.path().join("lease.json"),
            recovery_ownership: None,
            lease: Arc::new(Mutex::new(DurableJobLease::new(
                JobIdentity::new_local(),
                std::process::id(),
                None,
                None,
                0,
                false,
                false,
                "test-command-fingerprint".into(),
            ))),
        };
        writer.admit(41, &worker.id).unwrap();
        (directory, writer, worker)
    }

    fn preparation_fixture() -> (tempfile::TempDir, DurableLeaseWriter, WorkerConfig) {
        preparation_fixture_with_identity("abc123")
    }

    fn preparation_fixture_with_identity(
        identity: &str,
    ) -> (tempfile::TempDir, DurableLeaseWriter, WorkerConfig) {
        let (directory, writer, worker) = admitted_preparation_fixture();
        RecoverySession::begin(
            &writer,
            &worker,
            vec!["/data/projects/source-recovery".into()],
            None,
            None,
            None,
            TransferConfig::default(),
            directory.path().to_owned(),
            identity.into(),
        )
        .unwrap();
        (directory, writer, worker)
    }

    #[tokio::test]
    async fn new_source_intent_is_bound_before_worker_admission() {
        let (_directory, writer, _) = preparation_fixture();
        assert_eq!(
            writer.snapshot().recovery.as_ref().unwrap()["source_authority_namespace"],
            "current"
        );
        let before = std::fs::read(&writer.path).unwrap();
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer: writer.clone(),
        };
        assert_eq!(
            session
                .bind_source_namespace_with(async |_, _, _| {
                    panic!("a persisted admission binding must never rediscover another namespace")
                })
                .await
                .unwrap(),
            SourceAuthorityNamespace::Current
        );
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_namespace_binding_preserves_original_evidence_and_survives_reload() {
        for namespace in [
            SourceAuthorityNamespace::Current,
            SourceAuthorityNamespace::Legacy,
        ] {
            let (_directory, writer) = terminal_cancellation_fixture();
            let mut original = writer.snapshot().recovery.unwrap();
            original
                .as_object_mut()
                .unwrap()
                .remove("source_authority_namespace");
            original["source_roots"] = serde_json::json!(["/data//projects/source-recovery/"]);
            original["future_custody"] = serde_json::json!({"keep": true});
            writer.set_recovery(original.clone()).unwrap();
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            assert_eq!(
                session
                    .bind_source_namespace_with(async |_, roots, identity| {
                        assert_eq!(roots, &["/data/projects/source-recovery"]);
                        assert_eq!(identity, "0123456789abcdef0123456789abcdef");
                        Ok(namespace)
                    })
                    .await
                    .unwrap(),
                namespace
            );
            original["source_authority_namespace"] = serde_json::to_value(namespace).unwrap();
            assert_eq!(owned.snapshot().recovery.unwrap(), original);
            drop(session);
            drop(owned);
            let reloaded = DurableLeaseWriter {
                path: writer.path.clone(),
                recovery_ownership: None,
                lease: Arc::new(Mutex::new(
                    DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap(),
                )),
            };
            let owned = recovery_owner::claim(&reloaded).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            assert_eq!(
                session
                    .bind_source_namespace_with(async |_, _, _| {
                        panic!("restart must reuse the recorded namespace")
                    })
                    .await
                    .unwrap(),
                namespace
            );
            assert_eq!(owned.snapshot().recovery.unwrap(), original);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn namespace_binding_refuses_ambiguous_inventory_changed_journal_and_lost_owner() {
        for failure in ["inventory", "journal", "owner"] {
            let (directory, writer) = terminal_cancellation_fixture();
            let mut original = writer.snapshot().recovery.unwrap();
            original
                .as_object_mut()
                .unwrap()
                .remove("source_authority_namespace");
            writer.set_recovery(original.clone()).unwrap();
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let result = session
                .bind_source_namespace_with(async |_, _, _| {
                    match failure {
                        "inventory" => anyhow::bail!("ambiguous worker identity"),
                        "journal" => {
                            let mut changed = original.clone();
                            changed["identity"] = serde_json::json!("abcdef");
                            owned.set_recovery(changed)?;
                        }
                        "owner" => {
                            std::fs::hard_link(
                                owned.path.with_extension("recovery.lock"),
                                directory.path().join("extra-owner-link"),
                            )?;
                        }
                        _ => unreachable!(),
                    }
                    Ok(SourceAuthorityNamespace::Legacy)
                })
                .await;
            assert!(result.is_err(), "{failure}");
            assert_eq!(session.recipe.source_authority_namespace, None);
            assert!(
                owned.snapshot().recovery.as_ref().unwrap()["source_authority_namespace"].is_null()
            );
            if failure != "journal" {
                assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            }
        }
    }

    #[test]
    fn malformed_source_namespace_never_enters_recovery() {
        for value in [
            serde_json::json!("tmp"),
            serde_json::json!(true),
            serde_json::json!({"current": true}),
        ] {
            let (_directory, writer, _) = preparation_fixture();
            let mut recipe = writer.snapshot().recovery.unwrap();
            recipe["source_authority_namespace"] = value;
            writer.set_recovery(recipe).unwrap();
            assert!(load_recipe(&writer).is_err());
        }
    }

    fn terminal_cancellation_fixture() -> (tempfile::TempDir, DurableLeaseWriter) {
        let (directory, writer, _) =
            preparation_fixture_with_identity("0123456789abcdef0123456789abcdef");
        let mut recipe = load_recipe(&writer).unwrap();
        // Deliberately model an older acknowledged cancellation. These are
        // local lifecycle facts, not a substitute worker quiescence proof.
        recipe.preparation_cancelled = true;
        recipe.sources_released = true;
        recipe.tree_retired = true;
        recipe.pair_released = true;
        recipe.returned = Some(EXIT_BUILD_ERROR);
        recipe.retired = true;
        writer
            .set_recovery(serde_json::to_value(recipe).unwrap())
            .unwrap();
        writer.record_exit(EXIT_BUILD_ERROR).unwrap();
        // Old binaries acknowledged without the worker settlement field.
        // Today's acknowledgement gate must refuse creating that state.
        writer.lease.lock().unwrap().acknowledge_terminal(1);
        writer.persist().unwrap();
        (directory, writer)
    }

    fn terminal_legacy_cancellation_fixture(
        namespace: Option<SourceAuthorityNamespace>,
        paired: bool,
    ) -> (tempfile::TempDir, DurableLeaseWriter) {
        let (directory, writer) = terminal_cancellation_fixture();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.preparation_cancelled = false;
        recipe.prepared = true;
        recipe.execution_started = true;
        recipe.exit_code = Some(137);
        recipe.source_authority_namespace = namespace;
        if paired {
            let root = recipe.source_roots[0].clone();
            recipe.pair = Some((format!("{root}/./"), recipe.identity.clone()));
            recipe.retire_root = Some(format!("{root}//"));
        }
        let mut original = serde_json::to_value(recipe).unwrap();
        original["source_roots"] = serde_json::json!(["/data//projects/source-recovery/"]);
        original["future_custody"] = serde_json::json!({"original": true});
        writer.set_recovery(original).unwrap();
        (directory, writer)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_legacy_cancellation_discovery_survives_lost_settlement_and_restart() {
        let _guard = test_guard!();
        for recorded in [
            None,
            Some(SourceAuthorityNamespace::Current),
            Some(SourceAuthorityNamespace::Legacy),
        ] {
            for paired in [false, true] {
                let (_directory, writer) = terminal_legacy_cancellation_fixture(recorded, paired);
                let original = writer.snapshot();
                let owned = recovery_owner::claim(&writer).await.unwrap();
                let mut session = RecoverySession {
                    recipe: load_recipe(&owned).unwrap(),
                    writer: owned.clone(),
                };
                let selected = recorded.unwrap_or(SourceAuthorityNamespace::Legacy);
                assert!(
                    session
                        .discover_terminal_source_cancellation_with(
                            async |worker, roots, identity, namespace| {
                                assert_eq!(worker.id.as_str(), "source-recovery");
                                assert_eq!(roots, &["/data/projects/source-recovery"]);
                                assert_eq!(identity, "0123456789abcdef0123456789abcdef");
                                assert_eq!(namespace, recorded);
                                assert!(recovery_owner::claim(&writer).await.is_err());
                                assert_eq!(owned.snapshot(), original);
                                Ok(Some(selected))
                            },
                        )
                        .await
                        .unwrap()
                );
                let mut expected = original.clone();
                let recipe = expected.recovery.as_mut().unwrap();
                recipe["source_authority_namespace"] = serde_json::to_value(selected).unwrap();
                recipe["source_cancellation_settled"] = serde_json::json!(false);
                assert_eq!(owned.snapshot(), expected);
                assert!(writer.ensure_released_for_retry().is_err());
                assert!(owned.ensure_released_for_retry().is_err());
                let pending = std::fs::read(&writer.path).unwrap();
                assert!(
                    session
                        .reconcile_source_cancellation_with(async |_, _, _| {
                            anyhow::bail!("lost worker settlement reply")
                        })
                        .await
                        .is_err()
                );
                assert_eq!(std::fs::read(&writer.path).unwrap(), pending);
                assert_eq!(session.recipe.source_cancellation_settled, Some(false));
                drop(session);
                drop(owned);

                let reloaded = DurableLeaseWriter {
                    path: writer.path.clone(),
                    recovery_ownership: None,
                    lease: Arc::new(Mutex::new(
                        DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id())
                            .unwrap(),
                    )),
                };
                let owned = recovery_owner::claim(&reloaded).await.unwrap();
                let mut session = RecoverySession {
                    recipe: load_recipe(&owned).unwrap(),
                    writer: owned.clone(),
                };
                assert!(
                    !session
                        .discover_terminal_source_cancellation_with(async |_, _, _, _| {
                            panic!("restart must retain the discovered cancellation obligation")
                        })
                        .await
                        .unwrap()
                );
                session
                    .reconcile_source_cancellation_with(async |_, _, _| Ok(()))
                    .await
                    .unwrap();
                expected.recovery.as_mut().unwrap()["source_cancellation_settled"] =
                    serde_json::json!(true);
                assert_eq!(owned.snapshot(), expected);
                let settled = std::fs::read(&writer.path).unwrap();
                assert_eq!(
                    recover_owned_job_with_daemon(&owned, async |_request: &str| {
                        panic!("terminal settlement must not reopen daemon accounting")
                    })
                    .await
                    .unwrap(),
                    EXIT_BUILD_ERROR
                );
                assert_eq!(std::fs::read(&writer.path).unwrap(), settled);
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_legacy_cancellation_discovery_preserves_absent_and_unconfirmed_evidence() {
        let _guard = test_guard!();
        for recorded in [
            None,
            Some(SourceAuthorityNamespace::Current),
            Some(SourceAuthorityNamespace::Legacy),
        ] {
            for unconfirmed in [false, true] {
                let (_directory, writer) = terminal_legacy_cancellation_fixture(recorded, true);
                let owned = recovery_owner::claim(&writer).await.unwrap();
                let mut session = RecoverySession {
                    recipe: load_recipe(&owned).unwrap(),
                    writer: owned.clone(),
                };
                let before = std::fs::read(&writer.path).unwrap();
                let result = session
                    .discover_terminal_source_cancellation_with(async |_, _, _, namespace| {
                        assert_eq!(namespace, recorded);
                        if unconfirmed {
                            anyhow::bail!("worker cancellation evidence is conflicting")
                        }
                        Ok(None)
                    })
                    .await;
                if unconfirmed {
                    assert!(result.is_err());
                } else {
                    assert!(!result.unwrap());
                }
                assert_eq!(std::fs::read(&writer.path).unwrap(), before);
                assert_eq!(session.recipe.source_authority_namespace, recorded);
                assert_eq!(session.recipe.source_cancellation_settled, None);
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_legacy_cancellation_discovery_refuses_changed_proof_and_owner() {
        let _guard = test_guard!();
        for case in ["changed-recipe", "changed-gate", "changed-namespace"] {
            let (directory, writer) =
                terminal_legacy_cancellation_fixture(Some(SourceAuthorityNamespace::Current), true);
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let before = std::fs::read(&writer.path).unwrap();
            let changed = std::cell::RefCell::new(None);
            assert!(
                session
                    .discover_terminal_source_cancellation_with(async |_, _, _, _| {
                        match case {
                            "changed-recipe" => {
                                let mut next = owned.snapshot().recovery.unwrap();
                                next["future_custody"] = serde_json::json!({"changed": true});
                                owned.set_recovery(next)?;
                                *changed.borrow_mut() = Some(std::fs::read(&writer.path)?);
                            }
                            "changed-gate" => {
                                std::fs::hard_link(
                                    writer.path.with_extension("recovery.lock"),
                                    directory.path().join("aliased-gate.lock"),
                                )?;
                            }
                            "changed-namespace" => {
                                return Ok(Some(SourceAuthorityNamespace::Legacy));
                            }
                            _ => unreachable!(),
                        }
                        Ok(Some(SourceAuthorityNamespace::Current))
                    })
                    .await
                    .is_err(),
                "{case}"
            );
            assert_eq!(
                std::fs::read(&writer.path).unwrap(),
                changed.into_inner().unwrap_or(before),
                "{case}"
            );
            assert_eq!(session.recipe.source_cancellation_settled, None);
            assert_eq!(
                load_recipe(&owned).unwrap().source_cancellation_settled,
                None
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_legacy_cancellation_discovery_requires_exact_failed_retirement() {
        let _guard = test_guard!();
        for case in [
            "source-unreleased",
            "tree-unretired",
            "pair-unreleased",
            "unretired",
            "no-returned-outcome",
            "contradictory-exit",
            "wrong-state",
            "unacknowledged",
            "invalid-source-intent",
            "other-pair-token",
            "missing-retirement-root",
            "other-retirement-root",
        ] {
            let (_directory, writer) = terminal_legacy_cancellation_fixture(None, true);
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut recipe = load_recipe(&owned).unwrap();
            match case {
                "source-unreleased" => recipe.sources_released = false,
                "tree-unretired" => recipe.tree_retired = false,
                "pair-unreleased" => recipe.pair_released = false,
                "unretired" => recipe.retired = false,
                "no-returned-outcome" => recipe.returned = None,
                "invalid-source-intent" => recipe.source_roots.push("/data/../other".into()),
                "other-pair-token" => recipe.pair.as_mut().unwrap().1 = "abcdef".into(),
                "missing-retirement-root" => recipe.retire_root = None,
                "other-retirement-root" => recipe.retire_root = Some("/data/another-source".into()),
                _ => {}
            }
            owned
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            {
                let mut lease = owned.lease.lock().unwrap();
                match case {
                    "contradictory-exit" => lease.exit_code = Some(130),
                    "wrong-state" => {
                        lease.state = rch_common::job_identity::JobLifecycleState::Running
                    }
                    "unacknowledged" => lease.terminal_acknowledged = false,
                    _ => {}
                }
            }
            owned.persist().unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned,
            };
            assert!(
                session
                    .discover_terminal_source_cancellation_with(async |_, _, _, _| {
                        panic!("{case}: contradictory terminal evidence must not contact worker")
                    })
                    .await
                    .is_err(),
                "{case}"
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{case}");
        }

        let (_directory, writer) = terminal_legacy_cancellation_fixture(None, false);
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer: writer.clone(),
        };
        let before = std::fs::read(&writer.path).unwrap();
        assert!(
            session
                .discover_terminal_source_cancellation_with(async |_, _, _, _| {
                    panic!("unowned journal must not contact worker")
                })
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_legacy_cancellation_discovery_keeps_success_and_known_obligations_local() {
        let _guard = test_guard!();
        for case in [
            "success",
            "known-preparation",
            "pending",
            "settled",
            "no-source",
        ] {
            let (_directory, writer) = terminal_legacy_cancellation_fixture(None, false);
            let mut recipe = load_recipe(&writer).unwrap();
            match case {
                "success" => {
                    recipe.returned = Some(0);
                    recipe.exit_code = Some(0);
                }
                "known-preparation" => recipe.preparation_cancelled = true,
                "pending" => recipe.source_cancellation_settled = Some(false),
                "settled" => recipe.source_cancellation_settled = Some(true),
                "no-source" => recipe.source_roots.clear(),
                _ => unreachable!(),
            }
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&writer).unwrap(),
                writer: writer.clone(),
            };
            assert!(
                !session
                    .discover_terminal_source_cancellation_with(async |_, _, _, _| {
                        panic!("{case}: no unknown cancellation needs discovery")
                    })
                    .await
                    .unwrap()
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{case}");
        }
    }

    #[test]
    fn terminal_acknowledgement_refuses_unsettled_source_cancellation() {
        for settled in [None, Some(false), Some(true)] {
            let (_directory, writer, worker) = preparation_fixture();
            let mut recipe = load_recipe(&writer).unwrap();
            recipe.preparation_cancelled = true;
            recipe.source_cancellation_settled = settled;
            recipe.sources_released = true;
            recipe.tree_retired = true;
            recipe.pair_released = true;
            recipe.returned = Some(EXIT_BUILD_ERROR);
            recipe.retired = true;
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            writer.record_exit(EXIT_BUILD_ERROR).unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            if settled != Some(true) {
                assert!(writer.ensure_released_for_retry().is_err());
                assert!(writer.begin_retry_selection(true).is_err());
                assert!(writer.admit(42, &worker.id).is_err());
                assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            }
            let result = writer.acknowledge_terminal();
            if settled != Some(true) {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("cancellation settlement")
                );
                assert!(!writer.snapshot().terminal_acknowledged);
                assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            } else {
                result.unwrap();
                assert!(writer.snapshot().terminal_acknowledged);
            }
        }
        for malformed in [serde_json::json!("true"), serde_json::json!(1)] {
            let (_directory, writer) = terminal_cancellation_fixture();
            let mut recipe = writer.snapshot().recovery.unwrap();
            recipe["source_cancellation_settled"] = malformed;
            writer.set_recovery(recipe).unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            assert!(writer.acknowledge_terminal().is_err());
            assert!(writer.ensure_released_for_retry().is_err());
            assert!(load_recipe(&writer).is_err());
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        }
    }

    #[test]
    fn settled_cancellation_refuses_contradictory_terminal_evidence() {
        for (key, value) in [
            ("returned", serde_json::json!(0)),
            ("returned", serde_json::Value::Null),
            ("returned", serde_json::json!(i64::from(i32::MAX) + 1)),
            ("sources_released", serde_json::json!(false)),
            ("tree_retired", serde_json::json!(false)),
            ("pair_released", serde_json::json!(false)),
            ("tree_retired", serde_json::Value::Null),
            ("pair_released", serde_json::json!("true")),
        ] {
            let (_directory, writer, worker) = preparation_fixture();
            let mut recipe = load_recipe(&writer).unwrap();
            recipe.preparation_cancelled = true;
            recipe.source_cancellation_settled = Some(true);
            recipe.sources_released = true;
            recipe.tree_retired = true;
            recipe.pair_released = true;
            recipe.returned = Some(EXIT_BUILD_ERROR);
            recipe.retired = true;
            let mut contradictory = serde_json::to_value(recipe).unwrap();
            contradictory[key] = value;
            assert!(
                !DurableLeaseWriter::cancellation_allows_retirement(&contradictory),
                "{key}"
            );
            writer.set_recovery(contradictory).unwrap();
            writer.record_exit(EXIT_BUILD_ERROR).unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            assert!(load_recipe(&writer).is_err(), "{key}");
            assert!(writer.acknowledge_terminal().is_err(), "{key}");
            assert!(writer.ensure_released_for_retry().is_err(), "{key}");
            assert!(writer.begin_retry_selection(true).is_err(), "{key}");
            assert!(writer.admit(42, &worker.id).is_err(), "{key}");
            assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{key}");
        }

        let (_directory, writer, _) = preparation_fixture();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.preparation_cancelled = true;
        recipe.source_cancellation_settled = Some(true);
        recipe.sources_released = true;
        recipe.tree_retired = true;
        recipe.pair_released = true;
        recipe.returned = Some(EXIT_BUILD_ERROR);
        // Settlement is published immediately before retired, so that exact
        // interrupted checkpoint must remain readable after a restart.
        assert!(!recipe.retired);
        writer
            .set_recovery(serde_json::to_value(&recipe).unwrap())
            .unwrap();
        assert!(load_recipe(&writer).is_ok());
        assert!(DurableLeaseWriter::cancellation_allows_retirement(
            &writer.snapshot().recovery.unwrap()
        ));

        // Ordinary legacy delivery has no cancellation-settlement obligation.
        recipe.source_cancellation_settled = None;
        recipe.preparation_cancelled = false;
        recipe.returned = Some(0);
        recipe.sources_released = false;
        recipe.tree_retired = false;
        recipe.pair_released = false;
        writer
            .set_recovery(serde_json::to_value(recipe).unwrap())
            .unwrap();
        assert!(load_recipe(&writer).is_ok());
        assert!(DurableLeaseWriter::cancellation_allows_retirement(
            &writer.snapshot().recovery.unwrap()
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_cancellation_retries_worker_settlement_after_restart_without_replaying() {
        let (_directory, writer) = terminal_cancellation_fixture();
        let owned = recovery_owner::claim(&writer).await.unwrap();
        let mut session = RecoverySession {
            recipe: load_recipe(&owned).unwrap(),
            writer: owned.clone(),
        };
        let before = std::fs::read(&writer.path).unwrap();
        let error = session
            .reconcile_source_cancellation_with(async |worker, roots, identity| {
                assert_eq!(worker.id.as_str(), "source-recovery");
                assert_eq!(roots, &["/data/projects/source-recovery"]);
                assert_eq!(identity, "0123456789abcdef0123456789abcdef");
                anyhow::bail!("worker activity is still held")
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("worker activity is still held"));
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        assert_eq!(session.recipe.source_cancellation_settled, None);
        drop(session);
        drop(owned);

        // A new writer reloads the retained journal. The remote verdict here
        // is a supplied unit input; shell tests separately exercise its locks.
        let reloaded = DurableLeaseWriter {
            path: writer.path.clone(),
            recovery_ownership: None,
            lease: Arc::new(Mutex::new(
                DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap(),
            )),
        };
        let owned = recovery_owner::claim(&reloaded).await.unwrap();
        let mut session = RecoverySession {
            recipe: load_recipe(&owned).unwrap(),
            writer: owned.clone(),
        };
        let calls = std::cell::Cell::new(0);
        session
            .reconcile_source_cancellation_with(async |_, _, _| {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(
            load_recipe(&owned).unwrap().source_cancellation_settled,
            Some(true)
        );
        let after = std::fs::read(&writer.path).unwrap();
        session
            .reconcile_source_cancellation_with(async |_, _, _| {
                panic!("already settled cancellation must not contact the worker")
            })
            .await
            .unwrap();
        assert_eq!(std::fs::read(&writer.path).unwrap(), after);
        assert_eq!(owned.snapshot().identity, writer.snapshot().identity);
        assert_eq!(owned.snapshot().exit_code, Some(EXIT_BUILD_ERROR));
        assert!(owned.snapshot().terminal_acknowledged);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_cancellation_requires_complete_retirement_before_worker_contact() {
        for missing in ["sources", "tree", "pair", "returned"] {
            let (_directory, writer) = terminal_cancellation_fixture();
            let mut recipe = load_recipe(&writer).unwrap();
            match missing {
                "sources" => recipe.sources_released = false,
                "tree" => recipe.tree_retired = false,
                "pair" => recipe.pair_released = false,
                "returned" => recipe.returned = None,
                _ => unreachable!(),
            }
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned,
            };
            let error = session
                .reconcile_source_cancellation_with(async |_, _, _| {
                    panic!("incomplete retirement must not contact the worker")
                })
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("complete resource retirement"),
                "{error}"
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{missing}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_cancellation_checkpoint_preserves_original_recipe_evidence() {
        let (_directory, writer) = terminal_cancellation_fixture();
        let mut original = writer.snapshot().recovery.unwrap();
        original["source_roots"] = serde_json::json!(["/data//projects/source-recovery/"]);
        original["future_custody"] = serde_json::json!({"original": true});
        writer.set_recovery(original.clone()).unwrap();
        let owned = recovery_owner::claim(&writer).await.unwrap();
        let mut session = RecoverySession {
            recipe: load_recipe(&owned).unwrap(),
            writer: owned.clone(),
        };
        session
            .reconcile_source_cancellation_with(async |_, roots, _| {
                assert_eq!(roots, &["/data/projects/source-recovery"]);
                Ok(())
            })
            .await
            .unwrap();
        original["source_cancellation_settled"] = serde_json::json!(true);
        assert_eq!(owned.snapshot().recovery.unwrap(), original);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_settlement_preserves_late_heartbeat_but_refuses_changed_recipe() {
        for change_recipe in [false, true] {
            let (_directory, writer) = terminal_cancellation_fixture();
            {
                let mut lease = writer.lease.lock().unwrap();
                lease.terminal_acknowledged = false;
                lease.state = rch_common::job_identity::JobLifecycleState::Running;
            }
            writer.persist().unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&writer).unwrap(),
                writer: writer.clone(),
            };
            let result = session
                .reconcile_source_cancellation_with(async |_, _, _| {
                    writer.heartbeat("release_unconfirmed")?;
                    if change_recipe {
                        let mut changed = writer.snapshot().recovery.unwrap();
                        changed["identity"] = serde_json::json!("1123456789abcdef0123456789abcdef");
                        writer.set_recovery(changed)?;
                    }
                    Ok(())
                })
                .await;
            let current = writer.snapshot();
            assert_eq!(current.phase, "release_unconfirmed");
            assert!(current.heartbeat_unix_ms > 1);
            assert!(!current.terminal_acknowledged);
            if change_recipe {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("job journal changed")
                );
                assert_eq!(session.recipe.source_cancellation_settled, None);
                assert_eq!(
                    current.recovery.unwrap()["identity"],
                    "1123456789abcdef0123456789abcdef"
                );
            } else {
                result.unwrap();
                assert_eq!(
                    load_recipe(&writer).unwrap().source_cancellation_settled,
                    Some(true)
                );
                writer.acknowledge_terminal().unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_terminal_cancellation_recovery_keeps_one_journal_owner() {
        let (_directory, writer) = terminal_cancellation_fixture();
        let stale = DurableLeaseWriter {
            path: writer.path.clone(),
            recovery_ownership: None,
            lease: Arc::new(Mutex::new(writer.snapshot())),
        };
        let owned = recovery_owner::claim(&writer).await.unwrap();
        let mut session = RecoverySession {
            recipe: load_recipe(&owned).unwrap(),
            writer: owned.clone(),
        };
        session
            .reconcile_source_cancellation_with(async |_, _, _| {
                assert!(recovery_owner::claim(&stale).await.is_err());
                Ok(())
            })
            .await
            .unwrap();
        drop(session);
        drop(owned);
        let next = recovery_owner::claim(&stale).await.unwrap();
        assert_eq!(
            load_recipe(&next).unwrap().source_cancellation_settled,
            Some(true)
        );
        let mut session = RecoverySession {
            recipe: load_recipe(&next).unwrap(),
            writer: next,
        };
        session
            .reconcile_source_cancellation_with(async |_, _, _| {
                panic!("the second dispatcher must observe the settled journal")
            })
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn worker_cancellation_receipt_does_not_advance_a_failed_journal_publication() {
        let (directory, writer) = terminal_cancellation_fixture();
        let owned = recovery_owner::claim(&writer).await.unwrap();
        let mut session = RecoverySession {
            recipe: load_recipe(&owned).unwrap(),
            writer: owned.clone(),
        };
        let before = std::fs::read(&writer.path).unwrap();
        let gate = writer.path.with_extension("recovery.lock");
        let alias = directory.path().join("changed-gate.lock");
        let error = session
            .reconcile_source_cancellation_with(async |_, _, _| {
                std::fs::hard_link(&gate, &alias)?;
                Ok(())
            })
            .await;
        assert!(error.is_err());
        assert_eq!(session.recipe.source_cancellation_settled, None);
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        assert_eq!(
            load_recipe(&owned).unwrap().source_cancellation_settled,
            None
        );
    }

    fn retained_preparation_fixture() -> (PathBuf, DurableLeaseWriter, WorkerConfig) {
        let (directory, writer, worker) = admitted_preparation_fixture();
        let directory = directory.keep();
        let identity = "0123456789abcdef0123456789abcdef";
        let root = "/data/tmp/rch/source-content-pair-recovery";
        let retained = format!("{root}.retained-{identity}");
        RecoverySession::begin(
            &writer,
            &worker,
            vec![root.into(), retained.clone()],
            Some((root.into(), identity.into())),
            Some(root.into()),
            Some(retained),
            TransferConfig::default(),
            directory.clone(),
            identity.into(),
        )
        .unwrap();
        (directory, writer, worker)
    }

    #[cfg(unix)]
    fn retired_pair_cancellation_fixture(
        cancellation_started: bool,
    ) -> (PathBuf, DurableLeaseWriter) {
        let (directory, writer, _) = retained_preparation_fixture();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        recipe.execution_started = true;
        recipe.tree_retired = true;
        recipe.retained_materialized = Some(true);
        recipe.source_cancellation_settled = cancellation_started.then_some(false);
        writer
            .set_recovery(serde_json::to_value(recipe).unwrap())
            .unwrap();
        let mut wrapper = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let wrapper_pid = wrapper.id();
        assert!(wrapper.wait().unwrap().success());
        {
            let mut lease = writer.lease.lock().unwrap();
            lease.wrapper_pid = wrapper_pid;
            lease.process_start_ticks = None;
            lease.boot_id = None;
            lease.process_birth = None;
        }
        writer.persist().unwrap();
        (directory, writer)
    }

    #[cfg(unix)]
    fn completed_cancellation_fixture() -> (PathBuf, DurableLeaseWriter) {
        let (directory, writer, _) = preparation_fixture();
        let directory = directory.keep();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        recipe.execution_started = true;
        recipe.source_authority_namespace = Some(SourceAuthorityNamespace::Legacy);
        writer
            .set_recovery(serde_json::to_value(recipe).unwrap())
            .unwrap();
        let mut wrapper = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let wrapper_pid = wrapper.id();
        assert!(wrapper.wait().unwrap().success());
        {
            let mut lease = writer.lease.lock().unwrap();
            lease.wrapper_pid = wrapper_pid;
            lease.process_start_ticks = None;
            lease.boot_id = None;
            lease.process_birth = None;
        }
        writer.persist().unwrap();
        (directory, writer)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn completed_source_cancellation_remains_pending_across_journal_restart() {
        let _guard = test_guard!();
        for (pending, paired) in [(false, false), (false, true), (true, false), (true, true)] {
            let (_directory, writer) = completed_cancellation_fixture();
            let mut recipe = load_recipe(&writer).unwrap();
            recipe.source_cancellation_settled = pending.then_some(false);
            if paired {
                let root = recipe.source_roots[0].clone();
                recipe.pair = Some((root.clone(), recipe.identity.clone()));
                recipe.retire_root = Some(root);
            }
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let original = session.recipe.clone();
            assert!(session.recipe.exit_code.is_none());
            assert!(
                session
                    .checkpoint_completed_source_cancellation_with(
                        0,
                        async |worker, roots, token| {
                            assert!(!pending, "an existing obligation needs no rediscovery");
                            assert_eq!(worker.id, original.worker.id);
                            assert_eq!(roots, original.source_roots);
                            assert_eq!(token, original.identity);
                            // A supplied exact marker, not a completed receipt.
                            // The native registry tests exercise that distinction.
                            Ok(true)
                        }
                    )
                    .await
                    .unwrap()
            );
            let checkpoint = load_recipe(&owned).unwrap();
            assert_eq!(checkpoint.exit_code, Some(0));
            assert_eq!(checkpoint.source_cancellation_settled, Some(false));
            assert_eq!(
                checkpoint.source_authority_namespace,
                original.source_authority_namespace
            );
            assert!(checkpoint.returned.is_none());
            assert!(!checkpoint.tree_retired && !checkpoint.pair_released);
            assert!(!checkpoint.sources_released && !checkpoint.retired);
            assert!(owned.snapshot().exit_code.is_none());
            assert!(owned.acknowledge_terminal().is_err());
            assert!(owned.ensure_released_for_retry().is_err());
            assert!(recovery_owner::claim(&writer).await.is_err());
            drop(session);
            drop(owned);

            // Crash before the first cancel RPC: the next owner must resume
            // cleanup, even if discovery would now be unavailable. It cannot
            // advertise return or retirement from this checkpoint alone.
            let reloaded = DurableLeaseWriter {
                path: writer.path.clone(),
                recovery_ownership: None,
                lease: Arc::new(Mutex::new(
                    DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap(),
                )),
            };
            let owned = recovery_owner::claim(&reloaded).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            assert!(
                session
                    .checkpoint_completed_source_cancellation_with(0, async |_, _, _| {
                        panic!("restart must resume the durably pending cancellation")
                    })
                    .await
                    .unwrap()
            );
            assert_eq!(session.recipe.source_cancellation_settled, Some(false));
            assert!(session.recipe.returned.is_none());
            assert!(!session.recipe.sources_released && !session.recipe.retired);
            assert!(!owned.snapshot().terminal_acknowledged);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn completed_source_cancellation_preserves_unconfirmed_and_changed_evidence() {
        let _guard = test_guard!();
        for case in [
            "absent",
            "unconfirmed",
            "changed-journal",
            "changed-owner",
            "conflicting-completion",
            "recorded-success",
            "unstarted",
            "paired-absent",
            "paired-unconfirmed",
        ] {
            let (directory, writer) = completed_cancellation_fixture();
            let mut recipe = load_recipe(&writer).unwrap();
            match case {
                "conflicting-completion" => recipe.exit_code = Some(137),
                "unstarted" => recipe.execution_started = false,
                "paired-absent" | "paired-unconfirmed" => {
                    let root = recipe.source_roots[0].clone();
                    recipe.pair = Some((root.clone(), recipe.identity.clone()));
                    recipe.retire_root = Some(root);
                }
                _ => {}
            }
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            if case == "recorded-success" {
                writer.record_exit(0).unwrap();
            }
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let before = std::fs::read(&writer.path).unwrap();
            let changed = std::cell::RefCell::new(None);
            let result = session
                .checkpoint_completed_source_cancellation_with(0, async |_, _, _| {
                    assert_ne!(case, "unstarted");
                    match case {
                        "absent" | "paired-absent" => return Ok(false),
                        "unconfirmed" | "paired-unconfirmed" => {
                            anyhow::bail!("unconfirmed worker cancellation")
                        }
                        "changed-journal" => {
                            let mut next = owned.snapshot().recovery.unwrap();
                            next["identity"] = serde_json::json!("abcdef1234");
                            owned.set_recovery(next)?;
                            *changed.borrow_mut() = Some(std::fs::read(&writer.path)?);
                        }
                        "changed-owner" => {
                            std::fs::hard_link(
                                writer.path.with_extension("recovery.lock"),
                                directory.join("changed-recovery-gate.lock"),
                            )?;
                        }
                        _ => {}
                    }
                    Ok(true)
                })
                .await;
            if matches!(case, "absent" | "paired-absent") {
                assert!(!result.unwrap(), "{case}");
            } else {
                assert!(result.is_err(), "{case}");
            }
            assert_eq!(
                std::fs::read(&writer.path).unwrap(),
                changed.borrow().as_ref().unwrap_or(&before).clone(),
                "{case}"
            );
            assert_eq!(session.recipe.source_cancellation_settled, None);
            assert!(session.recipe.returned.is_none());
            assert!(!session.recipe.sources_released && !session.recipe.retired);
            assert!(!owned.snapshot().terminal_acknowledged);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paired_cancellation_recovery_requires_the_exact_cleanup_binding() {
        let _guard = test_guard!();
        for pending in [false, true] {
            for case in [
                "other-token",
                "pair-outside-closure",
                "other-retirement-root",
                "missing-retirement-root",
                "invalid-pair-root",
                "corrupt-source-closure",
                "empty-source-closure",
                "unbound-namespace",
                "returned-outcome",
            ] {
                let (_directory, writer) = completed_cancellation_fixture();
                let mut recipe = load_recipe(&writer).unwrap();
                let root = recipe.source_roots[0].clone();
                recipe.pair = Some((root.clone(), recipe.identity.clone()));
                recipe.retire_root = Some(root);
                recipe.source_cancellation_settled = pending.then_some(false);
                match case {
                    "other-token" => recipe.pair.as_mut().unwrap().1 = "abcdef1234".into(),
                    "pair-outside-closure" => {
                        let other = "/data/projects/another-source".to_string();
                        recipe.pair.as_mut().unwrap().0 = other.clone();
                        recipe.retire_root = Some(other);
                    }
                    "other-retirement-root" => {
                        recipe.retire_root = Some("/data/projects/another-source".into());
                    }
                    "missing-retirement-root" => recipe.retire_root = None,
                    "invalid-pair-root" => {
                        recipe.pair.as_mut().unwrap().0 = "../source-recovery".into();
                    }
                    "corrupt-source-closure" => {
                        recipe.source_roots.push("/data/projects/../other".into());
                    }
                    "empty-source-closure" => recipe.source_roots.clear(),
                    "unbound-namespace" => recipe.source_authority_namespace = None,
                    "returned-outcome" => recipe.returned = Some(EXIT_BUILD_ERROR),
                    _ => unreachable!(),
                }
                writer
                    .set_recovery(serde_json::to_value(recipe).unwrap())
                    .unwrap();
                let owned = recovery_owner::claim(&writer).await.unwrap();
                let mut session = RecoverySession {
                    recipe: load_recipe(&owned).unwrap(),
                    writer: owned.clone(),
                };
                let before = std::fs::read(&writer.path).unwrap();
                assert!(
                    session
                        .checkpoint_completed_source_cancellation_with(137, async |_, _, _| {
                            panic!("{case}: inconsistent ownership cannot query another intent")
                        })
                        .await
                        .is_err(),
                    "{case}, pending={pending}"
                );
                assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{case}");
                if !matches!(case, "unbound-namespace" | "returned-outcome") {
                    // Pre-execution and execution-lost callers can enter
                    // directly. They must reject the same invalid binding
                    // before publishing intent or contacting the worker.
                    assert!(cancel_source_grant(session).await.is_err(), "{case}");
                    assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{case}");
                }
                assert!(!owned.snapshot().terminal_acknowledged, "{case}");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paired_cancellation_recovery_checks_canonical_binding_without_rewriting_evidence() {
        let _guard = test_guard!();
        for namespace in [
            SourceAuthorityNamespace::Current,
            SourceAuthorityNamespace::Legacy,
        ] {
            let (_directory, writer) = completed_cancellation_fixture();
            let mut recipe = load_recipe(&writer).unwrap();
            let root = recipe.source_roots[0].clone();
            recipe.source_roots[0] = format!("{root}/");
            recipe.pair = Some((format!("{root}/./"), recipe.identity.clone()));
            recipe.retire_root = Some(format!("{root}//"));
            recipe.source_authority_namespace = Some(namespace);
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let before = std::fs::read(&writer.path).unwrap();
            assert!(
                !session
                    .checkpoint_completed_source_cancellation_with(137, async |_, roots, _| {
                        assert_eq!(roots, std::slice::from_ref(&root));
                        Ok(false)
                    })
                    .await
                    .unwrap()
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            assert_eq!(session.recipe.source_authority_namespace, Some(namespace));
            assert_eq!(
                session.recipe.pair.as_ref().unwrap().0,
                format!("{root}/./")
            );
            assert_eq!(session.recipe.retire_root, Some(format!("{root}//")));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paired_cancellation_recovery_defers_unreleased_pair_to_guarded_cleanup() {
        let _guard = test_guard!();
        for pending in [false, true] {
            for tree_retired in [false, true] {
                let (_directory, writer) = retired_pair_cancellation_fixture(pending);
                let mut recipe = load_recipe(&writer).unwrap();
                recipe.tree_retired = tree_retired;
                recipe.retained_materialized = tree_retired.then_some(true);
                writer
                    .set_recovery(serde_json::to_value(recipe).unwrap())
                    .unwrap();
                let owned = recovery_owner::claim(&writer).await.unwrap();
                let mut session = RecoverySession {
                    recipe: load_recipe(&owned).unwrap(),
                    writer: owned.clone(),
                };
                let original = session.recipe.clone();
                let before = std::fs::read(&writer.path).unwrap();
                assert_eq!(
                    session
                        .resume_retired_source_pair_cancellation_with(
                            async |_, roots, token| {
                                assert!(tree_retired && !pending);
                                assert_eq!(roots, original.source_roots);
                                assert_eq!(token, original.identity);
                                Ok(true)
                            },
                            async |_, root, token| {
                                assert!(tree_retired);
                                assert_eq!(root, original.pair.as_ref().unwrap().0);
                                assert_eq!(token, original.identity);
                                Ok(false)
                            },
                            async |_, _, _| panic!("the pair has no release proof"),
                            async |_| panic!("cleanup has not retired the pair"),
                        )
                        .await
                        .unwrap(),
                    None
                );
                assert_eq!(std::fs::read(&writer.path).unwrap(), before);
                // A false release probe grants no source access. The exact
                // execution completion must instead durably route this
                // journal to cancel_source_grant's real cleanup guard.
                assert!(
                    session
                        .checkpoint_completed_source_cancellation_with(137, async |_, _, _| {
                            assert!(!pending);
                            Ok(true)
                        })
                        .await
                        .unwrap()
                );
                let checkpoint = load_recipe(&owned).unwrap();
                assert_eq!(checkpoint.exit_code, Some(137));
                assert_eq!(checkpoint.source_cancellation_settled, Some(false));
                assert_eq!(checkpoint.tree_retired, tree_retired);
                assert_eq!(
                    checkpoint.retained_materialized,
                    tree_retired.then_some(true)
                );
                assert_eq!(checkpoint.pair, original.pair);
                assert_eq!(checkpoint.retire_root, original.retire_root);
                assert!(!checkpoint.pair_released && !checkpoint.sources_released);
                assert!(checkpoint.returned.is_none() && !checkpoint.retired);
                assert!(owned.acknowledge_terminal().is_err());
                assert!(recovery_owner::claim(&writer).await.is_err());
                drop(session);
                drop(owned);

                let reloaded = DurableLeaseWriter {
                    path: writer.path.clone(),
                    recovery_ownership: None,
                    lease: Arc::new(Mutex::new(
                        DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id())
                            .unwrap(),
                    )),
                };
                let owned = recovery_owner::claim(&reloaded).await.unwrap();
                let mut session = RecoverySession {
                    recipe: load_recipe(&owned).unwrap(),
                    writer: owned.clone(),
                };
                assert!(
                    session
                        .checkpoint_completed_source_cancellation_with(137, async |_, _, _| {
                            panic!("restart must retain the cleanup obligation")
                        })
                        .await
                        .unwrap()
                );
                assert_eq!(session.recipe.tree_retired, tree_retired);
                assert_eq!(
                    session.recipe.retained_materialized,
                    tree_retired.then_some(true)
                );
                assert!(!session.recipe.pair_released && !session.recipe.sources_released);
                assert!(session.recipe.returned.is_none() && !session.recipe.retired);
                assert!(!owned.snapshot().terminal_acknowledged);
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paired_cancellation_recovery_settles_before_acknowledgement_and_survives_reload() {
        let _guard = test_guard!();
        for (started, recorded_pair_release, observed_exit) in [
            (false, false, None),
            (true, false, Some(137)),
            (true, true, None),
        ] {
            let (_directory, writer) = retired_pair_cancellation_fixture(started);
            let mut recipe = load_recipe(&writer).unwrap();
            recipe.pair_released = recorded_pair_release;
            recipe.source_authority_namespace = Some(SourceAuthorityNamespace::Legacy);
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            if let Some(exit) = observed_exit {
                writer.record_exit(exit).unwrap();
            }
            let expected_exit = observed_exit.unwrap_or(EXIT_BUILD_ERROR);
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let original = session.recipe.clone();
            let calls = std::cell::RefCell::new(Vec::new());
            let result = session
                .resume_retired_source_pair_cancellation_with(
                    async |worker, roots, identity| {
                        assert!(!started);
                        assert_eq!(worker.id, original.worker.id);
                        assert_eq!(roots, original.source_roots);
                        assert_eq!(identity, original.identity);
                        calls.borrow_mut().push("cancellation evidence");
                        Ok(true)
                    },
                    async |worker, root, token| {
                        assert!(!recorded_pair_release);
                        assert_eq!(worker.id, original.worker.id);
                        assert_eq!(
                            (root, token),
                            (
                                original.pair.as_ref().unwrap().0.as_str(),
                                original.identity.as_str()
                            )
                        );
                        calls.borrow_mut().push("pair receipt");
                        Ok(true)
                    },
                    async |worker, roots, identity| {
                        assert_eq!(worker.id, original.worker.id);
                        assert_eq!(roots, original.source_roots);
                        assert_eq!(identity, original.identity);
                        assert_eq!(
                            load_recipe(&owned)?.source_cancellation_settled,
                            Some(false)
                        );
                        assert!(owned.acknowledge_terminal().is_err());
                        assert!(recovery_owner::claim(&writer).await.is_err());
                        calls.borrow_mut().push("cancel and finish");
                        Ok(())
                    },
                    async |session| {
                        assert_eq!(session.recipe.returned, Some(expected_exit));
                        assert!(session.recipe.tree_retired && session.recipe.pair_released);
                        assert!(session.recipe.sources_released);
                        session
                            .reconcile_source_cancellation_with(async |_, _, _| {
                                calls.borrow_mut().push("settlement");
                                Ok(())
                            })
                            .await
                    },
                )
                .await
                .unwrap();
            assert_eq!(result, Some(expected_exit));
            let mut expected_calls = Vec::new();
            if !started {
                expected_calls.push("cancellation evidence");
            }
            if !recorded_pair_release {
                expected_calls.push("pair receipt");
            }
            expected_calls.extend(["cancel and finish", "settlement"]);
            assert_eq!(*calls.borrow(), expected_calls);
            assert!(!owned.snapshot().terminal_acknowledged);
            assert_eq!(
                session.recipe.source_authority_namespace,
                original.source_authority_namespace
            );
            assert_eq!(session.recipe.retained_root, original.retained_root);
            assert_eq!(session.recipe.retained_materialized, Some(true));
            assert_eq!(
                session.recipe.exit_code, None,
                "metadata retirement must not invent execution completion"
            );
            owned.record_exit(expected_exit).unwrap();
            let wrapper_id = owned.wrapper_id();
            recovery_completion::finish(&owned, async |_request: &str| {
                Ok(format!(
                    "HTTP/1.1 200 OK\r\n\r\n{}",
                    serde_json::json!({
                        "status": "completed",
                        "local_wrapper_id": wrapper_id,
                        "record": {"id": 41, "worker_id": "source-recovery", "exit_code": 130}
                    })
                ))
            })
            .await
            .unwrap();
            assert!(owned.snapshot().terminal_acknowledged);
            assert_eq!(load_recipe(&owned).unwrap().daemon_exit_code, Some(130));
            let acknowledged = std::fs::read(&writer.path).unwrap();
            drop(session);
            drop(owned);

            let reloaded = DurableLeaseWriter {
                path: writer.path.clone(),
                recovery_ownership: None,
                lease: Arc::new(Mutex::new(
                    DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap(),
                )),
            };
            let owned = recovery_owner::claim(&reloaded).await.unwrap();
            assert_eq!(
                recover_owned_job_with_daemon(&owned, async |_request: &str| {
                    panic!("settled cancellation must not reopen daemon accounting")
                })
                .await
                .unwrap(),
                expected_exit
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), acknowledged);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paired_cancellation_recovery_preserves_missing_and_conflicting_evidence() {
        let _guard = test_guard!();
        for case in [
            "legacy-no-cancellation",
            "legacy-unconfirmed-cancellation",
            "legacy-no-pair-receipt",
            "pending-live-pair",
            "pair-transport-error",
            "unretired-tree",
            "unbound-namespace",
            "other-pair-token",
            "recorded-success",
            "no-journal-owner",
        ] {
            let started = !case.starts_with("legacy-");
            let (_directory, writer) = retired_pair_cancellation_fixture(started);
            let mut recipe = load_recipe(&writer).unwrap();
            match case {
                "unretired-tree" => {
                    recipe.tree_retired = false;
                    recipe.retained_materialized = None;
                }
                "unbound-namespace" => recipe.source_authority_namespace = None,
                "other-pair-token" => {
                    recipe.retained_root = None;
                    recipe.retained_materialized = None;
                    recipe.pair.as_mut().unwrap().1 = "1123456789abcdef0123456789abcdef".into();
                }
                _ => {}
            }
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            if case == "recorded-success" {
                writer.record_exit(0).unwrap();
            }
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: if case == "no-journal-owner" {
                    writer.clone()
                } else {
                    owned.clone()
                },
            };
            let before = std::fs::read(&writer.path).unwrap();
            let result = session
                .resume_retired_source_pair_cancellation_with(
                    async |_, _, _| {
                        if case == "legacy-unconfirmed-cancellation" {
                            anyhow::bail!("worker cancellation evidence is unconfirmed")
                        }
                        Ok(case != "legacy-no-cancellation")
                    },
                    async |_, _, _| {
                        assert_ne!(case, "legacy-no-cancellation");
                        assert_ne!(case, "legacy-unconfirmed-cancellation");
                        if case == "pair-transport-error" {
                            anyhow::bail!("unconfirmed pair receipt")
                        }
                        Ok(false)
                    },
                    async |_, _, _| panic!("{case}: no worker mutation is authorized"),
                    async |_| panic!("{case}: no settlement is authorized"),
                )
                .await;
            if matches!(
                case,
                "legacy-no-cancellation"
                    | "legacy-no-pair-receipt"
                    | "pending-live-pair"
                    | "unretired-tree"
            ) {
                assert_eq!(result.unwrap(), None, "{case}");
            } else {
                assert!(result.is_err(), "{case}");
            }
            assert!(!owned.snapshot().terminal_acknowledged, "{case}");
            assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{case}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paired_cancellation_recovery_reloads_legacy_fence_after_lost_reply() {
        let _guard = test_guard!();
        for lost_reply in ["cancellation", "settlement"] {
            let (_directory, writer) = retired_pair_cancellation_fixture(false);
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            assert!(
                owned
                    .snapshot()
                    .recovery
                    .as_ref()
                    .unwrap()
                    .get("source_cancellation_settled")
                    .is_none(),
                "the old journal has no cancellation-obligation checkpoint"
            );
            // The supplied worker observation is a matching marker without
            // a completed receipt. Native registry/SSH tests exercise those
            // bytes and locks; this test checks durable journal restart after
            // discovery, and must not treat the marker as release authority.
            let worker_finished = std::cell::Cell::new(false);
            let result = session
                .resume_retired_source_pair_cancellation_with(
                    async |_, _, _| {
                        assert!(!worker_finished.get());
                        Ok(true)
                    },
                    async |_, _, _| {
                        assert!(!worker_finished.get());
                        Ok(true)
                    },
                    async |_, _, _| {
                        assert_eq!(
                            load_recipe(&owned)?.source_cancellation_settled,
                            Some(false)
                        );
                        worker_finished.set(true);
                        if lost_reply == "cancellation" {
                            anyhow::bail!("worker cancelled but its reply was lost")
                        }
                        Ok(())
                    },
                    async |session| {
                        assert!(worker_finished.get());
                        session
                            .reconcile_source_cancellation_with(async |_, _, _| {
                                anyhow::bail!("worker settled but its reply was lost")
                            })
                            .await
                    },
                )
                .await;
            assert!(result.is_err());
            let checkpoint = load_recipe(&owned).unwrap();
            assert_eq!(checkpoint.source_cancellation_settled, Some(false));
            assert!(worker_finished.get());
            assert_eq!(checkpoint.returned.is_some(), lost_reply == "settlement");
            assert!(!checkpoint.retired && !owned.snapshot().terminal_acknowledged);
            drop(session);
            drop(owned);

            let reloaded = DurableLeaseWriter {
                path: writer.path.clone(),
                recovery_ownership: None,
                lease: Arc::new(Mutex::new(
                    DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap(),
                )),
            };
            let owned = recovery_owner::claim(&reloaded).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            if lost_reply == "cancellation" {
                assert_eq!(
                    session
                        .resume_retired_source_pair_cancellation_with(
                            async |_, _, _| panic!(
                                "the durable cancellation obligation survives restart"
                            ),
                            async |_, _, _| Ok(true),
                            async |_, _, _| Ok(()),
                            async |session| session
                                .reconcile_source_cancellation_with(async |_, _, _| Ok(()))
                                .await,
                        )
                        .await
                        .unwrap(),
                    Some(EXIT_BUILD_ERROR)
                );
            } else {
                // Production's returned-result branch reaches the same final
                // reconciliation; all tree/pair/source retirement is durable,
                // so no worker content or pair acquisition remains to repeat.
                assert!(
                    session.recipe.tree_retired
                        && session.recipe.pair_released
                        && session.recipe.sources_released
                );
                session
                    .reconcile_source_cancellation_with(async |_, _, _| Ok(()))
                    .await
                    .unwrap();
                session.retired().unwrap();
            }
            let settled = load_recipe(&owned).unwrap();
            assert_eq!(settled.returned, Some(EXIT_BUILD_ERROR));
            assert_eq!(settled.source_cancellation_settled, Some(true));
            assert!(settled.retired);
            assert!(
                !owned.snapshot().terminal_acknowledged,
                "daemon acknowledgement is still a separate gate"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn paired_cancellation_recovery_refuses_changed_journal_and_failed_publication() {
        let _guard = test_guard!();
        for failure in ["identity", "journal-gate"] {
            let (directory, writer) = retired_pair_cancellation_fixture(true);
            let owned = recovery_owner::claim(&writer).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let before = std::fs::read(&writer.path).unwrap();
            let changed = std::cell::RefCell::new(None);
            let result = session
                .resume_retired_source_pair_cancellation_with(
                    async |_, _, _| panic!("current cancellation is already durable"),
                    async |_, _, _| Ok(true),
                    async |_, _, _| {
                        if failure == "identity" {
                            let mut next = owned.snapshot().recovery.unwrap();
                            next["identity"] =
                                serde_json::json!("1123456789abcdef0123456789abcdef");
                            owned.set_recovery(next)?;
                            *changed.borrow_mut() = Some(std::fs::read(&writer.path)?);
                        } else {
                            std::fs::hard_link(
                                writer.path.with_extension("recovery.lock"),
                                directory.join("changed-recovery-gate.lock"),
                            )?;
                        }
                        Ok(())
                    },
                    async |_| panic!("changed evidence cannot advance to settlement"),
                )
                .await;
            assert!(result.is_err(), "{failure}");
            assert!(!session.recipe.sources_released && !session.recipe.pair_released);
            assert!(session.recipe.returned.is_none());
            assert!(!owned.snapshot().terminal_acknowledged);
            assert_eq!(
                std::fs::read(&writer.path).unwrap(),
                changed.borrow().as_ref().unwrap_or(&before).clone(),
                "{failure}: recovery overwrote unverified evidence"
            );
        }
    }

    #[cfg(unix)]
    fn go_fixture_command(go: &str, args: &[&str], environment: &[&str]) -> String {
        shell_words::join(
            [
                "env",
                "GOENV=off",
                "GOTOOLCHAIN=local",
                "GOWORK=off",
                "GOFLAGS=",
                "GOOS=",
                "GOARCH=",
                "CGO_ENABLED=0",
                "GOMAXPROCS=1",
            ]
            .into_iter()
            .chain(environment.iter().copied())
            .chain(std::iter::once(go))
            .chain(args.iter().copied()),
        )
    }

    #[cfg(unix)]
    async fn run_go_fixture(command: &mut tokio::process::Command) -> std::process::Output {
        command.stdin(Stdio::null()).kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(120), command.output())
            .await
            .expect("Go output fixture exceeded its bound")
            .expect("Go and rsync are required for the Go delivery regression")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn go_build_explicit_output_survives_recovery_and_missing_delivery() {
        use super::super::artifact_patterns::direct_compiler::{
            go_build_execution_command, validate_go_build_output,
        };
        use tokio::process::Command;

        let _guard = test_guard!();
        for (relative, inline_output) in [
            ("app", false),
            ("products/app [dev]*?", false),
            ("target/app", true),
        ] {
            let identity = uuid::Uuid::new_v4().to_string();
            let (_owner, writer, worker) = preparation_fixture_with_identity(&identity);
            let base = writer.path.parent().unwrap();
            let local = base.join("checkout");
            let remote = base.join("worker");
            let missing = base.join("missing-worker");
            let unrelated_target = base.join("unrelated-cargo-target");
            for root in [&local, &remote, &missing, &unrelated_target] {
                std::fs::create_dir_all(root.join("products")).unwrap();
                std::fs::create_dir_all(root.join("target")).unwrap();
            }
            for root in [&local, &remote] {
                std::fs::write(
                    root.join("go.mod"),
                    b"module fixture.invalid/output\n\ngo 1.20\n",
                )
                .unwrap();
            }
            let (source, expected_stdout): (&[u8], &[u8]) = if relative == "app" {
                // The previous output can also be a build input. Moving it
                // away before compilation would break this real embed case.
                (
                    b"package main\nimport (\"fmt\"; _ \"embed\")\nvar label = \"unset\"\n//go:embed app\nvar previous string\nfunc main() { fmt.Println(label + \":\" + previous) }\n",
                    b"go-delivered-37:old remote output\n",
                )
            } else {
                (
                    b"package main\nimport \"fmt\"\nvar label = \"unset\"\nfunc main() { fmt.Println(label) }\n",
                    b"go-delivered-37\n",
                )
            };
            std::fs::write(remote.join("main.go"), source).unwrap();
            std::fs::write(local.join("main.go"), b"local source sentinel").unwrap();
            std::fs::write(local.join(relative), b"old local output").unwrap();
            std::fs::write(remote.join(relative), b"old remote output").unwrap();
            std::fs::write(local.join("foreign.o"), b"other job's object").unwrap();
            std::fs::write(unrelated_target.join("sentinel"), b"unrelated Cargo target").unwrap();
            let output_option = format!("-o={relative}");
            let mut argv = vec![
                "build",
                "-p=1",
                "-ldflags",
                "-s -w -X main.label=go-delivered-37",
            ];
            if inline_output {
                argv.push(&output_option);
            } else {
                argv.extend(["-o", relative]);
            }
            argv.push("main.go");
            let command = go_fixture_command("go", &argv, &[]);
            assert_eq!(
                rch_common::classify_command(&command).kind,
                Some(CompilationKind::GoBuild)
            );
            let environment = validate_go_build_output(&command, &local).await.unwrap();
            assert_eq!(
                std::fs::read(local.join(relative)).unwrap(),
                b"old local output"
            );
            let pipeline = TransferPipeline::new(
                local.clone(),
                "go-fixture".into(),
                identity.clone(),
                TransferConfig::default(),
            )
            .with_remote_path_override(remote.to_str().unwrap().to_owned());
            let mut session = RecoverySession::prepare(
                &writer,
                &worker,
                &pipeline,
                vec!["/data/projects/source-recovery".into()],
                None,
                None,
                None,
                TransferConfig::default(),
                local.clone(),
                Some(&unrelated_target),
                Some(CompilationKind::GoBuild),
                &command,
                &[],
                identity,
            )
            .unwrap();
            assert!(session.has_native_output_contract());
            assert_eq!(session.recipe.phases.len(), 1);
            assert_eq!(session.recipe.phases[0].name, "project");
            assert!(session.returned(0).is_err());
            session.starting_execution().unwrap();
            let guarded = go_build_execution_command(&command, &environment).unwrap();
            let mut compiler = Command::new("sh");
            compiler.args(["-c", &guarded]).current_dir(&remote);
            let output = run_go_fixture(&mut compiler).await;
            assert!(output.status.success(), "{output:?}");
            session.completed(0).unwrap();
            let mut session = reload_publication(&session);
            assert_eq!(
                session.recipe.phases[0]
                    .native_outputs
                    .as_ref()
                    .unwrap()
                    .required_files,
                std::collections::BTreeSet::from([PathBuf::from(relative)])
            );
            for root in [&remote, &missing] {
                std::fs::write(root.join("foreign.o"), b"unrelated remote object").unwrap();
                std::fs::write(root.join("source.go"), b"unselected remote source").unwrap();
                std::fs::write(root.join("products/app d-decoy"), b"wildcard decoy").unwrap();
            }
            for complete in [false, true] {
                let stage = session.stage(0);
                let staged = session.staging_pipeline("project", &pipeline).unwrap();
                let patterns = session.cargo_artifact_patterns("project").unwrap();
                let mut rsync = staged.local_artifact_retrieval_for_test(
                    &worker,
                    if complete { &remote } else { &missing },
                    &patterns,
                );
                let output = run_go_fixture(&mut rsync).await;
                assert!(output.status.success(), "{output:?}");
                assert!(!stage.join("foreign.o").exists());
                assert!(!stage.join("source.go").exists());
                assert!(!stage.join("products/app d-decoy").exists());
                let journal_before = std::fs::read(&writer.path).unwrap();
                if !complete {
                    assert!(session.publish("project").await.is_err());
                    assert!(session.returned(0).is_err());
                    assert!(session.retain_failed_delivery_evidence());
                    assert_eq!(std::fs::read(&writer.path).unwrap(), journal_before);
                    assert_eq!(
                        std::fs::read(local.join(relative)).unwrap(),
                        b"old local output"
                    );
                    session = reload_publication(&session);
                    assert!(session.recipe.phases[0].published.is_empty());
                    assert!(session.recipe.phases[0].pending.is_none());
                } else {
                    session.publish("project").await.unwrap();
                    session.returned(0).unwrap();
                    session = reload_publication(&session);
                    assert!(session.recipe.phases[0].complete);
                    session.publish("project").await.unwrap();
                    assert_eq!(
                        std::fs::read(local.join(relative)).unwrap(),
                        std::fs::read(remote.join(relative)).unwrap()
                    );
                    let mut executable = Command::new(local.join(relative));
                    let output = run_go_fixture(&mut executable).await;
                    assert!(output.status.success(), "{output:?}");
                    assert_eq!(output.stdout, expected_stdout);
                }
            }
            assert_eq!(
                std::fs::read(local.join("main.go")).unwrap(),
                b"local source sentinel"
            );
            assert_eq!(
                std::fs::read(local.join("foreign.o")).unwrap(),
                b"other job's object"
            );
            assert_eq!(
                std::fs::read(unrelated_target.join("sentinel")).unwrap(),
                b"unrelated Cargo target"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn go_output_guards_preserve_old_files_on_invalid_or_empty_builds() {
        use super::super::artifact_patterns::direct_compiler::{
            go_build_execution_command, validate_go_build_output,
        };
        use std::os::unix::fs::{PermissionsExt, symlink};
        use tokio::process::Command;

        let _guard = test_guard!();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::write(
            root.join("go.mod"),
            b"module fixture.invalid/guard\n\ngo 1.20\n",
        )
        .unwrap();
        std::fs::write(root.join("main.go"), b"package main\nfunc main() {}\n").unwrap();
        std::fs::write(
            root.join("broken.go"),
            b"package main\nthis is invalid Go\n",
        )
        .unwrap();
        std::fs::write(root.join("app"), b"old output must survive").unwrap();
        std::fs::create_dir(root.join("directory-output")).unwrap();
        std::fs::create_dir(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/app"), b"outside sentinel").unwrap();
        symlink(root.join("outside/app"), root.join("linked-output")).unwrap();
        symlink(root.join("outside"), root.join("linked-parent")).unwrap();
        std::fs::write(root.join("file-parent"), b"parent sentinel").unwrap();
        let foreign_os = if std::env::consts::OS == "linux" {
            "GOOS=darwin"
        } else {
            "GOOS=linux"
        };
        let foreign_arch = if std::env::consts::ARCH == "x86_64" {
            "GOARCH=arm64"
        } else {
            "GOARCH=amd64"
        };
        let baseline_command =
            go_fixture_command("go", &["build", "-p=1", "-o", "app", "main.go"], &[]);
        let baseline = validate_go_build_output(&baseline_command, root)
            .await
            .unwrap();
        for (output_path, environment, reason) in [
            ("app", vec!["GOFLAGS=-n"], "empty GOFLAGS"),
            ("app", vec![foreign_os], "native GOOS/GOARCH"),
            ("app", vec![foreign_arch], "native GOOS/GOARCH"),
            ("directory-output", vec![], "regular file"),
            ("linked-output", vec![], "regular file"),
            ("linked-parent/app", vec![], "real directories"),
            ("file-parent/app", vec![], "real directories"),
        ] {
            let command = go_fixture_command(
                "go",
                &["build", "-p=1", "-o", output_path, "main.go"],
                &environment,
            );
            let error = validate_go_build_output(&command, root).await.unwrap_err();
            assert!(format!("{error:#}").contains(reason), "{error:#}");
            let guarded = go_build_execution_command(&command, &baseline).unwrap();
            let mut process = Command::new("sh");
            process.args(["-c", &guarded]).current_dir(root);
            let output = run_go_fixture(&mut process).await;
            assert_eq!(output.status.code(), Some(113), "{output:?}");
            let remote_reason = if environment.is_empty() {
                reason
            } else {
                "settings differ"
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(remote_reason),
                "{output:?}"
            );
            assert_eq!(
                std::fs::read(root.join("app")).unwrap(),
                b"old output must survive"
            );
            assert_eq!(
                std::fs::read(root.join("outside/app")).unwrap(),
                b"outside sentinel"
            );
        }
        // An ambient build setting that is absent on the worker is a mismatch,
        // even when both endpoints still report the same GOOS/GOARCH.
        for changed in ["CGO_ENABLED=1", "GOEXPERIMENT=none", "GOAMD64=v2"] {
            let command =
                go_fixture_command("go", &["build", "-p=1", "-o", "app", "main.go"], &[changed]);
            validate_go_build_output(&command, root).await.unwrap();
            let guarded = go_build_execution_command(&command, &baseline).unwrap();
            let mut process = Command::new("sh");
            process.args(["-c", &guarded]).current_dir(root);
            let output = run_go_fixture(&mut process).await;
            assert_eq!(output.status.code(), Some(113), "{changed}: {output:?}");
            assert!(String::from_utf8_lossy(&output.stderr).contains("settings differ"));
            assert_eq!(
                std::fs::read(root.join("app")).unwrap(),
                b"old output must survive"
            );
        }
        // Matching CGO_ENABLED=1 remains supported; the guard does not force
        // otherwise ordinary Go builds into a pure-Go-only policy.
        let cgo_command = go_fixture_command(
            "go",
            &["build", "-p=1", "-o", "cgo-enabled-app", "main.go"],
            &["CGO_ENABLED=1"],
        );
        let cgo_environment = validate_go_build_output(&cgo_command, root).await.unwrap();
        let guarded = go_build_execution_command(&cgo_command, &cgo_environment).unwrap();
        let mut process = Command::new("sh");
        process.args(["-c", &guarded]).current_dir(root);
        let output = run_go_fixture(&mut process).await;
        assert!(output.status.success(), "{output:?}");
        assert!(root.join("cgo-enabled-app").is_file());

        // Both are real Go failures, including the explicit -o/no-packages
        // case. Neither may replace a previous successful build's output.
        for package in ["broken.go", "./missing/..."] {
            let command = go_fixture_command("go", &["build", "-p=1", "-o", "app", package], &[]);
            let environment = validate_go_build_output(&command, root).await.unwrap();
            let guarded = go_build_execution_command(&command, &environment).unwrap();
            let mut process = Command::new("sh");
            process.args(["-c", &guarded]).current_dir(root);
            let output = run_go_fixture(&mut process).await;
            assert_eq!(output.status.code(), Some(1), "{output:?}");
            assert_eq!(
                std::fs::read(root.join("app")).unwrap(),
                b"old output must survive"
            );
        }

        // Package loading must see exactly the caller's embed inputs. An
        // adjacent empty staging directory or a newly created output parent
        // changes `go:embed *` and makes an otherwise valid package fail.
        for (fixture, output_path) in [
            ("wildcard-root-output", "app"),
            ("wildcard-new-parent", "new-products/app"),
        ] {
            let project = root.join(fixture);
            std::fs::create_dir(&project).unwrap();
            std::fs::write(
                project.join("go.mod"),
                b"module fixture.invalid/embed\n\ngo 1.20\n",
            )
            .unwrap();
            std::fs::write(project.join("app"), b"embedded prior output").unwrap();
            std::fs::write(
                project.join("main.go"),
                b"package main\nimport (\"embed\"; \"fmt\")\n//go:embed *\nvar inputs embed.FS\nfunc main() { previous, err := inputs.ReadFile(\"app\"); if err != nil { panic(err) }; fmt.Println(string(previous)) }\n",
            )
            .unwrap();
            assert!(!project.join("new-products").exists());
            let command = go_fixture_command("go", &["build", "-p=1", "-o", output_path, "."], &[]);
            let environment = validate_go_build_output(&command, &project).await.unwrap();
            let guarded = go_build_execution_command(&command, &environment).unwrap();
            let mut compiler = Command::new("sh");
            compiler.args(["-c", &guarded]).current_dir(&project);
            let output = run_go_fixture(&mut compiler).await;
            assert!(output.status.success(), "{fixture}: {output:?}");
            let mut executable = Command::new(project.join(output_path));
            let output = run_go_fixture(&mut executable).await;
            assert!(output.status.success(), "{fixture}: {output:?}");
            assert_eq!(output.stdout, b"embedded prior output\n");
            if output_path != "app" {
                assert_eq!(
                    std::fs::read(project.join("app")).unwrap(),
                    b"embedded prior output"
                );
            }
        }

        // Failure injection: a Go shim reports success but creates no file.
        // Its env probe forwards to the actual compiler; an
        // old destination must still not satisfy the fresh-output contract.
        let mut real_env = Command::new("sh");
        real_env
            .args(["-c", &go_fixture_command("go", &["env", "GOROOT"], &[])])
            .current_dir(root);
        let goroot = run_go_fixture(&mut real_env).await;
        assert!(goroot.status.success(), "{goroot:?}");
        let go = PathBuf::from(String::from_utf8(goroot.stdout).unwrap().trim()).join("bin/go");
        let go = shell_escape::escape(go.to_string_lossy());
        let shim = root.join("shim/go");
        std::fs::create_dir(shim.parent().unwrap()).unwrap();
        std::fs::write(
            &shim,
            format!("#!/bin/sh\nif [ \"$1\" = env ]; then exec {go} \"$@\"; fi\nexit 0\n"),
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let command = go_fixture_command(
            shim.to_str().unwrap(),
            &["build", "-o", "app", "main.go"],
            &[],
        );
        let environment = validate_go_build_output(&command, root).await.unwrap();
        let guarded = go_build_execution_command(&command, &environment).unwrap();
        let mut process = Command::new("sh");
        process.args(["-c", &guarded]).current_dir(root);
        let output = run_go_fixture(&mut process).await;
        assert_eq!(output.status.code(), Some(113), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("without its required output file")
        );
        assert_eq!(
            std::fs::read(root.join("app")).unwrap(),
            b"old output must survive"
        );
        assert!(!std::fs::read_dir(root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".rch-go-output.")
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_native_outputs_are_complete_before_publication_and_survive_recovery() {
        use tokio::process::Command;
        async fn run(command: &mut Command) -> std::process::Output {
            command.stdin(Stdio::null()).kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(20), command.output())
                .await
                .expect("native output fixture exceeded its bound")
                .expect("GCC and rsync are required for the native delivery regression");
            assert!(output.status.success(), "{output:?}");
            output
        }

        let _guard = test_guard!();
        for (argv, expected, missing_index) in [
            (vec!["main.c", "lib/helper.c"], vec!["a.out"], 0),
            (
                vec!["-c", "main.c", "lib/helper.c"],
                vec!["helper.o", "main.o"],
                1,
            ),
            (
                vec!["-S", "main.c", "lib/helper.c"],
                vec!["helper.s", "main.s"],
                1,
            ),
            (
                vec![
                    "main.c",
                    "lib/helper.c",
                    "-o",
                    "products/app[dev]*?",
                    "-MMD",
                    "-MF",
                    "products/app.d",
                ],
                vec!["products/app.d", "products/app[dev]*?"],
                1,
            ),
            (
                vec![
                    "main.c",
                    "lib/helper.c",
                    "-o",
                    "target/app[dev]*?",
                    "-MMD",
                    "-MF",
                    "target/app.d",
                ],
                vec!["target/app.d", "target/app[dev]*?"],
                0,
            ),
        ] {
            let identity = uuid::Uuid::new_v4().to_string();
            let (_owner, writer, worker) = preparation_fixture_with_identity(&identity);
            let base = writer.path.parent().unwrap();
            let local = base.join("checkout");
            let remote = base.join("worker");
            let partial = base.join("partial-worker");
            let unrelated_target = base.join("unrelated-cargo-target");
            for path in [&local, &remote, &partial, &unrelated_target] {
                std::fs::create_dir_all(path.join("products")).unwrap();
                std::fs::create_dir_all(path.join("target")).unwrap();
            }
            std::fs::create_dir(remote.join("lib")).unwrap();
            std::fs::write(remote.join("main.c"),
                b"#include <stdio.h>\nint helper(void); int main(void) { printf(\"native-%d\\n\", helper()); return 0; }\n").unwrap();
            std::fs::write(
                remote.join("lib/helper.c"),
                b"int helper(void) { return 37; }\n",
            )
            .unwrap();
            std::fs::write(local.join("main.c"), b"local source sentinel").unwrap();
            std::fs::write(local.join("foreign.o"), b"other job's object").unwrap();
            std::fs::write(unrelated_target.join("sentinel"), b"unrelated Cargo target").unwrap();
            for relative in &expected {
                std::fs::write(local.join(relative), b"old local output").unwrap();
            }
            let command = shell_words::join(std::iter::once("gcc").chain(argv.iter().copied()));
            let pipeline = TransferPipeline::new(
                local.clone(),
                "native-fixture".into(),
                identity.clone(),
                TransferConfig::default(),
            )
            .with_remote_path_override(remote.to_str().unwrap().to_owned());
            let mut session = RecoverySession::prepare(
                &writer,
                &worker,
                &pipeline,
                vec!["/data/projects/source-recovery".into()],
                None,
                None,
                None,
                TransferConfig::default(),
                local.clone(),
                Some(&unrelated_target),
                Some(CompilationKind::Gcc),
                &command,
                &[],
                identity,
            )
            .unwrap();
            assert!(session.has_native_output_contract());
            assert_eq!(
                session.recipe.phases.len(),
                1,
                "ambient Cargo target must not displace native outputs"
            );
            assert_eq!(session.recipe.phases[0].name, "project");
            assert!(
                !session.recipe.phases[0].output_gate,
                "native completeness is independent of Cargo gating"
            );
            assert!(
                session.returned(0).is_err(),
                "pre-execution contract already forbids empty success"
            );
            session.starting_execution().unwrap();
            let mut compiler = Command::new("gcc");
            compiler
                .args(&argv)
                .current_dir(&remote)
                .env_remove("DEPENDENCIES_OUTPUT")
                .env_remove("SUNPRO_DEPENDENCIES");
            run(&mut compiler).await;
            session.completed(0).unwrap();
            let mut session = reload_publication(&session);
            assert_eq!(
                session.recipe.phases[0]
                    .native_outputs
                    .as_ref()
                    .unwrap()
                    .required_files,
                expected
                    .iter()
                    .map(PathBuf::from)
                    .collect::<std::collections::BTreeSet<_>>()
            );

            // A successful local rsync from this incomplete worker view must
            // not turn one object/depfile into proof of the entire contract.
            let missing = &expected[missing_index];
            for relative in expected.iter().filter(|relative| *relative != missing) {
                std::fs::copy(remote.join(relative), partial.join(relative)).unwrap();
            }
            for root in [&remote, &partial] {
                std::fs::write(root.join("foreign.o"), b"unrelated remote object").unwrap();
                std::fs::write(root.join("source.c"), b"unselected remote source").unwrap();
            }
            for complete in [false, true] {
                let stage = session.stage(0);
                let staged = session.staging_pipeline("project", &pipeline).unwrap();
                let patterns = session.cargo_artifact_patterns("project").unwrap();
                let mut rsync = staged.local_artifact_retrieval_for_test(
                    &worker,
                    if complete { &remote } else { &partial },
                    &patterns,
                );
                run(&mut rsync).await;
                assert!(!stage.join("foreign.o").exists());
                assert!(!stage.join("source.c").exists());
                let journal_before = std::fs::read(&writer.path).unwrap();
                if !complete {
                    assert!(session.publish("project").await.is_err());
                    assert_eq!(
                        std::fs::read(&writer.path).unwrap(),
                        journal_before,
                        "no durable publication frontier crossed"
                    );
                    assert!(session.returned(0).is_err());
                    assert!(session.retain_failed_delivery_evidence());
                    for relative in &expected {
                        assert_eq!(
                            std::fs::read(local.join(relative)).unwrap(),
                            b"old local output"
                        );
                    }
                    session = reload_publication(&session);
                    assert!(session.recipe.phases[0].published.is_empty());
                    assert!(session.recipe.phases[0].pending.is_none());
                } else {
                    session.publish("project").await.unwrap();
                    session.returned(0).unwrap();
                    session = reload_publication(&session);
                    assert!(session.recipe.phases[0].complete);
                    assert_eq!(session.recipe.phases[0].published.len(), expected.len());
                    session.publish("project").await.unwrap();
                    for relative in &expected {
                        assert_eq!(
                            std::fs::read(local.join(relative)).unwrap(),
                            std::fs::read(remote.join(relative)).unwrap()
                        );
                    }
                    if argv[0] != "-c" && argv[0] != "-S" {
                        let mut executable = Command::new(local.join(expected.last().unwrap()));
                        assert_eq!(run(&mut executable).await.stdout, b"native-37\n");
                    }
                }
            }
            assert_eq!(
                std::fs::read(local.join("main.c")).unwrap(),
                b"local source sentinel"
            );
            assert_eq!(
                std::fs::read(local.join("foreign.o")).unwrap(),
                b"other job's object"
            );
            assert_eq!(
                std::fs::read(unrelated_target.join("sentinel")).unwrap(),
                b"unrelated Cargo target"
            );
        }
    }

    fn publication_fixture() -> (tempfile::TempDir, tempfile::TempDir, RecoverySession) {
        let (directory, writer, _worker) = preparation_fixture();
        let stages = default_job_lease_directory().join("retrieval");
        std::fs::create_dir_all(&stages).unwrap();
        let stage_owner = tempfile::Builder::new()
            .prefix("publication-regression-")
            .disable_cleanup(true)
            .tempdir_in(stages)
            .unwrap();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.identity = stage_owner
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        recipe.project_root = directory.path().join("checkout");
        std::fs::create_dir(&recipe.project_root).unwrap();
        recipe.phases.push(RecoveryPhase {
            name: "project".into(),
            local: recipe.project_root.clone(),
            remote: "/unused/remote".into(),
            patterns: default_c_cpp_artifact_patterns(),
            result_dir: None,
            custom_target: false,
            output_gate: false,
            cargo_outputs: None,
            native_outputs: None,
            baseline: BTreeMap::new(),
            published: BTreeMap::new(),
            pending: None,
            complete: false,
            missing_result: None,
        });
        let session = RecoverySession { recipe, writer };
        std::fs::create_dir(session.stage(0)).unwrap();
        (directory, stage_owner, session)
    }

    #[test]
    fn clean_overlay_recovery_config_persists_extensions_and_retains_old_stage() {
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let old = session.stage(0);
        std::fs::write(old.join("worker-output"), b"retained").unwrap();
        session.recipe.transfer.max_transfer_time_ms = Some(138_000);
        let new = tempfile::tempdir().unwrap().keep();
        let config = TransferConfig {
            max_transfer_time_ms: Some(900_000),
            retrieval_staging_dir: Some(new.clone()),
            retrieval_min_free_bytes: 64 * 1024 * 1024,
            ..Default::default()
        };
        let original_identity = session.recipe.identity.clone();
        let original_phases = serde_json::to_value(&session.recipe.phases).unwrap();
        session.apply_retrieval_config(&config).unwrap();
        let mut reloaded = reload_publication(&session);
        assert_eq!(reloaded.recipe.transfer.max_transfer_time_ms, Some(900_000));
        assert_eq!(reloaded.stage(0), new.join(&original_identity).join("0"));
        assert_eq!(
            serde_json::to_value(&reloaded.recipe.phases).unwrap(),
            original_phases
        );
        assert!(!reloaded.writer.snapshot().terminal_acknowledged);
        assert_eq!(
            std::fs::read(old.join("worker-output")).unwrap(),
            b"retained"
        );
        reloaded
            .apply_retrieval_config(&TransferConfig {
                max_transfer_time_ms: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            load_recipe(&reloaded.writer)
                .unwrap()
                .transfer
                .max_transfer_time_ms,
            Some(900_000)
        );
        assert_eq!(
            load_recipe(&reloaded.writer)
                .unwrap()
                .transfer
                .retrieval_min_free_bytes,
            64 * 1024 * 1024
        );
        reloaded.recipe.phases[0].pending = Some((PathBuf::from("worker-output"), "hash".into()));
        assert!(
            reloaded
                .apply_retrieval_config(&TransferConfig {
                    retrieval_staging_dir: Some(old),
                    ..Default::default()
                })
                .is_err()
        );
        assert_eq!(reloaded.stage(0), new.join(original_identity).join("0"));
        let journal = std::fs::read(&reloaded.writer.path).unwrap();
        for invalid in [
            TransferConfig {
                retrieval_staging_dir: Some(PathBuf::from("relative")),
                ..Default::default()
            },
            TransferConfig {
                max_transfer_time_ms: Some(u64::MAX),
                ..Default::default()
            },
        ] {
            assert!(reloaded.apply_retrieval_config(&invalid).is_err());
            assert_eq!(std::fs::read(&reloaded.writer.path).unwrap(), journal);
        }
    }

    #[test]
    fn clean_overlay_recovery_extension_preserves_adaptive_budget() {
        for sentinel in [None, Some(0)] {
            for (initial_floor, requested, expected_floor) in [
                (138_000, 900_000, 900_000),
                (1_200_000, 900_000, 1_200_000),
                (900_000, 900_000, 900_000),
                (900_000, 0, 900_000),
            ] {
                let (_directory, _stage_owner, mut session) = publication_fixture();
                session.recipe.transfer.max_transfer_time_ms = sentinel;
                session.recipe.transfer.retry.total_timeout_ms = initial_floor;
                session.persist().unwrap();
                let mut expected = serde_json::to_value(&session.recipe).unwrap();
                expected["transfer"]["retry"]["total_timeout_ms"] = expected_floor.into();
                let stage = session.stage(0);
                std::fs::write(stage.join("worker-output"), b"retained output").unwrap();
                session
                    .apply_retrieval_config(&TransferConfig {
                        max_transfer_time_ms: Some(requested),
                        ..Default::default()
                    })
                    .unwrap();
                let mut reloaded = reload_publication(&session);
                assert_eq!(reloaded.recipe.transfer.max_transfer_time_ms, sentinel);
                assert_eq!(
                    reloaded.recipe.transfer.retry.total_timeout_ms,
                    expected_floor
                );
                // Compare the whole recipe, including worker/source authority,
                // output policy, publication checkpoints and original exit.
                assert_eq!(serde_json::to_value(&reloaded.recipe).unwrap(), expected);
                assert_eq!(reloaded.stage(0), stage);
                assert_eq!(
                    std::fs::read(stage.join("worker-output")).unwrap(),
                    b"retained output"
                );
                assert!(!reloaded.writer.snapshot().terminal_acknowledged);
                assert!(reloaded.recipe.returned.is_none());
                assert!(!reloaded.recipe.phases[0].complete);
                // A retry without an invocation override keeps the extension.
                reloaded
                    .apply_retrieval_config(&TransferConfig::default())
                    .unwrap();
                let reloaded = reload_publication(&reloaded);
                assert_eq!(serde_json::to_value(&reloaded.recipe).unwrap(), expected);
            }
        }
    }

    #[tokio::test]
    async fn clean_overlay_recovery_publication_skips_old_archive_without_acknowledging() {
        let _guard = test_guard!();
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let phases = session.recipe.phases.clone();
        let project_root = session.recipe.project_root.clone();
        let (_retained_directory, retained_writer, _worker) = retained_preparation_fixture();
        session.recipe = load_recipe(&retained_writer).unwrap();
        session.recipe.phases = phases;
        session.recipe.project_root = project_root;
        session.writer = retained_writer;
        // Reproduce a persisted recipe from before the reserved exclusion.
        session.recipe.phases[0].patterns = vec!["*".into(), "build/**".into()];
        let stage = session.stage(0);
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(
            stage.join(".rch-clean-overlay-base.tar"),
            b"immutable input",
        )
        .unwrap();
        std::fs::write(stage.join("a.out"), b"worker executable").unwrap();
        session.publish("project").await.unwrap();
        assert_eq!(
            std::fs::read(session.recipe.project_root.join("a.out")).unwrap(),
            b"worker executable"
        );
        assert!(
            !session
                .recipe
                .project_root
                .join(".rch-clean-overlay-base.tar")
                .exists()
        );
        assert!(!session.writer.snapshot().terminal_acknowledged);
        assert!(!session.recipe.sources_released);
        assert!(session.recipe.phases[0].complete);
        assert_eq!(
            std::fs::read(stage.join(".rch-clean-overlay-base.tar")).unwrap(),
            b"immutable input"
        );
    }

    fn reload_publication(session: &RecoverySession) -> RecoverySession {
        let writer = DurableLeaseWriter {
            path: session.writer.path.clone(),
            recovery_ownership: None,
            lease: Arc::new(Mutex::new(
                serde_json::from_slice(&std::fs::read(&session.writer.path).unwrap()).unwrap(),
            )),
        };
        RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer,
        }
    }

    fn captured_publication_fixture(
        kind: CompilationKind,
        command: &str,
        remote_root: &Path,
        custom_target: bool,
    ) -> (tempfile::TempDir, tempfile::TempDir, RecoverySession) {
        let (directory, stage_owner, mut session) = publication_fixture();
        let kind = Some(kind);
        session.recipe.kind = artifact_delivery_kind(kind, Some(command));
        session.recipe.prepared = true;
        session.recipe.execution_started = true;
        session.recipe.exit_code = Some(0);
        session.recipe.cargo_output_capture = CargoOutputCapture::for_command(kind, command);
        assert!(session.recipe.cargo_output_capture.is_some());
        let phase = &mut session.recipe.phases[0];
        phase.name = if custom_target { "target" } else { "project" }.into();
        phase.remote = remote_root.to_str().unwrap().to_owned();
        phase.custom_target = custom_target;
        phase.output_gate = true;
        phase.patterns = if custom_target {
            get_custom_target_artifact_patterns(kind, Some(command))
        } else {
            get_project_artifact_patterns(kind, Some(command), false)
        };
        session.persist().unwrap();
        (directory, stage_owner, session)
    }

    pub(super) async fn assert_cargo_fixture_publication(
        kind: CompilationKind,
        command: &str,
        stdout: &[u8],
        remote_root: &Path,
        custom_target: bool,
    ) {
        let (_directory, _stage_owner, session) =
            captured_publication_fixture(kind, command, remote_root, custom_target);
        // A detached collector must remember that evidence is still owed,
        // even if the wrapper stopped immediately after remote completion.
        let mut session = reload_publication(&session);
        assert!(session.needs_cargo_artifact_evidence());
        session
            .install_complete_cargo_evidence(&crate::transfer::CargoArtifactEvidence {
                stdout: stdout.to_vec(),
                remote_root: remote_root.to_path_buf(),
                remote_project_root: None,
            })
            .unwrap();
        let mut session = reload_publication(&session);
        let retained = session.retained_cargo_artifact_evidence().unwrap().unwrap();
        assert_eq!(retained.stdout, stdout);
        assert_eq!(retained.remote_root, remote_root);
        assert!(retained.remote_project_root.is_none());
        assert!(!session.needs_cargo_artifact_evidence());
        let required = session.recipe.phases[0]
            .cargo_outputs
            .as_ref()
            .unwrap()
            .required_files
            .clone();
        assert_eq!(
            required.len(),
            2,
            "fixture must select two named executables"
        );
        let missing = required
            .iter()
            .nth(1)
            .expect("fixture must contain a second executable");
        let local = session.recipe.phases[0].local.clone();
        let phase_name = session.recipe.phases[0].name.clone();
        let stage = session.stage(0);
        for relative in &required {
            let destination = local.join(relative);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::write(&destination, b"previous local executable").unwrap();
            if relative != missing {
                let staged = stage.join(relative);
                std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
                std::fs::copy(remote_root.join(relative), staged).unwrap();
            }
        }
        // A genuine non-empty support-file transfer used to hide a missing
        // requested executable from the old zero-output gate.
        let support = missing.parent().unwrap().join("deps/unrelated-runtime.so");
        std::fs::create_dir_all(stage.join(&support).parent().unwrap()).unwrap();
        std::fs::write(
            stage.join(&support),
            b"runtime support is not a requested binary",
        )
        .unwrap();
        let journal = std::fs::read(&session.writer.path).unwrap();
        assert!(session.publish(&phase_name).await.is_err());
        for relative in &required {
            assert_eq!(
                std::fs::read(local.join(relative)).unwrap(),
                b"previous local executable",
                "a missing executable must not partially replace {}",
                relative.display()
            );
        }
        assert!(!local.join(&support).exists());
        assert!(stage.join(&support).is_file());
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
        assert!(session.recipe.phases[0].published.is_empty());
        assert!(!session.recipe.phases[0].complete);
        assert!(session.returned(0).is_err());

        // Supply the missing output on the same attempt, then recover solely
        // from the disk journal and staged bytes. No command is replayed.
        let mut resumed = reload_publication(&session);
        std::fs::create_dir_all(stage.join(missing).parent().unwrap()).unwrap();
        std::fs::copy(remote_root.join(missing), stage.join(missing)).unwrap();
        resumed.publish(&phase_name).await.unwrap();
        for relative in &required {
            assert_eq!(
                std::fs::read(local.join(relative)).unwrap(),
                std::fs::read(remote_root.join(relative)).unwrap()
            );
        }
        resumed.returned(0).unwrap();
        let finished = reload_publication(&resumed);
        assert!(finished.recipe.phases[0].complete);
        assert_eq!(finished.recipe.returned, Some(0));
        assert_eq!(
            finished.recipe.phases[0]
                .cargo_outputs
                .as_ref()
                .unwrap()
                .required_files,
            required
        );
        assert!(!stage.exists());
    }

    fn cargo_bin_receipt(root: &Path, custom_target: bool) -> Vec<u8> {
        let mut receipt = Vec::new();
        for name in ["app", "helper"] {
            let path = root
                .join(if custom_target { "lean" } else { "target/lean" })
                .join(name);
            let record = serde_json::json!({
                "reason": "compiler-artifact",
                "target": {"name": name, "kind": ["bin"]},
                "filenames": [path], "executable": path, "fresh": true
            });
            receipt.extend(serde_json::to_vec(&record).unwrap());
            receipt.push(b'\n');
        }
        receipt.extend_from_slice(b"{\"reason\":\"build-finished\",\"success\":true}\n");
        receipt
    }

    // These are retained journal/byte-binding regressions, not SSH, compiler,
    // native SDK or admission proof. They run only after the real quality gates
    // admit test execution; all fixture owners remain retained.
    #[test]
    fn ordinary_cargo_retains_complete_producer_across_contract_recovery() {
        let remote_root = Path::new("/retained-cargo-output");
        let (directory, stage_owner, mut session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote_root,
            false,
        );
        let _directory = directory.keep();
        let _stage = stage_owner.keep();
        let stdout = cargo_bin_receipt(remote_root, false);
        assert!(session.recipe.caller_json_policy.is_none());
        assert!(
            session
                .retained_cargo_artifact_evidence()
                .unwrap()
                .is_none()
        );
        // Model interruption after producer custody, before contract install.
        session
            .retain_cargo_stdout(&stdout, remote_root, None, 0)
            .unwrap();
        let mut recovered = reload_publication(&session);
        assert!(recovered.needs_cargo_artifact_evidence());
        let retained = recovered
            .retained_cargo_artifact_evidence()
            .unwrap()
            .unwrap();
        assert_eq!(retained.stdout, stdout);
        assert_eq!(retained.remote_root, remote_root);
        assert!(retained.remote_project_root.is_none());
        recovered
            .install_complete_cargo_evidence(&retained)
            .unwrap();
        let completed = reload_publication(&recovered);
        assert!(!completed.needs_cargo_artifact_evidence());
        assert_eq!(
            completed
                .retained_cargo_artifact_evidence()
                .unwrap()
                .unwrap()
                .stdout,
            stdout
        );
        assert!(completed.recipe.caller_json_policy.is_none());
        assert!(completed.recipe.cargo_stderr.is_none());
        assert!(completed.recipe.caller_delivery.is_none());
    }

    #[test]
    fn retained_cargo_corruption_and_missing_bytes_do_not_allow_rebaselining() {
        let remote_root = Path::new("/retained-cargo-output");
        let (directory, stage_owner, mut session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote_root,
            false,
        );
        let _directory = directory.keep();
        let _stage = stage_owner.keep();
        let stdout = cargo_bin_receipt(remote_root, false);
        session
            .install_complete_cargo_evidence(&crate::transfer::CargoArtifactEvidence {
                stdout: stdout.clone(),
                remote_root: remote_root.to_path_buf(),
                remote_project_root: None,
            })
            .unwrap();
        let path = session.recipe.cargo_stdout.as_ref().unwrap().path.clone();
        // A wrong present file exercises the immutable byte pin without
        // truncating the original retained producer evidence.
        let corrupt_path = _directory.join("wrong-present-producer");
        let corrupt_bytes = b"changed same-attempt producer bytes";
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&corrupt_path)
            .unwrap()
            .write_all(corrupt_bytes)
            .unwrap();
        session.recipe.cargo_stdout.as_mut().unwrap().path = corrupt_path.clone();
        session.persist().unwrap();
        let mut corrupted = reload_publication(&session);
        assert!(!corrupted.needs_cargo_artifact_evidence());
        assert!(corrupted.retained_cargo_artifact_evidence().is_err());
        assert!(
            corrupted
                .retain_cargo_stdout(&stdout, remote_root, None, 0)
                .is_err()
        );
        assert_eq!(
            corrupted.recipe.cargo_stdout.as_ref().unwrap().path,
            corrupt_path
        );
        assert_eq!(std::fs::read(&path).unwrap(), stdout);
        assert_eq!(std::fs::read(&corrupt_path).unwrap(), corrupt_bytes);
        // Preserve both original and wrong files while making the recorded
        // path absent. This is a missing-path probe, not a deletion probe.
        corrupted.recipe.cargo_stdout.as_mut().unwrap().path = _directory.join("absent-producer");
        corrupted.persist().unwrap();
        let mut missing = reload_publication(&corrupted);
        assert!(missing.retained_cargo_artifact_evidence().is_err());
        assert!(
            missing
                .retain_cargo_stdout(&stdout, remote_root, None, 0)
                .is_err()
        );
        missing.recipe.exit_code = Some(7);
        missing.persist().unwrap();
        assert!(load_recipe(&missing.writer).is_err());
    }

    #[test]
    fn legacy_caller_receipt_preserves_its_observed_source_root() {
        let receipt: RetainedCargoStdout = serde_json::from_value(serde_json::json!({
            "path": "/retained/producer",
            "blake3": blake3::hash(b"").to_hex().to_string(),
            "bytes": 0,
            "remote_root": "/worker/target",
            "remote_project_root": "/worker/source",
            "exit_code": 0,
        }))
        .unwrap();
        assert_eq!(
            receipt.remote_project_root.as_deref(),
            Some(Path::new("/worker/source"))
        );
    }

    #[test]
    fn retained_cargo_root_preserves_the_worker_transport_spelling() {
        // This stores declared receipt data; it does not prove a Windows
        // compiler/transport executed. The coordinator must not reinterpret a
        // worker's drive spelling with its own Unix Path::is_absolute rules.
        let remote_root = Path::new("C:/rch/retained-cargo-output");
        let (directory, stage_owner, mut session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote_root,
            false,
        );
        let _directory = directory.keep();
        let _stage = stage_owner.keep();
        let stdout = cargo_bin_receipt(remote_root, false);
        session
            .retain_cargo_stdout(&stdout, remote_root, None, 0)
            .unwrap();
        let recovered = reload_publication(&session);
        let retained = recovered
            .retained_cargo_artifact_evidence()
            .unwrap()
            .unwrap();
        assert_eq!(retained.remote_root, remote_root);
        assert_eq!(retained.stdout, stdout);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_cargo_recovery_checks_original_local_producer_before_shortcuts() {
        // Real held journal ownership and local files exercise the production
        // recovery consumer. Job fields below are unit inputs, not evidence
        // that a worker/compiler/SDK ran. No worker or daemon may be contacted.
        // Successful returned-but-unacknowledged recovery needs real daemon
        // reconciliation and remains in that service lane. These seven cases
        // are exactly the local terminal-readback/early-refusal coverage.
        for (acknowledged, receipt_case) in [
            (true, "valid"),
            (true, "wrong-present"),
            (true, "missing"),
            (true, "legacy-absent"),
            (true, "failed-delivery-unbound"),
            (false, "wrong-present"),
            (false, "missing"),
        ] {
            // A successful returned-but-unacknowledged negative needs an
            // absent real wrapper. Let an owned process exit naturally;
            // never fake owner absence or signal a process to force it.
            let mut wrapper = std::process::Command::new("/usr/bin/true").spawn().unwrap();
            let wrapper_pid = wrapper.id();
            assert!(wrapper.wait().unwrap().success());
            let remote_root = Path::new("/retained-cargo-output");
            let (directory, stage_owner, mut session) = captured_publication_fixture(
                CompilationKind::CargoBuild,
                "cargo build --bin app --bin helper --profile lean",
                remote_root,
                false,
            );
            let directory = directory.keep();
            let _stage = stage_owner.keep();
            let stdout = cargo_bin_receipt(remote_root, false);
            session
                .retain_cargo_stdout(&stdout, remote_root, None, 0)
                .unwrap();
            // Real collection installs the output contract before any
            // publication and checkpoints every required output; a
            // successful terminal journal always carries both.
            session
                .install_cargo_artifact_evidence(&stdout, remote_root)
                .unwrap();
            let required = session.recipe.phases[0]
                .cargo_outputs
                .as_ref()
                .unwrap()
                .required_files
                .clone();
            for relative in required {
                let hash = blake3::hash(relative.as_os_str().as_encoded_bytes());
                session.recipe.phases[0]
                    .published
                    .insert(relative, hash.to_hex().to_string());
            }
            let original = session.recipe.cargo_stdout.as_ref().unwrap().path.clone();
            let delivered_exit = if receipt_case == "failed-delivery-unbound" {
                EXIT_ARTIFACT_TRANSFER_FAILED
            } else {
                0
            };
            session.recipe.returned = Some(delivered_exit);
            session.recipe.phases[0].complete = true;
            session.recipe.tree_retired = true;
            session.recipe.pair_released = true;
            session.recipe.sources_released = true;
            session.recipe.retired = true;
            match receipt_case {
                "wrong-present" | "failed-delivery-unbound" => {
                    let path = directory.join("wrong-present-producer");
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .unwrap()
                        .write_all(b"unbound producer bytes")
                        .unwrap();
                    session.recipe.cargo_stdout.as_mut().unwrap().path = path;
                }
                "missing" => {
                    session.recipe.cargo_stdout.as_mut().unwrap().path =
                        directory.join("absent-producer")
                }
                "legacy-absent" => session.recipe.cargo_stdout = None,
                "valid" => {}
                _ => unreachable!(),
            }
            {
                let mut lease = session.writer.lease.lock().unwrap();
                lease.wrapper_pid = wrapper_pid;
                lease.process_start_ticks = None;
                lease.boot_id = None;
                lease.process_birth = None;
            }
            session.persist().unwrap();
            session.writer.record_exit(delivered_exit).unwrap();
            if acknowledged {
                session.writer.acknowledge_terminal().unwrap();
            }
            let journal = std::fs::read(&session.writer.path).unwrap();
            let result = recover_job_with_daemon(&session.writer, async |_request: &str| {
                panic!("terminal producer check unexpectedly contacted daemon")
            })
            .await;
            if matches!(receipt_case, "wrong-present" | "missing") {
                let error = result.expect_err("invalid producer must not borrow terminal success");
                let description = format!("{error:#}");
                if receipt_case == "wrong-present" {
                    assert!(
                        description.contains(
                            "retained Cargo stdout bytes failed their exact invocation binding"
                        ),
                        "{receipt_case} did not reach the producer binding check: {description}"
                    );
                } else {
                    assert!(
                        description
                            .contains("retained Cargo stdout producer metadata is unavailable")
                            && error.chain().any(|cause| {
                                cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                                    error.kind() == std::io::ErrorKind::NotFound
                                })
                            }),
                        "{receipt_case} did not reach the producer read: {description}"
                    );
                }
            } else {
                assert_eq!(result.unwrap(), delivered_exit);
            }
            assert_eq!(std::fs::read(&original).unwrap(), stdout);
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
        }
    }

    #[cfg(unix)]
    fn caller_delivery_fixture(
        retained_source: bool,
        custom_target: bool,
    ) -> (PathBuf, RecoverySession) {
        let (directory, writer, _worker) = retained_preparation_fixture();
        std::fs::create_dir_all(default_job_lease_directory()).unwrap();
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer,
        };
        let local = directory.join("caller");
        std::fs::create_dir(&local).unwrap();
        std::fs::write(local.join("Cargo.toml"), b"[workspace]\n").unwrap();
        let remote = PathBuf::from(session.recipe.retire_root.as_ref().unwrap());
        let (output_local, output_remote, output_relative) = if custom_target {
            session.recipe.phases.push(RecoveryPhase {
                name: "project".into(),
                local: local.clone(),
                remote: remote.to_str().unwrap().into(),
                patterns: Vec::new(),
                result_dir: None,
                custom_target: false,
                output_gate: false,
                cargo_outputs: None,
                native_outputs: None,
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: true,
                missing_result: None,
            });
            (
                local.join("custom-target"),
                remote.join("custom-target"),
                Path::new("lean"),
            )
        } else {
            (local.clone(), remote.clone(), Path::new("target/lean"))
        };
        let command = "cargo build --bin app --bin helper --profile lean --message-format=json";
        session.recipe.project_root = local;
        session.recipe.transfer.retrieval_staging_dir = Some(directory.join("retrieval"));
        session.recipe.kind = Some(CompilationKind::CargoBuild);
        session.recipe.cargo_output_capture =
            CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), command);
        session.recipe.phases.push(RecoveryPhase {
            name: if custom_target {
                "custom-target"
            } else {
                "project"
            }
            .into(),
            local: output_local,
            remote: output_remote.to_str().unwrap().into(),
            patterns: if custom_target {
                get_custom_target_artifact_patterns(
                    Some(CompilationKind::CargoBuild),
                    Some(command),
                )
            } else {
                get_project_artifact_patterns(
                    Some(CompilationKind::CargoBuild),
                    Some(command),
                    false,
                )
            },
            result_dir: None,
            custom_target,
            output_gate: true,
            cargo_outputs: None,
            native_outputs: None,
            baseline: BTreeMap::new(),
            published: BTreeMap::new(),
            pending: None,
            complete: false,
            missing_result: None,
        });
        session.recipe.prepared = true;
        session.request_caller_json(&remote).unwrap();
        session.starting_execution().unwrap();
        session.completed(0).unwrap();

        // Compiler output and source-release acknowledgments are unit inputs.
        // Publication, retained caller copies and terminal JSON recovery below
        // use the production paths and real files, without contacting a peer.
        let mut stdout = Vec::new();
        for name in ["app", "helper"] {
            let path = output_remote.join(output_relative).join(name);
            let record = serde_json::json!({
                "reason": "compiler-artifact",
                "target": {"name": name, "kind": ["bin"]},
                "profile": {"test": false},
                "manifest_path": remote.join("Cargo.toml"),
                "filenames": [path], "executable": path, "fresh": true
            });
            stdout.extend(serde_json::to_vec(&record).unwrap());
            stdout.push(b'\n');
        }
        stdout.extend_from_slice(b"{\"reason\":\"build-finished\",\"success\":true}\n");
        session
            .install_complete_cargo_evidence(&crate::transfer::CargoArtifactEvidence {
                stdout,
                remote_root: output_remote,
                remote_project_root: Some(remote),
            })
            .unwrap();
        let stderr = b"complete compiler diagnostics\n";
        let stderr_path =
            retain_cargo_bytes(&session.recipe.wrapper_id, "cargo-stderr", stderr).unwrap();
        session.recipe.cargo_stderr = Some(RetainedCargoStderr {
            path: stderr_path,
            blake3: blake3::hash(stderr).to_hex().to_string(),
            bytes: stderr.len() as u64,
            exit_code: 0,
        });
        if !retained_source {
            session.recipe.source_roots.clear();
            session.recipe.pair = None;
            session.recipe.retire_root = None;
            session.recipe.retained_root = None;
        }
        session.persist().unwrap();
        let stage = session.stage(session.recipe.phases.len() - 1);
        std::fs::create_dir_all(stage.join(output_relative)).unwrap();
        std::fs::write(stage.join("collector-source.c"), b"private collector input").unwrap();
        for name in ["app", "helper"] {
            std::fs::write(stage.join(output_relative).join(name), name.as_bytes()).unwrap();
        }
        (directory, session)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_cargo_json_recovery_uses_delivery_outside_original_stage() {
        let _guard = test_guard!();
        let (_directory, mut session) = caller_delivery_fixture(true, false);
        let writer = session.writer.clone();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        let stdout = session
            .recipe
            .cargo_stdout
            .as_ref()
            .unwrap()
            .read()
            .unwrap();
        let stderr = b"complete compiler diagnostics\n";
        let stderr_path = session.recipe.cargo_stderr.as_ref().unwrap().path.clone();
        session.publish("project").await.unwrap();
        session.returned(0).unwrap();
        let expected_stdout = session.caller_cargo_json().await.unwrap();
        session.persist_tree_retirement(Some(true)).unwrap();
        session.pair_released().unwrap();
        session.sources_released().unwrap();
        session.retired().unwrap();
        writer.record_exit(0).unwrap();
        writer.acknowledge_terminal().unwrap();

        let producer = session.recipe.cargo_stdout.as_ref().unwrap().path.clone();
        let delivery = session.recipe.caller_delivery.as_ref().unwrap().clone();
        let original_stage = stage.parent().unwrap().to_owned();
        for retained in [
            &producer,
            &stderr_path,
            &delivery.path,
            &delivery.output_root,
        ] {
            assert!(!retained.starts_with(&original_stage));
        }
        assert_eq!(delivery.files.len(), 2);
        // A successful retained delivery releases its local stage at
        // retirement (bd-ra5aw, owner decision 2026-10-30), so recovery below
        // must work from the copies outside it.
        assert!(!original_stage.exists());
        for name in ["app", "helper"] {
            std::fs::write(
                local.join("target/lean").join(name),
                b"a later build's shared output",
            )
            .unwrap();
        }
        let recovered = reload_publication(&session);
        let journal = std::fs::read(&writer.path).unwrap();
        let (exit, recovered_stdout, recovered_stderr) =
            recover_job_cargo_json(&recovered.writer).await.unwrap();
        assert_eq!(exit, 0);
        assert_eq!(
            recovered_stdout.as_deref(),
            Some(expected_stdout.as_slice())
        );
        assert_eq!(recovered_stderr, stderr);
        assert_eq!(std::fs::read(&writer.path).unwrap(), journal);
        assert!(!original_stage.exists());
        assert_eq!(std::fs::read(producer).unwrap(), stdout);
        assert_eq!(std::fs::read(stderr_path).unwrap(), stderr);
        assert_eq!(std::fs::read(&delivery.path).unwrap(), expected_stdout);
        for name in ["app", "helper"] {
            let relative = Path::new("target/lean").join(name);
            assert_eq!(
                std::fs::read(delivery.output_root.join(&relative)).unwrap(),
                name.as_bytes()
            );
            assert_eq!(
                std::fs::read(local.join(relative)).unwrap(),
                b"a later build's shared output"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn caller_cargo_delivery_uses_original_stage_after_shared_output_replacement() {
        let _guard = test_guard!();
        for retained_source in [false, true] {
            for custom_target in [false, true] {
                let (_directory, mut session) =
                    caller_delivery_fixture(retained_source, custom_target);
                let index = session.recipe.phases.len() - 1;
                assert_eq!(index, usize::from(custom_target));
                let stage = session.stage(index);
                let phase = session.recipe.phases[index].clone();
                session.publish(&phase.name).await.unwrap();
                // Ordinary jobs need the stage too: their first caller copy
                // has not yet crossed its durable delivery boundary.
                assert!(stage.is_dir());
                session.returned(0).unwrap();
                let published = session.recipe.phases[index].published.clone();
                assert_eq!(published.len(), 2);
                for relative in published.keys() {
                    std::fs::write(phase.local.join(relative), b"a later build's shared output")
                        .unwrap();
                }

                // Crash after durable returned(0), before the first caller
                // receipt. Recovery must finish from the same staged bytes.
                let mut recovered = reload_publication(&session);
                assert!(recovered.recipe.caller_delivery.is_none());
                let stdout = recovered.caller_cargo_json().await.unwrap();
                let delivery = recovered.recipe.caller_delivery.as_ref().unwrap();
                assert_eq!(delivery.files, published);
                assert_eq!(recovered.recipe.phases[index].published, published);
                assert_eq!(recovered.recipe.returned, Some(0));
                assert!(!recovered.recipe.retired);
                assert_eq!(
                    std::fs::read(stage.join("collector-source.c")).unwrap(),
                    b"private collector input"
                );
                for relative in published.keys() {
                    let expected = relative.file_name().unwrap().to_str().unwrap().as_bytes();
                    assert_eq!(std::fs::read(stage.join(relative)).unwrap(), expected);
                    assert_eq!(
                        std::fs::read(delivery.output_root.join(relative)).unwrap(),
                        expected
                    );
                    assert_eq!(
                        std::fs::read(phase.local.join(relative)).unwrap(),
                        b"a later build's shared output"
                    );
                }
                assert_eq!(
                    reload_publication(&recovered)
                        .caller_cargo_json()
                        .await
                        .unwrap(),
                    stdout
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn caller_cargo_delivery_rejects_present_invalid_stage_without_shared_fallback() {
        let _guard = test_guard!();
        for invalid in [
            "changed-file",
            "missing-file",
            "symlink-file",
            "symlink-stage",
            "file-stage",
            "dangling-parent",
        ] {
            let (directory, mut session) = caller_delivery_fixture(true, false);
            session.publish("project").await.unwrap();
            session.returned(0).unwrap();
            let stage = session.stage(0);
            let source = stage.join("target/lean/app");
            let preserved = directory.join("preserved-stage-input");
            match invalid {
                "changed-file" => std::fs::write(&source, b"changed staged output").unwrap(),
                "missing-file" | "symlink-file" => {
                    std::fs::rename(&source, &preserved).unwrap();
                    if invalid == "symlink-file" {
                        std::os::unix::fs::symlink(&preserved, &source).unwrap();
                    }
                }
                "symlink-stage" | "file-stage" => {
                    std::fs::rename(&stage, &preserved).unwrap();
                    if invalid == "symlink-stage" {
                        std::os::unix::fs::symlink(&preserved, &stage).unwrap();
                    } else {
                        std::fs::write(&stage, b"not a staging directory").unwrap();
                    }
                }
                "dangling-parent" => {
                    let parent = stage.parent().unwrap();
                    std::fs::rename(parent, &preserved).unwrap();
                    std::os::unix::fs::symlink(directory.join("absent-target"), parent).unwrap();
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(&session.writer.path).unwrap();
            let mut recovered = reload_publication(&session);
            let error = recovered.caller_cargo_json().await.unwrap_err();
            assert!(
                recovered.recipe.caller_delivery.is_none(),
                "{invalid}: {error:#}"
            );
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
            // Valid shared bytes cannot hide a corrupt or incomplete stage.
            for name in ["app", "helper"] {
                assert_eq!(
                    std::fs::read(session.recipe.project_root.join("target/lean").join(name))
                        .unwrap(),
                    name.as_bytes()
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn caller_cargo_delivery_without_legacy_stage_requires_original_shared_bytes() {
        let _guard = test_guard!();
        for matching in [true, false] {
            let (directory, mut session) = caller_delivery_fixture(false, false);
            session.publish("project").await.unwrap();
            session.returned(0).unwrap();
            let stage = session.stage(0);
            let preserved = directory.join("preserved-legacy-stage");
            // Model an older ordinary recipe whose completed phase was
            // removed, while preserving every fixture byte for inspection.
            std::fs::rename(&stage, &preserved).unwrap();
            if !matching {
                std::fs::write(
                    session.recipe.project_root.join("target/lean/app"),
                    b"a later build's shared output",
                )
                .unwrap();
            }
            let before = std::fs::read(&session.writer.path).unwrap();
            let mut recovered = reload_publication(&session);
            let result = recovered.caller_cargo_json().await;
            if matching {
                result.unwrap();
                let delivery = recovered.recipe.caller_delivery.as_ref().unwrap();
                for name in ["app", "helper"] {
                    assert_eq!(
                        std::fs::read(delivery.output_root.join("target/lean").join(name)).unwrap(),
                        name.as_bytes()
                    );
                }
            } else {
                assert!(result.is_err());
                assert!(recovered.recipe.caller_delivery.is_none());
                assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
            }
            assert!(!stage.exists());
            for name in ["app", "helper"] {
                assert_eq!(
                    std::fs::read(preserved.join("target/lean").join(name)).unwrap(),
                    name.as_bytes()
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cargo_no_run_delivers_every_real_named_test_and_bench_after_recovery() {
        use std::process::Stdio;
        use tokio::process::Command;

        for (kind, subcommand, selector, target_kind, custom_target) in [
            (CompilationKind::CargoTest, "test", "test", "test", false),
            (CompilationKind::CargoTest, "test", "test", "test", true),
            (
                CompilationKind::CargoBench,
                "bench",
                "bench",
                "bench",
                false,
            ),
            (CompilationKind::CargoBench, "bench", "bench", "bench", true),
        ] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source project");
            for directory in ["src", "tests", "benches"] {
                std::fs::create_dir_all(source.join(directory)).unwrap();
            }
            std::fs::write(source.join("Cargo.toml"), concat!(
                "[package]\nname = \"rch_named_no_run_fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
                "[workspace]\n",
                "[[test]]\nname = \"alpha\"\npath = \"tests/alpha.rs\"\n",
                "[[test]]\nname = \"beta\"\npath = \"tests/beta.rs\"\n",
                "[[bench]]\nname = \"alpha\"\npath = \"benches/alpha.rs\"\nharness = false\n",
                "[[bench]]\nname = \"beta\"\npath = \"benches/beta.rs\"\nharness = false\n",
                "[profile.contract-fixture]\ninherits = \"dev\"\ndebug = 0\n",
            )).unwrap();
            std::fs::write(source.join("src/lib.rs"), "pub fn answer() -> u8 { 42 }\n").unwrap();
            for name in ["alpha", "beta"] {
                std::fs::write(
                    source.join("tests").join(format!("{name}.rs")),
                    format!("#[test] fn {name}_must_not_run() {{ panic!(\"no-run executed a test\"); }}\n"),
                ).unwrap();
                std::fs::write(
                    source.join("benches").join(format!("{name}.rs")),
                    "fn main() { panic!(\"no-run executed a benchmark\"); }\n",
                )
                .unwrap();
            }
            let remote_target = if custom_target {
                fixture.path().join("worker target")
            } else {
                source.join("target")
            };
            let remote_root = if custom_target {
                &remote_target
            } else {
                &source
            };
            let command = format!(
                "cargo {subcommand} --no-run --{selector} alpha --{selector} beta --profile contract-fixture --offline --jobs=1"
            );
            let capture = CargoOutputCapture::for_command(Some(kind), &command).unwrap();
            let instrumented = capture.execution_command(&command);
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut compile = Command::new(cargo);
            compile
                .current_dir(&source)
                .args(instrumented.split_ascii_whitespace().skip(1))
                // The live command pins build.build-dir into the worker output
                // tree. Exercise the real new layout, including executable
                // files beneath normally excluded build-cache directories.
                .arg("--config")
                .arg(format!(
                    "build.build-dir={}",
                    serde_json::to_string(remote_target.to_str().unwrap()).unwrap()
                ))
                .env("CARGO_HOME", fixture.path().join("cargo-home"))
                .env("CARGO_TARGET_DIR", &remote_target)
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("CARGO_BUILD_TARGET")
                .env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_BUILD_BUILD_DIR")
                .env_remove("CARGO_MAKEFLAGS")
                .env_remove("MAKEFLAGS")
                .stdin(Stdio::null())
                .kill_on_drop(true);
            let mut completed_stdout = Vec::new();
            for warm in [false, true] {
                let output = tokio::time::timeout(Duration::from_secs(90), compile.output())
                    .await
                    .expect("owned no-run Cargo fixture timed out")
                    .expect("Cargo is required for the named no-run delivery regression");
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
                    .unwrap()
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .filter(|record: &serde_json::Value| {
                        record["reason"] == "compiler-artifact"
                            && record["target"]["kind"] == serde_json::json!([target_kind])
                    })
                    .collect();
                assert_eq!(records.len(), 2, "both requested targets must be emitted");
                assert!(records.iter().all(|record| record["fresh"] == warm));
                let contract = capture.parse_receipt(&output.stdout, remote_root).unwrap();
                assert_eq!(contract.required_files.len(), 2);
                assert!(
                    contract
                        .required_files
                        .iter()
                        .all(|path| { path.components().any(|part| part.as_os_str() == "build") }),
                    "fixture must exercise the managed build directory: {contract:?}"
                );
                completed_stdout = output.stdout;
            }

            let (_local_owner, _stage_owner, mut session) =
                captured_publication_fixture(kind, &command, remote_root, custom_target);
            session
                .install_cargo_artifact_evidence(&completed_stdout, remote_root)
                .unwrap();
            let mut session = reload_publication(&session);
            let phase = &session.recipe.phases[0];
            let required = phase.cargo_outputs.as_ref().unwrap().required_files.clone();
            let patterns = phase.patterns.clone();
            let name = phase.name.clone();
            let local = phase.local.clone();
            let stage = session.stage(0);
            let missing = required.iter().next_back().unwrap();
            for relative in &required {
                std::fs::create_dir_all(local.join(relative).parent().unwrap()).unwrap();
                std::fs::write(local.join(relative), b"previous local executable").unwrap();
            }
            let source_sentinel = local.join("source.rs");
            std::fs::write(&source_sentinel, b"local source remains owned locally").unwrap();
            for complete_transfer in [false, true] {
                let mut transfer = Command::new("rsync");
                transfer.args(["-a", "--checksum", "--safe-links", "--prune-empty-dirs"]);
                if !complete_transfer {
                    // Simulate a successful but incomplete artifact transfer.
                    // The other executable makes the old nonempty gate pass.
                    transfer.arg(format!("--exclude=/{}", missing.display()));
                }
                for rule in crate::transfer::priority_rsync_includes(&patterns) {
                    transfer.arg(format!("--include={rule}"));
                }
                for pattern in &patterns {
                    if let Some(excluded) = pattern.strip_prefix("- ") {
                        transfer.arg(format!("--exclude={excluded}"));
                    }
                }
                transfer.arg("--include=*/");
                for pattern in &patterns {
                    if !pattern.starts_with("- ") {
                        transfer.arg(format!(
                            "--include=/{}",
                            pattern.strip_prefix("+ ").unwrap_or(pattern)
                        ));
                    }
                }
                transfer
                    .arg("--exclude=*")
                    .arg(format!("{}/", remote_root.display()))
                    .arg(format!("{}/", stage.display()))
                    .stdin(Stdio::null())
                    .kill_on_drop(true);
                let copied = tokio::time::timeout(Duration::from_secs(15), transfer.output())
                    .await
                    .expect("owned no-run rsync fixture timed out")
                    .expect("rsync is required for the named no-run delivery regression");
                assert!(copied.status.success(), "{copied:?}");
                if !complete_transfer {
                    assert!(
                        required
                            .iter()
                            .any(|relative| stage.join(relative).is_file())
                    );
                    assert!(!stage.join(missing).exists());
                    let journal = std::fs::read(&session.writer.path).unwrap();
                    assert!(session.publish(&name).await.is_err());
                    assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
                    assert!(session.returned(0).is_err());
                    for relative in &required {
                        assert_eq!(
                            std::fs::read(local.join(relative)).unwrap(),
                            b"previous local executable"
                        );
                    }
                    session = reload_publication(&session);
                } else {
                    session.publish(&name).await.unwrap();
                    session.returned(0).unwrap();
                    for relative in &required {
                        assert_eq!(
                            std::fs::read(local.join(relative)).unwrap(),
                            std::fs::read(remote_root.join(relative)).unwrap()
                        );
                    }
                    let restored = reload_publication(&session);
                    assert_eq!(restored.recipe.returned, Some(0));
                    assert!(restored.recipe.phases[0].complete);
                }
                assert_eq!(
                    std::fs::read(&source_sentinel).unwrap(),
                    b"local source remains owned locally"
                );
            }
        }
    }

    #[tokio::test]
    async fn cargo_missing_named_bin_preserves_all_outputs_until_disk_reloaded_retry() {
        for custom_target in [false, true] {
            let remote = tempfile::tempdir().unwrap();
            let outputs = remote
                .path()
                .join(if custom_target { "lean" } else { "target/lean" });
            std::fs::create_dir_all(&outputs).unwrap();
            std::fs::write(outputs.join("app"), b"new app executable").unwrap();
            std::fs::write(outputs.join("helper"), b"new helper executable").unwrap();
            assert_cargo_fixture_publication(
                CompilationKind::CargoBuild,
                "cargo build --bin app --bin helper --profile lean",
                &cargo_bin_receipt(remote.path(), custom_target),
                remote.path(),
                custom_target,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn cargo_awaiting_receipt_cannot_publish_or_report_success_and_retains_failure_stage() {
        let remote = tempfile::tempdir().unwrap();
        let (_directory, _stage_owner, session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote.path(),
            false,
        );
        let mut session = reload_publication(&session);
        let stage = session.stage(0);
        std::fs::create_dir_all(stage.join("target/lean")).unwrap();
        std::fs::write(stage.join("target/lean/app"), b"new app").unwrap();
        let before = std::fs::read(&session.writer.path).unwrap();
        assert!(session.publish("project").await.is_err());
        assert!(session.returned(0).is_err());
        assert!(
            !session.recipe.phases[0]
                .local
                .join("target/lean/app")
                .exists()
        );
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        session.returned(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
        session.sources_released().unwrap();
        session.retired().unwrap();
        assert!(session.retain_failed_delivery_evidence());
        assert_eq!(
            std::fs::read(stage.join("target/lean/app")).unwrap(),
            b"new app"
        );
        let retired = reload_publication(&session);
        assert!(retired.recipe.retired);
        assert!(!retired.recipe.phases[0].complete);
        assert_eq!(retired.recipe.returned, Some(EXIT_ARTIFACT_TRANSFER_FAILED));
    }

    #[test]
    fn cargo_invalid_evidence_cannot_expand_policy_or_replace_sources() {
        let remote = tempfile::tempdir().unwrap();
        let (_directory, _stage_owner, mut session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote.path(),
            false,
        );
        let before = std::fs::read(&session.writer.path).unwrap();
        let patterns = session.recipe.phases[0].patterns.clone();
        let receipt = cargo_bin_receipt(remote.path(), false);
        let finished_start = receipt[..receipt.len() - 1]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .unwrap()
            + 1;
        let missing_finished = &receipt[..finished_start];
        let error = session
            .install_cargo_artifact_evidence(missing_finished, remote.path())
            .unwrap_err();
        assert!(error.is::<CargoOutputContractRejected>());
        let forged = String::from_utf8(cargo_bin_receipt(remote.path(), false))
            .unwrap()
            .replace("target/lean/app", "Cargo.toml");
        assert!(
            session
                .install_cargo_artifact_evidence(forged.as_bytes(), remote.path())
                .is_err()
        );
        assert_eq!(session.recipe.phases[0].patterns, patterns);
        assert!(session.recipe.phases[0].cargo_outputs.is_none());
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
    }

    #[test]
    fn cargo_evidence_journal_failure_remains_retryable_and_cannot_authorize_publication() {
        let remote = tempfile::tempdir().unwrap();
        let (directory, _stage_owner, mut session) = captured_publication_fixture(
            CompilationKind::CargoBuild,
            "cargo build --bin app --bin helper --profile lean",
            remote.path(),
            false,
        );
        let journal = session.writer.path.clone();
        let before = std::fs::read(&journal).unwrap();
        // Atomic publication cannot replace a directory with the lease file.
        // This is a real filesystem failure, not an invalid Cargo receipt.
        session.writer.path = directory.path().to_owned();
        let error = session
            .install_cargo_artifact_evidence(
                &cargo_bin_receipt(remote.path(), false),
                remote.path(),
            )
            .unwrap_err();
        assert!(!error.is::<CargoOutputContractRejected>());
        assert!(session.needs_cargo_artifact_evidence());
        assert_eq!(std::fs::read(journal).unwrap(), before);
    }

    #[tokio::test]
    async fn recovery_publication_refuses_retained_or_pending_source_before_any_write() {
        for pending in [false, true] {
            let (_directory, _stage_owner, mut session) = publication_fixture();
            let local = session.recipe.project_root.clone();
            let stage = session.stage(0);
            let original = b"int main(void) { return 0; }\n";
            let remote = b"changed source from an earlier collector\n";
            std::fs::write(local.join("main.c"), original).unwrap();
            session.recipe.phases[0].baseline.insert(
                PathBuf::from("main.c"),
                fingerprint(&local.join("main.c")).unwrap().unwrap(),
            );
            std::fs::create_dir(stage.join("build")).unwrap();
            std::fs::write(stage.join("build/app"), b"valid artifact").unwrap();
            let retained = if pending {
                let temporary = local.join(format!(".rch-return-{}", session.recipe.identity));
                std::fs::write(&temporary, remote).unwrap();
                session.recipe.phases[0].pending = Some((
                    PathBuf::from("main.c"),
                    fingerprint(&temporary).unwrap().unwrap(),
                ));
                temporary
            } else {
                let retained = stage.join("main.c");
                std::fs::write(&retained, remote).unwrap();
                retained
            };
            session.persist().unwrap();
            let journal = std::fs::read(&session.writer.path).unwrap();

            let published = session.publish("project").await;
            // Source is never overwritten.
            assert_eq!(std::fs::read(local.join("main.c")).unwrap(), original);
            if pending {
                // The refused publication keeps its journaled copy for a retry.
                assert_eq!(std::fs::read(&retained).unwrap(), remote);
                // An interrupted write of an out-of-policy path cannot be
                // finished or skipped: refuse before any write.
                assert!(published.is_err());
                assert!(!local.join("build/app").exists());
                assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal);
                assert!(session.recipe.phases[0].published.is_empty());
            } else {
                // A retained out-of-policy file is skipped, not fatal: the
                // job's real outputs still publish, so recovery can retire
                // and release the worker-side source claim.
                published.unwrap();
                assert_eq!(
                    std::fs::read(local.join("build/app")).unwrap(),
                    b"valid artifact"
                );
                assert!(
                    !session.recipe.phases[0]
                        .published
                        .contains_key(&PathBuf::from("main.c"))
                );
                // Completion drops the stage, retained copy included; it was
                // never published and nothing reads it again.
                assert!(!stage.exists());
            }
        }
    }

    #[tokio::test]
    async fn publication_overwrites_outputs_another_job_replaced_after_preparation() {
        // Dispatchers share one CARGO_TARGET_DIR: between this job's
        // preparation snapshot and its publication, another job may replace
        // the same output. That is not an ownership conflict; publishing must
        // re-baseline under the publication lock and write, not refuse.
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        std::fs::create_dir(local.join("build")).unwrap();
        std::fs::write(local.join("build/app"), b"snapshot at preparation").unwrap();
        session.recipe.phases[0].baseline.insert(
            PathBuf::from("build/app"),
            fingerprint(&local.join("build/app")).unwrap().unwrap(),
        );
        std::fs::write(local.join("build/app"), b"written by a concurrent job").unwrap();
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"this job's output").unwrap();
        session.persist().unwrap();

        session.publish("project").await.unwrap();
        assert_eq!(
            std::fs::read(local.join("build/app")).unwrap(),
            b"this job's output"
        );
        assert!(session.recipe.phases[0].complete);
        assert!(
            !stage.exists(),
            "a completed publication must not keep its duplicate stage"
        );
    }

    /// The output root may sit behind system symlinks (macOS `/tmp`, `/var`,
    /// a symlinked `/data`): publication must accept that root, while a
    /// symlink BELOW it, which could redirect a write, is still refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn publication_accepts_symlinked_root_but_refuses_symlinks_inside_it() {
        let (directory, _stage_owner, mut session) = publication_fixture();
        let real = directory.path().join("real-target");
        std::fs::create_dir(&real).unwrap();
        let link = directory.path().join("linked-target");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        session.recipe.phases[0].local = link;
        let stage = session.stage(0);
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"output").unwrap();
        session.persist().unwrap();
        session.publish("project").await.unwrap();
        assert_eq!(std::fs::read(real.join("build/app")).unwrap(), b"output");

        let (directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let elsewhere = directory.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, local.join("build")).unwrap();
        let stage = session.stage(0);
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"output").unwrap();
        session.persist().unwrap();
        assert!(session.publish("project").await.is_err());
        assert!(!elsewhere.join("app").exists());
    }

    #[tokio::test]
    async fn publication_lock_is_released_between_publications() {
        let (_directory, _stage_owner, session) = publication_fixture();
        let root = session.recipe.project_root.clone();
        let first = lock_output_root(&root).await.unwrap();
        drop(first);
        // A second wrapper can publish into the same root once the first is done.
        let _second = lock_output_root(&root).await.unwrap();
    }

    /// Keep a real kernel lock held independently of the Tokio reactor. The
    /// watchdog makes a regression to a blocking wait fail in seconds instead
    /// of hanging the test for the production ten-minute publication budget.
    fn hold_publication_lock(
        lock: File,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (release, released) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _ = released.recv_timeout(Duration::from_secs(2));
            drop(lock);
        });
        (release, holder)
    }

    #[cfg(unix)]
    #[test]
    fn publication_identity_resolves_symlinks_before_parent_components_without_creating_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        std::fs::create_dir_all(real.join("nested")).unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(real.join("nested"), &alias).unwrap();
        let expected = std::fs::canonicalize(&real).unwrap().join("target");
        for path in [
            real.join("target"),
            alias.join("../target"),
            alias.join("missing/../../target"),
        ] {
            assert_eq!(output_lock_root_identity(&path).unwrap(), expected);
        }
        assert!(!real.join("target").exists());
        assert!(!real.join("nested/missing").exists());

        let dangling = directory.path().join("dangling");
        std::os::unix::fs::symlink(directory.path().join("absent"), &dangling).unwrap();
        assert!(output_lock_root_identity(&dangling.join("target")).is_err());
        std::fs::write(real.join("file"), b"not a directory").unwrap();
        assert!(output_lock_root_identity(&real.join("file/../target")).is_err());
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn symlinked_and_canonical_output_roots_share_publication_ownership() {
        let (directory, _stage_owner, session) = publication_fixture();
        let root = session.recipe.project_root.clone();
        let alias = directory.path().join("output-alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        let lock = lock_output_root(&root).await.unwrap();
        let (release, holder) = hold_publication_lock(lock);
        let alias_lock =
            tokio::time::timeout(Duration::from_millis(25), lock_output_root(&alias)).await;
        let _ = release.send(());
        holder.join().unwrap();
        assert!(
            alias_lock.is_err(),
            "path alias bypassed the existing publication owner"
        );
        let _after_release = lock_output_root(&alias).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn missing_output_root_keeps_its_lock_when_another_job_creates_the_directory() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let root = real.join("new-target/profile");
        let aliased_root = alias.join("new-target/profile");
        let lock = lock_output_root(&aliased_root).await.unwrap();
        assert!(
            !root.exists(),
            "lock discovery created the caller's output tree"
        );
        let (release, holder) = hold_publication_lock(lock);
        std::fs::create_dir_all(&root).unwrap();
        let created_lock =
            tokio::time::timeout(Duration::from_millis(25), lock_output_root(&root)).await;
        let _ = release.send(());
        holder.join().unwrap();
        assert!(
            created_lock.is_err(),
            "creating the output tree changed its ownership identity"
        );
        let _after_release = lock_output_root(&root).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn retargeted_output_alias_refuses_publication_and_retains_the_journal() {
        let (directory, _stage_owner, mut session) = publication_fixture();
        let original = session.recipe.project_root.clone();
        let replacement = directory.path().join("other-output");
        std::fs::create_dir(&replacement).unwrap();
        let alias = directory.path().join("output-alias");
        std::os::unix::fs::symlink(&original, &alias).unwrap();
        session.recipe.phases[0].local = alias.clone();
        let stage = session.stage(0);
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"completed remote output").unwrap();
        session.persist().unwrap();
        let before = std::fs::read(&session.writer.path).unwrap();
        let lock = lock_output_root(&original).await.unwrap();
        let (release, holder) = hold_publication_lock(lock);
        let mut publication = Box::pin(session.publish("project"));
        // Borrow the future so the first deadline leaves its original lock
        // identity pending, then retarget the alias before ownership arrives.
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut publication)
                .await
                .is_err()
        );
        std::fs::rename(&alias, directory.path().join("previous-output-alias")).unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        let _ = release.send(());
        holder.join().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), publication)
            .await
            .expect("publication did not resume after its original owner released the lock")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("output root changed while waiting")
        );
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        assert!(!original.join("build/app").exists());
        assert!(!replacement.join("build/app").exists());
        assert_eq!(
            std::fs::read(stage.join("build/app")).unwrap(),
            b"completed remote output"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn publication_deadline_keeps_staged_outputs_and_journal_for_same_job_retry() {
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        std::fs::create_dir(local.join("build")).unwrap();
        std::fs::write(local.join("build/app"), b"previous output").unwrap();
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/app"), b"completed remote output").unwrap();
        session.persist().unwrap();
        let before = std::fs::read(&session.writer.path).unwrap();
        let lock = lock_output_root(&local).await.unwrap();
        let (release, holder) = hold_publication_lock(lock);

        // This is the same cancellation boundary as jobs recover's deadline:
        // dropping the wait must not begin publication or retire ownership.
        let publication =
            tokio::time::timeout(Duration::from_millis(25), session.publish("project")).await;
        let _ = release.send(());
        holder.join().unwrap();
        assert!(
            publication.is_err(),
            "contended publication blocked its caller's deadline"
        );
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
        assert_eq!(
            std::fs::read(local.join("build/app")).unwrap(),
            b"previous output"
        );
        assert_eq!(
            std::fs::read(stage.join("build/app")).unwrap(),
            b"completed remote output"
        );
        assert!(!session.recipe.phases[0].complete);
        assert!(session.recipe.phases[0].pending.is_none());
        assert!(session.recipe.phases[0].published.is_empty());
        assert!(!session.recipe.sources_released);

        // Resume from the retained disk journal, not the cancelled future's
        // in-memory session. Only the already-staged bytes are published.
        let writer = DurableLeaseWriter {
            path: session.writer.path.clone(),
            recovery_ownership: None,
            lease: Arc::new(Mutex::new(serde_json::from_slice(&before).unwrap())),
        };
        let mut resumed = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer,
        };
        resumed.publish("project").await.unwrap();
        assert_eq!(
            std::fs::read(local.join("build/app")).unwrap(),
            b"completed remote output"
        );
        assert!(resumed.recipe.phases[0].complete);
        assert!(!stage.exists());
        assert_eq!(resumed.recipe.wrapper_id, session.recipe.wrapper_id);
        assert_eq!(resumed.recipe.build_id, session.recipe.build_id);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_root_publishers_wait_without_stalling_runtime_progress() {
        let (_first_dir, _first_stage_owner, mut first) = publication_fixture();
        let (_second_dir, _second_stage_owner, mut second) = publication_fixture();
        let local = first.recipe.project_root.clone();
        second.recipe.phases[0].local = local.clone();
        std::fs::create_dir(local.join("build")).unwrap();
        std::fs::write(local.join("build/app"), b"before both jobs").unwrap();
        for (session, name, bytes) in [
            (&mut first, "first.o", b"first job".as_slice()),
            (&mut second, "second.o", b"second job".as_slice()),
        ] {
            let stage = session.stage(0);
            std::fs::create_dir(stage.join("build")).unwrap();
            std::fs::write(stage.join("build/app"), bytes).unwrap();
            std::fs::write(stage.join("build").join(name), bytes).unwrap();
            session.persist().unwrap();
        }
        let lock = lock_output_root(&local).await.unwrap();
        let (release, holder) = hold_publication_lock(lock);
        let publications = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(first.publish("project"), second.publish("project"), async {
                // A heartbeat/recovery timer must still run while both jobs
                // wait. Neither may touch the shared output before ownership.
                tokio::time::sleep(Duration::from_millis(25)).await;
                assert_eq!(
                    std::fs::read(local.join("build/app")).unwrap(),
                    b"before both jobs"
                );
                release.send(()).unwrap();
            })
        })
        .await;
        drop(release);
        holder.join().unwrap();
        let (first_result, second_result, ()) = publications
            .expect("contended publication prevented the timer from releasing its owner");
        first_result.unwrap();
        second_result.unwrap();
        assert!(first.recipe.phases[0].complete);
        assert!(second.recipe.phases[0].complete);
        assert_eq!(
            std::fs::read(local.join("build/first.o")).unwrap(),
            b"first job"
        );
        assert_eq!(
            std::fs::read(local.join("build/second.o")).unwrap(),
            b"second job"
        );
        let final_output = std::fs::read(local.join("build/app")).unwrap();
        assert!(matches!(
            final_output.as_slice(),
            b"first job" | b"second job"
        ));
        assert!(!first.stage(0).exists());
        assert!(!second.stage(0).exists());
    }

    #[tokio::test]
    async fn recovery_publication_finishes_journaled_new_outputs_without_rewriting_them() {
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        for (path, bytes) in [("a.out", b"first output"), ("b.out", b"other output")] {
            std::fs::write(local.join(path), bytes).unwrap();
            std::fs::write(stage.join(path), b"stale retained staging bytes").unwrap();
        }
        let first = fingerprint(&local.join("a.out")).unwrap().unwrap();
        session.recipe.phases[0].pending = Some((PathBuf::from("a.out"), first.clone()));
        session.recipe.phases[0].published.insert(
            PathBuf::from("b.out"),
            fingerprint(&local.join("b.out")).unwrap().unwrap(),
        );
        std::fs::create_dir(stage.join("build")).unwrap();
        std::fs::write(stage.join("build/next.o"), b"next output").unwrap();
        session.persist().unwrap();

        session.publish("project").await.unwrap();
        assert_eq!(std::fs::read(local.join("a.out")).unwrap(), b"first output");
        assert_eq!(std::fs::read(local.join("b.out")).unwrap(), b"other output");
        assert_eq!(
            std::fs::read(local.join("build/next.o")).unwrap(),
            b"next output"
        );
        assert_eq!(session.recipe.phases[0].published.len(), 3);
        assert_eq!(
            session.recipe.phases[0].published[Path::new("a.out")],
            first
        );
        assert!(session.recipe.phases[0].pending.is_none());
        assert!(session.recipe.phases[0].complete);
    }

    #[tokio::test]
    async fn recovery_publication_retains_declared_result_directory_contract() {
        let (_directory, _stage_owner, mut session) = publication_fixture();
        let local = session.recipe.project_root.clone();
        let stage = session.stage(0);
        std::fs::create_dir(local.join("reports")).unwrap();
        std::fs::create_dir(stage.join("reports")).unwrap();
        std::fs::write(local.join("reports/result.json"), b"old report").unwrap();
        std::fs::write(stage.join("reports/result.json"), b"new report").unwrap();
        session.recipe.phases[0].patterns.clear();
        session.recipe.phases[0].result_dir = Some(PathBuf::from("reports"));
        session.recipe.phases[0].baseline.insert(
            PathBuf::from("reports/result.json"),
            fingerprint(&local.join("reports/result.json"))
                .unwrap()
                .unwrap(),
        );
        session.persist().unwrap();

        session.publish("project").await.unwrap();
        assert_eq!(
            std::fs::read(local.join("reports/result.json")).unwrap(),
            b"new report"
        );
        assert!(session.recipe.phases[0].complete);
    }

    #[test]
    fn retained_source_intent_binds_siblings_pair_and_authority_before_journaling() {
        let _guard = test_guard!();
        for case in [
            "different-sibling",
            "missing-original-authority",
            "missing-retained-authority",
            "missing-pair",
            "different-pair-root",
            "different-pair-token",
            "missing-original-root",
            "noncanonical-identity",
        ] {
            let (directory, writer, worker) = admitted_preparation_fixture();
            let directory = directory.keep();
            let root = "/data/tmp/rch/source-content-pair-recovery".to_owned();
            let mut identity = "0123456789abcdef0123456789abcdef".to_owned();
            let mut retained = format!("{root}.retained-{identity}");
            let mut roots = vec![root.clone(), retained.clone()];
            let mut pair = Some((root.clone(), identity.clone()));
            let mut retire_root = Some(root.clone());
            match case {
                "different-sibling" => {
                    retained = format!("{root}.retained-1123456789abcdef0123456789abcdef");
                    roots[1] = retained.clone();
                }
                "missing-original-authority" => roots = vec![retained.clone()],
                "missing-retained-authority" => roots = vec![root.clone()],
                "missing-pair" => pair = None,
                "different-pair-root" => {
                    pair = Some((format!("{root}-other"), identity.clone()));
                }
                "different-pair-token" => {
                    pair = Some((root.clone(), "1123456789abcdef0123456789abcdef".into()));
                }
                "missing-original-root" => retire_root = None,
                "noncanonical-identity" => {
                    identity = "ABCDEF0123456789ABCDEF0123456789".into();
                    retained = format!("{root}.retained-{identity}");
                    roots[1] = retained.clone();
                    pair = Some((root.clone(), identity.clone()));
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(&writer.path).unwrap();
            let result = RecoverySession::begin(
                &writer,
                &worker,
                roots,
                pair,
                retire_root,
                Some(retained),
                TransferConfig::default(),
                directory,
                identity,
            );
            assert!(result.is_err(), "admitted invalid retained intent: {case}");
            assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{case}");
            assert!(writer.snapshot().recovery.is_none(), "{case}");
            assert_eq!(writer.snapshot().identity.remote_build_id, Some(41));
        }
    }

    #[test]
    fn retained_source_prepare_cannot_drop_or_change_the_admitted_destination() {
        let _guard = test_guard!();
        let (directory, writer, worker) = retained_preparation_fixture();
        let intent = load_recipe(&writer).unwrap();
        let pipeline = TransferPipeline::new(
            directory.clone(),
            "retained-recovery".into(),
            intent.identity.clone(),
            intent.transfer.clone(),
        )
        .with_remote_path_override(format!(
            "{}/projects/app",
            intent.retire_root.as_deref().unwrap()
        ));
        let before = std::fs::read(&writer.path).unwrap();
        for changed in [
            None,
            Some(format!(
                "{}-other",
                intent.retained_root.as_deref().unwrap()
            )),
        ] {
            let result = RecoverySession::prepare(
                &writer,
                &worker,
                &pipeline,
                intent.source_roots.clone(),
                intent.pair.clone(),
                intent.retire_root.clone(),
                changed,
                intent.transfer.clone(),
                directory.clone(),
                None,
                Some(CompilationKind::CargoBuild),
                "cargo build",
                &[],
                intent.identity.clone(),
            );
            assert!(
                result.is_err(),
                "preparation replaced retained-source authority"
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        }
        let session = RecoverySession::prepare(
            &writer,
            &worker,
            &pipeline,
            intent.source_roots.clone(),
            intent.pair.clone(),
            intent.retire_root.clone(),
            intent.retained_root.clone(),
            intent.transfer.clone(),
            directory,
            None,
            Some(CompilationKind::CargoBuild),
            "cargo build",
            &[],
            intent.identity.clone(),
        )
        .unwrap();
        let persisted = reload_publication(&session).recipe;
        assert!(persisted.prepared);
        assert_eq!(persisted.retained_root, intent.retained_root);
        assert_eq!(persisted.retire_root, intent.retire_root);
        assert_eq!(persisted.pair, intent.pair);
        assert_eq!(persisted.source_roots, intent.source_roots);
        assert_eq!(persisted.retained_materialized, None);
        assert!(!persisted.tree_retired);
        assert!(!persisted.execution_started);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pending_publication_refuses_redirected_descendants_before_any_shortcut() {
        use std::os::unix::fs::symlink;
        let _guard = test_guard!();
        for already_published in [false, true] {
            let (directory, _stages, mut session) = publication_fixture();
            let local = session.recipe.phases[0].local.clone();
            let outside = directory.path().join("outside-phase");
            std::fs::create_dir(&outside).unwrap();
            symlink(&outside, local.join("build")).unwrap();
            let relative = PathBuf::from("build/app");
            let destination = outside.join("app");
            let temporary = outside.join(format!(".rch-return-{}", session.recipe.identity));
            let original = if already_published {
                &b"pending bytes"[..]
            } else {
                &b"prior outside bytes"[..]
            };
            std::fs::write(&destination, original).unwrap();
            std::fs::write(&temporary, b"pending bytes").unwrap();
            let hash = fingerprint(&temporary).unwrap().unwrap();
            let phase = &mut session.recipe.phases[0];
            if !already_published {
                phase.baseline.insert(
                    relative.clone(),
                    fingerprint(&destination).unwrap().unwrap(),
                );
            }
            phase.pending = Some((relative.clone(), hash));
            session.persist().unwrap();
            let recipe_before = serde_json::to_value(&session.recipe).unwrap();
            let lease_before = session.writer.snapshot();
            let journal_before = std::fs::read(&session.writer.path).unwrap();
            assert!(session.publish("project").await.is_err());
            assert_eq!(
                serde_json::to_value(&session.recipe).unwrap(),
                recipe_before
            );
            assert_eq!(session.writer.snapshot(), lease_before);
            assert_eq!(std::fs::read(&session.writer.path).unwrap(), journal_before);
            assert_eq!(std::fs::read(&destination).unwrap(), original);
            assert_eq!(std::fs::read(&temporary).unwrap(), b"pending bytes");
            assert!(!session.recipe.phases[0].complete);
            assert!(session.recipe.phases[0].pending.is_some());
            assert!(session.recipe.phases[0].published.is_empty());
            let alias = directory.path().join("caller-root-alias");
            symlink(&local, &alias).unwrap();
            std::fs::create_dir(local.join("real-directory")).unwrap();
            validate_output_ancestors(&alias, Path::new("real-directory/app")).unwrap();
            for escaped in [Path::new("../outside-phase/app"), destination.as_path()] {
                assert!(validate_output_ancestors(&local, escaped).is_err());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn prepared_output_refuses_same_inode_rewrites_and_growth_without_moving_its_cursor() {
        use std::io::Seek;
        use std::os::unix::fs::{FileExt, MetadataExt};
        let _guard = test_guard!();
        for reuse in [false, true] {
            for mutation in ["byte", "growth"] {
                let directory = tempfile::Builder::new()
                    .disable_cleanup(true)
                    .tempdir()
                    .unwrap();
                let source = directory.path().join("source");
                let temporary = directory.path().join("prepared-copy");
                let destination = directory.path().join("destination");
                let original = b"staged executable bytes";
                std::fs::write(&source, original).unwrap();
                std::fs::write(&destination, b"prior destination bytes").unwrap();
                let hash = fingerprint(&source).unwrap().unwrap();
                let first = prepare_output_temporary(&source, &temporary, &hash).unwrap();
                let prepared = if reuse {
                    prepare_output_temporary(&source, &temporary, &hash).unwrap()
                } else {
                    first
                };
                let metadata = prepared.file.metadata().unwrap();
                let mut cursor = prepared.file.try_clone().unwrap();
                let original_position = cursor.stream_position().unwrap();
                prepared.verify_content().unwrap();
                assert_eq!(cursor.stream_position().unwrap(), original_position);
                let rewrite = OpenOptions::new().write(true).open(&temporary).unwrap();
                let offset = if mutation == "byte" {
                    0
                } else {
                    metadata.len()
                };
                assert_eq!(rewrite.write_at(b"X", offset).unwrap(), 1);
                rewrite.sync_all().unwrap();
                assert_eq!(rewrite.metadata().unwrap().ino(), metadata.ino());
                assert_eq!(rewrite.metadata().unwrap().nlink(), metadata.nlink());
                assert_eq!(rewrite.metadata().unwrap().mode(), metadata.mode());
                assert!(prepared.publish(&destination).is_err());
                assert_eq!(
                    std::fs::read(&destination).unwrap(),
                    b"prior destination bytes"
                );
                assert_eq!(std::fs::read(&source).unwrap(), original);
                let changed = std::fs::read(&temporary).unwrap();
                if mutation == "byte" {
                    assert_eq!(changed.len(), original.len());
                    assert_eq!(changed[0], b'X');
                    assert_eq!(&changed[1..], &original[1..]);
                } else {
                    assert_eq!(&changed[..original.len()], original);
                    assert_eq!(changed[original.len()], b'X');
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn output_temporary_reuses_complete_copies_and_preserves_conflicting_evidence() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        let _guard = test_guard!();
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let source = directory.path().join("source");
        let temporary = directory.path().join("complete-copy");
        let bytes = b"staged executable bytes";
        std::fs::write(&source, bytes).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hash = fingerprint(&source).unwrap().unwrap();
        prepare_output_temporary(&source, &temporary, &hash).unwrap();
        let inode = std::fs::metadata(&temporary).unwrap().ino();
        assert_eq!(std::fs::read(&temporary).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&temporary).unwrap().mode() & 0o7777,
            0o755
        );
        let prepared = prepare_output_temporary(&source, &temporary, &hash).unwrap();
        assert_eq!(std::fs::metadata(&temporary).unwrap().ino(), inode);
        assert_eq!(std::fs::read(&temporary).unwrap(), bytes);
        for (name, original) in [("conflict", &b"other bytes"[..]), ("partial", &b""[..])] {
            let conflict = directory.path().join(name);
            std::fs::write(&conflict, original).unwrap();
            std::fs::set_permissions(&conflict, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(prepare_output_temporary(&source, &conflict, &hash).is_err());
            assert_eq!(std::fs::read(&conflict).unwrap(), original);
        }
        let link = directory.path().join("additional-copy-link");
        std::fs::hard_link(&temporary, &link).unwrap();
        let destination = directory.path().join("prior-destination");
        std::fs::write(&destination, b"prior destination bytes").unwrap();
        // Mutation AFTER preparation must invalidate actual publication too.
        // Preserve both original names and all bytes; no gate move or mock.
        assert!(prepared.publish(&destination).is_err());
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"prior destination bytes"
        );
        assert!(prepare_output_temporary(&source, &temporary, &hash).is_err());
        assert_eq!(std::fs::read(&temporary).unwrap(), bytes);
        assert_eq!(std::fs::read(&link).unwrap(), bytes);
        let redirect = directory.path().join("redirect-copy");
        symlink(&source, &redirect).unwrap();
        assert!(prepare_output_temporary(&source, &redirect, &hash).is_err());
        assert!(
            std::fs::symlink_metadata(&redirect)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let wrong_mode = directory.path().join("wrong-mode-copy");
        std::fs::write(&wrong_mode, bytes).unwrap();
        std::fs::set_permissions(&wrong_mode, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(prepare_output_temporary(&source, &wrong_mode, &hash).is_err());
        assert_eq!(std::fs::read(&wrong_mode).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&wrong_mode).unwrap().mode() & 0o7777,
            0o644
        );
        let publish_copy = directory.path().join("publish-copy");
        let published = directory.path().join("published-copy");
        let prepared = prepare_output_temporary(&source, &publish_copy, &hash).unwrap();
        let held_inode = prepared.file.metadata().unwrap().ino();
        prepared.publish(&published).unwrap();
        assert_eq!(std::fs::read(&published).unwrap(), bytes);
        assert_eq!(std::fs::metadata(&published).unwrap().ino(), held_inode);
        assert_eq!(
            std::fs::metadata(&published).unwrap().mode() & 0o7777,
            0o755
        );
        assert!(!publish_copy.exists());
        assert_eq!(std::fs::read(&source).unwrap(), bytes);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn output_checkpoints_restore_the_durable_epoch_on_publication_failure() {
        let _guard = test_guard!();
        for checkpoint in ["pending", "published-new", "published-existing", "baseline"] {
            for refuse_publication in [false, true] {
                let (directory, stages, mut session) = publication_fixture();
                let directory = directory.keep();
                let _stages = stages.keep();
                let local = session.recipe.phases[0].local.clone();
                let relative = PathBuf::from("build/app");
                let added = PathBuf::from("build/added");
                let absent = PathBuf::from("build/absent");
                let skip = PathBuf::from("build/published");
                std::fs::create_dir(local.join("build")).unwrap();
                std::fs::write(local.join(&relative), b"current app").unwrap();
                std::fs::write(local.join(&added), b"current addition").unwrap();
                std::fs::write(local.join(&skip), b"another job's later output").unwrap();
                let hash = fingerprint(&local.join(&relative)).unwrap().unwrap();
                let added_hash = fingerprint(&local.join(&added)).unwrap().unwrap();
                let phase = &mut session.recipe.phases[0];
                phase
                    .baseline
                    .insert(relative.clone(), "old baseline".into());
                phase
                    .baseline
                    .insert(absent.clone(), "absent baseline".into());
                phase
                    .baseline
                    .insert(skip.clone(), "published baseline".into());
                phase
                    .published
                    .insert(skip.clone(), "already published".into());
                phase.pending = Some((relative.clone(), "previous pending".into()));
                if checkpoint == "published-existing" {
                    phase
                        .published
                        .insert(relative.clone(), "previous published".into());
                }
                session.persist().unwrap();
                // Claim the actual journal after a real local owner exits.
                // The inputs above model checkpoints, not a compiler result.
                let mut owner = std::process::Command::new("sh")
                    .args(["-c", "exit 0"])
                    .spawn()
                    .unwrap();
                let owner_pid = owner.id();
                assert!(owner.wait().unwrap().success());
                {
                    let mut lease = session.writer.lease.lock().unwrap();
                    lease.wrapper_pid = owner_pid;
                    lease.process_start_ticks = None;
                    lease.boot_id = None;
                    lease.process_birth = None;
                }
                session.writer.persist().unwrap();
                session.writer = recovery_owner::claim(&session.writer).await.unwrap();
                let original_recipe = serde_json::to_value(&session.recipe).unwrap();
                let original_lease = session.writer.snapshot();
                let original_bytes = std::fs::read(&session.writer.path).unwrap();
                let gate = session.writer.path.with_extension("recovery.lock");
                let gate_alias = directory.join("additional-output-checkpoint-link.lock");
                if refuse_publication {
                    std::fs::hard_link(&gate, &gate_alias).unwrap();
                }
                let result = match checkpoint {
                    "pending" => {
                        session.persist_pending_output(0, Some((added.clone(), added_hash.clone())))
                    }
                    "published-new" | "published-existing" => {
                        session.persist_published_output(0, relative.clone(), hash.clone())
                    }
                    "baseline" => session.persist_output_baseline(
                        0,
                        &[
                            relative.clone(),
                            added.clone(),
                            absent.clone(),
                            skip.clone(),
                        ],
                    ),
                    _ => unreachable!(),
                };
                if refuse_publication {
                    assert!(result.is_err(), "{checkpoint}: refused gate was accepted");
                    assert_eq!(
                        serde_json::to_value(&session.recipe).unwrap(),
                        original_recipe
                    );
                    assert_eq!(session.writer.snapshot(), original_lease);
                    assert_eq!(std::fs::read(&session.writer.path).unwrap(), original_bytes);
                    assert!(gate_alias.is_file() && gate.is_file());
                } else {
                    result.unwrap();
                    assert_eq!(
                        serde_json::to_value(load_recipe(&session.writer).unwrap()).unwrap(),
                        serde_json::to_value(&session.recipe).unwrap()
                    );
                    let phase = &session.recipe.phases[0];
                    match checkpoint {
                        "pending" => {
                            assert_eq!(phase.pending, Some((added.clone(), added_hash.clone())))
                        }
                        "published-new" | "published-existing" => {
                            assert_eq!(phase.published.get(&relative), Some(&hash));
                            assert!(phase.pending.is_none());
                        }
                        "baseline" => {
                            assert_eq!(phase.baseline.get(&relative), Some(&hash));
                            assert_eq!(phase.baseline.get(&added), Some(&added_hash));
                            assert!(!phase.baseline.contains_key(&absent));
                            assert_eq!(phase.baseline.get(&skip).unwrap(), "published baseline");
                        }
                        _ => unreachable!(),
                    }
                }
                assert_eq!(
                    std::fs::read(local.join(&relative)).unwrap(),
                    b"current app"
                );
                assert_eq!(
                    std::fs::read(local.join(&added)).unwrap(),
                    b"current addition"
                );
                assert_eq!(
                    std::fs::read(local.join(&skip)).unwrap(),
                    b"another job's later output"
                );
            }
        }
    }

    #[test]
    fn baseline_inspection_failure_preserves_all_prior_entries() {
        let _guard = test_guard!();
        let (_directory, _stages, mut session) = publication_fixture();
        let local = session.recipe.phases[0].local.clone();
        let first = PathBuf::from("build/first");
        let invalid = PathBuf::from("build/directory");
        std::fs::create_dir_all(local.join(&invalid)).unwrap();
        std::fs::write(local.join(&first), b"later output").unwrap();
        session.recipe.phases[0]
            .baseline
            .insert(first.clone(), "prior baseline".into());
        session.persist().unwrap();
        let original_recipe = serde_json::to_value(&session.recipe).unwrap();
        let original_lease = session.writer.snapshot();
        let original_bytes = std::fs::read(&session.writer.path).unwrap();
        assert!(
            session
                .persist_output_baseline(0, &[first.clone(), invalid.clone()])
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(&session.recipe).unwrap(),
            original_recipe
        );
        assert_eq!(session.writer.snapshot(), original_lease);
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), original_bytes);
        assert_eq!(std::fs::read(local.join(&first)).unwrap(), b"later output");
        assert!(local.join(&invalid).is_dir());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn lifecycle_publication_keeps_session_and_journal_in_one_epoch_on_failure() {
        let _guard = test_guard!();
        for transition in [
            "execution",
            "completed",
            "returned",
            "retained-tree",
            "absent-tree",
            "pair",
            "sources",
            "retired",
        ] {
            for refuse_publication in [false, true] {
                let (directory, writer, _worker) = retained_preparation_fixture();
                // Use a genuinely exited local owner, not a fabricated owner
                // inspection result or a substitute publication function.
                let mut owner = std::process::Command::new("sh")
                    .args(["-c", "exit 0"])
                    .spawn()
                    .unwrap();
                let owner_pid = owner.id();
                assert!(owner.wait().unwrap().success());
                {
                    let mut lease = writer.lease.lock().unwrap();
                    lease.wrapper_pid = owner_pid;
                    lease.process_start_ticks = None;
                    lease.boot_id = None;
                    lease.process_birth = None;
                }
                writer.persist().unwrap();
                let writer = recovery_owner::claim(&writer).await.unwrap();
                let mut session = RecoverySession {
                    recipe: load_recipe(&writer).unwrap(),
                    writer: writer.clone(),
                };
                // These remote lifecycle flags are unit inputs only. No
                // compiler, SDK, remote source rename or slot release ran.
                session.recipe.prepared = true;
                session.recipe.execution_started =
                    transition != "execution" && transition != "absent-tree";
                if !matches!(transition, "execution" | "completed" | "absent-tree") {
                    session.recipe.exit_code = Some(7);
                }
                if matches!(transition, "pair" | "sources" | "retired") {
                    session.recipe.returned = Some(7);
                    session.recipe.tree_retired = true;
                    session.recipe.retained_materialized = Some(true);
                }
                session.recipe.pair_released = matches!(transition, "sources" | "retired");
                session.recipe.sources_released = transition == "retired";
                session.recipe.preparation_cancelled = transition == "absent-tree";
                session.persist().unwrap();
                let original_recipe = serde_json::to_value(&session.recipe).unwrap();
                let original_lease = writer.snapshot();
                let original_bytes = std::fs::read(&writer.path).unwrap();
                let gate = writer.path.with_extension("recovery.lock");
                let gate_alias = directory.join("additional-recovery-link.lock");
                if refuse_publication {
                    // Preserve the original path and bytes. A second actual
                    // link invalidates the existing publisher's single-link
                    // ownership fence, without moving or replacing the gate.
                    std::fs::hard_link(&gate, &gate_alias).unwrap();
                }
                let result = match transition {
                    "execution" => session.starting_execution(),
                    "completed" => session.completed(7),
                    "returned" => session.returned(7),
                    "retained-tree" => session.persist_tree_retirement(Some(true)),
                    "absent-tree" => session.persist_tree_retirement(Some(false)),
                    "pair" => session.pair_released(),
                    "sources" => session.sources_released(),
                    "retired" => session.retired(),
                    _ => unreachable!(),
                };
                if refuse_publication {
                    assert!(result.is_err(), "{transition}: refused gate was accepted");
                    assert_eq!(
                        serde_json::to_value(&session.recipe).unwrap(),
                        original_recipe,
                        "{transition}"
                    );
                    assert_eq!(writer.snapshot(), original_lease, "{transition}");
                    assert_eq!(
                        std::fs::read(&writer.path).unwrap(),
                        original_bytes,
                        "{transition}"
                    );
                    assert!(gate_alias.is_file() && gate.is_file());
                    if transition == "retired" {
                        // A failed write must not permit the actual retry's
                        // retired shortcut to return success. All remote
                        // release flags above are already true, so this
                        // reaches local publication without worker contact.
                        assert!(session.retire_returned().await.is_err());
                        assert_eq!(std::fs::read(&writer.path).unwrap(), original_bytes);
                    }
                } else {
                    assert!(result.is_ok(), "{transition}: {result:?}");
                    let recovered = load_recipe(&writer).unwrap();
                    assert_eq!(
                        serde_json::to_value(recovered).unwrap(),
                        serde_json::to_value(&session.recipe).unwrap()
                    );
                    assert_ne!(
                        serde_json::to_value(&session.recipe).unwrap(),
                        original_recipe
                    );
                    match transition {
                        "execution" => assert!(session.recipe.execution_started),
                        "completed" => assert_eq!(session.recipe.exit_code, Some(7)),
                        "returned" => assert_eq!(session.recipe.returned, Some(7)),
                        "retained-tree" | "absent-tree" => {
                            assert!(session.recipe.tree_retired);
                            assert_eq!(
                                session.recipe.retained_materialized,
                                Some(transition == "retained-tree")
                            );
                        }
                        "pair" => assert!(session.recipe.pair_released),
                        "sources" => assert!(session.recipe.sources_released),
                        "retired" => {
                            assert!(session.recipe.retired);
                            session.retire_returned().await.unwrap();
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    #[test]
    fn retained_source_tree_retirement_requires_an_acknowledged_filesystem_outcome() {
        let _guard = test_guard!();
        let (_directory, writer, _worker) = retained_preparation_fixture();
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer: writer.clone(),
        };
        let before = std::fs::read(&writer.path).unwrap();
        assert!(session.tree_retired().is_err());
        assert!(!session.recipe.tree_retired);
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        session.recipe.retained_materialized = Some(false);
        assert!(session.tree_retired().is_err());
        assert!(!session.recipe.tree_retired);
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        assert!(writer.ensure_released_for_retry().is_err());
    }

    #[tokio::test]
    async fn retained_source_retirement_releases_a_successful_stage_and_keeps_a_failed_one() {
        let _guard = test_guard!();
        for command_exit in [0, 7] {
            let (directory, writer, worker) = admitted_preparation_fixture();
            let directory = directory.keep();
            let identity = uuid::Uuid::new_v4().simple().to_string();
            let remote = format!("/data/tmp/rch/retained-lifecycle-{identity}");
            let retained = format!("{remote}.retained-{identity}");
            RecoverySession::begin(
                &writer,
                &worker,
                vec![remote.clone(), retained.clone()],
                Some((remote.clone(), identity.clone())),
                Some(remote),
                Some(retained),
                TransferConfig::default(),
                directory.clone(),
                identity,
            )
            .unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&writer).unwrap(),
                writer: writer.clone(),
            };
            let local = directory.join("caller-outputs");
            std::fs::create_dir(&local).unwrap();
            session.recipe.project_root = local.clone();
            session.recipe.phases.push(RecoveryPhase {
                name: "project".into(),
                local: local.clone(),
                remote: "/unused/remote-output".into(),
                patterns: default_c_cpp_artifact_patterns(),
                result_dir: None,
                custom_target: false,
                output_gate: false,
                cargo_outputs: None,
                native_outputs: None,
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: false,
                missing_result: None,
            });
            let stage = session.stage(0);
            std::fs::create_dir_all(stage.parent().unwrap().parent().unwrap()).unwrap();
            std::fs::create_dir(stage.parent().unwrap()).unwrap();
            std::fs::create_dir(&stage).unwrap();
            std::fs::create_dir(stage.join("build")).unwrap();
            for (path, bytes) in [
                (local.join("source.c"), b"original caller source".as_slice()),
                (
                    stage.join("source.c"),
                    b"private collector input".as_slice(),
                ),
                (
                    stage.join("build/app"),
                    b"retained delivery bytes".as_slice(),
                ),
            ] {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .unwrap()
                    .write_all(bytes)
                    .unwrap();
            }
            // The actual local publisher consumes real owned files. Compiler,
            // source-retirement and release flags below are unit inputs, not
            // evidence that a worker, SDK, source seal or slot release ran.
            session.recipe.prepared = true;
            session.starting_execution().unwrap();
            session.completed(command_exit).unwrap();
            session.publish("project").await.unwrap();
            session.returned(command_exit).unwrap();
            let before_retirement = std::fs::read(&writer.path).unwrap();
            assert!(session.tree_retired().is_err());
            assert!(session.retired().is_err());
            assert_eq!(std::fs::read(&writer.path).unwrap(), before_retirement);
            assert!(!session.recipe.pair_released && !session.recipe.sources_released);

            session.recipe.retained_materialized = Some(true);
            session.tree_retired().unwrap();
            assert!(session.retired().is_err());
            session.pair_released().unwrap();
            assert!(session.retired().is_err());
            session.sources_released().unwrap();
            // Planted negative: every release flag is set, but the job has not
            // retired, so its stage is still whole.
            assert_eq!(
                std::fs::read(stage.join("build/app")).unwrap(),
                b"retained delivery bytes"
            );
            session.retired().unwrap();
            let recovered = reload_publication(&session);
            assert!(recovered.recipe.retired);
            assert!(recovered.recipe.phases[0].complete);
            assert_eq!(recovered.recipe.returned, Some(command_exit));
            assert!(recovered.retain_source_lifecycle_evidence());
            // The caller's source and its published output are never touched.
            for (path, bytes) in [
                (local.join("source.c"), b"original caller source".as_slice()),
                (
                    local.join("build/app"),
                    b"retained delivery bytes".as_slice(),
                ),
            ] {
                assert_eq!(std::fs::read(path).unwrap(), bytes);
            }
            // bd-ra5aw (owner decision 2026-10-30): a successful delivery
            // releases the local stage; a failed command keeps all of it,
            // unpublished collector input included.
            if command_exit == 0 {
                assert!(!stage.parent().unwrap().exists());
            } else {
                for (path, bytes) in [
                    (
                        stage.join("source.c"),
                        b"private collector input".as_slice(),
                    ),
                    (
                        stage.join("build/app"),
                        b"retained delivery bytes".as_slice(),
                    ),
                ] {
                    assert_eq!(std::fs::read(path).unwrap(), bytes);
                }
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_retained_delivery_keeps_incomplete_and_pending_phase_evidence() {
        let _guard = test_guard!();
        let (directory, writer, _worker) = retained_preparation_fixture();
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer: writer.clone(),
        };
        session.recipe.project_root = directory.join("caller");
        session.recipe.transfer.retrieval_staging_dir = Some(directory.join("retrieval"));
        std::fs::create_dir_all(session.recipe.project_root.join("reports")).unwrap();
        for (name, result_dir) in [
            ("project", None),
            ("result:reports", Some(PathBuf::from("reports"))),
        ] {
            session.recipe.phases.push(RecoveryPhase {
                name: name.into(),
                local: session.recipe.project_root.clone(),
                remote: session.recipe.retire_root.as_ref().unwrap().clone(),
                patterns: if result_dir.is_some() {
                    Vec::new()
                } else {
                    default_c_cpp_artifact_patterns()
                },
                result_dir,
                custom_target: false,
                output_gate: false,
                cargo_outputs: None,
                native_outputs: None,
                baseline: BTreeMap::new(),
                published: BTreeMap::new(),
                pending: None,
                complete: false,
                missing_result: None,
            });
        }
        let artifact_stage = session.stage(0);
        let result_stage = session.stage(1);
        std::fs::create_dir_all(artifact_stage.join("build")).unwrap();
        std::fs::create_dir_all(result_stage.join("reports")).unwrap();
        std::fs::write(artifact_stage.join("source.c"), b"private collector input").unwrap();
        std::fs::write(artifact_stage.join("build/app"), b"unpublished artifact").unwrap();
        std::fs::write(result_stage.join("reports/result"), b"collected report").unwrap();
        let destination = session.recipe.project_root.join("reports/result");
        std::fs::write(&destination, b"original caller report").unwrap();
        let predecessor = fingerprint(&destination).unwrap().unwrap();
        let temporary = destination
            .parent()
            .unwrap()
            .join(format!(".rch-return-{}", session.recipe.identity));
        let temporary_alias = directory.join("preserved-publication-copy");
        let observed_temporary = temporary.clone();
        let observed_alias = temporary_alias.clone();
        session.recipe.prepared = true;
        session.starting_execution().unwrap();
        session.completed(7).unwrap();
        // Failed commands skip ordinary artifacts but still collect explicit
        // result directories. Change the real prepared copy at PendingDurable
        // so the production publisher refuses it before replacing the caller's
        // predecessor. A second link preserves both names and all their bytes.
        let error = session
            .publish_with_observer("result:reports", move |point, _| {
                if point == PublicationPoint::PendingDurable {
                    std::fs::hard_link(&observed_temporary, &observed_alias)?;
                }
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("prepared output identity, permissions or links changed")
        );
        assert!(publication_failure_is_terminal_in_recovery(&error));
        let pending = (
            PathBuf::from("reports/result"),
            fingerprint(&result_stage.join("reports/result"))
                .unwrap()
                .unwrap(),
        );
        assert_eq!(session.recipe.phases[1].pending, Some(pending.clone()));
        assert_eq!(
            session.recipe.phases[1]
                .baseline
                .get(Path::new("reports/result")),
            Some(&predecessor)
        );
        session.returned(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
        // A failed command need not have one of the narrower required-output
        // failure classifications. Its pending and private bytes still belong
        // to retained-source custody after all release flags are acknowledged.
        assert!(!session.retain_failed_delivery_evidence());
        session.persist_tree_retirement(Some(true)).unwrap();
        session.pair_released().unwrap();
        session.sources_released().unwrap();
        session.retired().unwrap();
        let recovered = reload_publication(&session);
        assert!(recovered.recipe.retired);
        assert_eq!(recovered.recipe.exit_code, Some(7));
        assert_eq!(
            recovered.recipe.returned,
            Some(EXIT_ARTIFACT_TRANSFER_FAILED)
        );
        assert!(!recovered.retain_failed_delivery_evidence());
        assert_eq!(recovered.recipe.phases[1].pending, Some(pending));
        assert_eq!(
            recovered.recipe.phases[1]
                .baseline
                .get(Path::new("reports/result")),
            Some(&predecessor)
        );
        assert!(recovered.recipe.phases.iter().all(|phase| !phase.complete));
        assert_eq!(
            std::fs::read(recovered.stage(0).join("source.c")).unwrap(),
            b"private collector input"
        );
        assert_eq!(
            std::fs::read(recovered.stage(0).join("build/app")).unwrap(),
            b"unpublished artifact"
        );
        assert_eq!(
            std::fs::read(recovered.stage(1).join("reports/result")).unwrap(),
            b"collected report"
        );
        for path in [temporary, temporary_alias] {
            assert_eq!(std::fs::read(path).unwrap(), b"collected report");
        }
        assert_eq!(
            std::fs::read(destination).unwrap(),
            b"original caller report"
        );
        assert!(!session.recipe.project_root.join("build/app").exists());
    }

    #[test]
    fn retained_source_recovery_rejects_contradictory_durable_acknowledgments() {
        let _guard = test_guard!();
        for case in [
            "tree-without-acknowledgment",
            "acknowledgment-before-tree",
            "acknowledgment-without-destination",
            "absent-after-execution",
            "absent-without-cancellation",
            "terminal-without-tree",
            "changed-destination",
            "changed-pair-token",
            "missing-retained-authority",
        ] {
            let (_directory, writer, _worker) = retained_preparation_fixture();
            let mut recipe = load_recipe(&writer).unwrap();
            match case {
                "tree-without-acknowledgment" => recipe.tree_retired = true,
                "acknowledgment-before-tree" => recipe.retained_materialized = Some(true),
                "acknowledgment-without-destination" => {
                    recipe.retained_root = None;
                    recipe.retained_materialized = Some(true);
                    recipe.tree_retired = true;
                }
                "absent-after-execution" => {
                    recipe.prepared = true;
                    recipe.execution_started = true;
                    recipe.preparation_cancelled = true;
                    recipe.retained_materialized = Some(false);
                    recipe.tree_retired = true;
                }
                "absent-without-cancellation" => {
                    recipe.retained_materialized = Some(false);
                    recipe.tree_retired = true;
                }
                "terminal-without-tree" => recipe.retired = true,
                "changed-destination" => {
                    recipe.retained_root = Some(format!(
                        "{}-other",
                        recipe.retained_root.as_deref().unwrap()
                    ));
                }
                "changed-pair-token" => {
                    recipe.pair.as_mut().unwrap().1 = "1123456789abcdef0123456789abcdef".into();
                }
                "missing-retained-authority" => {
                    recipe.source_roots = vec![recipe.retire_root.clone().unwrap()];
                }
                _ => unreachable!(),
            }
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            let disk_writer = DurableLeaseWriter {
                path: writer.path.clone(),
                recovery_ownership: None,
                lease: Arc::new(Mutex::new(serde_json::from_slice(&before).unwrap())),
            };
            assert!(
                load_recipe(&disk_writer).is_err(),
                "accepted contradictory state: {case}"
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{case}");
        }
    }

    #[test]
    fn retained_source_recovery_distinguishes_retained_bytes_from_cancelled_absence() {
        let _guard = test_guard!();
        for materialized in [true, false] {
            let (_directory, writer, _worker) = retained_preparation_fixture();
            let mut session = RecoverySession {
                recipe: load_recipe(&writer).unwrap(),
                writer: writer.clone(),
            };
            if materialized {
                session.recipe.prepared = true;
                session.starting_execution().unwrap();
                session.completed(0).unwrap();
            } else {
                session.recipe.preparation_cancelled = true;
                session.persist().unwrap();
            }
            // This fixture supplies the filesystem acknowledgment to exercise
            // journal validation. The rename protocol has separate OS tests.
            session.recipe.retained_materialized = Some(materialized);
            session.tree_retired().unwrap();
            let persisted = reload_publication(&session).recipe;
            assert!(persisted.tree_retired);
            assert_eq!(persisted.retained_materialized, Some(materialized));
            assert_eq!(persisted.execution_started, materialized);
            assert_eq!(persisted.preparation_cancelled, !materialized);
            assert_eq!(persisted.retained_root, session.recipe.retained_root);
            assert_eq!(persisted.pair, session.recipe.pair);
            assert!(!persisted.sources_released);
            assert!(!persisted.pair_released);
            assert!(!persisted.retired);
            assert!(writer.ensure_released_for_retry().is_err());
        }
    }

    #[test]
    fn source_intent_rejects_invalid_paths_and_identity_before_journaling() {
        let invalid_roots = [
            "relative",
            "/data/projects/source-recovery/",
            "/data/projects//source-recovery",
            "/data/projects/./source-recovery",
            "/data/projects/../source-recovery",
            "/data/projects/source\nrecovery",
            "/data/projects/source\rrecovery",
            "/data/projects/source\0recovery",
        ];
        for (roots, identity) in invalid_roots
            .into_iter()
            .map(|root| (vec![root.to_owned()], "abc123"))
            .chain([
                (Vec::new(), "abc123"),
                (vec!["/data/projects/source-recovery".into()], ""),
                (vec!["/data/projects/source-recovery".into()], "bad/token"),
            ])
        {
            let (directory, writer, worker) = admitted_preparation_fixture();
            let before = std::fs::read(&writer.path).unwrap();
            let result = RecoverySession::begin(
                &writer,
                &worker,
                roots.clone(),
                None,
                None,
                None,
                TransferConfig::default(),
                directory.path().to_owned(),
                identity.into(),
            );
            assert!(
                result.is_err(),
                "admitted invalid intent {roots:?}/{identity:?}"
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            assert!(writer.snapshot().recovery.is_none());
            assert_eq!(writer.snapshot().identity.remote_build_id, Some(41));
        }
    }

    #[test]
    fn source_intent_is_durable_before_remote_acquisition_and_blocks_re_admission() {
        let (_directory, writer, worker) = preparation_fixture();
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        let recipe: RecoveryRecipe = serde_json::from_value(disk.recovery.unwrap()).unwrap();
        assert_eq!(recipe.identity, "abc123");
        assert_eq!(recipe.source_roots, ["/data/projects/source-recovery"]);
        assert!(!recipe.prepared);
        assert!(!recipe.execution_started);
        assert!(recipe.phases.is_empty());
        assert!(writer.ensure_released_for_retry().is_err());
        assert!(writer.admit(42, &worker.id).is_err());
        assert_eq!(writer.snapshot().identity.remote_build_id, Some(41));
        assert!(writer.acknowledge_terminal().is_err());
    }

    #[test]
    fn source_execution_requires_preparation_and_persists_before_launch() {
        let (_directory, writer, _worker) = preparation_fixture();
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer: writer.clone(),
        };
        assert!(session.starting_execution().is_err());
        session.recipe.prepared = true;
        session.starting_execution().unwrap();
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        let recipe: RecoveryRecipe = serde_json::from_value(disk.recovery.unwrap()).unwrap();
        assert!(recipe.execution_started);
        assert!(
            session.starting_execution().is_err(),
            "a prepared execution is consumed once"
        );
    }

    #[test]
    fn delayed_heartbeat_publication_cannot_roll_back_execution_admission() {
        let (_directory, writer, _worker) = preparation_fixture();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        let mut session = RecoverySession {
            recipe,
            writer: writer.clone(),
        };
        let (captured_tx, captured_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let heartbeat_writer = writer.clone();
        let older = std::thread::spawn(move || {
            heartbeat_writer.persist_snapshot(|path, bytes| {
                captured_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                atomic_write(path, bytes)
            })
        });
        captured_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (starting_tx, starting_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let newer = std::thread::spawn(move || {
            starting_tx.send(()).unwrap();
            let result = session.starting_execution();
            finished_tx.send(()).unwrap();
            result
        });
        starting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let overtook = finished_rx.recv_timeout(Duration::from_millis(200)).is_ok();
        // Release both threads before asserting so a failed ordering assertion
        // never strands a blocked publisher in the test process.
        release_tx.send(()).unwrap();
        older.join().unwrap().unwrap();
        newer.join().unwrap().unwrap();
        assert!(
            !overtook,
            "new execution admission overtook an older pending disk publication"
        );
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        let persisted: RecoveryRecipe = serde_json::from_value(disk.recovery.unwrap()).unwrap();
        assert!(
            persisted.execution_started,
            "a delayed heartbeat replaced the durable execution boundary with Preparing"
        );
    }

    #[tokio::test]
    async fn started_source_intent_cannot_be_cancelled_as_preparation() {
        let (_directory, writer, _worker) = preparation_fixture();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        recipe.execution_started = true;
        writer
            .set_recovery(serde_json::to_value(&recipe).unwrap())
            .unwrap();
        let before = std::fs::read(&writer.path).unwrap();
        assert!(!cancel_preparation(&writer).await.unwrap());
        assert_eq!(
            std::fs::read(&writer.path).unwrap(),
            before,
            "a started attempt cannot contact the worker's cancellation path or rewrite its journal"
        );
    }

    #[test]
    fn returned_outputs_do_not_authorize_terminal_ack_until_sources_release() {
        let (_directory, writer, worker) = preparation_fixture();
        let mut session = RecoverySession {
            recipe: load_recipe(&writer).unwrap(),
            writer: writer.clone(),
        };
        session.returned(0).unwrap();
        session.tree_retired().unwrap();
        session.pair_released().unwrap();
        assert!(session.retired().is_err());
        assert!(writer.acknowledge_terminal().is_err());
        session.sources_released().unwrap();
        session.retired().unwrap();
        writer.record_exit(0).unwrap();
        writer.acknowledge_terminal().unwrap();
        writer.ensure_released_for_retry().unwrap();
        writer.admit(42, &worker.id).unwrap();
        let next = writer.snapshot();
        assert!(next.recovery.is_none());
        assert!(!next.terminal_acknowledged);
        assert_eq!(next.exit_code, None);
        assert_eq!(next.identity.remote_build_id, Some(42));
    }

    #[test]
    fn unsupported_or_mismatched_source_intent_never_enters_recovery() {
        let (_directory, writer, _worker) = preparation_fixture();
        let original = load_recipe(&writer).unwrap();
        for changed in [
            {
                let mut recipe = original.clone();
                recipe.version = 1;
                recipe
            },
            {
                let mut recipe = original.clone();
                recipe.build_id += 1;
                recipe
            },
            {
                let mut recipe = original.clone();
                recipe.worker.id = WorkerId::new("other");
                recipe
            },
        ] {
            writer
                .set_recovery(serde_json::to_value(changed).unwrap())
                .unwrap();
            assert!(load_recipe(&writer).is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn already_released_source_grant_settles_without_reopening_worker_paths() {
        let _guard = test_guard!();
        for (observed_exit, expected_exit, pending_cancellation) in [
            (None, EXIT_BUILD_ERROR, false),
            (Some(0), EXIT_ARTIFACT_TRANSFER_FAILED, false),
            (Some(101), 101, false),
            (None, EXIT_BUILD_ERROR, true),
        ] {
            let mut wrapper = std::process::Command::new("/usr/bin/true").spawn().unwrap();
            let wrapper_pid = wrapper.id();
            assert!(wrapper.wait().unwrap().success());

            let (_directory, writer, worker) = preparation_fixture();
            let mut session = RecoverySession {
                recipe: load_recipe(&writer).unwrap(),
                writer: writer.clone(),
            };
            session.recipe.prepared = true;
            session.starting_execution().unwrap();
            if pending_cancellation {
                session.recipe.sources_released = true;
                session.recipe.tree_retired = true;
                session.recipe.pair_released = true;
            }
            session.recipe.source_cancellation_settled = pending_cancellation.then_some(false);
            {
                let mut lease = session.writer.lease.lock().unwrap();
                lease.wrapper_pid = wrapper_pid;
                lease.process_start_ticks = None;
                lease.boot_id = None;
                lease.process_birth = None;
            }
            session.persist().unwrap();
            let wrapper_id = session.writer.snapshot().identity.local_wrapper_id;
            let worker_id = worker.id.as_str().to_owned();
            let owned = recovery_owner::claim(&session.writer).await.unwrap();
            let mut claimed_session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let mut daemon = async |_request: &str| {
                Ok(format!(
                    "HTTP/1.1 200 OK\r\n\r\n{}",
                    serde_json::json!({
                        "status": "completed",
                        "local_wrapper_id": wrapper_id,
                        "record": {
                            "id": 41,
                            "worker_id": worker_id,
                            "exit_code": expected_exit
                        }
                    })
                ))
            };
            let worker_calls = std::cell::Cell::new(0);
            let result = retire_already_released_source_grant_with(
                &mut claimed_session,
                &owned,
                &mut daemon,
                observed_exit,
                async |session| {
                    // The worker boundary is a unit input here. Native worker
                    // qualifications exercise the actual registry coordinator.
                    assert_eq!(session.recipe.returned, Some(expected_exit));
                    session
                        .reconcile_source_cancellation_with(async |_, _, _| {
                            worker_calls.set(worker_calls.get() + 1);
                            anyhow::bail!("interrupted worker settlement reply")
                        })
                        .await
                },
            )
            .await;
            let retired = if pending_cancellation {
                assert!(result.is_err());
                let checkpoint = load_recipe(&owned).unwrap();
                assert_eq!(checkpoint.returned, Some(expected_exit));
                assert_eq!(checkpoint.source_cancellation_settled, Some(false));
                assert!(!checkpoint.retired);
                assert!(!owned.snapshot().terminal_acknowledged);
                claimed_session.recipe = checkpoint;
                retire_already_released_source_grant_with(
                    &mut claimed_session,
                    &owned,
                    &mut daemon,
                    None,
                    async |session| {
                        session
                            .reconcile_source_cancellation_with(async |_, _, _| {
                                worker_calls.set(worker_calls.get() + 1);
                                Ok(())
                            })
                            .await
                    },
                )
                .await
                .unwrap()
            } else {
                result.unwrap()
            };
            assert_eq!(worker_calls.get(), if pending_cancellation { 2 } else { 0 });
            assert_eq!(retired, expected_exit);
            let settled_lease = owned.snapshot();
            assert!(settled_lease.terminal_acknowledged);
            assert_eq!(settled_lease.exit_code, Some(expected_exit));
            let settled_recipe = load_recipe(&owned).unwrap();
            assert!(settled_recipe.tree_retired);
            assert!(settled_recipe.pair_released);
            assert!(settled_recipe.sources_released);
            assert!(settled_recipe.retired);
            assert_eq!(settled_recipe.returned, Some(expected_exit));
            assert_eq!(
                settled_recipe.source_cancellation_settled,
                pending_cancellation.then_some(true)
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn permanent_local_publication_refusals_are_classified_terminal_in_recovery() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = test_guard!();

        // 1. Dangling symlink in output root path (Class 2: e.g. /data -> absent)
        {
            let (directory, _stage_owner, mut session) = publication_fixture();
            let dangling = directory.path().join("dangling-data");
            std::os::unix::fs::symlink(directory.path().join("missing-mount"), &dangling).unwrap();
            session.recipe.phases[0].local = dangling.join("projects/frankenterm/target");
            let stage = session.stage(0);
            std::fs::create_dir_all(stage.join("build")).unwrap();
            std::fs::write(stage.join("build/app"), b"compiled artifact").unwrap();
            session.persist().unwrap();

            let err = session.publish("project").await.unwrap_err();
            assert!(
                publication_failure_is_terminal_in_recovery(&err),
                "dangling output root symlink must be terminal in recovery: {err:#}"
            );
        }

        // 2. Pre-96ca9bf3 0644 .rch-return-<id> partial temporary (Class 3)
        {
            let (_directory, _stage_owner, mut session) = publication_fixture();
            let local = session.recipe.project_root.clone();
            let stage = session.stage(0);
            std::fs::create_dir_all(local.join("build")).unwrap();
            std::fs::create_dir_all(stage.join("build")).unwrap();
            std::fs::write(stage.join("build/app"), b"complete staged binary payload").unwrap();
            let legacy_temp = local
                .join("build")
                .join(format!(".rch-return-{}", session.recipe.identity));
            std::fs::write(&legacy_temp, b"complete").unwrap();
            std::fs::set_permissions(&legacy_temp, std::fs::Permissions::from_mode(0o644)).unwrap();
            session.persist().unwrap();

            let err = session.publish("project").await.unwrap_err();
            assert!(
                publication_failure_is_terminal_in_recovery(&err),
                "0644 partial .rch-return temporary must be terminal in recovery: {err:#}"
            );
            assert!(
                session
                    .returned(EXIT_ARTIFACT_TRANSFER_FAILED)
                    .map(|()| {
                        session.recipe.exit_code = Some(0);
                        session.retain_failed_delivery_evidence()
                    })
                    .unwrap(),
                "terminal failed delivery in recovery must retain staged outputs"
            );
        }

        // 3. Symlinked output ancestor inside output root
        {
            let (directory, _stage_owner, mut session) = publication_fixture();
            let local = session.recipe.project_root.clone();
            let elsewhere = directory.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, local.join("build")).unwrap();
            let stage = session.stage(0);
            std::fs::create_dir_all(stage.join("build")).unwrap();
            std::fs::write(stage.join("build/app"), b"output").unwrap();
            session.persist().unwrap();

            let err = session.publish("project").await.unwrap_err();
            assert!(
                publication_failure_is_terminal_in_recovery(&err),
                "symlinked output ancestor must be terminal in recovery: {err:#}"
            );
        }

        // 4. Retryable errors (cancellation, lock contention, storage full) must NOT be terminal
        for retryable in [
            anyhow::Error::new(publication_runtime::PublicationCancelled),
            anyhow::anyhow!(
                "output publication into /tmp/target is held by another wrapper: Resource temporarily unavailable"
            ),
            anyhow::anyhow!(
                "output root changed while waiting for publication ownership: /tmp/target; journal retained"
            ),
            anyhow::anyhow!(
                "insufficient controller publication storage: need 4096 additional bytes, available 0; staged output and retained copy remain retryable"
            ),
        ] {
            assert!(
                !publication_failure_is_terminal_in_recovery(&retryable),
                "retryable error was misclassified as terminal: {retryable:#}"
            );
        }
    }
}
