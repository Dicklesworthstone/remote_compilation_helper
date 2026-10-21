//! Optional worker-local Cargo target state, never an action/result cache.
//!
//! Exact verified inputs may seed a NEW private target directory. Cargo still
//! executes and owns every freshness decision, including build-script tracking.
//! Source timestamps come from the prior identical private workspace; output
//! timestamps are preserved, never advanced to manufacture freshness. No seed
//! is mounted writable or linked into an execution. Verified internal aliases
//! are reconstructed only between files of the SAME fresh private clone.
//! The process owns the pool
//! across reconnects, and clean shutdown drops all its temporary directories.

use crate::artifacts::{ArtifactPlan, CapturedArtifacts, MAX_ARTIFACT_BYTES, PreparedArtifacts};
use crate::result_spool::ResultRecipient;
use crate::session::CanonicalExecRequest;
use rabs_sandbox::canonical_namespace::{CanonicalNamespaceSpec, HostIsolationSupport};
use rabs_sandbox::source_transfer::{MAX_SOURCE_BYTES, SourceManifest};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Independent count and byte limits bound retained seeds and in-flight staging.
pub const MAX_TARGET_CACHE_ENTRIES: usize = 8;
pub const MAX_TARGET_CACHE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "target state interrupted",
        ))
    } else {
        Ok(())
    }
}

/// Privacy scope comes from the authenticated connection, not request metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetCacheScope([u8; 32]);

impl TargetCacheScope {
    #[must_use]
    pub fn new(worker: &str, endpoint: &str, recipient: &ResultRecipient) -> Self {
        let recipient = match recipient {
            ResultRecipient::TlsSpki(digest) => {
                format!("tls-spki:{}", crate::source_transfer::hex(digest))
            }
            ResultRecipient::LoopbackFixture => "explicit-loopback-fixture".to_owned(),
        };
        let encoded = serde_json::to_vec(&(worker, endpoint, recipient)).expect("string encoding");
        Self(Sha256::digest(encoded).into())
    }
}

/// Only SourceOwner constructs production inputs after its sealed handoff.
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceInputs {
    pub root: PathBuf,
    pub manifest: SourceManifest,
    pub full_source_digest: [u8; 32],
    pub projection: Option<(String, String)>,
    pub runtime_owner: Option<Arc<tempfile::TempDir>>,
}

impl WorkspaceInputs {
    /// SourceReceiver's seal and any Cargo-home projection remain untouched.
    /// Timestamp restoration is permitted only on this independent, verified
    /// runtime copy, whose owner stays live even if optional caching is refused.
    #[cfg(target_os = "linux")]
    pub(crate) fn private_runtime_clone(self, stopped: &impl Fn() -> bool) -> io::Result<Self> {
        self.clone_into(private_directory("rabs-target-workspace-")?, stopped)
    }

    #[cfg(target_os = "linux")]
    fn clone_into(
        self,
        directory: tempfile::TempDir,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        let before = SourceTimes::capture(&self, stopped)?;
        let required = self
            .manifest
            .files()
            .iter()
            .map(|file| file.path.clone())
            .collect();
        let tree = TreeInventory::scan(&self.root, &required, MAX_SOURCE_BYTES, stopped)?;
        copy_tree(&tree, directory.path(), stopped)?;
        let cloned = Self {
            root: directory.path().to_path_buf(),
            runtime_owner: Some(Arc::new(directory)),
            ..self
        };
        if SourceTimes::capture(&cloned, stopped)? != before {
            return Err(invalid(
                "runtime source clone differs from the sealed workspace",
            ));
        }
        Ok(cloned)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn private_runtime_clone(self, _stopped: &impl Fn() -> bool) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TargetKey([u8; 32]);

/// Bind the actual final environment, including the worker-authored grant and
/// private HOME's stable FIFO path. Hidden temporary backing paths are excluded:
/// the compiler sees only these canonical mount destinations.
pub(crate) fn target_key(
    scope: TargetCacheScope,
    request: &CanonicalExecRequest,
    inputs: &WorkspaceInputs,
    spec: &CanonicalNamespaceSpec,
    support: &HostIsolationSupport,
    plan: &ArtifactPlan,
    grant: u32,
) -> io::Result<TargetKey> {
    if spec.allows_network() {
        return Err(invalid(
            "target state requires the network-denied canonical namespace",
        ));
    }
    let toolchain = request
        .toolchain_identity
        .ok_or_else(|| invalid("target state requires a pinned toolchain"))?;
    let mut ro: Vec<_> = spec.ro_binds.iter().map(|bind| &bind.visible).collect();
    let mut rw: Vec<_> = spec.rw_binds.iter().map(|bind| &bind.visible).collect();
    ro.sort();
    rw.sort();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version":"rabs.private-cargo-target.v1",
        "scope":scope.0,
        "source":inputs.full_source_digest,
        "workspace":inputs.manifest.digest(),
        "projection":inputs.projection,
        "toolchain":[crate::source_transfer::hex(&toolchain.sha256), toolchain.files.to_string(), toolchain.bytes.to_string()],
        "program":request.program, "args":request.args,
        "cwd":spec.cwd, "env":spec.env, "hostname":spec.hostname,
        "network":spec.allows_network(), "ro":ro, "rw":rw,
        "bubblewrap":support.bubblewrap, "userns":support.unprivileged_userns,
        "grant":grant, "output":plan.virtual_root(),
        "required":plan.files().collect::<Vec<_>>(),
        "cargo_mode":format!("{:?}", plan.cargo_mode()),
        "runtime":"fresh-home+captured-or-empty-cargo-home+private-fifo-v1",
    }))?;
    Ok(TargetKey(Sha256::digest(bytes).into()))
}

#[derive(Debug, Default)]
struct PoolState {
    entries: VecDeque<Seed>,
    retained_bytes: u64,
    reserved_bytes: u64,
    reservations: usize,
}

/// Explicitly configured, process-owned, bounded private Cargo hot state.
#[derive(Debug)]
pub struct TargetCache {
    max_bytes: u64,
    state: Mutex<PoolState>,
}

impl TargetCache {
    /// A zero CLI limit disables the pool before this constructor is called.
    pub fn new(max_bytes: u64) -> io::Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Cargo target state requires Linux",
            ));
        }
        if max_bytes == 0 || max_bytes > MAX_TARGET_CACHE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target cache bytes must be between 1 and 8589934592",
            ));
        }
        Ok(Self {
            max_bytes,
            state: Mutex::new(PoolState::default()),
        })
    }

    /// Every successful hit is copied while the bounded seed remains owned by
    /// the pool. A contended pool is a cold execution, never a compiler wait.
    pub(crate) fn acquire(
        self: &Arc<Self>,
        key: TargetKey,
        inputs: WorkspaceInputs,
        new_output: impl FnOnce() -> io::Result<PreparedArtifacts>,
        request_id: u64,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<(TargetAttempt, Option<PreparedArtifacts>)> {
        if inputs
            .runtime_owner
            .as_ref()
            .is_none_or(|owner| owner.path() != inputs.root)
        {
            return Err(invalid(
                "target state requires a private runtime workspace owner",
            ));
        }
        let mut times = SourceTimes::capture(&inputs, stopped)?;
        let mut restored = None;
        let mut disposition = "cold";
        if let Ok(mut state) = self.state.try_lock() {
            if let Some(index) = state.entries.iter().position(|seed| seed.key == key) {
                let seed = &state.entries[index];
                let reuse = (|| {
                    let output = new_output()?;
                    seed.tree.restore(output.backing(), stopped)?;
                    seed.source.restore(&inputs, stopped)?;
                    Ok::<_, io::Error>(output)
                })();
                match reuse {
                    Ok(output) => {
                        times = seed.source.clone();
                        restored = Some(output);
                        disposition = "restored";
                        let seed = state.entries.remove(index).expect("located seed");
                        state.entries.push_back(seed);
                    }
                    Err(error) => {
                        let seed = state.entries.remove(index).expect("located seed");
                        state.retained_bytes -= seed.tree.bytes;
                        drop(seed);
                        eprintln!(
                            "{}",
                            serde_json::json!({"kind":"worker-target-state-refused", "request_id":request_id, "error":error.to_string()})
                        );
                        // A failed restore never exposes its partial output.
                        // Re-read source timestamps if restoration had begun;
                        // a cold target cannot trust any prior fingerprint.
                        times = SourceTimes::capture(&inputs, stopped)?;
                        disposition = "cold-after-refusal";
                    }
                }
            }
        } else {
            disposition = "cold-pool-busy";
        }
        eprintln!(
            "{}",
            serde_json::json!({"kind":"worker-target-state", "request_id":request_id, "disposition":disposition, "key_sha256":crate::source_transfer::hex(&key.0)})
        );
        Ok((
            TargetAttempt {
                cache: Arc::clone(self),
                key,
                inputs,
                times,
                request_id,
            },
            restored,
        ))
    }

    fn reserve(self: &Arc<Self>, bytes: u64) -> Option<Reservation> {
        if bytes > self.max_bytes {
            return None;
        }
        let mut state = self.state.try_lock().ok()?;
        while state.retained_bytes + state.reserved_bytes + bytes > self.max_bytes
            || state.entries.len() + state.reservations >= MAX_TARGET_CACHE_ENTRIES
        {
            let seed = state.entries.pop_front()?;
            state.retained_bytes -= seed.tree.bytes;
        }
        state.reserved_bytes += bytes;
        state.reservations += 1;
        Some(Reservation {
            cache: Arc::clone(self),
            bytes,
            active: true,
        })
    }
}

#[derive(Debug)]
struct Reservation {
    cache: Arc<TargetCache>,
    bytes: u64,
    active: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.active {
            let mut state = self
                .cache
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.reserved_bytes -= self.bytes;
            state.reservations -= 1;
        }
    }
}

#[derive(Debug)]
struct Seed {
    key: TargetKey,
    source: SourceTimes,
    tree: TreeSnapshot,
}

/// Staging is not publication. ExecutionControl owns this until its FINAL
/// successful execution frontier, after cancellation, drains and artifact
/// checks. Subsequent result-spool/delivery failures do not invalidate normal
/// Cargo state produced by that successfully completed native execution.
#[derive(Debug)]
pub(crate) struct PendingTargetSeed {
    // Drop the owned tree BEFORE releasing its byte/entry reservation, so a
    // cancelled candidate's filesystem cleanup remains inside the pool bound.
    seed: Option<Seed>,
    reservation: Reservation,
    request_id: u64,
}

impl PendingTargetSeed {
    pub(crate) fn publish(mut self) {
        let mut state = self
            .reservation
            .cache
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let seed = self.seed.take().expect("pending seed owns its snapshot");
        if let Some(index) = state.entries.iter().position(|prior| prior.key == seed.key) {
            let prior = state.entries.remove(index).expect("located seed");
            state.retained_bytes -= prior.tree.bytes;
        }
        state.reserved_bytes -= self.reservation.bytes;
        state.reservations -= 1;
        self.reservation.active = false;
        state.retained_bytes += seed.tree.bytes;
        state.entries.push_back(seed);
        eprintln!(
            "{}",
            serde_json::json!({"kind":"worker-target-state-published", "request_id":self.request_id, "seed_bytes":self.reservation.bytes, "retained_bytes":state.retained_bytes, "entries":state.entries.len()})
        );
    }
}

#[derive(Debug)]
pub(crate) struct TargetAttempt {
    cache: Arc<TargetCache>,
    key: TargetKey,
    inputs: WorkspaceInputs,
    times: SourceTimes,
    request_id: u64,
}

impl TargetAttempt {
    pub(crate) fn stage(
        self,
        artifacts: &PreparedArtifacts,
        captured: &CapturedArtifacts,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Option<PendingTargetSeed>> {
        if SourceTimes::capture(&self.inputs, stopped)? != self.times {
            return Err(invalid("source changed while Cargo was executing"));
        }
        let Some(reservation) = self.cache.reserve(captured.total_bytes()) else {
            return Ok(None);
        };
        let tree = TreeSnapshot::capture(artifacts.backing(), captured, stopped)?;
        if tree.bytes != reservation.bytes {
            return Err(invalid("target state differs from captured artifacts"));
        }
        Ok(Some(PendingTargetSeed {
            reservation,
            seed: Some(Seed {
                key: self.key,
                source: self.times,
                tree,
            }),
            request_id: self.request_id,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceTimes {
    files: BTreeMap<String, SystemTime>,
    directories: BTreeMap<String, StoredDirectory>,
}

#[cfg(target_os = "linux")]
impl SourceTimes {
    fn capture(inputs: &WorkspaceInputs, stopped: &impl Fn() -> bool) -> io::Result<Self> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        use std::os::unix::fs::PermissionsExt;
        let required = inputs
            .manifest
            .files()
            .iter()
            .map(|file| file.path.clone())
            .collect();
        let tree = TreeInventory::scan(&inputs.root, &required, MAX_SOURCE_BYTES, stopped)?;
        if tree.names().ne(inputs
            .manifest
            .files()
            .iter()
            .map(|file| file.path.as_str()))
        {
            return Err(invalid(
                "target state workspace differs from its sealed manifest",
            ));
        }
        let mut files = BTreeMap::new();
        for expected in inputs.manifest.files() {
            checkpoint(stopped)?;
            let mut file = tree.open_file(&expected.path)?;
            let metadata = file.metadata()?;
            if metadata.len() != expected.len
                || (metadata.permissions().mode() & 0o111 != 0) != expected.executable
                || hash_copy(&mut file, &mut io::sink(), expected.len, stopped)? != expected.sha256
            {
                return Err(invalid("target state source content verification failed"));
            }
            tree.verify_file(&expected.path, &file)?;
            files.insert(expected.path.clone(), metadata.modified()?);
        }
        let directories = directory_times(&tree)?;
        tree.verify(stopped)?;
        Ok(Self { files, directories })
    }

    fn restore(&self, inputs: &WorkspaceInputs, stopped: &impl Fn() -> bool) -> io::Result<()> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        if inputs
            .runtime_owner
            .as_ref()
            .is_none_or(|owner| owner.path() != inputs.root)
        {
            return Err(invalid(
                "source timestamps require a private runtime workspace owner",
            ));
        }
        let current = Self::capture(inputs, stopped)?;
        if current.files.keys().ne(self.files.keys())
            || current.directories.keys().ne(self.directories.keys())
            || current
                .directories
                .iter()
                .any(|(name, value)| self.directories[name].mode != value.mode)
        {
            return Err(invalid("target state source layout changed"));
        }
        let required = self.files.keys().cloned().collect();
        let tree = TreeInventory::scan(&inputs.root, &required, MAX_SOURCE_BYTES, stopped)?;
        for (name, modified) in &self.files {
            checkpoint(stopped)?;
            tree.open_file(name)?
                .set_times(FileTimes::new().set_modified(*modified))?;
        }
        // Updating a child timestamp does not alter its parent. Deepest-first
        // restoration also leaves the original root timestamp intact.
        for (name, directory) in self.directories.iter().rev() {
            checkpoint(stopped)?;
            tree.open_directory(name)?
                .set_times(FileTimes::new().set_modified(directory.modified))?;
        }
        if Self::capture(inputs, stopped)? != *self {
            return Err(invalid(
                "source filesystem cannot preserve Cargo timestamps",
            ));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl SourceTimes {
    fn capture(_: &WorkspaceInputs, _: &impl Fn() -> bool) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
    fn restore(&self, _: &WorkspaceInputs, _: &impl Fn() -> bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredFile {
    len: u64,
    digest: [u8; 32],
    mode: u32,
    modified: SystemTime,
    /// First relative path of an internal alias group; never a host inode ID.
    link_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredDirectory {
    mode: u32,
    modified: SystemTime,
}

#[derive(Debug)]
struct TreeSnapshot {
    directory: tempfile::TempDir,
    files: BTreeMap<String, StoredFile>,
    directories: BTreeMap<String, StoredDirectory>,
    bytes: u64,
}

#[cfg(target_os = "linux")]
fn directory_times(
    tree: &rabs_sandbox::artifact_tree::TreeInventory,
) -> io::Result<BTreeMap<String, StoredDirectory>> {
    use std::os::unix::fs::PermissionsExt;
    tree.directory_names()
        .map(|name| {
            let metadata = tree.open_directory(name)?.metadata()?;
            let mode = metadata.permissions().mode();
            if mode & 0o7000 != 0 {
                return Err(invalid(
                    "target state refuses special directory permission bits",
                ));
            }
            if mode & 0o700 != 0o700 {
                // Retained TempDir cleanup must not require privilege or leave
                // unaccounted read-only trees after eviction/cancellation.
                return Err(invalid(
                    "target state requires owner-readable writable directories",
                ));
            }
            Ok((
                name.to_owned(),
                StoredDirectory {
                    mode: mode & 0o777,
                    modified: metadata.modified()?,
                },
            ))
        })
        .collect()
}

#[cfg(target_os = "linux")]
impl TreeSnapshot {
    fn capture(
        root: &Path,
        captured: &CapturedArtifacts,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        let required = captured.file_names().map(str::to_owned).collect();
        let tree = TreeInventory::scan(root, &required, MAX_ARTIFACT_BYTES, stopped)?;
        let directory = private_directory("rabs-target-seed-")?;
        let (files, directories) = copy_tree(&tree, directory.path(), stopped)?;
        if files.keys().map(String::as_str).ne(captured.file_names()) {
            return Err(invalid("target seed differs from validated artifact set"));
        }
        for (name, file) in &files {
            if captured.file_identity(name)
                != Some((
                    file.len,
                    crate::source_transfer::hex(&file.digest).as_str(),
                    file.mode & 0o111 != 0,
                ))
            {
                return Err(invalid("target seed differs from validated artifact bytes"));
            }
        }
        Ok(Self {
            directory,
            files,
            directories,
            bytes: tree.total_bytes(),
        })
    }

    fn restore(&self, destination: &Path, stopped: &impl Fn() -> bool) -> io::Result<()> {
        use rabs_sandbox::artifact_tree::TreeInventory;
        let required = self.files.keys().cloned().collect();
        let tree = TreeInventory::scan(self.directory.path(), &required, self.bytes, stopped)?;
        let (files, directories) = copy_tree(&tree, destination, stopped)?;
        if files != self.files
            || directories != self.directories
            || tree.total_bytes() != self.bytes
        {
            return Err(invalid("private target seed was corrupted"));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl TreeSnapshot {
    fn capture(_: &Path, _: &CapturedArtifacts, _: &impl Fn() -> bool) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
    fn restore(&self, _: &Path, _: &impl Fn() -> bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "target state requires Linux",
        ))
    }
}

fn private_directory(prefix: &str) -> io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder.tempdir()
}

#[cfg(target_os = "linux")]
fn copy_tree(
    tree: &rabs_sandbox::artifact_tree::TreeInventory,
    destination: &Path,
    stopped: &impl Fn() -> bool,
) -> io::Result<(
    BTreeMap<String, StoredFile>,
    BTreeMap<String, StoredDirectory>,
)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let directories = directory_times(tree)?;
    for name in directories.keys().filter(|name| !name.is_empty()) {
        checkpoint(stopped)?;
        // PreparedArtifacts may already have declared parent directories. Only
        // this execution owns destination, which is never sourced from a peer.
        let path = destination.join(name);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists
                    && fs::symlink_metadata(&path)?.is_dir() => {}
            Err(error) => return Err(error),
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let mut files = BTreeMap::new();
    let mut aliases: BTreeMap<(u64, u64), String> = BTreeMap::new();
    for name in tree.names() {
        checkpoint(stopped)?;
        let mut input = tree.open_file(name)?;
        let metadata = input.metadata()?;
        if metadata.permissions().mode() & 0o7000 != 0 {
            return Err(invalid("target state refuses special permission bits"));
        }
        let mode = metadata.permissions().mode() & 0o777;
        let modified = metadata.modified()?;
        let inode = (metadata.dev(), metadata.ino());
        let link_to = aliases.get(&inode).cloned();
        let digest = if let Some(first) = &link_to {
            let digest = hash_copy(&mut input, &mut io::sink(), metadata.len(), stopped)?;
            let prior: &StoredFile = files
                .get(first)
                .ok_or_else(|| invalid("missing internal target alias"))?;
            if prior.len != metadata.len()
                || prior.digest != digest
                || prior.mode != mode
                || prior.modified != modified
            {
                return Err(invalid("internal target alias changed during copy"));
            }
            // TreeInventory has already proved the entire link group closed.
            // Both endpoints are newly created under this one private owner;
            // the original tree, the seed and other attempts share NO inode.
            fs::hard_link(destination.join(first), destination.join(name))?;
            digest
        } else {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(destination.join(name))?;
            let digest = hash_copy(&mut input, &mut output, metadata.len(), stopped)?;
            output.set_permissions(fs::Permissions::from_mode(mode))?;
            output.set_times(FileTimes::new().set_modified(modified))?;
            aliases.insert(inode, name.to_owned());
            digest
        };
        tree.verify_file(name, &input)?;
        files.insert(
            name.to_owned(),
            StoredFile {
                len: metadata.len(),
                digest,
                mode,
                modified,
                link_to,
            },
        );
    }
    for (name, directory) in directories.iter().rev() {
        checkpoint(stopped)?;
        let output = File::open(destination.join(name))?;
        output.set_permissions(fs::Permissions::from_mode(directory.mode))?;
        output.set_times(FileTimes::new().set_modified(directory.modified))?;
    }
    tree.verify(stopped)?;
    Ok((files, directories))
}

fn hash_copy(
    input: &mut File,
    output: &mut impl Write,
    length: u64,
    stopped: &impl Fn() -> bool,
) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut remaining = length;
    let mut buffer = [0; 64 * 1024];
    loop {
        checkpoint(stopped)?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or_else(|| invalid("target state file grew during copy"))?;
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    if remaining != 0 {
        return Err(invalid("target state file shrank during copy"));
    }
    Ok(hash.finalize().into())
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
