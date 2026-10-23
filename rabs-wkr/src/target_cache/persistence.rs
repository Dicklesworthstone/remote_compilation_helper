//! Restart retention for private Cargo targets, never execution/result authority.
//!
//! One locked, owner-only root contains at most eight generations, including
//! unfinished captures. A generation becomes discoverable only when the final
//! execution completion frontier renames its fully synced pending metadata.
//! Recovery removes incomplete/corrupt generations before accepting new writes.
//! Any uncertain reclamation disables writes instead of releasing disk quota.

use super::*;
use rabs_sandbox::artifact_tree::{
    MAX_TREE_ENTRIES, MAX_TREE_FILES, TreeInventory, validate_tree_names,
};
use rabs_sandbox::source_transfer::{MAX_SOURCE_FILES, SourceFile};
use serde_json::{Value, json};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Component;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, UNIX_EPOCH};

const LOCK: &str = "owner.lock";
const PREFIX: &str = "generation-";
const PENDING: &str = "pending.json";
const COMMITTED: &str = "seed.json";
const SCHEMA: &str = "rabs.private-cargo-target-disk.v1";
// Payload bytes remain charged by the existing target-byte reservation. This
// separate cap bounds metadata (including source/directory timestamps) per seed.
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct Storage {
    root: PathBuf,
    root_handle: File,
    _lock: File,
    epoch: String,
    next: AtomicU64,
    healthy: AtomicBool,
}

#[derive(Debug)]
pub(super) struct Generation {
    // Every pending or leased generation retains the exclusive store owner.
    storage: Arc<Storage>,
    root: PathBuf,
    target: PathBuf,
    sequence: u64,
    committed: bool,
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn ordinary_path(path: &Path) -> io::Result<()> {
    require(
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "target cache requires an absolute path without traversal",
    )?;
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        require(
            fs::symlink_metadata(&prefix)?.is_dir(),
            "target cache path contains a symlink or non-directory",
        )?;
    }
    Ok(())
}

fn private_path(path: &Path, directory: bool) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.uid() == rustix::process::geteuid().as_raw()
            && if directory {
                metadata.is_dir() && metadata.mode() & 0o7777 == 0o700
            } else {
                metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o7777 == 0o600
            },
        "target cache storage must be private, ordinary, unaliased and owned by the worker",
    )?;
    Ok(metadata)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino() && left.file_type() == right.file_type()
}

fn private_file(path: &Path) -> io::Result<File> {
    let named = private_path(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    require(
        same_file(&named, &file.metadata()?),
        "target cache metadata changed while opening",
    )?;
    Ok(file)
}

fn generation_name(sequence: u64) -> String {
    format!("{PREFIX}{sequence:016x}")
}

fn generation_sequence(name: &str) -> io::Result<u64> {
    let text = name
        .strip_prefix(PREFIX)
        .ok_or_else(|| invalid("unrelated data in target cache root"))?;
    let sequence = u64::from_str_radix(text, 16)
        .map_err(|_| invalid("invalid target cache generation name"))?;
    require(
        sequence != 0 && generation_name(sequence) == name,
        "noncanonical target cache generation name",
    )?;
    Ok(sequence)
}

impl Storage {
    pub(super) fn open(
        root: &Path,
        max_bytes: u64,
        epoch: &str,
    ) -> io::Result<(Arc<Self>, VecDeque<Arc<Seed>>)> {
        require(
            !epoch.is_empty()
                && epoch.len() <= 128
                && epoch.as_bytes()[0].is_ascii_alphanumeric()
                && epoch
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "target cache epoch must be 1..128 ASCII letters/digits/dots/underscores/hyphens, beginning with a letter or digit",
        )?;
        require(
            root.file_name().is_some(),
            "target cache requires a dedicated named directory",
        )?;
        let parent = root
            .parent()
            .ok_or_else(|| invalid("target cache has no parent"))?;
        ordinary_path(parent)?;
        match fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(root)?;
                File::open(parent)?.sync_all()?;
            }
            Err(error) => return Err(error),
        }
        ordinary_path(root)?;
        private_path(root, true)?;
        let root_handle = File::open(root)?;
        let lock_path = root.join(LOCK);
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
        {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                private_path(&lock_path, false)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                    .open(&lock_path)?
            }
            Err(error) => return Err(error),
        };
        let named = private_path(&lock_path, false)?;
        require(
            named.len() == 0 && same_file(&named, &lock.metadata()?),
            "invalid target cache owner lock",
        )?;
        lock.try_lock()?;
        lock.sync_all()?;
        root_handle.sync_all()?;
        let storage = Arc::new(Self {
            root: root.to_path_buf(),
            root_handle,
            _lock: lock,
            epoch: epoch.to_owned(),
            next: AtomicU64::new(1),
            healthy: AtomicBool::new(true),
        });
        storage.verify_owner()?;
        let mut generations = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_name() == LOCK {
                continue;
            }
            require(
                generations.len() < MAX_TARGET_CACHE_ENTRIES,
                "target cache exceeds its generation bound",
            )?;
            let name = entry.file_name();
            let sequence = generation_sequence(
                name.to_str()
                    .ok_or_else(|| invalid("non-UTF8 target generation"))?,
            )?;
            private_path(&entry.path(), true)?;
            generations.push(sequence);
        }
        generations.sort_unstable();
        if let Some(last) = generations.last() {
            storage.next.store(
                last.checked_add(1)
                    .ok_or_else(|| invalid("target generation counter overflow"))?,
                Ordering::Release,
            );
        }
        let mut entries: VecDeque<Arc<Seed>> = VecDeque::new();
        let mut bytes = 0_u64;
        for sequence in generations {
            // A dedicated cache namespace does not authorize deleting unrelated
            // sibling data. Unknown generation-level names require operator
            // attention; only target/ and our two metadata files are reclaimable.
            storage.validate_generation(sequence)?;
            match storage.load(sequence) {
                Ok(Some(seed)) => {
                    bytes = bytes
                        .checked_add(seed.tree.bytes)
                        .ok_or_else(|| invalid("target cache size overflow"))?;
                    entries.push_back(Arc::new(seed));
                }
                Ok(None) => storage.remove_generation(sequence)?,
                Err(error) => {
                    eprintln!(
                        "{}",
                        json!({"kind":"worker-target-state-recovery-refused", "generation":sequence, "error":error.to_string()})
                    );
                    storage.remove_generation(sequence)?;
                }
            }
        }
        // Lowered budgets and epoch rotations recover in the same namespace.
        // Never admit new copies while stale/unfinished payload remains uncharged.
        while bytes > max_bytes {
            let seed = entries.pop_front().expect("positive retained byte count");
            seed.tree.directory.retire()?;
            bytes -= seed.tree.bytes;
        }
        eprintln!(
            "{}",
            json!({"kind":"worker-target-state-recovered", "entries":entries.len(), "retained_bytes":bytes})
        );
        Ok((storage, entries))
    }

    pub(super) fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    fn verify_owner(&self) -> io::Result<()> {
        let root = private_path(&self.root, true)?;
        let lock = private_path(&self.root.join(LOCK), false)?;
        require(
            same_file(&root, &self.root_handle.metadata()?)
                && same_file(&lock, &self._lock.metadata()?),
            "target cache owner path changed",
        )
    }

    fn failed(&self, error: &io::Error) {
        self.healthy.store(false, Ordering::Release);
        eprintln!(
            "{}",
            json!({"kind":"worker-target-state-storage-disabled", "error":error.to_string()})
        );
    }

    pub(super) fn allocate(self: &Arc<Self>) -> io::Result<Generation> {
        require(
            self.healthy(),
            "target cache storage needs recovery before further writes",
        )?;
        self.verify_owner()?;
        let sequence = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                next.checked_add(1)
            })
            .map_err(|_| invalid("target cache generation counter overflow"))?;
        let root = self.root.join(generation_name(sequence));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let generation = Generation {
            storage: Arc::clone(self),
            target: root.join("target"),
            root,
            sequence,
            committed: false,
        };
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&generation.target)?;
        Ok(generation)
    }

    fn remove_generation(&self, sequence: u64) -> io::Result<()> {
        use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, openat2, unlinkat};
        let result = (|| {
            self.verify_owner()?;
            let name = generation_name(sequence);
            let root = self.root.join(&name);
            match fs::symlink_metadata(&root) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
                Ok(_) => {
                    self.validate_generation(sequence)?;
                }
            }
            let directory = File::from(openat2(
                &self.root_handle,
                name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )?);
            // Unpublish first. A crash during reclamation leaves an incomplete
            // generation that recovery removes, never a partially deleted hit.
            match unlinkat(&directory, COMMITTED, AtFlags::empty()) {
                Ok(()) => directory.sync_all()?,
                Err(error) if error == rustix::io::Errno::NOENT => {}
                Err(error) => return Err(error.into()),
            }
            // A corrupt target may contain links, special files or an accidental
            // mount. Unlink leaf names through anchored parent descriptors; never
            // follow links or descend into another mount during reclamation.
            let mut count = 0;
            remove_contents(&directory, &mut count, 0)?;
            unlinkat(&self.root_handle, name.as_str(), AtFlags::REMOVEDIR)?;
            self.root_handle.sync_all()
        })();
        if let Err(error) = &result {
            self.failed(error);
        }
        result
    }

    fn validate_generation(&self, sequence: u64) -> io::Result<()> {
        let root = self.root.join(generation_name(sequence));
        private_path(&root, true)?;
        for (count, entry) in fs::read_dir(&root)?.enumerate() {
            require(count < 3, "unexpected target generation entries")?;
            let name = entry?.file_name();
            require(
                name == "target" || name == PENDING || name == COMMITTED,
                "unrelated target generation entry",
            )?;
        }
        Ok(())
    }

    fn load(self: &Arc<Self>, sequence: u64) -> io::Result<Option<Seed>> {
        let root = self.root.join(generation_name(sequence));
        self.validate_generation(sequence)?;
        match fs::symlink_metadata(root.join(COMMITTED)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        require(
            !root.join(PENDING).try_exists()?,
            "generation contains both pending and completed metadata",
        )?;
        let mut file = private_file(&root.join(COMMITTED))?;
        require(
            file.metadata()?.len() <= MAX_METADATA_BYTES,
            "target cache metadata exceeds its bound",
        )?;
        let mut data = Vec::new();
        (&mut file)
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut data)?;
        require(
            data.len() as u64 <= MAX_METADATA_BYTES,
            "target cache metadata grew beyond its bound",
        )?;
        let envelope: Value = serde_json::from_slice(&data)?;
        let payload = envelope
            .get("seed")
            .ok_or_else(|| invalid("missing target seed metadata"))?;
        require(
            envelope.as_object().is_some_and(|value| value.len() == 2),
            "invalid target metadata envelope",
        )?;
        let digest = decode_digest(&envelope["sha256"])?;
        require(
            <[u8; 32]>::from(Sha256::digest(serde_json::to_vec(payload)?)) == digest,
            "target cache metadata checksum differs",
        )?;
        require(
            payload["schema"].as_str() == Some(SCHEMA),
            "unsupported persistent target schema",
        )?;
        require(
            payload["generation"].as_u64() == Some(sequence),
            "target generation identity differs",
        )?;
        if payload["epoch"].as_str() != Some(self.epoch.as_str()) {
            return Ok(None);
        }
        private_path(&root.join("target"), true)?;
        let seed = decode_seed(
            payload,
            Generation {
                storage: Arc::clone(self),
                target: root.join("target"),
                root,
                sequence,
                committed: true,
            },
        )?;
        // Actual disk bytes, names and topology must agree BEFORE quota accepts
        // metadata. Restore rechecks them again while copying to private output.
        verify_tree(&seed.tree, false, &|| false)?;
        Ok(Some(seed))
    }
}

fn remove_contents(directory: &File, count: &mut usize, depth: usize) -> io::Result<()> {
    use rustix::fs::{AtFlags, Dir, Mode, OFlags, ResolveFlags, openat2, unlinkat};
    require(depth <= 33, "target cleanup depth exceeds its bound")?;
    let mut entries = Dir::read_from(directory)?;
    while let Some(entry) = entries.read() {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        *count += 1;
        require(
            *count <= MAX_TREE_ENTRIES + 3,
            "target cleanup entry bound exceeded",
        )?;
        let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV;
        let observed = File::from(openat2(
            directory,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )?);
        let metadata = observed.metadata()?;
        require(
            metadata.uid() == rustix::process::geteuid().as_raw(),
            "target cleanup encountered a different owner",
        )?;
        if metadata.is_dir() {
            let child = File::from(openat2(
                directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                resolve,
            )?);
            require(
                same_file(&metadata, &child.metadata()?),
                "target cleanup directory changed",
            )?;
            remove_contents(&child, count, depth + 1)?;
            unlinkat(directory, name, AtFlags::REMOVEDIR)?;
        } else {
            unlinkat(directory, name, AtFlags::empty())?;
        }
    }
    directory.sync_all()
}

impl Generation {
    pub(super) fn path(&self) -> &Path {
        &self.target
    }

    pub(super) fn prepare(&self, seed: &Seed, stopped: &impl Fn() -> bool) -> io::Result<()> {
        self.storage.verify_owner()?;
        require(
            self.storage.healthy() && !self.committed,
            "target generation is not writable staging",
        )?;
        verify_tree(&seed.tree, true, stopped)?;
        let payload = encode_seed(seed, self.sequence, &self.storage.epoch);
        let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&payload)?).into();
        let bytes = serde_json::to_vec(
            &json!({"seed":payload, "sha256":crate::source_transfer::hex(&digest)}),
        )?;
        require(
            bytes.len() as u64 <= MAX_METADATA_BYTES,
            "target cache metadata exceeds its bound",
        )?;
        checkpoint(stopped)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.root.join(PENDING))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        self.storage.root_handle.sync_all()?;
        checkpoint(stopped)
    }

    pub(super) fn publish(&mut self) -> io::Result<()> {
        let result = (|| {
            require(
                self.storage.healthy() && !self.committed,
                "target cache storage cannot publish this generation",
            )?;
            self.storage.verify_owner()?;
            private_path(&self.root, true)?;
            private_path(&self.root.join(PENDING), false)?;
            require(
                !self.root.join(COMMITTED).try_exists()?,
                "target generation already published",
            )?;
            fs::rename(self.root.join(PENDING), self.root.join(COMMITTED))?;
            File::open(&self.root)?.sync_all()?;
            self.committed = true;
            Ok(())
        })();
        if let Err(error) = &result {
            self.storage.failed(error);
        }
        result
    }

    pub(super) fn retire(&self) -> io::Result<()> {
        self.storage.remove_generation(self.sequence)
    }
}

impl Drop for Generation {
    fn drop(&mut self) {
        if !self.committed {
            // Failure poisons storage before the enclosing reservation is freed.
            let _ = self.retire();
        }
    }
}

fn encode_time(time: SystemTime) -> Value {
    let (negative, duration) = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (false, duration),
        Err(error) => (true, error.duration()),
    };
    json!([negative, duration.as_secs(), duration.subsec_nanos()])
}

fn decode_time(value: &Value) -> io::Result<SystemTime> {
    let row = row(value, 3)?;
    let negative = row[0]
        .as_bool()
        .ok_or_else(|| invalid("invalid target timestamp sign"))?;
    let seconds = number(&row[1])?;
    let nanos = number(&row[2])?;
    require(
        nanos < 1_000_000_000 && !(negative && seconds == 0 && nanos == 0),
        "invalid target timestamp precision",
    )?;
    let duration = Duration::new(seconds, nanos as u32);
    if negative {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
    .ok_or_else(|| invalid("target timestamp is out of range"))
}

fn encode_directories(directories: &BTreeMap<String, StoredDirectory>) -> Vec<Value> {
    directories
        .iter()
        .map(|(name, directory)| json!([name, directory.mode, encode_time(directory.modified)]))
        .collect()
}

fn encode_seed(seed: &Seed, sequence: u64, epoch: &str) -> Value {
    let source: Vec<_> = seed
        .source_manifest
        .files()
        .iter()
        .map(|file| {
            json!([
                file.path,
                file.len,
                crate::source_transfer::hex(&file.sha256),
                file.executable,
                encode_time(seed.source.files[&file.path]),
            ])
        })
        .collect();
    let files: Vec<_> = seed
        .tree
        .files
        .iter()
        .map(|(name, file)| {
            json!([
                name,
                file.len,
                crate::source_transfer::hex(&file.digest),
                file.mode,
                encode_time(file.modified),
                file.link_to,
            ])
        })
        .collect();
    json!({
        "schema":SCHEMA, "epoch":epoch, "generation":sequence,
        "key":crate::source_transfer::hex(&seed.key.0),
        "compatible":seed.compatible.map(|key| crate::source_transfer::hex(&key.0)),
        "edit_family":seed.edit_family.map(|digest| crate::source_transfer::hex(&digest)),
        "source":source, "source_directories":encode_directories(&seed.source.directories),
        "files":files, "directories":encode_directories(&seed.tree.directories), "bytes":seed.tree.bytes,
    })
}

fn row(value: &Value, length: usize) -> io::Result<&[Value]> {
    value
        .as_array()
        .filter(|row| row.len() == length)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("invalid target metadata row"))
}

fn rows(value: &Value, limit: usize) -> io::Result<&[Value]> {
    value
        .as_array()
        .filter(|rows| rows.len() <= limit)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("target metadata row bound exceeded"))
}

fn text(value: &Value) -> io::Result<&str> {
    value
        .as_str()
        .ok_or_else(|| invalid("invalid target metadata string"))
}

fn number(value: &Value) -> io::Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| invalid("invalid target metadata number"))
}

fn decode_digest(value: &Value) -> io::Result<[u8; 32]> {
    let value = text(value)?;
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid target metadata digest",
    )?;
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("invalid target digest"))?;
    }
    Ok(result)
}

fn optional_digest(value: &Value) -> io::Result<Option<[u8; 32]>> {
    if value.is_null() {
        Ok(None)
    } else {
        decode_digest(value).map(Some)
    }
}

fn mode(value: &Value, directory: bool) -> io::Result<u32> {
    let mode = number(value)?;
    require(
        mode <= 0o777 && (!directory || mode & 0o700 == 0o700),
        "invalid target permissions",
    )?;
    Ok(mode as u32)
}

fn decode_directories(value: &Value) -> io::Result<BTreeMap<String, StoredDirectory>> {
    let mut directories = BTreeMap::new();
    for value in rows(value, MAX_TREE_ENTRIES + 1)? {
        let row = row(value, 3)?;
        let name = text(&row[0])?;
        if !name.is_empty() {
            validate_tree_names([name])?;
        }
        let directory = StoredDirectory {
            mode: mode(&row[1], true)?,
            modified: decode_time(&row[2])?,
        };
        require(
            directories.insert(name.to_owned(), directory).is_none(),
            "duplicate target directory",
        )?;
    }
    require(
        directories.contains_key(""),
        "target metadata lacks its root directory",
    )?;
    Ok(directories)
}

fn validate_layout<'a>(
    files: impl Iterator<Item = &'a str>,
    directories: &BTreeMap<String, StoredDirectory>,
) -> io::Result<()> {
    let names = validate_tree_names(files)?;
    require(
        names.len() + directories.len() <= MAX_TREE_ENTRIES + 1,
        "target metadata tree entry bound exceeded",
    )?;
    let mut folded = BTreeMap::new();
    for name in directories.keys().chain(names.iter()) {
        require(
            folded.insert(name.to_lowercase(), name).is_none(),
            "aliased or overlapping target paths",
        )?;
        if name.is_empty() {
            continue;
        }
        let parent = name.rsplit_once('/').map_or("", |(parent, _)| parent);
        require(
            directories.contains_key(parent),
            "target metadata omits a parent directory",
        )?;
    }
    Ok(())
}

fn decode_seed(payload: &Value, generation: Generation) -> io::Result<Seed> {
    const FIELDS: [&str; 11] = [
        "schema",
        "epoch",
        "generation",
        "key",
        "compatible",
        "edit_family",
        "source",
        "source_directories",
        "files",
        "directories",
        "bytes",
    ];
    require(
        payload.as_object().is_some_and(|value| {
            value.len() == FIELDS.len() && FIELDS.iter().all(|name| value.contains_key(*name))
        }),
        "invalid target seed fields",
    )?;
    let mut source_files = Vec::new();
    let mut times = BTreeMap::new();
    for value in rows(&payload["source"], MAX_SOURCE_FILES)? {
        let row = row(value, 5)?;
        let path = text(&row[0])?.to_owned();
        require(
            times.insert(path.clone(), decode_time(&row[4])?).is_none(),
            "duplicate source timestamp",
        )?;
        source_files.push(SourceFile {
            path,
            len: number(&row[1])?,
            sha256: decode_digest(&row[2])?,
            executable: row[3]
                .as_bool()
                .ok_or_else(|| invalid("invalid source executable flag"))?,
        });
    }
    let source_manifest =
        SourceManifest::new(source_files).map_err(|error| invalid(&error.to_string()))?;
    let source_directories = decode_directories(&payload["source_directories"])?;
    validate_layout(times.keys().map(String::as_str), &source_directories)?;
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for value in rows(&payload["files"], MAX_TREE_FILES)? {
        let row = row(value, 6)?;
        let name = text(&row[0])?.to_owned();
        let file = StoredFile {
            len: number(&row[1])?,
            digest: decode_digest(&row[2])?,
            mode: mode(&row[3], false)?,
            modified: decode_time(&row[4])?,
            link_to: if row[5].is_null() {
                None
            } else {
                Some(text(&row[5])?.to_owned())
            },
        };
        total = total
            .checked_add(file.len)
            .ok_or_else(|| invalid("target metadata size overflow"))?;
        require(
            total <= MAX_ARTIFACT_BYTES && files.insert(name, file).is_none(),
            "duplicate or oversized target file metadata",
        )?;
    }
    require(
        number(&payload["bytes"])? == total,
        "target metadata byte count differs",
    )?;
    let directories = decode_directories(&payload["directories"])?;
    validate_layout(files.keys().map(String::as_str), &directories)?;
    for (name, file) in &files {
        if let Some(first) = &file.link_to {
            let prior = files
                .get(first)
                .ok_or_else(|| invalid("target alias is outside this generation"))?;
            require(
                first < name
                    && prior.link_to.is_none()
                    && prior.len == file.len
                    && prior.digest == file.digest
                    && prior.mode == file.mode
                    && prior.modified == file.modified,
                "inconsistent target alias metadata",
            )?;
        }
    }
    Ok(Seed {
        key: TargetKey(decode_digest(&payload["key"])?),
        compatible: optional_digest(&payload["compatible"])?.map(TargetKey),
        source: SourceTimes {
            files: times,
            directories: source_directories,
        },
        source_manifest,
        edit_family: optional_digest(&payload["edit_family"])?,
        tree: TreeSnapshot {
            directory: SnapshotDirectory::Durable(generation),
            files,
            directories,
            bytes: total,
        },
        invalidated: AtomicBool::new(false),
    })
}

fn verify_tree(snapshot: &TreeSnapshot, sync: bool, stopped: &impl Fn() -> bool) -> io::Result<()> {
    let required = snapshot.files.keys().cloned().collect();
    let tree = TreeInventory::scan(
        snapshot.directory.path(),
        &required,
        snapshot.bytes,
        stopped,
    )?;
    require(
        tree.names().eq(snapshot.files.keys().map(String::as_str))
            && tree.total_bytes() == snapshot.bytes,
        "persistent target file closure differs",
    )?;
    let mut aliases = BTreeMap::new();
    for (name, expected) in &snapshot.files {
        checkpoint(stopped)?;
        let mut file = tree.open_file(name)?;
        let metadata = file.metadata()?;
        require(
            metadata.uid() == rustix::process::geteuid().as_raw(),
            "persistent target file has a different owner",
        )?;
        let identity = (metadata.dev(), metadata.ino());
        let link_to = aliases.get(&identity).cloned();
        let stored = StoredFile {
            len: metadata.len(),
            digest: hash_copy(&mut file, &mut io::sink(), metadata.len(), stopped)?,
            mode: metadata.mode() & 0o7777,
            modified: metadata.modified()?,
            link_to,
        };
        require(
            &stored == expected,
            "persistent target file bytes, timestamp, permissions or aliases differ",
        )?;
        aliases.entry(identity).or_insert_with(|| name.clone());
        tree.verify_file(name, &file)?;
        if sync {
            file.sync_all()?;
        }
    }
    require(
        directory_times(&tree)? == snapshot.directories,
        "persistent target directory metadata differs",
    )?;
    for name in tree.directory_names() {
        require(
            tree.open_directory(name)?.metadata()?.uid() == rustix::process::geteuid().as_raw(),
            "persistent target directory has a different owner",
        )?;
    }
    if sync {
        for name in snapshot.directories.keys().rev() {
            checkpoint(stopped)?;
            tree.open_directory(name)?.sync_all()?;
        }
    }
    tree.verify(stopped)
}
