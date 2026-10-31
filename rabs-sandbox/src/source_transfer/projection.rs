//! Process-owned read-only execution projections of verified source transfers.
//!
//! A projection key describes the exact files, modes and complete directory
//! topology of one mounted tree. It deliberately excludes unrelated artifacts
//! in the transfer. This is materialization reuse, never action-cache authority.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

type Key = [u8; 32];

fn lock<T>(mutex: &Mutex<T>) -> io::Result<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| io::Error::other("source projection pool lock poisoned"))
}

#[derive(Debug)]
struct Projection {
    prefix: String,
    files: Vec<SourceFile>,
    directories: Vec<String>,
    key: Key,
    bytes: u64,
}

impl Projection {
    fn select(source: &SourceReceiver, prefix: &str, directories: &[String]) -> io::Result<Self> {
        if source.sealed_root().is_none() || source.poisoned {
            return Err(invalid("source projection requires a sealed receiver"));
        }
        let root = prefix
            .strip_suffix('/')
            .ok_or_else(|| invalid("source projection prefix must end in a slash"))?;
        // Reuse the transport's bounded path grammar, including all parents.
        let mut parents = Vec::new();
        for (offset, _) in root.match_indices('/') {
            parents.push(root[..offset].to_owned());
        }
        parents.push(root.to_owned());
        crate::generated_source::validate_generated_directories(&parents)?;
        crate::generated_source::validate_generated_directories(directories)?;
        let mut bytes = 0_u64;
        let mut files = Vec::new();
        for file in source.manifest().files() {
            let Some(name) = file.path.strip_prefix(prefix) else {
                continue;
            };
            if directories
                .binary_search_by(|dir| dir.as_str().cmp(name))
                .is_ok()
            {
                return Err(invalid("source projection file is also a directory"));
            }
            for (offset, _) in name.match_indices('/') {
                if directories
                    .binary_search_by(|dir| dir.as_str().cmp(&name[..offset]))
                    .is_err()
                {
                    return Err(invalid("source projection omits a file parent"));
                }
            }
            bytes = bytes
                .checked_add(file.len)
                .ok_or_else(|| invalid("source projection size overflow"))?;
            files.push(SourceFile {
                path: name.to_owned(),
                ..file.clone()
            });
        }
        let mut hash = Sha256::new();
        hash.update(b"rabs.source-projection.v1\0");
        hash.update((prefix.len() as u64).to_be_bytes());
        hash.update(prefix.as_bytes());
        hash.update((files.len() as u64).to_be_bytes());
        for file in &files {
            hash.update((file.path.len() as u64).to_be_bytes());
            hash.update(file.path.as_bytes());
            hash.update(file.len.to_be_bytes());
            hash.update(file.sha256);
            hash.update([u8::from(file.executable)]);
        }
        hash.update((directories.len() as u64).to_be_bytes());
        for directory in directories {
            hash.update((directory.len() as u64).to_be_bytes());
            hash.update(directory.as_bytes());
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            files,
            directories: directories.to_vec(),
            key: hash.finalize().into(),
            bytes,
        })
    }

    fn members(&self) -> usize {
        // Charge both private container and mount root, including empty trees.
        2 + self.files.len() + self.directories.len()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Cost {
    bytes: u64,
    images: usize,
    members: usize,
}

#[derive(Debug)]
struct Quota {
    limit: Cost,
    used: Mutex<Cost>,
}

impl Quota {
    fn reserve(self: &Arc<Self>, projection: &Projection) -> io::Result<Option<Allocation>> {
        let cost = Cost {
            bytes: projection.bytes,
            images: 1,
            members: projection.members(),
        };
        let mut used = lock(&self.used)?;
        if used.bytes.saturating_add(cost.bytes) > self.limit.bytes
            || used.images.saturating_add(cost.images) > self.limit.images
            || used.members.saturating_add(cost.members) > self.limit.members
        {
            return Ok(None);
        }
        used.bytes += cost.bytes;
        used.images += cost.images;
        used.members += cost.members;
        Ok(Some(Allocation {
            quota: Arc::clone(self),
            cost,
            reclaim: true,
        }))
    }
}

/// Credit follows the actual image owner, including invalidated generations
/// still held by executions. Removing a lookup entry cannot refund this credit.
#[derive(Debug)]
struct Allocation {
    quota: Arc<Quota>,
    cost: Cost,
    reclaim: bool,
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if self.reclaim {
            let mut used = self
                .quota
                .used
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            used.bytes -= self.cost.bytes;
            used.images -= self.cost.images;
            used.members -= self.cost.members;
        }
    }
}

/// A retained path is usable only while its original private owner still names
/// the held directory. Membership changes here are legitimate pool operations;
/// membership inside each completed image is checked against a fixed witness.
#[derive(Debug)]
struct Parent {
    temporary: Option<tempfile::TempDir>,
    path: PathBuf,
    directory: File,
    metadata: fs::Metadata,
    preserve: AtomicBool,
    retention_lock: Option<Arc<File>>,
}

impl Parent {
    fn create(parent: &Path) -> io::Result<Self> {
        private_directory(parent)?;
        let parent = fs::canonicalize(parent)?;
        let mut temporary = tempfile::Builder::new();
        temporary.prefix(SOURCE_PROJECTION_PREFIX);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary.permissions(fs::Permissions::from_mode(0o700));
        }
        let temporary = temporary.tempdir_in(parent)?;
        private_directory(temporary.path())?;
        let path = temporary.path().to_path_buf();
        let directory = open_root(&path)?;
        let metadata = directory.metadata()?;
        let owner = Self {
            temporary: Some(temporary),
            path,
            directory,
            metadata,
            preserve: AtomicBool::new(false),
            retention_lock: None,
        };
        owner.verify()?;
        Ok(owner)
    }

    fn verify(&self) -> io::Result<()> {
        private_directory(&self.path)?;
        let current = fs::symlink_metadata(&self.path)?;
        if fs::canonicalize(&self.path)? != self.path
            || !same_identity(&self.metadata, &current)
            || !same_identity(&self.metadata, &self.directory.metadata()?)
        {
            return Err(invalid("source projection pool parent was replaced"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.mode() != self.metadata.mode()
                || current.uid() != self.metadata.uid()
                || current.gid() != self.metadata.gid()
            {
                return Err(invalid("source projection pool parent ownership changed"));
            }
        }
        Ok(())
    }
}

impl Drop for Parent {
    fn drop(&mut self) {
        let preserve = self.preserve.load(Ordering::Acquire) || self.verify().is_err();
        let failed = if let Some(directory) = self.temporary.take() {
            if preserve {
                // Never remove a replacement belonging to another owner.
                let _ = directory.keep();
                true
            } else {
                directory.close().is_err()
            }
        } else {
            false
        };
        if failed && let Some(guard) = self.retention_lock.take() {
            // Orphaned storage still consumes the domain allowance. Quarantine
            // its writer reservation until process exit, including close errors.
            std::mem::forget(guard);
        }
    }
}

#[derive(Debug)]
struct ImageOwner {
    temporary: Option<tempfile::TempDir>,
    directory: File,
    parent: Arc<Parent>,
    allocation: Allocation,
}

impl ImageOwner {
    fn create(parent: Arc<Parent>, allocation: Allocation) -> io::Result<Self> {
        parent.verify()?;
        let mut temporary = tempfile::Builder::new();
        temporary.prefix("image-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary.permissions(fs::Permissions::from_mode(0o700));
        }
        let temporary = temporary.tempdir_in(&parent.path)?;
        let directory = open_root(temporary.path())?;
        Ok(Self {
            temporary: Some(temporary),
            directory,
            parent,
            allocation,
        })
    }

    fn path(&self) -> &Path {
        self.temporary.as_ref().expect("live image owner").path()
    }

    fn verify(&self) -> io::Result<()> {
        self.parent.verify()?;
        private_directory(self.path())?;
        if fs::canonicalize(self.path())? != self.path() {
            return Err(invalid("source projection image parent is aliased"));
        }
        check_root(self.path(), &self.directory)
    }
}

impl Drop for ImageOwner {
    fn drop(&mut self) {
        let owned = self.verify().is_ok();
        if let Some(directory) = self.temporary.take() {
            if !owned {
                let _ = directory.keep();
                // An unlocatable original may still occupy disk. Keep its
                // reservation charged instead of manufacturing free capacity.
                self.allocation.reclaim = false;
            } else if directory.close().is_err() {
                self.allocation.reclaim = false;
            }
            if !self.allocation.reclaim {
                // The final pool owner must not recursively delete a child
                // whose image owner deliberately refused to remove it.
                self.parent.preserve.store(true, Ordering::Release);
            }
        }
    }
}

#[derive(Debug)]
struct Image {
    owner: ImageOwner,
    root: PathBuf,
    directory: File,
    container_metadata: fs::Metadata,
    directories: BTreeMap<String, fs::Metadata>,
    files: BTreeMap<String, fs::Metadata>,
    projection: Projection,
}

fn open_directory(root: &Path, directory: &File, name: &str) -> io::Result<File> {
    check_root(root, directory)?;
    let mut held = directory.try_clone()?;
    let mut path = root.to_path_buf();
    if !name.is_empty() {
        for component in name.split('/') {
            held = open_member(&held, &path, OsStr::new(component), true, FileAccess::Read)?;
            path.push(component);
        }
    }
    Ok(held)
}

impl Image {
    fn capture(
        owner: ImageOwner,
        source: &SourceReceiver,
        projection: Projection,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        checkpoint(stopped)?;
        owner.verify()?;
        // Cargo's shared-output validation uses the package basename when
        // connecting retained artifact mounts to the original transfer owner.
        let root = owner.path().join(
            projection
                .prefix
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap(),
        );
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root)?;
        let directory = open_root(&root)?;
        for name in &projection.directories {
            checkpoint(stopped)?;
            builder.create(root.join(name))?;
        }
        let mut source_states = Vec::with_capacity(projection.files.len());
        let mut files = BTreeMap::new();
        let mut buffer = [0_u8; MAX_SOURCE_CHUNK];
        for expected in &projection.files {
            checkpoint(stopped)?;
            let source_name = format!("{}{}", projection.prefix, expected.path);
            let mut input = open_source(
                &source.root,
                &source.root_directory,
                &source_name,
                FileAccess::Read,
            )?;
            let before = input.metadata()?;
            ordinary_file(&before, expected.len)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if (before.permissions().mode() & 0o111 != 0) != expected.executable {
                    return Err(invalid("source projection executable mode changed"));
                }
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options.open(root.join(&expected.path))?;
            let mut remaining = expected.len;
            let mut hash = Sha256::new();
            while remaining != 0 {
                checkpoint(stopped)?;
                let count = remaining.min(buffer.len() as u64) as usize;
                input.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count]);
                output.write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
            if input.read(&mut buffer[..1])? != 0
                || <[u8; 32]>::from(hash.finalize()) != expected.sha256
                || !same_state(&before, &input.metadata()?)
            {
                return Err(invalid("source projection bytes changed during copy"));
            }
            // Set final permissions BEFORE verifying the independent copy.
            // Capture its witness from the descriptor spanning the hash read;
            // a later pathname open or chmod must not bless an unseen mutation.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                output.set_permissions(fs::Permissions::from_mode(if expected.executable {
                    0o555
                } else {
                    0o444
                }))?;
            }
            output.rewind()?;
            let verified = output.metadata()?;
            ordinary_file(&verified, expected.len)?;
            let mut remaining = expected.len;
            let mut hash = Sha256::new();
            while remaining != 0 {
                checkpoint(stopped)?;
                let count = remaining.min(buffer.len() as u64) as usize;
                output.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count]);
                remaining -= count as u64;
            }
            if output.read(&mut buffer[..1])? != 0
                || <[u8; 32]>::from(hash.finalize()) != expected.sha256
                || !same_state(&verified, &output.metadata()?)
            {
                return Err(invalid("source projection copy failed verification"));
            }
            files.insert(expected.path.clone(), verified);
            source_states.push((source_name, before));
        }
        for (name, before) in source_states {
            checkpoint(stopped)?;
            let current = open_source(
                &source.root,
                &source.root_directory,
                &name,
                FileAccess::Read,
            )?;
            if !same_state(&before, &current.metadata()?) {
                return Err(invalid("source projection source generation changed"));
            }
        }
        let mut directories = BTreeMap::new();
        for name in std::iter::once("").chain(projection.directories.iter().map(String::as_str)) {
            checkpoint(stopped)?;
            directories.insert(
                name.to_owned(),
                open_directory(&root, &directory, name)?.metadata()?,
            );
        }
        let container_metadata = owner.directory.metadata()?;
        let image = Self {
            owner,
            root,
            directory,
            container_metadata,
            directories,
            files,
            projection,
        };
        image.verify(stopped)?;
        Ok(image)
    }

    fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        self.owner.verify()?;
        if !same_state(&self.container_metadata, &self.owner.directory.metadata()?) {
            return Err(invalid("source projection container membership changed"));
        }
        let mut found = BTreeSet::new();
        for (name, original) in &self.directories {
            checkpoint(stopped)?;
            let directory = open_directory(&self.root, &self.directory, name)?;
            if !same_state(original, &directory.metadata()?) {
                return Err(invalid("source projection directory generation changed"));
            }
            each_child(&directory, &self.root.join(name), |basename| {
                checkpoint(stopped)?;
                let basename = basename
                    .to_str()
                    .ok_or_else(|| invalid("source projection has an undeclared member"))?;
                let relative = if name.is_empty() {
                    basename.to_owned()
                } else {
                    format!("{name}/{basename}")
                };
                if (!self.files.contains_key(&relative)
                    && !self.directories.contains_key(&relative))
                    || !found.insert(relative)
                {
                    return Err(invalid("source projection membership changed"));
                }
                Ok(())
            })?;
        }
        if found.len() + 1 != self.files.len() + self.directories.len() {
            return Err(invalid("source projection lost a declared member"));
        }
        for (name, original) in &self.files {
            checkpoint(stopped)?;
            let file = open_source(&self.root, &self.directory, name, FileAccess::Read)?;
            if !same_state(original, &file.metadata()?) {
                return Err(invalid("source projection file generation changed"));
            }
        }
        // Fence directory membership again after the complete bounded walk.
        for (name, original) in self.directories.iter().rev() {
            checkpoint(stopped)?;
            if !same_state(
                original,
                &open_directory(&self.root, &self.directory, name)?.metadata()?,
            ) {
                return Err(invalid("source projection changed during verification"));
            }
        }
        self.owner.verify()?;
        checkpoint(stopped)
    }
}

/// Strong execution owner of one exact read-only projection. Cloning a lease
/// retains the same generation and its quota until every execution releases it.
#[derive(Debug, Clone)]
pub struct SourceProjectionLease(Arc<Image>);

impl SourceProjectionLease {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.0.root
    }

    /// Protect the complete pool against writable physical aliases, including
    /// siblings of this image. The private parent is checked on every verify.
    #[must_use]
    pub fn protected_parent(&self) -> &Path {
        &self.0.owner.parent.path
    }

    pub fn verify(&self, stopped: impl Fn() -> bool) -> io::Result<()> {
        self.0.verify(&stopped)
    }

    /// Compare a fresh request's exact projection contract, without treating an
    /// arbitrary host path or the surrounding transfer digest as authority.
    pub fn matches(
        &self,
        source: &SourceReceiver,
        prefix: &str,
        directories: &[String],
    ) -> io::Result<bool> {
        Ok(self.0.projection.key == Projection::select(source, prefix, directories)?.key)
    }

    #[must_use]
    pub fn file_count(&self) -> usize {
        self.0.files.len()
    }

    #[must_use]
    pub fn directories(&self) -> &[String] {
        &self.0.projection.directories
    }
}

#[derive(Debug)]
enum Entry {
    Capturing(u64),
    Ready { image: Arc<Image>, used: u64 },
}

#[derive(Debug, Default)]
struct State {
    entries: BTreeMap<Key, Entry>,
    clock: u64,
}

/// Bounded process-local materialization reuse. Reservations precede copies;
/// active leases, pending captures and invalidated generations all remain
/// charged. Capacity pressure uses the caller's ordinary private projection.
#[derive(Debug)]
pub struct SourceProjectionPool {
    parent: Arc<Parent>,
    quota: Arc<Quota>,
    state: Mutex<State>,
    changed: Condvar,
}

struct Capture<'a> {
    pool: &'a SourceProjectionPool,
    key: Key,
    ticket: u64,
}

impl Drop for Capture<'_> {
    fn drop(&mut self) {
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if matches!(state.entries.get(&self.key), Some(Entry::Capturing(ticket)) if *ticket == self.ticket)
        {
            state.entries.remove(&self.key);
        }
        self.pool.changed.notify_all();
    }
}

impl SourceProjectionPool {
    /// Create a new owned pool below a configured private worker directory.
    /// Byte, image and member limits include captures and retired generations.
    pub fn new(
        parent: &Path,
        max_bytes: u64,
        max_images: usize,
        max_members: usize,
    ) -> io::Result<Self> {
        if !parent.is_absolute()
            || max_bytes == 0
            || max_bytes > 8 * 1024 * 1024 * 1024
            || !(1..=256).contains(&max_images)
            || !(2..=1_048_576).contains(&max_members)
        {
            return Err(invalid(
                "source projection pool limits are outside their bounds",
            ));
        }
        Ok(Self {
            parent: Arc::new(Parent::create(parent)?),
            quota: Arc::new(Quota {
                limit: Cost {
                    bytes: max_bytes,
                    images: max_images,
                    members: max_members,
                },
                used: Mutex::new(Cost::default()),
            }),
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        })
    }

    /// Keep an already acquired process-shared capacity lock until this pool
    /// and its final execution lease have released their owned images. The
    /// caller retains responsibility for acquiring/validating that lock; it is
    /// not source identity or publication authority. Set only before first use.
    pub fn with_retention_lock(mut self, guard: Arc<File>) -> io::Result<Self> {
        let parent = Arc::get_mut(&mut self.parent)
            .filter(|parent| parent.retention_lock.is_none())
            .ok_or_else(|| invalid("source projection retention lock is already in use"))?;
        parent.retention_lock = Some(guard);
        Ok(self)
    }

    /// Protect every retained image even when this request uses private inputs.
    pub fn protected_parent(&self) -> io::Result<&Path> {
        self.parent.verify()?;
        Ok(&self.parent.path)
    }

    /// Acquire exactly the declared projection. Same-key captures coalesce;
    /// cancellation abandons only this caller's wait/capture. An invalid warm
    /// generation is retired and can only be replaced by another verified copy.
    /// `None` means capacity or the source filesystem cohort cannot admit this
    /// image, never a reusable proof. Cross-filesystem caches use private inputs.
    pub fn acquire(
        &self,
        source: &SourceReceiver,
        prefix: &str,
        directories: &[String],
        stopped: impl Fn() -> bool,
    ) -> io::Result<Option<SourceProjectionLease>> {
        let projection = Projection::select(source, prefix, directories)?;
        self.parent.verify()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if self.parent.directory.metadata()?.dev() != source.root_directory.metadata()?.dev() {
                checkpoint(&stopped)?;
                return Ok(None);
            }
        }
        if projection.bytes > self.quota.limit.bytes
            || projection.members() > self.quota.limit.members
        {
            checkpoint(&stopped)?;
            return Ok(None);
        }
        loop {
            checkpoint(&stopped)?;
            self.parent.verify()?;
            let mut state = lock(&self.state)?;
            state.clock = state.clock.wrapping_add(1);
            let ticket = state.clock;
            match state.entries.get_mut(&projection.key) {
                Some(Entry::Ready { image, used }) => {
                    *used = ticket;
                    // Clone under the same mutex as eviction. Weak references
                    // cannot race the active-lease check and resurrect an image.
                    let image = Arc::clone(image);
                    drop(state);
                    match image.verify(&stopped) {
                        Ok(()) => return Ok(Some(SourceProjectionLease(image))),
                        Err(error) => {
                            checkpoint(&stopped)?;
                            let mut state = lock(&self.state)?;
                            let retired = if matches!(state.entries.get(&projection.key), Some(Entry::Ready { image: current, .. }) if Arc::ptr_eq(current, &image))
                            {
                                state.entries.remove(&projection.key)
                            } else {
                                None
                            };
                            drop(state);
                            drop(retired);
                            drop(image);
                            // Parent damage cannot be repaired by recopying a
                            // child under the same untrusted name.
                            self.parent.verify().map_err(|_| error)?;
                            continue;
                        }
                    }
                }
                Some(Entry::Capturing(_)) => {
                    let (state, _) = self
                        .changed
                        .wait_timeout(state, Duration::from_millis(20))
                        .map_err(|_| io::Error::other("source projection wait poisoned"))?;
                    drop(state);
                    continue;
                }
                None => {}
            }
            let allocation = self.quota.reserve(&projection)?;
            let Some(allocation) = allocation else {
                let victim = state
                    .entries
                    .iter()
                    .filter_map(|(key, entry)| match entry {
                        Entry::Ready { image, used } if Arc::strong_count(image) == 1 => {
                            Some((*key, *used))
                        }
                        _ => None,
                    })
                    .min_by_key(|(_, used)| *used)
                    .map(|(key, _)| key);
                if let Some(victim) = victim {
                    let removed = state.entries.remove(&victim);
                    drop(state);
                    drop(removed);
                    continue;
                }
                checkpoint(&stopped)?;
                return Ok(None);
            };
            state
                .entries
                .insert(projection.key, Entry::Capturing(ticket));
            drop(state);
            let capture = Capture {
                pool: self,
                key: projection.key,
                ticket,
            };
            let owner = ImageOwner::create(Arc::clone(&self.parent), allocation)?;
            let image = Arc::new(Image::capture(owner, source, projection, &stopped)?);
            checkpoint(&stopped)?;
            let mut state = lock(&self.state)?;
            if !matches!(state.entries.get(&capture.key), Some(Entry::Capturing(current)) if *current == ticket)
            {
                return Err(invalid("source projection capture lost its reservation"));
            }
            state.entries.insert(
                capture.key,
                Entry::Ready {
                    image: Arc::clone(&image),
                    used: ticket,
                },
            );
            drop(state);
            drop(capture);
            checkpoint(&stopped)?;
            return Ok(Some(SourceProjectionLease(image)));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
