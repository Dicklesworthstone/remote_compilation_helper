//! Measured Linux host compatibility for remote leaf rustc execution.
//!
//! The transferred toolchain covers rustc and its internal libraries, but not
//! the host ELF interpreter, libc or other libraries exposed through /usr.
//! Resolve the actual ELF runtime with a clean, bounded loader probe, hash
//! stable external library bytes, and bind stable CPU/kernel/filesystem facts.
//! Internal paths are relative to the retained toolchain: physical placement
//! does not participate in identity.
//!
//! Observation and retention share the same byte and topology measurement.
//! A worker can retain a private sparse runtime and expose only those selected
//! libraries and its captured loader cache in the dependency namespace. This
//! is not discovery of arbitrary dlopen, locale, NSS, /proc or /dev reads; the
//! metadata-only eligibility gate and separate input-closure checks still apply.
//! No hostname, PID, core count, frequency, load or configured label is keyed.

use rabs_protocol::result_identity::TypedDigest;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

mod pool;
pub use pool::{MAX_RETAINED_RUNTIMES, RuntimeLease, RuntimePool, RuntimeRequest};

/// Fixed identity domain shared with the remote dependency key builder.
pub const RUNTIME_COHORT_DOMAIN: &str = "rabs.rustc-host-runtime.v2";

/// An observation that cannot support remote result publication.
#[derive(Debug)]
pub enum RuntimeCohortError {
    /// The platform or loader format is outside this observer's contract.
    Unsupported(&'static str),
    /// Missing, inconsistent, changing or excessive observation data.
    Invalid(&'static str),
    /// Filesystem or bounded process observation failed.
    Io(io::Error),
}

impl fmt::Display for RuntimeCohortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(detail) => write!(formatter, "runtime cohort unsupported: {detail}"),
            Self::Invalid(detail) => write!(formatter, "runtime cohort invalid: {detail}"),
            Self::Io(error) => write!(formatter, "runtime cohort observation: {error}"),
        }
    }
}

impl std::error::Error for RuntimeCohortError {}

impl From<io::Error> for RuntimeCohortError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Observe the host runtime used by one retained compiler.
///
/// Paths are physical local paths. On the edge, supply the complete original
/// ordered LD_LIBRARY_PATH alongside the original compiler/toolchain root,
/// including independently witnessed safe output and parent directories.
/// This preserves actual loader failures and selection: no source component
/// is silently stripped before probing. Missing directories require a fresh
/// absence check and remain in the probe's search string. On the worker,
/// toolchain entries are rebased to its retained physical root; witnessed
/// private-empty namespace aliases may be omitted from the physical probe.
///
/// Any library actually resolved outside the toolchain must still be in the
/// supported /usr runtime roots. The adapter must separately refuse empty loader
/// components, other LD_* controls and GLIBC_TUNABLES, and must retain and
/// revalidate every non-toolchain loader-directory witness through execution.
///
/// The filesystem root is a writable private staging directory on the source
/// and output materialization filesystem. An owned child probes actual case,
/// Unicode and timestamp behavior and is removed on return. Stable filesystem
/// type and name limits are bound; path names and free space are not.
///
/// Keep the toolchain immutable across observation and compilation. External
/// host libraries are stable-read and path-revalidated during observation;
/// rerun after compilation to detect a changed cohort.
///
/// # Errors
/// Refuses non-Linux/non-ELF hosts, unresolved libraries, unsupported probe
/// output, unclosed loader paths, changing files and exhausted bounds.
pub fn observe_runtime_cohort(
    compiler: &Path,
    toolchain_root: &Path,
    loader_search_paths: &[PathBuf],
    filesystem_root: &Path,
) -> Result<TypedDigest, RuntimeCohortError> {
    #[cfg(target_os = "linux")]
    {
        linux::observe(
            compiler,
            toolchain_root,
            loader_search_paths,
            filesystem_root,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            compiler,
            toolchain_root,
            loader_search_paths,
            filesystem_root,
        );
        Err(RuntimeCohortError::Unsupported(
            "Linux ELF runtime required",
        ))
    }
}

/// Owned, bounded runtime bytes for one dependency execution lifetime.
///
/// The private backing directory must outlive every child and output drain.
/// Its path is intentionally not exposed as a writable workspace capability.
/// Call `verify` after execution and before accepting a result.
pub struct RetainedRuntime {
    // Keep construction private even where the Linux implementation is absent.
    _private: (),
    #[cfg(target_os = "linux")]
    inner: linux::RuntimeSnapshot,
}

impl RetainedRuntime {
    /// Compatibility identity measured from the bytes actually retained.
    pub fn cohort(&self) -> &TypedDigest {
        #[cfg(target_os = "linux")]
        {
            &self.inner.cohort
        }
        #[cfg(not(target_os = "linux"))]
        {
            unreachable!("retained runtimes can only be constructed on Linux")
        }
    }

    /// Revalidate every owned entry and its bytes without trusting host libraries.
    ///
    /// # Errors
    /// Refuses cancellation, missing/extra/changed entries and replaced owners.
    pub fn verify(&self, cancelled: impl Fn() -> bool) -> Result<(), RuntimeCohortError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.verify(&cancelled)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cancelled;
            Err(RuntimeCohortError::Unsupported(
                "Linux ELF runtime required",
            ))
        }
    }

    /// Verify the retained bytes against this execution's output filesystem.
    ///
    /// A runtime lease can outlive the output directory used for its original
    /// capture. Reuse must measure the current attempt's filesystem and CPU/
    /// kernel contract, never an earlier attempt's disposable path.
    ///
    /// # Errors
    /// Has [`Self::verify`]'s refusals, including a changed filesystem class.
    pub fn verify_on_filesystem(
        &self,
        filesystem_root: &Path,
        cancelled: impl Fn() -> bool,
    ) -> Result<(), RuntimeCohortError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.verify_on_filesystem(filesystem_root, &cancelled)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (filesystem_root, cancelled);
            Err(RuntimeCohortError::Unsupported(
                "Linux ELF runtime required",
            ))
        }
    }

    fn remove_owned(&self) -> Result<(), RuntimeCohortError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.owner.remove_owned()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(RuntimeCohortError::Unsupported(
                "Linux ELF runtime required",
            ))
        }
    }

    pub(crate) fn append_mounts(
        &self,
        args: &mut Vec<OsString>,
        writable_backings: &[PathBuf],
    ) -> Result<(), RuntimeCohortError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.append_mounts(args, writable_backings)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (args, writable_backings);
            Err(RuntimeCohortError::Unsupported(
                "Linux ELF runtime required",
            ))
        }
    }

    /// Launch strict namespaces through the compiler's measured ELF interpreter.
    /// Glibc otherwise needs /proc/self/exe to resolve the main ELF's $ORIGIN.
    /// This preserves the exact environment and keeps procfs outside that view.
    pub(crate) fn append_interpreter(
        &self,
        args: &mut Vec<OsString>,
    ) -> Result<(), RuntimeCohortError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.append_interpreter(args)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = args;
            Err(RuntimeCohortError::Unsupported(
                "Linux ELF runtime required",
            ))
        }
    }
}

/// Measure and retain the selected ELF runtime in a new private child.
///
/// `retention_parent` must be an existing directory owned by this worker and
/// not writable by other users. It must be separate from action-writable
/// backings; the namespace builder checks physical inode ancestry again.
///
/// # Errors
/// Has the observer's refusals, plus cancellation, unsafe retention ownership,
/// unavailable capacity and any failure to preserve the exact selected bytes.
pub fn retain_runtime_cohort(
    compiler: &Path,
    toolchain_root: &Path,
    loader_search_paths: &[PathBuf],
    filesystem_root: &Path,
    retention_parent: &Path,
    cancelled: impl Fn() -> bool,
) -> Result<RetainedRuntime, RuntimeCohortError> {
    #[cfg(target_os = "linux")]
    {
        Ok(RetainedRuntime {
            _private: (),
            inner: linux::retain(
                compiler,
                toolchain_root,
                loader_search_paths,
                filesystem_root,
                retention_parent,
                &cancelled,
            )?,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            compiler,
            toolchain_root,
            loader_search_paths,
            filesystem_root,
            retention_parent,
            cancelled,
        );
        Err(RuntimeCohortError::Unsupported(
            "Linux ELF runtime required",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::fs::{self, File, FileTimes, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::Component;
    use std::process::{Child, Command, ExitStatus, Output, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant, UNIX_EPOCH};

    const MAX_PROBE_BYTES: u64 = 64 * 1024;
    const MAX_CPUINFO_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_LIBRARIES: usize = 128;
    const MAX_LIBRARY_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_EXTERNAL_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_LOADER_CACHE_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_RUNTIME_ENTRIES: usize = 4096;
    static NEXT_PROBE: AtomicU64 = AtomicU64::new(1);

    fn invalid(detail: &'static str) -> RuntimeCohortError {
        RuntimeCohortError::Invalid(detail)
    }

    fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), RuntimeCohortError> {
        if cancelled() {
            return Err(invalid("runtime retention cancelled"));
        }
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct FileIdentity(u64, u64);

    impl FileIdentity {
        fn of(metadata: &fs::Metadata) -> Self {
            Self(metadata.dev(), metadata.ino())
        }
    }

    /// A create-new private child; the held root and parent descriptors prevent
    /// a replaced pathname from acquiring this owner's cleanup authority.
    pub(super) struct RuntimeDirectory {
        path: PathBuf,
        handle: File,
        parent_path: PathBuf,
        parent_handle: File,
        removed: AtomicBool,
        preserve: AtomicBool,
    }

    impl RuntimeDirectory {
        pub(super) fn new(parent: &Path) -> Result<Self, RuntimeCohortError> {
            if !parent.is_absolute() {
                return Err(invalid("runtime retention parent is not absolute"));
            }
            let parent_path = fs::canonicalize(parent)?;
            let parent_metadata = fs::symlink_metadata(&parent_path)?;
            if !parent_metadata.is_dir()
                || parent_metadata.uid() != rustix::process::geteuid().as_raw()
                || parent_metadata.mode() & 0o022 != 0
            {
                return Err(invalid(
                    "runtime retention parent is not worker-owned and private",
                ));
            }
            let open_directory = |path: &Path| -> io::Result<File> {
                rustix::fs::open(
                    path,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map(File::from)
                .map_err(Into::into)
            };
            let parent_handle = open_directory(&parent_path)?;
            if FileIdentity::of(&parent_handle.metadata()?) != FileIdentity::of(&parent_metadata) {
                return Err(invalid(
                    "runtime retention parent changed during acquisition",
                ));
            }
            for _ in 0..64 {
                let sequence = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
                let path =
                    parent_path.join(format!(".rabs-runtime-{}-{sequence}", std::process::id()));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {
                        let handle = open_directory(&path)?;
                        let result = Self {
                            path,
                            handle,
                            parent_path,
                            parent_handle,
                            removed: AtomicBool::new(false),
                            preserve: AtomicBool::new(false),
                        };
                        result.verify_owner()?;
                        return Ok(result);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(invalid("runtime retention child name budget exhausted"))
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        pub(super) fn preserve(&self) {
            self.preserve.store(true, Ordering::Release);
        }

        pub(super) fn remove_owned(&self) -> Result<(), RuntimeCohortError> {
            if self.removed.load(Ordering::Acquire) {
                return Ok(());
            }
            if self.preserve.load(Ordering::Acquire) {
                return Err(invalid(
                    "runtime storage requires retention after failed cleanup",
                ));
            }
            self.verify_owner()?;
            fs::remove_dir_all(&self.path)?;
            self.removed.store(true, Ordering::Release);
            Ok(())
        }

        pub(super) fn remove_empty(&self) -> Result<(), RuntimeCohortError> {
            if self.removed.load(Ordering::Acquire) {
                return Ok(());
            }
            if self.preserve.load(Ordering::Acquire) {
                return Err(invalid(
                    "runtime storage requires retention after failed cleanup",
                ));
            }
            self.verify_owner()?;
            // Pool containers may hold a capture whose inner owner refused
            // cleanup. Never recursively erase such an uncertain child.
            fs::remove_dir(&self.path)?;
            self.removed.store(true, Ordering::Release);
            Ok(())
        }

        pub(super) fn verify_owner(&self) -> Result<(), RuntimeCohortError> {
            if self.removed.load(Ordering::Acquire) {
                return Err(invalid("retained runtime owner was released"));
            }
            if self.preserve.load(Ordering::Acquire) {
                return Err(invalid("runtime storage is closed after uncertain cleanup"));
            }
            let held = self.handle.metadata()?;
            let named = fs::symlink_metadata(&self.path)?;
            let parent = fs::symlink_metadata(&self.parent_path)?;
            if !held.is_dir()
                || !named.is_dir()
                || !parent.is_dir()
                || held.uid() != rustix::process::geteuid().as_raw()
                || held.mode() & 0o777 != 0o700
                || parent.uid() != held.uid()
                || parent.mode() & 0o022 != 0
                || FileIdentity::of(&held) != FileIdentity::of(&named)
                || FileIdentity::of(&parent) != FileIdentity::of(&self.parent_handle.metadata()?)
            {
                return Err(invalid("retained runtime owner or parent was replaced"));
            }
            Ok(())
        }

        fn destination(&self, absolute: &Path) -> Result<PathBuf, RuntimeCohortError> {
            let relative = absolute
                .strip_prefix("/")
                .map_err(|_| invalid("runtime entry is not absolute"))?;
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err(invalid("runtime entry is not normalized"));
            }
            Ok(self.path.join(relative))
        }

        fn ensure_directory(&self, absolute: &Path) -> Result<(), RuntimeCohortError> {
            self.verify_owner()?;
            let mut path = self.path.clone();
            for component in absolute
                .strip_prefix("/")
                .map_err(|_| invalid("runtime directory is not absolute"))?
                .components()
            {
                let Component::Normal(name) = component else {
                    return Err(invalid("runtime directory is not normalized"));
                };
                path.push(name);
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&path)?;
                        if !metadata.is_dir()
                            || metadata.uid() != rustix::process::geteuid().as_raw()
                            || metadata.mode() & 0o777 != 0o700
                        {
                            return Err(invalid(
                                "runtime capture parent is not a private directory",
                            ));
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        }
    }

    impl Drop for RuntimeDirectory {
        fn drop(&mut self) {
            // Only the create-new child is reclaimed, never the supplied spill
            // parent. A replaced child or parent is left untouched.
            let _ = self.remove_owned();
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum RuntimeEntry {
        Directory,
        Symlink(PathBuf),
        File {
            bytes: u64,
            mode: u32,
            digest: [u8; 32],
        },
    }

    #[derive(Default)]
    struct RuntimeTree {
        entries: BTreeMap<PathBuf, RuntimeEntry>,
        interpreter: Option<PathBuf>,
    }

    impl RuntimeTree {
        fn insert(&mut self, path: PathBuf, entry: RuntimeEntry) -> Result<(), RuntimeCohortError> {
            if let Some(previous) = self.entries.get(&path) {
                if previous != &entry {
                    return Err(invalid("runtime topology changed during capture"));
                }
            } else {
                if self.entries.len() >= MAX_RUNTIME_ENTRIES {
                    return Err(invalid("runtime entry budget exhausted"));
                }
                self.entries.insert(path, entry);
            }
            Ok(())
        }

        fn finish(&self, owner: &RuntimeDirectory) -> Result<(), RuntimeCohortError> {
            // No symlink is installed until every ordinary file has been
            // written. Absolute source links can never redirect capture I/O.
            for (path, entry) in &self.entries {
                if matches!(entry, RuntimeEntry::Directory) {
                    owner.ensure_directory(path)?;
                }
            }
            for (path, entry) in &self.entries {
                if let RuntimeEntry::Symlink(target) = entry {
                    owner.verify_owner()?;
                    std::os::unix::fs::symlink(target, owner.destination(path)?)?;
                }
            }
            Ok(())
        }

        fn verify(
            &self,
            owner: &RuntimeDirectory,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<BTreeSet<FileIdentity>, RuntimeCohortError> {
            check_cancelled(cancelled)?;
            owner.verify_owner()?;
            let mut pending = vec![owner.path.clone()];
            let mut seen = BTreeSet::new();
            let mut identities = BTreeSet::from([FileIdentity::of(&owner.handle.metadata()?)]);
            let mut budget = MAX_EXTERNAL_BYTES;
            let mut checked = BTreeMap::new();
            while let Some(directory) = pending.pop() {
                check_cancelled(cancelled)?;
                checked.insert(
                    directory.clone(),
                    Stamp::of(&fs::symlink_metadata(&directory)?),
                );
                for item in fs::read_dir(&directory)? {
                    check_cancelled(cancelled)?;
                    let item = item?;
                    let physical = item.path();
                    let relative = physical
                        .strip_prefix(&owner.path)
                        .map_err(|_| invalid("runtime verification escaped owner"))?;
                    let path = Path::new("/").join(relative);
                    if !seen.insert(path.clone()) || seen.len() > MAX_RUNTIME_ENTRIES {
                        return Err(invalid("runtime verification entry budget exhausted"));
                    }
                    let expected = self
                        .entries
                        .get(&path)
                        .ok_or_else(|| invalid("unexpected retained runtime entry"))?;
                    let metadata = fs::symlink_metadata(&physical)?;
                    checked.insert(physical.clone(), Stamp::of(&metadata));
                    identities.insert(FileIdentity::of(&metadata));
                    if metadata.uid() != rustix::process::geteuid().as_raw() {
                        return Err(invalid("retained runtime entry ownership changed"));
                    }
                    match expected {
                        RuntimeEntry::Directory
                            if metadata.is_dir() && metadata.mode() & 0o777 == 0o700 =>
                        {
                            pending.push(physical)
                        }
                        RuntimeEntry::Symlink(target)
                            if metadata.is_symlink() && fs::read_link(&physical)? == *target => {}
                        RuntimeEntry::File {
                            bytes,
                            mode,
                            digest,
                        } if metadata.is_file()
                            && metadata.nlink() == 1
                            && metadata.len() == *bytes
                            && metadata.mode() & 0o777 == *mode =>
                        {
                            if stable_file(&physical, &mut budget, None, cancelled)?.digest
                                != *digest
                            {
                                return Err(invalid("retained runtime file bytes changed"));
                            }
                        }
                        _ => return Err(invalid("retained runtime entry changed")),
                    }
                }
            }
            if seen.len() != self.entries.len() {
                return Err(invalid("retained runtime entry is missing"));
            }
            for (path, before) in checked {
                check_cancelled(cancelled)?;
                if Stamp::of(&fs::symlink_metadata(path)?) != before {
                    return Err(invalid("retained runtime changed during verification"));
                }
            }
            owner.verify_owner()?;
            Ok(identities)
        }
    }

    pub(super) struct RuntimeSnapshot {
        pub(super) cohort: TypedDigest,
        pub(super) owner: RuntimeDirectory,
        tree: RuntimeTree,
        filesystem_root: PathBuf,
        ambient: Vec<u8>,
    }

    impl RuntimeSnapshot {
        pub(super) fn append_interpreter(
            &self,
            args: &mut Vec<OsString>,
        ) -> Result<(), RuntimeCohortError> {
            let interpreter = self
                .tree
                .interpreter
                .as_ref()
                .ok_or_else(|| invalid("runtime lacks its measured ELF interpreter"))?;
            args.push(interpreter.as_os_str().to_owned());
            Ok(())
        }

        pub(super) fn verify(
            &self,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<(), RuntimeCohortError> {
            self.verify_on_filesystem(&self.filesystem_root, cancelled)
        }

        pub(super) fn verify_on_filesystem(
            &self,
            filesystem_root: &Path,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<(), RuntimeCohortError> {
            self.tree.verify(&self.owner, cancelled)?;
            if ambient_profile(filesystem_root)? != self.ambient {
                return Err(invalid(
                    "runtime CPU, kernel or filesystem identity changed",
                ));
            }
            check_cancelled(cancelled)
        }

        pub(super) fn append_mounts(
            &self,
            args: &mut Vec<OsString>,
            writable_backings: &[PathBuf],
        ) -> Result<(), RuntimeCohortError> {
            let identities = self.tree.verify(&self.owner, &|| false)?;
            let root_ancestors = physical_ancestors(&self.owner.path)?;
            for backing in writable_backings {
                // Callers supply worker-owned output/home trees, without
                // preexisting nested mounts. Root ancestry checks also catch
                // bind aliases, which canonical path strings alone miss.
                if !backing.is_absolute() {
                    return Err(invalid("writable runtime neighbor is not absolute"));
                }
                let ancestors = physical_ancestors(backing)?;
                let backing_identity = *ancestors
                    .first()
                    .ok_or_else(|| invalid("missing writable backing identity"))?;
                if root_ancestors.contains(&backing_identity)
                    || ancestors
                        .iter()
                        .any(|identity| identities.contains(identity))
                {
                    return Err(invalid(
                        "writable backing physically overlaps retained runtime",
                    ));
                }
            }
            let mut mounts = Vec::new();
            for top in ["/usr", "/lib", "/lib64"] {
                match self.tree.entries.get(Path::new(top)) {
                    Some(RuntimeEntry::Directory) => mounts.extend([
                        OsString::from("--ro-bind"),
                        self.owner.destination(Path::new(top))?.into_os_string(),
                        OsString::from(top),
                    ]),
                    Some(RuntimeEntry::Symlink(target)) => mounts.extend([
                        OsString::from("--symlink"),
                        target.as_os_str().to_owned(),
                        OsString::from(top),
                    ]),
                    Some(RuntimeEntry::File { .. }) => {
                        return Err(invalid("runtime root is not a directory or alias"));
                    }
                    None => {}
                }
            }
            if self
                .tree
                .entries
                .contains_key(Path::new("/etc/ld.so.cache"))
            {
                mounts.extend([
                    OsString::from("--ro-bind"),
                    self.owner
                        .destination(Path::new("/etc/ld.so.cache"))?
                        .into_os_string(),
                    OsString::from("/etc/ld.so.cache"),
                ]);
            }
            self.owner.verify_owner()?;
            args.extend(mounts);
            Ok(())
        }
    }

    fn physical_ancestors(path: &Path) -> Result<Vec<FileIdentity>, RuntimeCohortError> {
        // Canonical strings alone miss bind aliases of a runtime directory or
        // its parent. Compare filesystem identity at each physical ancestor.
        let canonical = fs::canonicalize(path)?;
        canonical
            .ancestors()
            .map(|ancestor| {
                fs::metadata(ancestor)
                    .map(|metadata| FileIdentity::of(&metadata))
                    .map_err(Into::into)
            })
            .collect()
    }

    fn append(bytes: &mut Vec<u8>, field: &[u8]) {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field);
    }

    fn digest(bytes: &[u8]) -> TypedDigest {
        let mut hasher = Sha256::new();
        hasher.update(RUNTIME_COHORT_DOMAIN.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: RUNTIME_COHORT_DOMAIN,
            bytes: hasher.finalize().into(),
        }
    }

    fn bounded_read(reader: impl Read, maximum: u64) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        reader.take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err(io::Error::other("runtime observation byte limit exceeded"));
        }
        Ok(bytes)
    }

    fn read_system(path: &str, maximum: u64) -> Result<Vec<u8>, RuntimeCohortError> {
        bounded_read(crate::regular_input::open(Path::new(path))?, maximum).map_err(Into::into)
    }

    fn validated_search_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, RuntimeCohortError> {
        if paths.len() > 128 {
            return Err(invalid("too many loader search directories"));
        }
        let mut search = Vec::with_capacity(paths.len());
        for path in paths {
            let text = path
                .to_str()
                .ok_or_else(|| invalid("non-UTF-8 loader search directory"))?;
            if !text.starts_with('/')
                || text.len() <= 1
                || text.len() > 4096
                || text.contains(['\0', ':'])
                || text[1..]
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err(invalid(
                    "loader search directory is not normalized and absolute",
                ));
            }
            match fs::metadata(path) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => return Err(invalid("loader search entry is not a directory")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // ENOENT through a dangling/foreign alias is not a retained
                    // absence witness. The shared no-symlink observer confirms
                    // missing input paths before ldd receives the exact list.
                    crate::loader_directories::observe_loader_directories(
                        &[text.to_owned()],
                        || false,
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
            // Keep the original spelling and order. Canonicalizing/omitting a
            // search entry here could change the compiler's actual lookup.
            search.push(path.clone());
        }
        Ok(search)
    }

    fn elf_interpreter(file: &mut File) -> Result<PathBuf, RuntimeCohortError> {
        let size = file.metadata()?.len();
        let mut header = [0_u8; 64];
        file.rewind()?;
        file.read_exact(&mut header)?;
        if &header[..7] != b"\x7fELF\x02\x01\x01" {
            return Err(invalid("runtime requires a little-endian ELF64 compiler"));
        }
        let table = u64::from_le_bytes(header[32..40].try_into().unwrap());
        let width = u16::from_le_bytes(header[54..56].try_into().unwrap());
        let count = u16::from_le_bytes(header[56..58].try_into().unwrap());
        if width != 56
            || !(1..=128).contains(&count)
            || table < 64
            || table
                .checked_add(u64::from(width) * u64::from(count))
                .is_none_or(|end| end > size)
        {
            return Err(invalid("invalid or excessive ELF program header table"));
        }
        let mut interpreter = None;
        for index in 0..count {
            file.seek(SeekFrom::Start(table + u64::from(index) * 56))?;
            let mut program = [0_u8; 56];
            file.read_exact(&mut program)?;
            if u32::from_le_bytes(program[..4].try_into().unwrap()) != 3 {
                continue;
            }
            let offset = u64::from_le_bytes(program[8..16].try_into().unwrap());
            let bytes = u64::from_le_bytes(program[32..40].try_into().unwrap());
            if interpreter.is_some()
                || !(2..=4096).contains(&bytes)
                || offset.checked_add(bytes).is_none_or(|end| end > size)
            {
                return Err(invalid("invalid or duplicate ELF interpreter"));
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut path = vec![0_u8; usize::try_from(bytes).unwrap()];
            file.read_exact(&mut path)?;
            if path.pop() != Some(0) {
                return Err(invalid("ELF interpreter lacks its terminator"));
            }
            let path =
                std::str::from_utf8(&path).map_err(|_| invalid("ELF interpreter is not UTF-8"))?;
            if !path.starts_with('/')
                || path[1..]
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
                || path
                    .bytes()
                    .any(|byte| byte == 0 || byte.is_ascii_whitespace())
            {
                return Err(invalid("ELF interpreter is not a normalized absolute path"));
            }
            interpreter = Some(PathBuf::from(path));
        }
        interpreter.ok_or_else(|| invalid("compiler has no ELF interpreter"))
    }

    fn probe_targets(compiler: &Path, root: &Path) -> Result<Vec<PathBuf>, RuntimeCohortError> {
        // Backend DSOs may be dlopen-loaded even by a metadata-only compile.
        // Include their DT_NEEDED closure instead of assuming that ldd rustc
        // alone covers the runtime. The retained dataset owns their bytes.
        let mut targets = BTreeSet::from([compiler.to_path_buf()]);
        let mut entries_left = 4096_usize;
        let mut directories = vec![root.join("lib")];
        let rustlib = root.join("lib/rustlib");
        match fs::read_dir(&rustlib) {
            Ok(entries) => {
                for entry in entries {
                    entries_left = entries_left
                        .checked_sub(1)
                        .ok_or_else(|| invalid("runtime enumeration entry budget exhausted"))?;
                    let path = entry?.path().join("codegen-backends");
                    match fs::metadata(&path) {
                        Ok(metadata) if metadata.is_dir() => directories.push(path),
                        Ok(_) => return Err(invalid("codegen backend root is not a directory")),
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                            ) => {}
                        Err(error) => return Err(error.into()),
                    }
                    if directories.len() > 128 {
                        return Err(invalid("too many codegen backend directories"));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        for directory in directories {
            let entries = match fs::read_dir(directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                entries_left = entries_left
                    .checked_sub(1)
                    .ok_or_else(|| invalid("runtime enumeration entry budget exhausted"))?;
                let entry = entry?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 runtime member name"))?;
                if !name.starts_with("lib") || !name.contains(".so") {
                    continue;
                }
                let path = fs::canonicalize(entry.path())?;
                if !path.starts_with(root) || !fs::metadata(&path)?.is_file() {
                    return Err(invalid("runtime DSO leaves the retained toolchain"));
                }
                targets.insert(retained_probe_target(&path, root)?);
                if targets.len() > 32 {
                    return Err(invalid("too many retained runtime DSOs"));
                }
            }
        }
        Ok(targets.into_iter().collect())
    }

    fn retained_probe_target(path: &Path, root: &Path) -> Result<PathBuf, RuntimeCohortError> {
        let mut file = crate::regular_input::open(path)?;
        let before = Stamp::of(&file.metadata()?);
        let mut magic = [0_u8; 4];
        file.read_exact(&mut magic)?;
        let target = if magic == *b"\x7fELF" {
            path.to_path_buf()
        } else {
            // Official Rust distributions include a short libLLVM*.so GNU
            // linker-script alias alongside the real versioned ELF library.
            // ldd rejects the script itself. Accept only one direct sibling
            // INPUT member and probe that actual ELF; never interpret linker
            // commands, searches, groups or arbitrary non-ELF DSO contents.
            if before.size > 4096 {
                return Err(invalid("non-ELF runtime DSO is not a bounded linker alias"));
            }
            let mut script = magic.to_vec();
            script.extend_from_slice(&bounded_read(&mut file, 4096 - 4)?);
            let script = std::str::from_utf8(&script)
                .map_err(|_| invalid("non-ELF runtime DSO is not a UTF-8 linker alias"))?
                .trim();
            let name = script
                .strip_prefix("INPUT(")
                .and_then(|script| script.strip_suffix(')'))
                .filter(|name| {
                    name.starts_with("lib")
                        && name.contains(".so")
                        && name.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                })
                .ok_or_else(|| invalid("unsupported runtime linker alias"))?;
            let target = fs::canonicalize(
                path.parent()
                    .ok_or_else(|| invalid("runtime linker alias has no parent"))?
                    .join(name),
            )?;
            if !target.starts_with(root) || target == path {
                return Err(invalid(
                    "runtime linker alias leaves its retained toolchain",
                ));
            }
            let mut elf = crate::regular_input::open(&target)?;
            let target_before = Stamp::of(&elf.metadata()?);
            elf.read_exact(&mut magic)?;
            if magic != *b"\x7fELF"
                || Stamp::of(&elf.metadata()?) != target_before
                || Stamp::of(&fs::metadata(&target)?) != target_before
            {
                return Err(invalid(
                    "runtime linker alias target is not a stable ELF file",
                ));
            }
            target
        };
        if Stamp::of(&file.metadata()?) != before || Stamp::of(&fs::metadata(path)?) != before {
            return Err(invalid("runtime probe target changed during acquisition"));
        }
        Ok(target)
    }

    fn without_probe_headers(
        output: &[u8],
        targets: &[PathBuf],
    ) -> Result<Vec<u8>, RuntimeCohortError> {
        let text = std::str::from_utf8(output).map_err(|_| invalid("non-UTF-8 loader output"))?;
        let mut flat = Vec::new();
        for line in text.lines() {
            if let Some(header) = line.trim().strip_suffix(':') {
                if !targets.iter().any(|path| path.to_str() == Some(header)) {
                    return Err(invalid("loader reported an unrequested probe target"));
                }
                continue;
            }
            flat.extend_from_slice(line.as_bytes());
            flat.push(b'\n');
        }
        Ok(flat)
    }

    struct ProbeChild {
        child: Child,
        unreaped: bool,
    }

    impl ProbeChild {
        fn finish(&mut self) -> io::Result<ExitStatus> {
            use rustix::process::{Pid, Signal, kill_process_group};
            // The leader has not been reaped: its PID still pins this group's
            // identity, including while it is a zombie. Never signal a cached
            // numeric PID after wait() makes it available for reuse.
            let signal = kill_process_group(Pid::from_child(&self.child), Signal::KILL);
            if signal.is_err_and(|error| error != rustix::io::Errno::SRCH) {
                let _ = self.child.kill();
            }
            let status = self.child.wait();
            self.unreaped = false;
            match signal {
                Ok(()) | Err(rustix::io::Errno::SRCH) => status,
                Err(error) => Err(error.into()),
            }
        }
    }

    impl Drop for ProbeChild {
        fn drop(&mut self) {
            if self.unreaped {
                let _ = self.finish();
            }
        }
    }

    fn read_probe_lane(reader: &mut impl Read, bytes: &mut Vec<u8>) -> io::Result<bool> {
        let maximum = usize::try_from(MAX_PROBE_BYTES)
            .map_err(|_| io::Error::other("runtime observation byte limit is unrepresentable"))?;
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return Ok(true),
                Ok(count) => {
                    bytes.extend_from_slice(&buffer[..count]);
                    if bytes.len() > maximum {
                        return Err(io::Error::other("runtime observation byte limit exceeded"));
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn capture_probe_process(command: &mut Command, budget: Duration) -> io::Result<Output> {
        use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
        command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let mut owner = ProbeChild {
            child: command.spawn()?,
            unreaped: true,
        };
        let mut stdout = owner
            .child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing probe stdout"))?;
        let mut stderr = owner
            .child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing probe stderr"))?;
        fcntl_setfl(&stdout, fcntl_getfl(&stdout)? | OFlags::NONBLOCK)?;
        fcntl_setfl(&stderr, fcntl_getfl(&stderr)? | OFlags::NONBLOCK)?;
        let (mut output, mut errors) = (Vec::new(), Vec::new());
        let (mut stdout_eof, mut stderr_eof) = (false, false);
        let completion = (|| -> io::Result<()> {
            loop {
                if started.elapsed() >= budget {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "ELF loader probe exceeded its deadline",
                    ));
                }
                if !stdout_eof {
                    stdout_eof = read_probe_lane(&mut stdout, &mut output)?;
                }
                if !stderr_eof {
                    stderr_eof = read_probe_lane(&mut stderr, &mut errors)?;
                }
                match waitid(
                    WaitId::Pid(Pid::from_child(&owner.child)),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                ) {
                    Ok(Some(_)) if stdout_eof && stderr_eof => return Ok(()),
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(error) => {
                        // An external reaper can invalidate numeric signal
                        // ownership. Refuse and close our nonblocking pipes.
                        if error == rustix::io::Errno::CHILD {
                            owner.unreaped = false;
                        }
                        return Err(error.into());
                    }
                }
                std::thread::sleep(
                    Duration::from_millis(2).min(budget.saturating_sub(started.elapsed())),
                );
            }
        })();
        let status = if owner.unreaped {
            owner.finish()
        } else {
            Err(io::Error::other("loader probe lost child ownership"))
        };
        // Close every group writer before returning. A successful leader
        // whose descendant still holds a pipe cannot turn partial output into
        // a successful observation; both EOFs share the original deadline.
        completion?;
        let status = status?;
        Ok(Output {
            status,
            stdout: output,
            stderr: errors,
        })
    }

    fn capture_probe(command: &mut Command, budget: Duration) -> io::Result<Output> {
        let started = Instant::now();
        let watchdog = if Path::new("/usr/bin/gnutimeout").try_exists()? {
            "/usr/bin/gnutimeout"
        } else {
            "/usr/bin/timeout"
        };
        let mut version = Command::new(watchdog);
        version
            .arg("--version")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("LANG", "C");
        let identity = capture_probe_process(&mut version, budget)?;
        if !identity.status.success()
            || !identity.stderr.is_empty()
            || !identity.stdout.starts_with(b"timeout (GNU coreutils)")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ELF runtime probes require GNU Coreutils timeout (gnutimeout or timeout)",
            ));
        }
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "ELF loader probe exceeded its deadline",
            ));
        }
        // This independent watchdog survives an abrupt death of its Rust
        // owner. Native draining alone cannot enforce a deadline after SIGKILL.
        // Its budget shares the original deadline with capability discovery.
        let mut watched = Command::new(watchdog);
        watched
            .arg("--signal=KILL")
            .arg(format!("{}s", remaining.as_secs_f64()))
            .arg(command.get_program())
            .args(command.get_args())
            .env_clear();
        for (name, value) in command.get_envs() {
            if let Some(value) = value {
                watched.env(name, value);
            }
        }
        if let Some(directory) = command.get_current_dir() {
            watched.current_dir(directory);
        }
        capture_probe_process(&mut watched, remaining)
    }

    fn probe(targets: &[PathBuf], search: &[PathBuf]) -> Result<Vec<u8>, RuntimeCohortError> {
        // Fixed tool and clean environment: daemon PATH/LD_* never select the
        // probe or change resolution. Own bounded draining and retain a GNU
        // watchdog for parent death, all under the original five-second budget.
        let mut command = Command::new("/usr/bin/ldd");
        command
            .arg("--")
            .args(targets)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !search.is_empty() {
            command.env(
                "LD_LIBRARY_PATH",
                std::env::join_paths(search).map_err(|_| invalid("invalid loader search path"))?,
            );
        }
        let output = capture_probe(&mut command, Duration::from_secs(5))?;
        if !output.status.success() {
            return Err(
                io::Error::other(format!("ELF loader probe failed: {}", output.status)).into(),
            );
        }
        if !output.stderr.is_empty() {
            return Err(invalid(
                "ELF loader probe reported unresolved runtime evidence",
            ));
        }
        without_probe_headers(&output.stdout, targets)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Library {
        name: String,
        path: PathBuf,
    }

    fn libraries(
        stdout: &[u8],
        toolchain_root: Option<&Path>,
    ) -> Result<Vec<Library>, RuntimeCohortError> {
        let stdout = std::str::from_utf8(stdout).map_err(|_| invalid("non-UTF-8 loader output"))?;
        let mut result = BTreeMap::new();
        for line in stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let (entry, address) = line
                .rsplit_once(" (")
                .ok_or_else(|| invalid("unresolved or unsupported ELF loader output"))?;
            address
                .strip_suffix(')')
                .and_then(|value| value.strip_prefix("0x"))
                .filter(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .ok_or_else(|| invalid("invalid ELF loader address"))?;
            if matches!(entry, "linux-vdso.so.1" | "linux-gate.so.1") {
                continue; // Actual kernel ABI is bound below; ASLR is not.
            }
            let (name, path) = entry.split_once(" => ").unwrap_or((entry, entry));
            if name.is_empty()
                || name.bytes().any(|byte| byte.is_ascii_whitespace())
                || (name.starts_with('/') && name != path)
                || !path.starts_with('/')
                || path.len() > 4096
                || path[1..]
                    .split('/')
                    .any(|part| part.is_empty() || part == ".")
                || path
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte == 0)
            {
                return Err(invalid("nonabsolute or unrepresentable ELF library path"));
            }
            if result.len() >= MAX_LIBRARIES && !result.contains_key(name) {
                return Err(invalid("too many runtime libraries"));
            }
            let path = if path.split('/').any(|part| part == "..") {
                // Official rustc RPATHs use $ORIGIN/../lib. Resolve those
                // aliases only inside the complete retained toolchain. Every
                // traversed prefix must remain inside it, including after a
                // symlink or parent component; host-library traversal remains
                // refused. The caller retains and revalidates this whole tree.
                let root = toolchain_root
                    .ok_or_else(|| invalid("unbound ELF library parent traversal"))?;
                let relative = Path::new(path)
                    .strip_prefix(root)
                    .map_err(|_| invalid("ELF library parent traversal outside toolchain"))?;
                if name.starts_with('/') {
                    return Err(invalid("ELF interpreter parent traversal is unsupported"));
                }
                let mut resolved = root.to_path_buf();
                for component in relative.components() {
                    resolved = fs::canonicalize(resolved.join(component.as_os_str()))?;
                    if !resolved.starts_with(root) {
                        return Err(invalid("ELF library traversal leaves retained toolchain"));
                    }
                }
                resolved
            } else {
                PathBuf::from(path)
            };
            if let Some(previous) = result.insert(name.to_owned(), path.clone())
                && previous != path
            {
                return Err(invalid("one ELF library name resolves to different paths"));
            }
        }
        if result.is_empty() {
            return Err(invalid("ELF loader did not report a runtime closure"));
        }
        Ok(result
            .into_iter()
            .map(|(name, path)| Library { name, path })
            .collect())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        size: u64,
        mode: u32,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    impl Stamp {
        fn of(metadata: &fs::Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.len(),
                mode: metadata.mode(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
    }

    struct StableFile {
        digest: [u8; 32],
        stamp: Stamp,
    }

    fn stable_file(
        path: &Path,
        budget: &mut u64,
        destination: Option<&Path>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<StableFile, RuntimeCohortError> {
        check_cancelled(cancelled)?;
        let mut held = crate::regular_input::open(path)?;
        let before = Stamp::of(&held.metadata()?);
        if before.size > MAX_LIBRARY_BYTES || before.size > *budget {
            return Err(invalid("external runtime exceeds its byte budget"));
        }
        *budget -= before.size;
        let mut output = destination
            .map(|destination| {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(destination)
            })
            .transpose()?;
        let mut copied = 0_u64;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            check_cancelled(cancelled)?;
            let count = held.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied
                .checked_add(count as u64)
                .filter(|count| *count <= before.size)
                .ok_or_else(|| invalid("runtime library grew during observation"))?;
            hasher.update(&buffer[..count]);
            if let Some(output) = &mut output {
                // Copy and identity consume the same held-file read. A second
                // pathname read can never silently substitute captured bytes.
                output.write_all(&buffer[..count])?;
            }
        }
        if copied != before.size
            || Stamp::of(&held.metadata()?) != before
            || Stamp::of(&fs::metadata(path)?) != before
        {
            return Err(invalid("runtime library changed during observation"));
        }
        if let Some(output) = output {
            output.set_permissions(fs::Permissions::from_mode(before.mode & 0o777))?;
        }
        Ok(StableFile {
            digest: hasher.finalize().into(),
            stamp: before,
        })
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SourceWitness {
        stamp: Stamp,
        symlink: Option<PathBuf>,
    }

    struct Measurement<'a> {
        owner: Option<&'a RuntimeDirectory>,
        tree: RuntimeTree,
        witnesses: BTreeMap<PathBuf, SourceWitness>,
        budget: u64,
    }

    impl<'a> Measurement<'a> {
        fn new(owner: Option<&'a RuntimeDirectory>) -> Self {
            Self {
                owner,
                tree: RuntimeTree::default(),
                witnesses: BTreeMap::new(),
                budget: MAX_EXTERNAL_BYTES,
            }
        }

        fn witness(
            &mut self,
            path: &Path,
            metadata: &fs::Metadata,
            symlink: Option<PathBuf>,
        ) -> Result<(), RuntimeCohortError> {
            let witness = SourceWitness {
                stamp: Stamp::of(metadata),
                symlink,
            };
            if let Some(previous) = self.witnesses.get(path) {
                if previous != &witness {
                    return Err(invalid(
                        "runtime source topology changed during observation",
                    ));
                }
            } else {
                if self.witnesses.len() >= MAX_RUNTIME_ENTRIES {
                    return Err(invalid("runtime source entry budget exhausted"));
                }
                self.witnesses.insert(path.to_path_buf(), witness);
            }
            Ok(())
        }

        fn verify_sources(&self, cancelled: &dyn Fn() -> bool) -> Result<(), RuntimeCohortError> {
            for (path, expected) in &self.witnesses {
                check_cancelled(cancelled)?;
                let metadata = fs::symlink_metadata(path)?;
                if Stamp::of(&metadata) != expected.stamp {
                    return Err(invalid("runtime source changed during observation"));
                }
                if let Some(target) = &expected.symlink
                    && fs::read_link(path)? != *target
                {
                    return Err(invalid("runtime source alias changed during observation"));
                }
            }
            Ok(())
        }

        fn trace(
            &mut self,
            path: &Path,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<PathBuf, RuntimeCohortError> {
            if !path.is_absolute() {
                return Err(invalid("runtime topology path is not absolute"));
            }
            let mut pending: VecDeque<_> = path
                .components()
                .filter_map(|component| match component {
                    Component::RootDir => None,
                    _ => Some(component.as_os_str().to_owned()),
                })
                .collect();
            let mut current = PathBuf::from("/");
            let mut links = 0_u32;
            while let Some(part) = pending.pop_front() {
                check_cancelled(cancelled)?;
                if part == "." {
                    continue;
                }
                if part == ".." {
                    if !current.pop() {
                        return Err(invalid("runtime alias escapes the filesystem root"));
                    }
                    continue;
                }
                current.push(part);
                if current.as_os_str().len() > 4096 {
                    return Err(invalid("runtime alias path budget exhausted"));
                }
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.is_symlink() {
                    links += 1;
                    if links > 40 {
                        return Err(invalid("runtime alias traversal budget exhausted"));
                    }
                    let target = fs::read_link(&current)?;
                    if target.as_os_str().is_empty()
                        || target.as_os_str().len() > 4096
                        || target.to_str().is_none()
                    {
                        return Err(invalid("runtime alias target is unrepresentable"));
                    }
                    self.witness(&current, &metadata, Some(target.clone()))?;
                    self.tree
                        .insert(current.clone(), RuntimeEntry::Symlink(target.clone()))?;
                    if target.is_absolute() {
                        current = PathBuf::from("/");
                    } else {
                        current.pop();
                    }
                    for component in target.components().rev() {
                        if !matches!(component, Component::RootDir) {
                            pending.push_front(component.as_os_str().to_owned());
                        }
                    }
                } else {
                    self.witness(&current, &metadata, None)?;
                    if metadata.is_dir() {
                        self.tree.insert(current.clone(), RuntimeEntry::Directory)?;
                    } else if !metadata.is_file() || !pending.is_empty() {
                        return Err(invalid(
                            "runtime topology contains a special or non-directory parent",
                        ));
                    }
                }
            }
            if !fs::symlink_metadata(&current)?.is_file() {
                return Err(invalid("runtime alias does not resolve to a regular file"));
            }
            Ok(current)
        }

        fn file(
            &mut self,
            path: &Path,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<[u8; 32], RuntimeCohortError> {
            if let Some(RuntimeEntry::File { digest, .. }) = self.tree.entries.get(path) {
                return Ok(*digest);
            }
            let destination = self
                .owner
                .map(|owner| {
                    owner.ensure_directory(
                        path.parent()
                            .ok_or_else(|| invalid("runtime file has no parent"))?,
                    )?;
                    owner.destination(path)
                })
                .transpose()?;
            let measured = stable_file(path, &mut self.budget, destination.as_deref(), cancelled)?;
            let witness = self
                .witnesses
                .get(path)
                .ok_or_else(|| invalid("runtime file was not traced"))?;
            if witness.stamp != measured.stamp {
                return Err(invalid(
                    "runtime file changed between topology and byte observation",
                ));
            }
            self.tree.insert(
                path.to_path_buf(),
                RuntimeEntry::File {
                    bytes: measured.stamp.size,
                    mode: measured.stamp.mode & 0o777,
                    digest: measured.digest,
                },
            )?;
            Ok(measured.digest)
        }

        fn loader_cache(&mut self, cache: &OptionalFile) -> Result<(), RuntimeCohortError> {
            let Some((_, stamp)) = &cache.file else {
                return Ok(());
            };
            self.budget = self
                .budget
                .checked_sub(stamp.size)
                .ok_or_else(|| invalid("runtime cache exceeds the byte budget"))?;
            let path = Path::new("/etc/ld.so.cache");
            self.tree
                .insert(PathBuf::from("/etc"), RuntimeEntry::Directory)?;
            let digest = Sha256::digest(&cache.bytes).into();
            self.tree.insert(
                path.to_path_buf(),
                RuntimeEntry::File {
                    bytes: stamp.size,
                    mode: stamp.mode & 0o777,
                    digest,
                },
            )?;
            if let Some(owner) = self.owner {
                owner.ensure_directory(Path::new("/etc"))?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(owner.destination(path)?)?;
                output.write_all(&cache.bytes)?;
                output.set_permissions(fs::Permissions::from_mode(stamp.mode & 0o777))?;
            }
            Ok(())
        }
    }

    struct OptionalFile {
        path: PathBuf,
        file: Option<(File, Stamp)>,
        bytes: Vec<u8>,
    }

    impl OptionalFile {
        fn read(
            path: &Path,
            maximum: u64,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<Self, RuntimeCohortError> {
            check_cancelled(cancelled)?;
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => {}
                Ok(_) => return Err(invalid("loader configuration is not an ordinary file")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(Self {
                        path: path.to_path_buf(),
                        file: None,
                        bytes: Vec::new(),
                    });
                }
                Err(error) => return Err(error.into()),
            }
            let mut file = crate::regular_input::open(path)?;
            let stamp = Stamp::of(&file.metadata()?);
            if stamp.size > maximum {
                return Err(invalid("loader configuration byte limit exceeded"));
            }
            let bytes = bounded_read(&mut file, maximum)?;
            check_cancelled(cancelled)?;
            let result = Self {
                path: path.to_path_buf(),
                file: Some((file, stamp)),
                bytes,
            };
            result.verify()?;
            if result
                .file
                .as_ref()
                .is_some_and(|(_, stamp)| stamp.size != result.bytes.len() as u64)
            {
                return Err(invalid("loader configuration changed during its read"));
            }
            Ok(result)
        }

        fn verify(&self) -> Result<(), RuntimeCohortError> {
            match (&self.file, fs::symlink_metadata(&self.path)) {
                (Some((file, before)), Ok(named))
                    if named.is_file()
                        && Stamp::of(&named) == *before
                        && Stamp::of(&file.metadata()?) == *before =>
                {
                    Ok(())
                }
                (None, Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                _ => Err(invalid(
                    "loader configuration changed during the loader probe",
                )),
            }
        }
    }

    fn library_record(
        library: &Library,
        root: &Path,
        measurement: &mut Measurement<'_>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, RuntimeCohortError> {
        let resolved = fs::canonicalize(&library.path)?;
        let mut record = Vec::new();
        if let Ok(relative) = resolved.strip_prefix(root) {
            // Bytes and symlinks are pinned by the retained toolchain. Avoid
            // rehashing hundreds of megabytes of LLVM on every observation.
            if !fs::metadata(&resolved)?.is_file() {
                return Err(invalid("toolchain runtime member is not regular"));
            }
            if !library.path.starts_with(root) {
                return Err(RuntimeCohortError::Unsupported(
                    "toolchain runtime alias lies outside its retained root",
                ));
            }
            append(&mut record, b"retained-toolchain");
            append(
                &mut record,
                relative
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 toolchain member"))?
                    .as_bytes(),
            );
            if !library.name.starts_with('/') {
                append(&mut record, library.name.as_bytes());
            }
        } else {
            let traced = measurement.trace(&library.path, cancelled)?;
            if traced != resolved {
                return Err(invalid("runtime alias changed during topology observation"));
            }
            append(&mut record, b"host-runtime");
            append(&mut record, library.name.as_bytes());
            append(
                &mut record,
                library
                    .path
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 runtime path"))?
                    .as_bytes(),
            );
            append(
                &mut record,
                resolved
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 resolved runtime path"))?
                    .as_bytes(),
            );
            append(&mut record, &measurement.file(&resolved, cancelled)?);
        }
        if fs::canonicalize(&library.path)? != resolved {
            return Err(invalid("runtime library path changed during observation"));
        }
        Ok(record)
    }

    fn cpu_profile(raw: &[u8]) -> Result<Vec<u8>, RuntimeCohortError> {
        let text = std::str::from_utf8(raw).map_err(|_| invalid("non-UTF-8 CPU identity"))?;
        let fields: &[&str] = match std::env::consts::ARCH {
            "x86_64" => &[
                "vendor_id",
                "cpu family",
                "model",
                "stepping",
                "model name",
                "flags",
            ],
            "aarch64" => &[
                "CPU implementer",
                "CPU architecture",
                "CPU variant",
                "CPU part",
                "CPU revision",
                "Features",
            ],
            _ => {
                return Err(RuntimeCohortError::Unsupported(
                    "unsupported CPU architecture",
                ));
            }
        };
        let mut profiles = BTreeSet::new();
        for block in text.split("\n\n") {
            let mut values = BTreeMap::new();
            for line in block.lines() {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                let name = name.trim();
                if fields.contains(&name) {
                    let normalized = if matches!(name, "flags" | "Features") {
                        value
                            .split_whitespace()
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>()
                            .join(" ")
                    } else {
                        value.split_whitespace().collect::<Vec<_>>().join(" ")
                    };
                    if normalized.is_empty() || values.insert(name, normalized).is_some() {
                        return Err(invalid("empty or duplicate CPU identity field"));
                    }
                }
            }
            if values.is_empty() {
                continue;
            }
            if fields.iter().any(|name| !values.contains_key(name)) {
                return Err(invalid("incomplete CPU model or feature identity"));
            }
            let mut profile = Vec::new();
            for (name, value) in values {
                append(&mut profile, name.as_bytes());
                append(&mut profile, value.as_bytes());
            }
            profiles.insert(profile);
        }
        if profiles.is_empty() {
            return Err(invalid("missing CPU model and feature identity"));
        }
        let mut result = Vec::new();
        append(&mut result, std::env::consts::ARCH.as_bytes());
        for profile in profiles {
            append(&mut result, &profile);
        }
        Ok(result)
    }

    struct ProbeDirectory(PathBuf);

    impl ProbeDirectory {
        fn new(parent: &Path) -> Result<Self, RuntimeCohortError> {
            if !parent.is_absolute() || !fs::metadata(parent)?.is_dir() {
                return Err(invalid(
                    "filesystem probe requires a private absolute directory",
                ));
            }
            for _ in 0..64 {
                let sequence = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(
                    ".rabs-runtime-fs-{}-{sequence}",
                    std::process::id()
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(invalid("filesystem probe name budget exhausted"))
        }
    }

    impl Drop for ProbeDirectory {
        fn drop(&mut self) {
            // Only a create-new child owned by this probe is removed.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(super) fn filesystem_profile(root: &Path) -> Result<Vec<u8>, RuntimeCohortError> {
        let directory = ProbeDirectory::new(root)?;
        let path = directory.0.join("case");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        if directory.0.join("CASE").try_exists()? {
            return Err(RuntimeCohortError::Unsupported(
                "case-sensitive filesystem required",
            ));
        }
        let unicode = directory.0.join("u\u{e9}");
        let _unicode_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(unicode)?;
        if directory.0.join("ue\u{301}").try_exists()? {
            return Err(RuntimeCohortError::Unsupported(
                "byte-distinct Unicode filenames required",
            ));
        }
        let modified =
            UNIX_EPOCH + Duration::from_secs(1_600_000_000) + Duration::from_nanos(123_456_789);
        file.set_times(FileTimes::new().set_modified(modified))?;
        let observed = file
            .metadata()?
            .modified()?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("filesystem timestamp is not representable"))?;
        let statistics = rustix::fs::statfs(&directory.0).map_err(io::Error::from)?;
        let mut profile = Vec::new();
        append(
            &mut profile,
            b"case-sensitive.unicode-bytes.regular-files.v1",
        );
        append(&mut profile, statistics.f_type.to_string().as_bytes());
        append(&mut profile, statistics.f_namelen.to_string().as_bytes());
        append(&mut profile, &observed.as_secs().to_le_bytes());
        append(&mut profile, &observed.subsec_nanos().to_le_bytes());
        Ok(profile)
    }

    pub(super) fn observe(
        compiler: &Path,
        toolchain_root: &Path,
        loader_search_paths: &[PathBuf],
        filesystem_root: &Path,
    ) -> Result<TypedDigest, RuntimeCohortError> {
        let (cohort, _, _) = measure(
            compiler,
            toolchain_root,
            loader_search_paths,
            filesystem_root,
            None,
            &|| false,
        )?;
        Ok(cohort)
    }

    pub(super) fn retain(
        compiler: &Path,
        toolchain_root: &Path,
        loader_search_paths: &[PathBuf],
        filesystem_root: &Path,
        retention_parent: &Path,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<RuntimeSnapshot, RuntimeCohortError> {
        check_cancelled(cancelled)?;
        let owner = RuntimeDirectory::new(retention_parent)?;
        let (cohort, tree, ambient) = measure(
            compiler,
            toolchain_root,
            loader_search_paths,
            filesystem_root,
            Some(&owner),
            cancelled,
        )?;
        check_cancelled(cancelled)?;
        tree.finish(&owner)?;
        let result = RuntimeSnapshot {
            cohort,
            owner,
            tree,
            filesystem_root: filesystem_root.to_path_buf(),
            ambient,
        };
        result.verify(cancelled)?;
        Ok(result)
    }

    fn measure(
        compiler: &Path,
        toolchain_root: &Path,
        loader_search_paths: &[PathBuf],
        filesystem_root: &Path,
        owner: Option<&RuntimeDirectory>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(TypedDigest, RuntimeTree, Vec<u8>), RuntimeCohortError> {
        check_cancelled(cancelled)?;
        if !compiler.is_absolute()
            || !toolchain_root.is_absolute()
            || loader_search_paths.len() > 128
        {
            return Err(invalid("runtime paths must be absolute and bounded"));
        }
        let root = fs::canonicalize(toolchain_root)?;
        let compiler = fs::canonicalize(compiler)?;
        if !compiler.starts_with(&root) || !fs::metadata(&root)?.is_dir() {
            return Err(invalid("compiler is outside the retained toolchain"));
        }
        let mut executable = crate::regular_input::open(&compiler)?;
        let compiler_stamp = Stamp::of(&executable.metadata()?);
        let mut magic = [0_u8; 4];
        executable.read_exact(&mut magic)?;
        if magic != *b"\x7fELF" {
            return Err(RuntimeCohortError::Unsupported(
                "compiler is not an ELF binary",
            ));
        }
        let interpreter = elf_interpreter(&mut executable)?;
        let preload =
            OptionalFile::read(Path::new("/etc/ld.so.preload"), MAX_PROBE_BYTES, cancelled)?;
        if preload.bytes.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err(RuntimeCohortError::Unsupported(
                "global loader preloads are not exposed in the action namespace",
            ));
        }
        // Capture before ldd: later host cache bytes must never be paired with
        // an earlier loader selection. Absence is also witnessed and keyed.
        let cache = OptionalFile::read(
            Path::new("/etc/ld.so.cache"),
            MAX_LOADER_CACHE_BYTES,
            cancelled,
        )?;
        let mut measurement = Measurement::new(owner);
        measurement.loader_cache(&cache)?;
        let search = validated_search_paths(loader_search_paths)?;
        let targets = probe_targets(&compiler, &root)?;
        let libraries = libraries(&probe(&targets, &search)?, Some(&root))?;
        if !libraries
            .iter()
            .any(|library| Path::new(&library.name) == interpreter && library.path == interpreter)
        {
            return Err(invalid(
                "ELF interpreter is absent from the measured runtime",
            ));
        }
        measurement.tree.interpreter = Some(interpreter.clone());
        check_cancelled(cancelled)?;
        preload.verify()?;
        cache.verify()?;
        let mut records = Vec::new();
        for library in libraries {
            check_cancelled(cancelled)?;
            let resolved = fs::canonicalize(&library.path)?;
            if !resolved.starts_with(&root) && !resolved.starts_with("/usr") {
                return Err(RuntimeCohortError::Unsupported(
                    "external library is outside the supported selected /usr runtime",
                ));
            }
            records.push(library_record(
                &library,
                &root,
                &mut measurement,
                cancelled,
            )?);
        }
        measurement.verify_sources(cancelled)?;
        preload.verify()?;
        cache.verify()?;
        records.sort();
        let mut observed = Vec::new();
        append(&mut observed, b"elf-host-cohort-v2");
        // Changing launch semantics must not reuse a previously qualified key.
        append(&mut observed, b"explicit-elf-interpreter-v1");
        append(&mut observed, interpreter.as_os_str().as_encoded_bytes());
        for record in records {
            append(&mut observed, &record);
        }
        append(
            &mut observed,
            if cache.file.is_some() {
                b"loader-cache-present"
            } else {
                b"loader-cache-absent"
            },
        );
        for (path, entry) in &measurement.tree.entries {
            if !(path.starts_with("/usr")
                || path.starts_with("/lib")
                || path.starts_with("/lib64")
                || path == Path::new("/etc")
                || path == Path::new("/etc/ld.so.cache"))
            {
                return Err(RuntimeCohortError::Unsupported(
                    "selected runtime alias leaves supported namespace roots",
                ));
            }
            append(
                &mut observed,
                path.to_str()
                    .ok_or_else(|| invalid("runtime entry is not UTF-8"))?
                    .as_bytes(),
            );
            match entry {
                RuntimeEntry::Directory => append(&mut observed, b"private-directory-mode-0700"),
                RuntimeEntry::Symlink(target) => {
                    append(&mut observed, b"symlink");
                    append(
                        &mut observed,
                        target
                            .to_str()
                            .ok_or_else(|| invalid("runtime alias target is not UTF-8"))?
                            .as_bytes(),
                    );
                }
                RuntimeEntry::File {
                    bytes,
                    mode,
                    digest,
                } => {
                    append(&mut observed, b"regular-file");
                    append(&mut observed, &bytes.to_le_bytes());
                    append(&mut observed, &mode.to_le_bytes());
                    append(&mut observed, digest);
                }
            }
        }
        let ambient = ambient_profile(filesystem_root)?;
        append(&mut observed, &ambient);
        check_cancelled(cancelled)?;
        if Stamp::of(&executable.metadata()?) != compiler_stamp
            || Stamp::of(&fs::metadata(&compiler)?) != compiler_stamp
        {
            return Err(invalid("compiler changed during runtime observation"));
        }
        Ok((digest(&observed), measurement.tree, ambient))
    }

    fn ambient_profile(filesystem_root: &Path) -> Result<Vec<u8>, RuntimeCohortError> {
        let mut observed = Vec::new();
        for path in ["/proc/sys/kernel/ostype", "/proc/sys/kernel/osrelease"] {
            let raw = read_system(path, 4096)?;
            let value = std::str::from_utf8(&raw)
                .map_err(|_| invalid("non-UTF-8 kernel identity"))?
                .trim();
            if value.is_empty() {
                return Err(invalid("empty kernel identity"));
            }
            append(&mut observed, value.as_bytes());
        }
        append(
            &mut observed,
            &cpu_profile(&read_system("/proc/cpuinfo", MAX_CPUINFO_BYTES)?)?,
        );
        append(&mut observed, &filesystem_profile(filesystem_root)?);
        Ok(observed)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn loader_capture_preserves_fast_child_status_and_both_streams() {
            for number in 0..32 {
                let code = if number % 2 == 0 { "0" } else { "7" };
                let mut command = Command::new("/bin/sh");
                command.env_clear().args([
                    "-c",
                    "printf stdout; printf stderr >&2; exit \"$1\"",
                    "probe",
                    code,
                ]);
                let output = capture_probe(&mut command, Duration::from_secs(5)).unwrap();
                assert_eq!(output.status.code(), Some(code.parse().unwrap()));
                assert_eq!(output.stdout, b"stdout");
                assert_eq!(output.stderr, b"stderr");
            }
        }

        #[test]
        fn loader_capture_accepts_empty_streams_and_reports_spawn_failure() {
            let output = capture_probe(
                Command::new("/bin/true").env_clear(),
                Duration::from_secs(5),
            )
            .unwrap();
            assert!(output.status.success());
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
            let missing = capture_probe(
                &mut Command::new("/nonexistent-rabs-loader-probe"),
                Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(missing.status.code(), Some(127));
            assert!(missing.stdout.is_empty());
            assert!(!missing.stderr.is_empty());
            let error = capture_probe_process(
                &mut Command::new("/nonexistent-rabs-loader-probe"),
                Duration::from_secs(5),
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn loader_capture_rejects_overflow_on_either_real_pipe() {
            for script in ["printf '%070000d' 0", "printf '%070000d' 0 >&2"] {
                let mut command = Command::new("/bin/sh");
                command.env_clear().args(["-c", script]);
                let error = capture_probe(&mut command, Duration::from_secs(5)).unwrap_err();
                assert!(error.to_string().contains("byte limit exceeded"), "{error}");
            }
        }

        #[test]
        fn loader_capture_deadline_drains_live_and_exited_leaders_without_accepting_open_pipes() {
            for ending in ["wait", "exit 0"] {
                let owner = tempfile::tempdir().unwrap();
                let marker = owner.path().join("child-pid");
                let mut command = Command::new("/bin/sh");
                command
                    .env_clear()
                    .args([
                        "-c",
                        &format!("/bin/sleep 60 & printf '%s' \"$!\" > \"$1\"; {ending}"),
                        "probe",
                    ])
                    .arg(&marker);
                let error = capture_probe(&mut command, Duration::from_secs(1)).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{ending}: {error}");
                let child: u32 = fs::read_to_string(marker).unwrap().parse().unwrap();
                let deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    match fs::read_to_string(format!("/proc/{child}/stat")) {
                        Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                        Ok(status)
                            if status.rsplit_once(')').is_some_and(|(_, fields)| {
                                matches!(fields.split_whitespace().next(), Some("Z" | "X"))
                            }) =>
                        {
                            break;
                        }
                        other => assert!(
                            Instant::now() < deadline,
                            "probe descendant survived group cleanup: {other:?}"
                        ),
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }

        #[test]
        fn elf_interpreter_refuses_malformed_tables_and_paths() {
            let owner = tempfile::tempdir().unwrap();
            let path = owner.path().join("compiler");
            let valid = |name: &[u8]| {
                let mut bytes = vec![0_u8; 120];
                bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
                bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
                bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
                bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
                bytes[64..68].copy_from_slice(&3_u32.to_le_bytes());
                bytes[72..80].copy_from_slice(&120_u64.to_le_bytes());
                bytes[96..104].copy_from_slice(&(name.len() as u64).to_le_bytes());
                bytes.extend_from_slice(name);
                bytes
            };
            let good = valid(b"/lib64/ld-linux-x86-64.so.2\0");
            fs::write(&path, &good).unwrap();
            assert_eq!(
                elf_interpreter(&mut File::open(&path).unwrap()).unwrap(),
                Path::new("/lib64/ld-linux-x86-64.so.2")
            );
            let mut bad_header = good.clone();
            bad_header[4] = 1;
            let mut overflow = good.clone();
            overflow[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
            let mut excessive = good.clone();
            excessive[56..58].copy_from_slice(&129_u16.to_le_bytes());
            let mut duplicate = good[..120].to_vec();
            duplicate[56..58].copy_from_slice(&2_u16.to_le_bytes());
            duplicate[72..80].copy_from_slice(&176_u64.to_le_bytes());
            duplicate.extend_from_within(64..120);
            duplicate.extend_from_slice(&good[120..]);
            for bytes in [
                bad_header,
                overflow,
                excessive,
                duplicate,
                good[..good.len() - 1].to_vec(),
                valid(b"relative/loader\0"),
                valid(b"/lib/../loader\0"),
                valid(b"/lib//loader\0"),
                valid(b"/lib/loader"),
                valid(b"/lib/loader\0extra\0"),
            ] {
                fs::write(&path, bytes).unwrap();
                assert!(elf_interpreter(&mut File::open(&path).unwrap()).is_err());
            }
        }

        #[test]
        fn loader_addresses_are_ignored_but_unresolved_and_relative_paths_are_refused() {
            let a = b"linux-vdso.so.1 (0x1111)\nlibc.so.6 => /lib/libc.so.6 (0x2222)\n/lib64/ld-linux.so.2 (0x3333)\n";
            let b = b"linux-vdso.so.1 (0x9999)\n/lib64/ld-linux.so.2 (0xaaaa)\nlibc.so.6 => /lib/libc.so.6 (0xbbbb)\n";
            assert_eq!(libraries(a, None).unwrap(), libraries(b, None).unwrap());
            for bad in [
                b"libmissing.so => not found\n".as_slice(),
                b"libc.so => relative/libc.so (0x1234)\n",
                b"statically linked\n",
                b"libc.so => /lib/libc.so (invalid)\n",
                b"linux-vdso.so.1 (0x1234)\n",
                b"/lib64/ld-linux.so.2 => /lib/other-loader.so (0x1234)\n",
                b"libc.so => /usr/lib/../lib/libc.so (0x1234)\n",
            ] {
                assert!(libraries(bad, None).is_err(), "{bad:?}");
            }
        }

        #[test]
        fn rustc_origin_paths_resolve_only_inside_the_retained_toolchain() {
            let owner = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let root = owner.path().join("toolchain");
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join("bin"))
                .unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join("lib"))
                .unwrap();
            let root = fs::canonicalize(root).unwrap();
            let driver = root.join("lib/librustc_driver.so");
            fs::write(&driver, b"parser fixture, not ELF execution evidence").unwrap();
            let report = format!(
                "librustc_driver.so => {}/bin/../lib/librustc_driver.so (0x1234)\n\
                 librustc_driver.so => {}/lib/../lib/librustc_driver.so (0x5678)\n",
                root.display(),
                root.display()
            );
            assert!(libraries(report.as_bytes(), None).is_err());
            assert_eq!(
                libraries(report.as_bytes(), Some(&root)).unwrap(),
                vec![Library {
                    name: "librustc_driver.so".to_owned(),
                    path: driver,
                }]
            );
            std::os::unix::fs::symlink("lib", root.join("inside")).unwrap();
            let inside = format!(
                "driver.so => {}/inside/../lib/librustc_driver.so (0x1234)\n",
                root.display()
            );
            assert!(libraries(inside.as_bytes(), Some(&root)).is_ok());
            std::os::unix::fs::symlink(owner.path(), root.join("outside")).unwrap();
            for bad in [
                "driver.so => /usr/lib/../lib/libc.so (0x1234)\n".to_owned(),
                format!(
                    "driver.so => {}/../toolchain/lib/librustc_driver.so (0x1234)\n",
                    root.display()
                ),
                format!(
                    "driver.so => {}/outside/toolchain/../toolchain/lib/librustc_driver.so (0x1234)\n",
                    root.display()
                ),
                format!(
                    "driver.so => {}/bin/../lib/missing.so (0x1234)\n",
                    root.display()
                ),
                format!(
                    "driver.so => {}/bin//../lib/librustc_driver.so (0x1234)\n",
                    root.display()
                ),
            ] {
                assert!(libraries(bad.as_bytes(), Some(&root)).is_err(), "{bad}");
            }
        }

        #[test]
        fn dlopen_backend_targets_are_included_and_probe_headers_are_exact() {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("toolchain");
            let backend = root.join("lib/rustlib/host/codegen-backends");
            fs::create_dir_all(&backend).unwrap();
            fs::create_dir(root.join("bin")).unwrap();
            let compiler = root.join("bin/rustc");
            let driver = root.join("lib/librustc_driver.so");
            let codegen = backend.join("librustc_codegen_llvm.so");
            for path in [&compiler, &driver, &codegen] {
                fs::write(path, b"\x7fELFfixture").unwrap();
            }
            let targets = probe_targets(&compiler, &root).unwrap();
            assert_eq!(targets.len(), 3);
            for path in [&compiler, &driver, &codegen] {
                assert!(targets.contains(path));
            }
            let raw = format!(
                "{}:\nlibc.so => /lib/libc.so (0x1234)\n{}:\nlibz.so => /lib/libz.so (0x2345)\n",
                compiler.display(),
                codegen.display()
            );
            let flattened = without_probe_headers(raw.as_bytes(), &targets).unwrap();
            assert_eq!(libraries(&flattened, None).unwrap().len(), 2);
            assert!(without_probe_headers(b"/unrequested/compiler:\n", &targets).is_err());
        }

        #[test]
        fn official_llvm_linker_alias_probes_its_retained_elf_and_refuses_other_scripts() {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("toolchain");
            fs::create_dir_all(root.join("lib")).unwrap();
            fs::create_dir(root.join("bin")).unwrap();
            let compiler = root.join("bin/rustc");
            fs::write(&compiler, b"\x7fELFcompiler").unwrap();
            let actual = root.join("lib/libLLVM.so.23.1-rust-1.100.0-nightly");
            fs::write(&actual, b"\x7fELFselected LLVM").unwrap();
            let alias = root.join("lib/libLLVM-23-rust-1.100.0-nightly.so");
            fs::write(&alias, b"INPUT(libLLVM.so.23.1-rust-1.100.0-nightly)\n").unwrap();
            let targets = probe_targets(&compiler, &root).unwrap();
            assert_eq!(targets.len(), 2);
            assert!(targets.contains(&compiler));
            assert!(targets.contains(&actual));
            assert!(!targets.contains(&alias));
            for script in [
                "GROUP(libLLVM.so.23.1-rust-1.100.0-nightly)",
                "INPUT(/usr/lib/libLLVM.so)",
                "INPUT(../libLLVM.so)",
                "INPUT(libLLVM.so extra.so)",
                "INPUT(libLLVM-23-rust-1.100.0-nightly.so)",
                "arbitrary non-ELF DSO",
            ] {
                fs::write(&alias, script).unwrap();
                assert!(probe_targets(&compiler, &root).is_err(), "{script}");
            }
            let foreign = directory.path().join("libforeign.so");
            fs::write(&foreign, b"\x7fELFoutside toolchain").unwrap();
            std::os::unix::fs::symlink(&foreign, root.join("lib/libforeign.so")).unwrap();
            fs::write(&alias, b"INPUT(libforeign.so)\n").unwrap();
            assert!(retained_probe_target(&alias, &root).is_err());
        }

        #[test]
        fn external_library_byte_changes_change_the_runtime_record() {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("toolchain");
            fs::create_dir(&root).unwrap();
            let path = directory.path().join("libexternal.so");
            fs::write(&path, b"first runtime bytes").unwrap();
            let library = Library {
                name: "libexternal.so".into(),
                path: path.clone(),
            };
            let first =
                library_record(&library, &root, &mut Measurement::new(None), &|| false).unwrap();
            fs::write(path, b"different runtime bytes").unwrap();
            let changed =
                library_record(&library, &root, &mut Measurement::new(None), &|| false).unwrap();
            assert_ne!(first, changed);
            assert_ne!(digest(&first), digest(&changed));
        }

        #[test]
        fn retained_toolchain_placement_is_not_runtime_identity() {
            let directory = tempfile::tempdir().unwrap();
            let mut records = Vec::new();
            for name in ["edge-toolchain", "worker-retained-123"] {
                let root = directory.path().join(name);
                fs::create_dir_all(root.join("lib")).unwrap();
                let path = root.join("lib/libinternal.so");
                fs::write(&path, b"same retained bytes").unwrap();
                records.push(
                    library_record(
                        &Library {
                            name: "libinternal.so".into(),
                            path,
                        },
                        &root,
                        &mut Measurement::new(None),
                        &|| false,
                    )
                    .unwrap(),
                );
            }
            assert_eq!(records[0], records[1]);
        }

        #[test]
        fn actual_filesystem_measurement_is_stable_across_private_roots() {
            let left = tempfile::tempdir().unwrap();
            let right = tempfile::tempdir().unwrap();
            assert_eq!(
                filesystem_profile(left.path()).unwrap(),
                filesystem_profile(right.path()).unwrap()
            );
            assert_eq!(fs::read_dir(left.path()).unwrap().count(), 0);
            assert_eq!(fs::read_dir(right.path()).unwrap().count(), 0);
        }

        #[cfg(target_arch = "x86_64")]
        #[test]
        fn cpu_frequency_processor_number_and_feature_order_are_not_identity() {
            let a = b"processor: 0\nvendor_id: GenuineIntel\ncpu family: 6\nmodel: 143\nstepping: 8\nmodel name: Example CPU\ncpu MHz: 900\nflags: sse avx avx2\n";
            let b = b"processor: 19\nvendor_id: GenuineIntel\ncpu family: 6\nmodel: 143\nstepping: 8\nmodel name: Example CPU\ncpu MHz: 3600\nflags: avx2 sse avx\n";
            assert_eq!(cpu_profile(a).unwrap(), cpu_profile(b).unwrap());
            let changed = String::from_utf8(b.to_vec())
                .unwrap()
                .replace("avx2", "avx512f");
            assert_ne!(
                cpu_profile(a).unwrap(),
                cpu_profile(changed.as_bytes()).unwrap()
            );
            assert!(cpu_profile(b"processor: 0\nflags: sse\n").is_err());
        }

        #[test]
        fn complete_edge_loader_paths_preserve_empty_missing_and_invalid_candidate_behavior() {
            let compiler = std::env::current_exe().unwrap();
            let root = compiler.parent().unwrap();
            let scratch = tempfile::tempdir().unwrap();
            let loader = tempfile::tempdir().unwrap();
            let missing = loader.path().join("not-yet-created");
            let search = vec![loader.path().to_path_buf(), missing];
            assert_eq!(validated_search_paths(&search).unwrap(), search);
            let baseline = observe(&compiler, root, &[], scratch.path()).unwrap();
            assert_eq!(
                observe(&compiler, root, &search, scratch.path()).unwrap(),
                baseline
            );

            let needed = libraries(&probe(std::slice::from_ref(&compiler), &[]).unwrap(), None)
                .unwrap()
                .into_iter()
                .find(|library| !library.name.starts_with('/'))
                .unwrap();
            fs::write(loader.path().join(needed.name), b"invalid dynamic library").unwrap();
            assert!(
                observe(&compiler, root, &search, scratch.path()).is_err(),
                "the edge probe must see a candidate that breaks the actual compiler loader"
            );
        }

        #[test]
        fn loader_path_validation_refuses_relative_nondirectory_and_dangling_aliases() {
            let scratch = tempfile::tempdir().unwrap();
            let file = scratch.path().join("regular");
            fs::write(&file, b"not a directory").unwrap();
            for path in [
                PathBuf::from("relative"),
                PathBuf::from("/tmp/../other"),
                file,
            ] {
                assert!(validated_search_paths(&[path]).is_err());
            }
            let alias = scratch.path().join("dangling");
            std::os::unix::fs::symlink(scratch.path().join("missing"), &alias).unwrap();
            assert!(validated_search_paths(&[alias]).is_err());
        }

        #[test]
        fn running_elf_runtime_observation_is_repeatable() {
            // Real ELF loader/CPU/filesystem observation of this executable;
            // not evidence of a remote rustc compile or authenticated delivery.
            let compiler = std::env::current_exe().unwrap();
            let root = compiler.parent().unwrap();
            let scratch = tempfile::tempdir().unwrap();
            let first = observe(&compiler, root, &[], scratch.path()).unwrap();
            let second = observe(&compiler, root, &[], scratch.path()).unwrap();
            assert_eq!(first, second);
            assert_eq!(first.domain, RUNTIME_COHORT_DOMAIN);
        }

        #[test]
        fn retained_selected_runtime_matches_observer_and_uses_only_owned_mounts() {
            let directory = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let toolchain = directory.path().join("toolchain");
            fs::create_dir_all(toolchain.join("bin")).unwrap();
            fs::create_dir(toolchain.join("lib")).unwrap();
            let compiler = toolchain.join("bin/rustc");
            fs::copy("/usr/bin/true", &compiler).unwrap();
            let observed = observe(&compiler, &toolchain, &[], directory.path()).unwrap();
            let retained = retain_runtime_cohort(
                &compiler,
                &toolchain,
                &[],
                directory.path(),
                directory.path(),
                || false,
            )
            .unwrap();
            assert_eq!(retained.cohort(), &observed);
            retained.verify(|| false).unwrap();
            let writable = directory.path().join("output");
            fs::create_dir(&writable).unwrap();
            let mut args = Vec::new();
            retained.append_mounts(&mut args, &[writable]).unwrap();
            assert!(!args.is_empty());
            assert!(args.len().is_multiple_of(3));
            for mount in args.as_chunks::<3>().0 {
                if mount[0] == "--ro-bind" {
                    assert!(Path::new(&mount[1]).starts_with(&retained.inner.owner.path));
                    assert_ne!(mount[1], mount[2]);
                } else {
                    assert_eq!(mount[0], "--symlink");
                    assert!(matches!(
                        mount[2].to_str(),
                        Some("/lib" | "/lib64" | "/usr")
                    ));
                }
            }
            assert!(
                args.as_chunks::<3>()
                    .0
                    .iter()
                    .any(|mount| mount[2] == "/usr")
            );
            let snapshot_path = retained.inner.owner.path.clone();
            drop(retained);
            assert!(!snapshot_path.try_exists().unwrap());
            assert!(directory.path().is_dir());
            assert!(compiler.is_file());
        }

        #[test]
        fn same_read_capture_keeps_bytes_and_aliases_after_source_changes() {
            let directory = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let source = directory.path().join("source");
            fs::create_dir(&source).unwrap();
            let library = source.join("libfixture.so.1");
            fs::write(&library, b"captured library bytes").unwrap();
            let relative = source.join("libfixture.so");
            std::os::unix::fs::symlink("libfixture.so.1", &relative).unwrap();
            let absolute = source.join("libabsolute.so");
            std::os::unix::fs::symlink(&relative, &absolute).unwrap();
            let owner = RuntimeDirectory::new(directory.path()).unwrap();
            let mut measurement = Measurement::new(Some(&owner));
            let resolved = measurement.trace(&absolute, &|| false).unwrap();
            assert_eq!(resolved, library);
            let measured = measurement.file(&resolved, &|| false).unwrap();
            measurement.verify_sources(&|| false).unwrap();
            measurement.tree.finish(&owner).unwrap();
            assert_eq!(
                fs::read_link(owner.destination(&absolute).unwrap()).unwrap(),
                relative
            );
            assert_eq!(
                fs::read_link(owner.destination(&relative).unwrap()).unwrap(),
                Path::new("libfixture.so.1")
            );
            let copied = owner.destination(&library).unwrap();
            assert_eq!(fs::read(&copied).unwrap(), b"captured library bytes");
            let expected: [u8; 32] = Sha256::digest(b"captured library bytes").into();
            assert_eq!(measured, expected);
            fs::write(&library, b"replacement host bytes").unwrap();
            assert!(measurement.verify_sources(&|| false).is_err());
            measurement.tree.verify(&owner, &|| false).unwrap();
            assert_eq!(fs::read(&copied).unwrap(), b"captured library bytes");
            fs::write(&copied, b"modified retained bytes").unwrap();
            assert!(measurement.tree.verify(&owner, &|| false).is_err());
        }

        #[test]
        fn loader_cache_capture_witnesses_presence_bytes_and_generation() {
            let directory = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let path = directory.path().join("cache");
            let missing = OptionalFile::read(&path, MAX_LOADER_CACHE_BYTES, &|| false).unwrap();
            missing.verify().unwrap();
            fs::write(&path, b"selected loader cache").unwrap();
            assert!(missing.verify().is_err());
            let captured = OptionalFile::read(&path, MAX_LOADER_CACHE_BYTES, &|| false).unwrap();
            let owner = RuntimeDirectory::new(directory.path()).unwrap();
            let mut measurement = Measurement::new(Some(&owner));
            measurement.loader_cache(&captured).unwrap();
            measurement.tree.finish(&owner).unwrap();
            let copied = owner.destination(Path::new("/etc/ld.so.cache")).unwrap();
            assert_eq!(fs::read(copied).unwrap(), b"selected loader cache");
            fs::write(&path, b"new loader cache").unwrap();
            assert!(captured.verify().is_err());
            measurement.tree.verify(&owner, &|| false).unwrap();
            let current = OptionalFile::read(&path, MAX_LOADER_CACHE_BYTES, &|| false).unwrap();
            let mut changed = Measurement::new(None);
            changed.loader_cache(&current).unwrap();
            assert_ne!(measurement.tree.entries, changed.tree.entries);
            let too_large = directory.path().join("large-cache");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&too_large)
                .unwrap()
                .set_len(MAX_LOADER_CACHE_BYTES + 1)
                .unwrap();
            assert!(OptionalFile::read(&too_large, MAX_LOADER_CACHE_BYTES, &|| false).is_err());
            let alias = directory.path().join("cache-alias");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            assert!(OptionalFile::read(&alias, MAX_LOADER_CACHE_BYTES, &|| false).is_err());
        }

        #[test]
        fn retained_tree_refuses_extra_entries_hardlinks_and_replaced_owner() {
            let directory = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let source = directory.path().join("source");
            fs::write(&source, b"runtime bytes").unwrap();
            let owner = RuntimeDirectory::new(directory.path()).unwrap();
            let mut measurement = Measurement::new(Some(&owner));
            let resolved = measurement.trace(&source, &|| false).unwrap();
            measurement.file(&resolved, &|| false).unwrap();
            measurement.tree.finish(&owner).unwrap();
            measurement.tree.verify(&owner, &|| false).unwrap();
            let copied = owner.destination(&source).unwrap();
            fs::hard_link(&copied, directory.path().join("writable-alias")).unwrap();
            assert!(measurement.tree.verify(&owner, &|| false).is_err());

            let empty_owner = RuntimeDirectory::new(directory.path()).unwrap();
            let empty_tree = RuntimeTree::default();
            empty_tree.verify(&empty_owner, &|| false).unwrap();
            fs::write(empty_owner.path.join("unexpected"), b"not selected").unwrap();
            assert!(empty_tree.verify(&empty_owner, &|| false).is_err());

            let replace_owner = RuntimeDirectory::new(directory.path()).unwrap();
            let original_path = replace_owner.path.clone();
            let moved = directory.path().join("moved-owned-runtime");
            fs::rename(&original_path, &moved).unwrap();
            fs::create_dir(&original_path).unwrap();
            fs::write(
                original_path.join("replacement"),
                b"must survive guarded cleanup",
            )
            .unwrap();
            assert!(replace_owner.verify_owner().is_err());
            drop(replace_owner);
            assert_eq!(
                fs::read(original_path.join("replacement")).unwrap(),
                b"must survive guarded cleanup"
            );
            assert!(moved.is_dir());
        }

        #[test]
        fn capture_bounds_and_cancellation_are_fail_closed() {
            let directory = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            assert!(
                retain_runtime_cohort(
                    Path::new("/not-probed"),
                    Path::new("/not-probed"),
                    &[],
                    directory.path(),
                    directory.path(),
                    || true,
                )
                .is_err()
            );
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
            let shared = directory.path().join("shared-parent");
            fs::create_dir(&shared).unwrap();
            fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
            assert!(RuntimeDirectory::new(&shared).is_err());
            let owner = RuntimeDirectory::new(directory.path()).unwrap();
            assert!(RuntimeTree::default().verify(&owner, &|| true).is_err());
            let source = directory.path().join("source");
            fs::write(&source, b"one byte budget is not enough").unwrap();
            assert!(stable_file(&source, &mut 1, None, &|| false).is_err());
            let mut budget = MAX_EXTERNAL_BYTES;
            assert!(stable_file(&source, &mut budget, None, &|| true).is_err());
            let mut tree = RuntimeTree::default();
            for index in 0..MAX_RUNTIME_ENTRIES {
                tree.insert(
                    PathBuf::from(format!("/usr/entry-{index}")),
                    RuntimeEntry::Directory,
                )
                .unwrap();
            }
            assert!(
                tree.insert(PathBuf::from("/usr/one-too-many"), RuntimeEntry::Directory)
                    .is_err()
            );
            let mut output = String::new();
            for index in 0..=MAX_LIBRARIES {
                output.push_str(&format!(
                    "lib{index}.so => /usr/lib/lib{index}.so (0x1234)\n"
                ));
            }
            assert!(libraries(output.as_bytes(), None).is_err());
            let large = directory.path().join("large-library");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&large)
                .unwrap()
                .set_len(MAX_LIBRARY_BYTES + 1)
                .unwrap();
            let mut budget = MAX_EXTERNAL_BYTES;
            assert!(stable_file(&large, &mut budget, None, &|| false).is_err());
        }

        #[test]
        fn writable_aliases_and_ancestors_cannot_expose_retained_runtime() {
            let directory = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let toolchain = directory.path().join("toolchain");
            fs::create_dir_all(toolchain.join("bin")).unwrap();
            let compiler = toolchain.join("bin/rustc");
            fs::copy("/usr/bin/true", &compiler).unwrap();
            let retained = retain_runtime_cohort(
                &compiler,
                &toolchain,
                &[],
                directory.path(),
                directory.path(),
                || false,
            )
            .unwrap();
            let alias = directory.path().join("runtime-alias");
            std::os::unix::fs::symlink(&retained.inner.owner.path, &alias).unwrap();
            for backing in [
                retained.inner.owner.path.clone(),
                retained.inner.owner.path.join("usr"),
                directory.path().to_path_buf(),
                alias,
                PathBuf::from("/"),
            ] {
                let mut args = vec![OsString::from("unchanged")];
                assert!(retained.append_mounts(&mut args, &[backing]).is_err());
                assert_eq!(args, [OsString::from("unchanged")]);
            }
            let sibling = directory.path().join("private-output");
            fs::create_dir(&sibling).unwrap();
            retained.append_mounts(&mut Vec::new(), &[sibling]).unwrap();
        }
    }
}
