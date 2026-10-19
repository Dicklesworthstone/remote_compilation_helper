//! Mount the rabs-cas store in the janitor region and reconcile it
//! fail-closed at boot (bead bd-hfhq2).
//!
//! `mount_and_reconcile` acquires exclusive local process ownership BEFORE
//! opening the blob layout or metadata index, then reconciles real filesystem
//! state. The lock lives as long as the shared LiveCas, including through
//! coordinator authority acquisition and janitor sweeps. A second process must
//! not reinterpret a live coordinator's authority as a dead boot's authority.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use rabs_asupersync::daemon_runtime::SubsystemWork;
use rabs_cas::blob_store::BlobStoreLayout;
use rabs_cas::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore};
use rabs_cas::startup_reconciliation::{FilesystemReality, ServingDecision, reconcile_startup};

const MOUNT_LOCK: &str = ".mount.lock";

/// Local filesystem fencing, not a cross-host election mechanism. All production
/// mounts must use this entry point. The inode is retained after unlock: removing
/// it would let an old waiter and a new opener lock different files for one root.
fn acquire_mount_lock(root: &Path) -> Result<MountLock, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(root).map_err(|e| format!("CAS root metadata: {e}"))?;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("CAS root must not be writable by group or other users".to_owned());
        }
    }
    let path = root.join(MOUNT_LOCK);
    let validate = || -> Result<std::fs::Metadata, String> {
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("CAS mount lock metadata: {e}"))?;
        if !metadata.is_file() {
            return Err(
                "CAS mount lock must be an ordinary file, not a link or directory".to_owned(),
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
                return Err("CAS mount lock must be private and have one link".to_owned());
            }
        }
        Ok(metadata)
    };
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate()?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| format!("open CAS mount lock: {e}"))?
        }
        Err(error) => return Err(format!("create CAS mount lock: {error}")),
    };
    file.try_lock()
        .map_err(|e| format!("CAS already mounted or exclusive lock unavailable: {e}"))?;
    // Take the guard the instant the lock is held, not once validation
    // has passed. Everything below can still refuse, and each of those
    // returns was previously a plain `File` drop — release by last
    // close, with the fork hazard `MountLock` exists to remove. The
    // adversarial paths are exactly the ones that should not fall back
    // to the weaker rule.
    let file = MountLock(file);
    let named = validate()?;
    let opened = file
        .0
        .metadata()
        .map_err(|e| format!("opened CAS mount lock: {e}"))?;
    if !opened.is_file() {
        return Err("opened CAS mount lock is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (named.dev(), named.ino()) != (opened.dev(), opened.ino()) || opened.nlink() != 1 {
            return Err("CAS mount lock changed during acquisition".to_owned());
        }
    }
    #[cfg(not(unix))]
    let _ = named;
    Ok(file)
}

/// Exclusive process ownership of one CAS root, released DETERMINISTICALLY.
///
/// The lock is `flock(2)`, which belongs to the open file description
/// rather than to the descriptor. `flock(2)` is explicit about what ends
/// one: "A lock is released either by an explicit `LOCK_UN` operation on
/// any of these duplicate file descriptors, or when ALL such file
/// descriptors have been closed." Duplicates here means the ones `dup`
/// and `fork` create.
///
/// Dropping a `File` only closes OUR descriptor, so before this type
/// existed the release was the second clause: the lock survived until
/// every duplicate anywhere in the system was gone. Anything that forks
/// while a `LiveCas` is mounted — every `Command::spawn` in this process,
/// including the capability probes — hands the child a duplicate, and
/// `O_CLOEXEC` does not retire it until the child reaches `exec`. A drop
/// inside that window therefore did NOT free the root, and the next
/// mount of it failed with "would block" for reasons unrelated to the
/// caller.
///
/// That was observable: the janitor mount-lock tests failed 3 runs in 14
/// (bd-oxi0c), always the reacquire-after-drop assertion, and only when
/// a sibling test forked concurrently.
///
/// Taking the first clause instead makes release a property of this
/// type rather than of what else happens to be forking: `LOCK_UN` frees
/// the description immediately, whoever else still references it.
#[derive(Debug)]
pub struct MountLock(File);

impl Drop for MountLock {
    fn drop(&mut self) {
        // Best effort by necessity — drop cannot report. An unlock
        // failure leaves exactly the old behaviour (released on last
        // close), so this can only improve on it, never regress it.
        let _ = self.0.unlock();
    }
}

/// A fully inspected startup inventory, constructed BEFORE reconciliation can
/// retire any location or tombstone. Only an explicit NotFound observation
/// permits a negative answer. Unknown paths fail toward metadata retention.
///
/// This is not content verification or an atomic filesystem snapshot. The
/// caller holds exclusive CAS ownership and has not admitted writers yet.
/// Same-UID processes deliberately racing pathname replacement are outside
/// that cooperative ownership model; this is not a filesystem sandbox.
#[derive(Debug)]
pub struct OsFilesystem {
    present: BTreeSet<String>,
    missing: BTreeSet<String>,
}

impl OsFilesystem {
    /// Inspect every store root and every recorded location before returning
    /// an infallible reconciliation view. Paths must be absolute physical
    /// paths without symlink components. No file contents are read or changed.
    ///
    /// Bounds cover filesystem entries and retained path bytes, not the SQL
    /// metadata scan that supplies `claimed`. An incomplete inventory refuses
    /// startup instead of becoming a partial, apparently authoritative view.
    ///
    /// # Errors
    /// IO errors other than a confirmed missing location; links, special nodes,
    /// unrepresentable paths, changed directories, or exhausted scan budgets.
    pub fn new(roots: Vec<PathBuf>, claimed: &[String]) -> Result<Self, String> {
        Self::with_limits(roots, claimed, 1_000_000, 256 * 1024 * 1024)
    }

    fn with_limits(
        roots: Vec<PathBuf>,
        claimed: &[String],
        max_entries: usize,
        max_path_bytes: usize,
    ) -> Result<Self, String> {
        if roots.is_empty() || roots.len() > max_entries || claimed.len() > max_entries {
            return Err("CAS inventory root/location limit exceeded".into());
        }
        let mut inventory = Self {
            present: BTreeSet::new(),
            missing: BTreeSet::new(),
        };
        let mut bytes_left = max_path_bytes;
        let mut entries_left = max_entries;
        let mut pending = Vec::new();
        let mut visited = BTreeSet::new();
        for root in roots {
            Self::charge_path(&root, &mut bytes_left)?;
            pending.push(root);
        }
        while let Some(directory) = pending.pop() {
            if !visited.insert(directory.clone()) {
                continue;
            }
            let before = Self::inspect_path(&directory)?
                .ok_or_else(|| format!("CAS inventory root disappeared: {}", directory.display()))?;
            if !before.is_dir() {
                return Err(format!("CAS inventory root is not a directory: {}", directory.display()));
            }
            let entries = std::fs::read_dir(&directory)
                .map_err(|error| format!("CAS inventory read directory: {error}"))?;
            for entry in entries {
                entries_left = entries_left.checked_sub(1)
                    .ok_or("CAS inventory entry limit exceeded")?;
                let path = entry.map_err(|error| format!("CAS inventory entry: {error}"))?.path();
                let text = Self::charge_path(&path, &mut bytes_left)?;
                let metadata = Self::inspect_path(&path)?
                    .ok_or_else(|| format!("CAS inventory entry disappeared: {}", path.display()))?;
                if metadata.is_dir() {
                    pending.push(path);
                } else if metadata.is_file() {
                    inventory.present.insert(text.to_owned());
                } else {
                    return Err(format!("CAS inventory unsupported node: {}", path.display()));
                }
            }
            let after = Self::inspect_path(&directory)?
                .ok_or("CAS inventory directory disappeared during traversal")?;
            if !same_directory(&before, &after) {
                return Err("CAS inventory directory changed during traversal".into());
            }
        }
        // All absence judgments must succeed BEFORE the reconciler's first
        // repair. Permission errors, ENOTDIR and IO faults are not absence.
        for path in claimed {
            let physical = Path::new(path);
            Self::charge_path(physical, &mut bytes_left)?;
            match Self::inspect_path(physical)? {
                Some(metadata) if metadata.is_file() => {
                    if inventory.missing.contains(path) {
                        return Err(format!("CAS location changed during inventory: {path}"));
                    }
                    inventory.present.insert(path.clone());
                }
                Some(_) => return Err(format!("CAS location is not a regular file: {path}")),
                None if inventory.present.contains(path) => {
                    return Err(format!("CAS location changed during inventory: {path}"));
                }
                None => {
                    inventory.missing.insert(path.clone());
                }
            }
        }
        Ok(inventory)
    }

    fn charge_path<'a>(path: &'a Path, bytes_left: &mut usize) -> Result<&'a str, String> {
        let text = path.to_str().ok_or("CAS inventory path is not UTF-8")?;
        *bytes_left = bytes_left.checked_sub(text.len())
            .ok_or("CAS inventory path-byte limit exceeded")?;
        Ok(text)
    }

    fn inspect_path(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
        if !path.is_absolute() {
            return Err("CAS inventory requires absolute physical paths".into());
        }
        if path.components().any(|component| {
            !matches!(component, Component::RootDir | Component::Normal(_))
        }) {
            return Err("CAS inventory path is not a physical path".into());
        }
        let mut prefix = PathBuf::new();
        let mut components = path.components().peekable();
        let mut last = None;
        while let Some(component) = components.next() {
            match component {
                Component::RootDir | Component::Normal(_) => prefix.push(component.as_os_str()),
                _ => return Err("CAS inventory path is not a physical path".into()),
            }
            let metadata = match std::fs::symlink_metadata(&prefix) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(format!("CAS inventory metadata: {error}")),
            };
            if metadata.file_type().is_symlink() {
                return Err(format!("CAS inventory refuses symlink: {}", prefix.display()));
            }
            if components.peek().is_some() && !metadata.is_dir() {
                return Err(format!("CAS inventory parent is not a directory: {}", prefix.display()));
            }
            last = Some(metadata);
        }
        Ok(last)
    }
}

fn same_directory(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    after.is_dir()
        && (before.dev(), before.ino(), before.mtime(), before.mtime_nsec(),
            before.ctime(), before.ctime_nsec())
            == (after.dev(), after.ino(), after.mtime(), after.mtime_nsec(),
                after.ctime(), after.ctime_nsec())
}

impl FilesystemReality for OsFilesystem {
    fn exists(&self, store_path: &str) -> bool {
        // The reconciler interprets false as permission to delete metadata.
        // Never manufacture that permission for a path we did not inspect.
        !self.missing.contains(store_path)
    }

    fn all_paths(&self) -> Vec<String> {
        self.present.iter().cloned().collect()
    }
}

/// A live, reconciled store: mounted once at boot, owned by the janitor
/// region for the daemon lifetime, and SHARED with the coordinator, which
/// is the only role allowed to commit through it (I8/I9/I10).
///
/// The metadata mutex serializes in-process writes; the held mount lock
/// excludes other local processes from reconciliation and authority takeover.
pub struct LiveCas {
    store: Mutex<SqlMetadataStore<RusqliteEngine>>,
    layout: BlobStoreLayout,
    cas_root: PathBuf,
    /// Startup reconciliation refused serving (torn authoritative state).
    pub serving_refused: bool,
    /// Count of drift rows repaired during reconciliation.
    pub repaired: usize,
    /// Count of drift rows reported (orphans; nothing touched).
    pub reported: usize,
    /// Monotonic plan-sequence for janitor-owned GC receipts.
    pub gc_seq: std::sync::atomic::AtomicU64,
    // Keep this last: all metadata handles drop before process ownership
    // does. Field order still governs that — `MountLock`'s own `Drop`
    // runs when this field drops, which is after `store`, so the
    // sqlite handles are closed before any other process can mount.
    // (A `Drop for LiveCas` would have run BEFORE every field and
    // inverted exactly that, which is why the unlock lives on the
    // field's type rather than on the struct.)
    _mount_lock: MountLock,
}

impl LiveCas {
    /// The metadata index. Keep the guard through a complete mutation sequence.
    #[must_use]
    pub fn store(&self) -> &Mutex<SqlMetadataStore<RusqliteEngine>> {
        &self.store
    }

    /// The content-addressed byte store layout.
    #[must_use]
    pub fn layout(&self) -> &BlobStoreLayout {
        &self.layout
    }

    /// The canonical store root.
    #[must_use]
    pub fn cas_root(&self) -> &Path {
        &self.cas_root
    }

    /// A pathname replaced after mounting must not redirect physical GC into
    /// another store. Check the named fencing inode against the held descriptor.
    pub(super) fn verify_mount_path(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let held = self._mount_lock.0.metadata().map_err(|e| e.to_string())?;
        let named = std::fs::symlink_metadata(self.cas_root.join(MOUNT_LOCK))
            .map_err(|e| format!("CAS mount lock disappeared: {e}"))?;
        if !named.file_type().is_file()
            || named.nlink() != 1
            || named.mode() & 0o077 != 0
            || (named.dev(), named.ino(), named.uid()) != (held.dev(), held.ino(), held.uid())
        {
            return Err("CAS mount lock changed after mounting".into());
        }
        Ok(())
    }
}

impl std::fmt::Debug for LiveCas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveCas")
            .field("cas_root", &self.cas_root)
            .field("serving_refused", &self.serving_refused)
            .field("repaired", &self.repaired)
            .field("reported", &self.reported)
            .finish()
    }
}

/// Exclusively mount the store and reconcile before any authority may be
/// acquired. A failed mount never touches SQLite or blob metadata without the
/// lock. The lock is released on every startup error and at the last owner drop.
pub fn mount_and_reconcile(cas_root: &Path) -> Result<LiveCas, String> {
    // `create_dir_all` honours the process umask, and the Debian/Ubuntu
    // default is 0002 (user-private groups), which creates a 0775 root
    // — group-writable, which `acquire_mount_lock` then refuses. The
    // daemon would create a CAS root and immediately decline to mount
    // it, so a cold start could not succeed on a stock host at all.
    //
    // Tighten what WE create. A PRE-EXISTING root is deliberately left
    // alone: its permissions are evidence about who else can write
    // there, and silently repairing someone else's directory would
    // convert the security check below into a no-op rather than
    // satisfying it.
    let preexisting = cas_root.exists();
    std::fs::create_dir_all(cas_root)
        .map_err(|e| format!("cas root {}: {e}", cas_root.display()))?;
    #[cfg(unix)]
    if !preexisting {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cas_root, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cas root permissions {}: {e}", cas_root.display()))?;
    }
    let cas_root =
        std::fs::canonicalize(cas_root).map_err(|e| format!("canonical CAS root: {e}"))?;
    let mount_lock = acquire_mount_lock(&cas_root)?;
    let layout = BlobStoreLayout::open(&cas_root.join("blobs"))
        .map_err(|e| format!("blob layout: {e:?}"))?;
    let engine = RusqliteEngine::open(&cas_root.join("meta.sqlite"))
        .map_err(|e| format!("metadata engine: {e:?}"))?;
    let mut store = SqlMetadataStore::open(engine).map_err(|e| format!("metadata store: {e:?}"))?;
    // Secondary read indexes are installed once under exclusive mount ownership,
    // never lazily on a compiler's consultation or while a writer is admitted.
    rabs_cas::read_indexes::prepare_serving_indexes(&mut store)
        .map_err(|e| format!("metadata query indexes: {e:?}"))?;

    // Finish every fallible filesystem observation before reconciliation is
    // allowed to remove a single location or tombstone. The mount lock spans
    // capture and application; no writer has been admitted in between.
    let claimed: Vec<String> = store.reconciliation_scan()
        .map_err(|error| format!("reconciliation inventory metadata: {error:?}"))?
        .into_iter().map(|row| row.store_path).collect();
    let filesystem = OsFilesystem::new(vec![layout.root().to_path_buf()], &claimed)?;
    let report =
        reconcile_startup(&mut store, &filesystem).map_err(|e| format!("reconcile: {e:?}"))?;

    Ok(LiveCas {
        store: Mutex::new(store),
        layout,
        cas_root,
        serving_refused: matches!(report.serving, ServingDecision::Refused(_)),
        repaired: report.repaired.len(),
        reported: report.reported.len(),
        gc_seq: std::sync::atomic::AtomicU64::new(1),
        _mount_lock: mount_lock,
    })
}

/// Build the janitor region work around an ALREADY-MOUNTED store.
/// The shared owner outlives every region that may still be using it.
pub fn janitor_work_holding(mounted: Result<Arc<LiveCas>, String>) -> SubsystemWork {
    Box::new(move |cx, mut shutdown| {
        Box::pin(async move {
            let mounted = mounted?;
            println!(
                "{{\"v\":1,\"kind\":\"janitor-cas-mounted\",\"root\":{:?},\"serving_refused\":{},\"repaired\":{},\"reported\":{}}}",
                mounted.cas_root().display().to_string(),
                mounted.serving_refused,
                mounted.repaired,
                mounted.reported,
            );
            cx.trace("janitor region up: rabs-cas store mounted + reconciled");
            let _held = mounted;
            shutdown.wait().await;
            Ok(())
        })
    })
}

/// Summary of one janitor-owned GC sweep (W1: quota/GC ownership).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcSweepSummary {
    /// Locations the plan marked for reclaim.
    pub planned: u64,
    /// Locations actually reclaimed this pass.
    pub reclaimed: u64,
    /// Locations skipped (protected re-check or concurrent use).
    pub skipped: u64,
}

impl LiveCas {
    /// Total bytes under the store root, without caching.
    #[must_use]
    pub fn store_usage_bytes(&self) -> u64 {
        fn walk(dir: &Path) -> u64 {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return 0;
            };
            let mut total = 0;
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    total += walk(&p);
                } else if let Ok(meta) = p.metadata() {
                    total += meta.len();
                }
            }
            total
        }
        walk(&self.cas_root)
    }

    /// Run one GC sweep over the live store. The lock serializes planning and
    /// execution with other users of this mount.
    pub fn gc_sweep(&self, mode: rabs_cas::gc::GcMode) -> Result<GcSweepSummary, String> {
        use rabs_cas::gc::{GcWorld, execute_gc, plan_gc};
        let seq = self
            .gc_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut store = self.store.lock().map_err(|_| "metadata lock poisoned")?;
        let plan = plan_gc(&mut *store, &GcWorld::default(), mode, seq)
            .map_err(|e| format!("gc plan: {e:?}"))?;
        let receipt = execute_gc(&mut *store, &plan).map_err(|e| format!("gc exec: {e:?}"))?;
        Ok(GcSweepSummary {
            planned: receipt.planned as u64,
            reclaimed: receipt.reclaimed.len() as u64,
            skipped: receipt.skipped.len() as u64,
        })
    }
}

/// Janitor quota/GC ownership. Quota remains advisory; uncertainty must not
/// silently authorize deletion of an active build's state.
pub fn janitor_work_with_gc(
    mounted: Result<Arc<LiveCas>, String>,
    quota_bytes: Option<u64>,
) -> SubsystemWork {
    super::maintenance::work(mounted, quota_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_util::private_tempdir;

    #[test]
    fn mount_on_a_fresh_dir_reconciles_clean_and_allows_serving() {
        let dir = private_tempdir();
        let cas_root = dir.path().join("cas");
        let mounted = mount_and_reconcile(&cas_root).expect("mount");
        assert!(!mounted.serving_refused, "fresh store must allow serving");
        assert_eq!(mounted.repaired, 0);
        assert_eq!(mounted.reported, 0);
        assert!(cas_root.join("blobs").join("objects").is_dir());
        assert!(cas_root.join("meta.sqlite").exists());
    }

    #[test]
    fn mount_is_idempotent_across_reopen() {
        let dir = private_tempdir();
        let cas_root = dir.path().join("cas");
        let first = mount_and_reconcile(&cas_root).expect("first mount");
        assert!(
            mount_and_reconcile(&cas_root).is_err(),
            "live ownership must not be superseded"
        );
        drop(first);
        let second = mount_and_reconcile(&cas_root).expect("re-mount");
        assert!(!second.serving_refused);
    }

    #[test]
    fn shared_owner_holds_lock_until_last_reference_drops() {
        let dir = private_tempdir();
        let first = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let other_region = Arc::clone(&first);
        drop(first);
        assert!(mount_and_reconcile(dir.path()).is_err());
        drop(other_region);
        assert!(
            dir.path().join(MOUNT_LOCK).is_file(),
            "never unlink the fencing inode"
        );
        assert!(mount_and_reconcile(dir.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn alias_cannot_acquire_another_lock_for_the_same_store() {
        let dir = private_tempdir();
        let root = dir.path().join("cas");
        let mounted = mount_and_reconcile(&root).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(mount_and_reconcile(&alias).is_err());
        drop(mounted);
        assert_eq!(mount_and_reconcile(&alias).unwrap().cas_root(), root);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_lock_paths_refuse_before_metadata_creation() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for case in 0..4 {
            let dir = private_tempdir();
            let root = dir.path().join("cas");
            std::fs::create_dir(&root).unwrap();
            let outside = dir.path().join("outside");
            std::fs::write(&outside, b"must remain unchanged").unwrap();
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
            let path = root.join(MOUNT_LOCK);
            match case {
                0 => symlink(&outside, &path).unwrap(),
                1 => std::fs::hard_link(&outside, &path).unwrap(),
                2 => std::fs::create_dir(&path).unwrap(),
                _ => {
                    std::fs::write(&path, b"shared").unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
                        .unwrap();
                }
            }
            assert!(mount_and_reconcile(&root).is_err());
            assert!(!root.join("meta.sqlite").exists());
            assert_eq!(std::fs::read(&outside).unwrap(), b"must remain unchanged");
        }
    }

    #[test]
    fn failed_startup_releases_process_ownership() {
        let dir = private_tempdir();
        std::fs::write(dir.path().join("blobs"), b"not a directory").unwrap();
        assert!(mount_and_reconcile(dir.path()).is_err());
        // Preserve the bad input for inspection instead of deleting it.
        std::fs::rename(dir.path().join("blobs"), dir.path().join("bad-blobs")).unwrap();
        assert!(mount_and_reconcile(dir.path()).is_ok());
    }

    #[test]
    fn mount_lock_subprocess_helper() {
        let Some(root) = std::env::var_os("RABS_TEST_CAS_MOUNT_LOCK") else {
            return;
        };
        std::process::exit(if mount_and_reconcile(Path::new(&root)).is_err() {
            41
        } else {
            42
        });
    }

    #[test]
    fn another_process_cannot_mount_live_coordinator_state() {
        let dir = private_tempdir();
        let _mounted = mount_and_reconcile(dir.path()).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "janitor::store::tests::mount_lock_subprocess_helper",
            ])
            .env("RABS_TEST_CAS_MOUNT_LOCK", dir.path())
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(41),
            "child must run the helper and refuse the mount"
        );
    }

    #[test]
    fn os_filesystem_sees_written_files_and_absent_paths() {
        let dir = private_tempdir();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let nested = root.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        let file = nested.join("obj.bin");
        std::fs::write(&file, b"x").unwrap();
        let fs = OsFilesystem::new(
            vec![root.clone()],
            &[root.join("missing").to_str().unwrap().to_owned()],
        ).unwrap();
        assert!(fs.exists(file.to_str().unwrap()));
        assert!(!fs.exists(root.join("missing").to_str().unwrap()));
        assert!(fs.all_paths().iter().any(|p| p.ends_with("obj.bin")));
    }

    #[test]
    fn inventory_is_complete_deterministic_and_unknown_paths_never_authorize_repair() {
        let dir = private_tempdir();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let nested = root.join("nested");
        std::fs::create_dir(&nested).unwrap();
        let first = root.join("first");
        let second = nested.join("second");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        let missing = root.join("absent").to_str().unwrap().to_owned();
        let inventory =
            OsFilesystem::new(vec![root.clone()], std::slice::from_ref(&missing)).unwrap();
        assert_eq!(inventory.all_paths(), vec![
            first.to_str().unwrap().to_owned(), second.to_str().unwrap().to_owned(),
        ]);
        assert!(!inventory.exists(&missing));
        assert!(inventory.exists(root.join("never-inspected").to_str().unwrap()));
        // The reconciler consumes the checked observation, not another IO
        // lookup that can fail after it has already started deleting rows.
        std::fs::rename(&first, root.join("retained-first")).unwrap();
        assert!(inventory.exists(first.to_str().unwrap()));
        assert_eq!(std::fs::read(root.join("retained-first")).unwrap(), b"first");
    }

    #[test]
    fn inventory_refuses_missing_roots_invalid_parents_and_resource_exhaustion() {
        let dir = private_tempdir();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let file = root.join("file");
        std::fs::write(&file, b"unchanged").unwrap();
        assert!(OsFilesystem::new(vec![root.join("absent")], &[]).is_err());
        assert!(OsFilesystem::new(vec![file.clone()], &[]).is_err());
        assert!(OsFilesystem::new(vec![root.clone()], &[
            file.join("child").to_str().unwrap().to_owned(),
        ]).is_err(), "ENOTDIR must not be turned into a missing location");
        assert!(OsFilesystem::new(vec![root.clone()], &["relative/path".into()]).is_err());
        assert!(OsFilesystem::new(vec![root.clone()], &[
            root.to_str().unwrap().to_owned(),
        ]).is_err(), "a directory is not a blob location");
        assert!(OsFilesystem::with_limits(vec![root.clone()], &[], 1, 1).is_err());
        std::fs::write(root.join("another"), b"another").unwrap();
        assert!(OsFilesystem::with_limits(vec![root.clone()], &[], 1, 8192).is_err());
        let complete = OsFilesystem::with_limits(vec![root], &[], 2, 8192).unwrap();
        assert_eq!(complete.all_paths().len(), 2);
        assert_eq!(std::fs::read(file).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn inventory_refuses_links_cycles_and_special_nodes_without_following_them() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;
        for case in ["cycle", "external", "file", "dangling", "socket"] {
            let dir = private_tempdir();
            let outside = private_tempdir();
            let root = std::fs::canonicalize(dir.path()).unwrap();
            let outside = std::fs::canonicalize(outside.path()).unwrap();
            let evidence = outside.join("evidence");
            std::fs::write(&evidence, b"outside bytes remain unchanged").unwrap();
            let path = root.join("suspicious");
            let _socket = match case {
                "cycle" => { symlink(&root, &path).unwrap(); None }
                "external" => { symlink(&outside, &path).unwrap(); None }
                "file" => { symlink(&evidence, &path).unwrap(); None }
                "dangling" => { symlink(outside.join("missing"), &path).unwrap(); None }
                "socket" => Some(UnixListener::bind(&path).unwrap()),
                _ => unreachable!(),
            };
            assert!(OsFilesystem::new(vec![root], &[]).is_err(), "{case}");
            assert!(std::fs::symlink_metadata(path).is_ok(), "evidence retained: {case}");
            assert_eq!(std::fs::read(evidence).unwrap(), b"outside bytes remain unchanged");
        }
    }

    #[cfg(unix)]
    #[test]
    fn inventory_refuses_symlink_ancestors_even_when_the_leaf_is_missing() {
        use std::os::unix::fs::symlink;
        let dir = private_tempdir();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = root.join("alias");
        symlink(&real, &alias).unwrap();
        assert!(OsFilesystem::new(vec![alias.clone()], &[]).is_err());
        assert!(OsFilesystem::new(vec![real], &[
            alias.join("missing").to_str().unwrap().to_owned(),
        ]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_inventory_paths_refuse_instead_of_being_silently_omitted() {
        use std::os::unix::ffi::OsStringExt;
        let dir = private_tempdir();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let path = root.join(std::ffi::OsString::from_vec(b"object-\xff".to_vec()));
        std::fs::write(&path, b"preserved").unwrap();
        let error = OsFilesystem::new(vec![root], &[]).unwrap_err();
        assert!(error.contains("UTF-8"));
        assert_eq!(std::fs::read(path).unwrap(), b"preserved");
    }

    #[cfg(unix)]
    #[test]
    fn failed_inventory_retains_location_and_tombstone_until_a_complete_remount() {
        use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
        use std::os::unix::fs::symlink;
        let dir = private_tempdir();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let cas = mount_and_reconcile(&root).unwrap();
        let object = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.sha256.v1",
            bytes: [91; 32],
        };
        let missing = cas.layout().root().join("missing").to_str().unwrap().to_owned();
        let key = rabs_cas::metadata_store::digest_key(&object);
        let before = {
            let mut store = cas.store().lock().unwrap();
            store.record_object(&object, 13).unwrap();
            store.add_location(&object, &missing, Some(1), "raw", true).unwrap();
            store.add_gc_tombstone(&key, &missing, 1, 2).unwrap();
            store.differential_snapshot().unwrap()
        };
        let obstruction = cas.layout().root().join("cycle");
        symlink(cas.layout().root(), &obstruction).unwrap();
        drop(cas);
        assert!(mount_and_reconcile(&root).is_err());
        // Test-owned store, no daemon is alive. Startup may have opened and
        // prepared indexes, but not retired any location/tombstone evidence.
        let mut store = SqlMetadataStore::open(
            RusqliteEngine::open(&root.join("meta.sqlite")).unwrap(),
        ).unwrap();
        assert_eq!(store.differential_snapshot().unwrap(), before);
        assert!(store.object_located(&object).unwrap());
        assert_eq!(store.due_gc_tombstones(u64::MAX).unwrap().len(), 1);
        drop(store);
        // Preserve the obstruction outside the scanned blob layout. A later
        // clean mount may repair the genuinely missing row and stale marker.
        std::fs::rename(obstruction, root.join("retained-cycle")).unwrap();
        let remounted = mount_and_reconcile(&root).unwrap();
        assert!(!remounted.serving_refused);
        assert_eq!(remounted.repaired, 2);
        let mut store = remounted.store().lock().unwrap();
        assert!(!store.object_located(&object).unwrap());
        assert!(store.due_gc_tombstones(u64::MAX).unwrap().is_empty());
    }

    /// A cold start must succeed on a host whose default umask is
    /// group-writable — which is the Debian/Ubuntu default (0002).
    ///
    /// `create_dir_all` honours the umask, so the mount used to create a
    /// 0775 CAS root and then refuse it for being group-writable: the
    /// daemon declined to mount a directory it had just made itself, and
    /// no cold start could succeed on a stock Debian/Ubuntu box at all.
    /// The whole rabsd test
    /// suite failed on exactly those workers too, which is how this was
    /// found.
    #[cfg(unix)]
    #[test]
    fn a_cold_start_creates_a_private_cas_root_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;

        // The mode is asserted EXACTLY rather than just "not
        // group-writable", which is what makes this umask-independent:
        // without the explicit tightening the created root inherits the
        // ambient umask, giving 0755 on a 0022 host and 0775 on a 0002
        // one. Neither is 0700, so this fails on any host if the fix
        // regresses — and the 0775 case is the one where the mount then
        // refused the directory it had just created, so no cold start
        // could succeed on a stock Debian/Ubuntu box at all.
        let dir = private_tempdir();
        let cas_root = dir.path().join("cas");

        let mounted = mount_and_reconcile(&cas_root);
        assert!(
            mounted.is_ok(),
            "a cold start must succeed: {:?}",
            mounted.err()
        );
        assert_eq!(
            std::fs::metadata(&cas_root)
                .expect("cas root exists")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "a CAS root this mount created must be private to its owner"
        );
    }

    /// The security check still has teeth: a PRE-EXISTING root with
    /// unsafe permissions is refused rather than silently repaired.
    /// Without this, the fix above would have turned the check into a
    /// no-op instead of satisfying it.
    #[cfg(unix)]
    #[test]
    fn a_preexisting_group_writable_root_is_still_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = private_tempdir();
        let cas_root = dir.path().join("cas");
        std::fs::create_dir_all(&cas_root).unwrap();
        std::fs::set_permissions(&cas_root, std::fs::Permissions::from_mode(0o775)).unwrap();

        let mounted = mount_and_reconcile(&cas_root);
        assert!(
            mounted
                .as_ref()
                .err()
                .is_some_and(|e| e.contains("writable by group or other")),
            "a root someone else can write must be refused, got {mounted:?}"
        );
        assert_eq!(
            std::fs::metadata(&cas_root).unwrap().permissions().mode() & 0o777,
            0o775,
            "a refused root must be left exactly as found, not repaired"
        );
    }
}
