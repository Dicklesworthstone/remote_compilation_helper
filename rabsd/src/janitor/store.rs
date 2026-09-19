//! Mount the rabs-cas store in the janitor region and reconcile it
//! fail-closed at boot (bead bd-hfhq2).
//!
//! `mount_and_reconcile` acquires exclusive local process ownership BEFORE
//! opening the blob layout or metadata index, then reconciles real filesystem
//! state. The lock lives as long as the shared LiveCas, including through
//! coordinator authority acquisition and janitor sweeps. A second process must
//! not reinterpret a live coordinator's authority as a dead boot's authority.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rabs_asupersync::daemon_runtime::SubsystemWork;
use rabs_cas::blob_store::BlobStoreLayout;
use rabs_cas::metadata_store::{RusqliteEngine, SqlMetadataStore};
use rabs_cas::startup_reconciliation::{FilesystemReality, ServingDecision, reconcile_startup};

const MOUNT_LOCK: &str = ".mount.lock";

/// Local filesystem fencing, not a cross-host election mechanism. All production
/// mounts must use this entry point. The inode is retained after unlock: removing
/// it would let an old waiter and a new opener lock different files for one root.
fn acquire_mount_lock(root: &Path) -> Result<File, String> {
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
    let named = validate()?;
    let opened = file
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

/// Production `FilesystemReality`: real `exists` checks plus a recursive
/// walk of the store roots for orphan detection. (The library ships only
/// a set-backed test double, `SetFilesystem`.)
pub struct OsFilesystem {
    roots: Vec<PathBuf>,
}

impl OsFilesystem {
    /// A view over the given store roots.
    #[must_use]
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self { roots }
    }

    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::walk(&path, out);
            } else if let Some(text) = path.to_str() {
                out.push(text.to_string());
            }
        }
    }
}

impl FilesystemReality for OsFilesystem {
    fn exists(&self, store_path: &str) -> bool {
        Path::new(store_path).exists()
    }

    fn all_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        for root in &self.roots {
            Self::walk(root, &mut out);
        }
        out
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
    // Keep this last: all metadata handles drop before process ownership does.
    _mount_lock: File,
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

    let filesystem = OsFilesystem::new(vec![layout.root().to_path_buf()]);
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
            match mounted.gc_sweep(rabs_cas::gc::GcMode::Normal) {
                Ok(s) => println!(
                    "{{\"v\":1,\"kind\":\"janitor-gc-sweep\",\"planned\":{},\"reclaimed\":{},\"skipped\":{}}}",
                    s.planned, s.reclaimed, s.skipped
                ),
                Err(reason) => println!(
                    "{{\"v\":1,\"kind\":\"janitor-gc-sweep-failed\",\"reason\":{:?}}}",
                    reason
                ),
            }
            let usage = mounted.store_usage_bytes();
            if let Some(q) = quota_bytes
                && usage > q
            {
                println!(
                    "{{\"v\":1,\"kind\":\"janitor-quota-exceeded\",\"bytes\":{},\"quota_bytes\":{}}}",
                    usage, q
                );
            }
            println!(
                "{{\"v\":1,\"kind\":\"janitor-store-usage\",\"bytes\":{}}}",
                usage
            );
            cx.trace("janitor region up: store mounted, gc swept, quota checked");
            let _held = mounted;
            shutdown.wait().await;
            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_on_a_fresh_dir_reconciles_clean_and_allows_serving() {
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
            let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        let file = nested.join("obj.bin");
        std::fs::write(&file, b"x").unwrap();
        let fs = OsFilesystem::new(vec![dir.path().to_path_buf()]);
        assert!(fs.exists(file.to_str().unwrap()));
        assert!(!fs.exists(dir.path().join("missing").to_str().unwrap()));
        assert!(fs.all_paths().iter().any(|p| p.ends_with("obj.bin")));
    }

    /// A cold start must succeed on a host whose default umask is
    /// group-writable — which is the Debian/Ubuntu default (0002).
    ///
    /// `create_dir_all` honours the umask, so the mount used to create a
    /// 0775 CAS root and then refuse it for being group-writable: the
    /// daemon declined to mount a directory it had just made itself, and
    /// no cold start could succeed on a stock host. The whole rabsd test
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
        let dir = tempfile::tempdir().unwrap();
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

        let dir = tempfile::tempdir().unwrap();
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
