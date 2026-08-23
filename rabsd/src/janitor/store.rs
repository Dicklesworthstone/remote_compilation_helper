//! Mount the rabs-cas store in the janitor region and reconcile it
//! fail-closed at boot (bead bd-hfhq2).
//!
//! `mount_and_reconcile` opens the content-addressed blob layout and the
//! metadata index (rusqlite — the reference/differential truth engine),
//! then runs `startup_reconciliation::reconcile_startup` against real
//! filesystem state: vanished object copies are repaired out of the
//! index, orphans are reported, and if the authoritative state is torn
//! the store refuses to serve until an operator reset. `janitor_work`
//! wraps that in the subsystem region: mount at boot, hold for the
//! daemon lifetime, release on shutdown.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rabs_asupersync::daemon_runtime::SubsystemWork;
use rabs_cas::blob_store::BlobStoreLayout;
use rabs_cas::metadata_store::{RusqliteEngine, SqlMetadataStore};
use rabs_cas::startup_reconciliation::{FilesystemReality, ServingDecision, reconcile_startup};

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
/// The metadata handle sits behind a `Mutex` because rusqlite's
/// `Connection` is `Send` but not `Sync`; the lock is also the in-process
/// serialization point for the compare-and-set publication transaction.
pub struct LiveCas {
    /// Metadata index (action pointers, location rows, tombstones).
    store: Mutex<SqlMetadataStore<RusqliteEngine>>,
    /// Content-addressed blob byte store layout.
    layout: BlobStoreLayout,
    /// Store root the layout and metadata db live under.
    cas_root: PathBuf,
    /// Startup reconciliation refused serving (torn authoritative state).
    pub serving_refused: bool,
    /// Count of drift rows repaired during reconciliation.
    pub repaired: usize,
    /// Count of drift rows reported (orphans; nothing touched).
    pub reported: usize,
    /// Monotonic plan-sequence for janitor-owned GC receipts.
    pub gc_seq: std::sync::atomic::AtomicU64,
}

impl LiveCas {
    /// The metadata index. Callers hold the lock only for the duration of
    /// one store transaction.
    #[must_use]
    pub fn store(&self) -> &Mutex<SqlMetadataStore<RusqliteEngine>> {
        &self.store
    }

    /// The content-addressed byte store layout.
    #[must_use]
    pub fn layout(&self) -> &BlobStoreLayout {
        &self.layout
    }

    /// The store root.
    #[must_use]
    pub fn cas_root(&self) -> &Path {
        &self.cas_root
    }
}

impl std::fmt::Debug for LiveCas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SqlMetadataStore is not Debug (and printing it would mean
        // taking the lock from a formatter); report the mount facts.
        f.debug_struct("LiveCas")
            .field("cas_root", &self.cas_root)
            .field("serving_refused", &self.serving_refused)
            .field("repaired", &self.repaired)
            .field("reported", &self.reported)
            .finish()
    }
}

/// Open the blob layout + metadata index under `cas_root` and reconcile
/// against filesystem reality. Creates the store on first boot.
///
/// # Errors
/// A string reason if any layout/engine/store/reconcile step fails —
/// the janitor is fail-open at the *daemon* level (its Err becomes an
/// abandoned-obligation reason in the shutdown receipt, builds still pass
/// through locally), but the store itself reconciles fail-*closed*.
pub fn mount_and_reconcile(cas_root: &Path) -> Result<LiveCas, String> {
    std::fs::create_dir_all(cas_root)
        .map_err(|e| format!("cas root {}: {e}", cas_root.display()))?;
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
        cas_root: cas_root.to_path_buf(),
        serving_refused: matches!(report.serving, ServingDecision::Refused(_)),
        repaired: report.repaired.len(),
        reported: report.reported.len(),
        gc_seq: std::sync::atomic::AtomicU64::new(1),
    })
}

/// Build the janitor region work around an ALREADY-MOUNTED store.
///
/// The mount is lifted out of the region because the coordinator needs
/// the same handle to commit through (a region owns its work, not the
/// process's shared state). The region keeps its two obligations: publish
/// the boot evidence, and hold the store until shutdown so the metadata
/// handle is released exactly once, cleanly.
///
/// A failed mount is passed in as the `Err` it was: the region returns it,
/// so a torn or unopenable store still shows up as the janitor's abandoned
/// obligation in the shutdown receipt instead of vanishing.
pub fn janitor_work_holding(mounted: Result<Arc<LiveCas>, String>) -> SubsystemWork {
    Box::new(move |cx, mut shutdown| {
        Box::pin(async move {
            let mounted = mounted?;
            // Structured boot evidence: a mounted, reconciled store.
            println!(
                "{{\"v\":1,\"kind\":\"janitor-cas-mounted\",\"root\":{:?},\"serving_refused\":{},\"repaired\":{},\"reported\":{}}}",
                mounted.cas_root().display().to_string(),
                mounted.serving_refused,
                mounted.repaired,
                mounted.reported,
            );
            cx.trace("janitor region up: rabs-cas store mounted + reconciled");
            // Hold a reference for the region lifetime, so the store
            // outlives every region that may still be using it; the
            // metadata handle is released when the last holder (janitor
            // or coordinator) drops after shutdown.
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
    /// Total bytes of blob content under the store root — the quota
    /// input. Directory walk; no caching (the janitor runs rarely).
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

    /// Run one GC sweep over the live store: plan with the default
    /// world (unlisted objects are CommittedResult/cold), then execute.
    /// The plan `seq` comes from an internal monotonic counter so
    /// receipt rows never collide across sweeps.
    ///
    /// # Errors
    /// A string reason if planning or execution fails against the
    /// metadata store.
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

/// Build the janitor region work WITH quota/GC ownership — the W1
/// remainder. After boot evidence the region RUNS one GC sweep and
/// publishes usage/quota evidence, then holds the store for its
/// lifetime exactly as [`janitor_work_holding`] does.
///
/// `quota_bytes` is advisory-first: a breach is PUBLISHED loudly
/// (`janitor-quota-exceeded` evidence) but does not tear the store or
/// refuse serving by itself — enforcement escalation belongs to the
/// disk-pressure subsystem, not to silent deletion.
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
            if let Some(q) = quota_bytes {
                if usage > q {
                    println!(
                        "{{\"v\":1,\"kind\":\"janitor-quota-exceeded\",\"bytes\":{},\"quota_bytes\":{}}}",
                        usage, q
                    );
                }
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
        // A fresh store has no drift and is not torn.
        assert!(!mounted.serving_refused, "fresh store must allow serving");
        assert_eq!(mounted.repaired, 0);
        assert_eq!(mounted.reported, 0);
        // The on-disk layout was created.
        assert!(cas_root.join("blobs").join("objects").is_dir());
        assert!(cas_root.join("meta.sqlite").exists());
    }

    #[test]
    fn mount_is_idempotent_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let cas_root = dir.path().join("cas");
        let _first = mount_and_reconcile(&cas_root).expect("first mount");
        // Re-opening the same on-disk store must succeed and stay clean —
        // this is the boot-after-boot path a restart exercises.
        let second = mount_and_reconcile(&cas_root).expect("re-mount");
        assert!(!second.serving_refused);
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
}
