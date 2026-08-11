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

/// A live, reconciled store held by the janitor region.
pub struct MountedCas {
    /// Metadata index (action pointers, location rows, tombstones).
    pub store: SqlMetadataStore<RusqliteEngine>,
    /// Content-addressed blob byte store layout.
    pub layout: BlobStoreLayout,
    /// Startup reconciliation refused serving (torn authoritative state).
    pub serving_refused: bool,
    /// Count of drift rows repaired during reconciliation.
    pub repaired: usize,
    /// Count of drift rows reported (orphans; nothing touched).
    pub reported: usize,
}

/// Open the blob layout + metadata index under `cas_root` and reconcile
/// against filesystem reality. Creates the store on first boot.
///
/// # Errors
/// A string reason if any layout/engine/store/reconcile step fails —
/// the janitor is fail-open at the *daemon* level (its Err becomes an
/// abandoned-obligation reason in the shutdown receipt, builds still pass
/// through locally), but the store itself reconciles fail-*closed*.
pub fn mount_and_reconcile(cas_root: &Path) -> Result<MountedCas, String> {
    std::fs::create_dir_all(cas_root).map_err(|e| format!("cas root {}: {e}", cas_root.display()))?;
    let layout =
        BlobStoreLayout::open(&cas_root.join("blobs")).map_err(|e| format!("blob layout: {e:?}"))?;
    let engine = RusqliteEngine::open(&cas_root.join("meta.sqlite"))
        .map_err(|e| format!("metadata engine: {e:?}"))?;
    let mut store = SqlMetadataStore::open(engine).map_err(|e| format!("metadata store: {e:?}"))?;

    let filesystem = OsFilesystem::new(vec![layout.root().to_path_buf()]);
    let report =
        reconcile_startup(&mut store, &filesystem).map_err(|e| format!("reconcile: {e:?}"))?;

    Ok(MountedCas {
        store,
        layout,
        serving_refused: matches!(report.serving, ServingDecision::Refused(_)),
        repaired: report.repaired.len(),
        reported: report.reported.len(),
    })
}

/// Build the janitor region work: mount the store, reconcile fail-closed,
/// hold it for the daemon lifetime, release on shutdown.
#[must_use]
pub fn janitor_work(cas_root: PathBuf) -> SubsystemWork {
    Box::new(move |cx, mut shutdown| {
        Box::pin(async move {
            let mounted = mount_and_reconcile(&cas_root)?;
            // Structured boot evidence: a mounted, reconciled store.
            println!(
                "{{\"v\":1,\"kind\":\"janitor-cas-mounted\",\"root\":{:?},\"serving_refused\":{},\"repaired\":{},\"reported\":{}}}",
                cas_root.display().to_string(),
                mounted.serving_refused,
                mounted.repaired,
                mounted.reported,
            );
            cx.trace("janitor region up: rabs-cas store mounted + reconciled");
            // Own the store for the region lifetime; drop on shutdown
            // flushes and releases the metadata handle cleanly.
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
