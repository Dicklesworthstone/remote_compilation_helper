//! Cache inventory reporting (bead K010; plan §5399 operator surface).
//!
//! What is cached WHERE, at three layers, with access control on the
//! namespace dimension:
//!
//! - **L1** — the edge's in-memory [`L1ActionCache`] (live entries +
//!   lookup stats), exposed read-only;
//! - **L2** — worker/project result caches on disk (`<root>/<project>/
//!   <hash>` layout), enumerated locally;
//! - **toolchains** — per-worker recorded capabilities from the metadata
//!   store.
//!
//! ## Access control
//!
//! Project names are a NAMESPACE: a viewer holding
//! [`NamespacePolicy::allowed`] sees those projects' names and counts;
//! everything else contributes ONLY an aggregate hidden count —
//! existence itself is hidden, not merely redacted. This mirrors the
//! redaction discipline (values never leak past a class boundary)
//! applied at listing granularity. There is no wildcard grant: an empty
//! allowed-set hides every project name.
//!
//! Worker-over-SSH probing is a follow-on once a wire envelope carries
//! [`crate::pressure::WorkerPressureSnapshot`]; this module covers the
//! LOCAL edge plus store-recorded facts.

use crate::l1_cache::{L1ActionCache, L1EntrySnapshot, LookupStats};
use crate::metadata_store::{SqlEngine, SqlMetadataStore, SqlValue};
use std::collections::BTreeMap;
use std::path::Path;

/// The namespace access policy for one inventory view.
#[derive(Debug, Clone, Default)]
pub struct NamespacePolicy {
    /// Project namespaces whose names may appear. Empty hides all.
    pub allowed: BTreeMap<String, ()>,
}

impl NamespacePolicy {
    /// Allow-list constructor.
    #[must_use]
    pub fn allowing<I: IntoIterator<Item = String>>(namespaces: I) -> Self {
        Self {
            allowed: namespaces.into_iter().map(|n| (n, ())).collect(),
        }
    }

    /// Whether a project's NAME may appear in this view.
    #[must_use]
    pub fn visible(&self, project: &str) -> bool {
        self.allowed.contains_key(project)
    }
}

/// One visible L2 project cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2ProjectCache {
    /// Project namespace (directory name under the cache root).
    pub project: String,
    /// Result-hash directories held for this project.
    pub hash_dirs: u32,
}

/// Per-worker toolchain facts recorded by admission/probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerToolchains {
    /// Worker identity.
    pub worker: String,
    /// Recorded capabilities that look like toolchains (rustc/<ver>,
    /// cargo/<ver>, ...). Filtered, never raw rows.
    pub toolchains: Vec<String>,
}

/// Aggregate CAS/store facts (counts only — digests are content-derived
/// and may name restricted sources, so they are NOT listed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoreCacheFacts {
    /// Distinct action entries known to the store.
    pub action_entries: u64,
    /// Workers with recorded capabilities.
    pub workers_with_capabilities: u64,
}

/// The full inventory receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheInventoryReport {
    /// L1 section; `None` when the caller has no live edge cache mounted.
    pub l1: Option<L1Inventory>,
    /// Visible L2 project caches (sorted by name).
    pub l2_visible: Vec<L2ProjectCache>,
    /// How many projects were hidden by the namespace policy. Names of
    /// hidden projects NEVER appear anywhere in the report.
    pub restricted_project_count: u32,
    /// Toolchain facts per worker.
    pub toolchains: Vec<WorkerToolchains>,
    /// Store-side aggregate facts.
    pub store: StoreCacheFacts,
}

/// L1 section of the receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L1Inventory {
    /// Configured capacity.
    pub capacity: usize,
    /// Live entries, FIFO order (oldest first).
    pub entries: Vec<L1EntrySnapshot>,
    /// Lookup statistics.
    pub stats: LookupStats,
}

/// Enumerate L2 project caches under `l2_root` (`<project>/<hash>`).
///
/// An absent root is an empty inventory; unreadable entries are skipped —
/// enumeration is best-effort visibility and must never fail a doctor.
pub fn collect_l2(l2_root: &Path) -> Vec<L2ProjectCache> {
    let mut out = Vec::new();
    let Ok(projects) = std::fs::read_dir(l2_root) else {
        return out;
    };
    for project in projects.flatten() {
        let path = project.path();
        if !path.is_dir() {
            continue;
        }
        let mut hash_dirs = 0u32;
        if let Ok(hashes) = std::fs::read_dir(&path) {
            for hash in hashes.flatten() {
                if hash.path().is_dir() {
                    hash_dirs += 1;
                }
            }
        }
        out.push(L2ProjectCache {
            project: project.file_name().to_string_lossy().into_owned(),
            hash_dirs,
        });
    }
    out.sort_by(|a, b| a.project.cmp(&b.project));
    out
}

fn count_first_int<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
    sql: &str,
) -> Result<u64, crate::metadata_store::StoreError> {
    let rows = store.engine_mut().query(sql, &[])?;
    Ok(rows.first().and_then(|r| r.first()).map_or(0, |v| match v {
        SqlValue::Int(n) => (*n).max(0) as u64,
        _ => 0,
    }))
}

fn store_facts<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
) -> Result<StoreCacheFacts, crate::metadata_store::StoreError> {
    let action_entries = count_first_int(store, "SELECT COUNT(*) FROM action_entries")?;
    let workers_with_capabilities = count_first_int(
        store,
        "SELECT COUNT(DISTINCT worker) FROM worker_capabilities",
    )?;
    Ok(StoreCacheFacts {
        action_entries,
        workers_with_capabilities,
    })
}

fn worker_toolchains<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
) -> Result<Vec<WorkerToolchains>, crate::metadata_store::StoreError> {
    let rows = store.engine_mut().query(
        "SELECT worker, capability FROM worker_capabilities \
         WHERE capability LIKE 'rustc/%' OR capability LIKE 'cargo/%' \
         ORDER BY worker, capability",
        &[],
    )?;
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in &rows {
        let worker = match row.first() {
            Some(SqlValue::Text(t)) => t.clone(),
            _ => continue,
        };
        let cap = match row.get(1) {
            Some(SqlValue::Text(t)) => t.clone(),
            _ => continue,
        };
        map.entry(worker).or_default().push(cap);
    }
    Ok(map
        .into_iter()
        .map(|(worker, toolchains)| WorkerToolchains { worker, toolchains })
        .collect())
}

/// Build the full inventory.
///
/// # Errors
/// Typed [`crate::metadata_store::StoreError`] from the store scans.
pub fn build_report<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
    l1: Option<&L1ActionCache>,
    l2_root: &Path,
    policy: &NamespacePolicy,
) -> Result<CacheInventoryReport, crate::metadata_store::StoreError> {
    // L2 enumeration happens BEFORE the policy filter: hidden projects
    // collapse into a count, their names never entering the report.
    let all_l2 = collect_l2(l2_root);
    let mut l2_visible = Vec::new();
    let mut restricted_project_count = 0u32;
    for project in all_l2 {
        if policy.visible(&project.project) {
            l2_visible.push(project);
        } else {
            restricted_project_count += 1;
        }
    }

    let l1 = l1.map(|cache| L1Inventory {
        capacity: cache.capacity(),
        entries: cache.snapshot(),
        stats: cache.stats(),
    });

    Ok(CacheInventoryReport {
        l1,
        l2_visible,
        restricted_project_count,
        toolchains: worker_toolchains(store)?,
        store: store_facts(store)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_cache::LookupStats;

    fn seed_l2(root: &Path) {
        for (project, hashes) in [("proj-alpha", 3), ("proj-beta", 1), ("proj-secret", 9)] {
            for h in 0..hashes {
                let dir = root.join(project).join(format!("hash-{h}"));
                std::fs::create_dir_all(dir).expect("seed l2");
            }
        }
    }

    fn fixture_store() -> SqlMetadataStore<crate::metadata_store::RusqliteEngine> {
        SqlMetadataStore::open(crate::metadata_store::RusqliteEngine::open_in_memory().unwrap())
            .expect("store")
    }

    #[test]
    fn l2_enumeration_counts_hash_directories_per_project() {
        let dir = tempfile::tempdir().unwrap();
        seed_l2(dir.path());
        let mut all = collect_l2(dir.path());
        assert_eq!(all.len(), 3);
        all.retain(|p| p.project == "proj-secret");
        assert_eq!(all[0].hash_dirs, 9);
    }

    #[test]
    fn namespace_policy_hides_existence_not_just_names() {
        let dir = tempfile::tempdir().unwrap();
        seed_l2(dir.path());
        let mut store = fixture_store();

        // A viewer allowed ONLY proj-alpha: beta is VISIBLE-named, secret
        // collapses into a bare count.
        let policy = NamespacePolicy::allowing(["proj-alpha".to_owned(), "proj-beta".to_owned()]);
        let report = build_report(&mut store, None, dir.path(), &policy).unwrap();

        assert_eq!(report.l2_visible.len(), 2);
        assert!(report.l2_visible.iter().all(|p| p.project != "proj-secret"));
        assert_eq!(report.restricted_project_count, 1);

        // A viewer with NO grants sees zero names but honest totals.
        let nobody = NamespacePolicy::default();
        let report = build_report(&mut store, None, dir.path(), &nobody).unwrap();
        assert!(report.l2_visible.is_empty());
        assert_eq!(report.restricted_project_count, 3);
    }

    #[test]
    fn l1_section_reports_capacity_live_entries_and_stats() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = fixture_store();
        let mut cache = L1ActionCache::new(8, None);
        let key = rabs_protocol::result_identity::TypedDigest {
            algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [7u8; 32],
        };
        cache.insert(
            key.clone(),
            crate::metadata_store::ActionEntryRow {
                action_key: key.clone(),
                key_epoch: 2,
                projection_epoch: 5,
            },
        );

        let policy = NamespacePolicy::allowing(["proj-alpha".to_owned()]);
        let report = build_report(&mut store, Some(&cache), dir.path(), &policy).unwrap();
        let l1 = report.l1.expect("l1 section present");
        assert_eq!(l1.capacity, 8);
        assert_eq!(l1.entries.len(), 1);
        assert_eq!(l1.entries[0].key_epoch, 2);
        assert_eq!(l1.entries[0].projection_epoch, 5);
        assert_eq!(l1.stats.hits, 0);

        // Silence unused-import style lints for types used above only via
        // inference paths.
        let _: Option<LookupStats> = None;
    }
}
