//! Physical reclamation of unpinned raw CAS blobs (H014/H022, bd-hfhq2).
//!
//! The generic GC executor retires metadata locations; it does not unlink
//! filesystem bytes. This adapter uses the SAME planner and pin closure, then
//! unlinks only the exact raw-v1 pathname derived from a typed object identity.
//! No staging directory, quarantine tree, external replica, packed file, pin,
//! publication, or object/edge record is deleted.
//!
//! Initial live scope is deliberately quiescent: any open action generation,
//! quarantine, divergence incident, failed startup reconciliation, or missing
//! authority defers collection. Captures/transfers also retain their existing
//! durable pins. The CAS mutex covers the fresh plan through physical unlink
//! and metadata retirement, excluding new execution admission and pin writes.
//!
//! A candidate needs two observations of the same inode/version separated by
//! monotonic grace. Restart loses those observations and restarts grace; old
//! tombstones or a wall-clock jump cannot accelerate it. An intent is durable
//! before unlink. The containing directory is synced BEFORE metadata is retired.
//! Interrupted unlinks retain their intent/location/tombstone for roll-forward.
//! This assumes the existing exclusive mount and cooperative same-UID writers,
//! not a filesystem sandbox against a malicious process with the same UID.

use super::store::LiveCas;
use rabs_cas::blob_store::{BlobStoreLayout, RAW_PROFILE_V1};
use rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN;
use rabs_cas::gc::{GcMode, GcWorld, LocationRef, mark_plan, plan_gc};
use rabs_cas::metadata_store::{GcReceiptRow, RabsMetadataStore, SqlValue};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::TryLockError;
use std::time::{Duration, Instant};

const INTENT: &str = "rabs-physical-gc-unlink-v1";
const SEQUENCE_SQL: &str = "SELECT MAX(seq) FROM (SELECT seq FROM gc_receipts \
    UNION ALL SELECT marked_seq AS seq FROM gc_tombstones)";
const LOCATION_SQL: &str = "SELECT encoding, quarantined FROM object_locations \
    WHERE object_key = ?1 AND store_path = ?2";
const INTENT_SQL: &str = "SELECT decision FROM decision_receipts \
    WHERE kind = ?1 AND subject = ?2 AND seq = 0";

/// Actual filesystem work, not a count of deleted metadata rows. Unlinked
/// logical bytes need not equal freed blocks (an open fd may retain blocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimReport {
    pub state: &'static str,
    pub observed: usize,
    pub unlinked_files: u64,
    pub unlinked_bytes: u64,
    pub recovered_locations: u64,
    pub retained: u64,
}

impl ReclaimReport {
    fn deferred(state: &'static str) -> Self {
        Self {
            state,
            observed: 0,
            unlinked_files: 0,
            unlinked_bytes: 0,
            recovered_locations: 0,
            retained: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Stamp {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mode: meta.mode(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

#[derive(Debug)]
struct Observation {
    stamp: Stamp,
    since: Instant,
}

/// One janitor-owned collector. Retained observations are bounded by the
/// caller's location limit. Database snapshots still inspect the whole index;
/// the location bound limits physical operations, not metadata scan complexity.
#[derive(Debug, Default)]
pub struct Reclaimer {
    observed: BTreeMap<LocationRef, Observation>,
}

impl Reclaimer {
    /// Reclaim at most `limit` canonical raw locations, after `grace`. A busy
    /// store is deferred rather than queued behind foreground compilation.
    pub fn sweep(
        &mut self,
        cas: &LiveCas,
        grace: Duration,
        limit: usize,
    ) -> Result<ReclaimReport, String> {
        self.sweep_clock(cas, grace, limit, &Instant::now)
    }

    fn sweep_clock(
        &mut self,
        cas: &LiveCas,
        grace: Duration,
        limit: usize,
        clock: &impl Fn() -> Instant,
    ) -> Result<ReclaimReport, String> {
        if grace.is_zero() || !(1..=1024).contains(&limit) {
            return Err("physical GC requires positive grace and 1..=1024 locations".into());
        }
        if cas.serving_refused {
            return Ok(ReclaimReport::deferred("reconciliation-refused"));
        }
        let mut store = match cas.store().try_lock() {
            Ok(store) => store,
            Err(TryLockError::WouldBlock) => return Ok(ReclaimReport::deferred("store-busy")),
            Err(TryLockError::Poisoned(_)) => return Err("metadata lock poisoned".into()),
        };
        if store.active_authority().map_err(db_error)?.is_none() {
            return Ok(ReclaimReport::deferred("no-authority"));
        }
        for (sql, reason) in [
            (
                "SELECT 1 FROM action_generations WHERE tombstoned != 1 LIMIT 1",
                "active-generation",
            ),
            ("SELECT 1 FROM quarantines LIMIT 1", "quarantine-present"),
            (
                "SELECT 1 FROM divergence_incidents LIMIT 1",
                "divergence-evidence",
            ),
            (
                "SELECT 1 FROM object_locations WHERE quarantined != 0 LIMIT 1",
                "quarantined-location",
            ),
        ] {
            if !store.query(sql, &[]).map_err(db_error)?.is_empty() {
                return Ok(ReclaimReport::deferred(reason));
            }
        }
        let root = fs::symlink_metadata(cas.cas_root()).map_err(|e| e.to_string())?;
        if !root.file_type().is_dir() || root.mode() & 0o077 != 0 {
            return Ok(ReclaimReport::deferred("private-root-required"));
        }
        cas.verify_mount_path()?;
        let mut report = ReclaimReport::deferred("completed");
        let result = self.collect(
            &mut *store,
            cas,
            root.uid(),
            grace,
            limit,
            clock,
            &mut report,
        );
        result.map_err(|error| format!(
            "physical GC interrupted after {} unlinks ({} logical bytes) and {} metadata recoveries: {error}",
            report.unlinked_files, report.unlinked_bytes, report.recovered_locations,
        ))?;
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect(
        &mut self,
        store: &mut dyn RabsMetadataStore,
        cas: &LiveCas,
        uid: u32,
        grace: Duration,
        limit: usize,
        clock: &impl Fn() -> Instant,
        report: &mut ReclaimReport,
    ) -> Result<(), String> {
        let layout = cas.layout();
        let seq = next_sequence(store)?;
        // Reuse the existing protection judgment. Nothing executes this full
        // metadata-only plan: filter its eligible locations to the supported
        // physical representation, then bound the actual mark/unlink work.
        let world = GcWorld {
            reclaim_budget: usize::MAX,
            ..GcWorld::default()
        };
        let mut plan = plan_gc(store, &world, GcMode::Normal, seq).map_err(db_error)?;
        // Give already-observed candidates priority over newly arriving blobs.
        plan.reclaim.sort_by(|a, b| {
            (!self.observed.contains_key(a), a).cmp(&(!self.observed.contains_key(b), b))
        });
        let due: BTreeSet<_> = store
            .due_gc_tombstones(seq)
            .map_err(db_error)?
            .into_iter()
            .map(|row| LocationRef {
                object_key: row.object_key,
                store_path: row.store_path,
            })
            .collect();
        let mut selected = Vec::new();
        let mut stamps = BTreeMap::new();
        for location in &plan.reclaim {
            if selected.len() == limit {
                break;
            }
            let Some(path) = canonical_raw_path(layout, location) else {
                report.retained += 1;
                continue;
            };
            let parameters = [
                SqlValue::Text(location.object_key.clone()),
                SqlValue::Text(location.store_path.clone()),
            ];
            let rows = store.query(LOCATION_SQL, &parameters).map_err(db_error)?;
            if !matches!(rows.as_slice(), [row] if matches!(row.as_slice(),
                [SqlValue::Text(encoding), SqlValue::Int(0)] if encoding == RAW_PROFILE_V1))
            {
                report.retained += 1;
                continue;
            }
            let stamp = match inspect(layout, &path, uid) {
                Ok(stamp) => stamp,
                Err(_) => {
                    report.retained += 1;
                    continue;
                }
            };
            if stamp.is_none() && !has_intent(store, location)? {
                // Missing without our durable intent belongs to reconciliation,
                // not evidence that this collector freed any bytes.
                report.retained += 1;
                continue;
            }
            stamps.insert(location.clone(), stamp);
            selected.push(location.clone());
        }
        let keep: BTreeSet<_> = selected.iter().cloned().collect();
        // Newly protected/unsupported objects lose their grace, not their pins.
        // Limit rescue writes to our own bounded observation set.
        for location in self
            .observed
            .keys()
            .filter(|location| !keep.contains(*location))
        {
            store
                .remove_gc_tombstone(&location.object_key, &location.store_path)
                .map_err(db_error)?;
        }
        self.observed.retain(|location, _| keep.contains(location));
        plan.truncated |= plan.reclaim.len() > selected.len();
        plan.reclaim = selected;
        mark_plan(store, &plan, 1).map_err(db_error)?;
        report.observed = plan.reclaim.len();

        for location in &plan.reclaim {
            let stamp = stamps.get(location).ok_or("lost candidate observation")?;
            let path = Path::new(&location.store_path);
            let Some(stamp) = stamp else {
                // A previous unlink may have succeeded before sync or metadata
                // retirement failed. Sync absence, then roll forward; no claim
                // of another physical unlink and no interpretation as a hit.
                cas.verify_mount_path()?;
                if inspect(layout, path, uid)?.is_some() {
                    return Err("missing candidate reappeared before metadata recovery".into());
                }
                sync_parent(path)?;
                retire_location(store, location)?;
                self.observed.remove(location);
                report.recovered_locations += 1;
                continue;
            };
            let ready = self.observed.get(location).is_some_and(|old| {
                old.stamp == *stamp && clock().saturating_duration_since(old.since) >= grace
            }) && due.contains(location);
            if !ready {
                if self
                    .observed
                    .get(location)
                    .is_none_or(|old| old.stamp != *stamp)
                {
                    self.observed.insert(
                        location.clone(),
                        Observation {
                            stamp: stamp.clone(),
                            since: clock(),
                        },
                    );
                }
                continue;
            }
            let total = report
                .unlinked_bytes
                .checked_add(stamp.len)
                .ok_or("byte count overflow")?;
            store
                .record_decision_receipt(
                    INTENT,
                    &intent_subject(location),
                    0,
                    "unlink",
                    "canonical-raw-v1",
                )
                .map_err(db_error)?;
            // Recheck both component types and inode/version immediately before
            // unlink; a replacement or an extra hard link restarts/refuses it.
            if inspect(layout, path, uid)? != Some(stamp.clone()) {
                return Err("candidate changed before physical unlink".into());
            }
            cas.verify_mount_path()?;
            fs::remove_file(path).map_err(|e| format!("unlink {}: {e}", path.display()))?;
            report.unlinked_files += 1;
            report.unlinked_bytes = total;
            sync_parent(path)?;
            retire_location(store, location)?;
            self.observed.remove(location);
        }
        store
            .record_gc_receipt(&GcReceiptRow {
                seq,
                mode: "physical-raw-v1".into(),
                planned: report.observed as u64,
                reclaimed: report.unlinked_files,
                skipped: (report.observed as u64).saturating_sub(report.unlinked_files),
                truncated: plan.truncated,
            })
            .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

fn next_sequence(store: &mut dyn RabsMetadataStore) -> Result<u64, String> {
    let rows = store.query(SEQUENCE_SQL, &[]).map_err(db_error)?;
    let value = match rows.as_slice() {
        [row] => match row.as_slice() {
            [SqlValue::Null] => 0,
            [SqlValue::Int(value)] if *value >= 0 => *value,
            _ => return Err("invalid GC sequence".into()),
        },
        _ => return Err("ambiguous GC sequence".into()),
    };
    value
        .checked_add(1)
        .filter(|value| *value < i64::MAX)
        .map(|value| value as u64)
        .ok_or_else(|| "GC sequence exhausted".into())
}

fn intent_subject(location: &LocationRef) -> String {
    format!("{}\n{}", location.object_key, location.store_path)
}

fn has_intent(store: &mut dyn RabsMetadataStore, location: &LocationRef) -> Result<bool, String> {
    let rows = store
        .query(
            INTENT_SQL,
            &[
                SqlValue::Text(INTENT.into()),
                SqlValue::Text(intent_subject(location)),
            ],
        )
        .map_err(db_error)?;
    match rows.as_slice() {
        [] => Ok(false),
        [row] if matches!(row.as_slice(), [SqlValue::Text(decision)] if decision == "unlink") => {
            Ok(true)
        }
        _ => Err("invalid physical GC intent".into()),
    }
}

fn retire_location(
    store: &mut dyn RabsMetadataStore,
    location: &LocationRef,
) -> Result<(), String> {
    store
        .remove_location_by_key(&location.object_key, &location.store_path)
        .map_err(db_error)?;
    store
        .remove_gc_tombstone(&location.object_key, &location.store_path)
        .map_err(db_error)?;
    Ok(())
}

fn canonical_raw_path(layout: &BlobStoreLayout, location: &LocationRef) -> Option<PathBuf> {
    let hex = location
        .object_key
        .strip_prefix(ATP_OBJECT_CONTENT_DOMAIN)?
        .strip_prefix(':')?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    let object = TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: ATP_OBJECT_CONTENT_DOMAIN,
        bytes,
    };
    let expected = layout.published_path(&object, RAW_PROFILE_V1, &object);
    (expected.as_os_str() == Path::new(&location.store_path).as_os_str()).then_some(expected)
}

fn inspect(layout: &BlobStoreLayout, path: &Path, uid: u32) -> Result<Option<Stamp>, String> {
    let parent = path.parent().ok_or("missing raw shard directory")?;
    for directory in [
        layout.root().to_path_buf(),
        layout.root().join("objects"),
        parent.to_path_buf(),
    ] {
        let meta = fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if !meta.file_type().is_dir() || meta.uid() != uid {
            return Err("raw CAS parent is not an owned real directory".into());
        }
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() && meta.nlink() == 1 && meta.uid() == uid => {
            Ok(Some(Stamp::of(&meta)))
        }
        Ok(_) => Err("raw CAS candidate is linked, non-regular, or foreign-owned".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("missing raw shard directory")?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| format!("sync raw shard {}: {e}", parent.display()))
}

#[cfg(test)]
mod tests;
