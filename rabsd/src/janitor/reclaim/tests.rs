//! Real CAS/filesystem fixtures; no claimed compiler or fleet execution.
use super::*;
use crate::coord::live::CoordLive;
use crate::janitor::store::mount_and_reconcile;
use crate::test_util::private_tempdir;
use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{ActionEntryRow, QuarantineScope, digest_key};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;

fn fixture() -> (tempfile::TempDir, Arc<LiveCas>) {
    let dir = private_tempdir();
    let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    coord.acquire_boot_authority("physical-gc-test").unwrap();
    (dir, cas)
}

fn put(cas: &LiveCas, bytes: &[u8]) -> (TypedDigest, PathBuf) {
    let object = digest_set(bytes, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    let mut store = cas.store().lock().unwrap();
    put_if_absent(
        cas.layout(),
        &mut *store,
        &object,
        &mut &bytes[..],
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    let path = cas
        .layout()
        .published_path(&object, RAW_PROFILE_V1, &object);
    (object, path)
}

fn sweep(collector: &mut Reclaimer, cas: &LiveCas, at: Instant, limit: usize) -> ReclaimReport {
    collector
        .sweep_clock(cas, Duration::from_secs(10), limit, &|| at)
        .unwrap()
}

#[test]
fn physical_gc_unlinks_bytes_only_after_monotonic_grace_and_keeps_object_identity() {
    let (_dir, cas) = fixture();
    let (object, path) = put(&cas, b"actual orphan bytes");
    let mut collector = Reclaimer::default();
    let start = Instant::now();
    assert_eq!(sweep(&mut collector, &cas, start, 4).unlinked_files, 0);
    assert_eq!(
        sweep(&mut collector, &cas, start + Duration::from_secs(9), 4).unlinked_files,
        0
    );
    assert_eq!(fs::read(&path).unwrap(), b"actual orphan bytes");
    let result = sweep(&mut collector, &cas, start + Duration::from_secs(10), 4);
    assert_eq!(result.unlinked_files, 1);
    assert_eq!(result.unlinked_bytes, 19);
    assert!(!path.exists());
    let mut store = cas.store().lock().unwrap();
    assert!(store.object_locations(&object).unwrap().is_empty());
    // GC retires locations, not the typed object identity/evidence ledger.
    let rows = store
        .query(
            "SELECT logical_size FROM objects WHERE key = ?1",
            &[SqlValue::Text(digest_key(&object))],
        )
        .unwrap();
    assert_eq!(rows, vec![vec![SqlValue::Int(19)]]);
}

#[test]
fn new_pin_and_reachability_edge_rescue_a_previously_marked_blob() {
    let (_dir, cas) = fixture();
    let (child, child_path) = put(&cas, b"reachable child");
    let (root, root_path) = put(&cas, b"publication root");
    let start = Instant::now();
    let mut collector = Reclaimer::default();
    sweep(&mut collector, &cas, start, 4);
    {
        let mut store = cas.store().lock().unwrap();
        store
            .add_object_edge(&root, &child, "manifest-entry")
            .unwrap();
        store
            .create_pin(
                7,
                &root,
                "coordinator",
                "action-publication",
                None,
                None,
                true,
                "retained truth",
            )
            .unwrap();
    }
    let result = sweep(&mut collector, &cas, start + Duration::from_secs(100), 4);
    assert_eq!(result.unlinked_files, 0);
    assert!(root_path.is_file() && child_path.is_file());
    assert!(collector.observed.is_empty());
    assert!(
        cas.store()
            .lock()
            .unwrap()
            .due_gc_tombstones(u64::MAX / 2)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn active_generations_and_quarantines_defer_without_mutation() {
    let (_dir, cas) = fixture();
    let (object, path) = put(&cas, b"retain during work");
    let key =
        rabs_key::typed_digest::compute(rabs_key::typed_digest::DOMAIN_ACTION_KEY, b"gc action");
    {
        let mut store = cas.store().lock().unwrap();
        let active = store.active_authority().unwrap().unwrap().digest;
        store
            .upsert_action_entry(&ActionEntryRow {
                action_key: key.clone(),
                key_epoch: 1,
                projection_epoch: 1,
            })
            .unwrap();
        store.create_generation(&active, 1, &key).unwrap();
    }
    let before = cas.store().lock().unwrap().differential_snapshot().unwrap();
    let mut collector = Reclaimer::default();
    assert_eq!(
        sweep(&mut collector, &cas, Instant::now(), 4).state,
        "active-generation"
    );
    assert_eq!(
        cas.store().lock().unwrap().differential_snapshot().unwrap(),
        before
    );
    {
        let mut store = cas.store().lock().unwrap();
        store.tombstone_generation(1).unwrap();
        store
            .add_quarantine(
                QuarantineScope::LogicalObject,
                &digest_key(&object),
                "preserve incident",
            )
            .unwrap();
    }
    let before = cas.store().lock().unwrap().differential_snapshot().unwrap();
    assert_eq!(
        sweep(&mut collector, &cas, Instant::now(), 4).state,
        "quarantine-present"
    );
    assert_eq!(
        cas.store().lock().unwrap().differential_snapshot().unwrap(),
        before
    );
    assert_eq!(fs::read(path).unwrap(), b"retain during work");
}

#[test]
fn restart_restarts_grace_even_when_persistent_tombstones_are_due() {
    let (dir, cas) = fixture();
    let (_object, path) = put(&cas, b"restart candidate");
    let start = Instant::now();
    sweep(&mut Reclaimer::default(), &cas, start, 4);
    drop(cas);
    let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
    CoordLive::with_cas(Arc::clone(&cas))
        .acquire_boot_authority("physical-gc-test")
        .unwrap();
    let mut restarted = Reclaimer::default();
    let later = start + Duration::from_secs(100);
    assert_eq!(sweep(&mut restarted, &cas, later, 4).unlinked_files, 0);
    assert!(path.is_file());
    assert_eq!(
        sweep(&mut restarted, &cas, later + Duration::from_secs(10), 4).unlinked_files,
        1
    );
}

#[test]
fn replacement_inodes_restart_grace_and_hardlinks_never_unlink() {
    let (dir, cas) = fixture();
    let (_object, path) = put(&cas, b"same payload");
    let mut collector = Reclaimer::default();
    let start = Instant::now();
    sweep(&mut collector, &cas, start, 4);
    let retained = dir.path().join("old-inode");
    fs::rename(&path, &retained).unwrap();
    fs::write(&path, b"same payload").unwrap();
    assert_eq!(
        sweep(&mut collector, &cas, start + Duration::from_secs(10), 4).unlinked_files,
        0
    );
    let linked = dir.path().join("hard-link");
    fs::hard_link(&path, &linked).unwrap();
    assert_eq!(
        sweep(&mut collector, &cas, start + Duration::from_secs(30), 4).unlinked_files,
        0
    );
    assert!(path.is_file() && linked.is_file() && retained.is_file());
}

#[test]
fn symlink_shards_and_external_replica_paths_are_not_followed_or_deleted() {
    let (dir, cas) = fixture();
    let (object, path) = put(&cas, b"scope payload");
    let outside = private_tempdir();
    let external = outside.path().join("replica");
    fs::write(&external, b"scope payload").unwrap();
    cas.store()
        .lock()
        .unwrap()
        .add_location(
            &object,
            external.to_str().unwrap(),
            None,
            RAW_PROFILE_V1,
            true,
        )
        .unwrap();
    let shard = path.parent().unwrap();
    let saved = dir.path().join("saved-shard");
    fs::rename(shard, &saved).unwrap();
    symlink(&saved, shard).unwrap();
    let mut collector = Reclaimer::default();
    let start = Instant::now();
    sweep(&mut collector, &cas, start, 4);
    assert_eq!(
        sweep(&mut collector, &cas, start + Duration::from_secs(30), 4).unlinked_files,
        0
    );
    assert_eq!(fs::read(external).unwrap(), b"scope payload");
    assert_eq!(
        fs::read(saved.join(path.file_name().unwrap())).unwrap(),
        b"scope payload"
    );
    assert_eq!(
        cas.store()
            .lock()
            .unwrap()
            .object_locations(&object)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn bounded_passes_prefer_old_observations_and_make_incremental_progress() {
    let (_dir, cas) = fixture();
    let paths: Vec<_> = (0..5)
        .map(|n| put(&cas, format!("blob {n}").as_bytes()).1)
        .collect();
    let mut collector = Reclaimer::default();
    let start = Instant::now();
    let mut total = 0;
    for tick in 0..10 {
        let result = sweep(
            &mut collector,
            &cas,
            start + Duration::from_secs(tick * 10),
            1,
        );
        assert!(result.observed <= 1 && result.unlinked_files <= 1);
        assert!(collector.observed.len() <= 1);
        total += result.unlinked_files;
    }
    assert_eq!(total, 5);
    assert!(paths.iter().all(|path| !path.exists()));
}

#[test]
fn interrupted_unlink_recovers_only_an_exact_intent_and_never_counts_bytes_twice() {
    let (dir, cas) = fixture();
    let (object, path) = put(&cas, b"interrupted unlink");
    let location = LocationRef {
        object_key: digest_key(&object),
        store_path: path.to_str().unwrap().into(),
    };
    cas.store()
        .lock()
        .unwrap()
        .record_decision_receipt(
            INTENT,
            &intent_subject(&location),
            0,
            "unlink",
            "canonical-raw-v1",
        )
        .unwrap();
    // Model absence after the physical frontier while preserving fixture bytes.
    fs::rename(&path, dir.path().join("preserved-unlinked-fixture")).unwrap();
    let mut collector = Reclaimer::default();
    let result = sweep(&mut collector, &cas, Instant::now(), 4);
    assert_eq!(result.unlinked_files, 0);
    assert_eq!(result.unlinked_bytes, 0);
    assert_eq!(result.recovered_locations, 1);
    assert!(
        cas.store()
            .lock()
            .unwrap()
            .object_locations(&object)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        sweep(&mut collector, &cas, Instant::now(), 4).recovered_locations,
        0
    );
}

#[test]
fn missing_without_intent_untrusted_root_and_busy_store_are_not_deletion_permission() {
    let (dir, cas) = fixture();
    let (object, path) = put(&cas, b"unconfirmed absence");
    fs::rename(path, dir.path().join("preserved-missing-fixture")).unwrap();
    let mut collector = Reclaimer::default();
    assert_eq!(
        sweep(&mut collector, &cas, Instant::now(), 4).recovered_locations,
        0
    );
    assert_eq!(
        cas.store()
            .lock()
            .unwrap()
            .object_locations(&object)
            .unwrap()
            .len(),
        1
    );
    {
        let _held = cas.store().lock().unwrap();
        assert_eq!(
            sweep(&mut collector, &cas, Instant::now(), 4).state,
            "store-busy"
        );
    }
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        sweep(&mut collector, &cas, Instant::now(), 4).state,
        "private-root-required"
    );
}

#[test]
fn replaced_mount_fencing_inode_refuses_before_touching_blob_or_metadata() {
    let (dir, cas) = fixture();
    let (_object, path) = put(&cas, b"do not touch replacement mount");
    let start = Instant::now();
    let mut collector = Reclaimer::default();
    sweep(&mut collector, &cas, start, 4);
    let lock = dir.path().join(".mount.lock");
    fs::rename(&lock, dir.path().join("old-held-mount-lock")).unwrap();
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    let before = cas.store().lock().unwrap().differential_snapshot().unwrap();
    let result = collector.sweep_clock(&cas, Duration::from_secs(10), 4, &|| {
        start + Duration::from_secs(100)
    });
    assert!(result.unwrap_err().contains("mount lock changed"));
    assert_eq!(
        cas.store().lock().unwrap().differential_snapshot().unwrap(),
        before
    );
    assert!(path.is_file());
}
