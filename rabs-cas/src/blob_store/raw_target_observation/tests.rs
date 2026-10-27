use super::*;
use crate::blob_store::{
    DurabilityPolicy, FaultPoint, PutLimits, PutOutcome, publish_staged_observed_inner,
    publish_staged_with_observation, put_if_absent,
};
use crate::digest_set::{DigestRequest, digest_set};
use crate::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore};
use std::fs;
use std::io::{Seek, SeekFrom};

fn store() -> SqlMetadataStore<RusqliteEngine> {
    SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap()
}

fn id(bytes: &[u8]) -> TypedDigest {
    digest_set(bytes, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id
}

fn stage(layout: &BlobStoreLayout, bytes: &[u8]) -> PathBuf {
    let path = layout.root().join("staging/incoming.raw");
    fs::write(&path, bytes).unwrap();
    path
}

fn seed(layout: &BlobStoreLayout, bytes: &[u8]) -> TypedDigest {
    let key = id(bytes);
    let mut reader = bytes;
    put_if_absent(
        layout,
        &mut store(),
        &key,
        &mut reader,
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    key
}

#[test]
fn raw_observation_preserves_empty_binary_and_multibuffer_publication() {
    for bytes in [vec![], vec![0, 255, 128, 10], vec![37; 3 * 65536 + 7]] {
        let temp = tempfile::tempdir().unwrap();
        let layout = BlobStoreLayout::open(temp.path()).unwrap();
        let key = id(&bytes);
        let mut db = store();
        let missing = RawTargetObservation::observe(&layout, &key, u64::MAX).unwrap();
        assert!(missing.file.is_none());
        assert!(!db.object_located(&key).unwrap());
        let incoming = stage(&layout, &bytes);
        assert!(matches!(
            publish_staged_with_observation(
                &layout,
                &mut db,
                &key,
                &incoming,
                DurabilityPolicy::FULL,
                &missing,
            )
            .unwrap(),
            PutOutcome::Stored { .. }
        ));
        let observation = RawTargetObservation::observe(&layout, &key, u64::MAX).unwrap();
        let incoming = stage(&layout, &bytes);
        assert!(matches!(
            publish_staged_with_observation(
                &layout,
                &mut db,
                &key,
                &incoming,
                DurabilityPolicy::FULL,
                &observation,
            )
            .unwrap(),
            PutOutcome::IdempotentDuplicate { .. }
        ));
        assert!(!incoming.exists());
        assert_eq!(
            fs::read(layout.published_path(&key, RAW_PROFILE_V1, &key)).unwrap(),
            bytes
        );
        assert!(db.object_located(&key).unwrap());
    }
}

#[test]
fn create_race_refuses_without_metadata_or_stage_loss_then_reobserves() {
    let temp = tempfile::tempdir().unwrap();
    let layout = BlobStoreLayout::open(temp.path()).unwrap();
    let bytes = b"winner and candidate";
    let key = id(bytes);
    let missing = RawTargetObservation::observe(&layout, &key, 100).unwrap();
    seed(&layout, bytes);
    let incoming = stage(&layout, bytes);
    let mut db = store();
    let error = publish_staged_with_observation(
        &layout,
        &mut db,
        &key,
        &incoming,
        DurabilityPolicy::FULL,
        &missing,
    )
    .unwrap_err();
    assert!(RawTargetObservation::changed(&error));
    assert_eq!(fs::read(&incoming).unwrap(), bytes);
    assert!(!db.object_located(&key).unwrap());
    let current = RawTargetObservation::observe(&layout, &key, 100).unwrap();
    assert!(matches!(
        publish_staged_with_observation(
            &layout,
            &mut db,
            &key,
            &incoming,
            DurabilityPolicy::FULL,
            &current,
        )
        .unwrap(),
        PutOutcome::IdempotentDuplicate { .. }
    ));
}

#[test]
fn equal_byte_replacement_cannot_reuse_an_old_descriptor_witness() {
    let temp = tempfile::tempdir().unwrap();
    let layout = BlobStoreLayout::open(temp.path()).unwrap();
    let bytes = b"unchanged bytes are not unchanged custody";
    let key = seed(&layout, bytes);
    let target = layout.published_path(&key, RAW_PROFILE_V1, &key);
    let old = RawTargetObservation::observe(&layout, &key, 100).unwrap();
    fs::rename(&target, temp.path().join("retained-original")).unwrap();
    fs::write(&target, bytes).unwrap();
    let incoming = stage(&layout, bytes);
    let mut db = store();
    let error = publish_staged_with_observation(
        &layout,
        &mut db,
        &key,
        &incoming,
        DurabilityPolicy::FULL,
        &old,
    )
    .unwrap_err();
    assert!(RawTargetObservation::changed(&error));
    assert!(!db.object_located(&key).unwrap());
    assert_eq!(fs::read(incoming).unwrap(), bytes);
    let current = RawTargetObservation::observe(&layout, &key, 100).unwrap();
    assert_eq!(current.digest(&target, &key).unwrap(), key);
    assert!(
        old.digest(&target, &key).is_err(),
        "refresh cannot revive the old witness"
    );
}

#[test]
fn restored_mtime_cannot_hide_a_same_length_rewrite() {
    let temp = tempfile::tempdir().unwrap();
    let layout = BlobStoreLayout::open(temp.path()).unwrap();
    let key = seed(&layout, b"original");
    let target = layout.published_path(&key, RAW_PROFILE_V1, &key);
    let before = fs::metadata(&target).unwrap();
    let observation = RawTargetObservation::observe(&layout, &key, 100).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    fs::write(&target, b"modified").unwrap();
    filetime::set_file_times(
        &target,
        filetime::FileTime::from_last_access_time(&before),
        filetime::FileTime::from_last_modification_time(&before),
    )
    .unwrap();
    let error = observation.digest(&target, &key).unwrap_err();
    assert!(RawTargetObservation::changed(&error));
}

#[test]
fn growth_truncation_permission_change_and_hardlink_change_invalidate() {
    use std::os::unix::fs::PermissionsExt;
    for change in 0..4 {
        let temp = tempfile::tempdir().unwrap();
        let layout = BlobStoreLayout::open(temp.path()).unwrap();
        let key = seed(&layout, b"original");
        let target = layout.published_path(&key, RAW_PROFILE_V1, &key);
        let observation = RawTargetObservation::observe(&layout, &key, 100).unwrap();
        match change {
            0 => fs::write(&target, b"original plus growth").unwrap(),
            1 => fs::write(&target, b"small").unwrap(),
            2 => fs::set_permissions(&target, fs::Permissions::from_mode(0o400)).unwrap(),
            _ => fs::hard_link(&target, temp.path().join("another-link")).unwrap(),
        }
        assert!(RawTargetObservation::changed(
            &observation.digest(&target, &key).unwrap_err()
        ));
    }
}

#[test]
fn observation_cannot_cross_store_path_digest_or_digest_domain() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let layout = BlobStoreLayout::open(first.path()).unwrap();
    let other = BlobStoreLayout::open(second.path()).unwrap();
    let bytes = b"bound object";
    let key = seed(&layout, bytes);
    let observation = RawTargetObservation::observe(&layout, &key, 100).unwrap();
    let incoming = stage(&other, bytes);
    let mut db = store();
    let error = publish_staged_with_observation(
        &other,
        &mut db,
        &key,
        &incoming,
        DurabilityPolicy::FULL,
        &observation,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PutError::Io {
            step: "raw-target-observation-binding",
            ..
        }
    ));
    assert!(incoming.exists());
    assert!(!db.object_located(&key).unwrap());
    let target = layout.published_path(&key, RAW_PROFILE_V1, &key);
    assert!(observation.digest(&target, &id(b"other")).is_err());
    let mut foreign = key.clone();
    foreign.domain = "rabs.foreign-digest.v1";
    assert!(observation.digest(&target, &foreign).is_err());
}

#[test]
fn mismatch_uses_the_original_collision_quarantine_not_a_fast_duplicate() {
    let temp = tempfile::tempdir().unwrap();
    let layout = BlobStoreLayout::open(temp.path()).unwrap();
    let good = b"trusted candidate";
    let key = id(good);
    let mut db = store();
    let mut reader = good.as_slice();
    put_if_absent(
        &layout,
        &mut db,
        &key,
        &mut reader,
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    let target = layout.published_path(&key, RAW_PROFILE_V1, &key);
    fs::write(&target, b"different corrupt bytes").unwrap();
    let observation = RawTargetObservation::observe(&layout, &key, 100).unwrap();
    assert_ne!(observation.digest(&target, &key).unwrap(), key);
    let incoming = stage(&layout, good);
    let error = publish_staged_with_observation(
        &layout,
        &mut db,
        &key,
        &incoming,
        DurabilityPolicy::FULL,
        &observation,
    )
    .unwrap_err();
    let PutError::CollisionIncident {
        existing_path,
        preserved_incoming_path,
        ..
    } = error
    else {
        panic!("collision must not become a duplicate: {error:?}");
    };
    assert_eq!(fs::read(existing_path).unwrap(), b"different corrupt bytes");
    assert_eq!(fs::read(preserved_incoming_path).unwrap(), good);
    assert!(!incoming.exists());
}

#[test]
fn oversized_and_special_targets_are_never_treated_as_absent() {
    let temp = tempfile::tempdir().unwrap();
    let layout = BlobStoreLayout::open(temp.path()).unwrap();
    let key = seed(&layout, b"12345678");
    assert!(matches!(
        RawTargetObservation::observe(&layout, &key, 7),
        Err(PutError::LogicalLimitExceeded { limit: 7 })
    ));
    let target = layout.published_path(&key, RAW_PROFILE_V1, &key);
    let original = temp.path().join("held-original");
    fs::rename(&target, &original).unwrap();
    std::os::unix::fs::symlink(&original, &target).unwrap();
    assert!(RawTargetObservation::observe(&layout, &key, 100).is_err());
    fs::remove_file(&target).unwrap();
    fs::create_dir(&target).unwrap();
    assert!(RawTargetObservation::observe(&layout, &key, 100).is_err());
}

#[test]
fn observed_descriptor_cursor_is_not_used_for_duplicate_replay() {
    let temp = tempfile::tempdir().unwrap();
    let layout = BlobStoreLayout::open(temp.path()).unwrap();
    let bytes = b"cursor remains private";
    let key = seed(&layout, bytes);
    let mut observation = RawTargetObservation::observe(&layout, &key, 100).unwrap();
    observation
        .file
        .as_mut()
        .unwrap()
        .file
        .seek(SeekFrom::Start(3))
        .unwrap();
    let incoming = stage(&layout, bytes);
    publish_staged_with_observation(
        &layout,
        &mut store(),
        &key,
        &incoming,
        DurabilityPolicy::FULL,
        &observation,
    )
    .unwrap();
    assert_eq!(
        observation
            .file
            .as_mut()
            .unwrap()
            .file
            .stream_position()
            .unwrap(),
        3
    );
}

#[test]
fn prepared_new_put_retains_every_existing_publish_fault_boundary() {
    for fault in [
        FaultPoint::StagingSynced,
        FaultPoint::Linked,
        FaultPoint::DirectorySynced,
        FaultPoint::MetadataRecorded,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let layout = BlobStoreLayout::open(temp.path()).unwrap();
        let bytes = b"crash boundary object";
        let key = id(bytes);
        let observation = RawTargetObservation::observe(&layout, &key, 100).unwrap();
        let incoming = stage(&layout, bytes);
        let mut db = store();
        let result = publish_staged_observed_inner(
            &layout,
            &mut db,
            &key,
            &incoming,
            bytes.len() as u64,
            DurabilityPolicy::FULL,
            Some(fault),
            RAW_PROFILE_V1,
            &key,
            Some(&observation),
        );
        assert_eq!(result, Err(PutError::CrashInjected(fault)));
        let target = layout.published_path(&key, RAW_PROFILE_V1, &key);
        if target.exists() {
            assert_eq!(fs::read(&target).unwrap(), bytes);
        }
        let retry = RawTargetObservation::observe(&layout, &key, 100).unwrap();
        publish_staged_with_observation(
            &layout,
            &mut db,
            &key,
            &incoming,
            DurabilityPolicy::FULL,
            &retry,
        )
        .unwrap();
        assert_eq!(fs::read(target).unwrap(), bytes);
        assert!(db.object_located(&key).unwrap());
        assert!(!incoming.exists());
    }
}
