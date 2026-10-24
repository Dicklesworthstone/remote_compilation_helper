//! The production disk pool and verifier are exercised with explicit fixture
//! keys below; the native Cargo tests additionally check actual freshness and
//! execution after cache teardown/reopen. No TLS or namespace evidence is implied.

use super::*;

fn persistent(root: &Path, bytes: u64, epoch: &str) -> Arc<TargetCache> {
    Arc::new(TargetCache::open_persistent(bytes, root, epoch).unwrap())
}

fn seed_path(cache: &TargetCache) -> PathBuf {
    cache
        .state
        .lock()
        .unwrap()
        .entries
        .front()
        .unwrap()
        .tree
        .directory
        .path()
        .to_path_buf()
}

fn generations(root: &Path) -> Vec<PathBuf> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != "owner.lock")
        .collect()
}

#[test]
fn completed_target_survives_reopen_with_private_inodes_and_exact_timestamps() {
    let disk = private_directory("rabs-persistent-target-").unwrap();
    let (source, plan, target, _) = small_fixture();
    fs::hard_link(
        target.backing().join("artifact"),
        target.backing().join("alias"),
    )
    .unwrap();
    let captured = target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    let cache = persistent(disk.path(), 32, "host-v1");
    let key = TargetKey([3; 32]);
    let (attempt, restored) = cache
        .acquire(
            key,
            None,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    attempt
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let path = seed_path(&cache);
    let (source_times, target_times) = {
        let state = cache.state.lock().unwrap();
        (
            state.entries[0].source.clone(),
            state.entries[0].tree.files.clone(),
        )
    };
    drop(cache);
    assert!(path.parent().unwrap().join("seed.json").is_file());
    let cache = persistent(disk.path(), 32, "host-v1");
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 8);
    let (attempt, restored) = cache
        .acquire(
            key,
            None,
            inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            2,
            &|| false,
        )
        .unwrap();
    let restored = restored.expect("complete seed survives process-cache ownership restart");
    assert_eq!(
        SourceTimes::capture(&attempt.inputs, &|| false).unwrap(),
        source_times
    );
    assert_eq!(
        cache.state.lock().unwrap().entries[0].tree.files,
        target_times
    );
    let original = fs::metadata(path.join("artifact")).unwrap();
    let copied = fs::metadata(restored.backing().join("artifact")).unwrap();
    let alias = fs::metadata(restored.backing().join("alias")).unwrap();
    assert_ne!(
        (original.dev(), original.ino()),
        (copied.dev(), copied.ino())
    );
    assert_eq!((copied.dev(), copied.ino()), (alias.dev(), alias.ino()));
    fs::write(restored.backing().join("artifact"), b"edit").unwrap();
    assert_eq!(fs::read(path.join("artifact")).unwrap(), b"seed");
    assert_eq!(fs::read(restored.backing().join("alias")).unwrap(), b"edit");
    assert_eq!(
        fs::metadata(restored.backing().join("empty-out-dir"))
            .unwrap()
            .mode()
            & 0o777,
        0o750
    );
}

#[test]
fn cancelled_pending_and_crash_leftovers_never_become_restart_hits() {
    let disk = private_directory("rabs-persistent-pending-").unwrap();
    let cache = persistent(disk.path(), 32, "host-v1");
    let (pending, _, _) = stage_small(&cache, TargetKey([1; 32]));
    let path = pending
        .seed
        .as_ref()
        .unwrap()
        .tree
        .directory
        .path()
        .parent()
        .unwrap()
        .to_path_buf();
    assert!(path.join("pending.json").is_file());
    assert!(!path.join("seed.json").exists());
    drop(pending);
    assert!(
        !path.exists(),
        "cancellation reclaims its still-charged generation"
    );
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 0);
    drop(cache);

    // Reconstruct a process-crash prefix: partially copied bytes with no final
    // marker. Recovery must reclaim them before admitting a new byte budget.
    let orphan = disk.path().join("generation-0000000000000002");
    fs::create_dir(&orphan).unwrap();
    fs::set_permissions(&orphan, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(orphan.join("target")).unwrap();
    fs::write(orphan.join("target/unfinished"), [0; 64]).unwrap();
    fs::write(orphan.join("pending.json"), b"truncated{").unwrap();
    let cache = persistent(disk.path(), 4, "host-v1");
    assert!(cache.state.lock().unwrap().entries.is_empty());
    assert!(generations(disk.path()).is_empty());
    stage_small(&cache, TargetKey([2; 32])).0.publish();
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 4);
}

#[test]
fn persistent_lock_is_retained_by_a_live_generation_lease() {
    let disk = private_directory("rabs-persistent-lock-").unwrap();
    let cache = persistent(disk.path(), 32, "host-v1");
    stage_small(&cache, TargetKey([1; 32])).0.publish();
    let lease = Arc::clone(&cache.state.lock().unwrap().entries[0]);
    assert!(TargetCache::open_persistent(32, disk.path(), "host-v1").is_err());
    drop(cache);
    assert!(
        TargetCache::open_persistent(32, disk.path(), "host-v1").is_err(),
        "a target reader still owns the store lock"
    );
    drop(lease);
    assert_eq!(
        persistent(disk.path(), 32, "host-v1")
            .state
            .lock()
            .unwrap()
            .entries
            .len(),
        1
    );
}

#[test]
fn epoch_rotation_and_reduced_quota_reclaim_old_targets_in_the_same_root() {
    let disk = private_directory("rabs-persistent-epoch-").unwrap();
    let cache = persistent(disk.path(), 12, "host-v1");
    for key in [1, 2, 3] {
        stage_small(&cache, TargetKey([key; 32])).0.publish();
    }
    assert_eq!(generations(disk.path()).len(), 3);
    drop(cache);
    let cache = persistent(disk.path(), 4, "host-v1");
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].key, TargetKey([3; 32]));
        assert_eq!(state.retained_bytes, 4);
    }
    assert_eq!(generations(disk.path()).len(), 1);
    drop(cache);
    let cache = persistent(disk.path(), 4, "host-v2");
    assert!(cache.state.lock().unwrap().entries.is_empty());
    assert!(generations(disk.path()).is_empty());
    stage_small(&cache, TargetKey([4; 32])).0.publish();
    drop(cache);
    assert_eq!(
        persistent(disk.path(), 4, "host-v2")
            .state
            .lock()
            .unwrap()
            .entries
            .len(),
        1
    );
    for epoch in ["", "../host", "-host", "host space", "host/one", "höst"] {
        assert!(TargetCache::open_persistent(4, disk.path(), epoch).is_err());
    }
    assert!(TargetCache::open_persistent(4, disk.path(), &"x".repeat(129)).is_err());
}

fn rewrite_metadata(path: &Path, change: impl FnOnce(&mut serde_json::Value), checksum: bool) {
    let mut envelope: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    change(&mut envelope["seed"]);
    if checksum {
        let hash: [u8; 32] = Sha256::digest(serde_json::to_vec(&envelope["seed"]).unwrap()).into();
        envelope["sha256"] = serde_json::json!(crate::source_transfer::hex(&hash));
    }
    fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
}

#[test]
fn recovery_rejects_corrupt_bytes_paths_timestamps_aliases_and_metadata() {
    for case in [
        "bytes",
        "extra",
        "time",
        "external-alias",
        "symlink",
        "checksum",
        "schema",
        "source-path",
        "missing-parent",
        "alias",
        "length",
        "oversized-metadata",
    ] {
        let disk = private_directory("rabs-persistent-corrupt-").unwrap();
        let cache = persistent(disk.path(), 32, "host-v1");
        stage_small(&cache, TargetKey([1; 32])).0.publish();
        let path = seed_path(&cache);
        let metadata = path.parent().unwrap().join("seed.json");
        drop(cache);
        let witness = private_directory("rabs-persistent-witness-").unwrap();
        match case {
            "bytes" => fs::write(path.join("artifact"), b"evil").unwrap(),
            "extra" => fs::write(path.join("unrecorded"), [0; 64]).unwrap(),
            "time" => File::open(path.join("artifact"))
                .unwrap()
                .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
                .unwrap(),
            "external-alias" => {
                fs::hard_link(path.join("artifact"), witness.path().join("outside")).unwrap()
            }
            "symlink" => {
                fs::write(witness.path().join("outside"), b"seed").unwrap();
                std::os::unix::fs::symlink(witness.path(), path.join("outside-link")).unwrap();
            }
            "checksum" => rewrite_metadata(
                &metadata,
                |seed| seed["key"] = serde_json::json!("00".repeat(32)),
                false,
            ),
            "schema" => rewrite_metadata(
                &metadata,
                |seed| seed["schema"] = serde_json::json!("future-v2"),
                true,
            ),
            "source-path" => rewrite_metadata(
                &metadata,
                |seed| seed["source"][0][0] = serde_json::json!("../escape"),
                true,
            ),
            "missing-parent" => rewrite_metadata(
                &metadata,
                |seed| seed["directories"] = serde_json::json!([]),
                true,
            ),
            "alias" => rewrite_metadata(
                &metadata,
                |seed| seed["files"][0][5] = serde_json::json!("../outside"),
                true,
            ),
            "length" => {
                rewrite_metadata(&metadata, |seed| seed["bytes"] = serde_json::json!(0), true)
            }
            "oversized-metadata" => OpenOptions::new()
                .write(true)
                .open(&metadata)
                .unwrap()
                .set_len(16 * 1024 * 1024 + 1)
                .unwrap(),
            _ => unreachable!(),
        }
        let cache = persistent(disk.path(), 32, "host-v1");
        assert!(cache.state.lock().unwrap().entries.is_empty(), "{case}");
        assert!(
            generations(disk.path()).is_empty(),
            "{case}: corrupt bytes cannot remain uncharged"
        );
        if matches!(case, "external-alias" | "symlink") {
            assert_eq!(
                fs::read(witness.path().join("outside")).unwrap(),
                b"seed",
                "reclamation must not follow an external alias"
            );
        }
    }
}

#[test]
fn unknown_cache_data_is_refused_without_reclamation() {
    let disk = private_directory("rabs-persistent-unrelated-").unwrap();
    let cache = persistent(disk.path(), 32, "host-v1");
    stage_small(&cache, TargetKey([1; 32])).0.publish();
    let unrelated = seed_path(&cache).parent().unwrap().join("operator-note");
    fs::write(&unrelated, b"keep this").unwrap();
    drop(cache);
    assert!(TargetCache::open_persistent(32, disk.path(), "host-v1").is_err());
    assert_eq!(fs::read(&unrelated).unwrap(), b"keep this");
}

#[test]
fn failed_reclamation_keeps_bytes_charged_and_disables_new_captures() {
    let disk = private_directory("rabs-persistent-reclaim-").unwrap();
    let cache = persistent(disk.path(), 4, "host-v1");
    stage_small(&cache, TargetKey([1; 32])).0.publish();
    let root = seed_path(&cache).parent().unwrap().to_path_buf();
    fs::write(root.join("operator-note"), b"preserve this").unwrap();
    assert!(cache.reserve(4).is_none());
    let state = cache.state.lock().unwrap();
    assert_eq!(
        state.retained_bytes, 4,
        "unreclaimed bytes cannot be released for another copy"
    );
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.entries.len(), 1);
    assert!(state.entries[0].invalidated.load(Ordering::Acquire));
    drop(state);
    assert!(cache.reserve(1).is_none());
    assert_eq!(
        fs::read(root.join("operator-note")).unwrap(),
        b"preserve this"
    );
    assert!(root.join("target/artifact").is_file());
}

#[test]
fn failed_final_marker_publication_releases_reservation_without_deadlock_or_hit() {
    let disk = private_directory("rabs-persistent-publish-").unwrap();
    let cache = persistent(disk.path(), 32, "host-v1");
    let (pending, _, _) = stage_small(&cache, TargetKey([1; 32]));
    let root = pending
        .seed
        .as_ref()
        .unwrap()
        .tree
        .directory
        .path()
        .parent()
        .unwrap()
        .to_path_buf();
    // A preexisting destination cannot be silently overwritten at the final
    // frontier. Publication fails before the pool lock; Drop must still finish.
    fs::write(root.join("seed.json"), b"not a committed seed").unwrap();
    let (sent, received) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        pending.publish();
        sent.send(()).unwrap();
    });
    received
        .recv_timeout(Duration::from_secs(5))
        .expect("failed publish must not deadlock on its reservation");
    writer.join().unwrap();
    {
        let state = cache.state.lock().unwrap();
        assert!(state.entries.is_empty());
        assert_eq!(state.reserved_bytes, 0);
        assert_eq!(state.reservations, 0);
    }
    assert!(
        cache.reserve(4).is_none(),
        "uncertain disk storage is disabled"
    );
    assert!(generations(disk.path()).is_empty());
    drop(cache);
    assert!(
        persistent(disk.path(), 32, "host-v1")
            .state
            .lock()
            .unwrap()
            .entries
            .is_empty()
    );
}

#[test]
fn persistent_eviction_keeps_leased_and_pending_bytes_charged() {
    let disk = private_directory("rabs-persistent-quota-").unwrap();
    let cache = persistent(disk.path(), 8, "host-v1");
    stage_small(&cache, TargetKey([1; 32])).0.publish();
    let lease = Arc::clone(&cache.state.lock().unwrap().entries[0]);
    let old = lease.tree.directory.path().to_path_buf();
    let (pending, _, _) = stage_small(&cache, TargetKey([2; 32]));
    assert!(cache.reserve(1).is_none());
    assert_eq!(generations(disk.path()).len(), 2);
    assert!(old.exists());
    pending.publish();
    drop(lease);
    let (next, _, _) = stage_small(&cache, TargetKey([3; 32]));
    assert!(
        !old.exists(),
        "exclusive eviction reclaims durable payload before quota is reused"
    );
    next.publish();
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 8);
    assert_eq!(generations(disk.path()).len(), 2);
}

#[test]
fn real_cargo_restart_reuses_targets_and_reruns_the_current_test_command() {
    let fixture = CargoFixture::with_dependency();
    let disk = private_directory("rabs-real-persistent-cargo-").unwrap();
    let cache = persistent(disk.path(), 128 * 1024 * 1024, "fixture-host-v1");
    let first = fixture.command(&cache, "test", &[], false);
    first.assert_fresh("hot_dep", false, false);
    assert_eq!(first.test_runs, 1);
    drop(cache);

    fixture.fresh_upload_timestamps();
    let cache = persistent(disk.path(), 128 * 1024 * 1024, "fixture-host-v1");
    let warm = fixture.command(&cache, "test", &[], true);
    warm.assert_all_fresh();
    assert_eq!(
        warm.test_runs, 2,
        "persistent targets must never replay test results"
    );
    drop(cache);

    // Source/data timestamps survive the restart too. Cargo must recompile the
    // changed crate, retain the dependency, and return the new native failure.
    fs::write(fixture.workspace.join("input.txt"), "41\n").unwrap();
    fixture.fresh_upload_timestamps();
    let cache = persistent(disk.path(), 128 * 1024 * 1024, "fixture-host-v1");
    let failed = fixture.command_with_status(&cache, "test", &[], true, 101);
    failed.assert_fresh("hot_dep", false, true);
    failed.assert_fresh("hot_fixture", true, false);
    failed.assert_output_contains("actually_executes_each_time");
    drop(cache);

    fixture.fresh_upload_timestamps();
    let cache = persistent(disk.path(), 128 * 1024 * 1024, "fixture-host-v1");
    let failed_again = fixture.command_with_status(&cache, "test", &[], true, 101);
    failed_again.assert_all_fresh();
    failed_again.assert_output_contains("actually_executes_each_time");
}

#[test]
fn real_cargo_failed_compile_survives_restart_and_reuses_completed_dependencies() {
    let fixture = CargoFixture::with_dependency();
    let disk = private_directory("rabs-real-persistent-failure-").unwrap();
    let source = fixture.workspace.join("src/main.rs");
    let original = fs::read_to_string(&source).unwrap();
    fs::write(
        &source,
        format!("{original}\nfn broken() {{ missing_function(); }}\n"),
    )
    .unwrap();
    let cache = persistent(disk.path(), 128 * 1024 * 1024, "fixture-host-v1");
    fixture
        .command_with_status(&cache, "build", &[], false, 101)
        .assert_fresh("hot_dep", false, false);
    drop(cache);
    fs::write(&source, original).unwrap();
    fixture.fresh_upload_timestamps();
    let cache = persistent(disk.path(), 128 * 1024 * 1024, "fixture-host-v1");
    let fixed = fixture.command(&cache, "build", &[], true);
    fixed.assert_fresh("hot_dep", false, true);
    fixed.assert_fresh("hot_fixture", false, false);
}
