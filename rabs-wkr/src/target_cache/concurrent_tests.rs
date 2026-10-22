//! Exercise the production cache, snapshot copier and quota owner. Artifact
//! bytes and target keys are fixtures; no Cargo, TLS or sandbox run is implied.

use super::*;
use rabs_sandbox::source_transfer::SourceFile;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::mpsc;
use std::time::Duration;

struct Fixture {
    source: tempfile::TempDir,
    plan: ArtifactPlan,
    target: PreparedArtifacts,
    captured: CapturedArtifacts,
}

impl Fixture {
    fn new(payload: &[u8]) -> Self {
        let source = private_directory("rabs-concurrent-source-").unwrap();
        fs::write(source.path().join("lib.rs"), b"pub fn answer() {}\n").unwrap();
        fs::set_permissions(source.path().join("lib.rs"), fs::Permissions::from_mode(0o444)).unwrap();
        let plan = ArtifactPlan::new_tree("cargo".into(), vec!["artifact".into()]).unwrap();
        let target = PreparedArtifacts::new(plan.clone()).unwrap();
        fs::write(target.backing().join("artifact"), payload).unwrap();
        let captured = target.capture_with_dependency_inputs(None, || false).unwrap();
        Self { source, plan, target, captured }
    }

    fn inputs(&self) -> WorkspaceInputs {
        let bytes = fs::read(self.source.path().join("lib.rs")).unwrap();
        let manifest = SourceManifest::new(vec![SourceFile {
            path: "lib.rs".into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
            executable: false,
        }]).unwrap();
        WorkspaceInputs {
            root: self.source.path().to_path_buf(),
            full_source_digest: manifest.digest(),
            manifest,
            projection: None,
            runtime_owner: None,
        }.private_runtime_clone(&|| false).unwrap()
    }

    fn pending(&self, cache: &Arc<TargetCache>, key: TargetKey) -> PendingTargetSeed {
        let (attempt, _) = cache.acquire(
            key, self.inputs(), || PreparedArtifacts::new(self.plan.clone()), 1, &|| false,
        ).unwrap();
        attempt.stage(&self.target, &self.captured, &|| false).unwrap().unwrap()
    }

    fn restore(&self, cache: &Arc<TargetCache>, key: TargetKey) -> PreparedArtifacts {
        cache.acquire(
            key, self.inputs(), || PreparedArtifacts::new(self.plan.clone()), 2, &|| false,
        ).unwrap().1.expect("a leased warm seed must remain reusable")
    }
}

fn lease(cache: &TargetCache, key: TargetKey) -> Arc<Seed> {
    Arc::clone(cache.state.lock().unwrap().entries.iter().rev()
        .find(|seed| seed.key == key).unwrap())
}

fn accounted(cache: &TargetCache) {
    let state = cache.state.lock().unwrap();
    assert_eq!(state.retained_bytes, state.entries.iter().map(|seed| seed.tree.bytes).sum::<u64>());
    assert!(state.retained_bytes + state.reserved_bytes <= cache.max_bytes);
    assert!(state.entries.len() + state.reservations <= MAX_TARGET_CACHE_ENTRIES);
}

#[test]
fn simultaneous_same_and_different_key_restores_keep_private_writers() {
    for same_key in [false, true] {
        let fixture = Fixture::new(b"seed");
        let cache = Arc::new(TargetCache::new(32).unwrap());
        let first_key = TargetKey([1; 32]);
        let second_key = if same_key { first_key } else { TargetKey([2; 32]) };
        fixture.pending(&cache, first_key).publish();
        if !same_key {
            fixture.pending(&cache, second_key).publish();
        }
        let (entered, observed) = mpsc::channel();
        let (release, resumed) = mpsc::channel();
        let input = fixture.inputs();
        let plan = fixture.plan.clone();
        let first_cache = Arc::clone(&cache);
        std::thread::scope(|scope| {
            let first = scope.spawn(move || {
                first_cache.acquire(first_key, input, || {
                    entered.send(()).unwrap();
                    resumed.recv_timeout(Duration::from_secs(5)).unwrap();
                    PreparedArtifacts::new(plan)
                }, 3, &|| false).unwrap().1.unwrap()
            });
            observed.recv_timeout(Duration::from_secs(5)).unwrap();
            // The first reader still owns its seed, but not the pool mutex.
            // The former implementation returned a cold miss here.
            let second = fixture.restore(&cache, second_key);
            accounted(&cache);
            release.send(()).unwrap();
            let first = first.join().unwrap();
            let a = first.backing().join("artifact");
            let b = second.backing().join("artifact");
            assert_ne!(fs::metadata(&a).unwrap().ino(), fs::metadata(&b).unwrap().ino());
            assert_eq!(fs::read(&a).unwrap(), b"seed");
            assert_eq!(fs::read(&b).unwrap(), b"seed");
            fs::write(&a, b"mine").unwrap();
            assert_eq!(fs::read(&b).unwrap(), b"seed");
        });
        accounted(&cache);
    }
}

#[test]
fn reservations_protect_active_seed_bytes_without_destructive_refusal() {
    let fixture = Fixture::new(b"seed");
    let cache = Arc::new(TargetCache::new(12).unwrap());
    let a = TargetKey([1; 32]);
    let b = TargetKey([2; 32]);
    fixture.pending(&cache, a).publish();
    fixture.pending(&cache, b).publish();
    let active = lease(&cache, a);
    let path = active.tree.directory.path().to_path_buf();
    let pending = cache.reserve(4).unwrap();
    for _ in 0..3 {
        assert!(cache.reserve(5).is_none());
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.iter().map(|seed| seed.key).collect::<Vec<_>>(), vec![a, b]);
        assert_eq!(state.retained_bytes, 8);
        assert_eq!(state.reserved_bytes, 4);
    }
    // The first entry is oldest but leased. Only the idle second entry can go.
    let next = cache.reserve(4).unwrap();
    assert_eq!(fs::read(path.join("artifact")).unwrap(), b"seed");
    assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
    assert_eq!(cache.state.lock().unwrap().entries[0].key, a);
    accounted(&cache);
    drop((next, pending));
    cache.finish_seed_use(active, false);
    assert_eq!(fs::read(fixture.restore(&cache, a).backing().join("artifact")).unwrap(), b"seed");
    accounted(&cache);
}

#[test]
fn active_and_weak_seed_owners_count_toward_zero_byte_entry_limits() {
    let fixture = Fixture::new(b"seed");
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([1; 32]);
    fixture.pending(&cache, key).publish();
    let active = lease(&cache, key);
    let weak = Arc::downgrade(&active);
    let path = active.tree.directory.path().to_path_buf();
    let mut reserved: Vec<_> = (0..MAX_TARGET_CACHE_ENTRIES - 1)
        .map(|_| cache.reserve(0).unwrap()).collect();
    assert!(cache.reserve(0).is_none());
    cache.finish_seed_use(active, false);
    assert!(cache.reserve(0).is_none(), "a Weak upgrade must not evade accounting");
    assert!(weak.upgrade().is_some());
    assert!(path.exists());
    drop(weak);
    reserved.push(cache.reserve(0).unwrap());
    assert!(!path.exists());
    assert!(cache.reserve(0).is_none());
    accounted(&cache);
    drop(reserved);
    assert_eq!(cache.state.lock().unwrap().reservations, 0);
}

#[test]
fn replacement_keeps_old_backing_until_its_last_reader_and_selects_new_generation() {
    let old_fixture = Fixture::new(b"old!");
    let new_fixture = Fixture::new(b"new!");
    let cache = Arc::new(TargetCache::new(8).unwrap());
    let key = TargetKey([1; 32]);
    old_fixture.pending(&cache, key).publish();
    let first = lease(&cache, key);
    let last = Arc::clone(&first);
    let old_path = first.tree.directory.path().to_path_buf();
    new_fixture.pending(&cache, key).publish();
    assert_eq!(cache.state.lock().unwrap().entries.len(), 2);
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 8);
    assert!(cache.reserve(5).is_none());
    assert_eq!(fs::read(new_fixture.restore(&cache, key).backing().join("artifact")).unwrap(), b"new!");
    cache.finish_seed_use(first, true);
    assert!(old_path.exists());
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 8);
    // A late failure of the old generation must not discard its replacement.
    last.invalidated.store(true, Ordering::Release);
    cache.finish_seed_use(last, false);
    assert!(!old_path.exists());
    assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 4);
    assert_eq!(fs::read(new_fixture.restore(&cache, key).backing().join("artifact")).unwrap(), b"new!");
    accounted(&cache);
}

#[test]
fn invalidated_generation_is_not_reused_or_unaccounted_while_another_reader_owns_it() {
    let fixture = Fixture::new(b"seed");
    let cache = Arc::new(TargetCache::new(4).unwrap());
    let key = TargetKey([1; 32]);
    fixture.pending(&cache, key).publish();
    let owner = lease(&cache, key);
    let path = owner.tree.directory.path().to_path_buf();
    let (_, restored) = cache.acquire(key, fixture.inputs(), || {
        owner.invalidated.store(true, Ordering::Release);
        PreparedArtifacts::new(fixture.plan.clone())
    }, 2, &|| false).unwrap();
    assert!(restored.is_none());
    let (_, cold) = cache.acquire(key, fixture.inputs(), || {
        panic!("invalidated generation cannot authorize restoration")
    }, 3, &|| false).unwrap();
    assert!(cold.is_none());
    assert!(cache.reserve(1).is_none());
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 4);
    assert!(path.exists());
    cache.finish_seed_use(owner, false);
    assert!(!path.exists());
    assert!(cache.state.lock().unwrap().entries.is_empty());
    accounted(&cache);
}

#[test]
fn publication_and_reservation_progress_inside_an_unrelated_restore() {
    let fixture = Fixture::new(b"seed");
    let cache = Arc::new(TargetCache::new(16).unwrap());
    let a = TargetKey([1; 32]);
    let b = TargetKey([2; 32]);
    fixture.pending(&cache, a).publish();
    let ready = fixture.pending(&cache, b);
    let (_, restored) = cache.acquire(a, fixture.inputs(), || {
        // Reentrant operations use the real pool, not a second lock model.
        let reservation = cache.reserve(4).expect("restore must not hold the pool lock");
        ready.publish();
        accounted(&cache);
        drop(reservation);
        PreparedArtifacts::new(fixture.plan.clone())
    }, 2, &|| false).unwrap();
    assert_eq!(fs::read(restored.unwrap().backing().join("artifact")).unwrap(), b"seed");
    assert_eq!(fs::read(fixture.restore(&cache, b).backing().join("artifact")).unwrap(), b"seed");
    accounted(&cache);
}

#[test]
fn rejected_destination_keeps_its_lru_position_without_holding_other_restores() {
    let fixture = Fixture::new(b"seed");
    let cache = Arc::new(TargetCache::new(16).unwrap());
    let a = TargetKey([1; 32]);
    let b = TargetKey([2; 32]);
    fixture.pending(&cache, a).publish();
    fixture.pending(&cache, b).publish();
    let (_, restored) = cache.acquire(a, fixture.inputs(), || {
        let other = fixture.restore(&cache, b);
        assert_eq!(fs::read(other.backing().join("artifact")).unwrap(), b"seed");
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected allocation refusal"))
    }, 3, &|| false).unwrap();
    assert!(restored.is_none());
    assert_eq!(cache.state.lock().unwrap().entries.iter().map(|seed| seed.key).collect::<Vec<_>>(), vec![a, b]);
    assert_eq!(fs::read(fixture.restore(&cache, a).backing().join("artifact")).unwrap(), b"seed");
    accounted(&cache);
}

#[cfg(panic = "unwind")]
#[test]
fn allocation_unwind_releases_the_read_lease_without_poisoning_the_pool() {
    let fixture = Fixture::new(b"seed");
    let cache = Arc::new(TargetCache::new(8).unwrap());
    let key = TargetKey([1; 32]);
    fixture.pending(&cache, key).publish();
    let input = fixture.inputs();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = cache.acquire(key, input, || panic!("injected allocation unwind"), 2, &|| false);
    }));
    assert!(panicked.is_err());
    assert!(!cache.state.is_poisoned());
    assert_eq!(fs::read(fixture.restore(&cache, key).backing().join("artifact")).unwrap(), b"seed");
    let capacity = cache.reserve(8).expect("unwinding must release seed ownership");
    assert!(cache.state.lock().unwrap().entries.is_empty());
    accounted(&cache);
    drop(capacity);
}
