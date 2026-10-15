use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const KIND: DependencySourceKind = DependencySourceKind::RegistryPackage;

fn fixture(size: u64) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("package");
    fs::create_dir(&root).unwrap();
    fs::File::create(root.join("lib.rs"))
        .unwrap()
        .set_len(size)
        .unwrap();
    (directory, root)
}

fn observation(root: &Path) -> Arc<Observation> {
    Arc::new(Observation::read(root, KIND, None).unwrap())
}

fn reserve(facts: &Arc<LiveFacts>, observation: &Arc<Observation>) -> Reservation {
    let mut memos = facts.packages.lock().unwrap();
    Reservation::insert(facts, &mut memos, Arc::clone(observation))
}

fn ready(facts: &Arc<LiveFacts>, root: &Path) -> Arc<PackageFacts> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match facts.package(root, KIND, None) {
            Ok(captured) => return captured,
            Err(FactsMiss::Pending) => {
                assert!(Instant::now() < deadline, "package capture stayed pending");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("package capture refused: {error}"),
        }
    }
}

fn join_warm(facts: &Arc<LiveFacts>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while *facts.warming.lock().unwrap() != 0 {
        assert!(Instant::now() < deadline, "package warmer did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn concurrent_foreground_requests_share_one_real_sealed_capture() {
    let (_directory, root) = fixture(17);
    let facts = LiveFacts::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let (started, start) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let producer = {
        let facts = Arc::clone(&facts);
        let root = root.clone();
        let calls = Arc::clone(&calls);
        std::thread::spawn(move || {
            observe_with(&facts, &root, KIND, None, move |observation| {
                calls.fetch_add(1, Ordering::SeqCst);
                started.send(()).unwrap();
                blocked.recv_timeout(Duration::from_secs(5)).unwrap();
                observation.capture()
            })
        })
    };
    start.recv_timeout(Duration::from_secs(5)).unwrap();
    let followers: Vec<_> = (0..16)
        .map(|_| {
            let facts = Arc::clone(&facts);
            let root = root.clone();
            std::thread::spawn(move || {
                observe_with(&facts, &root, KIND, None, |_| {
                    panic!("duplicate request started another sealed capture")
                })
            })
        })
        .collect();
    for follower in followers {
        assert!(matches!(follower.join().unwrap(), Err(FactsMiss::Pending)));
    }
    // An unrelated package can complete while the producer holds its capture.
    let (_other_directory, other) = fixture(9);
    facts.package(&other, KIND, None).unwrap();
    release.send(()).unwrap();
    let captured = producer.join().unwrap().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*facts.warming.lock().unwrap(), 0);
    assert!(Arc::ptr_eq(&captured, &facts.package(&root, KIND, None).unwrap()));
    assert_eq!(captured.snapshot.file_bytes(super::super::PACKAGE_ROOT, "lib.rs").unwrap(), &[0; 17]);
    captured.verify_unchanged(&root).unwrap();
}

#[test]
fn concurrent_large_requests_use_one_existing_warm_slot() {
    let (_directory, root) = fixture(SYNCHRONOUS_PACKAGE_BYTES + 1);
    let facts = LiveFacts::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let (started, start) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let counter = Arc::clone(&calls);
    assert!(matches!(
        observe_with(&facts, &root, KIND, None, move |observation| {
            counter.fetch_add(1, Ordering::SeqCst);
            started.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(5)).unwrap();
            observation.capture()
        }),
        Err(FactsMiss::Pending)
    ));
    start.recv_timeout(Duration::from_secs(5)).unwrap();
    for _ in 0..32 {
        assert!(matches!(facts.package(&root, KIND, None), Err(FactsMiss::Pending)));
    }
    assert_eq!(*facts.warming.lock().unwrap(), 1);
    release.send(()).unwrap();
    let captured = ready(&facts, &root);
    join_warm(&facts);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(captured.bytes, SYNCHRONOUS_PACKAGE_BYTES + 1);
    captured.verify_unchanged(&root).unwrap();
}

#[test]
fn changed_generation_does_not_wait_for_or_inherit_an_old_capture() {
    let (_directory, root) = fixture(17);
    let facts = LiveFacts::new();
    let original = observation(&root);
    let owner = reserve(&facts, &original);
    let old_bytes = original.capture().unwrap();
    fs::write(root.join("lib.rs"), b"changed source generation").unwrap();
    let newer = facts.package(&root, KIND, None).unwrap();
    assert!(matches!(owner.finish(Ok(old_bytes), true), Err(FactsMiss::Refused(_))));
    assert!(Arc::ptr_eq(&newer, &facts.package(&root, KIND, None).unwrap()));
    newer.verify_unchanged(&root).unwrap();
}

#[test]
fn a_capture_that_started_after_mutation_cannot_fill_an_earlier_observation() {
    let (_directory, root) = fixture(17);
    let facts = LiveFacts::new();
    let original = observation(&root);
    let owner = reserve(&facts, &original);
    fs::write(root.join("lib.rs"), b"new source bytes").unwrap();
    let new_bytes = original.capture().unwrap();
    assert!(matches!(
        owner.finish(Ok(new_bytes), false),
        Err(FactsMiss::Refused(reason)) if reason.contains("admitted observation")
    ));
    assert!(facts.packages.lock().unwrap().is_empty());
    facts.package(&root, KIND, None).unwrap().verify_unchanged(&root).unwrap();
}

#[test]
fn failure_backoff_is_scoped_to_exact_source_and_generated_inputs() {
    let (_directory, plan) = super::super::tests::generated_fixture();
    let root = Path::new(&plan.source_root);
    let generated = Path::new(plan.generated_root.as_ref().unwrap());
    let facts = LiveFacts::new();
    let original = Arc::new(Observation::read(root, plan.source_kind, Some(generated)).unwrap());
    reserve(&facts, &original).finish(Err("old capture failed".into()), true).unwrap_err();
    assert!(matches!(
        facts.package(root, plan.source_kind, Some(generated)),
        Err(FactsMiss::Refused(reason)) if reason == "old capture failed"
    ));
    fs::write(generated.join("value.rs"), b"pub const VALUE:u32=42;").unwrap();
    let changed = facts.package(root, plan.source_kind, Some(generated)).unwrap();
    changed.verify_unchanged(root).unwrap();
    assert_ne!(changed.generated, original.generated);
    // Omitting generated inputs is a different observation, not the failed one.
    let plain = facts.package(root, plan.source_kind, None).unwrap();
    assert!(plain.generated.is_none());
}

#[test]
fn failed_warm_admission_releases_only_its_exact_token() {
    let (_directory, root) = fixture(SYNCHRONOUS_PACKAGE_BYTES + 1);
    let facts = LiveFacts::new();
    let original = observation(&root);
    let original_owner = reserve(&facts, &original);
    fs::write(root.join("extra.rs"), b"another source").unwrap();
    let changed = observation(&root);
    *facts.warming.lock().unwrap() = super::super::MAX_WARMING;
    assert!(matches!(facts.package(&root, KIND, None), Err(FactsMiss::Pending)));
    let memos = facts.packages.lock().unwrap();
    assert!(original_owner.owns(&memos));
    assert!(!memos.contains_key(&changed));
    drop(memos);
    drop(original_owner);
    *facts.warming.lock().unwrap() = 0;
    ready(&facts, &root).verify_unchanged(&root).unwrap();
    join_warm(&facts);
}

#[test]
fn stale_same_observation_token_cannot_overwrite_or_remove_its_successor() {
    let (_directory, root) = fixture(17);
    let facts = LiveFacts::new();
    let observed = observation(&root);
    let stale = reserve(&facts, &observed);
    // Inject eviction/retry of exactly the same generation, not changed bytes.
    facts.packages.lock().unwrap().remove(&observed);
    let successor = reserve(&facts, &observed);
    assert!(matches!(stale.finish(observed.capture(), true), Err(FactsMiss::Pending)));
    assert!(successor.owns(&facts.packages.lock().unwrap()));
    let captured = successor.finish(observed.capture(), true).unwrap();
    assert!(Arc::ptr_eq(&captured, &facts.package(&root, KIND, None).unwrap()));
}

#[test]
fn foreground_unwind_and_unstarted_closure_drop_release_reservations() {
    let (_directory, root) = fixture(17);
    let facts = LiveFacts::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = observe_with(&facts, &root, KIND, None, |_| panic!("capture fault"));
    }));
    assert!(result.is_err());
    assert!(facts.packages.lock().unwrap().is_empty());
    let observed = observation(&root);
    let reservation = reserve(&facts, &observed);
    let unstarted = move || reservation.finish(observed.capture(), true);
    drop(unstarted);
    assert!(facts.packages.lock().unwrap().is_empty());
    facts.package(&root, KIND, None).unwrap();
}

#[test]
fn background_unwind_releases_both_reservation_and_warm_capacity() {
    let (_directory, root) = fixture(SYNCHRONOUS_PACKAGE_BYTES + 1);
    let facts = LiveFacts::new();
    assert!(matches!(
        observe_with(&facts, &root, KIND, None, |_| panic!("warm capture fault")),
        Err(FactsMiss::Pending)
    ));
    join_warm(&facts);
    assert!(facts.packages.lock().unwrap().is_empty());
    ready(&facts, &root).verify_unchanged(&root).unwrap();
    join_warm(&facts);
}

#[test]
fn pending_observations_are_bounded_and_never_evicted_to_admit_more_work() {
    let (directory, root) = fixture(17);
    let facts = LiveFacts::new();
    let mut owners = Vec::new();
    for index in 0..MAX_PACKAGE_MEMOS {
        let other = directory.path().join(format!("package-{index}"));
        fs::create_dir(&other).unwrap();
        fs::write(other.join("lib.rs"), b"source").unwrap();
        owners.push(reserve(&facts, &observation(&other)));
    }
    assert!(matches!(
        observe_with(&facts, &root, KIND, None, |_| panic!("saturated capture ran")),
        Err(FactsMiss::Pending)
    ));
    assert_eq!(facts.packages.lock().unwrap().len(), MAX_PACKAGE_MEMOS);
    drop(owners.pop());
    facts.package(&root, KIND, None).unwrap();
    assert_eq!(facts.packages.lock().unwrap().len(), MAX_PACKAGE_MEMOS);
    assert!(owners.iter().all(|owner| owner.owns(&facts.packages.lock().unwrap())));
}

#[test]
fn prospective_byte_limit_evicts_memo_references_not_subscribers_or_captures() {
    let (_directory, root) = fixture(17);
    let (_other_directory, other) = fixture(9);
    let facts = LiveFacts::new();
    let subscriber = facts.package(&root, KIND, None).unwrap();
    let pending = reserve(&facts, &observation(&other));
    let mut memos = facts.packages.lock().unwrap();
    make_byte_room(&mut memos, 8, 25);
    assert_eq!(memos.len(), 2, "exact bound retains the memo");
    make_byte_room(&mut memos, 9, 25);
    assert_eq!(memos.len(), 1, "prospective insertion exceeds the bound");
    assert!(pending.owns(&memos));
    drop(memos);
    subscriber.verify_unchanged(&root).unwrap();
    assert_eq!(subscriber.snapshot.file_bytes(super::super::PACKAGE_ROOT, "lib.rs").unwrap(), &[0; 17]);
}

#[test]
fn replaced_root_and_new_members_cannot_reuse_a_ready_snapshot() {
    let (directory, root) = fixture(17);
    let facts = LiveFacts::new();
    let original = facts.package(&root, KIND, None).unwrap();
    let moved = directory.path().join("retained-root");
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    // Move the exact original file inode into the new directory.
    fs::rename(moved.join("lib.rs"), root.join("lib.rs")).unwrap();
    let replacement = facts.package(&root, KIND, None).unwrap();
    assert!(!Arc::ptr_eq(&original, &replacement));
    fs::write(root.join("new.rs"), b"new member").unwrap();
    let added = facts.package(&root, KIND, None).unwrap();
    assert!(!Arc::ptr_eq(&replacement, &added));
    assert!(replacement.verify_unchanged(&root).is_err());
    added.verify_unchanged(&root).unwrap();
}

// Explicit recency fixtures avoid sleeping or assuming filesystem/clock resolution.
fn stamp_ready(facts: &Arc<LiveFacts>, root: &Path, stamp: Instant) {
    let key = observation(root);
    let mut memos = facts.packages.lock().unwrap();
    let Some(PackageSlot::Ready { last_used, .. }) = memos.get_mut(&key) else {
        panic!("fixture snapshot is not ready");
    };
    *last_used = stamp;
}

fn retained_bytes(memos: &PackageMemos) -> u64 {
    memos.values().map(|slot| match slot {
        PackageSlot::Ready { captured, .. } => captured.bytes,
        _ => 0,
    }).sum()
}

#[test]
fn byte_pressure_preserves_hot_snapshots_and_only_recaptures_the_evicted_package() {
    let fixtures = [fixture(17), fixture(9), fixture(4), fixture(8)];
    let facts = LiveFacts::new();
    let captured: Vec<_> = fixtures[..3].iter()
        .map(|(_, root)| facts.package(root, KIND, None).unwrap())
        .collect();
    let base = Instant::now();
    for (index, (_, root)) in fixtures[..3].iter().enumerate() {
        stamp_ready(&facts, root, base + Duration::from_millis(index as u64));
    }
    let keys: Vec<_> = fixtures.iter().map(|(_, root)| observation(root)).collect();
    let pending = reserve(&facts, &keys[3]);
    {
        let mut memos = facts.packages.lock().unwrap();
        let reused = memos.get_mut(&keys[0]).unwrap()
            .reuse(base + Duration::from_secs(1)).unwrap().unwrap();
        assert!(Arc::ptr_eq(&reused, &captured[0]));
        assert!(make_byte_room(&mut memos, 6, 30));
        assert_eq!(retained_bytes(&memos), 21);
        assert!(memos.contains_key(&keys[0]));
        assert!(!memos.contains_key(&keys[1]));
        assert!(memos.contains_key(&keys[2]));
        assert!(pending.owns(&memos));
    }
    for index in [0, 2] {
        let reused = observe_with(&facts, &fixtures[index].1, KIND, None, |_| {
            panic!("pressure discarded a retained hot snapshot")
        }).unwrap();
        assert!(Arc::ptr_eq(&reused, &captured[index]));
    }
    // Eviction dropped only the memo reference. An existing subscriber keeps
    // its exact immutable bytes, but new demand must perform a fresh capture.
    captured[1].verify_unchanged(&fixtures[1].1).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let replacement = observe_with(&facts, &fixtures[1].1, KIND, None, move |observed| {
        count.fetch_add(1, Ordering::SeqCst);
        observed.capture()
    }).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!Arc::ptr_eq(&replacement, &captured[1]));
    assert_eq!(replacement.files, captured[1].files);
    assert_eq!(*facts.warming.lock().unwrap(), 0);
}

#[test]
fn unequal_byte_victims_stop_at_the_budget_and_keep_zero_byte_snapshots() {
    let fixtures = [fixture(0), fixture(4), fixture(17), fixture(9)];
    let facts = LiveFacts::new();
    let base = Instant::now();
    for (index, (_, root)) in fixtures.iter().enumerate() {
        facts.package(root, KIND, None).unwrap();
        stamp_ready(&facts, root, base + Duration::from_millis(index as u64));
    }
    let keys: Vec<_> = fixtures.iter().map(|(_, root)| observation(root)).collect();
    let mut memos = facts.packages.lock().unwrap();
    assert!(make_byte_room(&mut memos, 20, 30));
    assert_eq!(retained_bytes(&memos), 9);
    assert_eq!(memos.len(), 2);
    assert!(memos.contains_key(&keys[0]), "zero bytes cannot relieve byte pressure");
    assert!(memos.contains_key(&keys[3]), "do not flush the last ready snapshot");
    assert!(make_byte_room(&mut memos, 21, 30), "exact bound must retain both");
    assert_eq!(memos.len(), 2);
    assert!(!make_byte_room(&mut memos, 31, 30));
    assert!(!make_byte_room(&mut memos, u64::MAX, 30));
    assert_eq!(memos.len(), 2, "unretainable incoming data must not flush the cache");
}

fn pressure_fixture() -> (tempfile::TempDir, Arc<LiveFacts>, Vec<PathBuf>) {
    let directory = tempfile::tempdir().unwrap();
    let facts = LiveFacts::new();
    let base = Instant::now();
    let mut roots = Vec::new();
    for index in 0..=MAX_PACKAGE_MEMOS {
        let root = directory.path().join(format!("package-{index}"));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("lib.rs"), b"x").unwrap();
        if index != MAX_PACKAGE_MEMOS {
            facts.package(&root, KIND, None).unwrap();
            stamp_ready(&facts, &root, base + Duration::from_millis(index as u64));
        }
        roots.push(root);
    }
    (directory, facts, roots)
}

#[test]
fn actual_entry_pressure_keeps_127_ready_snapshots_instead_of_flushing_them() {
    let (_directory, facts, roots) = pressure_fixture();
    let keys: Vec<_> = roots.iter().map(|root| observation(root)).collect();
    let hot = {
        let mut memos = facts.packages.lock().unwrap();
        memos.get_mut(&keys[0]).unwrap()
            .reuse(Instant::now() + Duration::from_secs(1)).unwrap().unwrap()
    };
    facts.package(&roots[MAX_PACKAGE_MEMOS], KIND, None).unwrap();
    {
        let memos = facts.packages.lock().unwrap();
        assert_eq!(memos.len(), MAX_PACKAGE_MEMOS);
        assert!(!memos.contains_key(&keys[1]), "oldest unused snapshot is the sole victim");
        assert!(memos.contains_key(&keys[0]));
        assert_eq!(retained_bytes(&memos), MAX_PACKAGE_MEMOS as u64);
    }
    for index in (0..MAX_PACKAGE_MEMOS).filter(|index| *index != 1) {
        let reused = observe_with(&facts, &roots[index], KIND, None, |_| {
            panic!("entry pressure recaptured a surviving snapshot")
        }).unwrap();
        reused.verify_unchanged(&roots[index]).unwrap();
        if index == 0 { assert!(Arc::ptr_eq(&reused, &hot)); }
    }
}

#[test]
fn retrying_an_expired_failure_at_capacity_does_not_evict_another_package() {
    let (_directory, facts, roots) = pressure_fixture();
    let keys: Vec<_> = roots.iter().map(|root| observation(root)).collect();
    let base = Instant::now();
    {
        let mut memos = facts.packages.lock().unwrap();
        memos.insert(Arc::clone(&keys[0]), PackageSlot::Failed {
            reason: "expired fixture failure".into(), at: base,
        });
        assert!(memos.get_mut(&keys[0]).unwrap().reuse(base + PROBE_RETRY).is_none());
        assert!(make_entry_room(&mut memos, &keys[0], base + PROBE_RETRY));
        assert_eq!(memos.len(), MAX_PACKAGE_MEMOS);
        assert!(keys[..MAX_PACKAGE_MEMOS].iter().all(|key| memos.contains_key(key)));
    }
    // Drive the same reservation/finish path used after that expired lookup.
    let owner = reserve(&facts, &keys[0]);
    let captured = owner.finish(keys[0].capture(), false).unwrap();
    assert!(Arc::ptr_eq(&captured, &facts.package(&roots[0], KIND, None).unwrap()));
    let memos = facts.packages.lock().unwrap();
    assert_eq!(memos.len(), MAX_PACKAGE_MEMOS);
    assert!(keys[..MAX_PACKAGE_MEMOS].iter().all(|key| memos.contains_key(key)));
}
