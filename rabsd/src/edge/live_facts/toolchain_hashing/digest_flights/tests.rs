use super::super::{digest_stable_at, hash_files, lstat_regular};
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(8);

#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn hold(&self) -> io::Result<()> {
        self.entered.store(true, Ordering::Release);
        let (released, _) = self
            .changed
            .wait_timeout_while(self.released.lock().unwrap(), DEADLINE, |released| {
                !*released
            })
            .unwrap();
        if *released {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test read was not released",
            ))
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

fn until(mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + DEADLINE;
    while !ready() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(2));
    }
    true
}

fn joined(flights: &Flights, signature: FileSig, readers: usize) -> bool {
    flights
        .active
        .lock()
        .unwrap()
        .get(&signature)
        .is_some_and(|flight| Arc::strong_count(flight) > readers)
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, FileSig, TypedDigest) {
    let directory = crate::test_util::private_tempdir();
    let path = directory.path().join("libcore.rlib");
    std::fs::write(&path, vec![137; 512 * 1024 + 17]).unwrap();
    let (signature, expected) = digest_stable_at(&path, lstat_regular(&path).unwrap()).unwrap();
    (directory, path, signature, expected)
}

fn digest(path: &Path, signature: FileSig) -> io::Result<TypedDigest> {
    digest_stable_at(path, signature).map(|(_, digest)| digest)
}

#[test]
fn real_overlapping_batches_share_one_read_and_populate_each_existing_memo() {
    let (_directory, path, signature, expected) = fixture();
    let gate = Gate::default();
    let reads = AtomicUsize::new(0);
    let busy = AtomicBool::new(false);
    thread::scope(|scope| {
        let mut readers = Vec::new();
        for _ in 0..15 {
            readers.push(scope.spawn(|| {
                let memo = DigestMemo::default();
                let result = hash_files(&[(&path, signature)], &busy, &memo, |path, signature| {
                    assert!(memo.entries.try_lock().is_ok());
                    reads.fetch_add(1, Ordering::SeqCst);
                    gate.hold()?;
                    digest(path, signature)
                });
                (result, memo.get(&signature))
            }));
        }
        let all_joined = until(|| joined(&FLIGHTS, signature, 15));
        gate.release();
        let results: Vec<_> = readers
            .into_iter()
            .map(|reader| reader.join().unwrap())
            .collect();
        assert!(
            all_joined,
            "overlapping batches did not join one file observation"
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        for (result, memoized) in results {
            assert_eq!(result.unwrap(), vec![expected.clone()]);
            assert_eq!(memoized, Some(expected.clone()));
        }
    });
    assert!(!FLIGHTS.active.lock().unwrap().contains_key(&signature));
    assert!(!busy.load(Ordering::Acquire));
}

#[test]
fn changed_generation_can_complete_while_old_generation_is_still_reading() {
    let (_directory, path, original, _) = fixture();
    let flights = Flights::default();
    let old_memo = DigestMemo::default();
    let new_memo = DigestMemo::default();
    let gate = Gate::default();
    thread::scope(|scope| {
        let old = scope.spawn(|| {
            read_with(&flights, &old_memo, &path, original, &|path, signature| {
                let bytes = digest(path, signature)?;
                gate.hold()?;
                Ok(bytes)
            })
        });
        assert!(until(|| gate.entered.load(Ordering::Acquire)));
        std::fs::write(&path, b"different generation").unwrap();
        let replacement = lstat_regular(&path).unwrap();
        assert_ne!(replacement, original);
        let (completed, completion) = std::sync::mpsc::channel();
        let (shared, memo, named) = (&flights, &new_memo, &path);
        let new = scope.spawn(move || {
            completed
                .send(read_with(shared, memo, named, replacement, &digest))
                .unwrap();
        });
        let fast = completion.recv_timeout(Duration::from_secs(2));
        gate.release();
        let obsolete = old.join().unwrap();
        new.join().unwrap();
        assert!(
            fast.expect("new generation waited on obsolete read")
                .is_ok()
        );
        assert!(obsolete.is_err());
        assert!(old_memo.get(&original).is_none());
        assert_eq!(
            new_memo.get(&replacement),
            Some(digest(&path, replacement).unwrap())
        );
    });
    assert!(flights.active.lock().unwrap().is_empty());
}

#[test]
fn follower_validates_its_own_path_after_sharing_a_hardlinked_generation() {
    let (directory, path, _, expected) = fixture();
    let alias_root = directory.path().join("aliases");
    std::fs::create_dir(&alias_root).unwrap();
    let alias = alias_root.join("libcore.rlib");
    std::fs::hard_link(&path, &alias).unwrap();
    let signature = lstat_regular(&path).unwrap();
    assert_eq!(signature, lstat_regular(&alias).unwrap());
    let flights = Flights::default();
    let owner_memo = DigestMemo::default();
    let follower_memo = DigestMemo::default();
    let gate = Gate::default();
    thread::scope(|scope| {
        let owner = scope.spawn(|| {
            read_with(&flights, &owner_memo, &path, signature, &|path, sig| {
                let digest = digest(path, sig)?;
                gate.hold()?;
                Ok(digest)
            })
        });
        assert!(until(|| gate.entered.load(Ordering::Acquire)));
        let follower = scope.spawn(|| {
            read_with(&flights, &follower_memo, &alias, signature, &|_, _| {
                panic!("follower reread the same generation")
            })
        });
        let follower_joined = until(|| joined(&flights, signature, 2));
        // Moving the parent retains both old hardlinks and their file generation.
        // Only the follower's spelling changes to a distinct equal-byte inode.
        std::fs::rename(&alias_root, directory.path().join("retained-aliases")).unwrap();
        std::fs::create_dir(&alias_root).unwrap();
        std::fs::copy(&path, &alias).unwrap();
        assert_eq!(lstat_regular(&path).unwrap(), signature);
        gate.release();
        let accepted = owner.join().unwrap();
        let refused = follower.join().unwrap();
        assert!(follower_joined);
        assert_eq!(accepted.unwrap(), expected);
        assert!(
            refused.is_err(),
            "leader path validation authorized a replaced alias"
        );
        assert!(follower_memo.get(&signature).is_none());
    });
}

#[test]
fn read_errors_wake_followers_preserve_errno_and_allow_a_later_retry() {
    let (_directory, path, signature, expected) = fixture();
    let flights = Flights::default();
    let memo = DigestMemo::default();
    let gate = Gate::default();
    thread::scope(|scope| {
        let owner = scope.spawn(|| {
            read_with(&flights, &memo, &path, signature, &|_, _| {
                gate.hold()?;
                Err(io::Error::from_raw_os_error(5))
            })
        });
        assert!(until(|| gate.entered.load(Ordering::Acquire)));
        let follower = scope.spawn(|| {
            read_with(&flights, &memo, &path, signature, &|_, _| {
                panic!("failed flight started a second reader")
            })
        });
        let follower_joined = until(|| joined(&flights, signature, 2));
        gate.release();
        let outcomes = [owner.join().unwrap(), follower.join().unwrap()];
        assert!(follower_joined);
        for result in outcomes {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(5));
        }
    });
    assert!(flights.active.lock().unwrap().is_empty());
    assert!(memo.get(&signature).is_none());
    assert_eq!(
        read_with(&flights, &memo, &path, signature, &digest).unwrap(),
        expected
    );
}

#[test]
fn unwinding_owner_wakes_all_followers_without_remembering_partial_work() {
    let (_directory, path, signature, expected) = fixture();
    let flights = Flights::default();
    let memo = DigestMemo::default();
    let gate = Gate::default();
    thread::scope(|scope| {
        let owner = scope.spawn(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                read_with(&flights, &memo, &path, signature, &|_, _| {
                    gate.hold()?;
                    panic!("injected descriptor-reader unwind");
                })
            }))
        });
        assert!(until(|| gate.entered.load(Ordering::Acquire)));
        let follower = scope.spawn(|| {
            read_with(&flights, &memo, &path, signature, &|_, _| {
                panic!("abandoned flight executed the follower")
            })
        });
        let follower_joined = until(|| joined(&flights, signature, 2));
        gate.release();
        let interrupted = owner.join().unwrap();
        let refused = follower.join().unwrap();
        assert!(follower_joined);
        assert!(interrupted.is_err());
        assert!(refused.unwrap_err().to_string().contains("abandoned"));
    });
    assert!(flights.active.lock().unwrap().is_empty());
    assert!(memo.get(&signature).is_none());
    assert_eq!(
        read_with(&flights, &memo, &path, signature, &digest).unwrap(),
        expected
    );
}

#[test]
fn reentry_is_a_typed_refusal_instead_of_waiting_on_itself() {
    let (_directory, _path, signature, expected) = fixture();
    let flights = Flights::default();
    let result = flights.run(signature, || {
        flights.run(signature, || {
            panic!("recursive flight must not execute another read")
        })
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(flights.active.lock().unwrap().is_empty());
    assert_eq!(
        flights.run(signature, || Ok(expected.clone())).unwrap(),
        expected
    );
}

#[test]
fn full_table_keeps_existing_owners_and_falls_back_to_a_verified_read() {
    let (_directory, path, signature, expected) = fixture();
    let flights = Flights::default();
    let memo = DigestMemo::default();
    let mut owners = Vec::new();
    // Synthetic signatures exercise capacity only, never input authority.
    for index in 0..MAX_FLIGHTS {
        let mut other = signature;
        other.ino = signature.ino.wrapping_add(index as u64 + 1);
        match flights.acquire(other) {
            Admission::Owner(owner) => owners.push(owner),
            _ => panic!("synthetic reservation was not admitted"),
        }
    }
    assert!(matches!(
        flights.acquire(owners[0].signature),
        Admission::Follower(_)
    ));
    let reads = AtomicUsize::new(0);
    let result = read_with(&flights, &memo, &path, signature, &|path, signature| {
        reads.fetch_add(1, Ordering::SeqCst);
        assert!(flights.active.try_lock().is_ok());
        digest(path, signature)
    })
    .unwrap();
    assert_eq!(result, expected);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(flights.active.lock().unwrap().len(), MAX_FLIGHTS);
    drop(owners);
    assert!(flights.active.lock().unwrap().is_empty());
}

#[test]
fn poisoned_advisory_flight_table_does_not_block_verified_reads() {
    let (_directory, path, signature, expected) = fixture();
    let flights = Flights::default();
    let memo = DigestMemo::default();
    let failure = std::panic::catch_unwind(|| {
        let _held = flights.active.lock().unwrap();
        panic!("injected flight-map poisoning");
    });
    assert!(failure.is_err());
    let reads = AtomicUsize::new(0);
    let actual = read_with(&flights, &memo, &path, signature, &|path, signature| {
        reads.fetch_add(1, Ordering::SeqCst);
        digest(path, signature)
    })
    .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(flights.active.is_poisoned());
}

#[test]
fn conflicting_memo_insert_is_not_overwritten_by_a_completed_read() {
    let (_directory, path, signature, expected) = fixture();
    let flights = Flights::default();
    let memo = DigestMemo::default();
    let mut contradictory = expected.clone();
    contradictory.bytes[0] ^= 1;
    let result = read_with(&flights, &memo, &path, signature, &|path, signature| {
        let actual = digest(path, signature)?;
        // Explicit corruption injection, not a second legitimate authority.
        memo.remember(signature, &contradictory)?;
        Ok(actual)
    });
    assert!(result.unwrap_err().to_string().contains("conflicting"));
    assert_eq!(memo.get(&signature), Some(contradictory));
    assert!(flights.active.lock().unwrap().is_empty());
}

#[test]
fn warm_or_changed_paths_do_not_wait_on_an_unrelated_pending_observation() {
    let (_directory, path, signature, expected) = fixture();
    let flights = Flights::default();
    let memo = DigestMemo::default();
    let Admission::Owner(owner) = flights.acquire(signature) else {
        panic!("reservation was not admitted");
    };
    memo.remember(signature, &expected).unwrap();
    assert_eq!(
        read_with(&flights, &memo, &path, signature, &|_, _| {
            panic!("warm file was reread")
        })
        .unwrap(),
        expected
    );
    std::fs::write(&path, b"changed after memoization").unwrap();
    assert!(
        read_with(&flights, &memo, &path, signature, &|_, _| {
            panic!("stale file reached hashing")
        })
        .is_err()
    );
    drop(owner);
    assert!(flights.active.lock().unwrap().is_empty());
}
