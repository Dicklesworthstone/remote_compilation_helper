//! Share an in-flight verified read of one exact toolchain file generation.
//!
//! This table is not another digest cache: the owner removes its entry when
//! work ends. All followers validate THEIR path, and populate THEIR existing
//! memo, after receiving the result. No pathname, mtime alone, or pending read
//! grants authority. The existing warm/scoped-helper threads own all work and
//! waits; no request queue, executor, detached reader, or new thread is created.
//! A stalled owner cannot hold another warm thread indefinitely: all followers
//! share one monotonic wait deadline established when that read is admitted.
//! Expiry refuses the follower, never cancels the owner or starts a second read.

use super::{DigestMemo, FileSig, verify_files};
use rabs_protocol::result_identity::TypedDigest;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

const MAX_FLIGHTS: usize = 64;
const MAX_FOLLOWER_WAIT: Duration = Duration::from_secs(30);
static FLIGHTS: LazyLock<Flights> = LazyLock::new(Flights::default);

#[derive(Clone)]
struct Failure {
    kind: io::ErrorKind,
    raw: Option<i32>,
    message: String,
}

impl Failure {
    fn capture(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    fn error(&self) -> io::Error {
        self.raw.map_or_else(
            || io::Error::new(self.kind, self.message.clone()),
            io::Error::from_raw_os_error,
        )
    }
}

struct Flight {
    owner: ThreadId,
    wait_deadline: Instant,
    result: Mutex<Option<Result<TypedDigest, Failure>>>,
    changed: Condvar,
}

impl Flight {
    fn wait(&self) -> io::Result<TypedDigest> {
        let mut result = self.result.lock().map_err(|_| poisoned())?;
        loop {
            if let Some(result) = &*result {
                return result.clone().map_err(|failure| failure.error());
            }
            if self.owner == thread::current().id() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "recursive toolchain digest observation",
                ));
            }
            // The deadline belongs to the original read, not this follower or
            // this notification. Spurious wakes and later callers cannot renew
            // it. This bounds coordination only; kernel I/O in the owner is not
            // cancellable and remains owned/charged until that reader finishes.
            let remaining = self
                .wait_deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "shared toolchain digest wait deadline exceeded",
                    )
                })?;
            let (next, _) = self
                .changed
                .wait_timeout(result, remaining)
                .map_err(|_| poisoned())?;
            result = next;
        }
    }
}

fn poisoned() -> io::Error {
    io::Error::other("toolchain digest flight result poisoned")
}

struct Flights {
    active: Mutex<HashMap<FileSig, Arc<Flight>>>,
    follower_wait: Duration,
}

impl Default for Flights {
    fn default() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            follower_wait: MAX_FOLLOWER_WAIT,
        }
    }
}

enum Admission<'a> {
    Owner(Owner<'a>),
    Follower(Arc<Flight>),
    Direct,
}

impl Flights {
    fn acquire(&self, signature: FileSig) -> Admission<'_> {
        let Ok(mut active) = self.active.lock() else {
            // Advisory state failure cannot turn a verified read into a hit.
            return Admission::Direct;
        };
        if let Some(flight) = active.get(&signature) {
            return Admission::Follower(Arc::clone(flight));
        }
        if active.len() >= MAX_FLIGHTS {
            // Keep all admitted owners. Existing warm-thread capacity bounds
            // the direct read; do not queue behind an unrelated file identity.
            return Admission::Direct;
        }
        let flight = Arc::new(Flight {
            owner: thread::current().id(),
            // Overflow must refuse waiting, not create an unbounded wait or
            // authorize duplicate work. The production duration is fixed above.
            wait_deadline: Instant::now()
                .checked_add(self.follower_wait)
                .unwrap_or_else(Instant::now),
            result: Mutex::new(None),
            changed: Condvar::new(),
        });
        active.insert(signature, Arc::clone(&flight));
        Admission::Owner(Owner {
            table: self,
            signature,
            flight,
        })
    }

    fn run(
        &self,
        signature: FileSig,
        work: impl FnOnce() -> io::Result<TypedDigest>,
    ) -> io::Result<TypedDigest> {
        match self.acquire(signature) {
            Admission::Direct => work(),
            Admission::Follower(flight) => flight.wait(),
            Admission::Owner(owner) => {
                // Neither table nor result mutex covers hashing, persistence,
                // user-supplied test callbacks, or result destruction.
                let result = work();
                *owner.flight.result.lock().map_err(|_| poisoned())? =
                    Some(result.as_ref().cloned().map_err(Failure::capture));
                // Drop publishes abandonment on unwind; on success it retires
                // this exact entry and wakes all already admitted followers.
                drop(owner);
                result
            }
        }
    }
}

struct Owner<'a> {
    table: &'a Flights,
    signature: FileSig,
    flight: Arc<Flight>,
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        {
            let mut result = self
                .flight
                .result
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if result.is_none() {
                *result = Some(Err(Failure::capture(&io::Error::other(
                    "toolchain digest owner abandoned its read",
                ))));
            }
        }
        if let Ok(mut active) = self.table.active.lock()
            && active
                .get(&self.signature)
                .is_some_and(|current| Arc::ptr_eq(current, &self.flight))
        {
            active.remove(&self.signature);
        }
        self.flight.changed.notify_all();
    }
}

pub(super) fn read(
    memo: &DigestMemo,
    path: &Path,
    signature: FileSig,
    hash: &(impl Fn(&Path, FileSig) -> io::Result<TypedDigest> + Sync),
) -> io::Result<TypedDigest> {
    read_with(&FLIGHTS, memo, path, signature, hash)
}

fn read_with(
    flights: &Flights,
    memo: &DigestMemo,
    path: &Path,
    signature: FileSig,
    hash: &(impl Fn(&Path, FileSig) -> io::Result<TypedDigest> + Sync),
) -> io::Result<TypedDigest> {
    verify_files(&[(path, signature)])?;
    if let Some(digest) = memo.get(&signature) {
        return Ok(digest);
    }
    let digest = flights.run(signature, || {
        verify_files(&[(path, signature)])?;
        // A preceding leader may have finished between lookup and admission.
        if let Some(digest) = memo.get(&signature) {
            return Ok(digest);
        }
        let digest = hash(path, signature)?;
        verify_files(&[(path, signature)])?;
        // Record before retiring the flight, closing the lookup/admission race.
        // No incomplete batch is promoted, but individually verified work stays.
        memo.remember(signature, &digest)?;
        Ok(digest)
    })?;
    // Same inode/version can be reached by different names. The leader's name
    // cannot prove that a follower's alias still resolves to that generation.
    verify_files(&[(path, signature)])?;
    // Normal callers share the same memo. An independent memo still needs its
    // own conflict check; a shared read never imports another memo's authority.
    memo.remember(signature, &digest)?;
    Ok(digest)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod wait_budget_tests {
    use super::super::{digest_stable_at, lstat_regular};
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    // Only the owner delay is injected. The read path still uses the production
    // flight table, descriptor-verified hashing, file identities and digest memo.
    const TEST_DEADLINE: Duration = Duration::from_secs(5);

    struct Gate {
        entered: mpsc::Sender<()>,
        released: Mutex<mpsc::Receiver<()>>,
    }

    impl Gate {
        fn hold(&self) -> io::Result<()> {
            self.entered.send(()).map_err(io::Error::other)?;
            self.released
                .lock()
                .map_err(|_| poisoned())?
                .recv_timeout(TEST_DEADLINE)
                .map_err(io::Error::other)
        }
    }

    fn gate() -> (Gate, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        (
            Gate {
                entered,
                released: Mutex::new(released),
            },
            observed,
            release,
        )
    }

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, FileSig, TypedDigest) {
        let directory = crate::test_util::private_tempdir();
        let path = directory.path().join("libbounded.rlib");
        std::fs::write(&path, b"exact retained toolchain bytes").unwrap();
        let (signature, expected) = digest_stable_at(&path, lstat_regular(&path).unwrap()).unwrap();
        (directory, path, signature, expected)
    }

    fn digest(path: &Path, signature: FileSig) -> io::Result<TypedDigest> {
        digest_stable_at(path, signature).map(|(_, digest)| digest)
    }

    fn expired_flights() -> Flights {
        Flights {
            follower_wait: Duration::ZERO,
            ..Flights::default()
        }
    }

    #[test]
    fn expired_followers_do_not_steal_or_retry_an_owned_read() {
        let (_directory, path, signature, expected) = fixture();
        let flights = expired_flights();
        let owner_memo = DigestMemo::default();
        let follower_memo = DigestMemo::default();
        let reads = AtomicUsize::new(0);
        let (gate, entered, release) = gate();
        thread::scope(|scope| {
            let owner = scope.spawn(|| {
                read_with(&flights, &owner_memo, &path, signature, &|path, signature| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    gate.hold()?;
                    digest(path, signature)
                })
            });
            entered.recv_timeout(TEST_DEADLINE).unwrap();
            let original = Arc::clone(flights.active.lock().unwrap().get(&signature).unwrap());
            for _ in 0..4 {
                let error = read_with(
                    &flights,
                    &follower_memo,
                    &path,
                    signature,
                    &|_, _| panic!("timeout must not dispatch a duplicate file read"),
                )
                .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert!(follower_memo.get(&signature).is_none());
                let active = flights.active.lock().unwrap();
                assert_eq!(active.len(), 1);
                assert!(Arc::ptr_eq(active.get(&signature).unwrap(), &original));
                assert!(original.result.lock().unwrap().is_none());
            }
            assert_eq!(reads.load(Ordering::SeqCst), 1);
            release.send(()).unwrap();
            assert_eq!(owner.join().unwrap().unwrap(), expected);
            assert_eq!(owner_memo.get(&signature), Some(expected.clone()));
            // A completed verified memo remains usable; the elapsed coordination
            // deadline is not a content expiry or permission to discard a result.
            assert_eq!(
                read_with(&flights, &owner_memo, &path, signature, &|_, _| {
                    panic!("completed owner result must not be reread")
                })
                .unwrap(),
                expected
            );
        });
        assert!(flights.active.lock().unwrap().is_empty());
    }

    #[test]
    fn timed_out_follower_can_finish_an_independent_file_while_owner_is_blocked() {
        let (directory, path, signature, expected) = fixture();
        let other = directory.path().join("libindependent.rlib");
        std::fs::write(&other, b"independent toolchain bytes").unwrap();
        let (other_signature, other_digest) =
            digest_stable_at(&other, lstat_regular(&other).unwrap()).unwrap();
        let flights = expired_flights();
        let memo = DigestMemo::default();
        let (gate, entered, release) = gate();
        thread::scope(|scope| {
            let owner = scope.spawn(|| {
                read_with(&flights, &memo, &path, signature, &|path, signature| {
                    gate.hold()?;
                    digest(path, signature)
                })
            });
            entered.recv_timeout(TEST_DEADLINE).unwrap();
            assert_eq!(
                read_with(&flights, &memo, &path, signature, &digest)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            assert_eq!(
                read_with(&flights, &memo, &other, other_signature, &digest).unwrap(),
                other_digest
            );
            assert!(memo.get(&signature).is_none());
            assert_eq!(flights.active.lock().unwrap().len(), 1);
            release.send(()).unwrap();
            assert_eq!(owner.join().unwrap().unwrap(), expected);
        });
        assert!(flights.active.lock().unwrap().is_empty());
    }

    #[test]
    fn notifications_cannot_renew_the_original_follower_deadline() {
        let flight = Arc::new(Flight {
            owner: thread::current().id(),
            wait_deadline: Instant::now() + Duration::from_millis(50),
            result: Mutex::new(None),
            changed: Condvar::new(),
        });
        let (completed, completion) = mpsc::channel();
        let follower = Arc::clone(&flight);
        let reader = thread::spawn(move || completed.send(follower.wait()).unwrap());
        let limit = Instant::now() + Duration::from_secs(2);
        let outcome = loop {
            if let Ok(outcome) = completion.try_recv() {
                break Some(outcome);
            }
            if Instant::now() >= limit {
                break None;
            }
            flight.changed.notify_all();
            thread::sleep(Duration::from_millis(2));
        };
        // Always release an incorrectly unbounded waiter before asserting, so
        // the regression control terminates instead of hanging the test runner.
        let still_unpublished = flight.result.lock().unwrap().is_none();
        *flight.result.lock().unwrap() = Some(Err(Failure::capture(&io::Error::other(
            "test cleanup after notification window",
        ))));
        flight.changed.notify_all();
        reader.join().unwrap();
        let error = outcome.expect("notifications extended the shared deadline").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("shared toolchain digest wait deadline"));
        assert!(still_unpublished, "a follower must not publish its timeout to other readers");
    }

    #[test]
    fn completed_results_and_original_errors_remain_available_after_wait_expiry() {
        let (_directory, _path, _signature, expected) = fixture();
        for outcome in [
            Ok(expected.clone()),
            Err(Failure::capture(&io::Error::from_raw_os_error(5))),
        ] {
            let flight = Flight {
                owner: thread::current().id(),
                wait_deadline: Instant::now(),
                result: Mutex::new(Some(outcome.clone())),
                changed: Condvar::new(),
            };
            match outcome {
                Ok(value) => assert_eq!(flight.wait().unwrap(), value),
                Err(_) => assert_eq!(flight.wait().unwrap_err().raw_os_error(), Some(5)),
            }
        }
        assert_eq!(Flights::default().follower_wait, Duration::from_secs(30));
    }

    #[test]
    fn owner_failure_after_follower_timeout_does_not_poison_later_read_admission() {
        let (_directory, path, signature, expected) = fixture();
        let flights = expired_flights();
        let memo = DigestMemo::default();
        let (gate, entered, release) = gate();
        thread::scope(|scope| {
            let owner = scope.spawn(|| {
                read_with(&flights, &memo, &path, signature, &|_, _| {
                    gate.hold()?;
                    Err(io::Error::from_raw_os_error(5))
                })
            });
            entered.recv_timeout(TEST_DEADLINE).unwrap();
            assert_eq!(
                read_with(&flights, &memo, &path, signature, &digest)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            release.send(()).unwrap();
            assert_eq!(owner.join().unwrap().unwrap_err().raw_os_error(), Some(5));
        });
        assert!(flights.active.lock().unwrap().is_empty());
        assert!(memo.get(&signature).is_none());
        assert_eq!(
            read_with(&flights, &memo, &path, signature, &digest).unwrap(),
            expected
        );
    }

    #[test]
    fn timed_out_alias_cannot_adopt_a_later_result_for_a_replaced_path() {
        let (directory, path, _signature, expected) = fixture();
        let aliases = directory.path().join("aliases");
        std::fs::create_dir(&aliases).unwrap();
        let alias = aliases.join("libbounded.rlib");
        std::fs::hard_link(&path, &alias).unwrap();
        let signature = lstat_regular(&path).unwrap();
        let flights = expired_flights();
        let memo = DigestMemo::default();
        let (gate, entered, release) = gate();
        thread::scope(|scope| {
            let owner = scope.spawn(|| {
                read_with(&flights, &memo, &path, signature, &|path, signature| {
                    gate.hold()?;
                    digest(path, signature)
                })
            });
            entered.recv_timeout(TEST_DEADLINE).unwrap();
            assert_eq!(
                read_with(&flights, &memo, &alias, signature, &digest)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            std::fs::rename(&aliases, directory.path().join("retained-aliases")).unwrap();
            std::fs::create_dir(&aliases).unwrap();
            std::fs::copy(&path, &alias).unwrap();
            release.send(()).unwrap();
            assert_eq!(owner.join().unwrap().unwrap(), expected);
            assert_eq!(memo.get(&signature), Some(expected.clone()));
            assert!(read_with(&flights, &memo, &alias, signature, &|_, _| {
                panic!("a replaced alias must be refused before hashing")
            }).is_err());
        });
    }

    #[test]
    fn an_expired_flight_keeps_the_existing_recursive_read_refusal() {
        let (_directory, _path, signature, expected) = fixture();
        let flights = expired_flights();
        assert_eq!(
            flights
                .run(signature, || flights.run(signature, || Ok(expected.clone())))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(flights.active.lock().unwrap().is_empty());
    }
}
