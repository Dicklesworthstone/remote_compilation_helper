//! Bounded, cancellation-safe ownership of live toolchain observations.
//!
//! A ready sysroot can contain thousands of files. Never stat those files while
//! holding the shared toolchain memo mutex. A failed validation may replace only
//! the exact ready observation it checked, and a warm worker may complete or
//! abandon only its own reservation. This is observation ownership, not compiler
//! execution authority; request guards and all downstream gates remain mandatory.

use super::{
    FactsMiss, LiveFacts, PROBE_RETRY, ProbedToolchain, Slot, ToolchainFacts, probe_toolchain,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const MAX_TOOLCHAIN_MEMOS: usize = 64;
type Memos = HashMap<PathBuf, Slot<ProbedToolchain>>;

struct Reservation {
    facts: Arc<LiveFacts>,
    compiler: PathBuf,
    token: Arc<()>,
}

impl Reservation {
    fn insert(
        facts: &Arc<LiveFacts>,
        memos: &mut Memos,
        compiler: &Path,
    ) -> Result<Self, FactsMiss> {
        if !memos.contains_key(compiler) && memos.len() >= MAX_TOOLCHAIN_MEMOS {
            // Never evict active work: a second caller must not start another
            // probe merely because a memo reached its bound. Outstanding guards
            // retain their own ready observations after advisory eviction.
            memos.retain(|_, slot| matches!(slot, Slot::Warming(_)));
        }
        if !memos.contains_key(compiler) && memos.len() >= MAX_TOOLCHAIN_MEMOS {
            return Err(FactsMiss::Pending);
        }
        let token = Arc::new(());
        memos.insert(compiler.to_path_buf(), Slot::Warming(Arc::clone(&token)));
        Ok(Self {
            facts: Arc::clone(facts),
            compiler: compiler.to_path_buf(),
            token,
        })
    }

    fn owns(&self, memos: &Memos) -> bool {
        matches!(memos.get(&self.compiler),
            Some(Slot::Warming(token)) if Arc::ptr_eq(token, &self.token))
    }

    fn finish(self, result: Result<ProbedToolchain, String>) -> bool {
        // File validation and destruction of a rejected observation take place
        // outside the mutex. Even an internal probe must name this compiler.
        let result = result.and_then(|probed| {
            if probed.inputs.compiler.0 != self.compiler || !probed.still_current() {
                return Err("toolchain inputs changed before warm completion".into());
            }
            Ok(probed)
        });
        let slot = match result {
            Ok(probed) => Slot::Ready(Arc::new(probed)),
            Err(reason) => Slot::Failed {
                reason,
                at: Instant::now(),
            },
        };
        let Ok(mut memos) = self.facts.toolchains.lock() else {
            return false;
        };
        if !self.owns(&memos) {
            return false;
        }
        memos.insert(self.compiler.clone(), slot);
        true
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut memos) = self.facts.toolchains.lock()
            && self.owns(&memos)
        {
            // Covers an unstarted closure, probe unwind, or abandoned result.
            // A successor with equal inputs still has a different token.
            memos.remove(&self.compiler);
        }
    }
}

enum Lookup {
    Ready(Arc<ProbedToolchain>),
    Reserved(Reservation),
}

pub(super) fn observe(
    facts: &Arc<LiveFacts>,
    compiler: &Path,
    env: &[(String, String)],
) -> Result<ToolchainFacts, FactsMiss> {
    observe_with(
        facts,
        compiler,
        env,
        ProbedToolchain::still_current,
        probe_toolchain,
    )
}

fn observe_with(
    facts: &Arc<LiveFacts>,
    compiler: &Path,
    env: &[(String, String)],
    verify: impl FnOnce(&ProbedToolchain) -> bool,
    probe: impl FnOnce(&Path, &[(String, String)]) -> Result<ProbedToolchain, String> + Send + 'static,
) -> Result<ToolchainFacts, FactsMiss> {
    if !compiler.is_absolute() {
        return Err(FactsMiss::Refused("compiler path is not absolute".into()));
    }
    let lookup = {
        let mut memos = facts
            .toolchains
            .lock()
            .map_err(|_| FactsMiss::Refused("toolchain memo poisoned".into()))?;
        match memos.get(compiler) {
            Some(Slot::Ready(probed)) => Lookup::Ready(Arc::clone(probed)),
            Some(Slot::Warming(_)) => return Err(FactsMiss::Pending),
            Some(Slot::Failed { reason, at }) if at.elapsed() < PROBE_RETRY => {
                return Err(FactsMiss::Refused(reason.clone()));
            }
            _ => Lookup::Reserved(Reservation::insert(facts, &mut memos, compiler)?),
        }
    };
    let reservation = match lookup {
        Lookup::Reserved(reservation) => reservation,
        Lookup::Ready(probed) => {
            // This may do slow filesystem I/O. Other compiler identities and
            // ready-guard acquisitions must remain independent of that latency.
            if verify(&probed) {
                return Ok(probed.facts.clone());
            }
            let mut memos = facts
                .toolchains
                .lock()
                .map_err(|_| FactsMiss::Refused("toolchain memo poisoned".into()))?;
            if !matches!(memos.get(compiler),
                Some(Slot::Ready(current)) if Arc::ptr_eq(current, &probed))
            {
                // Another caller already replaced or evicted this generation.
                // Never overwrite its work using our obsolete validation.
                return Err(FactsMiss::Pending);
            }
            Reservation::insert(facts, &mut memos, compiler)?
        }
    };
    let compiler = compiler.to_path_buf();
    let env = env.to_vec();
    // Reuse the existing bounded warm pool and its permit. The reservation is
    // in the closure before admission, so spawn failure and unwinding cannot
    // leave permanent Warming state. No new runtime, queue, or worker pool.
    facts.start_warm(move |_| {
        reservation.finish(probe(&compiler, &env));
    });
    Err(FactsMiss::Pending)
}

#[cfg(test)]
mod tests {
    use super::super::{MAX_WARMING, tests::toolchain_fixture};
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex, mpsc};
    use std::time::Duration;

    const DEADLINE: Duration = Duration::from_secs(8);

    fn until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + DEADLINE;
        while !condition() {
            assert!(
                Instant::now() < deadline,
                "toolchain observation did not settle"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn ready(facts: &Arc<LiveFacts>, compiler: &Path) -> Arc<ProbedToolchain> {
        let probed = Arc::new(probe_toolchain(compiler, &[]).unwrap());
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.to_path_buf(), Slot::Ready(Arc::clone(&probed)));
        probed
    }

    #[test]
    fn ready_validation_never_holds_the_shared_memo_mutex() {
        let (_dir, compiler) = toolchain_fixture();
        let facts = LiveFacts::new();
        let expected = ready(&facts, &compiler);
        let actual = observe_with(
            &facts,
            &compiler,
            &[],
            |probed| {
                let guard = facts
                    .toolchains
                    .try_lock()
                    .expect("memo held during filesystem validation");
                drop(guard);
                probed.still_current()
            },
            |_, _| panic!("ready observations do not probe"),
        )
        .unwrap();
        assert_eq!(actual, expected.facts);
        assert_eq!(*facts.warming.lock().unwrap(), 0);
    }

    #[test]
    fn blocked_validation_does_not_block_another_ready_toolchain() {
        let (_first_dir, first) = toolchain_fixture();
        let (_second_dir, second) = toolchain_fixture();
        let facts = LiveFacts::new();
        ready(&facts, &first);
        let expected = ready(&facts, &second).facts.clone();
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let slow_facts = Arc::clone(&facts);
        let slow = std::thread::spawn(move || {
            observe_with(
                &slow_facts,
                &first,
                &[],
                move |probed| {
                    entered.send(()).unwrap();
                    released.recv_timeout(DEADLINE).unwrap();
                    probed.still_current()
                },
                |_, _| panic!("ready observation unexpectedly reprobed"),
            )
        });
        entering.recv_timeout(DEADLINE).unwrap();
        let fast_facts = Arc::clone(&facts);
        let (finished, finishing) = mpsc::channel();
        let fast = std::thread::spawn(move || {
            finished.send(fast_facts.toolchain(&second, &[])).unwrap();
        });
        let answer = finishing.recv_timeout(Duration::from_secs(2));
        // Release even on failure so an old lock-holding implementation does
        // not leave the harness with a blocked child thread.
        release.send(()).unwrap();
        slow.join().unwrap().unwrap();
        fast.join().unwrap();
        assert_eq!(
            answer
                .expect("unrelated lookup blocked behind validation")
                .unwrap(),
            expected
        );
    }

    #[test]
    fn obsolete_validation_cannot_overwrite_a_successor_observation() {
        let (_dir, compiler) = toolchain_fixture();
        let facts = LiveFacts::new();
        ready(&facts, &compiler);
        let successor = Arc::new(probe_toolchain(&compiler, &[]).unwrap());
        let answer = observe_with(
            &facts,
            &compiler,
            &[],
            |_| {
                facts
                    .toolchains
                    .lock()
                    .unwrap()
                    .insert(compiler.clone(), Slot::Ready(Arc::clone(&successor)));
                false
            },
            |_, _| panic!("obsolete validation started a new probe"),
        );
        assert_eq!(answer, Err(FactsMiss::Pending));
        assert!(matches!(facts.toolchains.lock().unwrap().get(&compiler),
            Some(Slot::Ready(current)) if Arc::ptr_eq(current, &successor)));
        assert_eq!(*facts.warming.lock().unwrap(), 0);
    }

    #[test]
    fn fifteen_callers_share_one_owned_probe_and_one_ready_result() {
        let (_dir, compiler) = toolchain_fixture();
        let facts = LiveFacts::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered, entering) = mpsc::channel();
        let mut callers = Vec::new();
        for _ in 0..15 {
            let facts = Arc::clone(&facts);
            let compiler = compiler.clone();
            let calls = Arc::clone(&calls);
            let release = Arc::clone(&release);
            let entered = entered.clone();
            callers.push(std::thread::spawn(move || {
                observe_with(
                    &facts,
                    &compiler,
                    &[],
                    ProbedToolchain::still_current,
                    move |compiler, env| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        entered.send(()).unwrap();
                        let (lock, changed) = &*release;
                        let (allowed, _) = changed
                            .wait_timeout_while(lock.lock().unwrap(), DEADLINE, |allowed| !*allowed)
                            .unwrap();
                        assert!(*allowed, "probe release deadline expired");
                        drop(allowed);
                        probe_toolchain(compiler, env)
                    },
                )
            }));
        }
        for caller in callers {
            assert_eq!(caller.join().unwrap(), Err(FactsMiss::Pending));
        }
        entering.recv_timeout(DEADLINE).unwrap();
        let observed_calls = calls.load(Ordering::SeqCst);
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        until(|| *facts.warming.lock().unwrap() == 0);
        assert_eq!(observed_calls, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let expected = facts.toolchain(&compiler, &[]).unwrap();
        facts
            .toolchain_guard(&compiler, &expected)
            .unwrap()
            .verify_unchanged(&compiler)
            .unwrap();
    }

    #[test]
    fn a_panicking_probe_releases_memo_and_real_warm_capacity() {
        let (_dir, compiler) = toolchain_fixture();
        let facts = LiveFacts::new();
        assert_eq!(
            observe_with(
                &facts,
                &compiler,
                &[],
                ProbedToolchain::still_current,
                |_, _| panic!("injected toolchain probe panic"),
            ),
            Err(FactsMiss::Pending)
        );
        until(|| *facts.warming.lock().unwrap() == 0);
        assert!(!facts.toolchains.lock().unwrap().contains_key(&compiler));
        assert_eq!(facts.toolchain(&compiler, &[]), Err(FactsMiss::Pending));
        until(|| *facts.warming.lock().unwrap() == 0);
        let observed = facts.toolchain(&compiler, &[]).unwrap();
        facts
            .toolchain_guard(&compiler, &observed)
            .unwrap()
            .verify_unchanged(&compiler)
            .unwrap();
    }

    #[test]
    fn saturated_pool_drops_the_unstarted_reservation_without_probing() {
        let (_dir, compiler) = toolchain_fixture();
        let facts = LiveFacts::new();
        *facts.warming.lock().unwrap() = MAX_WARMING;
        assert_eq!(
            observe_with(
                &facts,
                &compiler,
                &[],
                ProbedToolchain::still_current,
                |_, _| panic!("saturated pool ran an unadmitted probe"),
            ),
            Err(FactsMiss::Pending)
        );
        assert!(!facts.toolchains.lock().unwrap().contains_key(&compiler));
        assert_eq!(*facts.warming.lock().unwrap(), MAX_WARMING);
    }

    #[test]
    fn stale_completion_and_abandonment_preserve_a_new_reservation() {
        let (_dir, compiler) = toolchain_fixture();
        let facts = LiveFacts::new();
        for finish in [false, true] {
            let (old, new) = {
                let mut memos = facts.toolchains.lock().unwrap();
                let old = Reservation::insert(&facts, &mut memos, &compiler).unwrap();
                let new = Reservation::insert(&facts, &mut memos, &compiler).unwrap();
                (old, new)
            };
            if finish {
                assert!(!old.finish(probe_toolchain(&compiler, &[])));
            } else {
                drop(old);
            }
            assert!(new.owns(&facts.toolchains.lock().unwrap()));
            assert!(new.finish(probe_toolchain(&compiler, &[])));
            facts.toolchain(&compiler, &[]).unwrap();
        }
    }

    #[test]
    fn failures_keep_existing_backoff_without_poisoning_the_pool() {
        let (_dir, compiler) = toolchain_fixture();
        let facts = LiveFacts::new();
        assert_eq!(
            observe_with(
                &facts,
                &compiler,
                &[],
                ProbedToolchain::still_current,
                |_, _| Err("fixture probe refused".into()),
            ),
            Err(FactsMiss::Pending)
        );
        until(|| *facts.warming.lock().unwrap() == 0);
        assert_eq!(
            observe_with(
                &facts,
                &compiler,
                &[],
                ProbedToolchain::still_current,
                |_, _| panic!("failed probe retried during its backoff"),
            ),
            Err(FactsMiss::Refused("fixture probe refused".into()))
        );
        assert_eq!(*facts.warming.lock().unwrap(), 0);
    }

    #[test]
    fn memo_capacity_preserves_active_reservations_and_evicts_only_advisory_state() {
        let facts = LiveFacts::new();
        let mut owners = Vec::new();
        {
            let mut memos = facts.toolchains.lock().unwrap();
            for index in 0..MAX_TOOLCHAIN_MEMOS {
                owners.push(
                    Reservation::insert(
                        &facts,
                        &mut memos,
                        &PathBuf::from(format!("/fixture/{index}/bin/rustc")),
                    )
                    .unwrap(),
                );
            }
            assert_eq!(memos.len(), MAX_TOOLCHAIN_MEMOS);
            assert!(matches!(
                Reservation::insert(&facts, &mut memos, Path::new("/fixture/extra/bin/rustc"),),
                Err(FactsMiss::Pending)
            ));
        }
        let completed = owners.pop().unwrap();
        assert!(completed.finish(Err("fixture failure".into())));
        {
            let mut memos = facts.toolchains.lock().unwrap();
            let next =
                Reservation::insert(&facts, &mut memos, Path::new("/fixture/extra/bin/rustc"))
                    .unwrap();
            assert_eq!(memos.len(), MAX_TOOLCHAIN_MEMOS);
            assert!(owners.iter().all(|owner| owner.owns(&memos)));
            // Drop must acquire the mutex only after this critical section.
            owners.push(next);
        }
        drop(owners);
        assert!(facts.toolchains.lock().unwrap().is_empty());
    }
}
