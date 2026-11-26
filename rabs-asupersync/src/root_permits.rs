//! Coordinator-owned Cargo root-permit broker (bead I001; risk R48;
//! plan Epic I). Backs the `CargoRootPermitRegion` of
//! [`crate::region_tree`] and the `ObligationKind::CargoRootPermit`
//! obligation of [`crate::obligations`].
//!
//! WHY A BROKER (risk R48): Cargo assumes ONE implicit root token per
//! invocation. A shared jobserver pipe bounds *intra*-Cargo parallelism
//! but says nothing about *how many* independent Cargo processes may run
//! — ten Cargo invocations are ten implicit root tokens no pipe ever
//! accounted. The broker makes the implicit explicit: every managed
//! Cargo process must hold a brokered root permit for its full
//! lifetime, and the pool size IS the host's root-parallelism budget.
//! No unaccounted implicit concurrency can exist because the permit is
//! only obtainable here, and the pool is bounded by construction.
//!
//! Division of labor (two budgets, never conflated):
//! - root permits (THIS module): how many Cargo processes at once;
//! - worker-local jobserver ([`crate::jobserver`]): how many compile
//!   jobs inside one Cargo process at once.
//!
//! Discipline: release is exactly-once (a double release is a typed
//! error, mirroring I7's law for the obligation); the RAII guard makes
//! forgetting impossible; the obligation pairing means a leaked permit
//! surfaces as an unresolved `CargoRootPermit` at region close instead
//! of vanishing into a counter.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::obligations::{ObligationError, ObligationKind, ObligationSet};

/// Why a permit could not be taken or given back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermitError {
    /// No permit free within the waited budget.
    Timeout,
    /// The permit was released more than once (I7's exactly-once law).
    DoubleRelease(u64),
    /// The permit id is unknown to this broker (foreign or stale).
    UnknownPermit(u64),
}

/// Coordinator-side ledger state.
#[derive(Debug)]
struct BrokerState {
    /// Free root slots (granted roots = `max_roots - available`).
    available: usize,
    /// Monotonic permit ids (never reused — attribution stays unambiguous).
    next_id: u64,
    /// Outstanding (granted, unreleased) permit ids.
    live: BTreeMap<u64, ()>,
    /// Each registration has a private wakeup and retains its place across
    /// cancellation/health polls. Only the head can take the next slot.
    waiting: VecDeque<Arc<Condvar>>,
}

impl BrokerState {
    fn wake_head(&self) {
        if self.available > 0
            && let Some(head) = self.waiting.front()
        {
            head.notify_one();
        }
    }
}

/// The coordinator-owned broker. Share as `Arc` across the coordinator's
/// launch paths; every managed Cargo process goes through it.
#[derive(Debug)]
pub struct RootPermitBroker {
    max_roots: usize,
    state: Mutex<BrokerState>,
}

/// FIFO registration for a Cargo root. Dropping it withdraws this caller
/// without opening an obligation or consuming a root slot.
#[derive(Debug)]
pub struct RootPermitWaiter {
    broker: Arc<RootPermitBroker>,
    ready: Arc<Condvar>,
    queued: bool,
}

/// One granted root permit (RAII: drop = release).
///
/// The permit backs exactly ONE Cargo process for its FULL lifetime —
/// from before spawn to after reaping. Dropping early while the process
/// lives would mint exactly the unaccounted implicit concurrency R48
/// forbids; callers therefore hold the guard, not a counter.
#[derive(Debug)]
pub struct RootPermit {
    id: u64,
    broker: Arc<RootPermitBroker>,
    /// Set false once release has run (explicit or Drop) so a consumed
    /// guard can never release twice even if `release()` is called and
    /// the value is then dropped.
    released: bool,
}

impl RootPermitBroker {
    /// Create a broker with `max_roots` root slots.
    ///
    /// # Panics
    /// A zero-root broker grants nothing and deadlocks every client by
    /// construction — refused loudly instead.
    #[must_use]
    pub fn new(max_roots: usize) -> Arc<Self> {
        assert!(max_roots > 0, "a zero-root broker deadlocks every client");
        Arc::new(Self {
            max_roots,
            state: Mutex::new(BrokerState {
                available: max_roots,
                next_id: 0,
                live: BTreeMap::new(),
                waiting: VecDeque::new(),
            }),
        })
    }

    /// The granted-root budget (the pool size).
    #[must_use]
    pub fn max_roots(&self) -> usize {
        self.max_roots
    }

    /// Currently ACTIVE (granted, unreleased) permits.
    ///
    /// The T016 invariant is `active() <= max_roots()` at EVERY
    /// observation — structurally guaranteed because permits exist only
    /// as values this broker handed out against this counter.
    #[must_use]
    pub fn active(&self) -> usize {
        self.state.lock().map(|s| s.live.len()).unwrap_or(0)
    }

    /// Take a root permit if one is free, without waiting.
    ///
    /// Also opens the `CargoRootPermit` obligation in `set` so the
    /// owning attempt's region cannot close while the process lives.
    /// Queued callers have priority over a new nonblocking request.
    #[must_use]
    pub fn try_acquire(self: &Arc<Self>, set: &mut ObligationSet) -> Option<RootPermit> {
        let mut state = self.state.lock().ok()?;
        if state.available == 0 || !state.waiting.is_empty() {
            return None;
        }
        Some(self.grant(&mut state, set))
    }

    fn grant(self: &Arc<Self>, state: &mut BrokerState, set: &mut ObligationSet) -> RootPermit {
        state.available -= 1;
        state.next_id += 1;
        let id = state.next_id;
        state.live.insert(id, ());
        set.open(ObligationKind::CargoRootPermit);
        RootPermit {
            id,
            broker: Arc::clone(self),
            released: false,
        }
    }

    /// Register once when waiting for a root, including callers that must
    /// periodically leave their wait to check for cancellation or shutdown.
    #[must_use]
    pub fn queue(self: &Arc<Self>) -> RootPermitWaiter {
        let ready = Arc::new(Condvar::new());
        self.state
            .lock()
            .expect("root broker mutex poisoned")
            .waiting
            .push_back(Arc::clone(&ready));
        RootPermitWaiter {
            broker: Arc::clone(self),
            ready,
            queued: true,
        }
    }

    /// Take a root permit, blocking until one frees. Opens the
    /// `CargoRootPermit` obligation in `set` (see [`Self::try_acquire`]).
    ///
    /// # Panics
    /// If the broker's mutex is poisoned by a panicking holder — a
    /// corrupted ledger must not silently over-grant.
    #[must_use]
    pub fn acquire(self: &Arc<Self>, set: &mut ObligationSet) -> RootPermit {
        self.queue()
            .wait(set, None)
            .expect("an unbounded wait cannot time out")
    }

    /// Take a root permit with a wait budget.
    ///
    /// # Errors
    /// [`PermitError::Timeout`] when no slot frees in time.
    pub fn acquire_timeout(
        self: &Arc<Self>,
        set: &mut ObligationSet,
        timeout: Duration,
    ) -> Result<RootPermit, PermitError> {
        self.queue()
            .wait_timeout(set, timeout)
            .map_err(|_| PermitError::Timeout)
    }

    /// Return permit `id` to the pool. Exactly-once: a second release
    /// of the same id is a typed [`PermitError::DoubleRelease`] — the
    /// ledger must never credit one process twice.
    ///
    /// # Errors
    /// [`PermitError::DoubleRelease`] / [`PermitError::UnknownPermit`].
    pub fn release(&self, id: u64) -> Result<(), PermitError> {
        let mut state = self.state.lock().map_err(|_| PermitError::Timeout)?;
        if state.live.remove(&id).is_none() {
            // Never issued by THIS broker, or already released.
            return if id <= state.next_id {
                Err(PermitError::DoubleRelease(id))
            } else {
                Err(PermitError::UnknownPermit(id))
            };
        }
        state.available += 1;
        state.wake_head();
        Ok(())
    }

    /// Pair a held permit with the attempt's obligation set: resolve
    /// `CargoRootPermit` exactly once at release time. Called by
    /// [`RootPermit::release_into`]; exposed for callers that manage
    /// their own set lifecycle around a raw id.
    ///
    /// # Errors
    /// The obligation set's own discipline (never opened / already
    /// resolved — the latter IS the double-release signal upstream).
    pub fn resolve_obligation(set: &mut ObligationSet) -> Result<(), ObligationError> {
        set.resolve(ObligationKind::CargoRootPermit)
    }
}

impl RootPermitWaiter {
    /// Wait up to `timeout` for this registration. On expiry, returns the
    /// same registration to poll again or drop to cancel.
    ///
    /// # Errors
    /// Returns this still-queued waiter when no slot is available to it
    /// before the wait expires.
    pub fn wait_timeout(
        self,
        set: &mut ObligationSet,
        timeout: Duration,
    ) -> Result<RootPermit, Self> {
        self.wait(set, Some(timeout))
    }

    fn wait(
        mut self,
        set: &mut ObligationSet,
        timeout: Option<Duration>,
    ) -> Result<RootPermit, Self> {
        let state = self
            .broker
            .state
            .lock()
            .expect("root broker mutex poisoned");
        let blocked = |state: &mut BrokerState| {
            state.available == 0
                || !state
                    .waiting
                    .front()
                    .is_some_and(|head| Arc::ptr_eq(head, &self.ready))
        };
        let mut state = match timeout {
            Some(timeout) => {
                self.ready
                    .wait_timeout_while(state, timeout, blocked)
                    .expect("root broker mutex poisoned")
                    .0
            }
            None => self
                .ready
                .wait_while(state, blocked)
                .expect("root broker mutex poisoned"),
        };
        if blocked(&mut state) {
            drop(state);
            return Err(self);
        }
        state.waiting.pop_front();
        self.queued = false;
        let permit = self.broker.grant(&mut state, set);
        state.wake_head();
        Ok(permit)
    }
}

impl Drop for RootPermitWaiter {
    fn drop(&mut self) {
        if self.queued {
            let mut state = self
                .broker
                .state
                .lock()
                .expect("root broker mutex poisoned");
            state
                .waiting
                .retain(|waiter| !Arc::ptr_eq(waiter, &self.ready));
            state.wake_head();
        }
    }
}

impl RootPermit {
    /// The permit id (stable attribution key for logs/receipts).
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Release the root and resolve the paired `CargoRootPermit`
    /// obligation. Consumes the guard; dropping without calling this
    /// releases the ROOT but leaves the obligation OPEN — a leaked
    /// permit is exactly what `may_close_region` must catch, so only
    /// use plain `Drop` on paths where the obligation is resolved
    /// separately.
    ///
    /// # Errors
    /// The obligation resolution result (typed; see
    /// [`RootPermitBroker::resolve_obligation`]). The root returns to
    /// the pool regardless.
    pub fn release_into(mut self, set: &mut ObligationSet) -> Result<(), ObligationError> {
        self.released = true;
        let result = Self::broker_release(&self.broker, self.id);
        debug_assert!(result.is_ok(), "live permit must release cleanly");
        RootPermitBroker::resolve_obligation(set)
    }

    fn broker_release(broker: &RootPermitBroker, id: u64) -> Result<(), PermitError> {
        broker.release(id)
    }
}

impl Drop for RootPermit {
    fn drop(&mut self) {
        if !self.released {
            // RAII backstop: the ROOT must return or the pool leaks.
            // (Obligation resolution stays the caller's explicit act —
            // see `release_into`.)
            let _ = Self::broker_release(&self.broker, self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn set() -> ObligationSet {
        ObligationSet::default()
    }

    #[test]
    fn pool_is_bounded_by_construction() {
        let broker = RootPermitBroker::new(3);
        let mut s1 = set();
        let mut s2 = set();
        let mut s3 = set();
        let mut s4 = set();

        let p1 = broker.try_acquire(&mut s1).expect("first");
        let p2 = broker.try_acquire(&mut s2).expect("second");
        let p3 = broker.try_acquire(&mut s3).expect("third");
        assert_eq!(broker.active(), 3);
        assert!(
            broker.try_acquire(&mut s4).is_none(),
            "fourth permit must not exist with max_roots=3"
        );

        drop(p1); // RAII release
        assert_eq!(broker.active(), 2);
        let p4 = broker.try_acquire(&mut s4).expect("after release");
        let _ = (p2, p3, p4);
    }

    #[test]
    fn release_is_exactly_once_typed() {
        let broker = RootPermitBroker::new(1);
        let mut set_a = set();
        let permit = broker.try_acquire(&mut set_a).expect("grant");
        let id = permit.id();
        drop(permit); // RAII release #1
        assert_eq!(broker.active(), 0);
        // A second release of the SAME id is the typed double-release.
        assert_eq!(broker.release(id), Err(PermitError::DoubleRelease(id)));
        // A never-issued id is unknown, not double.
        assert_eq!(
            broker.release(9_999),
            Err(PermitError::UnknownPermit(9_999))
        );
    }

    #[test]
    fn obligation_pairing_gates_region_close() {
        let broker = RootPermitBroker::new(1);
        let mut attempt_set = set();
        let permit = broker.acquire(&mut attempt_set);
        // Region close must be BLOCKED while the Cargo process lives.
        assert!(attempt_set.may_close_region().is_err());
        // Release resolves the obligation exactly once...
        permit.release_into(&mut attempt_set).expect("release");
        // ...and the region may close.
        assert!(attempt_set.may_close_region().is_ok());
    }

    #[test]
    fn blocking_acquire_wakes_on_release() {
        let broker = RootPermitBroker::new(1);
        let mut main_set = set();
        let permit = broker.try_acquire(&mut main_set).expect("grant");

        let broker_for_worker = Arc::clone(&broker);
        let worker = std::thread::spawn(move || {
            let mut worker_set = set();
            // Blocks until main releases.
            let p = broker_for_worker.acquire(&mut worker_set);
            p.release_into(&mut worker_set).is_ok()
        });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(broker.active(), 1, "blocked acquirer must not over-grant");
        drop(permit);
        assert!(worker.join().expect("thread"), "blocked acquire never woke");
    }

    #[test]
    fn timeout_reports_when_pool_stays_empty() {
        let broker = RootPermitBroker::new(1);
        let mut holder = set();
        let _permit = broker.try_acquire(&mut holder).expect("grant");
        let mut waiter = set();
        assert!(matches!(
            broker.acquire_timeout(&mut waiter, Duration::from_millis(80)),
            Err(PermitError::Timeout)
        ));
    }

    #[test]
    fn health_polls_preserve_fifo_and_cancellation_passes_a_free_slot() {
        let broker = RootPermitBroker::new(1);
        let holder = broker.acquire(&mut set());
        let oldest = broker.queue();
        let cancelled = broker.queue();
        let next = broker.queue();
        let mut obligations = set();

        // Canonical services repeatedly time out while checking authority
        // and caller interest. A timeout must keep the original position.
        let oldest = oldest
            .wait_timeout(&mut obligations, Duration::ZERO)
            .unwrap_err();
        let oldest = oldest
            .wait_timeout(&mut obligations, Duration::ZERO)
            .unwrap_err();
        assert!(obligations.may_close_region().is_ok());
        drop(holder);
        assert!(broker.try_acquire(&mut set()).is_none());
        let next = next.wait_timeout(&mut set(), Duration::ZERO).unwrap_err();
        let permit = oldest
            .wait_timeout(&mut obligations, Duration::ZERO)
            .unwrap();
        assert!(obligations.may_close_region().is_err());
        permit.release_into(&mut obligations).unwrap();

        // A cancelled caller may be at the head with capacity available.
        let next = next.wait_timeout(&mut set(), Duration::ZERO).unwrap_err();
        drop(cancelled);
        let permit = next.wait_timeout(&mut set(), Duration::ZERO).unwrap();
        assert_eq!(broker.active(), 1);
        drop(permit);
        assert!(broker.try_acquire(&mut set()).is_some());
    }

    #[test]
    fn cancelling_the_queue_head_wakes_a_sleeping_successor() {
        let broker = RootPermitBroker::new(1);
        let first = broker.queue();
        let second = broker.queue();
        let worker = std::thread::spawn(move || {
            second
                .wait_timeout(&mut set(), Duration::from_secs(2))
                .unwrap()
        });
        drop(first);
        let permit = worker.join().unwrap();
        assert_eq!(broker.active(), 1);
        drop(permit);
        assert_eq!(broker.active(), 0);
    }

    #[test]
    fn stress_active_never_exceeds_granted_roots() {
        // T016-style: many contending acquirers; a watcher samples the
        // invariant continuously. Structural bound: permits exist only
        // as values this broker handed out against its counter.
        const ROOTS: usize = 4;
        const WORKERS: usize = 12;
        const ROUNDS: usize = 40;
        let broker = RootPermitBroker::new(ROOTS);
        let violations = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicUsize::new(0));

        let watcher_broker = Arc::clone(&broker);
        let watcher_violations = Arc::clone(&violations);
        let watcher_stop = Arc::clone(&stop);
        let watcher = std::thread::spawn(move || {
            while watcher_stop.load(Ordering::Relaxed) == 0 {
                if watcher_broker.active() > watcher_broker.max_roots() {
                    watcher_violations.fetch_add(1, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_micros(200));
            }
        });

        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let worker_broker = Arc::clone(&broker);
            handles.push(std::thread::spawn(move || {
                for round in 0..ROUNDS as u64 {
                    let mut s = set();
                    if let Ok(permit) =
                        worker_broker.acquire_timeout(&mut s, Duration::from_secs(5))
                    {
                        std::thread::sleep(Duration::from_micros((permit.id() + round) % 7 * 100));
                        let _ = permit.release_into(&mut s);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("stress worker");
        }

        stop.store(1, Ordering::Relaxed);
        watcher.join().expect("watcher");
        assert_eq!(broker.active(), 0, "all permits returned after joins");
        assert_eq!(
            violations.load(Ordering::Relaxed),
            0,
            "active permits exceeded the granted-root budget"
        );
        assert_eq!(broker.active(), 0, "all permits returned after joins");
    }
}
