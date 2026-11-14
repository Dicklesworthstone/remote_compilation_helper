//! In-memory custody of already admitted operations across transport loss.
//!
//! A reservation can be activated only by its original input owner. Resume
//! can take an existing payload, but cannot construct one or run a build.
//! Entries remain bound to one TLS peer and one complete coordinator authority;
//! neither this registry nor its tokens promise recovery after process restart.

use rabs_protocol::authority::CoordinatorAuthority;
use rabs_protocol::durable_ids::BuildOperationId;
use rabs_protocol::reconnect::{ResumableToken, SubscriberId};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "remote operation is unavailable for this peer, token, or authority",
    )
}

// Destructors must still drain custody after a panic. No lock guards cross
// user code, filesystem work, thread joins, or an await point.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct Entry<T> {
    peer: [u8; 32],
    token: ResumableToken,
    stopped: Arc<AtomicBool>,
    state: Mutex<State<T>>,
}

struct State<T> {
    receiving: bool,
    retired: bool,
    payload: Option<T>,
    attached: Option<Arc<AtomicBool>>,
    deadline: Instant,
    detached_until: Option<Instant>,
}

impl<T> State<T> {
    fn expired(&self, now: Instant) -> bool {
        now >= self.deadline || self.detached_until.is_some_and(|until| now >= until)
    }
}

pub(super) struct Registry<T> {
    authority: CoordinatorAuthority,
    maximum: usize,
    grace: Duration,
    stopped: AtomicBool,
    entries: Mutex<BTreeMap<u128, Arc<Entry<T>>>>,
}

pub(super) enum Claim<T> {
    Pending,
    Attached(Attachment<T>),
}

/// At most one complete Progress record can be unacknowledged. A reconnect
/// may report either whole record boundary, never a mixed or invented cursor.
#[derive(Default)]
pub(super) struct DiagnosticFrontier {
    acknowledged: (u64, u64),
    offered: (u64, u64),
}

impl DiagnosticFrontier {
    pub(super) fn reattach(&mut self, exposed: (u64, u64)) -> io::Result<()> {
        if exposed != self.acknowledged && exposed != self.offered {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "remote diagnostic resume cursor is not a complete offered record",
            ));
        }
        self.acknowledged = exposed;
        self.offered = exposed;
        Ok(())
    }

    pub(super) fn acknowledge_poll(&mut self) -> (u64, u64) {
        self.acknowledged = self.offered;
        self.offered
    }

    pub(super) fn offer(&mut self, stdout: u64, stderr: u64) -> io::Result<()> {
        if stdout < self.acknowledged.0 || stderr < self.acknowledged.1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "remote diagnostic output moved backwards",
            ));
        }
        self.offered = (stdout, stderr);
        Ok(())
    }
}

pub(super) struct Reservation<T> {
    registry: Arc<Registry<T>>,
    entry: Arc<Entry<T>>,
    live: bool,
}

pub(super) struct Attachment<T> {
    registry: Arc<Registry<T>>,
    entry: Arc<Entry<T>>,
    value: Option<T>,
    deadline: Instant,
    live: bool,
}

impl<T> Registry<T> {
    pub(super) fn new(
        authority: CoordinatorAuthority,
        maximum: usize,
        grace: Duration,
    ) -> io::Result<Arc<Self>> {
        if authority.incarnation_id.0 == 0
            || !(1..=32).contains(&maximum)
            || grace.is_zero()
            || grace > Duration::from_secs(300)
        {
            return Err(refused());
        }
        Ok(Arc::new(Self {
            authority,
            maximum,
            grace,
            stopped: AtomicBool::new(false),
            entries: Mutex::new(BTreeMap::new()),
        }))
    }

    pub(super) fn reserve(
        self: &Arc<Self>,
        peer: [u8; 32],
        connection_stop: Arc<AtomicBool>,
        deadline: Instant,
        now: Instant,
    ) -> io::Result<Reservation<T>> {
        if peer == [0; 32] || now >= deadline || connection_stop.load(Ordering::Acquire) {
            return Err(refused());
        }
        let mut entropy = File::open("/dev/urandom")?;
        for _ in 0..8 {
            let mut bytes = [0u8; 48];
            entropy.read_exact(&mut bytes)?;
            let request = u128::from_be_bytes(bytes[..16].try_into().expect("fixed ID length"));
            let secret: [u8; 32] = bytes[16..].try_into().expect("fixed secret length");
            if request == 0 || secret == [0; 32] {
                continue;
            }
            let entry = Arc::new(Entry {
                peer,
                token: ResumableToken {
                    request: BuildOperationId(request),
                    subscriber: SubscriberId(1),
                    issued_by_incarnation: self.authority.incarnation_id.0,
                    secret,
                },
                stopped: Arc::new(AtomicBool::new(false)),
                state: Mutex::new(State {
                    receiving: true,
                    retired: false,
                    payload: None,
                    attached: Some(Arc::clone(&connection_stop)),
                    deadline,
                    detached_until: None,
                }),
            });
            let mut entries = lock(&self.entries);
            if self.stopped.load(Ordering::Acquire) || entries.len() >= self.maximum {
                return Err(refused());
            }
            if entries.contains_key(&request) {
                continue;
            }
            entries.insert(request, Arc::clone(&entry));
            return Ok(Reservation {
                registry: Arc::clone(self),
                entry,
                live: true,
            });
        }
        Err(io::Error::other(
            "could not allocate a fresh remote operation token",
        ))
    }

    pub(super) fn claim(
        self: &Arc<Self>,
        authority: &CoordinatorAuthority,
        peer: [u8; 32],
        token: &ResumableToken,
        connection_stop: Arc<AtomicBool>,
        now: Instant,
    ) -> io::Result<Claim<T>> {
        if self.stopped.load(Ordering::Acquire)
            || authority != &self.authority
            || token.issued_by_incarnation != self.authority.incarnation_id.0
            || connection_stop.load(Ordering::Acquire)
        {
            return Err(refused());
        }
        let entry = lock(&self.entries)
            .get(&token.request.0)
            .cloned()
            .ok_or_else(refused)?;
        if entry.peer != peer || entry.token != *token {
            return Err(refused());
        }
        let mut state = lock(&entry.state);
        if state.retired || entry.stopped.load(Ordering::Acquire) {
            drop(state);
            self.retire(&entry);
            return Err(refused());
        }
        if state.expired(now) {
            drop(state);
            self.retire_if_expired(&entry, Some(now));
            return Err(refused());
        }
        if state.receiving || state.attached.is_some() {
            return Ok(Claim::Pending);
        }
        let value = state.payload.take().ok_or_else(refused)?;
        state.attached = Some(connection_stop);
        state.detached_until = None;
        let deadline = state.deadline;
        drop(state);
        Ok(Claim::Attached(Attachment {
            registry: Arc::clone(self),
            entry,
            value: Some(value),
            deadline,
            live: true,
        }))
    }

    /// Cancellation does not need to wait for the old attachment to notice
    /// EOF. The same authenticated peer can retire its exact existing owner;
    /// this route has no input declaration, admission, or execution callback.
    pub(super) fn cancel(
        &self,
        authority: &CoordinatorAuthority,
        peer: [u8; 32],
        token: &ResumableToken,
    ) -> io::Result<()> {
        if authority != &self.authority
            || token.issued_by_incarnation != self.authority.incarnation_id.0
        {
            return Err(refused());
        }
        let entry = lock(&self.entries)
            .get(&token.request.0)
            .cloned()
            .ok_or_else(refused)?;
        if entry.peer != peer || entry.token != *token {
            return Err(refused());
        }
        self.retire(&entry);
        Ok(())
    }

    fn retire(&self, entry: &Arc<Entry<T>>) {
        self.retire_entry(entry, None, true);
    }

    fn retire_if_expired(&self, entry: &Arc<Entry<T>>, now: Option<Instant>) {
        self.retire_entry(entry, now, true);
    }

    fn retire_entry(
        &self,
        entry: &Arc<Entry<T>>,
        now: Option<Instant>,
        interrupt_connection: bool,
    ) {
        let payload = {
            let mut state = lock(&entry.state);
            // The deadline and detachment phase may have changed after a
            // reaper's snapshot. Test and retire under the same entry lock.
            if now.is_some_and(|now| !state.expired(now)) {
                return;
            }
            state.retired = true;
            entry.stopped.store(true, Ordering::Release);
            if let Some(connection) = state.attached.take()
                && interrupt_connection
            {
                connection.store(true, Ordering::Release);
            }
            state.payload.take()
        };
        {
            let mut entries = lock(&self.entries);
            if entries
                .get(&entry.token.request.0)
                .is_some_and(|current| Arc::ptr_eq(current, entry))
            {
                entries.remove(&entry.token.request.0);
            }
        }
        // The payload may cancel and join execution threads, or release an
        // admission permit. It must never do so under either registry lock.
        drop(payload);
    }

    pub(super) fn reap(&self, now: Instant) {
        let entries = lock(&self.entries).values().cloned().collect::<Vec<_>>();
        for entry in entries {
            self.retire_if_expired(&entry, Some(now));
        }
    }

    pub(super) fn shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
        let entries = lock(&self.entries).values().cloned().collect::<Vec<_>>();
        // Signal every writer before any detached owner's destructor joins.
        for entry in &entries {
            entry.stopped.store(true, Ordering::Release);
            if let Some(connection) = &lock(&entry.state).attached {
                connection.store(true, Ordering::Release);
            }
        }
        for entry in entries {
            self.retire(&entry);
        }
    }
}

impl<T> Reservation<T> {
    pub(super) fn token(&self) -> &ResumableToken {
        &self.entry.token
    }

    pub(super) fn operation_stop(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.entry.stopped)
    }

    pub(super) fn activate(
        mut self,
        value: T,
        deadline: Instant,
        now: Instant,
    ) -> io::Result<Attachment<T>> {
        let mut state = lock(&self.entry.state);
        if self.registry.stopped.load(Ordering::Acquire)
            || self.entry.stopped.load(Ordering::Acquire)
            || state.retired
            || !state.receiving
            || state.expired(now)
            || now >= deadline
            || state
                .attached
                .as_ref()
                .is_none_or(|connection| connection.load(Ordering::Acquire))
        {
            return Err(refused());
        }
        state.receiving = false;
        // Only activation changes the input phase into an execution phase.
        // Every later transition can only shorten this fixed lifetime.
        state.deadline = deadline;
        drop(state);
        self.live = false;
        Ok(Attachment {
            registry: Arc::clone(&self.registry),
            entry: Arc::clone(&self.entry),
            value: Some(value),
            deadline,
            live: true,
        })
    }
}

impl<T> Drop for Reservation<T> {
    fn drop(&mut self) {
        if self.live {
            // This connection is already leaving its operation handler. Keep
            // its wire usable for the original terminal Failure response.
            self.registry.retire_entry(&self.entry, None, false);
        }
    }
}

impl<T> Attachment<T> {
    pub(super) fn operation_stop(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.entry.stopped)
    }

    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) fn shorten_deadline(&mut self, deadline: Instant) {
        self.deadline = self.deadline.min(deadline);
        let mut state = lock(&self.entry.state);
        state.deadline = state.deadline.min(self.deadline);
    }

    /// Only a known transport failure may relinquish live custody. All other
    /// exits, including unwinding and protocol/local publication errors, abort.
    pub(super) fn detach(mut self, now: Instant) -> io::Result<()> {
        let mut state = lock(&self.entry.state);
        if self.registry.stopped.load(Ordering::Acquire)
            || self.entry.stopped.load(Ordering::Acquire)
            || state.retired
            || state.receiving
            || state.expired(now)
            || state.payload.is_some()
        {
            return Err(refused());
        }
        state.payload = self.value.take();
        state.attached = None;
        state.detached_until = Some((now + self.registry.grace).min(state.deadline));
        self.live = false;
        Ok(())
    }
}

impl<T> Deref for Attachment<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.value
            .as_ref()
            .expect("live attachment owns its payload")
    }
}

impl<T> DerefMut for Attachment<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value
            .as_mut()
            .expect("live attachment owns its payload")
    }
}

impl<T> Drop for Attachment<T> {
    fn drop(&mut self) {
        if self.live {
            self.registry.retire_entry(&self.entry, None, false);
        }
        // Owned payload drops after retirement has signaled cancellation and
        // released the locks. Its writer owner performs the actual join.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::authority::{ClusterId, CoordinatorIncarnationId};
    use std::sync::atomic::AtomicUsize;

    fn authority() -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId("operation-registry-test".into()),
            credential_generation: 2,
            term: 7,
            incarnation_id: CoordinatorIncarnationId(19),
        }
    }

    fn connection() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn diagnostics_resume_only_at_a_complete_exposed_record_boundary() {
        let mut frontier = DiagnosticFrontier::default();
        frontier.reattach((0, 0)).unwrap();
        assert_eq!(frontier.acknowledge_poll(), (0, 0));
        frontier.offer(10, 20).unwrap();
        for invalid in [(1, 0), (10, 0), (0, 20), (11, 20), (10, 21)] {
            assert!(frontier.reattach(invalid).is_err());
        }
        // Lost before exposure: replay the complete record once.
        frontier.reattach((0, 0)).unwrap();
        frontier.offer(10, 20).unwrap();
        // Lost after exposure: continue after the existing record.
        frontier.reattach((10, 20)).unwrap();
        assert_eq!(frontier.acknowledge_poll(), (10, 20));
        frontier.offer(30, 25).unwrap();
        assert_eq!(frontier.acknowledge_poll(), (30, 25));
        assert!(frontier.reattach((10, 20)).is_err());
        assert!(frontier.offer(29, 25).is_err());
        frontier.reattach((30, 25)).unwrap();
    }

    struct Payload {
        value: usize,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for Payload {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fixture() -> (Arc<Registry<Payload>>, Arc<AtomicUsize>, Instant) {
        (
            Registry::new(authority(), 1, Duration::from_secs(60)).unwrap(),
            Arc::new(AtomicUsize::new(0)),
            Instant::now(),
        )
    }

    fn activate(
        registry: &Arc<Registry<Payload>>,
        drops: &Arc<AtomicUsize>,
        now: Instant,
    ) -> (ResumableToken, Attachment<Payload>) {
        let reservation = registry
            .reserve([1; 32], connection(), now + Duration::from_secs(5), now)
            .unwrap();
        let token = reservation.token().clone();
        let attachment = reservation
            .activate(
                Payload {
                    value: 42,
                    drops: Arc::clone(drops),
                },
                now + Duration::from_secs(120),
                now,
            )
            .unwrap();
        (token, attachment)
    }

    #[test]
    fn pending_input_cannot_create_execution_and_failed_reservation_disappears() {
        let (registry, _, now) = fixture();
        let reservation = registry
            .reserve([1; 32], connection(), now + Duration::from_secs(5), now)
            .unwrap();
        let token = reservation.token().clone();
        assert!(matches!(
            registry
                .claim(&authority(), [1; 32], &token, connection(), now)
                .unwrap(),
            Claim::Pending
        ));
        drop(reservation);
        assert!(
            registry
                .claim(&authority(), [1; 32], &token, connection(), now)
                .is_err()
        );
    }

    #[test]
    fn ordinary_owner_failure_preserves_the_wire_for_a_terminal_refusal() {
        let (registry, drops, now) = fixture();
        let session = connection();
        let reservation = registry
            .reserve(
                [1; 32],
                Arc::clone(&session),
                now + Duration::from_secs(5),
                now,
            )
            .unwrap();
        let stopped = reservation.operation_stop();
        let attached = reservation
            .activate(
                Payload {
                    value: 1,
                    drops: Arc::clone(&drops),
                },
                now + Duration::from_secs(10),
                now,
            )
            .unwrap();
        drop(attached);
        assert!(stopped.load(Ordering::Acquire));
        assert!(!session.load(Ordering::Acquire));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn detach_and_claim_preserve_the_single_payload_and_exclude_second_attachment() {
        let (registry, drops, now) = fixture();
        let (token, mut attached) = activate(&registry, &drops, now);
        let operation_stop = attached.operation_stop();
        attached.deref_mut().value = 77;
        assert!(matches!(
            registry
                .claim(&authority(), [1; 32], &token, connection(), now)
                .unwrap(),
            Claim::Pending
        ));
        attached.detach(now).unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!operation_stop.load(Ordering::Acquire));
        let Claim::Attached(attached) = registry
            .claim(&authority(), [1; 32], &token, connection(), now)
            .unwrap()
        else {
            panic!("detached operation must attach");
        };
        assert_eq!(attached.deref().value, 77);
        drop(attached);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(operation_stop.load(Ordering::Acquire));
    }

    #[test]
    fn peer_secret_subscriber_and_complete_authority_are_bound() {
        let (registry, drops, now) = fixture();
        let (token, attached) = activate(&registry, &drops, now);
        attached.detach(now).unwrap();
        assert!(
            registry
                .claim(&authority(), [2; 32], &token, connection(), now)
                .is_err()
        );
        let mut wrong = token.clone();
        wrong.secret[0] ^= 1;
        assert!(
            registry
                .claim(&authority(), [1; 32], &wrong, connection(), now)
                .is_err()
        );
        wrong = token.clone();
        wrong.subscriber = SubscriberId(2);
        assert!(
            registry
                .claim(&authority(), [1; 32], &wrong, connection(), now)
                .is_err()
        );
        for changed in [
            CoordinatorAuthority {
                term: 8,
                ..authority()
            },
            CoordinatorAuthority {
                credential_generation: 3,
                ..authority()
            },
            CoordinatorAuthority {
                incarnation_id: CoordinatorIncarnationId(20),
                ..authority()
            },
            CoordinatorAuthority {
                cluster_id: ClusterId("another".into()),
                ..authority()
            },
        ] {
            assert!(
                registry
                    .claim(&changed, [1; 32], &token, connection(), now)
                    .is_err()
            );
        }
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(matches!(
            registry
                .claim(&authority(), [1; 32], &token, connection(), now)
                .unwrap(),
            Claim::Attached(_)
        ));
    }

    #[test]
    fn detached_custody_holds_capacity_until_expiry_then_drains_once() {
        let (registry, drops, now) = fixture();
        let (token, attached) = activate(&registry, &drops, now);
        let stopped = attached.operation_stop();
        attached.detach(now).unwrap();
        assert!(
            registry
                .reserve([1; 32], connection(), now + Duration::from_secs(5), now)
                .is_err()
        );
        registry.reap(now + Duration::from_secs(59));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        registry.reap(now + Duration::from_secs(60));
        registry.reap(now + Duration::from_secs(61));
        assert!(stopped.load(Ordering::Acquire));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            registry
                .claim(&authority(), [1; 32], &token, connection(), now)
                .is_err()
        );
        assert!(
            registry
                .reserve([1; 32], connection(), now + Duration::from_secs(5), now)
                .is_ok()
        );
    }

    #[test]
    fn reconnect_cannot_extend_the_original_or_shortened_deadline() {
        let (registry, drops, now) = fixture();
        let (token, mut attached) = activate(&registry, &drops, now);
        attached.shorten_deadline(now + Duration::from_secs(20));
        attached.shorten_deadline(now + Duration::from_secs(200));
        assert_eq!(attached.deadline(), now + Duration::from_secs(20));
        attached.detach(now + Duration::from_secs(10)).unwrap();
        let Claim::Attached(attached) = registry
            .claim(
                &authority(),
                [1; 32],
                &token,
                connection(),
                now + Duration::from_secs(19),
            )
            .unwrap()
        else {
            panic!("unexpired operation must attach");
        };
        attached.detach(now + Duration::from_secs(19)).unwrap();
        registry.reap(now + Duration::from_secs(20));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn attached_expiry_signals_both_owners_before_payload_drop() {
        let (registry, drops, now) = fixture();
        let session = connection();
        let reservation = registry
            .reserve(
                [1; 32],
                Arc::clone(&session),
                now + Duration::from_secs(5),
                now,
            )
            .unwrap();
        let stopped = reservation.operation_stop();
        let attached = reservation
            .activate(
                Payload {
                    value: 1,
                    drops: Arc::clone(&drops),
                },
                now + Duration::from_secs(10),
                now,
            )
            .unwrap();
        registry.reap(now + Duration::from_secs(10));
        assert!(session.load(Ordering::Acquire));
        assert!(stopped.load(Ordering::Acquire));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(attached);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn shutdown_refuses_new_work_and_drains_retained_execution() {
        let (registry, drops, now) = fixture();
        let (token, attached) = activate(&registry, &drops, now);
        attached.detach(now).unwrap();
        registry.shutdown();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            registry
                .claim(&authority(), [1; 32], &token, connection(), now)
                .is_err()
        );
        assert!(
            registry
                .reserve([1; 32], connection(), now + Duration::from_secs(5), now)
                .is_err()
        );
    }

    #[test]
    fn authenticated_cancellation_interrupts_attached_and_detached_owners() {
        for detached in [false, true] {
            let (registry, drops, now) = fixture();
            let (token, attached) = activate(&registry, &drops, now);
            let stopped = attached.operation_stop();
            let session = lock(&attached.entry.state).attached.clone().unwrap();
            let attached = if detached {
                attached.detach(now).unwrap();
                None
            } else {
                Some(attached)
            };
            assert!(registry.cancel(&authority(), [2; 32], &token).is_err());
            let mut wrong = token.clone();
            wrong.secret[0] ^= 1;
            assert!(registry.cancel(&authority(), [1; 32], &wrong).is_err());
            let changed = CoordinatorAuthority {
                term: 8,
                ..authority()
            };
            assert!(registry.cancel(&changed, [1; 32], &token).is_err());
            assert!(!stopped.load(Ordering::Acquire));
            registry.cancel(&authority(), [1; 32], &token).unwrap();
            assert!(stopped.load(Ordering::Acquire));
            if !detached {
                assert!(session.load(Ordering::Acquire));
            }
            drop(attached);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(
                registry
                    .claim(&authority(), [1; 32], &token, connection(), now)
                    .is_err()
            );
        }
    }

    #[test]
    fn payload_destructors_run_without_registry_locks() {
        struct Reenter {
            registry: std::sync::Weak<Registry<Reenter>>,
            dropped: Arc<AtomicBool>,
        }
        impl Drop for Reenter {
            fn drop(&mut self) {
                if let Some(registry) = self.registry.upgrade() {
                    // These must be available even while expiry/shutdown is
                    // draining the detached payload, before any writer joins.
                    assert!(registry.entries.try_lock().is_ok());
                    registry.reap(Instant::now());
                }
                self.dropped.store(true, Ordering::Release);
            }
        }
        let now = Instant::now();
        let registry = Registry::new(authority(), 1, Duration::from_secs(1)).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let reservation = registry
            .reserve([1; 32], connection(), now + Duration::from_secs(5), now)
            .unwrap();
        reservation
            .activate(
                Reenter {
                    registry: Arc::downgrade(&registry),
                    dropped: Arc::clone(&dropped),
                },
                now + Duration::from_secs(5),
                now,
            )
            .unwrap()
            .detach(now)
            .unwrap();
        registry.shutdown();
        assert!(dropped.load(Ordering::Acquire));
    }
}
