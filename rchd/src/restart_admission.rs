//! Fenced, expiring ownership of the daemon's maintenance admission barrier.
//!
//! A deadline may reopen admission only while shutdown has not been committed.
//! Every later mutation checks the same incarnation, token and kernel process
//! identity under the admission lock, so an expired operator cannot resume and
//! shut down a daemon that has admitted unrelated work.

use rch_common::process_identity::{
    OwnerPresence, ProcessIdentity, ProcessObservation, observe_process, owner_presence,
};
use rch_common::{MaintenanceOwner, MaintenanceRecovery, RestartAdmissionResponse};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tracing::info;
use uuid::Uuid;

const MAINTENANCE_TTL_MS: u64 = 30_000;
pub(crate) const MAINTENANCE_TTL: Duration = Duration::from_millis(MAINTENANCE_TTL_MS);

#[derive(Clone, Debug)]
pub(crate) struct MaintenanceFence {
    pub daemon_incarnation: String,
    pub token: String,
}

/// Captured from the accepted Unix socket, never from client-supplied JSON.
#[derive(Clone, Debug)]
pub(crate) struct MaintenancePeer {
    pub pid: u32,
    pub identity: ProcessIdentity,
}

impl MaintenancePeer {
    pub(crate) fn capture(pid: Option<i32>) -> Option<Self> {
        let pid = u32::try_from(pid?).ok().filter(|pid| *pid > 1)?;
        match observe_process(pid) {
            ProcessObservation::Present(identity) if identity.is_valid() => {
                Some(Self { pid, identity })
            }
            _ => None,
        }
    }

    fn matches(&self, owner: &MaintenanceOwner) -> bool {
        self.pid == owner.pid && self.identity == owner.process_identity
    }

    /// The caller captures this witness before connecting. Requiring the same
    /// birth closes PID reuse while a connection waits in the accept backlog.
    pub(crate) fn validate_acquisition_identity(
        &self,
        expected: &ProcessIdentity,
    ) -> Result<(), &'static str> {
        if !expected.is_valid() {
            return Err("maintenance_owner_identity_unknown");
        }
        if &self.identity != expected {
            return Err("maintenance_owner_identity_mismatch");
        }
        Ok(())
    }

    /// Re-observe the same connection owner's durable birth. Capturing a new
    /// identity from its numeric PID after an await could authorize a recycled
    /// PID on an old socket instead of the process that opened the connection.
    pub(crate) fn revalidate(&self) -> Option<&Self> {
        self.revalidate_with(&observe_process(self.pid))
    }

    fn revalidate_with(&self, observation: &ProcessObservation) -> Option<&Self> {
        (self.identity.presence(observation) == OwnerPresence::Live).then_some(self)
    }
}

struct MaintenanceLease {
    owner: MaintenanceOwner,
    deadline: Instant,
}

enum MaintenanceTransition {
    Acquired,
    Released,
    Recovered(&'static str),
}

/// Logging may block on an output sink. Keep lifecycle events separate from
/// the protected state so callers always release the admission lock first.
pub(crate) struct MaintenanceEvent {
    incarnation: String,
    owner: MaintenanceOwner,
    transition: MaintenanceTransition,
}

impl MaintenanceEvent {
    pub(crate) fn emit(self) {
        let Self {
            incarnation,
            owner,
            transition,
        } = self;
        match transition {
            MaintenanceTransition::Acquired => info!(
                daemon_incarnation = %incarnation,
                token = %owner.token,
                owner_pid = owner.pid,
                generation = owner.generation,
                "Acquired maintenance admission ownership"
            ),
            MaintenanceTransition::Released => info!(
                daemon_incarnation = %incarnation,
                token = %owner.token,
                owner_pid = owner.pid,
                generation = owner.generation,
                "Released maintenance admission ownership"
            ),
            MaintenanceTransition::Recovered(reason) => info!(
                daemon_incarnation = %incarnation,
                token = %owner.token,
                owner_pid = owner.pid,
                generation = owner.generation,
                reason,
                "Recovered abandoned maintenance admission ownership"
            ),
        }
    }
}

pub(crate) struct RestartAdmissionState {
    incarnation: String,
    generation: u64,
    used_tokens: HashSet<String>,
    lease: Option<MaintenanceLease>,
    retired_owner: Option<MaintenanceOwner>,
    shutdown_committed: bool,
    last_recovery: Option<MaintenanceRecovery>,
    pending_events: Vec<MaintenanceEvent>,
}

impl Default for RestartAdmissionState {
    fn default() -> Self {
        Self {
            incarnation: Uuid::new_v4().to_string(),
            generation: 0,
            used_tokens: HashSet::new(),
            lease: None,
            retired_owner: None,
            shutdown_committed: false,
            last_recovery: None,
            pending_events: Vec::new(),
        }
    }
}

impl RestartAdmissionState {
    pub(crate) fn take_events(&mut self) -> Vec<MaintenanceEvent> {
        std::mem::take(&mut self.pending_events)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.lease.is_some() || self.shutdown_committed
    }

    pub(crate) fn recover(&mut self, now: Instant, wall_ms: u64) -> bool {
        self.recover_with(now, wall_ms, |owner| {
            owner_presence(owner.pid, Some(&owner.process_identity))
        })
    }

    fn recover_with(
        &mut self,
        now: Instant,
        wall_ms: u64,
        presence: impl FnOnce(&MaintenanceOwner) -> OwnerPresence,
    ) -> bool {
        if self.shutdown_committed {
            return false;
        }
        let Some(lease) = &self.lease else {
            return false;
        };
        let reason = if now >= lease.deadline {
            "deadline_expired"
        } else if presence(&lease.owner) == OwnerPresence::Absent {
            "owner_absent"
        } else {
            return false;
        };
        let lease = self.lease.take().expect("checked maintenance lease");
        self.pending_events.push(MaintenanceEvent {
            incarnation: self.incarnation.clone(),
            owner: lease.owner.clone(),
            transition: MaintenanceTransition::Recovered(reason),
        });
        self.last_recovery = Some(MaintenanceRecovery {
            token: lease.owner.token.clone(),
            pid: lease.owner.pid,
            reason: reason.into(),
            recovered_unix_ms: wall_ms,
        });
        self.retired_owner = Some(lease.owner);
        true
    }

    fn validate_incarnation(&self, fence: &MaintenanceFence) -> Result<(), &'static str> {
        if fence.daemon_incarnation != self.incarnation {
            return Err("daemon_incarnation_changed");
        }
        if self.shutdown_committed {
            return Err("shutdown_committed");
        }
        Ok(())
    }

    pub(crate) fn validate_owner(
        &self,
        fence: &MaintenanceFence,
        peer: Option<&MaintenancePeer>,
    ) -> Result<(), &'static str> {
        self.validate_incarnation(fence)?;
        let peer = peer.ok_or("maintenance_peer_identity_unknown")?;
        let lease = self.lease.as_ref().ok_or("maintenance_ownership_lost")?;
        if Instant::now() >= lease.deadline {
            return Err("maintenance_ownership_lost");
        }
        let owner = &lease.owner;
        if owner.token != fence.token || !peer.matches(owner) {
            return Err("maintenance_owner_mismatch");
        }
        Ok(())
    }

    pub(crate) fn acquire(
        &mut self,
        fence: &MaintenanceFence,
        peer: Option<&MaintenancePeer>,
        purpose: String,
        now: Instant,
        wall_ms: u64,
    ) -> Result<(), &'static str> {
        self.validate_incarnation(fence)?;
        let peer = peer.ok_or("maintenance_peer_identity_unknown")?;
        if let Some(lease) = &self.lease {
            if lease.owner.token != fence.token || !peer.matches(&lease.owner) {
                return Err("maintenance_already_owned");
            }
            // An acquisition retry is idempotent and also proves the same
            // operation is still active. It cannot replace another owner.
            return self.renew(fence, Some(peer), now, wall_ms);
        }
        if self.used_tokens.contains(&fence.token) {
            return Err("maintenance_token_retired");
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or("maintenance_generation_exhausted")?;
        self.used_tokens.insert(fence.token.clone());
        self.lease = Some(MaintenanceLease {
            owner: MaintenanceOwner {
                token: fence.token.clone(),
                pid: peer.pid,
                process_identity: peer.identity.clone(),
                purpose,
                generation: self.generation,
                acquired_unix_ms: wall_ms,
                deadline_unix_ms: wall_ms.saturating_add(MAINTENANCE_TTL_MS),
                remaining_ms: MAINTENANCE_TTL_MS,
                owner_presence: "live".into(),
            },
            deadline: now + MAINTENANCE_TTL,
        });
        self.pending_events.push(MaintenanceEvent {
            incarnation: self.incarnation.clone(),
            owner: self
                .lease
                .as_ref()
                .expect("acquired maintenance lease")
                .owner
                .clone(),
            transition: MaintenanceTransition::Acquired,
        });
        Ok(())
    }

    pub(crate) fn renew(
        &mut self,
        fence: &MaintenanceFence,
        peer: Option<&MaintenancePeer>,
        now: Instant,
        wall_ms: u64,
    ) -> Result<(), &'static str> {
        self.validate_owner(fence, peer)?;
        let lease = self.lease.as_mut().expect("validated maintenance owner");
        if now >= lease.deadline {
            return Err("maintenance_ownership_lost");
        }
        lease.deadline = now + MAINTENANCE_TTL;
        lease.owner.deadline_unix_ms = wall_ms.saturating_add(MAINTENANCE_TTL_MS);
        Ok(())
    }

    pub(crate) fn release(
        &mut self,
        fence: &MaintenanceFence,
        peer: Option<&MaintenancePeer>,
    ) -> Result<(), &'static str> {
        self.validate_incarnation(fence)?;
        let peer = peer.ok_or("maintenance_peer_identity_unknown")?;
        if self.lease.is_none()
            && self
                .retired_owner
                .as_ref()
                .is_some_and(|owner| owner.token == fence.token && peer.matches(owner))
        {
            return Ok(());
        }
        self.validate_owner(fence, Some(peer))?;
        let lease = self.lease.take().expect("validated maintenance owner");
        self.pending_events.push(MaintenanceEvent {
            incarnation: self.incarnation.clone(),
            owner: lease.owner.clone(),
            transition: MaintenanceTransition::Released,
        });
        self.retired_owner = Some(lease.owner);
        Ok(())
    }

    pub(crate) fn validate_recovery(&self, fence: &MaintenanceFence) -> Result<(), &'static str> {
        self.validate_incarnation(fence)?;
        let token = self
            .lease
            .as_ref()
            .map(|lease| &lease.owner.token)
            .or_else(|| self.retired_owner.as_ref().map(|owner| &owner.token));
        if token != Some(&fence.token) {
            return Err("maintenance_owner_mismatch");
        }
        if self.lease.is_some() {
            return Err("maintenance_owner_still_active");
        }
        Ok(())
    }

    pub(crate) fn commit_shutdown(
        &mut self,
        fence: &MaintenanceFence,
        peer: Option<&MaintenancePeer>,
    ) -> Result<(), &'static str> {
        self.validate_owner(fence, peer)?;
        // There must be no logging or other blocking work between this state
        // transition and the caller's shutdown notification/watchdog.
        self.shutdown_committed = true;
        Ok(())
    }

    /// Only the API holding the write lock may roll back a failed channel send.
    pub(crate) fn rollback_shutdown_send_failure(&mut self) {
        self.shutdown_committed = false;
    }

    pub(crate) fn begin_shutdown(&mut self) {
        self.shutdown_committed = true;
    }

    pub(crate) fn snapshot(
        &self,
        now: Instant,
        ownership_error: Option<String>,
    ) -> RestartAdmissionResponse {
        let owner = self.lease.as_ref().map(|lease| {
            let mut owner = lease.owner.clone();
            owner.remaining_ms =
                u64::try_from(lease.deadline.saturating_duration_since(now).as_millis())
                    .unwrap_or(u64::MAX);
            owner.owner_presence = match owner_presence(owner.pid, Some(&owner.process_identity)) {
                OwnerPresence::Live => "live",
                OwnerPresence::Absent => "absent",
                OwnerPresence::Unknown => "unknown",
            }
            .into();
            owner
        });
        let ownership_failed = ownership_error.is_some();
        RestartAdmissionResponse {
            success: true,
            status: if self.shutdown_committed {
                "shutting_down"
            } else if self.lease.is_some() {
                "owned"
            } else if ownership_failed {
                "ownership_failed"
            } else {
                "open"
            }
            .into(),
            message: None,
            daemon_incarnation: self.incarnation.clone(),
            admission_closed: self.is_closed() || ownership_failed,
            maintenance_closed: self.lease.is_some(),
            ownership_failed,
            ownership_error,
            shutdown_committed: self.shutdown_committed,
            maintenance_owner: owner,
            last_recovery: self.last_recovery.clone(),
            ..RestartAdmissionResponse::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::process_identity::ProcessStart;

    fn peer() -> MaintenancePeer {
        MaintenancePeer {
            pid: 4242,
            identity: ProcessIdentity {
                boot_id: "6a5a0649-d23a-4d74-b542-85f5e69de721".into(),
                start: ProcessStart::Linux { ticks: 1234 },
            },
        }
    }

    fn fence(state: &RestartAdmissionState) -> MaintenanceFence {
        MaintenanceFence {
            daemon_incarnation: state.incarnation.clone(),
            token: Uuid::new_v4().to_string(),
        }
    }

    #[test]
    fn maintenance_connection_birth_must_still_match_at_mutation() {
        let peer = peer();
        assert!(
            peer.revalidate_with(&ProcessObservation::Present(peer.identity.clone()))
                .is_some()
        );
        for observation in [
            ProcessObservation::Absent,
            ProcessObservation::Unknown,
            ProcessObservation::Present(ProcessIdentity {
                start: ProcessStart::Linux { ticks: 1235 },
                ..peer.identity.clone()
            }),
            ProcessObservation::Present(ProcessIdentity {
                boot_id: "0e9306b2-57d4-42c2-85b7-ec00aa52fe86".into(),
                ..peer.identity.clone()
            }),
        ] {
            assert!(peer.revalidate_with(&observation).is_none());
        }
    }

    #[test]
    fn maintenance_acquisition_requires_callers_original_birth_witness() {
        let peer = peer();
        assert!(peer.validate_acquisition_identity(&peer.identity).is_ok());
        for original in [
            ProcessIdentity {
                start: ProcessStart::Linux { ticks: 1233 },
                ..peer.identity.clone()
            },
            ProcessIdentity {
                boot_id: "0e9306b2-57d4-42c2-85b7-ec00aa52fe86".into(),
                ..peer.identity.clone()
            },
        ] {
            assert_eq!(
                peer.validate_acquisition_identity(&original),
                Err("maintenance_owner_identity_mismatch")
            );
        }
        let unknown = ProcessIdentity {
            boot_id: String::new(),
            ..peer.identity.clone()
        };
        assert_eq!(
            peer.validate_acquisition_identity(&unknown),
            Err("maintenance_owner_identity_unknown")
        );
    }

    #[test]
    fn maintenance_concurrent_operations_cannot_release_or_renew_each_other() {
        let mut state = RestartAdmissionState::default();
        let first = fence(&state);
        let second = fence(&state);
        let peer = peer();
        let now = Instant::now();
        state
            .acquire(&first, Some(&peer), "restart".into(), now, 100)
            .unwrap();
        assert_eq!(
            state.acquire(&second, Some(&peer), "stop".into(), now, 100),
            Err("maintenance_already_owned")
        );
        assert_eq!(
            state.release(&second, Some(&peer)),
            Err("maintenance_owner_mismatch")
        );
        assert_eq!(
            state.renew(&second, Some(&peer), now, 100),
            Err("maintenance_owner_mismatch")
        );
        assert!(state.is_closed());
        state.release(&first, Some(&peer)).unwrap();
        state
            .acquire(&second, Some(&peer), "stop".into(), now, 100)
            .unwrap();
        assert_eq!(
            state.release(&first, Some(&peer)),
            Err("maintenance_owner_mismatch")
        );
        assert!(state.is_closed());
        state.release(&second, Some(&peer)).unwrap();
        assert_eq!(
            state.acquire(&first, Some(&peer), "restart".into(), now, 100),
            Err("maintenance_token_retired")
        );
    }

    #[test]
    fn maintenance_pid_reuse_and_unknown_peer_cannot_mutate_ownership() {
        let mut state = RestartAdmissionState::default();
        let fence = fence(&state);
        let peer = peer();
        state
            .acquire(&fence, Some(&peer), "restart".into(), Instant::now(), 100)
            .unwrap();
        let mut replacement = peer.clone();
        replacement.identity.start = ProcessStart::Linux { ticks: 1235 };
        assert_eq!(
            state.release(&fence, Some(&replacement)),
            Err("maintenance_owner_mismatch")
        );
        assert_eq!(
            state.commit_shutdown(&fence, None),
            Err("maintenance_peer_identity_unknown")
        );
        assert!(state.is_closed());
    }

    #[test]
    fn maintenance_interruption_recovers_on_absence_or_monotonic_deadline() {
        for presence in [
            OwnerPresence::Live,
            OwnerPresence::Unknown,
            OwnerPresence::Absent,
        ] {
            let mut state = RestartAdmissionState::default();
            let fence = fence(&state);
            let peer = peer();
            let now = Instant::now();
            state
                .acquire(&fence, Some(&peer), "restart".into(), now, 100)
                .unwrap();
            let early = state.recover_with(now + Duration::from_secs(1), 10_000_000, |_| presence);
            assert_eq!(early, presence == OwnerPresence::Absent);
            if !early {
                // A backwards wall clock and uncertain/live ownership cannot
                // extend the fixed monotonic recovery bound.
                assert!(state.recover_with(now + MAINTENANCE_TTL, 0, |_| presence));
            }
            assert!(!state.is_closed());
            assert_eq!(
                state.commit_shutdown(&fence, Some(&peer)),
                Err("maintenance_ownership_lost")
            );
            assert_eq!(
                state.acquire(&fence, Some(&peer), "restart".into(), now, 100),
                Err("maintenance_token_retired")
            );
        }
    }

    #[test]
    fn maintenance_daemon_crash_fences_predecessor_requests() {
        let old = RestartAdmissionState::default();
        let old_fence = fence(&old);
        let mut fresh = RestartAdmissionState::default();
        assert!(!fresh.is_closed());
        assert_eq!(
            fresh.acquire(
                &old_fence,
                Some(&peer()),
                "restart".into(),
                Instant::now(),
                100
            ),
            Err("daemon_incarnation_changed")
        );
        assert_eq!(
            fresh.release(&old_fence, Some(&peer())),
            Err("daemon_incarnation_changed")
        );
    }

    #[test]
    fn maintenance_renewal_extends_only_an_unexpired_owner() {
        let mut state = RestartAdmissionState::default();
        let fence = fence(&state);
        let peer = peer();
        let now = Instant::now();
        state
            .acquire(&fence, Some(&peer), "restart".into(), now, 100)
            .unwrap();
        state
            .renew(&fence, Some(&peer), now + Duration::from_secs(20), 1)
            .unwrap();
        assert!(!state.recover_with(now + MAINTENANCE_TTL, u64::MAX, |_| OwnerPresence::Live));
        assert_eq!(
            state.renew(&fence, Some(&peer), now + Duration::from_secs(50), 2),
            Err("maintenance_ownership_lost")
        );
        assert!(state.recover_with(now + Duration::from_secs(50), 2, |_| OwnerPresence::Unknown));
        assert!(!state.is_closed());
    }

    #[test]
    fn maintenance_committed_shutdown_never_expires_or_reopens() {
        let mut state = RestartAdmissionState::default();
        let fence = fence(&state);
        let peer = peer();
        let now = Instant::now();
        state
            .acquire(&fence, Some(&peer), "restart".into(), now, 100)
            .unwrap();
        state.commit_shutdown(&fence, Some(&peer)).unwrap();
        assert!(
            !state.recover_with(now + MAINTENANCE_TTL * 2, 1_000_000, |_| {
                OwnerPresence::Absent
            })
        );
        assert_eq!(
            state.release(&fence, Some(&peer)),
            Err("shutdown_committed")
        );
        assert_eq!(
            state.renew(&fence, Some(&peer), now, 100),
            Err("shutdown_committed")
        );
        assert!(state.is_closed());
        state.rollback_shutdown_send_failure();
        state.release(&fence, Some(&peer)).unwrap();
        assert!(!state.is_closed());
    }

    #[test]
    fn maintenance_history_fault_is_distinct_after_successful_owner_release() {
        let mut state = RestartAdmissionState::default();
        let fence = fence(&state);
        let peer = peer();
        let now = Instant::now();
        state
            .acquire(&fence, Some(&peer), "restart".into(), now, 100)
            .unwrap();
        state.release(&fence, Some(&peer)).unwrap();
        let snapshot = state.snapshot(now, Some("durable ownership write failed".into()));
        assert!(snapshot.admission_closed && snapshot.ownership_failed);
        assert!(!snapshot.maintenance_closed);
        assert_eq!(snapshot.status, "ownership_failed");
    }
}
