//! Optional liveness exchange before a worker receives an operation.
//!
//! Standby authenticates no session and grants no execution or result access.
//! The ordinary session challenge still owns those transitions after work is
//! assigned. Sequence numbers fence delayed, duplicated, or reordered heartbeats
//! within this one connection; they never identify an execution.

use std::fmt;
use std::time::Duration;

/// Explicit capability advertised by workers that can wait for assignment.
pub const VERSION: &str = "worker-standby-v1";
/// Coordinator heartbeat cadence while no operation is assigned.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// One heartbeat must complete within this budget, including its write.
pub const PONG_TIMEOUT: Duration = Duration::from_secs(10);
/// Worker deadline for each complete coordinator record during standby.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// A frame violates the negotiated standby exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandbyError {
    /// Only this exact protocol version may govern the connection.
    Version,
    /// Ready may occur once, before any challenge or heartbeat.
    Ready,
    /// Heartbeats require a preceding ready and no session challenge.
    Ping,
    /// Heartbeats must start at one and increase by exactly one.
    Sequence,
    /// A connection can enter session admission only once.
    Challenge,
}

impl fmt::Display for StandbyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Version => "unsupported worker standby version",
            Self::Ready => "duplicate or misplaced worker standby ready",
            Self::Ping => "worker standby ping outside standby",
            Self::Sequence => "worker standby sequence is not consecutive",
            Self::Challenge => "duplicate worker session challenge",
        })
    }
}

impl std::error::Error for StandbyError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    AwaitingCoordinator,
    Standby {
        sequence: u64,
    },
    Challenged,
}

/// Worker-side state, independent of transport, JSON, clocks and admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkerStandby {
    phase: Phase,
}

impl WorkerStandby {
    /// Begin immediately after sending the ordinary worker hello.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Select standby once. A direct session challenge needs no ready frame.
    pub fn accept_ready(&mut self, version: &str) -> Result<(), StandbyError> {
        if version != VERSION {
            return Err(StandbyError::Version);
        }
        if self.phase != Phase::AwaitingCoordinator {
            return Err(StandbyError::Ready);
        }
        self.phase = Phase::Standby { sequence: 0 };
        Ok(())
    }

    /// Validate the next ping and return the exact sequence to echo in its pong.
    pub fn accept_ping(&mut self, version: &str, sequence: u64) -> Result<u64, StandbyError> {
        if version != VERSION {
            return Err(StandbyError::Version);
        }
        let Phase::Standby { sequence: previous } = self.phase else {
            return Err(StandbyError::Ping);
        };
        if previous.checked_add(1) != Some(sequence) {
            return Err(StandbyError::Sequence);
        }
        self.phase = Phase::Standby { sequence };
        Ok(sequence)
    }

    /// Leave standby, or start direct admission with an older coordinator.
    /// The caller validates the actual challenge under ordinary session policy.
    pub fn accept_challenge(&mut self) -> Result<(), StandbyError> {
        if self.phase == Phase::Challenged {
            return Err(StandbyError::Challenge);
        }
        self.phase = Phase::Challenged;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_and_parked_connections_enter_admission_once() {
        let mut direct = WorkerStandby::new();
        direct.accept_challenge().unwrap();
        assert_eq!(direct.accept_challenge(), Err(StandbyError::Challenge));
        assert_eq!(direct.accept_ready(VERSION), Err(StandbyError::Ready));
        assert_eq!(direct.accept_ping(VERSION, 1), Err(StandbyError::Ping));

        let mut parked = WorkerStandby::new();
        parked.accept_ready(VERSION).unwrap();
        assert_eq!(parked.accept_ping(VERSION, 1), Ok(1));
        assert_eq!(parked.accept_ping(VERSION, 2), Ok(2));
        parked.accept_challenge().unwrap();
        assert_eq!(parked.accept_ping(VERSION, 3), Err(StandbyError::Ping));
        assert_eq!(parked.accept_ready(VERSION), Err(StandbyError::Ready));
    }

    #[test]
    fn ready_and_ping_require_the_selected_protocol_and_phase() {
        let mut standby = WorkerStandby::new();
        assert_eq!(standby.accept_ping(VERSION, 1), Err(StandbyError::Ping));
        assert_eq!(standby.accept_ready("v0"), Err(StandbyError::Version));
        standby.accept_ready(VERSION).unwrap();
        assert_eq!(standby.accept_ready(VERSION), Err(StandbyError::Ready));
        assert_eq!(standby.accept_ping("v0", 1), Err(StandbyError::Version));
        assert_eq!(standby.accept_ping(VERSION, 1), Ok(1));
    }

    #[test]
    fn sequences_refuse_zero_replay_gaps_and_overflow_without_advancing() {
        let mut standby = WorkerStandby::new();
        standby.accept_ready(VERSION).unwrap();
        for sequence in [0, 2, u64::MAX] {
            assert_eq!(
                standby.accept_ping(VERSION, sequence),
                Err(StandbyError::Sequence)
            );
        }
        assert_eq!(standby.accept_ping(VERSION, 1), Ok(1));
        assert_eq!(standby.accept_ping(VERSION, 1), Err(StandbyError::Sequence));
        assert_eq!(standby.accept_ping(VERSION, 3), Err(StandbyError::Sequence));
        assert_eq!(standby.accept_ping(VERSION, 2), Ok(2));

        standby.phase = Phase::Standby { sequence: u64::MAX };
        assert_eq!(standby.accept_ping(VERSION, 0), Err(StandbyError::Sequence));
        assert_eq!(
            standby.accept_ping(VERSION, u64::MAX),
            Err(StandbyError::Sequence)
        );
    }
}
