//! Coordinator liveness for one authenticated execution, below the public peer.
//! The original request remains unchanged. A renewal is never retried, and only
//! one may be awaiting acknowledgment. Local expiry permanently stops renewals;
//! the worker independently fences its process using its own monotonic clock.

use super::{hex, invalid, require};
use rabs_protocol::lease_semantics::{
    DEFAULT_TTL_MS, MAX_TTL_MS, MIN_TTL_MS, REQUEST_EXECUTION_LEASE_VERSION,
    RequestExecutionLeaseIdentity,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io;
use std::time::{Duration, Instant};

pub(super) fn grant(hello: &Value, request: &Value, session: u64, lease: u64) -> io::Result<Value> {
    require(
        hello["execution_leases"]
            .as_array()
            .is_some_and(|versions| {
                versions
                    .iter()
                    .any(|version| version == REQUEST_EXECUTION_LEASE_VERSION)
            }),
        "authenticated execution requires renewable worker execution leases",
    )?;
    let value = json!({
        "version":REQUEST_EXECUTION_LEASE_VERSION, "session_id":session, "lease_id":lease,
        "request_id":request["request_id"],
        "request_sha256":hex(&Sha256::digest(serde_json::to_vec(request)?)),
        "boot_generation":hello["boot_generation"], "incarnation":hello["incarnation"],
        "ttl_ms":DEFAULT_TTL_MS,
    });
    ExecutionLease::parse(&value)?;
    Ok(value)
}

struct Active {
    expires: Instant,
    renew_at: Instant,
}

/// An ACK deadline is measured from the send instant, never its arrival. This
/// cannot mistake a delayed acknowledgment for extra worker execution time.
pub(super) struct ExecutionLease {
    identity: RequestExecutionLeaseIdentity,
    ttl: Duration,
    cadence: Duration,
    active: Option<Active>,
    pending: Option<(u64, Instant)>,
    sequence: u64,
    stopped: bool,
}

pub(super) enum Tick {
    Idle,
    Renew(Value),
    Expired,
}

impl ExecutionLease {
    pub(super) fn parse(value: &Value) -> io::Result<Self> {
        require(
            value.as_object().is_some_and(|fields| fields.len() == 8)
                && value["version"] == REQUEST_EXECUTION_LEASE_VERSION,
            "invalid execution lease grant",
        )?;
        let number = |name: &str| {
            value[name]
                .as_u64()
                .filter(|number| *number != 0)
                .ok_or_else(|| invalid(format!("invalid execution lease {name}")))
        };
        let encoded = |name: &str, length: usize| {
            value[name]
                .as_str()
                .filter(|text| {
                    text.len() == length
                        && text
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| invalid(format!("invalid execution lease {name}")))
        };
        let digest = encoded("request_sha256", 64)?;
        let mut request_sha256 = [0; 32];
        for (byte, pair) in request_sha256
            .iter_mut()
            .zip(digest.as_bytes().as_chunks::<2>().0)
        {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            *byte = digit(pair[0]) * 16 + digit(pair[1]);
        }
        let identity = RequestExecutionLeaseIdentity {
            session_id: number("session_id")?,
            lease_id: number("lease_id")?,
            request_id: value["request_id"]
                .as_u64()
                .ok_or_else(|| invalid("invalid execution lease request_id"))?,
            request_sha256,
            boot_generation: number("boot_generation")?,
            incarnation: u128::from_str_radix(encoded("incarnation", 32)?, 16)
                .map_err(|_| invalid("invalid execution lease incarnation"))?,
        };
        identity
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        let ttl_ms = number("ttl_ms")?;
        require(
            (MIN_TTL_MS..=MAX_TTL_MS).contains(&ttl_ms),
            "invalid execution lease TTL",
        )?;
        Ok(Self {
            identity,
            ttl: Duration::from_millis(ttl_ms),
            cadence: Duration::from_millis(ttl_ms / 3),
            active: None,
            pending: None,
            sequence: 0,
            stopped: false,
        })
    }

    pub(super) fn validate_request(&self, request: &Value) -> io::Result<()> {
        require(
            !self.stopped
                && self.active.is_none()
                && request["kind"] == "canonical-exec"
                && request["request_id"].as_u64() == Some(self.identity.request_id)
                && <[u8; 32]>::from(Sha256::digest(serde_json::to_vec(request)?))
                    == self.identity.request_sha256,
            "execution lease does not own the exact dispatch",
        )
    }

    /// Called only after the complete dispatch was written, using its start
    /// instant so a delayed flush cannot extend our view beyond the worker's.
    pub(super) fn arm(&mut self, sent_at: Instant) {
        self.active = Some(Active {
            expires: sent_at + self.ttl,
            renew_at: sent_at + self.cadence,
        });
    }

    pub(super) fn wake_at(&self) -> Option<Instant> {
        self.active.as_ref().map(|active| {
            if self.pending.is_some() {
                active.expires
            } else {
                active.renew_at.min(active.expires)
            }
        })
    }

    pub(super) fn expires_at(&self) -> Option<Instant> {
        self.active.as_ref().map(|active| active.expires)
    }

    pub(super) fn renewal_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn tick(&mut self, now: Instant) -> io::Result<Tick> {
        let Some(active) = &self.active else {
            return Ok(Tick::Idle);
        };
        if now >= active.expires {
            self.stop();
            return Ok(Tick::Expired);
        }
        if self.pending.is_some() || now < active.renew_at {
            return Ok(Tick::Idle);
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("execution lease renewal sequence exhausted"))?;
        // Burn before the first byte: no retry is safe after an uncertain write.
        self.pending = Some((self.sequence, now));
        Ok(Tick::Renew(json!({"kind":"execution-lease-renew",
            "session_id":self.identity.session_id, "lease_id":self.identity.lease_id,
            "request_id":self.identity.request_id, "renewal_seq":self.sequence})))
    }

    /// Returns true only for an exact pending lease ACK. Even after completion,
    /// one late ACK can be drained, but can never restart the renewal timer.
    pub(super) fn consume(&mut self, frame: &Value, now: Instant) -> io::Result<bool> {
        if frame["kind"] != "execution-lease-renewed" {
            return Ok(false);
        }
        let (sequence, sent_at) = self
            .pending
            .ok_or_else(|| invalid("unsolicited or duplicate execution lease acknowledgment"))?;
        require(
            frame.as_object().is_some_and(|fields| fields.len() == 6)
                && frame["session_id"].as_u64() == Some(self.identity.session_id)
                && frame["lease_id"].as_u64() == Some(self.identity.lease_id)
                && frame["request_id"].as_u64() == Some(self.identity.request_id)
                && frame["renewal_seq"].as_u64() == Some(sequence)
                && frame["accepted"].as_bool().is_some(),
            "foreign or malformed execution lease acknowledgment",
        )?;
        self.pending = None;
        if self.stopped {
            return Ok(true);
        }
        let expired = self
            .active
            .as_ref()
            .is_none_or(|active| now >= active.expires)
            || now >= sent_at + self.ttl;
        if frame["accepted"] != true || expired {
            self.stop();
        } else {
            self.active = Some(Active {
                expires: sent_at + self.ttl,
                renew_at: sent_at + self.cadence,
            });
        }
        Ok(true)
    }

    pub(super) fn stopped(&self) -> bool {
        self.stopped
    }

    pub(super) fn stop(&mut self) {
        self.stopped = true;
        self.active = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (ExecutionLease, Value, Instant) {
        let request = json!({"kind":"canonical-exec", "request_id":7, "args":["lib.rs"]});
        let hello = json!({"execution_leases":[REQUEST_EXECUTION_LEASE_VERSION],
            "boot_generation":1, "incarnation":format!("{:032x}", 2)});
        let lease = ExecutionLease::parse(&grant(&hello, &request, 11, 12).unwrap()).unwrap();
        (lease, request, Instant::now())
    }

    fn ack(renewal: &Value, accepted: bool) -> Value {
        let mut reply = renewal.clone();
        reply["kind"] = json!("execution-lease-renewed");
        reply["accepted"] = json!(accepted);
        reply
    }

    #[test]
    fn renews_only_one_exact_pending_request_and_uses_send_time() {
        let (mut lease, request, now) = setup();
        assert!(lease.wake_at().is_none());
        let mut changed = request.clone();
        changed["args"] = json!(["other.rs"]);
        assert!(lease.validate_request(&changed).is_err());
        lease.validate_request(&request).unwrap();
        lease.arm(now);
        assert!(matches!(lease.tick(now).unwrap(), Tick::Idle));
        let Tick::Renew(renewal) = lease.tick(now + Duration::from_secs(10)).unwrap() else {
            panic!("renewal due");
        };
        assert_eq!(renewal["renewal_seq"], 1);
        assert!(matches!(
            lease.tick(now + Duration::from_secs(20)).unwrap(),
            Tick::Idle
        ));
        assert!(
            lease
                .consume(&ack(&renewal, true), now + Duration::from_secs(25))
                .unwrap()
        );
        assert_eq!(lease.expires_at(), Some(now + Duration::from_secs(40)));
        assert!(
            lease
                .consume(&ack(&renewal, true), now + Duration::from_secs(25))
                .is_err()
        );
        let Tick::Renew(next) = lease.tick(now + Duration::from_secs(25)).unwrap() else {
            panic!("renewal due");
        };
        assert_eq!(next["renewal_seq"], 2);
    }

    #[test]
    fn expired_rejected_or_finished_leases_cannot_be_revived_by_late_ack() {
        for reason in ["expired", "rejected", "finished", "ack-after-expiry"] {
            let (mut lease, _, now) = setup();
            lease.arm(now);
            let Tick::Renew(renewal) = lease.tick(now + Duration::from_secs(10)).unwrap() else {
                panic!("renewal due");
            };
            match reason {
                "expired" => assert!(matches!(
                    lease.tick(now + Duration::from_secs(30)).unwrap(),
                    Tick::Expired
                )),
                "finished" => lease.stop(),
                _ => {}
            }
            let reply_at = if reason == "ack-after-expiry" { 30 } else { 15 };
            lease
                .consume(
                    &ack(&renewal, reason != "rejected"),
                    now + Duration::from_secs(reply_at),
                )
                .unwrap();
            assert!(lease.stopped());
            assert!(lease.wake_at().is_none());
            assert!(matches!(
                lease.tick(now + Duration::from_secs(31)).unwrap(),
                Tick::Idle
            ));
        }
    }

    #[test]
    fn foreign_and_malformed_acknowledgments_leave_pending_identity_intact() {
        let (mut lease, _, now) = setup();
        lease.arm(now);
        let Tick::Renew(renewal) = lease.tick(now + Duration::from_secs(10)).unwrap() else {
            panic!("renewal due");
        };
        for field in [
            "session_id",
            "lease_id",
            "request_id",
            "renewal_seq",
            "accepted",
            "extra",
        ] {
            let mut reply = ack(&renewal, true);
            reply[field] = json!(999);
            assert!(
                lease
                    .consume(&reply, now + Duration::from_secs(11))
                    .is_err(),
                "{field}"
            );
        }
        lease
            .consume(&ack(&renewal, true), now + Duration::from_secs(11))
            .unwrap();
        assert!(!lease.stopped());
    }
}
