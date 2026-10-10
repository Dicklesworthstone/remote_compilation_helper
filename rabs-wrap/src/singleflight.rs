//! Bounded, non-owning followers for the live dependency singleflight.
//!
//! Waiting never grants execution or materialization authority. The same
//! request bytes are resubmitted on the same connection, so the daemon
//! reobserves inputs and reruns its ordinary serving gates. A follower stops
//! before the edge's 64-request quota and one absolute wait deadline bounds
//! all sleeps, writes and reads. No connect threads, extra dependencies or
//! daemon blocking workers are retained between retries.

use super::reply_json::{self, Value};
use super::{
    ConsultStream, Live, MAX_LIVE_REPLY_BYTES, consult_succeeded, live_outcome, read_reply_bounded,
};
use std::io::{BufReader, Write};
use std::time::{Duration, Instant};

const MAX_RETRIES: u32 = 60;
const MAX_WAIT_MS: u64 = 60_000;

#[derive(Clone, Copy)]
struct WaitPolicy {
    budget: Duration,
    retries: u32,
    initial_delay: Duration,
    maximum_delay: Duration,
}

impl WaitPolicy {
    fn from_environment() -> Self {
        let milliseconds = std::env::var("RABS_SINGLEFLIGHT_WAIT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(MAX_WAIT_MS)
            .min(MAX_WAIT_MS);
        Self {
            budget: Duration::from_millis(milliseconds),
            retries: MAX_RETRIES,
            initial_delay: Duration::from_millis(50),
            maximum_delay: Duration::from_secs(1),
        }
    }
}

/// Read the initial response, following only explicitly negotiated waits.
/// Before accepting a hit, timeout/disconnection still permits local execution.
/// Once a hit is accepted, `live_outcome` owns the existing fail-closed protocol.
pub(super) fn read_decision(
    reader: BufReader<ConsultStream>,
    frame: &str,
    decision_budget: Duration,
    may_wait: bool,
) -> Result<Live, ()> {
    read_with_policy(
        reader,
        frame,
        decision_budget,
        may_wait,
        WaitPolicy::from_environment(),
    )
}

fn wait_key(reply: &Value) -> Option<&str> {
    if reply
        .get("compiler_skip_authorized")
        .and_then(Value::as_bool)
        != Some(false)
        || reply
            .get("materialization_started")
            .and_then(Value::as_bool)
            != Some(false)
        || reply.get("attempt").is_some()
        || reply.get("env").is_some()
    {
        return None;
    }
    reply
        .get("action_key")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty() && key.len() <= 256)
}

fn read_with_policy(
    mut reader: BufReader<ConsultStream>,
    frame: &str,
    decision_budget: Duration,
    may_wait: bool,
    policy: WaitPolicy,
) -> Result<Live, ()> {
    let mut following: Option<(String, Instant)> = None;
    let mut retries = 0;
    loop {
        let line = read_reply_bounded(&mut reader, MAX_LIVE_REPLY_BYTES).map_err(|_| ())?;
        let reply = reply_json::parse(&line).ok_or(())?;
        if reply.get("kind").and_then(Value::as_str) != Some("rustc-decision") {
            return if consult_succeeded(&line) {
                Ok(Live::PassThrough)
            } else {
                Err(())
            };
        }
        let decision = reply.get("decision").and_then(Value::as_str);
        if decision != Some("wait") {
            // A changing action identity is not the flight we followed. Drop
            // before accepting a hit or executing an admitted attempt. Any
            // reserved attempt is released by the daemon's connection guard.
            if matches!(decision, Some("hit" | "execute"))
                && following.as_ref().is_some_and(|(key, _)| {
                    reply.get("action_key").and_then(Value::as_str) != Some(key.as_str())
                })
            {
                return Err(());
            }
            return live_outcome(&reply, reader);
        }
        if !may_wait {
            return Err(());
        }
        let key = wait_key(&reply).ok_or(())?;
        let now = Instant::now();
        let deadline = if let Some((expected, deadline)) = &following {
            if expected != key {
                return Err(());
            }
            *deadline
        } else {
            let deadline = now.checked_add(policy.budget).ok_or(())?;
            following = Some((key.to_owned(), deadline));
            deadline
        };
        let delay = policy
            .initial_delay
            .saturating_mul(1_u32 << retries.min(5))
            .min(policy.maximum_delay);
        if retries >= policy.retries || delay >= deadline.saturating_duration_since(now) {
            // Healthy contention, not a broken daemon. No request in this
            // branch ever accepted installation or started our compiler.
            return Ok(Live::PassThrough);
        }
        std::thread::sleep(delay);
        let now = Instant::now();
        if now >= deadline {
            return Ok(Live::PassThrough);
        }
        reader.get_mut().deadline = now.checked_add(decision_budget).ok_or(())?.min(deadline);
        reader
            .get_mut()
            .write_all(frame.as_bytes())
            .map_err(|_| ())?;
        reader.get_mut().write_all(b"\n").map_err(|_| ())?;
        retries += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Read};
    use std::os::unix::net::UnixStream;

    const WAIT: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"wait\",\"action_key\":\"key\",\"compiler_skip_authorized\":false,\"materialization_started\":false}\n";

    fn policy(retries: u32) -> WaitPolicy {
        WaitPolicy {
            budget: Duration::from_secs(2),
            retries,
            initial_delay: Duration::ZERO,
            maximum_delay: Duration::ZERO,
        }
    }

    fn reader(stream: UnixStream) -> BufReader<ConsultStream> {
        BufReader::new(ConsultStream {
            stream,
            deadline: Instant::now() + Duration::from_secs(2),
        })
    }

    #[test]
    fn retry_count_bounds_even_a_peer_that_answers_immediately() {
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let daemon = std::thread::spawn(move || {
            let mut peer = BufReader::new(peer);
            let mut requests = 0;
            loop {
                peer.get_mut().write_all(WAIT.as_bytes()).unwrap();
                let mut line = String::new();
                if peer.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                assert_eq!(line, "original bytes\n");
                requests += 1;
            }
            requests
        });
        assert!(matches!(
            read_with_policy(
                reader(stream),
                "original bytes",
                Duration::from_secs(1),
                true,
                policy(3)
            ),
            Ok(Live::PassThrough)
        ));
        assert_eq!(daemon.join().unwrap(), 3);
        const {
            assert!(
                MAX_RETRIES + 1 < 64,
                "leave room below the edge request quota"
            );
        }
    }

    #[test]
    fn zero_wait_budget_never_sends_a_retry_or_acceptance() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(WAIT.as_bytes()).unwrap();
        let mut settings = policy(3);
        settings.budget = Duration::ZERO;
        assert!(matches!(
            read_with_policy(
                reader(stream),
                "original",
                Duration::from_secs(1),
                true,
                settings
            ),
            Ok(Live::PassThrough)
        ));
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn malformed_authority_or_unnegotiated_waits_are_not_followed() {
        for (line, negotiated) in [
            (WAIT.to_owned(), false),
            (
                WAIT.replace(
                    "\"compiler_skip_authorized\":false",
                    "\"compiler_skip_authorized\":true",
                ),
                true,
            ),
            (
                WAIT.replace(
                    "\"materialization_started\":false",
                    "\"materialization_started\":true",
                ),
                true,
            ),
            (
                WAIT.replace("\"action_key\":\"key\"", "\"action_key\":\"\""),
                true,
            ),
            (
                WAIT.replace(
                    "\"action_key\":\"key\"",
                    "\"action_key\":\"key\",\"action_key\":\"other\"",
                ),
                true,
            ),
            (
                WAIT.replace(
                    "\"materialization_started\":false",
                    "\"attempt\":\"admitted\"",
                ),
                true,
            ),
        ] {
            let (stream, mut peer) = UnixStream::pair().unwrap();
            peer.write_all(line.as_bytes()).unwrap();
            assert!(
                read_with_policy(
                    reader(stream),
                    "original",
                    Duration::from_secs(1),
                    negotiated,
                    policy(3)
                )
                .is_err()
            );
            assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        }
    }

    #[test]
    fn trickling_peer_cannot_hold_a_follower_past_its_wait_budget() {
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let daemon = std::thread::spawn(move || {
            let mut peer = BufReader::new(peer);
            peer.get_mut().write_all(WAIT.as_bytes()).unwrap();
            let mut line = String::new();
            assert!(peer.read_line(&mut line).unwrap() > 0);
            // Without an absolute wait bound these valid partial JSON bytes
            // can keep a per-read idle timeout alive indefinitely.
            for _ in 0..300 {
                if peer.get_mut().write_all(b" ").is_err() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        });
        let mut settings = policy(60);
        settings.budget = Duration::from_millis(100);
        let outcome = read_with_policy(
            reader(stream),
            "original",
            Duration::from_secs(10),
            true,
            settings,
        );
        assert!(outcome.is_err());
        assert!(
            daemon.join().unwrap(),
            "follower must close before the trickle ends"
        );
    }
}
