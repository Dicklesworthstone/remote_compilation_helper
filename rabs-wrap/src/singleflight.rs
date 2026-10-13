//! Bounded, non-owning followers for the live dependency singleflight.
//!
//! Waiting never grants execution or materialization authority. The same
//! request bytes are resubmitted on the same connection, so the daemon
//! reobserves inputs and reruns its ordinary serving gates. A follower stops
//! before the edge's 64-request quota and one absolute wait deadline bounds
//! all sleeps, writes and reads. The original caller must remain alive across
//! every wait and protocol transition; cancellation never authorizes fallback.

use super::reply_json::{self, Value};
use super::{ConsultStream, Live, MAX_LIVE_REPLY_BYTES, consult_succeeded, live_outcome};
use std::io::{self, BufRead, BufReader, Write};
use std::time::{Duration, Instant};

const MAX_RETRIES: u32 = 60;
const MAX_WAIT_MS: u64 = 60_000;
const OWNER_POLL: Duration = Duration::from_millis(100);

fn check_owner(owned: &impl Fn() -> bool) -> io::Result<()> {
    if owned() {
        Ok(())
    } else {
        // Not Interrupted: generic Read/Write helpers retry that error. A
        // cancelled caller is terminal, even when the daemon is still healthy.
        Err(io::Error::other(
            "compiler caller disappeared during RABS consultation",
        ))
    }
}

fn prepare_io(
    reader: &mut BufReader<ConsultStream>,
    deadline: Instant,
    owned: &impl Fn() -> bool,
) -> io::Result<()> {
    check_owner(owned)?;
    let now = Instant::now();
    if now >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RABS consult deadline elapsed",
        ));
    }
    reader.get_mut().deadline = now
        .checked_add(OWNER_POLL)
        .unwrap_or(deadline)
        .min(deadline);
    Ok(())
}

fn retryable_slice(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// Write only the unsent suffix across ownership-poll timeouts. All protocol
/// phases share the caller's absolute deadline, not a fresh per-byte budget.
pub(super) fn write_owned(
    reader: &mut BufReader<ConsultStream>,
    mut bytes: &[u8],
    deadline: Instant,
    owned: &impl Fn() -> bool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        prepare_io(reader, deadline, owned)?;
        match reader.get_mut().write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "RABS peer stopped accepting bytes",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if retryable_slice(&error) => {}
            Err(error) => return Err(error),
        }
    }
    prepare_io(reader, deadline, owned)?;
    reader.get_mut().deadline = deadline;
    Ok(())
}

/// Retain partial frame bytes across socket timeouts. A normal read_line retry
/// would discard its prefix; a normal write_all retry could duplicate consent.
/// Check ownership even for bytes already buffered by an earlier phase.
pub(super) fn read_owned_reply(
    reader: &mut BufReader<ConsultStream>,
    max_bytes: u64,
    deadline: Instant,
    owned: &impl Fn() -> bool,
) -> io::Result<String> {
    let mut line = Vec::new();
    loop {
        prepare_io(reader, deadline, owned)?;
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if retryable_slice(&error) => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "RABS reply ended before frame delimiter",
            ));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |at| at + 1);
        if (line.len() as u64).saturating_add(count as u64) > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RABS reply exceeds frame limit",
            ));
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            prepare_io(reader, deadline, owned)?;
            reader.get_mut().deadline = deadline;
            return String::from_utf8(line)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
    }
}

fn sleep_owned(delay: Duration, owned: &impl Fn() -> bool) -> io::Result<()> {
    let wake = Instant::now()
        .checked_add(delay)
        .ok_or_else(|| io::Error::other("RABS wait deadline overflow"))?;
    loop {
        check_owner(owned)?;
        let remaining = wake.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        std::thread::sleep(remaining.min(OWNER_POLL));
    }
}

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
/// Before accepting a hit, timeout/disconnection permits local execution ONLY
/// while the original caller is still owned. After acceptance, uncertainty
/// always follows live_outcome's existing fail-closed delivery protocol.
pub(super) fn read_decision(
    reader: BufReader<ConsultStream>,
    frame: &str,
    decision_budget: Duration,
    may_wait: bool,
    owned: &impl Fn() -> bool,
) -> Result<Live, ()> {
    read_with_policy(
        reader,
        frame,
        decision_budget,
        may_wait,
        WaitPolicy::from_environment(),
        owned,
    )
}

fn wait_key(reply: &Value) -> Option<&str> {
    // get() deliberately conflates absent and duplicate fields. Neither a
    // single nor a repeated execution grant belongs on a non-owning wait.
    let Value::Object(fields) = reply else {
        return None;
    };
    if reply
        .get("compiler_skip_authorized")
        .and_then(Value::as_bool)
        != Some(false)
        || reply
            .get("materialization_started")
            .and_then(Value::as_bool)
            != Some(false)
        || fields
            .iter()
            .any(|(name, _)| name == "attempt" || name == "env")
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
    owned: &impl Fn() -> bool,
) -> Result<Live, ()> {
    let mut following: Option<(String, Instant)> = None;
    let mut retries = 0;
    loop {
        let response_deadline = reader.get_ref().deadline;
        let line = read_owned_reply(&mut reader, MAX_LIVE_REPLY_BYTES, response_deadline, owned)
            .map_err(|_| ())?;
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
            return live_outcome(&reply, reader, owned);
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
        check_owner(owned).map_err(|_| ())?;
        if retries >= policy.retries || delay >= deadline.saturating_duration_since(now) {
            // Healthy contention, not a broken daemon. No request in this
            // branch ever accepted installation or started our compiler.
            return Ok(Live::PassThrough);
        }
        sleep_owned(delay, owned).map_err(|_| ())?;
        let now = Instant::now();
        if now >= deadline {
            return Ok(Live::PassThrough);
        }
        let request_deadline = now.checked_add(decision_budget).ok_or(())?.min(deadline);
        write_owned(&mut reader, frame.as_bytes(), request_deadline, owned).map_err(|_| ())?;
        write_owned(&mut reader, b"\n", request_deadline, owned).map_err(|_| ())?;
        retries += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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
                policy(3),
                &|| true,
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
                settings,
                &|| true,
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
            (
                WAIT.replace(
                    "\"action_key\":\"key\"",
                    "\"action_key\":\"key\",\"attempt\":null,\"attempt\":null",
                ),
                true,
            ),
            (
                WAIT.replace(
                    "\"action_key\":\"key\"",
                    "\"action_key\":\"key\",\"env\":[],\"env\":[]",
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
                    policy(3),
                    &|| true,
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
            &|| true,
        );
        assert!(outcome.is_err());
        assert!(
            daemon.join().unwrap(),
            "follower must close before the trickle ends"
        );
    }

    #[test]
    fn caller_loss_interrupts_partial_decision_without_accepting_or_retrying() {
        let owned = Arc::new(AtomicBool::new(true));
        let revoked = Arc::clone(&owned);
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.write_all(b"{\"kind\":\"rustc-decision\",\"decision\":\"hit\"")
            .unwrap();
        let daemon = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            revoked.store(false, Ordering::Release);
            let mut bytes = Vec::new();
            let result = peer.read_to_end(&mut bytes);
            assert!(
                result.is_ok()
                    || matches!(result, Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset)
            );
            bytes
        });
        let mut session = reader(stream);
        session.get_mut().deadline = Instant::now() + Duration::from_secs(30);
        assert!(
            read_with_policy(
                session,
                "original",
                Duration::from_secs(30),
                true,
                policy(60),
                &|| owned.load(Ordering::Acquire),
            )
            .is_err()
        );
        assert!(daemon.join().unwrap().is_empty());
    }

    #[test]
    fn cancelled_backoff_never_returns_permission_to_fall_back() {
        let owned = Arc::new(AtomicBool::new(true));
        let revoked = Arc::clone(&owned);
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.write_all(WAIT.as_bytes()).unwrap();
        let daemon = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            revoked.store(false, Ordering::Release);
            let mut bytes = Vec::new();
            let result = peer.read_to_end(&mut bytes);
            assert!(
                result.is_ok()
                    || matches!(result, Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset)
            );
            bytes
        });
        let mut settings = policy(60);
        settings.budget = Duration::from_secs(30);
        settings.initial_delay = Duration::from_secs(10);
        settings.maximum_delay = Duration::from_secs(10);
        assert!(
            read_with_policy(
                reader(stream),
                "must not retry",
                Duration::from_secs(30),
                true,
                settings,
                &|| owned.load(Ordering::Acquire),
            )
            .is_err()
        );
        assert!(daemon.join().unwrap().is_empty());
    }

    #[test]
    fn buffered_hit_is_not_accepted_after_ownership_is_revoked() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(
            b"first\n{\"kind\":\"rustc-decision\",\"decision\":\"hit\",\"capture_protocol\":1}\n",
        )
        .unwrap();
        let mut session = reader(stream);
        let deadline = session.get_ref().deadline;
        assert_eq!(
            read_owned_reply(&mut session, 4096, deadline, &|| true).unwrap(),
            "first\n"
        );
        assert!(
            read_with_policy(
                session,
                "original",
                Duration::from_secs(1),
                true,
                policy(3),
                &|| false,
            )
            .is_err()
        );
        let result = peer.read(&mut [0; 1]);
        assert!(
            matches!(result, Ok(0))
                || matches!(result, Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset)
        );
    }

    #[test]
    fn partial_owned_frames_survive_poll_timeouts_without_losing_bytes() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            peer.write_all(b"{\"decision\":").unwrap();
            std::thread::sleep(OWNER_POLL * 3);
            peer.write_all(b"\"pass-through\"}\nnext\n").unwrap();
        });
        let mut session = reader(stream);
        let deadline = session.get_ref().deadline;
        assert_eq!(
            read_owned_reply(&mut session, 4096, deadline, &|| true).unwrap(),
            "{\"decision\":\"pass-through\"}\n"
        );
        assert_eq!(session.get_ref().deadline, deadline);
        assert_eq!(
            read_owned_reply(&mut session, 4096, deadline, &|| true).unwrap(),
            "next\n"
        );
        sender.join().unwrap();
    }

    #[test]
    fn ownership_and_absolute_deadline_apply_to_writes_and_buffered_reads() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut session = reader(stream);
        let deadline = session.get_ref().deadline;
        assert!(write_owned(&mut session, b"consent\n", deadline, &|| false).is_err());
        assert_eq!(
            write_owned(&mut session, b"consent\n", Instant::now(), &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        peer.set_nonblocking(false).unwrap();
        peer.write_all(b"ok\n").unwrap();
        assert_eq!(
            read_owned_reply(&mut session, 3, deadline, &|| true).unwrap(),
            "ok\n"
        );
        peer.write_all(b"four\n").unwrap();
        assert_eq!(
            read_owned_reply(&mut session, 4, deadline, &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
