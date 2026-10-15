//! Bounded, non-owning readiness and live dependency singleflight waits.
//!
//! Waiting never grants execution or materialization authority. The same
//! request bytes are resubmitted on the same connection, so the daemon
//! reobserves inputs and reruns its ordinary serving gates. A follower stops
//! before the edge's 64-request quota and one absolute wait deadline bounds
//! all sleeps, writes and reads. The original caller must remain alive across
//! every wait and protocol transition; cancellation never authorizes fallback.
//!
//! Cold facts have no action key yet: `preparing` may precede a keyed `wait`,
//! but never follow it. Readiness and singleflight share ONE deadline and retry
//! quota. Once an action key is bound it cannot change, even after more facts
//! need warming. Unknown peers/frames remain ordinary pre-acceptance failures.

#[path = "singleflight_policy.rs"]
mod policy;

use super::reply_json::{self, Value};
use super::{ConsultStream, HELLO, Live, MAX_LIVE_REPLY_BYTES, MAX_REPLY_BYTES, connect_owned, consult_succeeded, live_outcome};
use policy::WaitPolicy;
use std::io::{self, BufRead, BufReader, Write};
use std::time::{Duration, Instant};

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

/// Read the initial response, following only explicitly negotiated waits.
/// Before accepting a hit, timeout/disconnection permits local execution ONLY
/// while the original caller is still owned. After acceptance, uncertainty
/// always follows live_outcome's existing fail-closed delivery protocol.
pub(super) fn read_decision(
    reader: BufReader<ConsultStream>,
    frame: &str,
    decision_budget: Duration,
    may_wait: bool,
    socket: &str,
    connect_timeout: Duration,
    owned: &impl Fn() -> bool,
) -> Result<Live, ()> {
    read_with_policy(
        reader,
        frame,
        decision_budget,
        may_wait,
        WaitPolicy::from_environment(),
        Some((socket, connect_timeout)),
        owned,
    )
}

#[derive(Debug, PartialEq, Eq)]
enum WaitFor<'a> {
    Facts,
    Action(&'a str),
}

fn action_key(reply: &Value) -> Option<&str> {
    reply
        .get("action_key")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty() && key.len() <= 256)
}

fn wait_for(reply: &Value) -> Option<WaitFor<'_>> {
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
    match reply.get("decision").and_then(Value::as_str) {
        Some("wait") => action_key(reply).map(WaitFor::Action),
        Some("preparing")
            if !fields.iter().any(|(name, _)| name == "action_key")
                && matches!(
                    reply.get("reason").and_then(Value::as_str),
                    Some(
                        "toolchain-facts-pending"
                            | "package-facts-pending"
                            | "dependency-facts-pending"
                    )
                ) =>
        {
            Some(WaitFor::Facts)
        }
        _ => None,
    }
}

/// Start an entirely new, unowned consultation only after the prior
/// non-owning response was completely parsed. No hit consent or execution
/// grant can reach this path. A failed/ambiguous handshake never authorizes
/// output writes or another compiler attempt.
fn reconnect_waiter(
    socket: &str,
    connect_timeout: Duration,
    decision_budget: Duration,
    absolute_deadline: Instant,
    owned: &impl Fn() -> bool,
) -> io::Result<BufReader<ConsultStream>> {
    check_owner(owned)?;
    let remaining = absolute_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "RABS wait expired"));
    }
    let stream = connect_owned(socket, connect_timeout.min(remaining), owned)?;
    let deadline = Instant::now()
        .checked_add(decision_budget)
        .ok_or_else(|| io::Error::other("RABS consult deadline overflow"))?
        .min(absolute_deadline);
    let mut reader = BufReader::new(ConsultStream { stream, deadline });
    write_owned(&mut reader, HELLO.as_bytes(), deadline, owned)?;
    write_owned(&mut reader, b"\n", deadline, owned)?;
    let hello = read_owned_reply(&mut reader, MAX_REPLY_BYTES, deadline, owned)?;
    if !hello.contains("hello-ok") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RABS reconnect handshake rejected",
        ));
    }
    Ok(reader)
}

fn read_with_policy(
    mut reader: BufReader<ConsultStream>,
    frame: &str,
    decision_budget: Duration,
    may_wait: bool,
    mut policy: WaitPolicy,
    rollover: Option<(&str, Duration)>,
    owned: &impl Fn() -> bool,
) -> Result<Live, ()> {
    let mut following_key: Option<String> = None;
    let mut wait_deadline = None;
    let mut retries = 0;
    // The first request was sent by consult(). Each reconnect starts a new
    // edge connection with its own quota; retries and the absolute deadline
    // remain owned by this logical consultation.
    let mut requests_on_connection = 1_u32;
    // Count reconnects separately from retries: a malicious or broken peer
    // cannot turn the per-connection quota into unlimited socket attempts.
    let mut rollovers = 0_u32;
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
        if !matches!(decision, Some("wait" | "preparing")) {
            // A changing action identity is not the flight we followed. Drop
            // before accepting a hit or executing an admitted attempt. Any
            // reserved attempt is released by the daemon's connection guard.
            if matches!(decision, Some("hit" | "execute")) && wait_deadline.is_some() {
                let key = action_key(&reply).ok_or(())?;
                if following_key
                    .as_deref()
                    .is_some_and(|expected| expected != key)
                {
                    return Err(());
                }
            }
            return live_outcome(&reply, reader, owned);
        }
        if !may_wait {
            return Err(());
        }
        match wait_for(&reply).ok_or(())? {
            WaitFor::Facts => {
                // Do not turn a keyed flight back into an unkeyed readiness
                // wait: that could disguise changed inputs or a new action.
                if following_key.is_some() {
                    return Err(());
                }
                if wait_deadline.is_none() {
                    policy = policy.for_preparation();
                }
            }
            WaitFor::Action(key) => match &following_key {
                Some(expected) if expected != key => return Err(()),
                Some(_) => {}
                None => following_key = Some(key.to_owned()),
            },
        }
        let now = Instant::now();
        // Preparing -> waiting must not buy a second timeout window. Nor
        // may changing preparation stages reset retries or backoff.
        let deadline = match wait_deadline {
            Some(deadline) => deadline,
            None => {
                let deadline = now.checked_add(policy.budget).ok_or(())?;
                wait_deadline = Some(deadline);
                deadline
            }
        };
        let delay = policy.delay_for(retries);
        check_owner(owned).map_err(|_| ())?;
        if retries >= policy.retries || delay >= deadline.saturating_duration_since(now) {
            // Healthy preparation/contention, not a broken daemon. Nothing
            // here accepted installation or started our compiler.
            return Ok(Live::PassThrough);
        }
        sleep_owned(delay, owned).map_err(|_| ())?;
        let now = Instant::now();
        if now >= deadline {
            return Ok(Live::PassThrough);
        }
        if requests_on_connection >= 60 {
            let (socket, connect_timeout) = rollover.ok_or(())?;
            if rollovers >= 16 {
                return Ok(Live::PassThrough);
            }
            rollovers += 1;
            // Drop the old follower connection before opening a new one. The
            // edge releases any connection-scoped flight accounting on drop.
            drop(reader);
            reader = reconnect_waiter(
                socket,
                connect_timeout,
                decision_budget,
                deadline,
                owned,
            )
            .map_err(|_| ())?;
            requests_on_connection = 0;
        }
        let request_deadline = Instant::now()
            .checked_add(decision_budget)
            .ok_or(())?
            .min(deadline);
        write_owned(&mut reader, frame.as_bytes(), request_deadline, owned).map_err(|_| ())?;
        write_owned(&mut reader, b"\n", request_deadline, owned).map_err(|_| ())?;
        requests_on_connection += 1;
        retries += 1;
    }
}

#[cfg(test)]
#[path = "singleflight_tests.rs"]
mod tests;
