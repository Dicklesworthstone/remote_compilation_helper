//! Committed-result metadata delivery for Cargo's pipelined compilation.
//!
//! Both sides explicitly negotiate protocol 1 and bind the accepted action
//! and committed manifest. The only intermediate frame exposes one exact,
//! continuous stderr prefix; the wrapper flushes it before acknowledging it.
//! That exposure is irreversible even if the install writer later returns.
//! All socket phases AND prefix delivery use the original install deadline.
//! Freshly published remote results additionally retain their execution
//! protocol and exact captured-result identity throughout installation.

use super::reply_json::{self, Value};
use super::{
    ConsultStream, Live, MAX_CAPTURE_BYTES, MAX_LIVE_REPLY_BYTES, accepted_install_reply,
    hex_decode, install_wait, json_string, singleflight,
};
use std::io::{self, BufReader, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const OWNER_POLL: Duration = Duration::from_millis(100);

struct Identity<'a> {
    action_key: &'a str,
    manifest_key: &'a str,
    remote_capture: Option<&'a str>,
}

fn contains(reply: &Value, field: &str) -> bool {
    matches!(reply, Value::Object(fields) if fields.iter().any(|(name, _)| name == field))
}

fn one(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Number(raw)) if raw == "1")
}

fn key<'a>(reply: &'a Value, field: &str, maximum: usize) -> Option<&'a str> {
    reply
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
}

/// Absence means legacy. An explicitly malformed or duplicated opt-in must
/// never be silently downgraded into a different acceptance contract.
fn negotiate(reply: &Value, maximum: usize) -> Result<Option<Identity<'_>>, ()> {
    if !contains(reply, "metadata_protocol") {
        return Ok(None);
    }
    if !one(reply.get("metadata_protocol")) {
        return Err(());
    }
    Ok(Some(Identity {
        action_key: key(reply, "action_key", maximum).ok_or(())?,
        manifest_key: key(reply, "manifest_key", maximum).ok_or(())?,
        remote_capture: None,
    }))
}

impl Identity<'_> {
    fn matches(&self, reply: &Value) -> bool {
        one(reply.get("metadata_protocol"))
            && reply.get("action_key").and_then(Value::as_str) == Some(self.action_key)
            && reply.get("manifest_key").and_then(Value::as_str) == Some(self.manifest_key)
            && self.remote_capture.is_none_or(|capture| {
                one(reply.get("remote_protocol"))
                    && reply.get("capture").and_then(Value::as_str) == Some(capture)
            })
    }

    fn frame(&self, kind: &str, sequence: bool) -> String {
        let remote = self.remote_capture.map_or_else(String::new, |capture| {
            format!(
                ",\"remote_protocol\":1,\"capture\":{}",
                json_string(capture)
            )
        });
        format!(
            "{{\"kind\":{},\"metadata_protocol\":1,\"action_key\":{},\"manifest_key\":{}{}{}}}\n",
            json_string(kind),
            json_string(self.action_key),
            json_string(self.manifest_key),
            remote,
            if sequence { ",\"sequence\":1" } else { "" },
        )
    }

    fn prefix(&self, reply: &Value) -> Option<Vec<u8>> {
        let Value::Object(fields) = reply else {
            return None;
        };
        // A remote prefix also binds its distinct execution protocol and
        // capture. Every required field is unique, including equal duplicates.
        if fields.len() != if self.remote_capture.is_some() { 8 } else { 6 }
            || reply.get("kind").and_then(Value::as_str) != Some("rustc-metadata")
            || !self.matches(reply)
            || !one(reply.get("sequence"))
        {
            return None;
        }
        let hex = reply.get("stderr_hex").and_then(Value::as_str)?;
        if hex.is_empty() || hex.len() > MAX_CAPTURE_BYTES * 2 {
            return None;
        }
        hex_decode(hex)
    }
}

/// A true exposure receipt prevents fallback even if the prefix/ACK exchange
/// was lost. Duplicate or ill-typed optional fields cannot authorize fallback.
pub(super) fn exposure_flag(reply: &Value) -> Option<bool> {
    if contains(reply, "metadata_exposed") {
        reply.get("metadata_exposed").and_then(Value::as_bool)
    } else {
        Some(false)
    }
}

fn check_live(deadline: Instant, owned: &impl Fn() -> bool) -> io::Result<()> {
    if !owned() {
        return Err(io::Error::other("original compiler caller disappeared"));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RABS install deadline elapsed",
        ));
    }
    Ok(())
}

/// Stderr itself can block if Cargo stops consuming output. Keep the wait
/// bounded without unsafe fd manipulation or another dependency. A failed
/// wait is terminal for this wrapper process: it exits silently, terminating
/// any unfinished writer instead of attempting to log through the same pipe.
fn deliver_prefix(
    mut sink: impl Write + Send + 'static,
    bytes: Vec<u8>,
    deadline: Instant,
    owned: &impl Fn() -> bool,
) -> io::Result<()> {
    check_live(deadline, owned)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("rabs-metadata-stderr".into())
        .spawn(move || {
            let result = sink.write_all(&bytes).and_then(|()| sink.flush());
            let _ = sender.send(result);
        })?;
    loop {
        check_live(deadline, owned)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining.min(OWNER_POLL)) {
            Ok(result) => {
                result?;
                return check_live(deadline, owned);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("metadata stderr writer did not finish"));
            }
        }
    }
}

fn failure(exposed: bool, reason: impl Into<String>) -> Live {
    if exposed {
        Live::FailClosedSilently
    } else {
        Live::FailClosed(reason.into())
    }
}

/// Only negotiation errors can reach the ordinary pre-acceptance fallback.
/// Every operation after attempted consent, including unwinding, is terminal
/// unless a typed writer-return receipt proves a still-unexposed install safe.
pub(super) fn outcome(
    offer: &Value,
    reader: BufReader<ConsultStream>,
    owned: &impl Fn() -> bool,
) -> Result<Live, ()> {
    let identity = negotiate(offer, 256)?;
    let Some(deadline) = Instant::now().checked_add(install_wait()) else {
        return Ok(Live::FailClosed(
            "RABS install deadline is not representable".into(),
        ));
    };
    let accepted = identity.as_ref().map_or_else(
        || "{\"kind\":\"rustc-accept\"}\n".to_owned(),
        |identity| identity.frame("rustc-accept", false),
    );
    Ok(accept_and_receive(
        reader,
        identity.as_ref(),
        &accepted,
        deadline,
        owned,
        accepted_install_reply,
        "cache-hit",
    ))
}

/// Remote execution was already accepted and produced private verified output.
/// Negotiate early delivery only for this exact ready capture; malformed new
/// fields fail closed before installation consent rather than authorizing a
/// second compiler. Workspace request-owned results keep their legacy path.
pub(super) fn remote_install(
    ready: &Value,
    key: &str,
    capture: &str,
    reader: BufReader<ConsultStream>,
    deadline: Instant,
    owned: &impl Fn() -> bool,
) -> Live {
    if contains(ready, "manifest_key") && !contains(ready, "metadata_protocol") {
        return Live::FailClosed("incomplete remote metadata negotiation".into());
    }
    let mut identity = match negotiate(ready, 512) {
        Ok(identity) => identity,
        Err(()) => return Live::FailClosed("invalid remote metadata negotiation".into()),
    };
    if let Some(identity) = &mut identity {
        if identity.action_key != key || identity.manifest_key != capture {
            return Live::FailClosed("remote metadata offer changed its captured result".into());
        }
        identity.remote_capture = Some(capture);
    }
    let accepted = identity.as_ref().map_or_else(
        || {
            format!(
                "{{\"kind\":\"rustc-accept\",\"capture\":{}}}\n",
                json_string(capture)
            )
        },
        |identity| identity.frame("rustc-accept", false),
    );
    accept_and_receive(
        reader,
        identity.as_ref(),
        &accepted,
        deadline,
        owned,
        |line| super::remote::completion(line, key),
        "remote",
    )
}

fn accept_and_receive(
    mut reader: BufReader<ConsultStream>,
    identity: Option<&Identity<'_>>,
    accepted: &str,
    deadline: Instant,
    owned: &impl Fn() -> bool,
    complete: impl Fn(&str) -> Live,
    description: &str,
) -> Live {
    catch_unwind(AssertUnwindSafe(|| {
        if singleflight::write_owned(&mut reader, accepted.as_bytes(), deadline, owned).is_err() {
            return Live::FailClosed(format!(
                "RABS {description} installation acceptance is uncertain"
            ));
        }
        receive(&mut reader, identity, deadline, owned, complete)
    }))
    .unwrap_or(Live::FailClosedSilently)
}

fn receive(
    reader: &mut BufReader<ConsultStream>,
    identity: Option<&Identity<'_>>,
    deadline: Instant,
    owned: &impl Fn() -> bool,
    complete: impl Fn(&str) -> Live,
) -> Live {
    let mut exposed = false;
    loop {
        let line =
            match singleflight::read_owned_reply(reader, MAX_LIVE_REPLY_BYTES, deadline, owned) {
                Ok(line) => line,
                Err(error) => {
                    return failure(
                        exposed,
                        format!("the RABS installation outcome is unknown: {error}"),
                    );
                }
            };
        let Some(answer) = reply_json::parse(&line) else {
            return failure(exposed, "malformed install answer");
        };
        if answer.get("kind").and_then(Value::as_str) == Some("rustc-metadata") {
            let Some(identity) = identity.filter(|_| !exposed) else {
                return failure(exposed, "unnegotiated or repeated metadata exposure");
            };
            let Some(prefix) = identity.prefix(&answer) else {
                return failure(exposed, "invalid metadata exposure identity or transcript");
            };
            // Sticky BEFORE any write attempt: even a partial stderr write,
            // panic, lost caller or ACK cannot make local compilation safe.
            exposed = true;
            if deliver_prefix(io::stderr(), prefix, deadline, owned).is_err() {
                return Live::FailClosedSilently;
            }
            let ack = identity.frame("rustc-metadata-ack", true);
            if singleflight::write_owned(reader, ack.as_bytes(), deadline, owned).is_err() {
                return Live::FailClosedSilently;
            }
            continue;
        }
        if let Some(identity) = identity {
            if !identity.matches(&answer) {
                return failure(
                    exposed,
                    "install answer changed the accepted metadata identity",
                );
            }
            let Some(reported_exposed) = exposure_flag(&answer) else {
                return failure(exposed, "ambiguous metadata exposure receipt");
            };
            if matches!(
                answer.get("decision").and_then(Value::as_str),
                Some("served" | "remote-complete")
            ) && contains(&answer, "metadata_exposed")
                && reported_exposed != exposed
            {
                return failure(
                    exposed,
                    "served transcript disagrees with metadata exposure",
                );
            }
        } else if contains(&answer, "metadata_protocol") || exposure_flag(&answer) != Some(false) {
            return failure(exposed, "unnegotiated metadata installation answer");
        }
        let terminal = complete(&line);
        return match terminal {
            Live::PassThrough | Live::FailClosed(_) if exposed => Live::FailClosedSilently,
            other => other,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FlushFence {
        owner: Arc<AtomicBool>,
        fail_flush: bool,
    }

    impl Write for FlushFence {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.owner.store(false, Ordering::SeqCst);
            if self.fail_flush {
                Err(io::Error::other("protocol fixture flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn prefix_delivery_checks_flush_and_original_caller_before_ack() {
        for fail_flush in [true, false] {
            let owner = Arc::new(AtomicBool::new(true));
            let sink = FlushFence {
                owner: Arc::clone(&owner),
                fail_flush,
            };
            let result = deliver_prefix(
                sink,
                b"metadata prefix".to_vec(),
                Instant::now() + Duration::from_secs(2),
                &|| owner.load(Ordering::SeqCst),
            );
            assert!(
                result.is_err(),
                "a lost caller or failed flush cannot be ACKed"
            );
            assert!(!owner.load(Ordering::SeqCst));
        }
    }

    struct PanickingWriter;

    impl Write for PanickingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            panic!("explicit metadata writer panic fixture");
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("panicked writer cannot flush");
        }
    }

    #[test]
    fn a_panicked_prefix_writer_cannot_confirm_exposure() {
        assert!(
            deliver_prefix(
                PanickingWriter,
                b"metadata prefix".to_vec(),
                Instant::now() + Duration::from_secs(2),
                &|| true,
            )
            .is_err()
        );
    }

    #[test]
    fn accepted_phase_panic_does_not_reach_the_fail_open_error_path() {
        let offer =
            reply_json::parse(r#"{"metadata_protocol":1,"action_key":"a","manifest_key":"m"}"#)
                .unwrap();
        let (stream, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let after_accept = Arc::new(AtomicBool::new(false));
        let mark_accepted = Arc::clone(&after_accept);
        let daemon = std::thread::spawn(move || {
            use std::io::BufRead;
            let mut line = String::new();
            BufReader::new(peer.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(line.contains("rustc-accept"));
            mark_accepted.store(true, Ordering::SeqCst);
            peer.write_all(b"{\"kind\":\"rustc-decision\"}\n").unwrap();
        });
        let reader = BufReader::new(ConsultStream {
            stream,
            deadline: Instant::now() + Duration::from_secs(2),
        });
        let outcome = outcome(&offer, reader, &|| {
            assert!(
                !after_accept.load(Ordering::SeqCst),
                "explicit accepted-phase ownership panic fixture"
            );
            true
        });
        assert!(matches!(outcome, Ok(Live::FailClosedSilently)));
        daemon.join().unwrap();
    }

    #[test]
    fn exposure_receipts_cannot_authorize_fallback_ambiguously() {
        for fields in [
            r#""metadata_exposed":true"#,
            r#""metadata_exposed":"false""#,
            r#""metadata_exposed":false,"metadata_exposed":false"#,
        ] {
            let line = format!(
                "{{\"kind\":\"rustc-decision\",\"decision\":\"serve-failed\",\"writer_returned\":true,{fields}}}"
            );
            assert!(matches!(accepted_install_reply(&line), Live::FailClosed(_)));
        }
    }
}
