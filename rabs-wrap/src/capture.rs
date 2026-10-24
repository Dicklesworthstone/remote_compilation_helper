//! Output-custody handoff for an admitted local compile (bd-k52xe).
//!
//! Cargo may release or rewrite a unit's outputs as soon as its wrapper exits.
//! The daemon must therefore finish copying the outputs BEFORE the wrapper
//! acknowledges their capture. A completion report alone does not authorize
//! publication. Timeouts abandon cache population, never repeat the compile.
//! The original caller is checked between bounded I/O slices as well as before
//! the ACK: cancellation cannot strand a wrapper behind a stalled capture peer.

use super::{ConsultStream, MAX_REPLY_BYTES, json_string, reply_json};
use std::io::{self, BufRead, BufReader, Write};
use std::time::{Duration, Instant};

const DEFAULT_WAIT_MS: u64 = 10_000;
const MAX_WAIT_MS: u64 = 60_000;
const MAX_CAPTURE_ID_BYTES: usize = 160;
const OWNER_POLL: Duration = Duration::from_millis(100);

pub(super) fn supported(reply: &reply_json::Value) -> bool {
    matches!(
        reply.get("capture_protocol"),
        Some(reply_json::Value::Number(version)) if version == "1"
    )
}

fn wait_budget(value: Option<&str>) -> Duration {
    Duration::from_millis(
        value
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_WAIT_MS)
            .min(MAX_WAIT_MS),
    )
}

fn acknowledgment(line: &str, attempt: &str) -> Option<String> {
    let reply = reply_json::parse(line)?;
    if reply.get("kind")?.as_str()? != "rustc-captured"
        || !supported(&reply)
        || reply.get("attempt")?.as_str()? != attempt
        || reply.get("publication_authorized")?.as_bool()?
    {
        return None;
    }
    let capture = reply.get("capture")?.as_str()?;
    if capture.is_empty()
        || capture.len() > MAX_CAPTURE_ID_BYTES
        || !capture.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return None;
    }
    Some(format!(
        "{{\"kind\":\"rustc-capture-ack\",\"attempt\":{},\"capture\":{}}}\n",
        json_string(attempt),
        json_string(capture),
    ))
}

fn abandoned() -> io::Error {
    io::Error::other("compiler output custody was not acknowledged")
}

/// Do not retry a whole report or read_line after a timeout: both can have
/// transferred a prefix. These helpers retain exact partial-write/read progress
/// while rechecking ownership under one absolute deadline for the handoff.
fn prepare_io(
    session: &mut BufReader<ConsultStream>,
    deadline: Instant,
    owned: &impl Fn() -> bool,
) -> io::Result<()> {
    if !owned() {
        return Err(abandoned());
    }
    let now = Instant::now();
    if now >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "compiler output capture deadline expired",
        ));
    }
    session.get_mut().deadline = now
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

fn write_owned(
    session: &mut BufReader<ConsultStream>,
    mut bytes: &[u8],
    deadline: Instant,
    owned: &impl Fn() -> bool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        prepare_io(session, deadline, owned)?;
        match session.get_mut().write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "capture peer stopped accepting bytes",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if retryable_slice(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_owned_receipt(
    session: &mut BufReader<ConsultStream>,
    deadline: Instant,
    owned: &impl Fn() -> bool,
) -> io::Result<String> {
    let mut line = Vec::new();
    loop {
        prepare_io(session, deadline, owned)?;
        let available = match session.fill_buf() {
            Ok(available) => available,
            Err(error) if retryable_slice(&error) => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "capture peer closed before a complete receipt",
            ));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |at| at + 1);
        if (line.len() as u64).saturating_add(count as u64) > MAX_REPLY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capture receipt exceeds its frame bound",
            ));
        }
        line.extend_from_slice(&available[..count]);
        session.consume(count);
        if newline.is_some() {
            return String::from_utf8(line)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
    }
}

/// Spend one deadline on report write, capture receipt and acknowledgment.
/// `owned` rechecks the original caller throughout I/O and before consent.
/// No error here can run a compiler or change the compiler's observed status.
pub(super) fn finish(
    session: &mut BufReader<ConsultStream>,
    attempt: &str,
    report: &str,
    owned: impl Fn() -> bool,
) -> io::Result<()> {
    let setting = std::env::var("RABS_CAPTURE_WAIT_MS").ok();
    finish_with_budget(
        session,
        attempt,
        report,
        wait_budget(setting.as_deref()),
        owned,
    )
}

fn finish_with_budget(
    session: &mut BufReader<ConsultStream>,
    attempt: &str,
    report: &str,
    budget: Duration,
    owned: impl Fn() -> bool,
) -> io::Result<()> {
    if budget.is_zero() || !owned() {
        return Err(abandoned());
    }
    let deadline = Instant::now().checked_add(budget).ok_or_else(abandoned)?;
    write_owned(session, report.as_bytes(), deadline, &owned)?;
    let receipt = read_owned_receipt(session, deadline, &owned)?;
    let acknowledgment = acknowledgment(&receipt, attempt).ok_or_else(abandoned)?;
    // A partially sent ACK is never retried from the start; only its unsent
    // suffix may progress, and only while the caller is still owned. The
    // daemon requires the complete newline-delimited consent frame.
    write_owned(session, acknowledgment.as_bytes(), deadline, &owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Read};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const ATTEMPT: &str = "0123456789abcdef0123456789abcdef";
    const REPORT: &str = "{\"kind\":\"rustc-complete\"}\n";

    fn receipt() -> String {
        format!(
            "{{\"kind\":\"rustc-captured\",\"capture_protocol\":1,\"attempt\":\"{ATTEMPT}\",\
             \"capture\":\"rabs.object:0123\",\"publication_authorized\":false}}\n"
        )
    }

    fn session(stream: UnixStream) -> BufReader<ConsultStream> {
        BufReader::new(ConsultStream {
            stream,
            deadline: Instant::now(),
        })
    }

    fn peer_closed(result: &io::Result<usize>) -> bool {
        result.is_ok()
            || matches!(result, Err(error) if error.kind() == io::ErrorKind::ConnectionReset)
    }

    #[test]
    fn capture_receipt_requires_exact_unambiguous_identity_and_protocol() {
        let expected = format!(
            "{{\"kind\":\"rustc-capture-ack\",\"attempt\":\"{ATTEMPT}\",\
             \"capture\":\"rabs.object:0123\"}}\n"
        );
        assert_eq!(acknowledgment(&receipt(), ATTEMPT), Some(expected));
        assert!(acknowledgment(&receipt(), "another-attempt").is_none());
        for bad in [
            receipt().replace("rustc-captured", "rustc-completion"),
            receipt().replace("\"capture_protocol\":1", "\"capture_protocol\":2"),
            receipt().replace("\"capture_protocol\":1", "\"capture_protocol\":\"1\""),
            receipt().replace(
                "\"publication_authorized\":false",
                "\"publication_authorized\":true",
            ),
            receipt().replace("\"capture\":\"rabs.object:0123\"", "\"capture\":\"\""),
            receipt().replace("\"capture\":\"rabs.object:0123\"", "\"capture\":null"),
            receipt().replace("\"capture\":\"rabs.object:0123\"", "\"capture\":\"a\\nb\""),
            receipt().replace(
                "\"capture_protocol\":1",
                "\"capture_protocol\":1,\"capture_protocol\":1",
            ),
            receipt().replace(
                "\"publication_authorized\":false",
                "\"publication_authorized\":false,\"publication_authorized\":false",
            ),
            receipt().replace("rabs.object:0123", &"x".repeat(MAX_CAPTURE_ID_BYTES + 1)),
        ] {
            assert!(acknowledgment(&bad, ATTEMPT).is_none(), "{bad}");
        }
    }

    #[test]
    fn capture_wait_is_bounded_and_can_disable_cache_population() {
        assert_eq!(wait_budget(None), Duration::from_secs(10));
        assert_eq!(wait_budget(Some("0")), Duration::ZERO);
        assert_eq!(wait_budget(Some("25")), Duration::from_millis(25));
        assert_eq!(
            wait_budget(Some("18446744073709551615")),
            Duration::from_secs(60)
        );
        assert_eq!(wait_budget(Some("invalid")), Duration::from_secs(10));
    }

    #[test]
    fn real_socket_handoff_waits_for_capture_and_preserves_its_identity() {
        let (client, server) = UnixStream::pair().unwrap();
        let (ready, seen) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut server = BufReader::new(server);
            let mut line = String::new();
            server.read_line(&mut line).unwrap();
            assert_eq!(line, REPORT);
            ready.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            server.get_mut().write_all(receipt().as_bytes()).unwrap();
            line.clear();
            server.read_line(&mut line).unwrap();
            line
        });
        let (finished, result) = std::sync::mpsc::channel();
        let wrapper = std::thread::spawn(move || {
            let result = finish_with_budget(
                &mut session(client),
                ATTEMPT,
                REPORT,
                Duration::from_secs(5),
                || true,
            );
            finished.send(result).unwrap();
        });
        seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            result.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        release.send(()).unwrap();
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        wrapper.join().unwrap();
        assert_eq!(
            server.join().unwrap(),
            acknowledgment(&receipt(), ATTEMPT).unwrap()
        );
    }

    #[test]
    fn caller_loss_after_capture_cannot_acknowledge_or_authorize_publication() {
        let owned = Arc::new(AtomicBool::new(true));
        let server_owned = Arc::clone(&owned);
        let (client, mut server) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut report = String::new();
            BufReader::new(server.try_clone().unwrap())
                .read_line(&mut report)
                .unwrap();
            assert_eq!(report, REPORT);
            server_owned.store(false, Ordering::Release);
            // Cancellation may now close before the peer sends its receipt.
            let _ = server.write_all(receipt().as_bytes());
            let mut bytes = Vec::new();
            assert!(peer_closed(&server.read_to_end(&mut bytes)));
            bytes
        });
        let mut client = session(client);
        assert!(
            finish_with_budget(&mut client, ATTEMPT, REPORT, Duration::from_secs(5), || {
                owned.load(Ordering::Acquire)
            })
            .is_err()
        );
        drop(client);
        assert!(
            server.join().unwrap().is_empty(),
            "no capture ACK after caller loss"
        );
    }

    #[test]
    fn missing_receipt_and_expired_budget_never_emit_an_ack() {
        for reply in [None, Some("{\"kind\":\"rustc-completion\"}\n")] {
            let budget = if reply.is_none() {
                Duration::from_millis(30)
            } else {
                Duration::from_secs(5)
            };
            let (client, mut server) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                server
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut report = String::new();
                BufReader::new(server.try_clone().unwrap())
                    .read_line(&mut report)
                    .unwrap();
                assert_eq!(report, REPORT);
                if let Some(reply) = reply {
                    server.write_all(reply.as_bytes()).unwrap();
                }
                let mut remaining = Vec::new();
                server.read_to_end(&mut remaining).unwrap();
                remaining
            });
            let mut client = session(client);
            assert!(finish_with_budget(&mut client, ATTEMPT, REPORT, budget, || true).is_err());
            drop(client);
            assert!(server.join().unwrap().is_empty());
        }
    }

    #[test]
    fn caller_loss_interrupts_a_stalled_or_partial_receipt_without_an_ack() {
        for partial in [b"".as_slice(), b"{\"kind\":\"rustc-captured\""] {
            let owned = Arc::new(AtomicBool::new(true));
            let server_owned = Arc::clone(&owned);
            let (client, mut server) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                server
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut report = String::new();
                BufReader::new(server.try_clone().unwrap())
                    .read_line(&mut report)
                    .unwrap();
                assert_eq!(report, REPORT);
                server.write_all(partial).unwrap();
                server_owned.store(false, Ordering::Release);
                let mut bytes = Vec::new();
                let result = server.read_to_end(&mut bytes);
                (result, bytes)
            });
            let mut client = session(client);
            let error = finish_with_budget(
                &mut client,
                ATTEMPT,
                REPORT,
                Duration::from_secs(10),
                || owned.load(Ordering::Acquire),
            )
            .unwrap_err();
            drop(client);
            let (closed, bytes) = server.join().unwrap();
            assert!(
                peer_closed(&closed),
                "caller loss must not await the capture timeout"
            );
            assert!(bytes.is_empty(), "cancelled caller emitted consent");
            assert_eq!(error.to_string(), abandoned().to_string());
        }
    }

    #[test]
    fn io_slice_timeouts_preserve_partial_receipt_bytes_and_one_ack() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut report = String::new();
            let mut reader = BufReader::new(server.try_clone().unwrap());
            reader.read_line(&mut report).unwrap();
            assert_eq!(report, REPORT);
            let receipt = receipt();
            let at = receipt.len() / 2;
            server.write_all(&receipt.as_bytes()[..at]).unwrap();
            // At least one read slice expires with a JSON prefix accumulated.
            std::thread::sleep(OWNER_POLL * 3);
            server.write_all(&receipt.as_bytes()[at..]).unwrap();
            let mut acknowledgment = String::new();
            reader.read_line(&mut acknowledgment).unwrap();
            let mut extra = Vec::new();
            reader.read_to_end(&mut extra).unwrap();
            (acknowledgment, extra)
        });
        let mut client = session(client);
        finish_with_budget(&mut client, ATTEMPT, REPORT, Duration::from_secs(5), || {
            true
        })
        .unwrap();
        drop(client);
        let (ack, extra) = server.join().unwrap();
        assert_eq!(ack, acknowledgment(&receipt(), ATTEMPT).unwrap());
        assert!(extra.is_empty(), "capture acknowledgment was repeated");
    }

    #[test]
    fn caller_loss_interrupts_a_backpressured_completion_report() {
        let owned = Arc::new(AtomicBool::new(true));
        let server_owned = Arc::clone(&owned);
        let (client, mut server) = UnixStream::pair().unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut prefix = [0; 16];
            server.read_exact(&mut prefix).unwrap();
            server_owned.store(false, Ordering::Release);
            // Do not drain the socket until cancellation has returned. A
            // write_all spanning the whole handoff budget deadlocks here.
            let released = released.recv_timeout(Duration::from_secs(5));
            let mut rest = Vec::new();
            let _ = server.read_to_end(&mut rest);
            (released.is_ok(), prefix, rest)
        });
        let report = format!(
            "{{\"kind\":\"rustc-complete\",\"padding\":\"{}\"}}\n",
            "x".repeat(8 * 1024 * 1024)
        );
        let mut client = session(client);
        let result = finish_with_budget(
            &mut client,
            ATTEMPT,
            &report,
            Duration::from_secs(10),
            || owned.load(Ordering::Acquire),
        );
        let _ = release.send(());
        drop(client);
        let (cancelled_before_drain, prefix, rest) = server.join().unwrap();
        assert!(
            cancelled_before_drain,
            "blocked report ignored caller cancellation"
        );
        assert_eq!(result.unwrap_err().to_string(), abandoned().to_string());
        let mut received = prefix.to_vec();
        received.extend(rest);
        assert!(report.as_bytes().starts_with(&received));
        assert!(received.len() < report.len());
        assert!(
            !received.contains(&b'\n'),
            "incomplete report became a complete frame"
        );
    }

    #[test]
    fn receipt_framing_rejects_truncation_non_utf8_and_oversize() {
        for bytes in [
            receipt().trim_end().as_bytes().to_vec(),
            vec![0xff, b'\n'],
            vec![b'x'; MAX_REPLY_BYTES as usize + 1],
        ] {
            let (client, mut server) = UnixStream::pair().unwrap();
            let sender = std::thread::spawn(move || {
                server
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let _ = server.write_all(&bytes);
            });
            let mut client = session(client);
            assert!(
                read_owned_receipt(
                    &mut client,
                    Instant::now() + Duration::from_secs(5),
                    &|| true
                )
                .is_err()
            );
            drop(client);
            sender.join().unwrap();
        }
    }

    #[test]
    fn stalled_report_resumes_at_the_unsent_suffix_without_duplication() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let report = format!(
            "{{\"kind\":\"rustc-complete\",\"padding\":\"{}\"}}\n",
            "0123456789abcdef".repeat(256 * 1024)
        );
        let expected = report.clone();
        let server = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut received = vec![0; expected.len()];
            // Allow the completion report to encounter socket backpressure
            // and more than one owner-poll timeout before draining it.
            std::thread::sleep(OWNER_POLL * 3);
            server.read_exact(&mut received).unwrap();
            assert_eq!(received, expected.as_bytes());
            server.write_all(receipt().as_bytes()).unwrap();
            let mut remainder = String::new();
            BufReader::new(server)
                .read_to_string(&mut remainder)
                .unwrap();
            remainder
        });
        let mut client = session(client);
        finish_with_budget(
            &mut client,
            ATTEMPT,
            &report,
            Duration::from_secs(5),
            || true,
        )
        .unwrap();
        drop(client);
        assert_eq!(
            server.join().unwrap(),
            acknowledgment(&receipt(), ATTEMPT).unwrap()
        );
    }

    #[test]
    fn continuous_receipt_progress_cannot_extend_the_handoff_deadline() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            server
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            for _ in 0..100 {
                if server.write_all(b" ").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let mut client = session(client);
        let error = read_owned_receipt(
            &mut client,
            Instant::now() + Duration::from_millis(150),
            &|| true,
        )
        .unwrap_err();
        drop(client);
        server.join().unwrap();
        // A per-slice-only deadline instead reaches EOF after the full trickle.
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn buffered_receipt_and_writes_still_require_current_ownership_and_deadline() {
        let (client, mut server) = UnixStream::pair().unwrap();
        server.write_all(receipt().as_bytes()).unwrap();
        let mut client = session(client);
        let future = Instant::now() + Duration::from_secs(5);
        prepare_io(&mut client, future, &|| true).unwrap();
        assert!(!client.fill_buf().unwrap().is_empty());
        assert!(read_owned_receipt(&mut client, future, &|| false).is_err());
        assert_eq!(
            read_owned_receipt(&mut client, Instant::now(), &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(write_owned(&mut client, b"ack\n", future, &|| false).is_err());
        assert!(write_owned(&mut client, b"ack\n", Instant::now(), &|| true).is_err());
        drop(client);
        let mut received = Vec::new();
        server.read_to_end(&mut received).unwrap();
        assert!(received.is_empty());
    }
}
