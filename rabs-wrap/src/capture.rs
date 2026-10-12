//! Output-custody handoff for an admitted local compile (bd-k52xe).
//!
//! Cargo may release or rewrite a unit's outputs as soon as its wrapper exits.
//! The daemon must therefore finish copying the outputs BEFORE the wrapper
//! acknowledges their capture. A completion report alone does not authorize
//! publication. Timeouts abandon cache population, never repeat the compile.

use super::{ConsultStream, MAX_REPLY_BYTES, json_string, read_reply_bounded, reply_json};
use std::io::{self, BufReader, Write};
use std::time::{Duration, Instant};

const DEFAULT_WAIT_MS: u64 = 10_000;
const MAX_WAIT_MS: u64 = 60_000;
const MAX_CAPTURE_ID_BYTES: usize = 160;

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

/// Spend one deadline on report write, capture receipt and acknowledgment.
/// `owned` rechecks the original caller after capture, before granting consent.
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
    let abandoned = || io::Error::other("compiler output custody was not acknowledged");
    if budget.is_zero() || !owned() {
        return Err(abandoned());
    }
    session.get_mut().deadline = Instant::now().checked_add(budget).ok_or_else(abandoned)?;
    session.get_mut().write_all(report.as_bytes())?;
    let receipt = read_reply_bounded(session, MAX_REPLY_BYTES)?;
    let acknowledgment = acknowledgment(&receipt, attempt).ok_or_else(abandoned)?;
    if !owned() {
        return Err(abandoned());
    }
    // ConsultStream checks the SAME deadline before each partial write. An
    // expired or partially sent ACK cannot authorize a complete publication.
    session.get_mut().write_all(acknowledgment.as_bytes())
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
            server.write_all(receipt().as_bytes()).unwrap();
            let mut bytes = Vec::new();
            server.read_to_end(&mut bytes).unwrap();
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
}
