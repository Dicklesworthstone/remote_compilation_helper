//! Explicit whole-Cargo stderr presentation while a daemon job is running.
//!
//! Worker stdout may contain artifact readiness events and remains behind the
//! ordinary verified completion and installation boundary. Only a contiguous
//! stderr prefix is shown early. Its digest is checked against both fully
//! verified final streams before any stdout or remaining stderr is emitted.

use super::{CLIENT_BUDGET, exchange_until, follow, invalid, remaining};
use asupersync::net::unix::UnixStream;
use rabs_asupersync::stream_drain::preview::MAX_PREVIEW_BYTES;
use rabsd::coord::prepared_operation::{CARGO_STDERR_PREVIEW_VERSION, DiagnosticStream};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::time::{Duration, Instant};

/// Fixed-size state, independent of output volume. A lost range permanently
/// ends live presentation; the verified result later supplies that entire
/// unseen suffix. A partial console write poisons this invocation instead.
#[derive(Default)]
struct StderrPrefix {
    bytes: u64,
    digest: Sha256,
    gap: bool,
    poisoned: bool,
    exposed: bool,
}

impl StderrPrefix {
    fn append(
        &mut self,
        offset: u64,
        skipped: u64,
        bytes: &[u8],
        output: &mut impl Write,
    ) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid("live stderr console delivery already failed"));
        }
        if bytes.len() > MAX_PREVIEW_BYTES {
            return Err(invalid("live stderr segment exceeds its bound"));
        }
        if self.gap {
            return Ok(());
        }
        if offset != self.bytes || skipped != 0 {
            self.gap = true;
            return Ok(());
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let end = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("live stderr prefix length overflow"))?;
        // Even a failed write or flush may have exposed bytes. Never retry the
        // segment, reset its digest, or proceed to final replay after failure.
        self.poisoned = true;
        self.exposed = true;
        output.write_all(bytes)?;
        output.flush()?;
        self.digest.update(bytes);
        self.bytes = end;
        self.poisoned = false;
        Ok(())
    }

    /// The shared follower has already validated this complete reply's exact
    /// operation, request, attempt, streams and monotonic cursors. Decode only
    /// stderr; stdout is never offered to a console from this callback.
    fn observe(&mut self, event: &Value, output: &mut impl Write) -> io::Result<()> {
        let segments = event["segments"]
            .as_array()
            .filter(|segments| segments.len() <= 2)
            .ok_or_else(|| invalid("invalid live stderr preview"))?;
        for segment in segments {
            if segment["stream"] != "stderr" {
                continue;
            }
            let number = |name: &str| {
                segment[name]
                    .as_u64()
                    .ok_or_else(|| invalid("invalid live stderr cursor"))
            };
            let encoded = segment["data_hex"]
                .as_str()
                .filter(|value| {
                    value.len() <= 2 * MAX_PREVIEW_BYTES
                        && value.len().is_multiple_of(2)
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| invalid("invalid live stderr bytes"))?;
            let mut bytes = Vec::with_capacity(encoded.len() / 2);
            for pair in encoded.as_bytes().as_chunks::<2>().0 {
                let digit = |byte: u8| {
                    if byte <= b'9' {
                        byte - b'0'
                    } else {
                        byte - b'a' + 10
                    }
                };
                bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
            }
            self.append(number("offset")?, number("skipped_bytes")?, &bytes, output)?;
        }
        Ok(())
    }

    fn descriptor(&self) -> io::Result<DiagnosticStream> {
        if self.poisoned {
            return Err(invalid("partial live stderr cannot be replayed"));
        }
        Ok(DiagnosticStream {
            bytes: self.bytes,
            sha256: rabs_protocol::raw_bytes::encode_hex(&self.digest.clone().finalize()),
        })
    }
}

fn cargo_status(reply: &Value) -> io::Result<()> {
    if reply["kind"] != "prepared-operation"
        || reply["operation"]["live_stderr"] != CARGO_STDERR_PREVIEW_VERSION
    {
        return Err(invalid(
            "live stderr requires the daemon's native whole-Cargo diagnostics contract",
        ));
    }
    Ok(())
}

fn deliver(
    id: &str,
    until: Instant,
    mut exchange: impl FnMut(&Value, Instant) -> io::Result<Value>,
    sleep: impl FnMut(Duration),
    prefix: &mut StderrPrefix,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<i32> {
    let mut exchange = |request: &Value, deadline| {
        let reply = exchange(request, deadline)?;
        if request["kind"] == "prepared-status" {
            cargo_status(&reply)?;
        }
        Ok(reply)
    };
    let completion = follow::follow(id, until, &mut exchange, sleep, |event| {
        remaining(until)?;
        prefix.observe(event, stderr)?;
        remaining(until).map(|_| ())
    })?;
    let (status, proof) = match completion {
        follow::Completion::CancelledBeforeStart { status } => {
            if prefix.exposed {
                return Err(invalid("unexecuted job already exposed live stderr"));
            }
            (status, None)
        }
        follow::Completion::Ready { status, proof } => (status, Some(*proof)),
    };
    let snapshot = proof
        .as_ref()
        .map(|proof| {
            proof
                .snapshot(until)?
                .after_stderr_prefix(&prefix.descriptor()?, until)
        })
        .transpose()?;
    // The job can be reconciled while its files are snapshotted. Recheck the
    // exact terminal attempt before exposing readiness-bearing Cargo stdout.
    let reply = exchange(
        &json!({"kind":"prepared-status", "operation_id":id}),
        until.min(Instant::now() + CLIENT_BUDGET),
    )?;
    remaining(until)?;
    follow::final_status(&status, &reply, id, proof.as_ref())?;
    match (proof, snapshot) {
        (Some(proof), Some(snapshot)) => {
            prefix.exposed = true;
            snapshot.emit(stdout, stderr, until)?;
            Ok(i32::from(proof.exit_code))
        }
        (None, None) => Ok(130),
        _ => Err(invalid(
            "live stderr completion lacks its verified snapshot",
        )),
    }
}

pub(super) fn run(id: &str, budget: Duration, socket: &str) -> i32 {
    let until = Instant::now() + budget;
    let mut prefix = StderrPrefix::default();
    let result = (|| -> io::Result<i32> {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .map_err(|error| io::Error::other(format!("live stderr runtime: {error:?}")))?;
        // Console writes run on this waiting client, never the daemon's
        // transport reactor or execution owner. A stalled reader cannot stop
        // worker pipe drains, lease renewals or cancellation handling.
        deliver(
            id,
            until,
            |request, deadline| {
                rabs_asupersync::daemon_runtime::block_on_top_level(
                    &runtime,
                    exchange_until(UnixStream::connect(socket), request, deadline),
                )
            },
            std::thread::sleep,
            &mut prefix,
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
        )
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                json!({
                    "kind":"prepared-client-error", "operation_id":id,
                    "detail":error.to_string(), "outcome_unconfirmed":true,
                    "diagnostics_may_have_been_exposed":prefix.exposed,
                    "reexecute":false,
                })
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn status(state: &str) -> Value {
        json!({"kind":"prepared-operation", "operation":{
            "id":ID, "request_sha256":"ab".repeat(32), "state":state, "attempt":1,
            "mode":"execute", "request_id":7, "worker":"worker",
            "worker_spki_sha256":"01".repeat(32), "delivery":"/delivery",
            "execution_may_have_run":true, "live_stderr":CARGO_STDERR_PREVIEW_VERSION,
        }})
    }

    fn segment(stream: &str, offset: u64, bytes: &[u8], skipped: u64) -> Value {
        json!({"stream":stream, "offset":offset, "next_offset":offset + bytes.len() as u64,
            "data_hex":rabs_protocol::raw_bytes::encode_hex(bytes),
            "skipped_bytes":skipped, "observed_bytes":offset + bytes.len() as u64})
    }

    fn preview(segments: Vec<Value>) -> Value {
        json!({"kind":"prepared-preview", "operation_id":ID, "request_sha256":"ab".repeat(32),
            "attempt":1, "available":true, "active":true, "reason":null,
            "segments":segments, "complete":false, "publication_authorized":false})
    }

    #[test]
    fn contiguous_binary_stderr_is_presented_while_cargo_readiness_stdout_is_withheld() {
        let mut replies = VecDeque::from([
            status("running"),
            preview(vec![
                segment(
                    "stdout",
                    0,
                    br#"{"reason":"compiler-artifact","fresh":true}"#,
                    0,
                ),
                segment("stderr", 0, b"Compiling\0\xff\n", 0),
            ]),
            status("uncertain"),
        ]);
        let mut prefix = StderrPrefix::default();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let mut queries = Vec::new();
        let result = deliver(
            ID,
            deadline(),
            |query, _| {
                queries.push(query.clone());
                Ok(replies.pop_front().unwrap())
            },
            |_| {},
            &mut prefix,
            &mut stdout,
            &mut stderr,
        );
        assert!(result.unwrap_err().to_string().contains("uncertain"));
        assert_eq!(stderr, b"Compiling\0\xff\n");
        assert!(stdout.is_empty());
        assert!(prefix.exposed);
        assert_eq!(prefix.descriptor().unwrap().bytes, stderr.len() as u64);
        assert!(replies.is_empty());
        assert!(queries.iter().all(|query| matches!(
            query["kind"].as_str(),
            Some("prepared-status" | "prepared-preview")
        )));
    }

    #[test]
    fn missing_or_changed_cargo_capability_refuses_without_transcript_fallback() {
        for changed in [Value::Null, json!(true), json!("cargo-diagnostics-v2")] {
            let mut refused = status("running");
            refused["operation"]["live_stderr"] = changed;
            let mut calls = 0;
            let mut prefix = StderrPrefix::default();
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            let result = deliver(
                ID,
                deadline(),
                |query, _| {
                    assert_eq!(query["kind"], "prepared-status");
                    calls += 1;
                    Ok(refused.clone())
                },
                |_| panic!("unsupported jobs cannot enter the polling loop"),
                &mut prefix,
                &mut stdout,
                &mut stderr,
            );
            assert!(result.is_err());
            assert_eq!(calls, 1);
            assert!(stdout.is_empty() && stderr.is_empty());
            assert!(!prefix.exposed);
        }
    }

    #[test]
    fn a_gap_permanently_freezes_the_emitted_prefix_without_losing_its_digest() {
        let mut prefix = StderrPrefix::default();
        let mut output = Vec::new();
        prefix.append(0, 0, b"first\0", &mut output).unwrap();
        let before = prefix.descriptor().unwrap();
        prefix.append(10, 4, b"tail", &mut output).unwrap();
        prefix.append(14, 0, b"more", &mut output).unwrap();
        // Even an apparent return to the prefix cannot resume a lossy stream.
        prefix.append(6, 0, b"replacement", &mut output).unwrap();
        assert!(prefix.gap);
        assert_eq!(output, b"first\0");
        assert_eq!(prefix.descriptor().unwrap(), before);
    }

    #[test]
    fn invalid_second_stream_is_rejected_before_any_live_stderr_write() {
        let mut bad = segment("stdout", 0, b"artifact", 0);
        bad["next_offset"] = json!(99);
        let mut replies = VecDeque::from([
            status("running"),
            preview(vec![segment("stderr", 0, b"must remain hidden", 0), bad]),
        ]);
        let mut prefix = StderrPrefix::default();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        assert!(
            deliver(
                ID,
                deadline(),
                |_, _| Ok(replies.pop_front().unwrap()),
                |_| panic!("invalid preview cannot advance"),
                &mut prefix,
                &mut stdout,
                &mut stderr,
            )
            .is_err()
        );
        assert!(!prefix.exposed);
        assert!(stdout.is_empty() && stderr.is_empty());
    }

    struct BrokenConsole {
        bytes: Vec<u8>,
        calls: usize,
        fail_flush: bool,
    }

    impl Write for BrokenConsole {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.fail_flush {
                self.bytes.extend_from_slice(bytes);
                return Ok(bytes.len());
            }
            if self.calls == 1 {
                self.bytes.extend_from_slice(&bytes[..1]);
                Ok(1)
            } else {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed console"))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "failed console flush",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn partial_write_or_failed_flush_poison_the_prefix_and_never_retry() {
        for fail_flush in [false, true] {
            let mut output = BrokenConsole {
                bytes: Vec::new(),
                calls: 0,
                fail_flush,
            };
            let mut prefix = StderrPrefix::default();
            assert!(prefix.append(0, 0, b"warning", &mut output).is_err());
            let calls = output.calls;
            let bytes = output.bytes.clone();
            assert!(prefix.exposed && prefix.poisoned);
            assert!(prefix.descriptor().is_err());
            assert!(prefix.append(0, 0, b"warning", &mut output).is_err());
            assert_eq!(output.calls, calls);
            assert_eq!(output.bytes, bytes);
        }
    }

    #[test]
    fn result_only_recovery_keeps_one_live_prefix_and_never_submits_or_cancels() {
        let mut recovering = status("running");
        recovering["operation"]["attempt"] = json!(2);
        recovering["operation"]["mode"] = json!("resume");
        recovering["operation"]["automatic_recoveries"] = json!(1);
        recovering["operation"]["recovery_origin_attempt"] = json!(1);
        let mut uncertain = recovering.clone();
        uncertain["operation"]["state"] = json!("uncertain");
        let mut replies = VecDeque::from([
            status("running"),
            preview(vec![segment("stderr", 0, b"only once", 0)]),
            recovering,
            uncertain,
        ]);
        let mut queries = Vec::new();
        let mut prefix = StderrPrefix::default();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let result = deliver(
            ID,
            deadline(),
            |query, _| {
                queries.push(query.clone());
                Ok(replies.pop_front().unwrap())
            },
            |_| {},
            &mut prefix,
            &mut stdout,
            &mut stderr,
        );
        assert!(result.unwrap_err().to_string().contains("uncertain"));
        assert_eq!(stderr, b"only once");
        assert!(stdout.is_empty());
        assert_eq!(
            queries
                .iter()
                .filter(|query| query["kind"] == "prepared-preview")
                .count(),
            1
        );
        assert!(queries.iter().all(|query| matches!(
            query["kind"].as_str(),
            Some("prepared-status" | "prepared-preview")
        )));
    }

    #[cfg(unix)]
    mod verified_delivery {
        use super::*;
        use rabsd::coord::prepared_operation::PreparedCompletion;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use std::sync::{Arc, Mutex};

        const STDOUT: &[u8] = b"{\"reason\":\"compiler-artifact\"}\n\0\xff";
        const STDERR: &[u8] = b"progress\0\xff\nremaining diagnostics\n";

        fn digest(bytes: &[u8]) -> String {
            rabs_protocol::raw_bytes::encode_hex(&Sha256::digest(bytes))
        }

        fn private_file(path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        // This fixture scripts the trusted daemon boundary, not execution. Real
        // private receipt/diagnostic files still pass every production snapshot,
        // identity, complete-stream, prefix and final-status check in deliver.
        fn fixture() -> (tempfile::TempDir, PreparedCompletion) {
            let owner = tempfile::tempdir().unwrap();
            let delivery = owner.path().canonicalize().unwrap().join("delivery");
            fs::create_dir(&delivery).unwrap();
            fs::create_dir(delivery.join("diagnostics")).unwrap();
            private_file(&delivery.join("diagnostics/stdout"), STDOUT);
            private_file(&delivery.join("diagnostics/stderr"), STDERR);
            let receipt = json!({
                "kind":"verified-worker-delivery", "request_id":7,
                "request_sha256":"cd".repeat(32), "worker_id":"worker",
                "worker_spki_sha256":"01".repeat(32), "transport_authenticated":true,
                "publication_authorized":false, "reexecute":false,
                "exit_code":0, "stop_reason":null,
                "stdout_bytes":STDOUT.len(), "stdout_sha256":digest(STDOUT),
                "stderr_bytes":STDERR.len(), "stderr_sha256":digest(STDERR),
            });
            let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
            private_file(&delivery.join("delivery.json"), &receipt_bytes);
            let proof = PreparedCompletion {
                version: 1,
                operation_id: ID.into(),
                request_sha256: "ab".repeat(32),
                delivery_request_sha256: "cd".repeat(32),
                receipt_sha256: digest(&receipt_bytes),
                request_id: 7,
                worker: "worker".into(),
                worker_spki_sha256: "01".repeat(32),
                delivery,
                exit_code: 0,
                stop_reason: None,
                outputs_installed: true,
                stdout: DiagnosticStream {
                    bytes: STDOUT.len() as u64,
                    sha256: digest(STDOUT),
                },
                stderr: DiagnosticStream {
                    bytes: STDERR.len() as u64,
                    sha256: digest(STDERR),
                },
            };
            (owner, proof)
        }

        fn delivered_status(proof: &PreparedCompletion, state: &str) -> Value {
            let mut reply = status(state);
            reply["operation"]["delivery"] = json!(proof.delivery);
            reply["operation"]["exit_code"] = json!(proof.exit_code);
            reply["operation"]["stop_reason"] = json!(proof.stop_reason);
            reply["operation"]["outputs_installed"] = json!(proof.outputs_installed);
            reply
        }

        fn replies(proof: &PreparedCompletion, prefix: &[u8]) -> VecDeque<Value> {
            VecDeque::from([
                delivered_status(proof, "running"),
                preview(vec![
                    segment("stdout", 0, STDOUT, 0),
                    segment("stderr", 0, prefix, 0),
                ]),
                delivered_status(proof, "completed"),
                json!({"kind":"prepared-completion", "operation_id":ID,
                    "completion":proof, "publication_authorized":false, "reexecute":false}),
                delivered_status(proof, "completed"),
            ])
        }

        #[derive(Clone, Default)]
        struct Console(Arc<Mutex<Vec<u8>>>);

        impl Write for Console {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        #[test]
        fn successful_delivery_exposes_only_stderr_early_and_each_final_stream_once() {
            let (_owner, proof) = fixture();
            let mut rows = replies(&proof, &STDERR[..10]);
            let mut stdout = Console::default();
            let mut stderr = Console::default();
            let out_observer = stdout.clone();
            let err_observer = stderr.clone();
            let mut prefix = StderrPrefix::default();
            let mut count = 0;
            let code = deliver(
                ID,
                deadline(),
                |query, _| {
                    count += 1;
                    if count >= 3 {
                        assert!(out_observer.0.lock().unwrap().is_empty());
                        assert_eq!(*err_observer.0.lock().unwrap(), &STDERR[..10]);
                    }
                    if count == 5 {
                        assert_eq!(query["kind"], "prepared-status");
                    }
                    Ok(rows.pop_front().unwrap())
                },
                |_| {},
                &mut prefix,
                &mut stdout,
                &mut stderr,
            )
            .unwrap();
            assert_eq!(code, 0);
            assert_eq!(count, 5);
            assert!(rows.is_empty());
            assert_eq!(*out_observer.0.lock().unwrap(), STDOUT);
            assert_eq!(*err_observer.0.lock().unwrap(), STDERR);
        }

        #[test]
        fn a_false_prefix_refuses_before_final_stdout_without_retrying_or_replaying() {
            let (_owner, proof) = fixture();
            let mut rows = replies(&proof, b"different!");
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            let mut prefix = StderrPrefix::default();
            let error = deliver(
                ID,
                deadline(),
                |_, _| Ok(rows.pop_front().unwrap()),
                |_| {},
                &mut prefix,
                &mut stdout,
                &mut stderr,
            )
            .unwrap_err();
            assert!(error.to_string().contains("prefix differs"));
            assert!(stdout.is_empty());
            assert_eq!(stderr, b"different!");
            assert_eq!(rows.len(), 1, "no final-status retry after a mismatch");
        }

        #[test]
        fn a_live_gap_is_filled_exactly_once_from_the_verified_final_suffix() {
            let (_owner, proof) = fixture();
            let mut rows = replies(&proof, &STDERR[..10]);
            rows.insert(2, delivered_status(&proof, "running"));
            rows.insert(3, preview(vec![segment("stderr", 15, &STDERR[15..20], 5)]));
            rows.insert(4, delivered_status(&proof, "running"));
            rows.insert(5, preview(vec![segment("stderr", 20, &STDERR[20..], 0)]));
            let mut stdout = Console::default();
            let mut stderr = Console::default();
            let err_observer = stderr.clone();
            let mut prefix = StderrPrefix::default();
            let mut count = 0;
            let code = deliver(
                ID,
                deadline(),
                |_, _| {
                    count += 1;
                    if count >= 3 {
                        assert_eq!(*err_observer.0.lock().unwrap(), &STDERR[..10]);
                    }
                    Ok(rows.pop_front().unwrap())
                },
                |_| {},
                &mut prefix,
                &mut stdout,
                &mut stderr,
            )
            .unwrap();
            assert_eq!(code, 0);
            assert!(prefix.gap);
            assert_eq!(prefix.descriptor().unwrap().bytes, 10);
            assert!(rows.is_empty());
            assert_eq!(*stdout.0.lock().unwrap(), STDOUT);
            assert_eq!(*stderr.0.lock().unwrap(), STDERR);
        }

        #[test]
        fn changed_final_files_refuse_stdout_after_the_live_prefix() {
            for mutation in ["stderr-bytes", "stderr-mode", "receipt", "stdout-link"] {
                let (owner, proof) = fixture();
                match mutation {
                    "stderr-bytes" => {
                        private_file(&proof.delivery.join("diagnostics/stderr"), b"corrupt");
                    }
                    "stderr-mode" => {
                        fs::set_permissions(
                            proof.delivery.join("diagnostics/stderr"),
                            fs::Permissions::from_mode(0o644),
                        )
                        .unwrap();
                    }
                    "receipt" => private_file(&proof.delivery.join("delivery.json"), b"{}"),
                    "stdout-link" => {
                        fs::hard_link(
                            proof.delivery.join("diagnostics/stdout"),
                            owner.path().join("alias"),
                        )
                        .unwrap();
                    }
                    _ => unreachable!(),
                }
                let mut rows = replies(&proof, &STDERR[..10]);
                let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
                let mut prefix = StderrPrefix::default();
                assert!(
                    deliver(
                        ID,
                        deadline(),
                        |_, _| Ok(rows.pop_front().unwrap()),
                        |_| {},
                        &mut prefix,
                        &mut stdout,
                        &mut stderr,
                    )
                    .is_err(),
                    "{mutation}"
                );
                assert!(stdout.is_empty(), "{mutation}");
                assert_eq!(stderr, &STDERR[..10]);
            }
        }
    }
}
