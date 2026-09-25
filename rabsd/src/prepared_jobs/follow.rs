//! Read-only, explicitly incomplete live diagnostics for one prepared attempt.
//! Preview bytes stay inside NDJSON records. A verified terminal result is a
//! separate event; it never silently replays or completes the preview transcript.

use super::{CLIENT_BUDGET, exchange_until, invalid, remaining, wait};
use asupersync::net::unix::UnixStream;
use rabsd::coord::prepared_operation::PreparedCompletion;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(200);
const COMPLETION_BUDGET: Duration = Duration::from_secs(300);
const MAX_PREVIEW_BYTES: usize = 8 * 1024;

fn arguments(args: &[String]) -> Result<(&str, Duration), &'static str> {
    if !matches!(args.len(), 2 | 3) || args[0] != "--job-follow" {
        return Err("usage: rabsd --job-follow <id32hex> [timeout-seconds]");
    }
    let id = &args[1];
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("job ID must be exactly 32 lowercase hexadecimal digits");
    }
    let seconds = match args.get(2) {
        None => 3600,
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse::<u64>().map_err(|_| "invalid follow timeout")?
        }
        Some(_) => return Err("follow timeout must be decimal seconds"),
    };
    if seconds == 0 || seconds > 86400 {
        return Err("follow timeout must be between 1 and 86400 seconds");
    }
    Ok((id, Duration::from_secs(seconds)))
}

#[derive(Default)]
struct Cursor {
    next: [u64; 2],
    observed: [u64; 2],
}

impl Cursor {
    fn request(&self, id: &str, digest: &str, attempt: u64) -> Value {
        json!({"kind":"prepared-preview", "operation_id":id,
            "request_sha256":digest, "attempt":attempt,
            "stdout_offset":self.next[0], "stderr_offset":self.next[1]})
    }

    fn accept(&mut self, reply: &Value, id: &str, digest: &str, attempt: u64) -> io::Result<()> {
        if !reply.as_object().is_some_and(|fields| fields.len() == 10)
            || reply["kind"] != "prepared-preview"
            || reply["operation_id"] != id
            || reply["request_sha256"] != digest
            || reply["attempt"].as_u64() != Some(attempt)
            || reply["complete"] != false
            || reply["publication_authorized"] != false
            || reply["active"].as_bool().is_none()
        {
            return Err(invalid(
                "preview differs from the selected incomplete job attempt",
            ));
        }
        let segments = reply["segments"]
            .as_array()
            .filter(|segments| segments.len() <= 2)
            .ok_or_else(|| invalid("invalid preview segments"))?;
        match reply["available"].as_bool() {
            Some(false)
                if segments.is_empty()
                    && reply["active"] == false
                    && matches!(reply["reason"].as_str(), Some("unavailable" | "busy")) =>
            {
                return Ok(());
            }
            Some(true) if reply["reason"].is_null() => {}
            _ => return Err(invalid("invalid preview availability")),
        }
        let mut seen = [false; 2];
        let mut next = self.next;
        let mut observed = self.observed;
        for segment in segments {
            if !segment.as_object().is_some_and(|fields| fields.len() == 6) {
                return Err(invalid("invalid preview segment fields"));
            }
            let lane = match segment["stream"].as_str() {
                Some("stdout") => 0,
                Some("stderr") => 1,
                _ => return Err(invalid("unknown preview stream")),
            };
            if seen[lane] {
                return Err(invalid("duplicate preview stream"));
            }
            seen[lane] = true;
            let number = |field: &str| {
                segment[field]
                    .as_u64()
                    .ok_or_else(|| invalid(format!("invalid preview {field}")))
            };
            let offset = number("offset")?;
            let end = number("next_offset")?;
            let skipped = number("skipped_bytes")?;
            let total = number("observed_bytes")?;
            let data = segment["data_hex"]
                .as_str()
                .filter(|value| {
                    value.len() <= MAX_PREVIEW_BYTES * 2
                        && value.len() % 2 == 0
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| invalid("invalid bounded binary preview"))?;
            if offset.checked_sub(self.next[lane]) != Some(skipped)
                || offset.checked_add((data.len() / 2) as u64) != Some(end)
                || end > total
                || total < self.observed[lane]
            {
                return Err(invalid("preview cursor, gap, or observed length changed"));
            }
            // Observed output may be ahead of this bounded returned range. It
            // never advances the delivery cursor or claims those bytes printed.
            next[lane] = end;
            observed[lane] = total;
        }
        self.next = next;
        self.observed = observed;
        Ok(())
    }
}

#[derive(Debug)]
enum Completion {
    CancelledBeforeStart {
        status: Value,
    },
    Ready {
        status: Value,
        proof: PreparedCompletion,
    },
}

fn cancelled_before_start(status: &Value) -> bool {
    status["state"] == "cancelled"
        && status["execution_may_have_run"] == false
        && status["exit_code"] == 130
        && status["cancel_requested"] == true
        && status["outputs_installed"] == false
        && status["stop_reason"] == "cancelled"
}

fn selected_status(reply: &Value, id: &str) -> io::Result<(String, u64)> {
    if reply["kind"] != "prepared-operation" {
        return Err(invalid(
            "daemon did not return the selected job; inspect the same job ID",
        ));
    }
    let status = &reply["operation"];
    let digest = wait::fingerprint(status, id)?;
    let attempt = status["attempt"]
        .as_u64()
        .ok_or_else(|| invalid("job status lacks its attempt identity"))?;
    Ok((digest, attempt))
}

fn followed_owner(status: &Value, attempt: u64) -> io::Result<u64> {
    let recoveries = match status.get("automatic_recoveries") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| invalid("invalid recovery count"))?,
    };
    let pending = match status.get("recovery_pending") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| invalid("invalid recovery readiness"))?,
    };
    if pending && (status["state"] != "queued" || recoveries == 0) {
        return Err(invalid("invalid queued recovery identity"));
    }
    match status.get("recovery_origin_attempt") {
        None | Some(Value::Null) if !pending => Ok(attempt),
        Some(value) => value
            .as_u64()
            .filter(|origin| {
                *origin > 0
                    && *origin <= attempt
                    && recoveries > 0
                    && matches!(status["mode"].as_str(), Some("resume" | "acknowledge"))
            })
            .ok_or_else(|| invalid("invalid automatic recovery origin")),
        None => Err(invalid(
            "queued recovery lacks its original execution identity",
        )),
    }
}

fn follow(
    id: &str,
    until: Instant,
    mut exchange: impl FnMut(&Value, Instant) -> io::Result<Value>,
    mut sleep: impl FnMut(Duration),
    mut emit: impl FnMut(&Value) -> io::Result<()>,
) -> io::Result<Completion> {
    let mut identity: Option<String> = None;
    let mut owner = None;
    let mut cursor = Cursor::default();
    let mut previous_preview = None;
    loop {
        remaining(until)?;
        let reply = exchange(
            &json!({"kind":"prepared-status", "operation_id":id}),
            until.min(Instant::now() + CLIENT_BUDGET),
        )?;
        remaining(until)?;
        let (digest, current_attempt) = selected_status(&reply, id)?;
        let status = &reply["operation"];
        let current_owner = followed_owner(status, current_attempt)?;
        if identity
            .as_ref()
            .is_some_and(|expected| expected != &digest)
        {
            return Err(invalid("job request identity changed while following"));
        }
        if owner.is_some_and(|previous| {
            previous != current_owner && !(previous == 0 && current_owner == 1)
        }) {
            return Err(invalid(
                "job attempt changed; start a separate explicit follow",
            ));
        }
        identity = Some(digest.clone());
        owner = Some(current_owner);
        match status["state"].as_str() {
            Some("queued" | "running" | "cancelling") => {
                if current_attempt == 0 && status["state"] != "queued" {
                    return Err(invalid("active job lacks a claimed attempt"));
                }
                if current_attempt != 0
                    && !matches!(status["mode"].as_str(), Some("resume" | "acknowledge"))
                {
                    let preview = exchange(
                        &cursor.request(id, &digest, current_attempt),
                        until.min(Instant::now() + CLIENT_BUDGET),
                    )?;
                    remaining(until)?;
                    cursor.accept(&preview, id, &digest, current_attempt)?;
                    if previous_preview.as_ref() != Some(&preview) {
                        emit(&preview)?;
                        previous_preview = Some(preview);
                    }
                }
                sleep(remaining(until)?.min(POLL_INTERVAL));
            }
            Some("uncertain") => {
                return Err(invalid(
                    "job outcome is uncertain; explicit reconciliation is required, never reexecution",
                ));
            }
            Some("failed_before_start") => {
                return Err(invalid(
                    "job failed before execution; inspect the retained job status",
                ));
            }
            Some("cancelled") if status["execution_may_have_run"] == false => {
                if !cancelled_before_start(status) {
                    return Err(invalid("inconsistent pre-execution cancellation"));
                }
                return Ok(Completion::CancelledBeforeStart {
                    status: status.clone(),
                });
            }
            Some("completed" | "cancelled") => {
                if current_attempt == 0 || status["execution_may_have_run"] != true {
                    return Err(invalid("terminal job lacks executed-result evidence"));
                }
                let reply = exchange(
                    &json!({"kind":"prepared-completion", "operation_id":id,
                    "request_sha256":digest}),
                    until.min(Instant::now() + COMPLETION_BUDGET),
                )?;
                remaining(until)?;
                if reply["kind"] != "prepared-completion"
                    || reply["operation_id"] != id
                    || reply["publication_authorized"] != false
                    || reply["reexecute"] != false
                {
                    return Err(invalid(
                        "daemon could not verify the complete local delivery",
                    ));
                }
                let proof: PreparedCompletion =
                    serde_json::from_value(reply["completion"].clone())?;
                wait::matches_status(&proof, status, id, &digest)?;
                return Ok(Completion::Ready {
                    status: status.clone(),
                    proof,
                });
            }
            _ => return Err(invalid("unknown job state; refusing follow completion")),
        }
    }
}

fn final_status(
    observed: &Value,
    reply: &Value,
    id: &str,
    proof: Option<&PreparedCompletion>,
) -> io::Result<()> {
    let (digest, attempt) = selected_status(reply, id)?;
    if observed["request_sha256"] != digest || observed["attempt"].as_u64() != Some(attempt) {
        return Err(invalid(
            "job identity or attempt changed during completion verification",
        ));
    }
    match proof {
        Some(proof) => wait::matches_status(proof, &reply["operation"], id, &digest),
        None if cancelled_before_start(&reply["operation"]) => Ok(()),
        None => Err(invalid("job cancellation changed during follow completion")),
    }
}

fn write_event(output: &mut impl Write, event: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, event)?;
    output.write_all(b"\n")?;
    output.flush()
}

pub(super) fn run(args: &[String], socket: &str) -> i32 {
    let (id, budget) = match arguments(args) {
        Ok(parsed) => parsed,
        Err(detail) => {
            eprintln!("rabsd: {detail}");
            return 2;
        }
    };
    let until = Instant::now() + budget;
    let mut exposed = false;
    let result = (|| -> io::Result<i32> {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .map_err(|error| io::Error::other(format!("job follow runtime: {error:?}")))?;
        let mut exchange = |request: &Value, deadline| {
            runtime.block_on(exchange_until(
                UnixStream::connect(socket),
                request,
                deadline,
            ))
        };
        let mut output = io::stdout().lock();
        let completion = follow(id, until, &mut exchange, std::thread::sleep, |event| {
            // Even a failed write can expose part of a record. Do not retry it.
            exposed = true;
            write_event(&mut output, event)
        })?;
        let (status, proof, exit_code) = match completion {
            Completion::CancelledBeforeStart { status } => (status, None, 130),
            Completion::Ready { status, proof } => {
                let _snapshot = proof.snapshot(until)?;
                remaining(until)?;
                let code = i32::from(proof.exit_code);
                (status, Some(proof), code)
            }
        };
        // Recovery can change the operation during the filesystem snapshot.
        // Recheck the observed attempt before naming a verified completion.
        let reply = exchange(
            &json!({"kind":"prepared-status", "operation_id":id}),
            until.min(Instant::now() + CLIENT_BUDGET),
        )?;
        remaining(until)?;
        final_status(&status, &reply, id, proof.as_ref())?;
        exposed = true;
        write_event(
            &mut output,
            &json!({
                "kind":"prepared-follow-completion", "operation_id":id,
                "request_sha256":status["request_sha256"], "attempt":status["attempt"],
                "state":status["state"], "exit_code":exit_code,
                "execution_may_have_run":status["execution_may_have_run"],
                "completion_verified":proof.is_some(), "completion":proof,
                "preview_complete":false, "publication_authorized":false, "reexecute":false,
            }),
        )?;
        Ok(exit_code)
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
                    "preview_may_have_been_exposed":exposed, "reexecute":false,
                })
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }
    fn status(state: &str, attempt: u64) -> Value {
        json!({"kind":"prepared-operation", "operation":{
            "id":ID, "request_sha256":"ab".repeat(32), "state":state, "attempt":attempt,
            "request_id":7, "worker":"worker", "worker_spki_sha256":"01".repeat(32),
            "delivery":"/delivery", "exit_code":1, "stop_reason":null,
            "outputs_installed":false, "execution_may_have_run":true,
        }})
    }
    fn preview(segments: Value) -> Value {
        json!({"kind":"prepared-preview", "operation_id":ID, "request_sha256":"ab".repeat(32),
            "attempt":1, "available":true, "active":true, "reason":null, "segments":segments,
            "complete":false, "publication_authorized":false})
    }
    fn segment(stream: &str, offset: u64, data: &str, skipped: u64, observed: u64) -> Value {
        json!({"stream":stream, "offset":offset, "next_offset":offset + (data.len() / 2) as u64,
            "data_hex":data, "skipped_bytes":skipped, "observed_bytes":observed})
    }

    #[test]
    fn arguments_bound_time_and_reject_other_job_operations() {
        assert_eq!(
            arguments(&args(&["--job-follow", ID])).unwrap().1,
            Duration::from_secs(3600)
        );
        assert_eq!(
            arguments(&args(&["--job-follow", ID, "86400"])).unwrap().1,
            Duration::from_secs(86400)
        );
        for values in [
            vec![],
            vec!["--job-follow"],
            vec!["--job-follow", "bad"],
            vec!["--job-follow", ID, "0"],
            vec!["--job-follow", ID, "86401"],
            vec!["--job-follow", ID, "+1"],
            vec!["--job-follow", ID, "1.0"],
            vec!["--job-follow", ID, "18446744073709551616"],
            vec!["--job-follow", ID, "--job-resume"],
            vec!["--job-follow", ID, "1", "extra"],
            vec!["--job-wait", ID],
        ] {
            assert!(arguments(&args(&values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn binary_segments_and_explicit_gaps_advance_only_returned_bytes() {
        let mut cursor = Cursor::default();
        cursor
            .accept(
                &preview(json!([
                    segment("stdout", 5, "00ff0a", 5, 100),
                    segment("stderr", 0, "fe", 0, 9),
                ])),
                ID,
                &"ab".repeat(32),
                1,
            )
            .unwrap();
        assert_eq!(
            cursor.request(ID, &"ab".repeat(32), 1),
            json!({
                "kind":"prepared-preview", "operation_id":ID, "request_sha256":"ab".repeat(32),
                "attempt":1, "stdout_offset":8, "stderr_offset":1,
            })
        );
        cursor
            .accept(
                &preview(json!([segment("stdout", 8, "ff", 0, 100)])),
                ID,
                &"ab".repeat(32),
                1,
            )
            .unwrap();
        assert_eq!(cursor.next, [9, 1]);
    }

    #[test]
    fn malformed_foreign_duplicate_or_unbounded_preview_is_rejected_atomically() {
        let good = preview(json!([segment("stdout", 0, "00ff", 0, 2)]));
        for field in [
            "operation_id",
            "request_sha256",
            "attempt",
            "complete",
            "publication_authorized",
        ] {
            let mut bad = good.clone();
            bad[field] = json!(999);
            assert!(
                Cursor::default()
                    .accept(&bad, ID, &"ab".repeat(32), 1)
                    .is_err(),
                "{field}"
            );
        }
        for (field, value) in [
            ("offset", json!(1)),
            ("next_offset", json!(3)),
            ("skipped_bytes", json!(1)),
            ("observed_bytes", json!(1)),
            ("data_hex", json!("FF")),
            ("data_hex", json!("f")),
            ("data_hex", json!("ff".repeat(MAX_PREVIEW_BYTES + 1))),
            ("stream", json!("log")),
        ] {
            let mut bad = good.clone();
            bad["segments"][0][field] = value;
            let mut cursor = Cursor::default();
            assert!(
                cursor.accept(&bad, ID, &"ab".repeat(32), 1).is_err(),
                "{field}"
            );
            assert_eq!(cursor.next, [0, 0]);
        }
        let mut bad = good.clone();
        bad["segments"] = json!([good["segments"][0], good["segments"][0]]);
        let mut cursor = Cursor::default();
        assert!(cursor.accept(&bad, ID, &"ab".repeat(32), 1).is_err());
        assert_eq!(cursor.next, [0, 0]);
    }

    #[test]
    fn unavailable_preview_is_explicit_and_never_resets_cursors() {
        let mut cursor = Cursor {
            next: [7, 3],
            observed: [12, 9],
        };
        for reason in ["unavailable", "busy"] {
            let mut value = preview(json!([]));
            value["available"] = json!(false);
            value["active"] = json!(false);
            value["reason"] = json!(reason);
            cursor.accept(&value, ID, &"ab".repeat(32), 1).unwrap();
            assert_eq!(cursor.next, [7, 3]);
            value["segments"] = json!([segment("stdout", 7, "ff", 0, 12)]);
            assert!(cursor.accept(&value, ID, &"ab".repeat(32), 1).is_err());
        }
    }

    #[test]
    fn follow_binds_initial_claim_and_stops_on_recovery_without_mutations() {
        let mut replies = std::collections::VecDeque::from([
            status("queued", 0),
            status("running", 1),
            preview(json!([segment("stdout", 0, "00ff", 0, 2)])),
            status("running", 2),
        ]);
        let mut queries = Vec::new();
        let mut events = Vec::new();
        let error = follow(
            ID,
            Instant::now() + Duration::from_secs(2),
            |query, _| {
                queries.push(query.clone());
                Ok(replies.pop_front().unwrap())
            },
            |_| {},
            |event| {
                events.push(event.clone());
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("attempt changed"));
        assert_eq!(events.len(), 1);
        assert_eq!(queries.len(), 4);
        assert!(queries.iter().all(|query| matches!(
            query["kind"].as_str(),
            Some("prepared-status" | "prepared-preview")
        )));
    }

    #[test]
    fn automatic_result_recovery_preserves_the_followed_execution_without_replaying_preview() {
        let recovery = |state, attempt, count, pending| {
            let mut value = status(state, attempt);
            value["operation"]["mode"] = json!("resume");
            value["operation"]["automatic_recoveries"] = json!(count);
            value["operation"]["recovery_pending"] = json!(pending);
            value["operation"]["recovery_origin_attempt"] = json!(1);
            value
        };
        let mut replies = std::collections::VecDeque::from([
            status("running", 1),
            preview(json!([segment("stdout", 0, "00ff", 0, 2)])),
            recovery("queued", 1, 1, true),
            recovery("running", 2, 1, false),
            recovery("queued", 2, 2, true),
            recovery("running", 3, 2, false),
            recovery("uncertain", 3, 2, false),
        ]);
        let mut queries = Vec::new();
        let mut events = Vec::new();
        let error = follow(
            ID,
            Instant::now() + Duration::from_secs(2),
            |query, _| {
                queries.push(query.clone());
                Ok(replies.pop_front().unwrap())
            },
            |_| {},
            |event| {
                events.push(event.clone());
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("outcome is uncertain"),
            "{error}"
        );
        assert!(
            replies.is_empty(),
            "following stopped before recovery resolved"
        );
        assert_eq!(
            events.len(),
            1,
            "recovery must not replay already exposed diagnostics"
        );
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

    #[test]
    fn follow_recovery_identity_checks_distinguish_pending_claims_and_manual_recovery() {
        let mut reply = status("queued", 1);
        let status = &mut reply["operation"];
        status["mode"] = json!("acknowledge");
        status["automatic_recoveries"] = json!(1);
        status["recovery_pending"] = json!(true);
        status["recovery_origin_attempt"] = json!(1);
        assert_eq!(followed_owner(status, 1).unwrap(), 1);
        status["state"] = json!("running");
        status["recovery_pending"] = json!(false);
        assert_eq!(followed_owner(status, 2).unwrap(), 1);
        status["recovery_origin_attempt"] = Value::Null;
        assert_eq!(
            followed_owner(status, 3).unwrap(),
            3,
            "manual claim is a different follow owner"
        );
        status["recovery_origin_attempt"] = json!(3);
        assert!(followed_owner(status, 2).is_err());
        status["recovery_origin_attempt"] = json!(1);
        status["automatic_recoveries"] = json!(0);
        assert!(followed_owner(status, 2).is_err());
        status["automatic_recoveries"] = json!(1);
        status["recovery_pending"] = json!(true);
        assert!(
            followed_owner(status, 2).is_err(),
            "running cannot remain pending"
        );
        status["state"] = json!("queued");
        status["mode"] = json!("execute");
        assert!(
            followed_owner(status, 2).is_err(),
            "recovery never becomes execution"
        );
    }

    #[test]
    fn cancelling_an_unclaimed_automatic_retry_does_not_invent_another_execution() {
        let mut pending = status("queued", 1);
        pending["operation"]["mode"] = json!("resume");
        pending["operation"]["automatic_recoveries"] = json!(1);
        pending["operation"]["recovery_pending"] = json!(true);
        pending["operation"]["recovery_origin_attempt"] = json!(1);
        let mut cancelled = pending.clone();
        cancelled["operation"]["state"] = json!("uncertain");
        cancelled["operation"]["cancel_requested"] = json!(true);
        cancelled["operation"]["recovery_pending"] = json!(false);
        let mut replies = std::collections::VecDeque::from([pending, cancelled]);
        let error = follow(
            ID,
            Instant::now() + Duration::from_secs(2),
            |query, _| {
                assert_eq!(query["kind"], "prepared-status");
                Ok(replies.pop_front().unwrap())
            },
            |_| {},
            |_| panic!("result recovery has no live compiler preview"),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("outcome is uncertain"),
            "{error}"
        );
        assert!(replies.is_empty());
    }

    #[test]
    fn failed_preview_write_or_exchange_stops_without_retry() {
        for write_failure in [false, true] {
            let mut calls = 0;
            let mut writes = 0;
            let error = follow(
                ID,
                Instant::now() + Duration::from_secs(2),
                |_, _| {
                    calls += 1;
                    if calls == 1 {
                        return Ok(status("running", 1));
                    }
                    if write_failure {
                        Ok(preview(json!([segment("stdout", 0, "00", 0, 1)])))
                    } else {
                        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "lost preview"))
                    }
                },
                |_| {},
                |_| {
                    writes += 1;
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "partial output"))
                },
            )
            .unwrap_err();
            assert_eq!(calls, 2);
            assert_eq!(writes, usize::from(write_failure));
            assert_eq!(
                error.kind(),
                if write_failure {
                    io::ErrorKind::BrokenPipe
                } else {
                    io::ErrorKind::UnexpectedEof
                }
            );
        }
    }

    #[test]
    fn expired_follow_does_not_contact_daemon_or_emit() {
        let error = follow(
            ID,
            Instant::now(),
            |_, _| panic!("expired exchange"),
            |_| panic!("expired sleep"),
            |_| panic!("expired output"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn pre_dispatch_cancellation_is_rechecked_without_delivery_access() {
        let mut reply = status("cancelled", 0);
        reply["operation"]["execution_may_have_run"] = json!(false);
        reply["operation"]["exit_code"] = json!(130);
        reply["operation"]["cancel_requested"] = json!(true);
        reply["operation"]["stop_reason"] = json!("cancelled");
        let done = follow(
            ID,
            Instant::now() + Duration::from_secs(2),
            |query, _| {
                assert_eq!(query["kind"], "prepared-status");
                Ok(reply.clone())
            },
            |_| panic!("terminal sleep"),
            |_| panic!("terminal preview"),
        )
        .unwrap();
        let Completion::CancelledBeforeStart { status } = done else {
            panic!("unexpected delivery")
        };
        final_status(&status, &reply, ID, None).unwrap();
        reply["operation"]["attempt"] = json!(1);
        assert!(final_status(&status, &reply, ID, None).is_err());
    }

    #[test]
    fn terminal_compiler_failure_requires_verified_metadata_and_stable_final_attempt() {
        use rabsd::coord::prepared_operation::DiagnosticStream;
        let proof = PreparedCompletion {
            version: 1,
            operation_id: ID.into(),
            request_sha256: "ab".repeat(32),
            delivery_request_sha256: "cd".repeat(32),
            receipt_sha256: "ef".repeat(32),
            request_id: 7,
            worker: "worker".into(),
            worker_spki_sha256: "01".repeat(32),
            delivery: "/delivery".into(),
            exit_code: 1,
            stop_reason: None,
            outputs_installed: false,
            stdout: DiagnosticStream {
                bytes: 0,
                sha256: "00".repeat(32),
            },
            stderr: DiagnosticStream {
                bytes: 0,
                sha256: "00".repeat(32),
            },
        };
        let reply = json!({"kind":"prepared-completion", "operation_id":ID,
            "completion":proof, "publication_authorized":false, "reexecute":false});
        let mut calls = 0;
        let done = follow(
            ID,
            Instant::now() + Duration::from_secs(2),
            |query, _| {
                calls += 1;
                match calls {
                    1 => {
                        assert_eq!(query["kind"], "prepared-status");
                        Ok(status("completed", 1))
                    }
                    2 => {
                        assert_eq!(
                            query,
                            &json!({"kind":"prepared-completion", "operation_id":ID,
                        "request_sha256":"ab".repeat(32)})
                        );
                        Ok(reply.clone())
                    }
                    _ => panic!("terminal polling retried"),
                }
            },
            |_| panic!("terminal sleep"),
            |_| panic!("unverified completion exposed"),
        )
        .unwrap();
        let Completion::Ready {
            status: observed,
            proof: actual,
        } = done
        else {
            panic!("lost compiler outcome")
        };
        assert_eq!(actual.exit_code, 1);
        assert_eq!(actual, proof);
        final_status(&observed, &status("completed", 1), ID, Some(&actual)).unwrap();
        for (field, value) in [
            ("attempt", json!(2)),
            ("state", json!("queued")),
            ("request_sha256", json!("cd".repeat(32))),
            ("exit_code", json!(0)),
            ("delivery", json!("/another-attempt")),
            ("outputs_installed", json!(true)),
        ] {
            let mut changed = status("completed", 1);
            changed["operation"][field] = value;
            assert!(
                final_status(&observed, &changed, ID, Some(&actual)).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn output_failure_preserves_partial_record_without_retry() {
        struct PartialOutput {
            bytes: Vec<u8>,
            failed: bool,
        }
        impl Write for PartialOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(!self.failed, "failed output was retried");
                if self.bytes.len() >= 12 {
                    self.failed = true;
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "partial record"));
                }
                let count = bytes.len().min(12 - self.bytes.len());
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("failed record must not flush")
            }
        }
        let mut output = PartialOutput {
            bytes: Vec::new(),
            failed: false,
        };
        let error = write_event(&mut output, &preview(json!([]))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(output.bytes.len(), 12);
        assert!(output.failed);
        assert!(!output.bytes.contains(&b'\n'));
    }

    #[test]
    fn ndjson_keeps_binary_preview_in_a_single_structured_record() {
        let event = preview(json!([segment("stderr", 0, "000aff", 0, 3)]));
        let mut output = Vec::new();
        write_event(&mut output, &event).unwrap();
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(serde_json::from_slice::<Value>(&output).unwrap(), event);
    }
}
