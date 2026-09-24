//! Read-only waiting and binary diagnostic replay for a durable daemon job.
//! Exiting this client does NOT cancel the job, resume an uncertain execution,
//! acknowledge worker results, or submit another command.

use super::{CLIENT_BUDGET, exchange_until, invalid, remaining};
use asupersync::net::unix::UnixStream;
use rabsd::coord::prepared_operation::PreparedCompletion;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(200);
const DEFAULT_WAIT_SECONDS: u64 = 3600;
const MAX_WAIT_SECONDS: u64 = 86400;
const COMPLETION_BUDGET: Duration = Duration::from_secs(300);

fn arguments(args: &[String]) -> Result<(&str, Duration), &'static str> {
    if !matches!(args.len(), 2 | 3) || args[0] != "--job-wait" {
        return Err("usage: rabsd --job-wait <id32hex> [timeout-seconds]");
    }
    let id = &args[1];
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("job ID must be exactly 32 lowercase hexadecimal digits");
    }
    let seconds = match args.get(2) {
        None => DEFAULT_WAIT_SECONDS,
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse::<u64>().map_err(|_| "invalid wait timeout")?
        }
        Some(_) => return Err("wait timeout must be decimal seconds"),
    };
    if seconds == 0 || seconds > MAX_WAIT_SECONDS {
        return Err("wait timeout must be between 1 and 86400 seconds");
    }
    Ok((id, Duration::from_secs(seconds)))
}

#[derive(Debug)]
enum Completion {
    CancelledBeforeStart,
    Ready(PreparedCompletion),
}

fn fingerprint(status: &Value, id: &str) -> io::Result<String> {
    let value = status["request_sha256"].as_str().ok_or_else(|| invalid("job status lacks its request identity"))?;
    if status["id"] != id || value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("invalid job status identity"));
    }
    Ok(value.to_owned())
}

fn matches_status(proof: &PreparedCompletion, status: &Value, id: &str, digest: &str) -> io::Result<()> {
    if proof.operation_id != id || proof.request_sha256 != digest
        || status["state"] != if proof.stop_reason.as_deref() == Some("cancelled") {"cancelled"} else {"completed"}
        || status["request_id"].as_u64() != Some(proof.request_id)
        || status["worker"].as_str() != Some(proof.worker.as_str())
        || status["worker_spki_sha256"].as_str() != Some(proof.worker_spki_sha256.as_str())
        || status["delivery"] != serde_json::to_value(&proof.delivery)?
        || status["exit_code"].as_u64() != Some(u64::from(proof.exit_code))
        || status["stop_reason"].as_str() != proof.stop_reason.as_deref()
        || status["outputs_installed"].as_bool() != Some(proof.outputs_installed)
    {
        return Err(invalid("completion differs from the observed job identity or outcome"));
    }
    Ok(())
}

/// A read-only sequence. Transport failure terminates it, rather than retrying
/// an operation whose outcome is unknown. Polling only repeats status reads.
fn follow(
    id: &str,
    until: Instant,
    mut exchange: impl FnMut(&Value, Instant) -> io::Result<Value>,
    mut sleep: impl FnMut(Duration),
) -> io::Result<Completion> {
    let mut identity: Option<String> = None;
    loop {
        remaining(until)?;
        let request = json!({"kind":"prepared-status", "operation_id":id});
        let reply = exchange(&request, until.min(Instant::now() + CLIENT_BUDGET))?;
        remaining(until)?;
        if reply["kind"] != "prepared-operation" {
            return Err(invalid("daemon did not return the selected job; inspect the same job ID"));
        }
        let status = &reply["operation"];
        let digest = fingerprint(status, id)?;
        if identity.as_ref().is_some_and(|expected| expected != &digest) {
            return Err(invalid("job request identity changed while waiting"));
        }
        identity = Some(digest.clone());
        match status["state"].as_str() {
            Some("queued" | "running" | "cancelling") => {
                sleep(remaining(until)?.min(POLL_INTERVAL));
            }
            Some("uncertain") => return Err(invalid(
                "job outcome is uncertain; explicit reconciliation is required, never reexecution")),
            Some("failed_before_start") => return Err(invalid(
                "job failed before execution; inspect the retained job status")),
            Some("cancelled") if status["execution_may_have_run"] == false => {
                if status["exit_code"] != 130 || status["cancel_requested"] != true
                    || status["outputs_installed"] != false || status["stop_reason"] != "cancelled"
                {
                    return Err(invalid("inconsistent pre-execution cancellation"));
                }
                return Ok(Completion::CancelledBeforeStart);
            }
            Some("completed" | "cancelled") => {
                if status["execution_may_have_run"] != true {
                    return Err(invalid("terminal job lacks executed-result evidence"));
                }
                let reply = exchange(&json!({"kind":"prepared-completion", "operation_id":id,
                    "request_sha256":digest}), until.min(Instant::now() + COMPLETION_BUDGET))?;
                remaining(until)?;
                if reply["kind"] != "prepared-completion" || reply["operation_id"] != id {
                    return Err(invalid("daemon could not verify the job's complete local delivery"));
                }
                let proof: PreparedCompletion = serde_json::from_value(reply["completion"].clone())?;
                matches_status(&proof, status, id, &digest)?;
                return Ok(Completion::Ready(proof));
            }
            _ => return Err(invalid("unknown job state; refusing completion replay")),
        }
    }
}

pub(super) fn run(args: &[String], socket: &str) -> i32 {
    let (id, budget) = match arguments(args) {
        Ok(parsed) => parsed,
        Err(detail) => { eprintln!("rabsd: {detail}"); return 2; }
    };
    let until = Instant::now() + budget;
    let mut exposed = false;
    let result = (|| -> io::Result<i32> {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build()
            .map_err(|error| io::Error::other(format!("job wait runtime: {error:?}")))?;
        let completion = follow(id, until, |request, deadline| {
            runtime.block_on(exchange_until(UnixStream::connect(socket), request, deadline))
        }, std::thread::sleep)?;
        let proof = match completion {
            Completion::CancelledBeforeStart => return Ok(130),
            Completion::Ready(proof) => proof,
        };
        let snapshot = proof.snapshot(until)?;
        remaining(until)?;
        // A failed or partial console write may already be visible. Once this
        // frontier is crossed, never repeat diagnostics or perform fallback.
        exposed = true;
        snapshot.emit(&mut io::stdout().lock(), &mut io::stderr().lock(), until)?;
        Ok(i32::from(proof.exit_code))
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "{}", json!({
                "kind":"prepared-client-error", "operation_id":id, "detail":error.to_string(),
                "outcome_unconfirmed":true, "diagnostics_may_have_been_exposed":exposed,
                "reexecute":false,
            }));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    fn args(values: &[&str]) -> Vec<String> { values.iter().map(|value| (*value).to_owned()).collect() }
    fn status(state: &str) -> Value {
        json!({"kind":"prepared-operation", "operation":{
            "id":ID,"request_sha256":"ab".repeat(32),"state":state,
            "request_id":7,"worker":"worker","worker_spki_sha256":"01".repeat(32),
            "delivery":"/delivery","exit_code":1,"stop_reason":null,
            "outputs_installed":false,"execution_may_have_run":true,
        }})
    }

    #[test]
    fn wait_arguments_are_bounded_and_do_not_accept_mutating_flags() {
        assert_eq!(arguments(&args(&["--job-wait", ID])).unwrap().1, Duration::from_secs(3600));
        assert_eq!(arguments(&args(&["--job-wait", ID, "86400"])).unwrap().1, Duration::from_secs(86400));
        for values in [vec!["--job-wait"], vec!["--job-wait", "bad"],
            vec!["--job-wait", ID, "0"], vec!["--job-wait", ID, "86401"],
            vec!["--job-wait", ID, "+20"], vec!["--job-wait", ID, "1.0"],
            vec!["--job-wait", ID, "--job-resume"], vec!["--job-wait", ID, "10", "extra"]] {
            assert!(arguments(&args(&values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn queued_and_active_waits_never_submit_cancel_or_resume() {
        let mut replies = std::collections::VecDeque::from([status("queued"), status("running"), status("uncertain")]);
        let mut requests = Vec::new();
        let error = follow(ID, Instant::now() + Duration::from_secs(2), |query, _| {
            requests.push(query.clone()); Ok(replies.pop_front().unwrap())
        }, |_| {}).unwrap_err();
        assert!(error.to_string().contains("uncertain"));
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|query| query == &json!({"kind":"prepared-status","operation_id":ID})));
    }

    #[test]
    fn changed_identity_and_lost_status_stop_without_retry() {
        for changed in [false, true] {
            let mut calls = 0;
            let error = follow(ID, Instant::now() + Duration::from_secs(2), |_, _| {
                calls += 1;
                if calls == 1 { return Ok(status("running")); }
                if !changed { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "lost status")); }
                let mut reply = status("completed");
                reply["operation"]["request_sha256"] = json!("cd".repeat(32));
                Ok(reply)
            }, |_| {}).unwrap_err();
            assert_eq!(calls, 2);
            assert!(error.to_string().contains(if changed {"identity changed"} else {"lost status"}));
        }
    }

    #[test]
    fn pre_execution_cancellation_returns_130_without_reading_any_delivery() {
        let mut reply = status("cancelled");
        reply["operation"]["execution_may_have_run"] = json!(false);
        reply["operation"]["exit_code"] = json!(130);
        reply["operation"]["cancel_requested"] = json!(true);
        reply["operation"]["stop_reason"] = json!("cancelled");
        let mut calls = 0;
        let done = follow(ID, Instant::now() + Duration::from_secs(2), |query, _| {
            calls += 1; assert_eq!(query["kind"], "prepared-status"); Ok(reply.clone())
        }, |_| {}).unwrap();
        assert!(matches!(done, Completion::CancelledBeforeStart));
        assert_eq!(calls, 1);
    }

    #[test]
    fn expired_wait_never_contacts_the_daemon() {
        let error = follow(ID, Instant::now(), |_, _| panic!("expired wait contacted daemon"), |_| {}).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn terminal_wait_requires_the_exact_completion_and_keeps_compiler_failure() {
        use rabsd::coord::prepared_operation::DiagnosticStream;
        let proof = PreparedCompletion {
            version:1, operation_id:ID.into(), request_sha256:"ab".repeat(32),
            delivery_request_sha256:"cd".repeat(32), receipt_sha256:"ef".repeat(32),
            request_id:7, worker:"worker".into(), worker_spki_sha256:"01".repeat(32),
            delivery:"/delivery".into(), exit_code:1, stop_reason:None, outputs_installed:false,
            stdout:DiagnosticStream { bytes:0, sha256:"00".repeat(32) },
            stderr:DiagnosticStream { bytes:0, sha256:"00".repeat(32) },
        };
        for change in [None, Some("request_sha256"), Some("worker_spki_sha256"),
            Some("delivery"), Some("exit_code"), Some("outputs_installed")]
        {
            let mut supplied = serde_json::to_value(&proof).unwrap();
            if let Some(field) = change {
                supplied[field] = match field {
                    "exit_code" => json!(0),
                    "outputs_installed" => json!(true),
                    "delivery" => json!("/another-job"),
                    _ => json!("99".repeat(32)),
                };
            }
            let mut calls = 0;
            let result = follow(ID, Instant::now() + Duration::from_secs(2), |request, _| {
                calls += 1;
                if calls == 1 {
                    assert_eq!(request, &json!({"kind":"prepared-status", "operation_id":ID}));
                    Ok(status("completed"))
                } else {
                    assert_eq!(request, &json!({"kind":"prepared-completion", "operation_id":ID,
                        "request_sha256":"ab".repeat(32)}));
                    Ok(json!({"kind":"prepared-completion", "operation_id":ID, "completion":supplied}))
                }
            }, |_| panic!("terminal status must not sleep"));
            assert_eq!(calls,2);
            if change.is_some() {
                assert!(result.is_err());
            } else {
                let Completion::Ready(actual) = result.unwrap() else { panic!("lost compiler result") };
                assert_eq!(actual,proof);
                assert_eq!(actual.exit_code,1);
            }
        }
    }
}
