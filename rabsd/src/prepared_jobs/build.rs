//! Capture once, submit one durable daemon operation, and replay its verified
//! completion. The client owns no worker reservation and never retries submit or
//! dispatch after a lost response. Leaving this client does not cancel the job.

use super::{exchange, invalid, wait};
use rabsd::coord::prepared_operation::PreparedOperationSpec;
use serde_json::{Value, json};
use std::io::{self, Write};

const USAGE: &str = "usage: rabsd --job-build --prepare-from <source-root> <spec.json> <id32hex> <listen-IP:port> <worker> <pin> <bundle> <delivery> <outputs>";

fn arguments(args: &[String]) -> io::Result<(&str, &str, PreparedOperationSpec)> {
    let [
        command,
        flag,
        source,
        specification,
        id,
        address,
        worker,
        pin,
        bundle,
        delivery,
        output,
    ] = args
    else {
        return Err(invalid(USAGE));
    };
    if command != "--job-build"
        || flag != "--prepare-from"
        || [
            source,
            specification,
            id,
            address,
            worker,
            pin,
            bundle,
            delivery,
            output,
        ]
        .into_iter()
        .any(|value| value.is_empty() || value.starts_with("--"))
    {
        return Err(invalid(USAGE));
    }
    // Reuse the ordinary local client's exact job-ID and positional contract.
    let mut submit = vec!["--job-submit".to_owned()];
    submit.extend_from_slice(&args[4..]);
    let request = super::request(&submit).map_err(invalid)?;
    let spec = serde_json::from_value(request["operation"].clone())?;
    Ok((source, specification, spec))
}

fn admission_reply(reply: &Value, id: &str) -> io::Result<()> {
    if reply["kind"] != "prepared-operation"
        || reply["operation"]["id"] != id
        || reply["publication_authorized"] != false
        || reply["reexecute"] != false
    {
        return Err(invalid(format!(
            "daemon did not admit the selected job: {reply}"
        )));
    }
    wait::fingerprint(&reply["operation"], id)?;
    Ok(())
}

pub(super) fn run(args: &[String], socket: &str) -> i32 {
    let (source, specification, spec) = match arguments(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("rabsd: {error}");
            return 2;
        }
    };
    let mut submitted = false;
    let result = (|| -> io::Result<()> {
        // Fail before a potentially large capture when the configured daemon is
        // unavailable. An existing ID is inspection/recovery intent, never a
        // request to recapture inputs or silently start another operation.
        let status = exchange(
            socket,
            &json!({"kind":"prepared-status", "operation_id":spec.id}),
        )?;
        if status["kind"] != "prepared-operation-error" {
            return Err(invalid(
                "job ID already exists; use --job-status or --job-wait without recapturing",
            ));
        }
        let prepared = crate::worker_exec::prepare_daemon_build(&spec, source, specification)?;
        if prepared["kind"] != "prepared-source-template" || prepared["request_id"] != "allocate" {
            return Err(invalid(
                "source preparation did not retain allocation intent",
            ));
        }
        // Output the inspectable identity BEFORE admission. A closed console
        // cannot leave the caller unaware of the ID of work it just submitted.
        writeln!(
            io::stderr().lock(),
            "{}",
            json!({
                "kind":"prepared-build-ready", "operation_id":spec.id, "bundle":spec.bundle,
                "request_id":null, "execution_may_have_run":false,
                "publication_authorized":false, "reexecute":false,
            })
        )?;
        submitted = true; // From this point a lost reply is an unknown admission.
        let reply = exchange(
            socket,
            &json!({"kind":"prepared-submit-allocated", "operation":spec}),
        )?;
        admission_reply(&reply, &spec.id)?;
        writeln!(io::stderr().lock(), "{reply}")?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = writeln!(
            io::stderr().lock(),
            "{}",
            json!({
                "kind":"prepared-client-error", "operation_id":spec.id,
                "detail":error.to_string(), "outcome_unconfirmed":submitted,
                "diagnostics_may_have_been_exposed":false, "reexecute":false,
            })
        );
        return 1;
    }
    // This existing native path verifies both complete retained streams before
    // emitting either, preserves the worker's exit status, and never reconnects
    // to a worker or repeats a compiler execution.
    wait::run(&["--job-wait".to_owned(), spec.id], socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        [
            "--job-build",
            "--prepare-from",
            "/source",
            "/spec.json",
            "0123456789abcdef0123456789abcdef",
            "127.0.0.1:7091",
            "worker",
            "pin",
            "/bundle",
            "/delivery",
            "/output",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn combined_build_requires_explicit_new_preparation_and_retained_job_identity() {
        let values = args();
        let (source, specification, spec) = arguments(&values).unwrap();
        assert_eq!((source, specification), ("/source", "/spec.json"));
        assert_eq!(spec.id, values[4]);
        for at in [0, 1, 4] {
            let mut changed = values.clone();
            changed[at] = "invalid".into();
            assert!(arguments(&changed).is_err());
        }
        assert!(arguments(&values[..10]).is_err());
        let mut recovery = values;
        recovery[1] = "--resume".into();
        assert!(arguments(&recovery).is_err());
    }

    #[test]
    fn admission_is_bound_to_the_original_job_and_has_no_publication_authority() {
        let id = &args()[4];
        let good = json!({"kind":"prepared-operation", "operation":{
            "id":id, "request_id":null, "request_sha256":"ab".repeat(32)},
            "publication_authorized":false, "reexecute":false});
        admission_reply(&good, id).unwrap();
        for field in ["publication_authorized", "reexecute"] {
            let mut wrong = good.clone();
            wrong[field] = json!(true);
            assert!(admission_reply(&wrong, id).is_err());
        }
        let mut wrong = good;
        wrong["operation"]["id"] = json!("00".repeat(16));
        assert!(admission_reply(&wrong, id).is_err());
    }
}
