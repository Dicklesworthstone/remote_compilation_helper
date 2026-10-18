//! Private remote execution and subscriber installation have separate consent
//! frontiers. Losing the caller while a worker runs can never authorize a
//! later write into Cargo's target tree.
use super::*;

const REMOTE_WAIT: Duration = Duration::from_secs(50 * 60);

fn remote_wait() -> Duration {
    std::env::var("RABS_REMOTE_WAIT_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map_or(REMOTE_WAIT, Duration::from_millis)
}

fn field<'a>(reply: &'a reply_json::Value, name: &str) -> Option<&'a str> {
    reply.get(name).and_then(reply_json::Value::as_str)
}

fn protocol(reply: &reply_json::Value) -> bool {
    matches!(reply.get("remote_protocol"), Some(reply_json::Value::Number(value)) if value == "1")
}

fn completed_failure(reply: &reply_json::Value) -> bool {
    field(reply, "kind") == Some("rustc-decision")
        && field(reply, "decision") == Some("remote-failed")
        && protocol(reply)
        && reply
            .get("execution_finished")
            .and_then(reply_json::Value::as_bool)
            == Some(true)
        && reply
            .get("writer_returned")
            .and_then(reply_json::Value::as_bool)
            == Some(true)
        && reply
            .get("compiler_skip_authorized")
            .and_then(reply_json::Value::as_bool)
            == Some(false)
}

/// No pre-install disconnect can become delayed installation consent. An
/// explicitly settled remote failure permits stock local execution; uncertain
/// execution or delivery fails closed on this invocation.
pub(super) fn outcome(
    offer: &reply_json::Value,
    mut reader: BufReader<ConsultStream>,
    owned: &impl Fn() -> bool,
) -> Result<Live, ()> {
    if !protocol(offer) || !capture::supported(offer) {
        return Ok(Live::PassThrough);
    }
    let Some(key) = field(offer, "action_key").filter(|key| !key.is_empty() && key.len() <= 512)
    else {
        return Err(());
    };
    let Some(deadline) = Instant::now().checked_add(remote_wait()) else {
        return Ok(Live::FailClosed(
            "RABS remote deadline is not representable".into(),
        ));
    };
    let accepted = format!(
        "{{\"kind\":\"rustc-remote-accept\",\"remote_protocol\":1,\"action_key\":{}}}\n",
        json_string(key),
    );
    if singleflight::write_owned(&mut reader, accepted.as_bytes(), deadline, owned).is_err() {
        return Ok(Live::FailClosed(
            "RABS remote execution acceptance is uncertain".into(),
        ));
    }
    let line =
        match singleflight::read_owned_reply(&mut reader, MAX_LIVE_REPLY_BYTES, deadline, owned) {
            Ok(line) => line,
            Err(error) => {
                return Ok(Live::FailClosed(format!(
                    "RABS remote execution outcome is unknown: {error}"
                )));
            }
        };
    let Some(ready) = reply_json::parse(&line) else {
        return Ok(Live::FailClosed("malformed remote execution answer".into()));
    };
    if completed_failure(&ready) {
        return Ok(Live::PassThrough);
    }
    if field(&ready, "kind") != Some("rustc-decision")
        || field(&ready, "decision") != Some("remote-ready")
        || field(&ready, "action_key") != Some(key)
        || !protocol(&ready)
        || !capture::supported(&ready)
        || ready
            .get("compiler_skip_authorized")
            .and_then(reply_json::Value::as_bool)
            != Some(false)
    {
        return Ok(Live::FailClosed(
            "unrecognized remote result handoff".into(),
        ));
    }
    let Some(capture) =
        field(&ready, "capture").filter(|capture| !capture.is_empty() && capture.len() <= 512)
    else {
        return Ok(Live::FailClosed(
            "remote result has no bounded capture identity".into(),
        ));
    };
    // The producer finished into private verified storage. A fresh owned write
    // grants installation of exactly this capture, not any later worker result.
    let Some(deadline) = Instant::now().checked_add(install_wait()) else {
        return Ok(Live::FailClosed(
            "RABS remote install deadline is not representable".into(),
        ));
    };
    let accepted = format!(
        "{{\"kind\":\"rustc-accept\",\"capture\":{}}}\n",
        json_string(capture),
    );
    if singleflight::write_owned(&mut reader, accepted.as_bytes(), deadline, owned).is_err() {
        return Ok(Live::FailClosed(
            "RABS remote installation acceptance is uncertain".into(),
        ));
    }
    let line =
        match singleflight::read_owned_reply(&mut reader, MAX_LIVE_REPLY_BYTES, deadline, owned) {
            Ok(line) => line,
            Err(error) => {
                return Ok(Live::FailClosed(format!(
                    "RABS remote installation outcome is unknown: {error}"
                )));
            }
        };
    Ok(completion(&line, key))
}

fn completion(line: &str, key: &str) -> Live {
    let Some(reply) = reply_json::parse(line) else {
        return Live::FailClosed("malformed remote installation answer".into());
    };
    if completed_failure(&reply) {
        return Live::PassThrough;
    }
    if field(&reply, "kind") != Some("rustc-decision")
        || field(&reply, "decision") != Some("remote-complete")
        || field(&reply, "action_key") != Some(key)
        || !protocol(&reply)
        || reply
            .get("compiler_skip_authorized")
            .and_then(reply_json::Value::as_bool)
            != Some(true)
        || reply
            .get("writer_returned")
            .and_then(reply_json::Value::as_bool)
            != Some(true)
    {
        return Live::FailClosed("remote installation did not authorize compiler skip".into());
    }
    field(&reply, "stderr_hex")
        .and_then(hex_decode)
        .map_or_else(
            || Live::FailClosed("malformed remote compiler transcript".into()),
            Live::Served,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_fallback_requires_both_execution_and_writer_settlement() {
        let valid = r#"{"kind":"rustc-decision","decision":"remote-failed","remote_protocol":1,"execution_finished":true,"writer_returned":true,"compiler_skip_authorized":false}"#;
        assert!(completed_failure(&reply_json::parse(valid).unwrap()));
        for (from, to) in [
            (
                "\"execution_finished\":true",
                "\"execution_finished\":false",
            ),
            ("\"writer_returned\":true", "\"writer_returned\":false"),
            ("\"remote_protocol\":1", "\"remote_protocol\":2"),
            (
                "\"compiler_skip_authorized\":false",
                "\"compiler_skip_authorized\":true",
            ),
            (
                "\"execution_finished\":true",
                "\"execution_finished\":true,\"execution_finished\":false",
            ),
        ] {
            let reply = reply_json::parse(&valid.replace(from, to)).unwrap();
            assert!(!completed_failure(&reply), "{from}");
        }
    }

    #[test]
    fn current_remote_result_is_distinct_from_a_cache_hit() {
        let valid = r#"{"kind":"rustc-decision","decision":"remote-complete","remote_protocol":1,"action_key":"this-action","writer_returned":true,"compiler_skip_authorized":true,"stderr_hex":"6f6b0a"}"#;
        assert!(
            matches!(completion(valid, "this-action"), Live::Served(bytes) if bytes == b"ok\n")
        );
        assert!(matches!(
            completion(valid, "other-action"),
            Live::FailClosed(_)
        ));
        assert!(matches!(
            completion(&valid.replace("remote-complete", "served"), "this-action"),
            Live::FailClosed(_)
        ));
        assert!(matches!(
            completion(
                &valid.replace("\"writer_returned\":true", "\"writer_returned\":false"),
                "this-action"
            ),
            Live::FailClosed(_)
        ));
        assert!(matches!(
            completion(&valid.replace("6f6b0a", "zz"), "this-action"),
            Live::FailClosed(_)
        ));
    }

    #[test]
    fn premature_ready_is_not_success_or_permission_to_fall_back() {
        let ready = r#"{"kind":"rustc-decision","decision":"remote-ready","remote_protocol":1,"action_key":"this-action","capture":"capture","capture_protocol":1,"compiler_skip_authorized":false}"#;
        assert!(matches!(
            completion(ready, "this-action"),
            Live::FailClosed(_)
        ));
        assert!(!completed_failure(&reply_json::parse(ready).unwrap()));
    }
}
