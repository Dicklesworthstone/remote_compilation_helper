//! Private remote execution and subscriber installation have separate consent
//! frontiers. Losing the caller while a worker runs can never authorize a
//! later write into Cargo's target tree.
use super::*;

const REMOTE_WAIT: Duration = Duration::from_secs(50 * 60);
const MAX_FAILURE_REASON_BYTES: usize = 8 * 1024;

/// A reason is diagnostic text, never execution or installation authority.
/// Keep ordinary recovery paths intact, but do not let a peer inject terminal
/// controls or turn a bounded protocol failure into unbounded stderr output.
fn failure_reason(reply: &reply_json::Value) -> String {
    let mut detail = String::new();
    if let Some(reason) = field(reply, "reason") {
        for character in reason.chars() {
            let rendered = if character.is_control() {
                character.escape_default().to_string()
            } else {
                character.to_string()
            };
            if detail.len() + rendered.len() > MAX_FAILURE_REASON_BYTES {
                detail.push_str(" [truncated]");
                break;
            }
            detail.push_str(&rendered);
        }
    }
    if detail.is_empty() {
        detail.push_str("daemon supplied no usable failure reason");
    }
    detail
}

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

fn completed_failure(reply: &reply_json::Value, key: &str) -> bool {
    field(reply, "kind") == Some("rustc-decision")
        && field(reply, "decision") == Some("remote-failed")
        && field(reply, "action_key") == Some(key)
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

/// Handle a complete typed failure in either consent phase. The daemon may
/// include the retained recovery directory when a transport outcome is unknown.
/// Discarding that reason strands the user behind a generic protocol error.
/// Preserve it without treating a recovery hint as proof that work has stopped.
fn failure_outcome(reply: &reply_json::Value, key: &str) -> Option<Live> {
    if field(reply, "kind") != Some("rustc-decision")
        || field(reply, "decision") != Some("remote-failed")
        || !protocol(reply)
    {
        return None;
    }
    // A settlement belongs to exactly the accepted action. Neither a legacy
    // unbound failure nor a different action's finished writer proves that
    // this action is safe to execute locally, in either consent phase.
    if field(reply, "action_key") != Some(key) {
        return Some(Live::FailClosed(format!(
            "RABS remote failure is not bound to the current action; local retry refused: {}",
            failure_reason(reply),
        )));
    }
    if completed_failure(reply, key) {
        return Some(Live::PassThrough);
    }
    Some(Live::FailClosed(format!(
        "RABS remote execution or installation is not confirmed settled; local retry refused: {}",
        failure_reason(reply),
    )))
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
    if let Some(failure) = failure_outcome(&ready, key) {
        return Ok(failure);
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
    if let Some(failure) = failure_outcome(&reply, key) {
        return failure;
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
        let valid = r#"{"kind":"rustc-decision","decision":"remote-failed","remote_protocol":1,"action_key":"this-action","execution_finished":true,"writer_returned":true,"compiler_skip_authorized":false}"#;
        assert!(completed_failure(
            &reply_json::parse(valid).unwrap(),
            "this-action"
        ));
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
            assert!(!completed_failure(&reply, "this-action"), "{from}");
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
        assert!(!completed_failure(
            &reply_json::parse(ready).unwrap(),
            "this-action"
        ));
    }

    const RECOVERY_REASON: &str = "worker transport lost; retained remote recovery directory: /state/dependency-workers/request-17";
    const UNSETTLED: &str = r#"{"kind":"rustc-decision","decision":"remote-failed","remote_protocol":1,"action_key":"this-action","execution_finished":false,"writer_returned":true,"compiler_skip_authorized":false}"#;
    const READY: &str = r#"{"kind":"rustc-decision","decision":"remote-ready","remote_protocol":1,"action_key":"this-action","capture":"capture-17","capture_protocol":1,"compiler_skip_authorized":false}"#;

    fn with_reason(frame: &str, reason: &str) -> String {
        format!(
            "{},\"reason\":{}}}",
            frame.strip_suffix('}').unwrap(),
            json_string(reason),
        )
    }

    #[test]
    fn uncertain_remote_failure_preserves_recovery_without_granting_a_retry() {
        let frame = with_reason(UNSETTLED, RECOVERY_REASON);
        let reply = reply_json::parse(&frame).unwrap();
        assert!(!completed_failure(&reply, "this-action"));
        assert!(
            matches!(failure_outcome(&reply, "this-action"), Some(Live::FailClosed(reason))
            if reason.contains(RECOVERY_REASON) && reason.contains("local retry refused"))
        );
        assert!(
            matches!(completion(&frame, "this-action"), Live::FailClosed(reason)
            if reason.contains(RECOVERY_REASON))
        );
    }

    #[test]
    fn recovery_text_never_overrides_missing_or_ambiguous_settlement() {
        let settled = with_reason(
            &UNSETTLED.replace(
                "\"execution_finished\":false",
                "\"execution_finished\":true",
            ),
            RECOVERY_REASON,
        );
        assert!(matches!(
            completion(&settled, "this-action"),
            Live::PassThrough
        ));
        for (from, to) in [
            (
                "\"execution_finished\":true",
                "\"execution_finished\":false",
            ),
            ("\"writer_returned\":true", "\"writer_returned\":false"),
            ("\"execution_finished\":true,", ""),
            ("\"writer_returned\":true,", ""),
            ("\"compiler_skip_authorized\":false,", ""),
            ("\"execution_finished\":true", "\"execution_finished\":1"),
            ("\"writer_returned\":true", "\"writer_returned\":null"),
            (
                "\"compiler_skip_authorized\":false",
                "\"compiler_skip_authorized\":true",
            ),
            (
                "\"execution_finished\":true",
                "\"execution_finished\":true,\"execution_finished\":true",
            ),
            (
                "\"writer_returned\":true",
                "\"writer_returned\":true,\"writer_returned\":true",
            ),
        ] {
            assert_ne!(settled.replace(from, to), settled, "fixture did not change");
            assert!(
                matches!(completion(&settled.replace(from, to), "this-action"),
                Live::FailClosed(reason) if reason.contains(RECOVERY_REASON)),
                "{from}"
            );
        }
        for (from, to) in [
            ("\"remote_protocol\":1", "\"remote_protocol\":2"),
            (
                "\"remote_protocol\":1",
                "\"remote_protocol\":1,\"remote_protocol\":1",
            ),
            ("\"decision\":\"remote-failed\"", "\"decision\":\"other\""),
            ("\"kind\":\"rustc-decision\"", "\"kind\":\"other\""),
        ] {
            let frame = settled.replace(from, to);
            assert!(failure_outcome(&reply_json::parse(&frame).unwrap(), "this-action").is_none());
            assert!(matches!(
                completion(&frame, "this-action"),
                Live::FailClosed(_)
            ));
        }
    }

    #[test]
    fn recovery_reason_is_bounded_terminal_safe_and_unicode_preserving() {
        let frame = with_reason(UNSETTLED, "/state/build café/任务\n\r\t\u{1b}[2J");
        let detail = failure_reason(&reply_json::parse(&frame).unwrap());
        assert_eq!(detail, "/state/build café/任务\\n\\r\\t\\u{1b}[2J");
        assert!(!detail.chars().any(char::is_control));
        for text in ["x", "任务", "\u{1b}"] {
            let reason = text.repeat(MAX_FAILURE_REASON_BYTES + 1);
            let frame = with_reason(UNSETTLED, &reason);
            let detail = failure_reason(&reply_json::parse(&frame).unwrap());
            assert!(detail.ends_with(" [truncated]"));
            assert!(detail.len() <= MAX_FAILURE_REASON_BYTES + " [truncated]".len());
            assert!(!detail.chars().any(char::is_control));
        }
        let frame = with_reason(UNSETTLED, &"x".repeat(MAX_FAILURE_REASON_BYTES));
        assert_eq!(
            failure_reason(&reply_json::parse(&frame).unwrap()).len(),
            MAX_FAILURE_REASON_BYTES,
        );
    }

    #[test]
    fn unusable_recovery_reason_still_fails_closed() {
        for field in [
            "",
            ",\"reason\":null",
            ",\"reason\":17",
            ",\"reason\":\"\"",
            ",\"reason\":\"first\",\"reason\":\"second\"",
        ] {
            let frame = format!("{}{field}}}", UNSETTLED.strip_suffix('}').unwrap());
            assert!(
                matches!(completion(&frame, "this-action"), Live::FailClosed(reason)
                if reason.contains("daemon supplied no usable failure reason"))
            );
        }
    }

    /// Exercise the production protocol against native sockets. The peer has
    /// finite I/O deadlines and half-closes after its terminal bytes, so an
    /// incomplete frame cannot hang the fixture on the normal 50-minute budget.
    fn failure_exchange(frame: String, after_install_consent: bool) -> (Live, Vec<String>) {
        let (client, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let daemon = std::thread::spawn(move || {
            let mut peer = BufReader::new(peer);
            let mut acknowledgments = Vec::new();
            let mut first = String::new();
            peer.read_line(&mut first).unwrap();
            assert_eq!(
                first,
                "{\"kind\":\"rustc-remote-accept\",\"remote_protocol\":1,\"action_key\":\"this-action\"}\n"
            );
            acknowledgments.push(first);
            if after_install_consent {
                writeln!(peer.get_mut(), "{READY}").unwrap();
                let mut second = String::new();
                peer.read_line(&mut second).unwrap();
                assert_eq!(
                    second,
                    "{\"kind\":\"rustc-accept\",\"capture\":\"capture-17\"}\n"
                );
                acknowledgments.push(second);
            }
            peer.get_mut().write_all(frame.as_bytes()).unwrap();
            peer.get_ref().shutdown(std::net::Shutdown::Write).unwrap();
            let mut extra = Vec::new();
            peer.read_to_end(&mut extra).unwrap();
            assert!(
                extra.is_empty(),
                "failure sent a retry or another installation ACK"
            );
            acknowledgments
        });
        let offer = reply_json::parse(
            r#"{"kind":"rustc-decision","decision":"remote","remote_protocol":1,"action_key":"this-action","capture_protocol":1}"#,
        )
        .unwrap();
        let reader = BufReader::new(ConsultStream {
            stream: client,
            deadline: Instant::now() + Duration::from_secs(5),
        });
        let result = outcome(&offer, reader, &|| true).unwrap();
        (result, daemon.join().unwrap())
    }

    #[test]
    fn socket_failure_before_install_consent_surfaces_retained_recovery() {
        let (result, acknowledgments) = failure_exchange(
            format!("{}\n", with_reason(UNSETTLED, RECOVERY_REASON)),
            false,
        );
        assert!(matches!(result, Live::FailClosed(reason) if reason.contains(RECOVERY_REASON)));
        assert_eq!(acknowledgments.len(), 1);
    }

    #[test]
    fn socket_failure_after_install_consent_surfaces_retained_recovery() {
        let frame = UNSETTLED
            .replace(
                "\"execution_finished\":false",
                "\"execution_finished\":true",
            )
            .replace("\"writer_returned\":true", "\"writer_returned\":false");
        let (result, acknowledgments) =
            failure_exchange(format!("{}\n", with_reason(&frame, RECOVERY_REASON)), true);
        assert!(matches!(result, Live::FailClosed(reason) if reason.contains(RECOVERY_REASON)));
        assert_eq!(acknowledgments.len(), 2);
    }

    #[test]
    fn socket_settled_failure_retains_the_existing_fallback_boundary() {
        let frame = UNSETTLED.replace(
            "\"execution_finished\":false",
            "\"execution_finished\":true",
        );
        for after_install_consent in [false, true] {
            let (result, acknowledgments) = failure_exchange(
                format!("{}\n", with_reason(&frame, RECOVERY_REASON)),
                after_install_consent,
            );
            assert!(matches!(result, Live::PassThrough));
            assert_eq!(
                acknowledgments.len(),
                if after_install_consent { 2 } else { 1 }
            );
        }
    }

    #[test]
    fn socket_foreign_or_unbound_settlement_never_authorizes_local_retry() {
        let settled = UNSETTLED.replace(
            "\"execution_finished\":false",
            "\"execution_finished\":true",
        );
        let action = "\"action_key\":\"this-action\",";
        for replacement in [
            "",
            "\"action_key\":\"other-action\",",
            "\"action_key\":\"this-action-suffix\",",
            "\"action_key\":\"\",",
            "\"action_key\":null,",
            "\"action_key\":17,",
            "\"action_key\":\"this-action\",\"action_key\":\"this-action\",",
            "\"action_key\":\"this-action\",\"action_key\":\"other-action\",",
        ] {
            let frame = settled.replace(action, replacement);
            assert_ne!(frame, settled, "fixture did not change");
            assert!(!completed_failure(
                &reply_json::parse(&frame).unwrap(),
                "this-action",
            ));
            for after_install_consent in [false, true] {
                let (result, acknowledgments) = failure_exchange(
                    format!("{}\n", with_reason(&frame, RECOVERY_REASON)),
                    after_install_consent,
                );
                assert!(
                    matches!(result, Live::FailClosed(reason)
                        if reason.contains("not bound to the current action")
                            && reason.contains("local retry refused")
                            && reason.contains(RECOVERY_REASON)),
                    "accepted a foreign or ambiguous settlement: {replacement:?}",
                );
                assert_eq!(
                    acknowledgments.len(),
                    if after_install_consent { 2 } else { 1 }
                );
            }
        }
    }

    #[test]
    fn truncated_failure_is_not_an_authoritative_recovery_hint() {
        let partial = with_reason(UNSETTLED, RECOVERY_REASON);
        for after_install_consent in [false, true] {
            // Even a complete JSON value without its frame delimiter is not
            // an acknowledged reply and must not authorize local execution.
            let (result, _) = failure_exchange(partial.clone(), after_install_consent);
            assert!(matches!(result, Live::FailClosed(reason)
                if reason.contains("outcome is unknown") && !reason.contains(RECOVERY_REASON)));
        }
    }
}
