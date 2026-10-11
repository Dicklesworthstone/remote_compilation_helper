//! The `rustc-request` frame (bd-14t4j / bd-k52xe): the wrapper's live
//! request, and the only frame whose answer may let a wrapper skip rustc.
//!
//! Request: `{"kind":"rustc-request","argv":[…],"cwd":"…","env":[["K","V"],…]}`
//! where `argv[0]` is the real compiler. Replies:
//!
//! - `{"kind":"rustc-decision","decision":"hit",…}` — every gate passes and
//!   the complete output plan is prepared, but NOTHING is written yet. A
//!   wrapper that still wants the hit answers `{"kind":"rustc-accept"}`
//!   and from then on waits for the install instead of running rustc; one
//!   that gave up simply closes, and no write ever happens. The install
//!   answer is `{"decision":"served","stderr_hex":…,
//!   "compiler_skip_authorized":true}` (replay and exit 0) or
//!   `{"decision":"serve-failed",…}` (the synchronous install returned; no
//!   writer remains, so the compiler may run);
//! - `{"kind":"rustc-decision","decision":"execute","attempt":…,"env":[…]}`
//!   — run the compiler with EXACTLY `env` as an admitted attempt, then send
//!   `{"kind":"rustc-complete","capture_protocol":1,…}` while retaining the
//!   output paths. A `rustc-captured` receipt names the immutable candidate;
//!   only its matching `rustc-capture-ack` permits coordinator publication;
//! - `{"kind":"rustc-decision","decision":"wait",…}` — only for requests
//!   with `wait_for_inflight: true`: another subscriber owns the dispatch.
//!   No writer or execution was admitted here. The wrapper may retry the
//!   identical request on this connection under its own bounded backoff.
//!   Each retry reobserves inputs and rechecks every serving/sampling gate;
//! - anything else — run the compiler as if RABS were absent.
//!
//! Requests outside the live class keep the shadow plane's observation, so
//! turning the lane on never loses the existing shadow evidence.

use crate::coord::live_dependency::{
    CompletionReport, InstallResult, LiveDecision, LiveDependencyLane, LiveDependencyRequest,
    LocalAttempt, MAX_TRANSCRIPT_BYTES, PendingServe,
};
use crate::edge::live_facts::{FactsMiss, LiveFacts};
use rabs_cas::metadata_store::digest_key;
use rabs_key::build_script_directives::bind_rustc_environment;
use rabs_key::live_dependency::{
    ExternFact, LiveRustcRequest, PlannedExtern, constructed_environment, live_dependency_key,
    plan_dependency_action,
};
use rabs_protocol::input_evidence::{
    ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::ObjectId;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;

/// Largest completion frame: a bounded transcript in hex plus envelope.
pub(super) const MAX_COMPLETION_FRAME_BYTES: usize = 2 * MAX_TRANSCRIPT_BYTES + 64 * 1024;
const MAX_ARGS: usize = 4096;
const MAX_ENV: usize = 4096;

/// The edge half of the live dependency lane: observation state plus the
/// coordinator capability that decides and publishes.
#[derive(Debug)]
pub struct LiveEdge {
    lane: LiveDependencyLane,
    facts: Arc<LiveFacts>,
}

impl LiveEdge {
    /// Bind observation state to a coordinator lane.
    #[must_use]
    pub fn new(lane: LiveDependencyLane) -> Self {
        Self {
            lane,
            facts: LiveFacts::new(),
        }
    }
}

/// What the connection must do next.
pub(super) enum Decided {
    /// Write this reply and continue.
    Reply(String),
    /// Write this reply, then wait for the subscriber's completion frame.
    Execute {
        reply: String,
        attempt: Box<LocalAttempt>,
    },
    /// Write this reply, then install only if the subscriber accepts.
    Hit {
        reply: String,
        pending: Box<PendingServe>,
    },
    /// Not eligible: answer through the shadow plane.
    Shadow(crate::edge::shadow::ConsultObservation),
}

fn pass_through(reason: &str) -> String {
    json!({
        "kind": "rustc-decision", "decision": "pass-through", "reason": reason,
        "compiler_skip_authorized": false,
    })
    .to_string()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn log(decision: &str, fields: &[(&str, &str)]) {
    let mut pairs = vec![("decision", decision)];
    pairs.extend_from_slice(fields);
    super::log_line("rabsd-live-dependency", &pairs);
}

/// The unit's `--crate-name`, so every request decision says which crate
/// it answered. Cargo compiles many units at once; a key alone cannot
/// explain which dependency missed or why (`rch why` needs both).
fn crate_name(argv: &[String]) -> &str {
    argv.iter()
        .enumerate()
        .find_map(|(at, arg)| {
            arg.strip_prefix("--crate-name=").or_else(|| {
                (arg == "--crate-name")
                    .then(|| argv.get(at + 1).map(String::as_str))
                    .flatten()
            })
        })
        .unwrap_or("?")
}

struct Parsed {
    argv: Vec<String>,
    cwd: String,
    env: Vec<(String, String)>,
}

fn parse_request(value: &Value) -> Option<Parsed> {
    let argv: Vec<String> = value
        .get("argv")?
        .as_array()?
        .iter()
        .map(|arg| arg.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    let cwd = value.get("cwd")?.as_str()?.to_owned();
    let env: Vec<(String, String)> = value
        .get("env")?
        .as_array()?
        .iter()
        .map(|pair| {
            let pair = pair.as_array()?;
            match pair.as_slice() {
                [name, value] => Some((name.as_str()?.to_owned(), value.as_str()?.to_owned())),
                _ => None,
            }
        })
        .collect::<Option<_>>()?;
    (!argv.is_empty() && argv.len() <= MAX_ARGS && env.len() <= MAX_ENV).then_some(Parsed {
        argv,
        cwd,
        env,
    })
}

fn observation(parsed: &Parsed) -> crate::edge::shadow::ConsultObservation {
    crate::edge::shadow::ConsultObservation {
        argv: parsed.argv.clone(),
        cwd: parsed.cwd.clone(),
        env_names: parsed
            .env
            .iter()
            .map(|(name, _)| name.clone())
            .filter(|name| name.starts_with("CARGO") || name.starts_with("RUSTC"))
            .collect(),
    }
}

/// The shadow observation of a request (the same names-only projection a
/// `consult` frame carries), for a daemon whose live lane is off.
pub(super) fn shadow_observation(value: &Value) -> Option<crate::edge::shadow::ConsultObservation> {
    parse_request(value).map(|parsed| observation(&parsed))
}

/// Decide one request (blocking: observation, hashing, coordinator SQL).
pub(super) fn decide(live: &LiveEdge, request: &Value) -> Decided {
    let Some(parsed) = parse_request(request) else {
        return Decided::Reply(pass_through("malformed-request"));
    };
    let unit = crate_name(&parsed.argv);
    // Every refusal below is logged with its reason: an unexplained miss is
    // indistinguishable from a lane that never saw the request.
    let refuse = |reason: &str| {
        log("pass-through", &[("crate", unit), ("reason", reason)]);
        Decided::Reply(pass_through(reason))
    };
    let constructed = constructed_environment(&parsed.env);
    let toolchain = match live
        .facts
        .toolchain(Path::new(&parsed.argv[0]), &constructed)
    {
        Ok(toolchain) => toolchain,
        Err(FactsMiss::Pending) => {
            log(
                "toolchain-warming",
                &[("crate", unit), ("compiler", &parsed.argv[0])],
            );
            return Decided::Shadow(observation(&parsed));
        }
        Err(FactsMiss::Refused(reason)) => {
            log(
                "shadow",
                &[
                    ("crate", unit),
                    ("reason", "toolchain-refused"),
                    ("detail", &reason),
                ],
            );
            return Decided::Shadow(observation(&parsed));
        }
    };
    let Some(host) = toolchain.host_triple().map(str::to_owned) else {
        log(
            "shadow",
            &[("crate", unit), ("reason", "toolchain-host-unknown")],
        );
        return Decided::Shadow(observation(&parsed));
    };
    let mut plan = match plan_dependency_action(
        LiveRustcRequest {
            argv: &parsed.argv,
            cwd: &parsed.cwd,
            env: &parsed.env,
        },
        &host,
    ) {
        Ok(plan) => plan,
        Err(refusal) => {
            // Out of class (workspace members, build scripts, ...): the
            // reason code is the `rch why`-grade explanation; the detail
            // names the exact argument or variable that put it there.
            log(
                "shadow",
                &[
                    ("crate", unit),
                    ("reason", refusal.code()),
                    ("detail", &refusal.to_string()),
                ],
            );
            return Decided::Shadow(observation(&parsed));
        }
    };
    let package = match live.facts.package(
        Path::new(&plan.source_root),
        plan.source_kind,
        plan.generated_root.as_deref().map(Path::new),
    ) {
        Ok(package) => package,
        Err(miss) => {
            log(
                "pass-through",
                &[
                    ("crate", unit),
                    ("package", &plan.package_root),
                    ("source", &plan.source_root),
                    ("reason", &miss.to_string()),
                ],
            );
            return Decided::Reply(pass_through(&miss.to_string()));
        }
    };
    if let Err(reason) = package.verify_generated_disjoint(&plan) {
        return refuse(&reason);
    }
    // This record comes from the generated-tree capture, never a wire field.
    // Keying below binds these same bytes; PackageFacts revalidates the run
    // record and generated inputs before serving and after execution.
    if let Err(reason) = bind_rustc_environment(
        &mut plan,
        package.build_script_output.as_deref(),
        &parsed.env,
    ) {
        return refuse(&reason.to_string());
    }
    let mut inputs = ActionInputManifest {
        schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
        inputs: package
            .files
            .iter()
            .map(|(relative, object, executable)| PositiveInput {
                virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
                object: ObjectId(object.clone()),
                file_type: InputFileType::Regular,
                executable: *executable,
                symlink_resolution: Vec::new(),
            })
            .collect(),
        ..ActionInputManifest::default()
    };
    inputs.inputs.extend(
        package
            .generated_files
            .iter()
            .map(|(relative, object, executable)| PositiveInput {
                virtual_path: RawBytes::new(
                    plan.generated_input_virtual_path(relative).into_bytes(),
                ),
                object: ObjectId(object.clone()),
                file_type: InputFileType::Regular,
                executable: *executable,
                symlink_resolution: Vec::new(),
            }),
    );
    let mut externs = Vec::new();
    let dependencies = match live.facts.dependencies(&plan) {
        Ok(dependencies) => dependencies,
        Err(miss) => return refuse(&miss.to_string()),
    };
    for planned in &plan.externs {
        if let PlannedExtern::File { path, .. } = planned {
            match live.facts.file_digest(Path::new(path)) {
                Ok(digest) => externs.push(ExternFact {
                    path: path.clone(),
                    content_digest: digest,
                }),
                Err(error) => return refuse(&format!("extern-unreadable: {error}")),
            }
        }
    }
    let key = match live_dependency_key(
        &plan,
        &toolchain,
        &externs,
        &dependencies.directories,
        package.build_script_output.as_deref(),
        &inputs,
    ) {
        Ok(key) => key,
        Err(refusal) => {
            log(
                "pass-through",
                &[
                    ("crate", unit),
                    ("reason", refusal.code()),
                    ("detail", &refusal.to_string()),
                ],
            );
            return Decided::Reply(pass_through(refusal.code()));
        }
    };
    let key_text = digest_key(&key.action_key);
    let decision = live.lane.decide(LiveDependencyRequest {
        key,
        plan,
        inputs,
        package,
        dependencies,
        externs: externs
            .into_iter()
            .map(|fact| (fact.path, fact.content_digest))
            .collect(),
    });
    decision_reply(
        decision,
        &key_text,
        unit,
        request.get("wait_for_inflight").and_then(Value::as_bool) == Some(true),
    )
}

fn decision_reply(
    decision: LiveDecision,
    key_text: &str,
    unit: &str,
    wait_for_inflight: bool,
) -> Decided {
    match decision {
        LiveDecision::Hit(pending) => {
            log("hit", &[("crate", unit), ("key", key_text)]);
            Decided::Hit {
                reply: json!({
                    "kind": "rustc-decision", "decision": "hit",
                    "action_key": key_text, "capture_protocol": 1,
                    "compiler_skip_authorized": false,
                })
                .to_string(),
                pending: Box::new(pending),
            }
        }
        LiveDecision::Execute(attempt) => {
            log(
                "execute",
                &[
                    ("crate", unit),
                    ("key", key_text),
                    ("attempt", &attempt.attempt_hex()),
                ],
            );
            let reply = json!({
                "kind": "rustc-decision", "decision": "execute",
                "action_key": key_text, "attempt": attempt.attempt_hex(),
                "env": attempt.execution_env(), "capture_protocol": 1,
                "compiler_skip_authorized": false,
            })
            .to_string();
            Decided::Execute {
                reply,
                attempt: Box::new(attempt),
            }
        }
        LiveDecision::InFlight if wait_for_inflight => {
            log("wait", &[("crate", unit), ("key", key_text)]);
            // Reply releases the blocking lane immediately. No waiter task,
            // actor, or output ownership is retained: the existing connection
            // quota bounds retries, and every retry passes through decide.
            Decided::Reply(
                json!({
                    "kind": "rustc-decision", "decision": "wait",
                    "action_key": key_text, "reason": "in-flight",
                    "compiler_skip_authorized": false, "materialization_started": false,
                })
                .to_string(),
            )
        }
        LiveDecision::InFlight => {
            // Older wrappers do not understand wait. Keep their old healthy
            // pass-through behavior instead of tripping their circuit breaker.
            Decided::Reply(pass_through(
                "in-flight: another subscriber is executing this action",
            ))
        }
        LiveDecision::PassThrough(reason) => {
            log(
                "pass-through",
                &[("crate", unit), ("key", key_text), ("reason", &reason)],
            );
            Decided::Reply(pass_through(&reason))
        }
    }
}

/// Install an accepted hit (blocking). Only `served` authorizes skipping
/// the compiler; every other answer is given after the synchronous install
/// returned, so no writer remains behind it.
pub(super) fn install(live: &LiveEdge, pending: Box<PendingServe>) -> String {
    let key_text = digest_key(pending.action_key());
    match pending.install() {
        InstallResult::Served {
            transcript,
            installed,
        } => {
            for output in installed {
                live.facts.remember(&output.path, output.sig, output.digest);
            }
            log("served", &[("key", &key_text)]);
            json!({
                "kind": "rustc-decision", "decision": "served",
                "action_key": key_text, "stderr_hex": hex(&transcript),
                "compiler_skip_authorized": true,
            })
            .to_string()
        }
        InstallResult::Declined(reason) | InstallResult::Fault(reason) => {
            log("serve-failed", &[("key", &key_text), ("reason", &reason)]);
            json!({
                "kind": "rustc-decision", "decision": "serve-failed",
                "action_key": key_text, "reason": reason,
                "compiler_skip_authorized": false, "writer_returned": true,
            })
            .to_string()
        }
    }
}

/// The version is required: an older wrapper that sends a report and exits
/// never supplies output custody, so its completion cannot even be captured.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionFrame {
    kind: String,
    capture_protocol: u32,
    attempt: String,
    exit_code: Value,
    signal: Value,
    stdout_hex: String,
    stderr_hex: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureAck {
    kind: String,
    attempt: String,
    capture: String,
}

fn completion_report(frame: &[u8], attempt: &str) -> Option<CompletionReport> {
    let value: CompletionFrame = serde_json::from_slice(frame).ok()?;
    if value.kind != "rustc-complete"
        || value.capture_protocol != 1
        || value.attempt != attempt
        || value
            .stdout_hex
            .len()
            .saturating_add(value.stderr_hex.len())
            > 2 * MAX_TRANSCRIPT_BYTES
    {
        return None;
    }
    let code = |value: &Value| -> Option<Option<i32>> {
        match value {
            Value::Null => Some(None),
            number => Some(Some(i32::try_from(number.as_i64()?).ok()?)),
        }
    };
    Some(CompletionReport {
        exit_code: code(&value.exit_code)?,
        signal: code(&value.signal)?,
        stdout: unhex(&value.stdout_hex)?,
        stderr: unhex(&value.stderr_hex)?,
    })
}

fn capture_ack(frame: &[u8], attempt: &str, capture: &str) -> Option<CaptureAck> {
    // Decode the raw frame directly. Parsing via Value first would silently
    // collapse duplicate identity/authority fields before validation.
    let ack: CaptureAck = serde_json::from_slice(frame).ok()?;
    (ack.kind == "rustc-capture-ack" && ack.attempt == attempt && ack.capture == capture)
        .then_some(ack)
}

fn completion_not_published(detail: &str) -> String {
    json!({
        "kind": "rustc-completion", "outcome": "not-published", "detail": detail,
        "publication_authorized": false,
    })
    .to_string()
}

/// No CAS lock or blocking-worker permit is retained while waiting for the
/// wrapper. A lost, truncated, malformed or expired ACK is non-publication.
async fn acknowledge_capture(
    stream: &mut asupersync::net::unix::UnixStream,
    attempt: &str,
    capture: &str,
) -> Option<CaptureAck> {
    let receipt = json!({
        "kind": "rustc-captured", "capture_protocol": 1,
        "attempt": attempt, "capture": capture, "publication_authorized": false,
    })
    .to_string();
    if !super::write_frame(stream, &receipt).await {
        return None;
    }
    // The existing absolute frame budget bounds the complete ACK, not each
    // trickled byte. The wrapper's own deadline covers report + receipt + ACK.
    capture_ack(&super::read_frame(stream).await?, attempt, capture)
}

/// Two-phase completion on the actual admitted session. Preparation copies
/// every output into immutable CAS objects before requesting acknowledgment;
/// publication only consumes those captured objects, never the target paths.
pub(super) async fn complete_on_lane(
    lane: &super::Limit,
    live: Arc<LiveEdge>,
    attempt: Box<LocalAttempt>,
    frame: Vec<u8>,
    stream: &mut asupersync::net::unix::UnixStream,
) -> String {
    let prepared = match lane.spawn(move || {
        let report = completion_report(&frame, &attempt.attempt_hex())
            .ok_or_else(|| "malformed or unversioned completion".to_owned())?;
        (*attempt).capture(&report)
    }) {
        Ok(mut work) => match work.wait().await {
            Ok(result) => result,
            Err(error) => Err(error.to_string()),
        },
        Err(error) => Err(error.to_string()),
    };
    let captured = match prepared {
        Ok(captured) => captured,
        Err(detail) => return completion_not_published(&detail),
    };
    let attempt_hex = captured.attempt_hex();
    let ack = acknowledge_capture(stream, &attempt_hex, captured.manifest_key()).await;
    let finished = lane.spawn(move || {
        let Some(ack) = ack else {
            drop(captured);
            return completion_not_published("output capture was not acknowledged");
        };
        // Recheck against the retained candidate, not values from a new
        // request or a mutable source path. Publication consumes this owner.
        if ack.attempt != captured.attempt_hex() || ack.capture != captured.manifest_key() {
            drop(captured);
            return completion_not_published("capture identity mismatch");
        }
        let key_text = digest_key(captured.action_key());
        let (outcome, known) = captured.publish();
        for output in known {
            live.facts.remember(&output.path, output.sig, output.digest);
        }
        let detail = match &outcome {
            crate::coord::live_dependency::CompletionOutcome::NotPublished(reason)
            | crate::coord::live_dependency::CompletionOutcome::Refused(reason) => reason.clone(),
            _ => String::new(),
        };
        log(outcome.label(), &[("key", &key_text), ("detail", &detail)]);
        json!({"kind": "rustc-completion", "outcome": outcome.label(), "detail": detail})
            .to_string()
    });
    match finished {
        // A panic here may follow a committed pointer. Do not report a
        // fabricated non-publication or permit another compiler execution.
        Ok(mut work) => work.wait().await.unwrap_or_else(|error| {
            json!({
                "kind": "rustc-completion", "outcome": "unconfirmed",
                "detail": error.to_string(), "reexecute": false,
            })
            .to_string()
        }),
        Err(error) => completion_not_published(&error.to_string()),
    }
}

#[cfg(test)]
mod completion_capture_tests {
    use super::*;

    #[test]
    fn completion_requires_version_exact_identity_and_bounded_valid_hex() {
        let report = json!({
            "kind": "rustc-complete", "capture_protocol": 1, "attempt": "attempt-a",
            "exit_code": 0, "signal": null, "stdout_hex": "", "stderr_hex": "0aff",
        });
        let encoded = report.to_string();
        assert_eq!(
            completion_report(encoded.as_bytes(), "attempt-a")
                .unwrap()
                .stderr,
            [10, 255]
        );
        assert!(completion_report(encoded.as_bytes(), "another-attempt").is_none());
        let mut old_wrapper = report.clone();
        old_wrapper
            .as_object_mut()
            .unwrap()
            .remove("capture_protocol");
        assert!(completion_report(old_wrapper.to_string().as_bytes(), "attempt-a").is_none());
        for (field, bad) in [
            ("capture_protocol", json!(2)),
            ("capture_protocol", json!("1")),
            ("exit_code", json!(2147483648_i64)),
            ("signal", json!(1.5)),
            ("stderr_hex", json!("+0")),
            ("stderr_hex", json!("f")),
            ("stderr_hex", json!("gg")),
            ("stdout_hex", json!("00".repeat(MAX_TRANSCRIPT_BYTES + 1))),
        ] {
            let mut changed = report.clone();
            changed[field] = bad;
            assert!(completion_report(changed.to_string().as_bytes(), "attempt-a").is_none());
        }
        let duplicate = encoded.replacen("{", "{\"attempt\":\"attempt-a\",", 1);
        assert!(completion_report(duplicate.as_bytes(), "attempt-a").is_none());
    }

    #[test]
    fn capture_ack_rejects_mismatched_duplicate_or_invented_authority_fields() {
        let good = br#"{"kind":"rustc-capture-ack","attempt":"a","capture":"c"}"#;
        assert!(capture_ack(good, "a", "c").is_some());
        assert!(capture_ack(good, "different", "c").is_none());
        assert!(capture_ack(good, "a", "different").is_none());
        for frame in [
            br#"{"kind":"rustc-complete","attempt":"a","capture":"c"}"#.as_slice(),
            br#"{"kind":"rustc-capture-ack","attempt":"a","capture":"c","capture":"c"}"#,
            br#"{"kind":"rustc-capture-ack","attempt":"a","capture":"c","publish":true}"#,
            br#"{"kind":"rustc-capture-ack","attempt":"a"}"#,
            br#"{"kind":"rustc-capture-ack","attempt":"a","capture":null}"#,
        ] {
            assert!(capture_ack(frame, "a", "c").is_none());
        }
    }

    #[test]
    fn actual_capture_socket_requires_the_matching_post_capture_ack() {
        use std::io::{BufRead, BufReader, Write};
        use std::time::Duration;
        for reply in [
            Some("{\"kind\":\"rustc-capture-ack\",\"attempt\":\"a\",\"capture\":\"c\"}\n"),
            Some("{\"kind\":\"rustc-capture-ack\",\"attempt\":\"a\",\"capture\":\"other\"}\n"),
            Some("{\"kind\":\"rustc-capture-ack\",\"attempt\":\"a\",\"capture\":\"c\"}"),
            None,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("capture.sock");
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .build()
                .unwrap();
            let acknowledged = runtime.block_on(async {
                let listener = asupersync::net::unix::UnixListener::bind(&path)
                    .await
                    .unwrap();
                let peer = std::thread::spawn(move || {
                    let socket = std::os::unix::net::UnixStream::connect(path).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut socket = BufReader::new(socket);
                    let mut line = String::new();
                    socket.read_line(&mut line).unwrap();
                    let receipt: Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(receipt["kind"], "rustc-captured");
                    assert_eq!(receipt["attempt"], "a");
                    assert_eq!(receipt["capture"], "c");
                    assert_eq!(receipt["publication_authorized"], false);
                    if let Some(reply) = reply {
                        socket.get_mut().write_all(reply.as_bytes()).unwrap();
                    }
                });
                let (mut socket, _) = listener.accept().await.unwrap();
                let acknowledged = acknowledge_capture(&mut socket, "a", "c").await.is_some();
                peer.join().unwrap();
                acknowledged
            });
            assert_eq!(
                acknowledged,
                reply.is_some_and(|reply| reply.ends_with('\n') && !reply.contains("other"))
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_parsing_is_strict_and_hex_round_trips() {
        let good = json!({
            "kind": "rustc-request", "argv": ["/t/bin/rustc", "--crate-name", "x"],
            "cwd": "/w", "env": [["HOME", "/h"], ["CARGO_PKG_NAME", "x"]],
        });
        let parsed = parse_request(&good).unwrap();
        assert_eq!(parsed.env.len(), 2);
        assert_eq!(observation(&parsed).env_names, vec!["CARGO_PKG_NAME"]);
        for bad in [
            json!({"argv": [], "cwd": "/w", "env": []}),
            json!({"argv": ["/r", 7], "cwd": "/w", "env": []}),
            json!({"argv": ["/r"], "cwd": "/w", "env": [["ONLY_NAME"]]}),
            json!({"argv": ["/r"], "env": []}),
        ] {
            assert!(parse_request(&bad).is_none(), "{bad}");
        }
        let bytes = b"{\"artifact\":\"/x\"}\n\xff".to_vec();
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn decisions_name_the_crate_in_either_argv_spelling() {
        let argv = |args: &[&str]| args.iter().map(|&arg| arg.to_owned()).collect::<Vec<_>>();
        assert_eq!(
            crate_name(&argv(&[
                "/r",
                "--crate-name",
                "serde_json",
                "--edition=2021"
            ])),
            "serde_json"
        );
        assert_eq!(crate_name(&argv(&["/r", "--crate-name=itoa"])), "itoa");
        // Malformed or probe invocations still log, with an explicit unknown.
        assert_eq!(crate_name(&argv(&["/r", "--crate-name"])), "?");
        assert_eq!(crate_name(&argv(&["/r", "-vV"])), "?");
    }

    #[test]
    fn in_flight_is_a_non_owning_retry_not_a_hit_or_execution() {
        let Decided::Reply(reply) = decision_reply(LiveDecision::InFlight, "key", "leaf", true)
        else {
            panic!("a follower must not retain an attempt or install capability");
        };
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["kind"], "rustc-decision");
        assert_eq!(reply["decision"], "wait");
        assert_eq!(reply["action_key"], "key");
        assert_eq!(reply["compiler_skip_authorized"], false);
        assert_eq!(reply["materialization_started"], false);
        assert!(reply.get("attempt").is_none());
        assert!(reply.get("env").is_none());
    }

    #[test]
    fn only_opted_in_contention_waits_and_faults_remain_pass_through() {
        for (decision, opted_in) in [
            (LiveDecision::InFlight, false),
            (LiveDecision::PassThrough("store unavailable".into()), true),
        ] {
            let Decided::Reply(reply) = decision_reply(decision, "key", "leaf", opted_in) else {
                panic!("no execution or output ownership on refusal");
            };
            let reply: Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(reply["decision"], "pass-through");
            assert_eq!(reply["compiler_skip_authorized"], false);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn captured_run_record_controls_live_environment_not_request_fields() {
        use crate::coord::live::CoordLive;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let cargo = root.join("cargo");
        let package = cargo.join("registry/src/fixture-index/demo-1.0.0");
        let generated = root.join("build/demo/out");
        let output = root.join("target/deps");
        let toolchain = root.join("toolchain");
        let compiler = toolchain.join("bin/rustc");
        for directory in [
            package.clone(),
            generated.clone(),
            output.clone(),
            toolchain.join("bin"),
            toolchain.join("lib/rustlib/x86_64-unknown-linux-gnu/lib"),
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        std::fs::write(
            package.join("lib.rs"),
            b"pub const LABEL: &str = env!(\"BUILD_LABEL\");\n",
        )
        .unwrap();
        std::fs::write(
            generated.parent().unwrap().join("root-output"),
            generated.to_str().unwrap(),
        )
        .unwrap();
        std::fs::write(
            generated.parent().unwrap().join("output"),
            b"cargo::rustc-env=BUILD_LABEL=pinned\n",
        )
        .unwrap();
        // Only identity probes are scripted. No fake compile or publication is
        // credited here: the assertion exercises the real live admission path.
        std::fs::write(
            &compiler,
            concat!(
                "#!/bin/sh\ncase \"$1\" in\n",
                "-vV) printf 'rustc fixture\\nhost: x86_64-unknown-linux-gnu\\n';;\n",
                "--print) bin=${0%/*}; printf '%s\\n' \"${bin%/*}\";;\n",
                "*) exit 99;;\nesac\n",
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut request = json!({
            "kind":"rustc-request",
            "argv":[compiler.to_str().unwrap(), "--crate-name=demo", "--crate-type=lib",
                "--emit=metadata,dep-info", "--out-dir", output.to_str().unwrap(),
                "--cap-lints=allow", "--error-format=json", package.join("lib.rs").to_str().unwrap()],
            "cwd":package.to_str().unwrap(),
            "env":[["CARGO_HOME", cargo.to_str().unwrap()],
                ["CARGO_MANIFEST_DIR", package.to_str().unwrap()], ["CARGO_PKG_NAME", "demo"],
                ["OUT_DIR", generated.to_str().unwrap()], ["BUILD_LABEL", "pinned"],
                ["UNDECLARED", "ambient"]],
        });
        let cas = Arc::new(crate::janitor::store::mount_and_reconcile(&root.join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(cas));
        coord
            .acquire_boot_authority("build-script-environment-fixture")
            .unwrap();
        coord.mark_up();
        let live = LiveEdge::new(LiveDependencyLane::new(coord));
        let env = constructed_environment(&parse_request(&request).unwrap().env);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match live.facts.toolchain(&compiler, &env) {
                Ok(_) => break,
                Err(FactsMiss::Pending) => {
                    assert!(Instant::now() < deadline, "fixture toolchain did not warm");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("fixture toolchain: {error}"),
            }
        }
        let Decided::Execute { reply, attempt } = decide(&live, &request) else {
            panic!("a captured custom rustc-env must reach live execution admission");
        };
        assert!(
            attempt
                .execution_env()
                .contains(&("BUILD_LABEL".into(), "pinned".into()))
        );
        assert!(
            !attempt
                .execution_env()
                .iter()
                .any(|(name, _)| name == "UNDECLARED")
        );
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["compiler_skip_authorized"], false);
        drop(attempt);
        request["env"][4][1] = json!("stale");
        request["build_script_output"] = json!("cargo::rustc-env=BUILD_LABEL=stale\n");
        let Decided::Reply(reply) = decide(&live, &request) else {
            panic!("wire fields cannot replace the captured run record");
        };
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["decision"], "pass-through");
        assert!(
            reply["reason"]
                .as_str()
                .unwrap()
                .contains("LIVE_DEP_REFUSED_ENV")
        );
        assert_eq!(std::fs::read_dir(output).unwrap().count(), 0);
    }
}
