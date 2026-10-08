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
//!   `{"kind":"rustc-complete",…}` on the same connection;
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
    if !text.len().is_multiple_of(2) {
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
    let constructed = constructed_environment(&parsed.env);
    let toolchain = match live
        .facts
        .toolchain(Path::new(&parsed.argv[0]), &constructed)
    {
        Ok(toolchain) => toolchain,
        Err(FactsMiss::Pending) => {
            log("toolchain-warming", &[("compiler", &parsed.argv[0])]);
            return Decided::Shadow(observation(&parsed));
        }
        Err(FactsMiss::Refused(reason)) => {
            log(
                "shadow",
                &[("reason", "toolchain-refused"), ("detail", &reason)],
            );
            return Decided::Shadow(observation(&parsed));
        }
    };
    let Some(host) = toolchain.host_triple().map(str::to_owned) else {
        log("shadow", &[("reason", "toolchain-host-unknown")]);
        return Decided::Shadow(observation(&parsed));
    };
    let plan = match plan_dependency_action(
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
            // reason code is the `rch why`-grade explanation.
            log("shadow", &[("reason", refusal.code())]);
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
                    ("package", &plan.package_root),
                    ("source", &plan.source_root),
                    ("reason", &miss.to_string()),
                ],
            );
            return Decided::Reply(pass_through(&miss.to_string()));
        }
    };
    if let Err(reason) = package.verify_generated_disjoint(&plan) {
        return Decided::Reply(pass_through(&reason));
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
        Err(miss) => return Decided::Reply(pass_through(&miss.to_string())),
    };
    for planned in &plan.externs {
        if let PlannedExtern::File { path, .. } = planned {
            match live.facts.file_digest(Path::new(path)) {
                Ok(digest) => externs.push(ExternFact {
                    path: path.clone(),
                    content_digest: digest,
                }),
                Err(error) => {
                    return Decided::Reply(pass_through(&format!("extern-unreadable: {error}")));
                }
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
        Err(refusal) => return Decided::Reply(pass_through(refusal.code())),
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
        request.get("wait_for_inflight").and_then(Value::as_bool) == Some(true),
    )
}

fn decision_reply(decision: LiveDecision, key_text: &str, wait_for_inflight: bool) -> Decided {
    match decision {
        LiveDecision::Hit(pending) => {
            log("hit", &[("key", key_text)]);
            Decided::Hit {
                reply: json!({
                    "kind": "rustc-decision", "decision": "hit",
                    "action_key": key_text, "compiler_skip_authorized": false,
                })
                .to_string(),
                pending: Box::new(pending),
            }
        }
        LiveDecision::Execute(attempt) => {
            log(
                "execute",
                &[("key", key_text), ("attempt", &attempt.attempt_hex())],
            );
            let reply = json!({
                "kind": "rustc-decision", "decision": "execute",
                "action_key": key_text, "attempt": attempt.attempt_hex(),
                "env": attempt.execution_env(),
                "compiler_skip_authorized": false,
            })
            .to_string();
            Decided::Execute {
                reply,
                attempt: Box::new(attempt),
            }
        }
        LiveDecision::InFlight if wait_for_inflight => {
            log("wait", &[("key", key_text)]);
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
            log("pass-through", &[("key", key_text), ("reason", &reason)]);
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

/// Complete an admitted attempt from the subscriber's completion frame
/// (blocking: harvest, upload, publication). A malformed or mismatched
/// frame settles the attempt without publication.
pub(super) fn complete(live: &LiveEdge, attempt: Box<LocalAttempt>, frame: &[u8]) -> String {
    let report = serde_json::from_slice::<Value>(frame)
        .ok()
        .and_then(|value| {
            if value.get("kind")?.as_str()? != "rustc-complete"
                || value.get("attempt")?.as_str()? != attempt.attempt_hex()
            {
                return None;
            }
            let code = |field: &str| -> Option<Option<i32>> {
                match value.get(field)? {
                    Value::Null => Some(None),
                    number => Some(Some(i32::try_from(number.as_i64()?).ok()?)),
                }
            };
            Some(CompletionReport {
                exit_code: code("exit_code")?,
                signal: code("signal")?,
                stdout: unhex(value.get("stdout_hex")?.as_str()?)?,
                stderr: unhex(value.get("stderr_hex")?.as_str()?)?,
            })
        });
    let key_text = digest_key(attempt.action_key());
    let Some(report) = report else {
        drop(attempt);
        log("completion-malformed", &[("key", &key_text)]);
        return super::refusal("malformed-completion", "");
    };
    let (outcome, known) = attempt.complete(&report);
    for output in known {
        live.facts.remember(&output.path, output.sig, output.digest);
    }
    let detail = match &outcome {
        crate::coord::live_dependency::CompletionOutcome::NotPublished(reason)
        | crate::coord::live_dependency::CompletionOutcome::Refused(reason) => reason.clone(),
        _ => String::new(),
    };
    log(outcome.label(), &[("key", &key_text), ("detail", &detail)]);
    json!({"kind": "rustc-completion", "outcome": outcome.label(), "detail": detail}).to_string()
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
    fn in_flight_is_a_non_owning_retry_not_a_hit_or_execution() {
        let Decided::Reply(reply) = decision_reply(LiveDecision::InFlight, "key", true) else {
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
            let Decided::Reply(reply) = decision_reply(decision, "key", opted_in) else {
                panic!("no execution or output ownership on refusal");
            };
            let reply: Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(reply["decision"], "pass-through");
            assert_eq!(reply["compiler_skip_authorized"], false);
        }
    }
}
