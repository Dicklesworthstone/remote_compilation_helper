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
//! - anything else — run the compiler as if RABS were absent.
//!
//! Requests outside the live class keep the shadow plane's observation, so
//! turning the lane on never loses the existing shadow evidence.

use crate::coord::live_dependency::{
    CompletionReport, InstallResult, LiveDecision, LiveDependencyLane, LiveDependencyRequest,
    LocalAttempt, MAX_TRANSCRIPT_BYTES, PendingServe,
};
use crate::edge::live_facts::{FactsMiss, LiveFacts, build_script_env};
use rabs_cas::metadata_store::digest_key;
use rabs_key::live_dependency::{
    BUILD_SCRIPT_OUT_DIR, LiveRustcRequest, constructed_environment, live_dependency_key,
    plan_dependency_action,
};
use rabs_protocol::input_evidence::{
    ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::ObjectId;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

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
    /// Relocatable keys of build-script packages whose compile was seen
    /// reading `OUT_DIR`. Their requests are keyed in exact mode instead.
    /// A hint only: soundness never depends on it (a relocatable compile
    /// that reads `OUT_DIR` is not published), and losing it on restart
    /// costs one unpublishable execution per package.
    out_dir_readers: Mutex<HashSet<String>>,
}

/// Bound on remembered `OUT_DIR` readers before the hint set resets.
const MAX_OUT_DIR_READERS: usize = 65_536;

impl LiveEdge {
    /// Bind observation state to a coordinator lane.
    #[must_use]
    pub fn new(lane: LiveDependencyLane) -> Self {
        Self {
            lane,
            facts: LiveFacts::new(),
            out_dir_readers: Mutex::new(HashSet::new()),
        }
    }

    fn reads_out_dir(&self, relocatable_key: &str) -> bool {
        self.out_dir_readers
            .lock()
            .is_ok_and(|readers| readers.contains(relocatable_key))
    }

    fn remember_out_dir_reader(&self, relocatable_key: String) {
        if let Ok(mut readers) = self.out_dir_readers.lock() {
            if readers.len() >= MAX_OUT_DIR_READERS {
                readers.clear();
            }
            readers.insert(relocatable_key);
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
    // A package with a build script presents OUT_DIR; the variables its
    // script set come from Cargo's own record of the script's output.
    let build_script_env = match parsed
        .env
        .iter()
        .find(|(name, _)| name == BUILD_SCRIPT_OUT_DIR)
    {
        None => None,
        Some((_, out_dir)) => match build_script_env(Path::new(out_dir)) {
            Ok(names) => Some(names),
            Err(reason) => {
                log(
                    "shadow",
                    &[
                        ("reason", "LIVE_DEP_BUILD_SCRIPT_OUTPUT"),
                        ("detail", &reason),
                    ],
                );
                return Decided::Shadow(observation(&parsed));
            }
        },
    };
    // A build-script package is keyed relocatably unless its compile was
    // already seen reading OUT_DIR; then the exact OUT_DIR mode applies.
    let mut keyed = match key_request(
        live,
        &parsed,
        &host,
        &toolchain,
        build_script_env.as_deref(),
        false,
    ) {
        Ok(keyed) => keyed,
        Err(decided) => return *decided,
    };
    if keyed.plan.build_script_out_dir.is_some()
        && live.reads_out_dir(&digest_key(&keyed.key.action_key))
    {
        keyed = match key_request(
            live,
            &parsed,
            &host,
            &toolchain,
            build_script_env.as_deref(),
            true,
        ) {
            Ok(keyed) => keyed,
            Err(decided) => return *decided,
        };
    }
    let Keyed {
        key,
        plan,
        inputs,
        package,
        dependencies,
        externs,
    } = keyed;
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
    decided(decision, key_text)
}

/// One request planned and keyed in one `OUT_DIR` mode.
struct Keyed {
    key: rabs_key::live_dependency::LiveDependencyKey,
    plan: rabs_key::live_dependency::DependencyActionPlan,
    inputs: ActionInputManifest,
    package: Arc<crate::edge::live_facts::PackageFacts>,
    dependencies: Arc<crate::edge::live_facts::DependencyFacts>,
    externs: Vec<rabs_key::live_dependency::ExternFact>,
}

/// Plan, observe and key one request (`generated_inputs` selects the exact
/// `OUT_DIR` mode). `Err` carries the answer for a request that cannot be
/// keyed this way.
fn key_request(
    live: &LiveEdge,
    parsed: &Parsed,
    host: &str,
    toolchain: &rabs_key::live_dependency::ToolchainFacts,
    build_script_env: Option<&[String]>,
    generated_inputs: bool,
) -> Result<Keyed, Box<Decided>> {
    let plan = match plan_dependency_action(
        LiveRustcRequest {
            argv: &parsed.argv,
            cwd: &parsed.cwd,
            env: &parsed.env,
            build_script_env,
            generated_inputs,
        },
        host,
    ) {
        Ok(plan) => plan,
        Err(refusal) => {
            // Out of class (workspace members, proc-macro consumers, ...):
            // the reason code is the `rch why`-grade explanation.
            log("shadow", &[("reason", refusal.code())]);
            return Err(Box::new(Decided::Shadow(observation(parsed))));
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
            return Err(Box::new(Decided::Reply(pass_through(&miss.to_string()))));
        }
    };
    if let Err(reason) = package.verify_generated_disjoint(&plan) {
        return Err(Box::new(Decided::Reply(pass_through(&reason))));
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
    // The direct externs are read by the same closure, so their exact
    // identities and the referenced candidates come from one observation.
    let dependencies = match live.facts.dependencies(&plan) {
        Ok(dependencies) => dependencies,
        Err(miss) => {
            log(
                "pass-through",
                &[
                    ("package", &plan.package_root),
                    ("reason", &miss.to_string()),
                ],
            );
            return Err(Box::new(Decided::Reply(pass_through(&miss.to_string()))));
        }
    };
    let externs = dependencies.externs.clone();
    let key = match live_dependency_key(
        &plan,
        toolchain,
        &externs,
        &dependencies.directories,
        package.build_script_output.as_deref(),
        &inputs,
    ) {
        Ok(key) => key,
        Err(refusal) => return Err(Box::new(Decided::Reply(pass_through(refusal.code())))),
    };
    Ok(Keyed {
        key,
        plan,
        inputs,
        package,
        dependencies,
        externs,
    })
}

/// The connection's next step for the lane's decision.
fn decided(decision: LiveDecision, key_text: String) -> Decided {
    match decision {
        LiveDecision::Hit(pending) => {
            log("hit", &[("key", &key_text)]);
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
                &[("key", &key_text), ("attempt", &attempt.attempt_hex())],
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
        LiveDecision::PassThrough(reason) => {
            log("pass-through", &[("key", &key_text), ("reason", &reason)]);
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
    // A relocatable build-script compile that read OUT_DIR cannot publish;
    // key this package in exact mode from now on.
    if report.exit_code == Some(0) && attempt.observed_build_script_out_dir() {
        log("out-dir-reader", &[("key", &key_text)]);
        live.remember_out_dir_reader(key_text.clone());
    }
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
}
