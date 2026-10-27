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
//! - `{"kind":"rustc-decision","decision":"preparing",…}` — also only
//!   with `wait_for_inflight: true`: shared input facts or the complete
//!   remote toolchain image are warming. There is no action identity or
//!   execution/install ownership yet. Retrying
//!   allows the FIRST cold build to populate the cache instead of requiring
//!   throwaway builds. Preparation and keyed waits share the wrapper's one
//!   deadline and retry quota. Older wrappers can decline before any writes;
//! - anything else — run the compiler as if RABS were absent.
//!
//! Requests outside the live class keep the shadow plane's observation, so
//! turning the lane on never loses the existing shadow evidence.

use crate::coord::live_dependency::canonical::CanonicalPaths;
use crate::coord::live_dependency::remote::{PendingRemote, RemoteDependencies};
use crate::coord::live_dependency::{
    CompletionReport, InstallResult, LiveDecision, LiveDependencyLane, LiveDependencyRequest,
    LocalAttempt, MAX_TRANSCRIPT_BYTES, PendingServe,
};
use crate::edge::live_facts::{FactsMiss, GENERATED_ROOT, LiveFacts};
use rabs_cas::metadata_store::digest_key;
use rabs_key::build_script_directives::bind_rustc_environment;
use rabs_key::live_dependency::{
    ExternFact, LiveRustcRequest, PlannedExtern, constructed_environment,
};
use rabs_protocol::input_evidence::{
    ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::ObjectId;
use rabs_sandbox::generated_source::GeneratedSource;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[path = "admission_preflight.rs"]
mod admission_preflight;
#[path = "build_script_reuse.rs"]
mod build_script_reuse;
#[path = "directory_source.rs"]
mod directory_source;
#[path = "input_preparation.rs"]
mod input_preparation;

/// Largest completion frame: a bounded transcript in hex plus envelope.
pub(super) const MAX_COMPLETION_FRAME_BYTES: usize = 2 * MAX_TRANSCRIPT_BYTES + 64 * 1024;
const MAX_ARGS: usize = 4096;
const MAX_ENV: usize = 4096;

/// The edge half of the live dependency lane: observation state plus the
/// coordinator capability that decides and publishes.
#[derive(Debug)]
pub struct LiveEdge {
    lane: LiveDependencyLane,
    pub(super) facts: Arc<LiveFacts>,
    reuse_empty_out_dir: bool,
    remote: Option<Arc<RemoteDependencies>>,
    canonical: Option<Arc<CanonicalPaths>>,
    #[cfg(test)]
    pub(super) publication_pause: Option<PublicationPause>,
}

/// Pause one fixture's actual publication after its matching capture ACK.
/// No result or authority is substituted; releasing the gate continues through
/// the ordinary captured-result publication and verification checks.
#[cfg(test)]
#[derive(Debug)]
pub(super) struct PublicationPause {
    pub(super) reached: std::sync::mpsc::Sender<()>,
    pub(super) release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
impl PublicationPause {
    fn wait(&self) {
        self.reached.send(()).expect("publication observer present");
        self.release
            .lock()
            .expect("publication gate not poisoned")
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("publication gate released within fixture budget");
    }
}

impl LiveEdge {
    /// Bind observation state to a coordinator lane.
    #[must_use]
    pub fn new(lane: LiveDependencyLane) -> Self {
        Self {
            lane,
            facts: LiveFacts::new(),
            reuse_empty_out_dir: build_script_reuse::enabled(),
            remote: None,
            canonical: None,
            #[cfg(test)]
            publication_pause: None,
        }
    }

    /// Only the prepared canonical driver may bind this capability. The
    /// ordinary serving socket never derives it from client-supplied fields.
    pub(crate) fn canonical(lane: LiveDependencyLane, paths: Arc<CanonicalPaths>) -> Self {
        Self {
            lane,
            facts: LiveFacts::new(),
            reuse_empty_out_dir: false,
            remote: None,
            canonical: Some(paths),
            #[cfg(test)]
            publication_pause: None,
        }
    }

    fn physical_path(&self, path: &str) -> Result<PathBuf, String> {
        match &self.canonical {
            Some(paths) => paths.physical(Path::new(path)),
            None => Ok(PathBuf::from(path)),
        }
    }

    /// An operator-configured worker pool may execute the dependency units of
    /// this local Cargo operation. Its context is keyed separately from both
    /// ordinary remote work and local canonical execution. Project environment
    /// and wrapper frames cannot create this pool or select its TLS identity.
    pub(crate) fn canonical_configured(
        lane: LiveDependencyLane,
        paths: Arc<CanonicalPaths>,
        state: &Path,
    ) -> Result<Self, String> {
        let mut live = Self::canonical(lane, paths);
        live.remote = RemoteDependencies::from_canonical_environment(state)
            .map_err(|error| error.to_string())?;
        Ok(live)
    }
}

impl LiveEdge {
    /// The serving socket owns its actual remote configuration. Tests and
    /// explicit local lanes use new(), which performs no environment lookup.
    pub(super) fn remote_configuration(&self) -> Option<&Value> {
        self.remote.as_ref().map(|remote| remote.configuration())
    }

    /// The edge must allow every configured worker to execute independently.
    /// A local-only daemon owns no remote execution capacity.
    pub(super) fn remote_worker_count(&self) -> usize {
        self.remote
            .as_ref()
            .map_or(0, |remote| remote.worker_count())
    }

    pub(super) fn configured(lane: LiveDependencyLane, state: &Path) -> Result<Self, String> {
        let mut live = Self::new(lane);
        live.remote =
            RemoteDependencies::from_environment(state).map_err(|error| error.to_string())?;
        Ok(live)
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
    /// Offer private worker execution, then obtain fresh install consent.
    Remote {
        reply: String,
        pending: Box<PendingRemote>,
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

/// A pending observation is not an action key or a reserved dispatch. Keep
/// this vocabulary separate from coordinator decisions: readiness cannot
/// acquire execution, publication or output-install authority.
#[derive(Clone, Copy)]
enum PendingFacts {
    Toolchain,
    Package,
    Dependencies,
    RemoteToolchain,
}

impl PendingFacts {
    const fn reason(self) -> &'static str {
        match self {
            Self::Toolchain => "toolchain-facts-pending",
            Self::Package => "package-facts-pending",
            Self::Dependencies => "dependency-facts-pending",
            Self::RemoteToolchain => "remote-toolchain-pending",
        }
    }
}

fn preparing(unit: &str, facts: PendingFacts) -> Decided {
    let reason = facts.reason();
    log("preparing", &[("crate", unit), ("reason", reason)]);
    // Returning Reply releases the blocking lane. The existing bounded
    // warmer owns the observation; this connection retains no waiter task,
    // action reservation or writable output. Its next request reobserves
    // everything through decide, rather than adopting a stale descriptor.
    Decided::Reply(
        json!({
            "kind": "rustc-decision", "decision": "preparing", "reason": reason,
            "compiler_skip_authorized": false, "materialization_started": false,
        })
        .to_string(),
    )
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
    let may_wait = request.get("wait_for_inflight").and_then(Value::as_bool) == Some(true);
    // Every refusal below is logged with its reason: an unexplained miss is
    // indistinguishable from a lane that never saw the request.
    let refuse = |reason: &str| {
        log("pass-through", &[("crate", unit), ("reason", reason)]);
        Decided::Reply(pass_through(reason))
    };
    // Compiler probes and primary packages cannot be admitted, even once
    // the sysroot is warm. Do not delay Cargo (or occupy a warmer) for them.
    // Passing preflight grants no authority: the observed-host planner below
    // still checks the entire source/output class and all serving gates.
    let candidate = LiveRustcRequest {
        argv: &parsed.argv,
        cwd: &parsed.cwd,
        env: &parsed.env,
    };
    let remote_requested =
        live.remote.is_some() && request.get("remote_protocol").and_then(Value::as_u64) == Some(1);
    // Project executors can connect to this operation-visible endpoint. Their
    // local completion claims cannot populate or serve the cache. A configured
    // worker protocol may proceed toward independent closed execution; without
    // it, ordinary Cargo compilation continues without even warming facts.
    let local_capture = live
        .canonical
        .as_ref()
        .map_or(Ok(()), |paths| paths.require_local_capture());
    if !remote_requested && let Err(reason) = &local_capture {
        return refuse(reason);
    }
    let rejection = if remote_requested {
        admission_preflight::remote_rejection(candidate)
    } else {
        admission_preflight::rejection(candidate)
    };
    if let Some(refusal) = rejection {
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
    let constructed = constructed_environment(&parsed.env);
    let physical_compiler = match live.physical_path(&parsed.argv[0]) {
        Ok(path) => path,
        Err(reason) => return refuse(&reason),
    };
    let probe_environment = match &live.canonical {
        Some(paths) => match paths.probe_environment(&constructed) {
            Ok(environment) => environment,
            Err(reason) => return refuse(&reason),
        },
        None => constructed,
    };
    let toolchain = match live.facts.toolchain(&physical_compiler, &probe_environment) {
        Ok(toolchain) => toolchain,
        Err(FactsMiss::Pending) => {
            log(
                "toolchain-warming",
                &[("crate", unit), ("compiler", &parsed.argv[0])],
            );
            if may_wait {
                return preparing(unit, PendingFacts::Toolchain);
            }
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
    let planning_request = LiveRustcRequest {
        argv: &parsed.argv,
        cwd: &parsed.cwd,
        env: &parsed.env,
    };
    let planned = match &live.canonical {
        Some(paths) => directory_source::plan_canonical_dependency_action(
            planning_request,
            &host,
            paths,
            remote_requested,
        ),
        None => directory_source::plan_dependency_action(planning_request, &host),
    };
    let mut plan = match planned {
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
    // Keep the original observation through the entire request lifecycle.
    // Later cache refreshes must not substitute another toolchain generation
    // after this invocation has been keyed or its compiler has started.
    let toolchain_guard = match live.facts.toolchain_guard(&physical_compiler, &toolchain) {
        Ok(guard) => guard,
        Err(FactsMiss::Pending) if may_wait => return preparing(unit, PendingFacts::Toolchain),
        Err(miss) => return refuse(&miss.to_string()),
    };
    let physical_plan = match &live.canonical {
        Some(paths) => match paths.project_plan(&plan) {
            Ok(physical) => physical,
            Err(reason) => return refuse(&reason),
        },
        None => plan.clone(),
    };
    let (package, dependencies) = match input_preparation::observe(
        &live.facts,
        &plan,
        &physical_plan,
        live.canonical.as_deref(),
        may_wait,
    ) {
        Ok(observed) => observed,
        Err(input_preparation::InputMiss::PackageAndDependenciesPending) => {
            log(
                "preparing",
                &[
                    ("crate", unit),
                    ("reason", PendingFacts::Dependencies.reason()),
                ],
            );
            return preparing(unit, PendingFacts::Package);
        }
        Err(input_preparation::InputMiss::Package(FactsMiss::Pending)) if may_wait => {
            return preparing(unit, PendingFacts::Package);
        }
        Err(input_preparation::InputMiss::Dependencies(FactsMiss::Pending)) if may_wait => {
            return preparing(unit, PendingFacts::Dependencies);
        }
        Err(input_preparation::InputMiss::Package(miss)) => {
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
        Err(input_preparation::InputMiss::Dependencies(miss)) => {
            return refuse(&miss.to_string());
        }
    };
    if let Err(reason) = package.verify_generated_disjoint(&physical_plan) {
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
    for planned in &plan.externs {
        if let PlannedExtern::File { path, .. } = planned {
            let physical_path = match live.physical_path(path) {
                Ok(path) => path,
                Err(reason) => return refuse(&reason),
            };
            match live.facts.file_digest(&physical_path) {
                Ok(digest) => externs.push(ExternFact {
                    path: path.clone(),
                    content_digest: digest,
                }),
                Err(error) => return refuse(&format!("extern-unreadable: {error}")),
            }
        }
    }
    // Observations retain physical paths; keys and the worker context use only
    // Cargo's namespace-visible names, never this operation's backing roots.
    let key_directories = if let Some(paths) = &live.canonical {
        match paths.dependency_facts(&dependencies.directories) {
            Ok(directories) => directories,
            Err(reason) => return refuse(&reason),
        }
    } else {
        dependencies.directories.clone()
    };
    let key_result = if let Err(reason) = local_capture {
        // Keep a refusal, not a usable local key, across every remote warming,
        // keying, worker-unavailable and execution-refusal fallback below.
        Err(rabs_key::live_dependency::LiveRefusal::Facts(reason))
    } else if live.canonical.is_some() {
        rabs_key::live_dependency::canonical_cargo_dependency_key(
            &plan,
            &toolchain,
            &externs,
            &key_directories,
            package.build_script_output.as_deref(),
            &inputs,
        )
    } else {
        build_script_reuse::key(
            &mut plan,
            &toolchain,
            &externs,
            &key_directories,
            &package,
            &inputs,
            live.reuse_empty_out_dir,
        )
    };
    // Older wrappers keep the existing local protocol. A remote descriptor
    // can only be selected alongside this distinct accepted-execution path.
    // The local key may deliberately refuse a mode (canonical archive codegen)
    // that the isolated worker can execute. Keep that refusal until remote
    // keying completes; never manufacture a local key for worker-only work.
    let mut remote_toolchain_pending = false;
    let remote = if request.get("remote_protocol").and_then(Value::as_u64) == Some(1) {
        live.remote.as_ref().and_then(|remote| {
            if plan.generated_root.is_some() {
                let generated_paths = package
                    .generated_files
                    .iter()
                    .map(|(path, _, _)| path.clone())
                    .collect::<Vec<_>>();
                // Use the transfer's exact projection before offering remote
                // execution. Unsupported generated layouts retain the local
                // key and protocol; no remote acceptance has happened yet.
                if let Err(reason) = GeneratedSource::from_snapshot(
                    Arc::clone(&package.snapshot),
                    GENERATED_ROOT,
                    &generated_paths,
                ) {
                    log(
                        "remote-ineligible",
                        &[("crate", unit), ("reason", &reason.to_string())],
                    );
                    return None;
                }
            }
            match remote.key(
                &plan,
                &toolchain,
                &toolchain_guard,
                &key_directories,
                &inputs,
                package.build_script_output.as_deref(),
                &parsed.argv,
                live.canonical.as_deref(),
            ) {
                Ok(Some((remote_key, invocation))) => {
                    Some((remote_key, Arc::clone(remote), invocation))
                }
                Ok(None) => {
                    remote_toolchain_pending = true;
                    if !may_wait {
                        log(
                            "remote-ineligible",
                            &[
                                ("crate", unit),
                                ("reason", "complete remote toolchain capture is warming"),
                            ],
                        );
                    }
                    None
                }
                Err(reason) => {
                    log("remote-ineligible", &[("crate", unit), ("reason", &reason)]);
                    None
                }
            }
        })
    } else {
        None
    };
    if remote_toolchain_pending && may_wait {
        // No lane has been consulted and the original local key was not
        // replaced. Retrying reobserves all inputs before remote admission.
        return preparing(unit, PendingFacts::RemoteToolchain);
    }
    let (key, remote) = match remote {
        Some((key, remote, invocation)) => (key, Some((remote, invocation))),
        None => match key_result {
            Ok(key) => (key, None),
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
        },
    };
    let key_text = digest_key(&key.action_key);
    let admitted = LiveDependencyRequest {
        key,
        plan,
        inputs,
        package,
        dependencies,
        toolchain: toolchain_guard,
        externs: externs
            .into_iter()
            .map(|fact| (fact.path, fact.content_digest))
            .collect(),
        canonical_paths: live.canonical.clone(),
    };
    let decision = match remote {
        Some((remote, invocation)) => live.lane.decide_remote(admitted, remote, invocation),
        None => live.lane.decide(admitted),
    };
    decision_reply(decision, &key_text, unit, may_wait)
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
        LiveDecision::Remote(pending) => {
            log("remote-offer", &[("crate", unit), ("key", key_text)]);
            Decided::Remote {
                reply: json!({
                    "kind":"rustc-decision", "decision":"remote", "remote_protocol":1,
                    "action_key":key_text, "capture_protocol":1,
                    "compiler_skip_authorized":false,
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

fn completion_not_published(key_text: &str, detail: &str) -> String {
    log("not-published", &[("key", key_text), ("detail", detail)]);
    json!({
        "kind": "rustc-completion", "outcome": "not-published", "detail": detail,
        "publication_authorized": false,
    })
    .to_string()
}

/// No CAS lock or worker thread is retained while waiting for the wrapper.
/// The caller keeps its completion capacity reservation across this bounded
/// exchange. A lost, truncated, malformed or expired ACK is non-publication.
async fn acknowledge_capture(
    stream: &mut super::EdgeStream,
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
    stream: &mut super::EdgeStream,
) -> String {
    let key_text = digest_key(attempt.action_key());
    // Reserve ONCE for capture -> acknowledgment -> publication/cleanup.
    // A fresh burst must not steal the publication slot after we told Cargo
    // that its outputs were captured. This permit grants capacity only: the
    // exact acknowledgment and every coordinator publication gate still apply.
    let Some(reservation) = lane.acquire() else {
        return completion_not_published(&key_text, &super::WorkError::Saturated.to_string());
    };
    let prepared = match reservation.stage(move || {
        let report = completion_report(&frame, &attempt.attempt_hex())
            .ok_or_else(|| "malformed or unversioned completion".to_owned())?;
        (*attempt).capture(&report)
    }) {
        Ok(mut work) => work.wait().await.map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    let (prepared, reservation) = match prepared {
        Ok(result) => result,
        Err(detail) => return completion_not_published(&key_text, &detail),
    };
    let captured = match prepared {
        Ok(captured) => captured,
        Err(detail) => return completion_not_published(&key_text, &detail),
    };
    let attempt_hex = captured.attempt_hex();
    let ack = acknowledge_capture(stream, &attempt_hex, captured.manifest_key()).await;
    // Capture's worker has been joined; acknowledgment held no thread or CAS
    // lock. Consume the same non-clone reservation, never race a second acquire.
    let finished_key = key_text.clone();
    let finished = reservation.finish(move || {
        let Some(ack) = ack else {
            drop(captured);
            return completion_not_published(&finished_key, "output capture was not acknowledged");
        };
        // Recheck against the retained candidate, not values from a new
        // request or a mutable source path. Publication consumes this owner.
        if ack.attempt != captured.attempt_hex() || ack.capture != captured.manifest_key() {
            drop(captured);
            return completion_not_published(&finished_key, "capture identity mismatch");
        }
        #[cfg(test)]
        if let Some(pause) = &live.publication_pause {
            pause.wait();
        }
        let (outcome, known) = captured.publish();
        for output in known {
            live.facts.remember(&output.path, output.sig, output.digest);
        }
        let detail = match &outcome {
            crate::coord::live_dependency::CompletionOutcome::NotPublished(reason)
            | crate::coord::live_dependency::CompletionOutcome::Refused(reason) => reason.clone(),
            _ => String::new(),
        };
        log(
            outcome.label(),
            &[("key", &finished_key), ("detail", &detail)],
        );
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
        Err(error) => completion_not_published(&key_text, &error.to_string()),
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
            let acknowledged =
                rabs_asupersync::daemon_runtime::block_on_top_level(&runtime, async {
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
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = super::super::EdgeStream::with_capacity(
                        super::super::FRAME_READ_BUFFER_BYTES,
                        socket,
                    );
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
    fn project_code_cannot_enable_local_capture_by_claiming_a_remote_protocol() {
        use crate::coord::live::CoordLive;
        use std::os::unix::fs::DirBuilderExt;

        let owner = Arc::new(crate::test_util::private_tempdir());
        let roots = [
            "/__rabs/workspace",
            "/__rabs/cargo-home",
            "/__rabs/toolchain",
            "/__rabs/out/cargo",
            "/__rabs/home",
        ];
        let mappings = roots
            .iter()
            .enumerate()
            .map(|(index, visible)| {
                let backing = owner.path().join(index.to_string());
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&backing)
                    .unwrap();
                (PathBuf::from(visible), backing)
            })
            .collect();
        let paths = CanonicalPaths::new(Arc::clone(&owner), mappings)
            .unwrap()
            .require_closed_dependency_execution()
            .unwrap();
        // A genuine coordinator with no worker (or CAS) configured. Neither
        // source nor compiler exists: this denial must precede observation.
        let coord = Arc::new(CoordLive::new());
        let live = LiveEdge::canonical(LiveDependencyLane::new(coord), paths);
        for protocol in [Value::Null, json!(0), json!(1), json!(2)] {
            let request = json!({
                "kind":"rustc-request", "remote_protocol":protocol,
                "wait_for_inflight":true,
                "argv":["/__rabs/toolchain/bin/rustc", "--crate-name=leaf"],
                "cwd":"/__rabs/cargo-home/registry/src/index/leaf-1.0.0",
                "env":[], "local_capture_allowed":true, "canonical_project_executors":false,
            });
            let Decided::Reply(reply) = decide(&live, &request) else {
                panic!("project executor must not obtain a local attempt, hit or warming task");
            };
            let reply: Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(reply["decision"], "pass-through");
            assert_eq!(
                reply["reason"],
                "canonical-project-executors-require-isolated-dependency-execution"
            );
            assert_eq!(reply["compiler_skip_authorized"], false);
            for absent in ["attempt", "action_key", "env"] {
                assert!(reply.get(absent).is_none(), "{reply}");
            }
        }
        for index in 0..roots.len() {
            assert_eq!(
                std::fs::read_dir(owner.path().join(index.to_string()))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    #[test]
    fn preparing_facts_has_neither_action_identity_nor_execution_or_install_authority() {
        for (facts, reason) in [
            (PendingFacts::Toolchain, "toolchain-facts-pending"),
            (PendingFacts::Package, "package-facts-pending"),
            (PendingFacts::Dependencies, "dependency-facts-pending"),
            (PendingFacts::RemoteToolchain, "remote-toolchain-pending"),
        ] {
            let Decided::Reply(reply) = preparing("leaf", facts) else {
                panic!("preparation must release the request lane without ownership");
            };
            let reply: Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(reply["kind"], "rustc-decision");
            assert_eq!(reply["decision"], "preparing");
            assert_eq!(reply["reason"], reason);
            assert_eq!(reply["compiler_skip_authorized"], false);
            assert_eq!(reply["materialization_started"], false);
            for absent in ["action_key", "attempt", "env"] {
                assert!(
                    reply.get(absent).is_none(),
                    "{absent} is not a readiness fact"
                );
            }
        }
    }

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
            attempt
                .execution_env()
                .contains(&("UNDECLARED".into(), "ambient".into()))
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
